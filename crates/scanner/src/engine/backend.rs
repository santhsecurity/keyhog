use super::*;
use crate::hw_probe::ScanBackend;
use keyhog_core::Chunk;

use std::sync::Arc;

pub(crate) struct PreparedChunk {
    pub(crate) chunk: Arc<Chunk>,
    pub(crate) preprocessed: ScannerPreprocessedText,
}

/// Build a Hyperscan database from ALL detector patterns.
///
/// Unlike the old approach that compiled AC literal prefixes (1500+ escaped
/// strings), this compiles the ACTUAL full regexes — one per unique
/// (detector_index, pattern) pair. This is what Titus does: compile every
/// regex into one Hyperscan database, scan once.
#[cfg(feature = "simd")]
pub(crate) fn build_simd_scanner(
    ac_map: &[CompiledPattern],
    _fallback: &[(CompiledPattern, Vec<String>)],
) -> Option<(crate::simd::backend::HsScanner, Vec<Vec<usize>>)> {
    use std::collections::HashMap;

    let mut regex_to_hs_id: HashMap<String, usize> = HashMap::new();
    let mut hs_patterns: Vec<(usize, usize, String, bool)> = Vec::new();
    let mut index_map: Vec<Vec<usize>> = Vec::new();

    for (idx, entry) in ac_map.iter().enumerate() {
        let regex_str = entry.regex.as_str();
        let hs_id = *regex_to_hs_id
            .entry(regex_str.to_string())
            .or_insert_with(|| {
                let id = hs_patterns.len();
                hs_patterns.push((
                    entry.detector_index,
                    id,
                    regex_str.to_string(),
                    entry.group.is_some(),
                ));
                index_map.push(Vec::new());
                id
            });
        index_map[hs_id].push(idx);
    }

    let pattern_refs: Vec<(usize, usize, &str, bool)> = hs_patterns
        .iter()
        .map(|(a, b, c, d)| (*a, *b, c.as_str(), *d))
        .collect();

    tracing::info!(
        unique = hs_patterns.len(),
        raw = ac_map.len(),
        "compiling deduplicated AC regexes into Hyperscan"
    );

    match crate::simd::backend::HsScanner::compile(&pattern_refs) {
        Ok((scanner, unsupported)) => {
            tracing::info!(
                compiled = scanner.pattern_count(),
                unsupported = unsupported.len(),
                "HS ready"
            );
            Some((scanner, index_map))
        }
        Err(error) => {
            tracing::warn!("HS compilation failed: {error}");
            None
        }
    }
}

impl CompiledScanner {
    pub(crate) fn scan_chunks_with_backend_internal(
        &self,
        chunks: &[Chunk],
        backend: ScanBackend,
    ) -> Vec<Vec<RawMatch>> {
        if backend != ScanBackend::Gpu || chunks.is_empty() || self.gpu_pattern_set.is_none() {
            return chunks
                .iter()
                .map(|chunk| self.scan_with_backend(chunk, backend))
                .collect();
        }

        let prepared: Vec<_> = chunks
            .iter()
            .map(|chunk| self.prepare_chunk(chunk))
            .collect();

        let total_patterns = self.ac_map.len() + self.fallback.len();
        let mut triggered = vec![vec![0u64; total_patterns.div_ceil(64)]; prepared.len()];
        if !self.populate_gpu_batch_triggers(&prepared, &mut triggered) {
            let fallback_backend = self.degraded_backend_after_gpu_failure();
            tracing::debug!(
                fallback = fallback_backend.label(),
                "gpu batch scan unavailable, degrading to non-gpu backend"
            );
            return chunks
                .iter()
                .map(|chunk| self.scan_with_backend(chunk, fallback_backend))
                .collect();
        }

        prepared
            .into_iter()
            .zip(triggered)
            .map(|(prepared, chunk_triggered)| {
                self.scan_prepared_with_triggered(prepared, backend, chunk_triggered, None)
            })
            .collect()
    }

    pub(crate) fn prepare_chunk(&self, chunk: &Chunk) -> PreparedChunk {
        let mut owned_normalized = None;
        let owned_unicode;
        let chunk = if chunk.data.is_ascii() {
            chunk
        } else {
            normalize_scannable_chunk(chunk, &mut owned_normalized)
        };

        let chunk = if self.config.unicode_normalization {
            let unicode_normalized = unicode_hardening::normalize_homoglyphs(&chunk.data);
            if unicode_normalized != chunk.data {
                owned_unicode = Some(keyhog_core::Chunk {
                    data: unicode_normalized,
                    metadata: chunk.metadata.clone(),
                });
                owned_unicode.as_ref().unwrap_or(chunk)
            } else {
                chunk
            }
        } else {
            chunk
        };

        let preprocessed = if let Some(pp) =
            crate::structured::preprocess(&chunk.data, chunk.metadata.path.as_deref())
        {
            pp
        } else {
            #[cfg(feature = "multiline")]
            if crate::multiline::has_concatenation_indicators(&chunk.data) {
                crate::multiline::preprocess_multiline(&chunk.data, &self.config.multiline)
            } else {
                ScannerPreprocessedText::passthrough(&chunk.data)
            }
            #[cfg(not(feature = "multiline"))]
            ScannerPreprocessedText::passthrough(&chunk.data)
        };

        PreparedChunk {
            chunk: Arc::new(chunk.clone()),
            preprocessed,
        }
    }

    pub(crate) fn scan_prepared_with_triggered(
        &self,
        prepared: PreparedChunk,
        backend: ScanBackend,
        triggered_patterns: Vec<u64>,
        deadline: Option<std::time::Instant>,
    ) -> Vec<RawMatch> {
        let line_offsets = compute_line_offsets(&prepared.preprocessed.text);
        let code_lines: Vec<&str> = prepared.chunk.data.lines().collect();
        let documentation_lines = context::documentation_line_flags(&code_lines);
        let mut scan_state = ScanState::default();

        #[cfg(feature = "simdsieve")]
        self.scan_hot_patterns_fast(
            &prepared.preprocessed.text,
            &line_offsets,
            &prepared.chunk,
            &mut scan_state,
        );

        let expanded_patterns = if backend == ScanBackend::Gpu {
            triggered_patterns // GPU runs full regexes; no AC prefix expansion needed.
        } else {
            self.expand_triggered_patterns(&triggered_patterns)
        };

        let total_patterns = self.ac_map.len() + self.fallback.len();
        let confirmed_patterns: Vec<usize> = if backend == ScanBackend::Gpu {
            (0..total_patterns)
                .filter(|&i| (expanded_patterns[i / 64] & (1 << (i % 64))) != 0)
                .collect()
        } else {
            (0..self.ac_map.len())
                .filter(|&i| (expanded_patterns[i / 64] & (1 << (i % 64))) != 0)
                .collect()
        };

        self.extract_confirmed_patterns(
            &confirmed_patterns,
            &prepared.preprocessed,
            &line_offsets,
            &code_lines,
            &documentation_lines,
            &prepared.chunk,
            &mut scan_state,
            deadline,
        );

        // Generic key=value scanner: catches secrets assigned to variables
        // with secret-related names. Only fires when no named detector already
        // found a match on the same line AND the value has high entropy.
        self.scan_generic_assignments(&code_lines, &prepared.chunk, &mut scan_state);

        #[cfg(feature = "entropy")]
        self.scan_entropy_fallback(
            &prepared.preprocessed,
            &line_offsets,
            &prepared.chunk,
            &mut scan_state,
        );

        #[cfg(feature = "ml")]
        self.apply_ml_batch_scores(&mut scan_state);

        tracing::debug!(
            backend = backend.label(),
            path = prepared
                .chunk
                .metadata
                .path
                .as_deref()
                .unwrap_or("<memory>"),
            matches = scan_state.matches.len(),
            "completed scan with selected backend"
        );

        scan_state.into_matches()
    }

    pub(crate) fn collect_triggered_patterns_for_backend(
        &self,
        text: &str,
        backend: ScanBackend,
    ) -> Vec<u64> {
        match backend {
            ScanBackend::Gpu => self.collect_triggered_patterns_gpu(text),
            ScanBackend::SimdCpu => self.collect_triggered_patterns_simd(text),
            ScanBackend::CpuFallback => self.collect_triggered_patterns_cpu(text),
        }
    }

    fn collect_triggered_patterns_gpu(&self, text: &str) -> Vec<u64> {
        if let Some(matcher) = self.gpu_matcher() {
            match matcher.scan_blocking(text.as_bytes()) {
                Ok(matches) => return self.triggered_patterns_from_gpu_matches(&matches),
                Err(error) => {
                    tracing::debug!("gpu scan failed, degrading to CPU path: {error}");
                }
            }
        }
        self.collect_triggered_patterns_simd(text)
    }

    fn collect_triggered_patterns_simd(&self, text: &str) -> Vec<u64> {
        #[cfg(feature = "simd")]
        if let Some(scanner) = &self.simd_prefilter {
            let mut triggered_patterns = vec![0u64; self.ac_map.len().div_ceil(64)];
            for (hs_id, _start, _end) in scanner.scan(text.as_bytes()) {
                let Some((_detector_index, ac_index, _has_group)) = scanner.pattern_info(hs_id)
                else {
                    continue;
                };
                self.mark_triggered_pattern(&mut triggered_patterns, ac_index);
            }
            return triggered_patterns;
        }

        self.collect_triggered_patterns_cpu(text)
    }

    fn collect_triggered_patterns_cpu(&self, text: &str) -> Vec<u64> {
        let mut triggered_patterns = vec![0u64; self.ac_map.len().div_ceil(64)];
        if let Some(ac) = &self.ac {
            for ac_match in ac.scan(text.as_bytes()).unwrap_or_default() {
                self.mark_triggered_pattern(&mut triggered_patterns, ac_match.pattern_id as usize);
            }
        }
        triggered_patterns
    }

    fn triggered_patterns_from_gpu_matches(&self, matches: &[warpstate::Match]) -> Vec<u64> {
        let total_patterns = self.ac_map.len() + self.fallback.len();
        let mut triggered_patterns = vec![0u64; total_patterns.div_ceil(64)];
        for matched in matches {
            let pattern_index = matched.pattern_id as usize;
            if pattern_index >= total_patterns {
                continue;
            }
            triggered_patterns[pattern_index / 64] |= 1u64 << (pattern_index % 64);
        }
        triggered_patterns
    }

    fn mark_triggered_pattern(&self, triggered_patterns: &mut [u64], pattern_index: usize) {
        if pattern_index / 64 >= triggered_patterns.len() {
            return;
        }
        triggered_patterns[pattern_index / 64] |= 1u64 << (pattern_index % 64);
        if pattern_index < self.prefix_propagation.len() {
            for &propagated_index in &self.prefix_propagation[pattern_index] {
                if propagated_index / 64 < triggered_patterns.len() {
                    triggered_patterns[propagated_index / 64] |= 1u64 << (propagated_index % 64);
                }
            }
        }
    }

    pub fn gpu_matcher(&self) -> Option<&warpstate::AutoMatcher> {
        self.gpu_matcher
            .get_or_init(|| {
                let patterns = self.gpu_pattern_set.as_ref()?.clone();
                let config = warpstate::AutoMatcherConfig::new()
                    .gpu_threshold(0)
                    .gpu_max_input_size(usize::MAX / 2)
                    .auto_tune_threshold(false)
                    .max_matches(self.config.max_matches_per_chunk.min(u32::MAX as usize) as u32);
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        tracing::warn!("failed to build GPU routing runtime: {error}");
                        return None;
                    }
                };

                match runtime.block_on(warpstate::AutoMatcher::with_config(&patterns, config)) {
                    Ok(matcher) => {
                        // Warm-up: dummy 1-byte scan to amortize cold-start latency.
                        if let Err(e) = matcher.scan_blocking(b"x") {
                            tracing::debug!("GPU warm-up scan failed: {e}");
                        } else {
                            tracing::debug!("GPU warm-up scan completed");
                        }
                        Some(matcher)
                    }
                    Err(error) => {
                        tracing::warn!("failed to initialize warpstate GPU matcher: {error}");
                        None
                    }
                }
            })
            .as_ref()
    }

    fn degraded_backend_after_gpu_failure(&self) -> ScanBackend {
        let caps = crate::hw_probe::probe_hardware();
        if caps.has_avx512 || caps.has_avx2 || caps.has_neon {
            ScanBackend::SimdCpu
        } else {
            ScanBackend::CpuFallback
        }
    }

    fn populate_gpu_batch_triggers(
        &self,
        prepared: &[PreparedChunk],
        triggered: &mut [Vec<u64>],
    ) -> bool {
        let Some(matcher) = self.gpu_matcher() else {
            return false;
        };

        const MAX_BATCH_BYTES: usize = 64 * 1024 * 1024;
        const MAX_BATCH_ITEMS: usize = 2048;

        let mut start = 0usize;
        while start < prepared.len() {
            let mut end = start;
            let mut batch_bytes = 0usize;
            while end < prepared.len() && end - start < MAX_BATCH_ITEMS {
                let len = prepared[end].preprocessed.text.len();
                if end > start && batch_bytes.saturating_add(len) > MAX_BATCH_BYTES {
                    break;
                }
                batch_bytes = batch_bytes.saturating_add(len);
                end += 1;
            }

            let (entries, buffer) = coalesce_preprocessed_batch(&prepared[start..end]);
            let matches = match matcher.scan_blocking(&buffer) {
                Ok(matches) => matches,
                Err(error) => {
                    tracing::warn!("batched GPU scan failed: {error}");
                    return false;
                }
            };

            map_batch_matches(self, &entries, matches, &mut triggered[start..end]);
            start = end;
        }

        true
    }
}

fn coalesce_preprocessed_batch(
    prepared: &[PreparedChunk],
) -> (Vec<(usize, usize, usize)>, Vec<u8>) {
    let total_bytes = prepared
        .iter()
        .map(|chunk| chunk.preprocessed.text.len())
        .sum();
    let mut entries = Vec::with_capacity(prepared.len());
    let mut buffer = Vec::with_capacity(total_bytes);

    for (index, chunk) in prepared.iter().enumerate() {
        let start = buffer.len();
        buffer.extend_from_slice(chunk.preprocessed.text.as_bytes());
        entries.push((index, start, chunk.preprocessed.text.len()));
    }

    (entries, buffer)
}

fn map_batch_matches(
    scanner: &CompiledScanner,
    entries: &[(usize, usize, usize)],
    matches: Vec<warpstate::Match>,
    triggered: &mut [Vec<u64>],
) {
    let mut cursor = 0usize;
    for matched in matches {
        let global_start = matched.start as usize;
        let global_end = matched.end as usize;

        while cursor < entries.len() {
            let (_, offset, len) = entries[cursor];
            if global_start < offset + len {
                break;
            }
            cursor += 1;
        }
        if cursor >= entries.len() {
            break;
        }

        let (chunk_index, offset, len) = entries[cursor];
        if global_start < offset || global_end > offset + len {
            continue;
        }
        scanner.mark_triggered_pattern(&mut triggered[chunk_index], matched.pattern_id as usize);
    }
}

#[cfg(test)]
mod tests {
    use super::{PreparedChunk, coalesce_preprocessed_batch, map_batch_matches};
    use crate::engine::CompiledScanner;
    use crate::types::ScannerPreprocessedText;
    use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
    use std::sync::Arc;

    fn chunk() -> Chunk {
        Chunk {
            data: String::new(),
            metadata: ChunkMetadata::default(),
        }
    }

    #[test]
    fn coalescing_preserves_offsets() {
        let prepared = vec![
            PreparedChunk {
                chunk: Arc::new(chunk()),
                preprocessed: ScannerPreprocessedText::passthrough("abc"),
            },
            PreparedChunk {
                chunk: Arc::new(chunk()),
                preprocessed: ScannerPreprocessedText::passthrough("defg"),
            },
        ];

        let (entries, buffer) = coalesce_preprocessed_batch(&prepared);
        assert_eq!(entries, vec![(0, 0, 3), (1, 3, 4)]);
        assert_eq!(buffer, b"abcdefg");
    }

    #[test]
    fn cross_boundary_matches_are_dropped() {
        let scanner = CompiledScanner::compile(vec![DetectorSpec {
            id: "demo-token".into(),
            name: "Demo Token".into(),
            service: "demo".into(),
            severity: Severity::High,
            patterns: vec![PatternSpec {
                regex: "abc".into(),
                description: None,
                group: None,
            }],
            companions: vec![],
            verify: None,
            keywords: vec!["abc".into()],
            ..Default::default()
        }])
        .unwrap();
        let entries = vec![(0usize, 0usize, 3usize), (1usize, 3usize, 3usize)];
        let matches = vec![
            warpstate::Match::from_parts(0, 1, 2),
            warpstate::Match::from_parts(0, 2, 4),
        ];
        let mut triggered = vec![vec![0u64; 1], vec![0u64; 1]];

        map_batch_matches(&scanner, &entries, matches, &mut triggered);

        assert_eq!(triggered[0][0], 1);
        assert_eq!(triggered[1][0], 0);
    }
}

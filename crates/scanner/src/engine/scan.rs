use super::*;

/// Fast check for secret-related keywords in file content.
/// Used to gate the multiline fallback — only files that mention
/// secret/key/token/password are worth reassembling.
fn has_secret_keyword_fast(data: &[u8]) -> bool {
    // Only check for prefixes that are BOTH (a) distinctive enough to be real
    // secrets and (b) commonly split across lines in source code.
    // Avoid short prefixes like AKIA/eyJ that appear in test fixtures.
    const KEYWORDS: &[&[u8]] = &[b"sk-proj-", b"sk_live_", b"ghp_", b"xoxb-", b"xoxp-"];
    for kw in KEYWORDS {
        if memchr::memmem::find(data, kw).is_some() {
            return true;
        }
    }
    false
}

/// Check for generic `secret=`, `password:`, `token=` etc. keywords.
/// Broader than `has_secret_keyword_fast` (which is for multiline only).
fn has_generic_assignment_keyword(data: &[u8]) -> bool {
    const KEYWORDS: &[&[u8]] = &[
        b"secret",
        b"SECRET",
        b"password",
        b"PASSWORD",
        b"passwd",
        b"PASSWD",
        b"token",
        b"TOKEN",
        b"api_key",
        b"API_KEY",
        b"apikey",
        b"APIKEY",
        b"auth_token",
        b"AUTH_TOKEN",
        b"private_key",
        b"PRIVATE_KEY",
        b"client_secret",
        b"CLIENT_SECRET",
        b"access_key",
        b"ACCESS_KEY",
    ];
    for kw in KEYWORDS {
        if memchr::memmem::find(data, kw).is_some() {
            return true;
        }
    }
    false
}

fn looks_like_variable_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 {
        return false;
    }
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl CompiledScanner {
    /// High-throughput coalesced scan: all files scanned in parallel,
    /// zero overhead for non-hit files.
    ///
    /// Architecture:
    ///   Phase 1: Parallel HS prefilter on raw bytes (no prep, no alloc)
    ///   Phase 2: Full extraction only on hit files (~5% of total)
    pub fn scan_coalesced(&self, chunks: &[keyhog_core::Chunk]) -> Vec<Vec<keyhog_core::RawMatch>> {
        use crate::hw_probe::ScanBackend;
        use rayon::prelude::*;

        // GPU path: try GPU coalesced scan first when available.
        #[cfg(feature = "gpu")]
        if self.gpu_pattern_set.is_some() && crate::hw_probe::probe_hardware().gpu_available {
            return self.scan_coalesced_gpu(chunks);
        }

        #[cfg(not(feature = "simd"))]
        {
            return chunks.iter().map(|c| self.scan(c)).collect();
        }

        #[cfg(feature = "simd")]
        {
            let Some(scanner) = &self.simd_prefilter else {
                return chunks.iter().map(|c| self.scan(c)).collect();
            };

            let ac_len = self.ac_map.len();

            // Phase 1: Parallel HS scan on RAW bytes. No prepare, no Arc, no alloc
            // for non-hit files. Thread-local scratch eliminates mutex contention.
            let triggers: Vec<(Vec<u64>, bool)> = chunks
                .par_iter()
                .map(|chunk| {
                    let data = chunk.data.as_bytes();

                    // HS scan on raw bytes.
                    let mut triggered = vec![0u64; ac_len.div_ceil(64)];
                    for (hs_id, _start, _end) in scanner.scan(data) {
                        let Some((_det, dedup_id, _grp)) = scanner.pattern_info(hs_id) else {
                            continue;
                        };
                        if let Some(orig) = self.hs_index_map.get(dedup_id) {
                            for &idx in orig {
                                if idx < ac_len {
                                    triggered[idx / 64] |= 1u64 << (idx % 64);
                                }
                            }
                        }
                    }
                    let has_hit = triggered.iter().any(|&w| w != 0);
                    (triggered, has_hit)
                })
                .collect();

            let hit_count = triggers.iter().filter(|(_, hit)| *hit).count();
            let total_hs_matches: usize = triggers
                .iter()
                .map(|(t, _)| t.iter().map(|w| w.count_ones() as usize).sum::<usize>())
                .sum();
            tracing::info!(
                files = chunks.len(),
                hits = hit_count,
                hs_matches = total_hs_matches,
                "coalesced scan phase 1 complete"
            );

            // Phase 2: Full extraction on hit files + multiline fallback (parallel).
            chunks
                .par_iter()
                .zip(triggers.into_par_iter())
                .map(|(chunk, (triggered, has_hit))| {
                    if has_hit {
                        let prepared = self.prepare_chunk(chunk);
                        return self.scan_prepared_with_triggered(
                            prepared,
                            ScanBackend::SimdCpu,
                            triggered,
                            None,
                        );
                    }
                    // Multiline fallback: files with concatenation indicators AND
                    // secret-related keywords may contain secrets split across lines
                    // that HS can't match on raw bytes. Only scan these selectively.
                    #[cfg(feature = "multiline")]
                    if crate::multiline::has_concatenation_indicators(&chunk.data)
                        && has_secret_keyword_fast(chunk.data.as_bytes())
                    {
                        return self.scan(chunk);
                    }

                    // Generic key=value fallback: run on SMALL non-hit files only.
                    // Large source files (>32KB) are almost never config; scanning them
                    // for generic assignments wastes CPU on Go/Java/Python framework code.
                    if chunk.data.len() <= 32 * 1024
                        && has_generic_assignment_keyword(chunk.data.as_bytes())
                    {
                        let code_lines: Vec<&str> = chunk.data.lines().collect();
                        let mut scan_state = crate::types::ScanState::default();
                        self.scan_generic_assignments(&code_lines, chunk, &mut scan_state);
                        let matches = scan_state.into_matches();
                        if !matches.is_empty() {
                            return matches;
                        }
                    }

                    Vec::new()
                })
                .collect()
        } // #[cfg(feature = "simd")] block
    } // scan_coalesced

    /// GPU coalesced scan via warpstate batch API.
    #[cfg(feature = "gpu")]
    pub fn scan_coalesced_gpu(
        &self,
        chunks: &[keyhog_core::Chunk],
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        use crate::hw_probe::ScanBackend;
        use warpstate::batch::{ScanItem, TaggedMatch};

        let Some(matcher) = self.gpu_matcher() else {
            #[cfg(feature = "simd")]
            return self.scan_coalesced(chunks);
            #[cfg(not(feature = "simd"))]
            return chunks.iter().map(|c| self.scan(c)).collect();
        };

        let items: Vec<ScanItem<'_>> = chunks
            .iter()
            .enumerate()
            .map(|(i, c)| ScanItem {
                id: i as u64,
                data: c.data.as_bytes(),
            })
            .collect();

        let tagged = match pollster::block_on(warpstate::batch::scan_batch_gpu(matcher, items)) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("GPU batch failed: {e}");
                #[cfg(feature = "simd")]
                return self.scan_coalesced(chunks);
                #[cfg(not(feature = "simd"))]
                return chunks.iter().map(|c| self.scan(c)).collect();
            }
        };

        let total_patterns = self.ac_map.len() + self.fallback.len();
        let mut per_chunk_triggers: Vec<Vec<u64>> = chunks
            .iter()
            .map(|_| vec![0u64; total_patterns.div_ceil(64)])
            .collect();

        for t in &tagged {
            let idx = t.source_id as usize;
            if idx < chunks.len() {
                let pid = t.matched.pattern_id as usize;
                if pid < total_patterns {
                    per_chunk_triggers[idx][pid / 64] |= 1u64 << (pid % 64);
                }
            }
        }

        use rayon::prelude::*;
        chunks
            .par_iter()
            .zip(per_chunk_triggers.into_par_iter())
            .map(|(chunk, triggered)| {
                if triggered.iter().all(|&w| w == 0) {
                    return Vec::new();
                }
                let prepared = self.prepare_chunk(chunk);
                self.scan_prepared_with_triggered(prepared, ScanBackend::Gpu, triggered, None)
            })
            .collect()
    }

    pub(crate) fn scan_inner(
        &self,
        chunk: &Chunk,
        backend: crate::hw_probe::ScanBackend,
        deadline: Option<std::time::Instant>,
    ) -> Vec<RawMatch> {
        let prepared = self.prepare_chunk(chunk);
        let triggered =
            self.collect_triggered_patterns_for_backend(&prepared.preprocessed.text, backend);
        self.scan_prepared_with_triggered(prepared, backend, triggered, deadline)
    }

    pub(crate) fn extract_matches(
        &self,
        entry: &CompiledPattern,
        preprocessed: &ScannerPreprocessedText,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        base_line: usize,
        base_offset: usize,
    ) {
        let detector = &self.detectors[entry.detector_index];
        if let Some(group) = entry.group {
            self.extract_grouped_matches(
                entry,
                detector,
                group,
                preprocessed,
                line_offsets,
                code_lines,
                documentation_lines,
                chunk,
                scan_state,
                base_line,
                base_offset,
            );
            return;
        }
        self.extract_plain_matches(
            entry,
            detector,
            preprocessed,
            line_offsets,
            code_lines,
            documentation_lines,
            chunk,
            scan_state,
            base_line,
            base_offset,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn extract_grouped_matches(
        &self,
        entry: &CompiledPattern,
        detector: &DetectorSpec,
        group: usize,
        preprocessed: &ScannerPreprocessedText,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        base_line: usize,
        base_offset: usize,
    ) {
        let search_text = &preprocessed.text;
        for caps in entry.regex.captures_iter(search_text) {
            let Some(full_match) = caps.get(FULL_MATCH_INDEX) else {
                continue;
            };
            let mut credential = caps
                .get(group)
                .map(|capture| capture.as_str())
                .unwrap_or_else(|| full_match.as_str());

            // If the captured group looks like a variable name rather than a value,
            // try to find a better capture group that contains the actual value.
            if looks_like_variable_name(credential) && caps.len() > 2 {
                for g in 1..caps.len() {
                    if g == group {
                        continue;
                    }
                    if let Some(candidate) = caps.get(g) {
                        let candidate_str = candidate.as_str();
                        if !looks_like_variable_name(candidate_str) && candidate_str.len() >= 8 {
                            credential = candidate_str;
                            break;
                        }
                    }
                }
            }

            self.process_match(
                entry,
                detector,
                search_text,
                preprocessed,
                line_offsets,
                code_lines,
                documentation_lines,
                chunk,
                scan_state,
                credential,
                full_match.start(),
                full_match.end(),
                base_line,
                base_offset,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn extract_plain_matches(
        &self,
        entry: &CompiledPattern,
        detector: &DetectorSpec,
        preprocessed: &ScannerPreprocessedText,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        base_line: usize,
        base_offset: usize,
    ) {
        let search_text = &preprocessed.text;
        for matched in entry.regex.find_iter(search_text) {
            self.process_match(
                entry,
                detector,
                search_text,
                preprocessed,
                line_offsets,
                code_lines,
                documentation_lines,
                chunk,
                scan_state,
                matched.as_str(),
                matched.start(),
                matched.end(),
                base_line,
                base_offset,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn process_match(
        &self,
        entry: &CompiledPattern,
        detector: &DetectorSpec,
        data: &str,
        preprocessed: &ScannerPreprocessedText,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        credential: &str,
        match_start: usize,
        match_end: usize,
        base_line: usize,
        base_offset: usize,
    ) {
        let line = match_line_number(preprocessed, line_offsets, match_start);
        if is_within_hex_context(data, match_start, match_end) {
            return;
        }
        if context::is_false_positive_context(
            code_lines,
            line.saturating_sub(PREVIOUS_LINE_DISTANCE),
            chunk.metadata.path.as_deref(),
        ) || context::is_false_positive_match_context(
            data,
            match_start,
            chunk.metadata.path.as_deref(),
        ) {
            return;
        }

        let inferred_context = context::infer_context_with_documentation(
            code_lines,
            line.saturating_sub(PREVIOUS_LINE_DISTANCE),
            chunk.metadata.path.as_deref(),
            documentation_lines,
        );
        if should_suppress_known_example_credential(
            credential,
            chunk.metadata.path.as_deref(),
            inferred_context,
        ) {
            return;
        }

        let companions = if !self.companions.is_empty() {
            self.match_companions(entry, preprocessed, line)
                .unwrap_or_default()
        } else {
            HashMap::new()
        };
        let entropy = match_entropy(credential.as_bytes());

        if detector.id.starts_with("generic-") && detector.id != "generic-private-key" {
            if entropy < 3.5 {
                return;
            }
            let camel_transitions = credential
                .as_bytes()
                .windows(2)
                .filter(|w| w[0].is_ascii_lowercase() && w[1].is_ascii_uppercase())
                .count();
            if camel_transitions >= 2 && !credential.chars().any(|ch| ch.is_ascii_digit()) {
                return;
            }
        }

        let Some(score_result) = self.match_confidence(
            entry,
            detector,
            code_lines,
            documentation_lines,
            chunk,
            credential,
            data,
            line,
            entropy,
            !companions.is_empty(),
            scan_state,
        ) else {
            return;
        };

        match score_result {
            MlScoreResult::Final(confidence) => {
                let raw_match = build_raw_match(
                    detector,
                    chunk,
                    credential,
                    companions,
                    match_start + base_offset,
                    line + base_line,
                    entropy,
                    confidence,
                    scan_state,
                );
                scan_state.push_match(raw_match, self.config.max_matches_per_chunk);
            }
            #[cfg(feature = "ml")]
            MlScoreResult::Pending {
                heuristic_conf,
                code_context,
                credential: pending_credential,
                ml_context,
            } => {
                let raw_match = build_raw_match(
                    detector,
                    chunk,
                    credential,
                    companions,
                    match_start + base_offset,
                    line + base_line,
                    entropy,
                    heuristic_conf,
                    scan_state,
                );
                scan_state.ml_pending.push(crate::types::MlPendingMatch {
                    raw_match,
                    heuristic_conf,
                    code_context,
                    credential: pending_credential,
                    ml_context,
                });
            }
        }
    }
}

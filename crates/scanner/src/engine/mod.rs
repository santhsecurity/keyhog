//! Core scanning engine implementation.

mod backend;
mod fallback;
mod hot_patterns;
mod scan;
mod windowed;

pub use windowed::{
    floor_char_boundary, line_number_for_offset, next_window_offset, record_window_match,
    window_chunk, window_end_offset,
};

use crate::compiler::*;
use crate::context::{self, CodeContext};
use crate::error::Result;
use crate::pipeline::*;
use crate::types::*;
use crate::unicode_hardening;
use aho_corasick::AhoCorasick;
use keyhog_core::{Chunk, DetectorSpec, RawMatch};
#[cfg(feature = "entropy")]
use keyhog_core::{MatchLocation, Severity};
#[cfg(feature = "ml")]
use sha2::Digest;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, OnceLock};
use warpstate::PatternSet;

/// Result of calculating a match's final confidence score.
pub enum MlScoreResult {
    /// Score is final and the match can be pushed immediately.
    Final(f64),
    #[cfg(feature = "ml")]
    /// ML scoring is deferred to a batch call at the end of the scan.
    Pending {
        heuristic_conf: f64,
        code_context: crate::context::CodeContext,
        credential: String,
        ml_context: String,
    },
}

/// A pre-compiled set of rules for fast execution.
pub struct CompiledScanner {
    pub(crate) ac: Option<PatternSet>,
    /// Complete pattern set (AC + fallback regexes) wired to the GPU matcher.
    pub(crate) gpu_pattern_set: Option<warpstate::PatternSet>,
    pub(crate) gpu_matcher: OnceLock<Option<warpstate::AutoMatcher>>,
    pub(crate) ac_map: Vec<CompiledPattern>,
    pub(crate) prefix_propagation: Vec<Vec<usize>>,
    pub(crate) fallback: Vec<(CompiledPattern, Vec<String>)>,
    pub(crate) companions: Vec<Vec<CompiledCompanion>>,
    pub(crate) detectors: Vec<DetectorSpec>,
    pub(crate) detector_to_patterns: Vec<Vec<usize>>,
    pub(crate) same_prefix_patterns: Vec<Vec<usize>>,
    #[allow(dead_code)]
    pub(crate) fallback_keyword_ac: Option<AhoCorasick>,
    #[allow(dead_code)]
    pub(crate) fallback_keyword_to_patterns: Vec<Vec<usize>>,
    #[cfg(feature = "simd")]
    pub(crate) simd_prefilter: Option<crate::simd::backend::HsScanner>,
    /// HS pattern ID → original ac_map indices.
    #[cfg(feature = "simd")]
    pub(crate) hs_index_map: Vec<Vec<usize>>,
    #[cfg(feature = "simdsieve")]
    pub(crate) simdsieve_prefilter: crate::simdsieve_prefilter::SimdPrefilter,
    pub config: ScannerConfig,
    pub alphabet_screen: Option<crate::alphabet_filter::AlphabetScreen>,
}

#[cfg(feature = "ml")]
pub fn cached_ml_score(
    scan_state: &mut ScanState,
    credential: &str,
    context: &str,
    config: &ScannerConfig,
) -> f64 {
    let mut hasher = sha2::Sha256::new();
    sha2::Digest::update(&mut hasher, credential.as_bytes());
    sha2::Digest::update(&mut hasher, [0u8]);
    sha2::Digest::update(&mut hasher, context.as_bytes());
    let digest = hasher.finalize();
    let mut digest_arr = [0u8; 32];
    digest_arr.copy_from_slice(&digest);

    let cache_key = (credential.to_string(), context.to_string());
    if let Some(score) = scan_state.ml_score_cache.get(&cache_key) {
        return *score;
    }

    let entry_bytes = credential.len() + context.len();
    while scan_state.ml_cache_bytes + entry_bytes > MAX_ML_CACHE_BYTES
        || scan_state.ml_score_cache.len() >= MAX_ML_CACHE_ENTRIES
    {
        if let Some(oldest) = scan_state.ml_cache_order.pop_front() {
            if scan_state.ml_score_cache.remove(&oldest).is_some() {
                scan_state.ml_cache_bytes = scan_state
                    .ml_cache_bytes
                    .saturating_sub(oldest.0.len() + oldest.1.len());
            }
        } else {
            break;
        }
    }

    let score = crate::ml_scorer::score_with_config(
        credential,
        context,
        &config.known_prefixes,
        &config.secret_keywords,
        &config.test_keywords,
        &config.placeholder_keywords,
    );
    scan_state.ml_score_cache.insert(cache_key.clone(), score);
    scan_state.ml_cache_order.push_back(cache_key);
    scan_state.ml_cache_bytes = scan_state.ml_cache_bytes.saturating_add(entry_bytes);
    score
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    let _ = assert_send_sync::<CompiledScanner>;
};

impl CompiledScanner {
    /// Compile all detector specs into a single scanner.
    #[must_use = "the scanner is expensive to compile — use it for scanning"]
    pub fn compile(detectors: Vec<DetectorSpec>) -> Result<Self> {
        let state = build_compile_state(&detectors)?;
        let ac = build_ac_pattern_set(&state.ac_literals)?;
        // Only compile GPU PatternSet if GPU hardware is actually available.
        let gpu_pattern_set = if crate::hw_probe::probe_hardware().gpu_available {
            build_gpu_pattern_set(&state.ac_literals)
        } else {
            None
        };
        let prefix_propagation = build_prefix_propagation(&state.ac_literals);
        let same_prefix_patterns = build_same_prefix_patterns(&state.ac_literals);
        let detector_to_patterns = build_detector_to_patterns(&state.ac_map, detectors.len());
        let (fallback_keyword_ac, fallback_keyword_to_patterns) =
            build_fallback_keyword_ac(&state.fallback);

        log_quality_warnings(&state.quality_warnings);

        #[cfg(feature = "simdsieve")]
        let simdsieve_prefilter = crate::simdsieve_prefilter::SimdPrefilter::new();

        #[cfg(feature = "simd")]
        let (simd_prefilter, hs_index_map) =
            backend::build_simd_scanner(&state.ac_map, &state.fallback)
                .map(|(s, m)| (Some(s), m))
                .unwrap_or((None, Vec::new()));

        let mut alphabet_targets = state.ac_literals.clone();
        for (_, keywords) in &state.fallback {
            alphabet_targets.extend(keywords.clone());
        }
        let alphabet_screen = if alphabet_targets.is_empty() {
            None
        } else {
            Some(crate::alphabet_filter::AlphabetScreen::new(
                &alphabet_targets,
            ))
        };

        Ok(Self {
            ac,
            gpu_pattern_set,
            gpu_matcher: OnceLock::new(),
            ac_map: state.ac_map,
            prefix_propagation,
            fallback: state.fallback,
            companions: state.companions,
            detectors,
            detector_to_patterns,
            same_prefix_patterns,
            fallback_keyword_ac,
            fallback_keyword_to_patterns,
            #[cfg(feature = "simd")]
            simd_prefilter,
            #[cfg(feature = "simd")]
            hs_index_map,
            #[cfg(feature = "simdsieve")]
            simdsieve_prefilter,
            config: ScannerConfig::default(),
            alphabet_screen,
        })
    }

    /// Apply a custom configuration to the compiled scanner.
    pub fn with_config(mut self, config: ScannerConfig) -> Self {
        self.config = config;
        self
    }

    /// Number of loaded detectors.
    pub fn detector_count(&self) -> usize {
        self.detectors.len()
    }

    /// Total number of patterns (AC + fallback).
    pub fn pattern_count(&self) -> usize {
        self.ac_map.len() + self.fallback.len()
    }

    /// Return the preferred backend for a file of the given size.
    #[must_use]
    pub fn select_backend_for_file(&self, file_size: u64) -> crate::hw_probe::ScanBackend {
        crate::hw_probe::select_backend(
            crate::hw_probe::probe_hardware(),
            file_size,
            self.pattern_count(),
        )
    }

    /// Return the steady-state backend label used for startup reporting.
    #[must_use]
    pub fn preferred_backend_label(&self) -> &'static str {
        self.select_backend_for_file(0).label()
    }

    /// Scan a chunk of text and return all raw credential matches.
    pub fn scan(&self, chunk: &Chunk) -> Vec<RawMatch> {
        self.scan_with_deadline(chunk, None)
    }

    /// Scan a chunk using a caller-selected backend.
    pub fn scan_with_backend(
        &self,
        chunk: &Chunk,
        backend: crate::hw_probe::ScanBackend,
    ) -> Vec<RawMatch> {
        self.scan_with_deadline_and_backend(chunk, None, Some(backend))
    }

    /// Scan multiple chunks using a caller-selected backend.
    pub fn scan_chunks_with_backend(
        &self,
        chunks: &[Chunk],
        backend: crate::hw_probe::ScanBackend,
    ) -> Vec<Vec<RawMatch>> {
        self.scan_chunks_with_backend_internal(chunks, backend)
    }

    /// Scan a chunk of text against all compiled detectors.
    pub fn scan_with_deadline(
        &self,
        chunk: &Chunk,
        deadline: Option<std::time::Instant>,
    ) -> Vec<RawMatch> {
        self.scan_with_deadline_and_backend(chunk, deadline, None)
    }

    pub fn scan_with_deadline_and_backend(
        &self,
        chunk: &Chunk,
        deadline: Option<std::time::Instant>,
        backend: Option<crate::hw_probe::ScanBackend>,
    ) -> Vec<RawMatch> {
        if let Some(path) = chunk.metadata.path.as_deref() {
            let filename = path.rsplit(['/', '\\']).next().unwrap_or(path);
            if filename == ".keyhog"
                || filename == ".keyhogignore"
                || path.split(['/', '\\']).any(|c| c == "detectors")
            {
                return Vec::new();
            }
        }

        if let Some(screen) = &self.alphabet_screen
            && !screen.screen(chunk.data.as_bytes())
        {
            return Vec::new();
        }

        #[cfg(feature = "simdsieve")]
        let _simdsieve_hint = if chunk.data.len() > 100_000 {
            let (should_scan, _confidence) =
                self.simdsieve_prefilter.quick_screen(chunk.data.as_bytes());
            should_scan
        } else {
            true
        };

        let selected_backend =
            backend.unwrap_or_else(|| self.select_backend_for_file(chunk.data.len() as u64));
        let mut matches = if chunk.data.len() > MAX_SCAN_CHUNK_BYTES {
            self.scan_windowed(chunk, deadline)
        } else {
            self.scan_inner(chunk, selected_backend, deadline)
        };

        self.scan_cross_chunk_fragments(chunk, &mut matches, deadline);

        #[cfg(feature = "decode")]
        if chunk.data.len() <= self.config.max_decode_bytes {
            let mut seen: HashSet<(String, String)> = matches
                .iter()
                .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
                .collect();
            for decoded_chunk in crate::decode::decode_chunk(
                chunk,
                self.config.max_decode_depth,
                self.config.validate_decode,
                deadline,
                self.alphabet_screen.as_ref(),
            ) {
                let decoded_matches = if decoded_chunk.data.len() > MAX_SCAN_CHUNK_BYTES {
                    self.scan_windowed(&decoded_chunk, deadline)
                } else {
                    let decoded_backend =
                        self.select_backend_for_file(decoded_chunk.data.len() as u64);
                    self.scan_inner(&decoded_chunk, decoded_backend, deadline)
                };
                for m in decoded_matches {
                    if seen.insert((m.detector_id.to_string(), m.credential.to_string())) {
                        matches.push(m);
                    }
                }
            }
        }

        matches
    }

    fn scan_cross_chunk_fragments(
        &self,
        chunk: &Chunk,
        matches: &mut Vec<RawMatch>,
        deadline: Option<std::time::Instant>,
    ) {
        static ASSIGN_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
            regex::Regex::new(
                r#"(?i)([a-z0-9_-]{2,32})\s*[:=]\s*["'`]([a-zA-Z0-9/+=_-]{4,})["'`](?:;|,)?$"#,
            )
            .expect("hardcoded regex must compile")
        });
        let assign_re = &*ASSIGN_RE;

        for (line_idx, line) in chunk.data.lines().enumerate() {
            if let Some(caps) = assign_re.captures(line) {
                let Some(var_name_match) = caps.get(1) else {
                    continue;
                };
                let Some(value_match) = caps.get(2) else {
                    continue;
                };

                let fragment = crate::fragment_cache::SecretFragment {
                    prefix: crate::multiline::extract_prefix(var_name_match.as_str()),
                    var_name: var_name_match.as_str().to_string(),
                    value: value_match.as_str().to_string(),
                    line: line_idx + 1,
                    path: chunk.metadata.path.clone(),
                };

                let candidates =
                    crate::fragment_cache::get_fragment_cache().record_and_reassemble(fragment);
                for candidate in candidates {
                    // Only reassemble candidates with enough entropy to be plausible secrets.
                    // Low-entropy reassemblies (concatenated variable names, prose) are noise.
                    let entropy = crate::pipeline::match_entropy(candidate.as_bytes());
                    if entropy < 3.0 || candidate.len() < 16 {
                        continue;
                    }

                    let dummy_chunk = Chunk {
                        data: format!("reassembled_key = \"{}\"", candidate),
                        metadata: chunk.metadata.clone(),
                    };

                    let backend = self.select_backend_for_file(dummy_chunk.data.len() as u64);
                    for mut reassembled_match in self.scan_inner(&dummy_chunk, backend, deadline) {
                        reassembled_match.detector_id =
                            format!("{}:reassembled", reassembled_match.detector_id).into();
                        matches.push(reassembled_match);
                    }
                }
            }
        }
    }

    fn expand_triggered_patterns(&self, triggered_patterns: &[u64]) -> Vec<u64> {
        let mut expanded = triggered_patterns.to_vec();
        for (word_idx, &word) in triggered_patterns.iter().enumerate() {
            if word == 0 {
                continue;
            }
            let mut bits = word;
            while bits != 0 {
                let bit = bits.trailing_zeros() as usize;
                let pat_idx = word_idx * 64 + bit;
                if pat_idx >= self.ac_map.len() {
                    break;
                }
                for &other_idx in &self.same_prefix_patterns[pat_idx] {
                    expanded[other_idx / 64] |= 1 << (other_idx % 64);
                }
                let det_idx = self.ac_map[pat_idx].detector_index;
                for &other_idx in &self.detector_to_patterns[det_idx] {
                    expanded[other_idx / 64] |= 1 << (other_idx % 64);
                }
                bits &= bits - 1; // clear lowest set bit
            }
        }
        expanded
    }

    #[allow(clippy::too_many_arguments)]
    fn extract_confirmed_patterns(
        &self,
        confirmed_patterns: &[usize],
        preprocessed: &ScannerPreprocessedText,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
    ) {
        for &pat_idx in confirmed_patterns {
            if let Some(deadline) = deadline
                && std::time::Instant::now() > deadline
            {
                break;
            }
            let entry = if pat_idx < self.ac_map.len() {
                &self.ac_map[pat_idx]
            } else {
                let fallback_idx = pat_idx - self.ac_map.len();
                if fallback_idx >= self.fallback.len() {
                    continue;
                }
                &self.fallback[fallback_idx].0
            };
            self.extract_matches(
                entry,
                preprocessed,
                line_offsets,
                code_lines,
                documentation_lines,
                chunk,
                scan_state,
                0,
                0,
            );
        }
    }

    #[cfg(feature = "ml")]
    fn apply_ml_batch_scores(&self, scan_state: &mut ScanState) {
        if scan_state.ml_pending.is_empty() {
            return;
        }

        let candidates: Vec<(String, String)> = scan_state
            .ml_pending
            .iter()
            .map(|pending| (pending.credential.clone(), pending.ml_context.clone()))
            .collect();

        let scores = crate::gpu::batch_ml_inference(&candidates, &self.config);
        let pending_matches: Vec<_> = scan_state.ml_pending.drain(..).collect();
        for (pending, ml_conf) in pending_matches.into_iter().zip(scores.into_iter()) {
            let mut final_score = (crate::types::ML_WEIGHT * ml_conf)
                + (crate::types::HEURISTIC_WEIGHT * pending.heuristic_conf);
            final_score = final_score.max(pending.heuristic_conf).max(ml_conf);

            if matches!(
                pending.code_context,
                crate::context::CodeContext::TestCode
                    | crate::context::CodeContext::Documentation
                    | crate::context::CodeContext::Comment
            ) && final_score < 0.95
            {
                final_score *= pending.code_context.confidence_multiplier();
            }

            let final_score =
                crate::confidence::apply_post_ml_penalties(final_score, &pending.credential);
            let final_score = crate::confidence::apply_path_confidence_penalties(
                final_score,
                pending.raw_match.location.file_path.as_deref(),
            );
            let final_score = if let Some(floor) =
                crate::confidence::known_prefix_confidence_floor(&pending.credential)
            {
                final_score.max(floor)
            } else {
                final_score
            };

            if !pending.code_context.should_hard_suppress(final_score) {
                let mut raw_match = pending.raw_match;
                raw_match.confidence = Some(final_score);
                scan_state.push_match(raw_match, self.config.max_matches_per_chunk);
            }
        }
    }
}

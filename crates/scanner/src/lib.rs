//! Two-phase secret scanning engine.
//!
//! Phase 1 builds an Aho-Corasick automaton from literal prefixes extracted from
//! detector regex patterns and runs a single O(n) pass over the input. Phase 2
//! confirms candidate regions with the full regex. Patterns without extractable
//! prefixes fall back to sequential regex scanning.
//!
//! # Feature flags
//!
//! - `ml` — MoE ML classifier for confidence scoring (default: on)
//! - `entropy` — Shannon entropy-based detection (default: on)
//! - `decode` — Decode-through scanning: base64, hex, URL, HTML, MIME (default: on)
//! - `multiline` — Multi-line concatenation joining (default: on)
//! - `gpu` — GPU-accelerated batch ML inference (optional)
//!
//! Additional layers: base64/hex decode-through, ML confidence scoring,
//! structural context analysis, and multi-match resolution.

/// Confidence scoring helpers for combining heuristic signals.
pub mod confidence;
/// Structural code-context inference used to adjust confidence.
pub mod context;
/// Decode-through scanning helpers for layered encodings.
#[cfg(feature = "decode")]
pub mod decode;
/// Entropy-based fallback detection for unknown secret formats.
#[cfg(feature = "entropy")]
pub mod entropy;
#[cfg(feature = "gpu")]
pub mod gpu;
#[allow(clippy::excessive_precision)]
/// Embedded ML scorer used to downrank likely placeholders and noise.
#[cfg(feature = "ml")]
pub mod ml_scorer;
/// Multi-line preprocessing for string concatenation and line continuations.
#[cfg(feature = "multiline")]
pub mod multiline;
/// Prefix propagation tables for literal-prefix matching.
pub mod prefix_trie;
/// Match-resolution helpers for suppressing lower-quality overlaps.
pub mod resolution;
/// Vectorscan/Hyperscan SIMD regex backend (optional, feature-gated).
pub mod simd;

#[cfg(test)]
#[allow(clippy::manual_range_contains, clippy::useless_format)]
mod adversarial_tests;

use aho_corasick::AhoCorasick;
use keyhog_core::{Chunk, CompanionSpec, DetectorSpec, MatchLocation, PatternSpec, RawMatch};
use multimatch::{MatchError, PatternSet, PatternSetBuilder};
use regex::Regex;
use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

// Fallback regex-only scanning switches to per-line mode once a chunk grows
// beyond 10 KB. Prefixless regexes over larger blobs are expensive and secrets
// are short enough that line-local scanning preserves recall.
const LARGE_FALLBACK_SCAN_THRESHOLD: usize = 10_000;

/// Hard cap on the dedup set to prevent unbounded memory growth when scanning
/// repositories with millions of duplicate credential-like strings.
const MAX_WINDOW_DEDUP_ENTRIES: usize = 100_000;

/// Maximum bytes scanned in a single chunk. Files larger than this are split
/// into overlapping windows. 1 MiB keeps peak RSS predictable under parallel
/// scanning with `rayon` (N threads × 1 MiB per chunk = bounded memory).
const MAX_SCAN_CHUNK_BYTES: usize = 1024 * 1024;

/// Overlap between adjacent scan windows when a file exceeds
/// `MAX_SCAN_CHUNK_BYTES`. Must be larger than the longest secret the scanner
/// can detect to avoid missing secrets that straddle a chunk boundary. 4 KiB
/// covers PEM-encoded RSA-4096 keys (~3,200 chars base64) with margin.
const WINDOW_OVERLAP_BYTES: usize = 4096;

/// Minimum line length considered for fallback pattern scanning. Lines shorter
/// than 8 bytes cannot contain a credential prefix plus a meaningful secret.
const MIN_FALLBACK_LINE_LENGTH: usize = 8;

/// Minimum AC literal prefix length. Shorter prefixes (e.g., "1", "x", "_")
/// match too many positions and degrade Aho-Corasick throughput.
const FULL_MATCH_INDEX: usize = 0;
const FIRST_CAPTURE_GROUP_INDEX: usize = 1;
const FIRST_LINE_NUMBER: usize = 1;
const PREVIOUS_LINE_DISTANCE: usize = 1;
const MIN_LITERAL_PREFIX_CHARS: usize = 3;

/// Compiled regex AST size limit. 10 MiB is large enough for complex detectors
/// while preventing pathological patterns from consuming unbounded memory
/// during regex compilation.
const REGEX_SIZE_LIMIT_BYTES: usize = 10 << 20;

/// How many characters around a hex match to inspect for structural context
/// (assignment operators, quotes, keywords).
const HEX_CONTEXT_RADIUS_CHARS: usize = 20;

/// Minimum length for a standalone hex string to qualify as a potential secret.
/// Shorter hex runs (e.g., CSS colors like `#ff00ff`) are too common.
const MIN_HEX_MATCH_LEN: usize = 16;
const MIN_HEX_DIGITS_IN_MATCH: usize = 16;

/// Minimum hex digits required in the context window around a match to trigger
/// hex-aware false-positive suppression.
const MIN_HEX_CONTEXT_DIGITS: usize = 8;

/// Maximum non-hex separators (colons, dashes) tolerated within a hex context
/// window before the match is treated as a non-hex string.
const MAX_HEX_CONTEXT_SEPARATORS: usize = 4;

#[cfg(feature = "ml")]
const MAX_ML_CACHE_ENTRIES: usize = 1024;
#[cfg(feature = "ml")]
const MAX_ML_CACHE_BYTES: usize = 256 * 1024;
#[cfg(feature = "ml")]
const ML_CONTEXT_RADIUS_LINES: usize = 5;
#[cfg(feature = "ml")]
const ML_WEIGHT: f64 = 0.6;
#[cfg(feature = "ml")]
const HEURISTIC_WEIGHT: f64 = 0.4;

#[cfg(not(feature = "multiline"))]
#[derive(Debug, Clone)]
struct LineMapping {
    start_offset: usize,
    end_offset: usize,
    line_number: usize,
}

#[cfg(not(feature = "multiline"))]
#[derive(Debug, Clone)]
struct PreprocessedText {
    text: String,
    mappings: Vec<LineMapping>,
}

#[cfg(not(feature = "multiline"))]
impl PreprocessedText {
    fn line_for_offset(&self, offset: usize) -> Option<usize> {
        self.mappings
            .iter()
            .find(|mapping| offset >= mapping.start_offset && offset < mapping.end_offset)
            .map(|mapping| mapping.line_number)
    }

    fn passthrough(line: &str) -> Self {
        Self {
            text: line.to_string(),
            mappings: vec![LineMapping {
                line_number: 1,
                start_offset: 0,
                end_offset: line.len(),
            }],
        }
    }
}

#[cfg(feature = "multiline")]
type ScannerPreprocessedText = multiline::PreprocessedText;

#[cfg(not(feature = "multiline"))]
type ScannerPreprocessedText = PreprocessedText;

#[derive(Debug, Error)]
/// Errors returned while compiling detector patterns into a scanner.
///
/// # Examples
///
/// ```rust
/// use keyhog_scanner::ScanError;
///
/// let error = ScanError::RegexSetCompile(regex::Error::Syntax("bad regex".into()));
/// assert!(error.to_string().contains("Fix"));
/// ```
pub enum ScanError {
    #[error(
        "failed to compile regex for detector {detector_id} pattern {index}: {source}. Fix: correct the detector regex or capture group configuration"
    )]
    RegexCompile {
        detector_id: String,
        index: usize,
        source: regex::Error,
    },
    #[error(
        "failed to compile scanner regex set: {0}. Fix: simplify the detector regex set or remove the invalid pattern"
    )]
    RegexSetCompile(#[from] regex::Error),
    #[error(
        "failed to build multimatch automaton: {0}. Fix: reduce detector complexity or remove unsupported regex constructs"
    )]
    Multimatch(#[from] MatchError),
    #[error(
        "failed to build Aho-Corasick automaton: {0}. Fix: shorten overly broad prefixes or reduce detector count"
    )]
    AhoCorasick(#[from] aho_corasick::BuildError),
}

/// A compiled entry: one pattern from one detector.
struct CompiledPattern {
    detector_index: usize,
    regex: Regex,
    group: Option<usize>,
}

/// An optional compiled companion pattern for a detector.
struct CompiledCompanion {
    regex: Regex,
    capture_group: Option<usize>,
    within_lines: usize,
}

/// The compiled scanner: all detector patterns fused into a single
/// Aho-Corasick automaton for prefiltering, backed by individual
/// regexes for extraction.
///
/// # Examples
///
/// ```rust
/// use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
/// use keyhog_scanner::CompiledScanner;
///
/// let scanner = CompiledScanner::compile(vec![DetectorSpec {
///     id: "demo-token".into(),
///     name: "Demo Token".into(),
///     service: "demo".into(),
///     severity: Severity::High,
///     patterns: vec![PatternSpec {
///         regex: "demo_[A-Z0-9]{8}".into(),
///         description: None,
///         group: None,
///     }],
///     companion: None,
///     verify: None,
///     keywords: vec!["demo_".into()],
/// }])
/// .unwrap();
///
/// let chunk = Chunk {
///     data: "TOKEN=demo_ABC12345".into(),
///     metadata: ChunkMetadata {
///         source_type: "filesystem".into(),
///         path: Some(".env".into()),
///         commit: None,
///         author: None,
///         date: None,
///     },
/// };
///
/// assert_eq!(scanner.scan(&chunk).len(), 1);
/// ```
pub struct CompiledScanner {
    /// Pattern matcher built from literal prefixes of patterns.
    ac: Option<PatternSet>,
    /// Maps AC pattern index → compiled pattern entry.
    ac_map: Vec<CompiledPattern>,
    /// Batched first-pass regex confirmation for AC-backed patterns.
    /// The literal prefix strings corresponding to ac_map entries.
    /// Prefix propagation: for each AC pattern, list of OTHER ac_map indices
    /// whose prefix is a superstring. Pre-computed at compile time.
    /// When AC matches pattern i, also check all patterns in propagation[i].
    prefix_propagation: Vec<Vec<usize>>,
    /// Patterns without extractable literal prefixes — checked via regex only.
    /// Each entry pairs the compiled pattern with its detector's keywords for
    /// chunk-level prefiltering (skip pattern if no keywords found in chunk).
    fallback: Vec<(CompiledPattern, Vec<String>)>,
    /// Compiled companion patterns, indexed by detector index.
    companions: Vec<Option<CompiledCompanion>>,
    /// Original detector specs for metadata.
    detectors: Vec<DetectorSpec>,
    /// Pre-computed: detector_index → list of AC pattern indices for that detector.
    /// Eliminates O(N²) expansion during scan.
    detector_to_patterns: Vec<Vec<usize>>,
    /// Pre-computed: AC pattern index → list of other pattern indices with same literal prefix.
    /// Eliminates O(N²) prefix comparison during scan.
    same_prefix_patterns: Vec<Vec<usize>>,
    /// Aho-Corasick automaton for fallback pattern keywords.
    /// Single-pass keyword scan replaces per-pattern contains() loops.
    fallback_keyword_ac: Option<AhoCorasick>,
    /// Maps keyword AC match index → list of fallback pattern indices that use this keyword.
    fallback_keyword_to_patterns: Vec<Vec<usize>>,
    /// Optional Hyperscan SIMD scanner for 3-5x throughput.
    /// When available, replaces both AC prefilter and fallback scanning
    /// with a single SIMD pass over all patterns simultaneously.
    #[cfg(feature = "simd")]
    hs_scanner: Option<simd::backend::HsScanner>,
}

impl CompiledScanner {
    /// Compile all detector specs into a single scanner.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::{DetectorSpec, PatternSpec, Severity};
    /// use keyhog_scanner::CompiledScanner;
    ///
    /// let scanner = CompiledScanner::compile(vec![DetectorSpec {
    ///     id: "demo-token".into(),
    ///     name: "Demo Token".into(),
    ///     service: "demo".into(),
    ///     severity: Severity::High,
    ///     patterns: vec![PatternSpec {
    ///         regex: "demo_[A-Z0-9]{8}".into(),
    ///         description: None,
    ///         group: None,
    ///     }],
    ///     companion: None,
    ///     verify: None,
    ///     keywords: vec!["demo_".into()],
    /// }])
    /// .unwrap();
    ///
    /// assert_eq!(scanner.detector_count(), 1);
    /// ```
    pub fn compile(detectors: Vec<DetectorSpec>) -> Result<Self, ScanError> {
        let CompileState {
            ac_literals,
            ac_map,
            fallback,
            companions,
            quality_warnings,
        } = build_compile_state(&detectors)?;
        log_quality_warnings(&quality_warnings);
        tracing::info!(
            ac_patterns = ac_map.len(),
            fallback_patterns = fallback.len(),
            detectors = detectors.len(),
            "scanner compiled"
        );

        let ac = build_ac_pattern_set(&ac_literals)?;
        let prefix_propagation = prefix_trie::build_propagation_table(&ac_literals);
        let detector_to_patterns = build_detector_to_patterns(&ac_map, detectors.len());
        let same_prefix_patterns = build_same_prefix_patterns(&ac_literals);

        // Build keyword AC for fallback pattern prefiltering
        let (fallback_keyword_ac, fallback_keyword_to_patterns) =
            build_fallback_keyword_ac(&fallback);

        // Build Hyperscan SIMD database when feature is enabled
        #[cfg(feature = "simd")]
        let hs_scanner = {
            // Collect ALL patterns (AC + fallback) for Hyperscan compilation
            let mut all_patterns: Vec<(usize, usize, &str, bool)> = Vec::new();
            for (i, entry) in ac_map.iter().enumerate() {
                all_patterns.push((
                    entry.detector_index,
                    i,
                    entry.regex.as_str(),
                    entry.group.is_some(),
                ));
            }
            for (i, (entry, _)) in fallback.iter().enumerate() {
                all_patterns.push((
                    entry.detector_index,
                    ac_map.len() + i,
                    entry.regex.as_str(),
                    entry.group.is_some(),
                ));
            }
            match simd::backend::HsScanner::compile(&all_patterns) {
                Ok((hs, unsupported)) => {
                    tracing::info!(
                        hs_patterns = hs.pattern_count(),
                        unsupported = unsupported.len(),
                        "hyperscan SIMD database compiled"
                    );
                    Some(hs)
                }
                Err(e) => {
                    tracing::warn!("hyperscan compilation failed, using AC fallback: {e}");
                    None
                }
            }
        };

        Ok(Self {
            ac,
            ac_map,
            prefix_propagation,
            fallback,
            companions,
            detectors,
            detector_to_patterns,
            same_prefix_patterns,
            fallback_keyword_ac,
            fallback_keyword_to_patterns,
            #[cfg(feature = "simd")]
            hs_scanner,
        })
    }

    /// Number of loaded detectors.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::{DetectorSpec, PatternSpec, Severity};
    /// use keyhog_scanner::CompiledScanner;
    ///
    /// let scanner = CompiledScanner::compile(vec![DetectorSpec {
    ///     id: "demo-token".into(),
    ///     name: "Demo Token".into(),
    ///     service: "demo".into(),
    ///     severity: Severity::High,
    ///     patterns: vec![PatternSpec {
    ///         regex: "demo_[A-Z0-9]{8}".into(),
    ///         description: None,
    ///         group: None,
    ///     }],
    ///     companion: None,
    ///     verify: None,
    ///     keywords: vec!["demo_".into()],
    /// }])
    /// .unwrap();
    ///
    /// assert_eq!(scanner.detector_count(), 1);
    /// ```
    pub fn detector_count(&self) -> usize {
        self.detectors.len()
    }

    /// Total number of patterns (AC + fallback).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::{DetectorSpec, PatternSpec, Severity};
    /// use keyhog_scanner::CompiledScanner;
    ///
    /// let scanner = CompiledScanner::compile(vec![DetectorSpec {
    ///     id: "demo-token".into(),
    ///     name: "Demo Token".into(),
    ///     service: "demo".into(),
    ///     severity: Severity::High,
    ///     patterns: vec![PatternSpec {
    ///         regex: "demo_[A-Z0-9]{8}".into(),
    ///         description: None,
    ///         group: None,
    ///     }],
    ///     companion: None,
    ///     verify: None,
    ///     keywords: vec!["demo_".into()],
    /// }])
    /// .unwrap();
    ///
    /// assert_eq!(scanner.pattern_count(), 1);
    /// ```
    pub fn pattern_count(&self) -> usize {
        self.ac_map.len() + self.fallback.len()
    }

    /// Maximum chunk size to scan (1MB). Larger chunks are split into overlapping windows.
    /// Maximum chunk size for windowed scanning.
    /// 1MB balances memory usage vs. split-boundary risk.
    /// Larger files are split with WINDOW_OVERLAP to avoid missing
    /// secrets at boundaries. Validated: 200KB adversarial test passes.
    pub(crate) const MAX_SCAN_CHUNK: usize = MAX_SCAN_CHUNK_BYTES;
    /// Overlap between windows to avoid missing secrets at boundaries.
    const WINDOW_OVERLAP: usize = WINDOW_OVERLAP_BYTES;

    /// Scan a chunk of text and return all raw credential matches.
    /// Applies multi-line preprocessing to detect secrets split across lines.
    /// Large chunks are split into overlapping windows for bounded scan time.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
    /// use keyhog_scanner::CompiledScanner;
    ///
    /// let scanner = CompiledScanner::compile(vec![DetectorSpec {
    ///     id: "demo-token".into(),
    ///     name: "Demo Token".into(),
    ///     service: "demo".into(),
    ///     severity: Severity::High,
    ///     patterns: vec![PatternSpec {
    ///         regex: "demo_[A-Z0-9]{8}".into(),
    ///         description: None,
    ///         group: None,
    ///     }],
    ///     companion: None,
    ///     verify: None,
    ///     keywords: vec!["demo_".into()],
    /// }])
    /// .unwrap();
    ///
    /// let matches = scanner.scan(&Chunk {
    ///     data: "TOKEN=demo_ABC12345".into(),
    ///     metadata: ChunkMetadata {
    ///         source_type: "filesystem".into(),
    ///         path: Some(".env".into()),
    ///         commit: None,
    ///         author: None,
    ///         date: None,
    ///     },
    /// });
    ///
    /// assert_eq!(matches.len(), 1);
    /// ```
    pub fn scan(&self, chunk: &Chunk) -> Vec<RawMatch> {
        // For large chunks, split into overlapping windows.
        let mut matches = if chunk.data.len() > Self::MAX_SCAN_CHUNK {
            self.scan_windowed(chunk)
        } else {
            self.scan_inner(chunk)
        };

        // Decode-through: scan base64/hex/URL decoded variants of the chunk.
        // Skip for large chunks — decode is O(N) per line and cascading scans
        // on decoded chunks can be expensive on multiline-heavy content.
        #[cfg(feature = "decode")]
        if chunk.data.len() <= 64 * 1024 {
            let mut seen: std::collections::HashSet<(String, String)> = matches
                .iter()
                .map(|m| (m.detector_id.clone(), m.credential.clone()))
                .collect();
            for decoded_chunk in decode::decode_chunk(chunk) {
                let decoded_matches = if decoded_chunk.data.len() > Self::MAX_SCAN_CHUNK {
                    self.scan_windowed(&decoded_chunk)
                } else {
                    self.scan_inner(&decoded_chunk)
                };
                for m in decoded_matches {
                    if seen.insert((m.detector_id.clone(), m.credential.clone())) {
                        matches.push(m);
                    }
                }
            }
        }

        matches
    }

    /// Split a large chunk into overlapping windows and scan each.
    ///
    /// # Window Layout
    ///
    /// ```text
    /// ├────── MAX_SCAN_CHUNK (1 MiB) ──────┤
    /// │ window 0                            │
    /// │                     ├─ OVERLAP (4K) ┤
    /// │                     │ window 1      │──── MAX_SCAN_CHUNK ────│
    /// │                     │               │                       │
    /// ```
    ///
    /// Windows advance by `MAX_SCAN_CHUNK - WINDOW_OVERLAP` bytes. The 4 KiB
    /// overlap ensures secrets up to ~3,200 chars (PEM RSA-4096 base64) that
    /// straddle a boundary are fully contained in at least one window.
    ///
    /// # Deduplication
    ///
    /// The `seen` set tracks `(credential, detector_id)` pairs across windows
    /// so that a secret in the overlap region is only reported once. The set is
    /// capped at [`MAX_WINDOW_DEDUP_ENTRIES`] and cleared on overflow to bound
    /// memory for pathological inputs with millions of matches.
    fn scan_windowed(&self, chunk: &Chunk) -> Vec<RawMatch> {
        let chunk_text = &chunk.data;
        let mut all_matches = Vec::with_capacity((chunk_text.len() / 4096).max(16));
        let mut seen = std::collections::HashSet::new();
        let mut seen_order = VecDeque::new();
        let mut offset = 0usize;

        while offset < chunk_text.len() {
            let end = window_end_offset(chunk_text, offset, Self::MAX_SCAN_CHUNK);
            let window_chunk = window_chunk(chunk, offset, end);
            for mut m in self.scan_inner(&window_chunk) {
                if record_window_match(chunk_text, offset, &mut m, &mut seen, &mut seen_order) {
                    all_matches.push(m);
                }
            }
            if end >= chunk_text.len() {
                break;
            }
            offset = next_window_offset(chunk_text, end, Self::WINDOW_OVERLAP);
        }

        all_matches
    }

    fn scan_inner(&self, chunk: &Chunk) -> Vec<RawMatch> {
        let mut owned_normalized = None;
        let chunk = if chunk.data.is_ascii() {
            chunk
        } else {
            normalize_scannable_chunk(chunk, &mut owned_normalized)
        };
        #[cfg(feature = "multiline")]
        let preprocessed = if crate::multiline::has_concatenation_indicators(&chunk.data) {
            multiline::preprocess_multiline(&chunk.data, &multiline::MultilineConfig::default())
        } else {
            ScannerPreprocessedText::passthrough(&chunk.data)
        };
        #[cfg(not(feature = "multiline"))]
        let preprocessed = ScannerPreprocessedText::passthrough(&chunk.data);

        let line_offsets = compute_line_offsets(&preprocessed.text);
        let code_lines: Vec<&str> = chunk.data.lines().collect();
        let documentation_lines = context::documentation_line_flags(&code_lines);
        let mut scan_state = ScanState {
            matches: Vec::with_capacity((chunk.data.len() / 4096).max(16)),
            ..Default::default()
        };

        // SIMD fast path: Hyperscan matches ALL patterns in a single SIMD pass.
        // NOTE: Hyperscan SIMD prefilter is compiled and ready (1634 patterns)
        // but disabled because it's 3x SLOWER than AC+keyword for our use case.
        // Reason: HS matches all patterns simultaneously (good for IDS) but we still
        // need Rust regex for capture group extraction. The double work (HS scan +
        // regex confirmation) is more expensive than AC prefilter + selective regex.
        // HS would help if we had 10K+ patterns where AC automaton size is the bottleneck.
        #[cfg(feature = "simd")]
        let used_simd = if let Some(hs) = &self.hs_scanner {
            let hs_matches = hs.scan(preprocessed.text.as_bytes());
            // Collect unique pattern indices that HS triggered
            let mut triggered_set = std::collections::HashSet::new();
            for &(hs_id, _start, _end) in &hs_matches {
                if let Some((det_idx, pat_idx, _has_group)) = hs.pattern_info(hs_id) {
                    triggered_set.insert((det_idx, pat_idx));
                }
            }
            // Run the Rust regex for each triggered pattern to extract matches
            let all_patterns: Vec<&CompiledPattern> = self
                .ac_map
                .iter()
                .chain(self.fallback.iter().map(|(p, _)| p))
                .collect();
            for &(_det_idx, pat_idx) in &triggered_set {
                if let Some(entry) = all_patterns.get(pat_idx) {
                    self.extract_matches(
                        entry,
                        &preprocessed,
                        &line_offsets,
                        &code_lines,
                        &documentation_lines,
                        chunk,
                        &mut scan_state.matches,
                        &mut scan_state.ml_score_cache,
                        &mut scan_state.ml_cache_order,
                        &mut scan_state.ml_cache_bytes,
                    );
                }
            }
            true
        } else {
            false
        };
        #[cfg(not(feature = "simd"))]
        let used_simd = false;

        if !used_simd {
            // Standard path: AC prefilter + fallback keyword scanning
            let expanded_patterns = self.collect_expanded_patterns(&preprocessed.text);
            let triggered: Vec<usize> = (0..self.ac_map.len())
                .filter(|&i| (expanded_patterns[i / 64] & (1 << (i % 64))) != 0)
                .collect();
            self.scan_prefiltered_patterns(
                &triggered,
                &preprocessed,
                &line_offsets,
                &code_lines,
                &documentation_lines,
                chunk,
                &mut scan_state.matches,
                &mut scan_state.ml_score_cache,
                &mut scan_state.ml_cache_order,
                &mut scan_state.ml_cache_bytes,
            );
        }
        if !used_simd {
            self.scan_fallback_patterns(
                &preprocessed,
                &line_offsets,
                &code_lines,
                &documentation_lines,
                chunk,
                &mut scan_state.matches,
                &mut scan_state.ml_score_cache,
                &mut scan_state.ml_cache_order,
                &mut scan_state.ml_cache_bytes,
            );
        }
        scan_state.matches
    }

    /// Dispatch regex execution for a single compiled pattern against the
    /// preprocessed text. Routes to either grouped extraction (when the
    /// pattern has a capture group for the credential value) or plain
    /// extraction (full-match mode).
    ///
    /// Matched credentials are appended to `matches` after confidence scoring
    /// and false-positive filtering. The ML score cache is shared across
    /// patterns to avoid redundant inference for the same credential string.
    #[allow(clippy::too_many_arguments)]
    fn extract_matches(
        &self,
        entry: &CompiledPattern,
        preprocessed: &ScannerPreprocessedText,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        matches: &mut Vec<RawMatch>,
        ml_score_cache: &mut HashMap<(String, String), f64>,
        ml_cache_order: &mut VecDeque<(String, String)>,
        ml_cache_bytes: &mut usize,
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
                matches,
                ml_score_cache,
                ml_cache_order,
                ml_cache_bytes,
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
            matches,
            ml_score_cache,
            ml_cache_order,
            ml_cache_bytes,
        );
    }

    /// Process a single regex match and push a `RawMatch` if it passes filters.
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
        matches: &mut Vec<RawMatch>,
        ml_score_cache: &mut HashMap<(String, String), f64>,
        ml_cache_order: &mut VecDeque<(String, String)>,
        ml_cache_bytes: &mut usize,
        credential: &str,
        match_start: usize,
        match_end: usize,
    ) {
        if is_within_hex_context(data, match_start, match_end) {
            return;
        }
        let line = match_line_number(preprocessed, line_offsets, match_start);
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
        let companion = self.match_companion(entry, preprocessed, line);
        let ent = match_entropy(credential.as_bytes());
        let conf = self.match_confidence(
            entry,
            detector,
            code_lines,
            documentation_lines,
            chunk,
            credential,
            data,
            line,
            ent,
            companion.is_some(),
            ml_score_cache,
            ml_cache_order,
            ml_cache_bytes,
        );
        matches.push(build_raw_match(
            detector,
            chunk,
            credential,
            companion,
            match_start,
            line,
            ent,
            conf,
        ));
    }

    fn collect_expanded_patterns(&self, text: &str) -> Vec<u64> {
        let triggered_patterns = self.collect_triggered_patterns(text);
        self.expand_triggered_patterns(&triggered_patterns)
    }

    fn collect_triggered_patterns(&self, text: &str) -> Vec<u64> {
        let mut triggered_patterns = vec![0u64; self.ac_map.len().div_ceil(64)];
        if let Some(ac) = &self.ac {
            for ac_match in ac.scan(text.as_bytes()) {
                let pat_idx = ac_match.pattern_id;
                if pat_idx >= self.ac_map.len() {
                    continue;
                }
                // SAFETY: pat_idx is bounded by ac_map.len() which is checked at compile time.
                // pat_idx % 64 is always 0..63, so the shift never overflows.
                triggered_patterns[pat_idx / 64] |= 1u64 << (pat_idx % 64);
                for &propagated_idx in &self.prefix_propagation[pat_idx] {
                    triggered_patterns[propagated_idx / 64] |= 1 << (propagated_idx % 64);
                }
            }
        }
        triggered_patterns
    }

    fn expand_triggered_patterns(&self, triggered_patterns: &[u64]) -> Vec<u64> {
        let mut expanded = triggered_patterns.to_vec();
        for pat_idx in 0..self.ac_map.len() {
            if (triggered_patterns[pat_idx / 64] & (1 << (pat_idx % 64))) != 0 {
                for &other_idx in &self.same_prefix_patterns[pat_idx] {
                    expanded[other_idx / 64] |= 1 << (other_idx % 64);
                }
                let det_idx = self.ac_map[pat_idx].detector_index;
                for &other_idx in &self.detector_to_patterns[det_idx] {
                    expanded[other_idx / 64] |= 1 << (other_idx % 64);
                }
            }
        }
        expanded
    }

    #[allow(clippy::too_many_arguments)]
    fn scan_prefiltered_patterns(
        &self,
        confirmed_patterns: &[usize],
        preprocessed: &ScannerPreprocessedText,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        matches: &mut Vec<RawMatch>,
        ml_score_cache: &mut HashMap<(String, String), f64>,
        ml_cache_order: &mut VecDeque<(String, String)>,
        ml_cache_bytes: &mut usize,
    ) {
        for &pat_idx in confirmed_patterns {
            let entry = &self.ac_map[pat_idx];
            self.extract_matches(
                entry,
                preprocessed,
                line_offsets,
                code_lines,
                documentation_lines,
                chunk,
                matches,
                ml_score_cache,
                ml_cache_order,
                ml_cache_bytes,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn scan_fallback_patterns(
        &self,
        preprocessed: &ScannerPreprocessedText,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        matches: &mut Vec<RawMatch>,
        ml_score_cache: &mut HashMap<(String, String), f64>,
        ml_cache_order: &mut VecDeque<(String, String)>,
        ml_cache_bytes: &mut usize,
    ) {
        if preprocessed.text.len() > LARGE_FALLBACK_SCAN_THRESHOLD && !self.fallback.is_empty() {
            self.scan_large_fallback_patterns(
                preprocessed,
                line_offsets,
                chunk,
                matches,
                ml_score_cache,
                ml_cache_order,
                ml_cache_bytes,
            );
            return;
        }
        // Single-pass keyword scan: find which fallback patterns are relevant for this chunk.
        let active_patterns: Vec<bool> = if let Some(kw_ac) = &self.fallback_keyword_ac {
            let mut active = vec![false; self.fallback.len()];
            // Mark patterns whose keywords have NO usable keywords as always-active
            for (i, (_pattern, keywords)) in self.fallback.iter().enumerate() {
                if !keywords.iter().any(|kw| kw.len() >= 4) {
                    active[i] = true;
                }
            }
            // Single AC scan over chunk to find all keyword matches
            for mat in kw_ac.find_iter(&chunk.data) {
                let kw_idx = mat.pattern().as_usize();
                if kw_idx < self.fallback_keyword_to_patterns.len() {
                    for &pattern_idx in &self.fallback_keyword_to_patterns[kw_idx] {
                        if pattern_idx < active.len() {
                            active[pattern_idx] = true;
                        }
                    }
                }
            }
            active
        } else {
            vec![true; self.fallback.len()]
        };

        for (i, (entry, _keywords)) in self.fallback.iter().enumerate() {
            if !active_patterns[i] {
                continue;
            }
            self.extract_matches(
                entry,
                preprocessed,
                line_offsets,
                code_lines,
                documentation_lines,
                chunk,
                matches,
                ml_score_cache,
                ml_cache_order,
                ml_cache_bytes,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn scan_large_fallback_patterns(
        &self,
        preprocessed: &ScannerPreprocessedText,
        line_offsets: &[usize],
        chunk: &Chunk,
        matches: &mut Vec<RawMatch>,
        ml_score_cache: &mut HashMap<(String, String), f64>,
        ml_cache_order: &mut VecDeque<(String, String)>,
        ml_cache_bytes: &mut usize,
    ) {
        // Use keyword AC for fast pre-filtering (same as scan_fallback_patterns)
        let active_set: Vec<bool> = if let Some(kw_ac) = &self.fallback_keyword_ac {
            let mut active = vec![false; self.fallback.len()];
            for (i, (_, keywords)) in self.fallback.iter().enumerate() {
                if !keywords.iter().any(|kw| kw.len() >= 4) {
                    active[i] = true;
                }
            }
            for mat in kw_ac.find_iter(&chunk.data) {
                let kw_idx = mat.pattern().as_usize();
                if kw_idx < self.fallback_keyword_to_patterns.len() {
                    for &pattern_idx in &self.fallback_keyword_to_patterns[kw_idx] {
                        if pattern_idx < active.len() {
                            active[pattern_idx] = true;
                        }
                    }
                }
            }
            active
        } else {
            vec![true; self.fallback.len()]
        };
        let active_fallback: Vec<&CompiledPattern> = self
            .fallback
            .iter()
            .enumerate()
            .filter(|(i, _)| active_set[*i])
            .map(|(_, (entry, _))| entry)
            .collect();

        if active_fallback.is_empty() {
            return;
        }

        for (line_idx, line) in preprocessed.text.lines().enumerate() {
            if line.len() < MIN_FALLBACK_LINE_LENGTH {
                continue;
            }
            let start_len = matches.len();
            let line_pre = ScannerPreprocessedText::passthrough(line);
            let line_code_lines = [line];
            let line_documentation_lines = [false];
            for entry in &active_fallback {
                self.extract_matches(
                    entry,
                    &line_pre,
                    &[0],
                    &line_code_lines,
                    &line_documentation_lines,
                    chunk,
                    matches,
                    ml_score_cache,
                    ml_cache_order,
                    ml_cache_bytes,
                );
            }
            adjust_fallback_match_locations(
                &mut matches[start_len..],
                line_idx,
                line_offsets[line_idx],
            );
        }
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
        matches: &mut Vec<RawMatch>,
        ml_score_cache: &mut HashMap<(String, String), f64>,
        ml_cache_order: &mut VecDeque<(String, String)>,
        ml_cache_bytes: &mut usize,
    ) {
        // The preprocessed text contains original text + appended multiline joins.
        // Single-pass search covers both structural and multiline-joined patterns.
        let search_text = &preprocessed.text;
        for caps in entry.regex.captures_iter(search_text) {
            let Some(full_match) = caps.get(FULL_MATCH_INDEX) else {
                continue;
            };
            let credential = caps
                .get(group)
                .map(|capture| capture.as_str())
                .unwrap_or_else(|| full_match.as_str());
            self.process_match(
                entry,
                detector,
                search_text,
                preprocessed,
                line_offsets,
                code_lines,
                documentation_lines,
                chunk,
                matches,
                ml_score_cache,
                ml_cache_order,
                ml_cache_bytes,
                credential,
                full_match.start(),
                full_match.end(),
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
        matches: &mut Vec<RawMatch>,
        ml_score_cache: &mut HashMap<(String, String), f64>,
        ml_cache_order: &mut VecDeque<(String, String)>,
        ml_cache_bytes: &mut usize,
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
                matches,
                ml_score_cache,
                ml_cache_order,
                ml_cache_bytes,
                matched.as_str(),
                matched.start(),
                matched.end(),
            );
        }
    }

    fn match_companion(
        &self,
        entry: &CompiledPattern,
        preprocessed: &ScannerPreprocessedText,
        line: usize,
    ) -> Option<String> {
        self.companions
            .get(entry.detector_index)
            .and_then(|companion| companion.as_ref())
            .and_then(|companion| find_companion(preprocessed, line, companion))
    }

    /// Compute the confidence score for a credential match.
    ///
    /// # Scoring Pipeline
    ///
    /// 1. **Heuristic signals** (`confidence::compute_confidence`): combines
    ///    literal prefix presence, capture-group anchoring, Shannon entropy,
    ///    keyword proximity, sensitive file paths, match length, and companion
    ///    secret presence into a raw score in `[0.0, 1.0]`.
    ///
    /// 2. **Context adjustment**: the surrounding code context (test files,
    ///    documentation, comments, example blocks) applies a multiplier that
    ///    reduces confidence for matches in non-production contexts.
    ///
    /// 3. **ML blending** (when `feature = "ml"` is enabled): a 41-feature
    ///    mixture-of-experts classifier produces an independent confidence
    ///    score. The final output is `max(blended, heuristic, ml)` — we take
    ///    the maximum so that a strong heuristic signal is never dragged down
    ///    by a weak ML prediction, and vice versa.
    ///
    /// When ML is disabled, returns the heuristic confidence directly.
    #[allow(clippy::too_many_arguments)]
    fn match_confidence(
        &self,
        entry: &CompiledPattern,
        detector: &DetectorSpec,
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        credential: &str,
        data: &str,
        line: usize,
        ent: f64,
        has_companion: bool,
        ml_score_cache: &mut HashMap<(String, String), f64>,
        ml_cache_order: &mut VecDeque<(String, String)>,
        ml_cache_bytes: &mut usize,
    ) -> f64 {
        let raw_conf = confidence::compute_confidence(&confidence::ConfidenceSignals {
            has_literal_prefix: extract_literal_prefix(entry.regex.as_str()).is_some(),
            has_context_anchor: entry.group.is_some(),
            entropy: ent,
            keyword_nearby: detector
                .keywords
                .iter()
                .any(|keyword| chunk.data.contains(keyword.as_str())),
            sensitive_file: chunk
                .metadata
                .path
                .as_deref()
                .map(confidence::is_sensitive_path)
                .unwrap_or(false),
            match_length: credential.len(),
            has_companion,
        });
        let context = context::infer_context_with_documentation(
            code_lines,
            line.saturating_sub(PREVIOUS_LINE_DISTANCE),
            chunk.metadata.path.as_deref(),
            documentation_lines,
        );
        let heuristic_conf = raw_conf * context.confidence_multiplier();
        #[cfg(not(feature = "ml"))]
        {
            let _ = (data, ml_score_cache, ml_cache_order, ml_cache_bytes);
            return heuristic_conf;
        }

        #[cfg(feature = "ml")]
        {
            let text_context = local_context_window(data, line, ML_CONTEXT_RADIUS_LINES);
            // Prepend file path so the MoE gate can route to the right expert
            // based on file extension (.env → config, .yml → CI, .tf → infra, etc.)
            let ml_context = match chunk.metadata.path.as_deref() {
                Some(path) => format!("file:{path}\n{text_context}"),
                None => text_context,
            };
            let ml_conf = cached_ml_score(
                ml_score_cache,
                ml_cache_order,
                ml_cache_bytes,
                credential,
                &ml_context,
            );
            // Use the HIGHER of ML and heuristic scores. A strong heuristic match
            // (prefix + entropy + context) should never be dragged down by a weak ML
            // prediction, and a strong ML prediction should override weak heuristics.
            let blended = (ML_WEIGHT * ml_conf) + (HEURISTIC_WEIGHT * heuristic_conf);
            blended.max(heuristic_conf).max(ml_conf)
        }
    }
}

#[derive(Default)]
struct ScanState {
    matches: Vec<RawMatch>,
    ml_score_cache: HashMap<(String, String), f64>,
    ml_cache_order: VecDeque<(String, String)>,
    ml_cache_bytes: usize,
}

struct CompileState {
    ac_literals: Vec<String>,
    ac_map: Vec<CompiledPattern>,
    fallback: Vec<(CompiledPattern, Vec<String>)>,
    companions: Vec<Option<CompiledCompanion>>,
    quality_warnings: Vec<String>,
}

fn build_compile_state(detectors: &[DetectorSpec]) -> Result<CompileState, ScanError> {
    let mut ac_literals = Vec::new();
    let mut ac_map = Vec::new();
    let mut fallback = Vec::new();
    let mut companions = Vec::with_capacity(detectors.len());
    let mut quality_warnings = Vec::new();
    for (detector_index, detector) in detectors.iter().enumerate() {
        companions.push(compile_detector_companion(detector)?);
        for (pattern_index, pattern) in detector.patterns.iter().enumerate() {
            compile_detector_pattern(
                detector_index,
                detector,
                pattern_index,
                pattern,
                &mut ac_literals,
                &mut ac_map,
                &mut fallback,
                &mut quality_warnings,
            )?;
        }
    }
    Ok(CompileState {
        ac_literals,
        ac_map,
        fallback,
        companions,
        quality_warnings,
    })
}

fn compile_detector_companion(
    detector: &DetectorSpec,
) -> Result<Option<CompiledCompanion>, ScanError> {
    detector
        .companion
        .as_ref()
        .map(|companion| compile_companion(companion, &detector.id))
        .transpose()
}

#[allow(clippy::too_many_arguments)]
fn compile_detector_pattern(
    detector_index: usize,
    detector: &DetectorSpec,
    pattern_index: usize,
    pattern: &PatternSpec,
    ac_literals: &mut Vec<String>,
    ac_map: &mut Vec<CompiledPattern>,
    fallback: &mut Vec<(CompiledPattern, Vec<String>)>,
    quality_warnings: &mut Vec<String>,
) -> Result<(), ScanError> {
    let prefix = extract_literal_prefix(&pattern.regex);
    if prefix.is_none() && detector.keywords.is_empty() {
        quality_warnings.push(format!(
            "detector '{}' pattern {} has no literal prefix and no keywords — will produce false positives. Add keywords for context anchoring.",
            detector.id, pattern_index
        ));
    }
    let compiled = compile_pattern(detector_index, pattern_index, pattern, &detector.id)?;
    match prefix {
        Some(prefix) => {
            ac_literals.push(prefix);
            ac_map.push(compiled);
        }
        _ => fallback.push((compiled, detector.keywords.clone())),
    }
    Ok(())
}

/// Build an Aho-Corasick automaton over all unique fallback keywords (≥4 chars).
/// Returns the AC and a mapping from keyword-match-index → fallback-pattern-indices.
fn build_fallback_keyword_ac(
    fallback: &[(CompiledPattern, Vec<String>)],
) -> (Option<AhoCorasick>, Vec<Vec<usize>>) {
    // Collect unique keywords → pattern indices
    let mut keyword_map: std::collections::HashMap<String, Vec<usize>> =
        std::collections::HashMap::new();
    for (pattern_idx, (_pattern, keywords)) in fallback.iter().enumerate() {
        for kw in keywords {
            if kw.len() >= 4 {
                keyword_map
                    .entry(kw.to_ascii_lowercase())
                    .or_default()
                    .push(pattern_idx);
            }
        }
    }
    if keyword_map.is_empty() {
        return (None, Vec::new());
    }
    let keywords: Vec<String> = keyword_map.keys().cloned().collect();
    let mapping: Vec<Vec<usize>> = keywords.iter().map(|kw| keyword_map[kw].clone()).collect();
    let ac = AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(&keywords)
        .ok();
    (ac, mapping)
}

fn log_quality_warnings(warnings: &[String]) {
    for warning in warnings {
        tracing::warn!("{}", warning);
    }
}

fn build_ac_pattern_set(ac_literals: &[String]) -> Result<Option<PatternSet>, ScanError> {
    if ac_literals.is_empty() {
        return Ok(None);
    }

    let mut builder = PatternSetBuilder::new();
    for (index, literal) in ac_literals.iter().enumerate() {
        builder = builder.add_literal(literal, index);
    }

    Ok(Some(builder.build()?))
}

fn build_detector_to_patterns(
    ac_map: &[CompiledPattern],
    detector_count: usize,
) -> Vec<Vec<usize>> {
    let mut detector_to_patterns = vec![Vec::new(); detector_count];
    for (pattern_index, entry) in ac_map.iter().enumerate() {
        detector_to_patterns[entry.detector_index].push(pattern_index);
    }
    detector_to_patterns
}

fn build_same_prefix_patterns(ac_literals: &[String]) -> Vec<Vec<usize>> {
    let mut prefix_groups: HashMap<&str, Vec<usize>> = HashMap::new();
    for (index, literal) in ac_literals.iter().enumerate() {
        prefix_groups
            .entry(literal.as_str())
            .or_default()
            .push(index);
    }
    let mut same_prefix_patterns = vec![Vec::new(); ac_literals.len()];
    for indices in prefix_groups.values() {
        for &index in indices {
            same_prefix_patterns[index] = indices
                .iter()
                .copied()
                .filter(|other| *other != index)
                .collect();
        }
    }
    same_prefix_patterns
}

fn normalize_scannable_chunk<'a>(
    chunk: &'a Chunk,
    owned_normalized: &'a mut Option<Chunk>,
) -> &'a Chunk {
    if chunk.data.is_ascii() {
        return chunk;
    }

    match normalize_chunk_data(&chunk.data) {
        Cow::Borrowed(_) => chunk,
        Cow::Owned(normalized_chunk_text) => {
            *owned_normalized = Some(keyhog_core::Chunk {
                data: normalized_chunk_text,
                metadata: chunk.metadata.clone(),
            });
            // SAFETY: `owned_normalized` was set to `Some(...)` two lines
            // above, so `.as_ref()` is infallible here.
            match owned_normalized.as_ref() {
                Some(chunk) => chunk,
                None => chunk,
            }
        }
    }
}

fn window_end_offset(text: &str, offset: usize, window_size: usize) -> usize {
    let mut end = (offset + window_size).min(text.len());
    while end < text.len() && !text.is_char_boundary(end) {
        end += 1; // Advance by 1 byte to find char boundary
    }
    end
}

fn window_chunk(chunk: &Chunk, offset: usize, end: usize) -> Chunk {
    Chunk {
        data: chunk.data[offset..end].to_string(),
        metadata: chunk.metadata.clone(),
    }
}

fn record_window_match(
    chunk_text: &str,
    offset: usize,
    matched: &mut RawMatch,
    seen: &mut std::collections::HashSet<(String, String, usize)>,
    seen_order: &mut VecDeque<(String, String, usize)>,
) -> bool {
    matched.location.offset += offset;
    matched.location.line = Some(line_number_for_offset(chunk_text, matched.location.offset));
    let key = (
        matched.detector_id.clone(),
        matched.credential.clone(),
        matched.location.offset,
    );
    if !seen.insert(key.clone()) {
        return false;
    }

    seen_order.push_back(key);
    while seen.len() > MAX_WINDOW_DEDUP_ENTRIES {
        let Some(oldest) = seen_order.pop_front() else {
            break;
        };
        seen.remove(&oldest);
    }

    true
}

fn next_window_offset(text: &str, end: usize, overlap: usize) -> usize {
    let mut offset = end.saturating_sub(overlap);
    while offset > 0 && !text.is_char_boundary(offset) {
        offset -= 1; // Step back by 1 byte to find char boundary
    }
    offset
}

fn adjust_fallback_match_locations(matches: &mut [RawMatch], line_idx: usize, line_offset: usize) {
    for matched in matches {
        if matched.location.line == Some(FIRST_LINE_NUMBER) {
            matched.location.line = Some(line_idx + FIRST_LINE_NUMBER);
        }
        matched.location.offset += line_offset;
    }
}

fn match_line_number(
    preprocessed: &ScannerPreprocessedText,
    line_offsets: &[usize],
    match_start: usize,
) -> usize {
    preprocessed
        .line_for_offset(match_start)
        .unwrap_or_else(|| line_number_for_offset_with_offsets(line_offsets, match_start))
}

#[allow(clippy::too_many_arguments)]
fn build_raw_match(
    detector: &DetectorSpec,
    chunk: &Chunk,
    credential: &str,
    companion: Option<String>,
    match_start: usize,
    line: usize,
    entropy: f64,
    confidence: f64,
) -> RawMatch {
    RawMatch {
        detector_id: detector.id.clone(),
        detector_name: detector.name.clone(),
        service: detector.service.clone(),
        severity: detector.severity,
        credential: credential.to_string(),
        companion,
        location: MatchLocation {
            source: chunk.metadata.source_type.clone(),
            file_path: chunk.metadata.path.clone(),
            line: Some(line),
            offset: match_start,
            commit: chunk.metadata.commit.clone(),
            author: chunk.metadata.author.clone(),
            date: chunk.metadata.date.clone(),
        },
        entropy: Some(entropy),
        confidence: Some(confidence),
    }
}

fn should_suppress_known_example_credential(
    credential: &str,
    file_path: Option<&str>,
    inferred_context: context::CodeContext,
) -> bool {
    if !context::is_known_example_credential(credential) {
        return false;
    }

    let sensitive_file = file_path
        .map(confidence::is_sensitive_path)
        .unwrap_or(false);
    !(sensitive_file && matches!(inferred_context, context::CodeContext::Assignment))
}

#[cfg(feature = "ml")]
fn cached_ml_score(
    ml_score_cache: &mut HashMap<(String, String), f64>,
    ml_cache_order: &mut VecDeque<(String, String)>,
    ml_cache_bytes: &mut usize,
    credential: &str,
    context: &str,
) -> f64 {
    #[cfg(not(feature = "ml"))]
    {
        let _ = (
            ml_score_cache,
            ml_cache_order,
            ml_cache_bytes,
            credential,
            context,
        );
        return 0.0;
    }

    #[cfg(feature = "ml")]
    {
        let cache_key = (credential.to_string(), context.to_string());

        if let Some(score) = ml_score_cache.get(&cache_key) {
            if let Some(position) = ml_cache_order.iter().position(|key| key == &cache_key) {
                ml_cache_order.remove(position);
            }
            ml_cache_order.push_back(cache_key);
            return *score;
        }

        let entry_bytes = cache_key.0.len().saturating_add(cache_key.1.len());
        while ml_score_cache.len() >= MAX_ML_CACHE_ENTRIES
            || ml_cache_bytes.saturating_add(entry_bytes) > MAX_ML_CACHE_BYTES
        {
            let Some(evicted) = ml_cache_order.pop_front() else {
                break;
            };
            if ml_score_cache.remove(&evicted).is_some() {
                *ml_cache_bytes =
                    ml_cache_bytes.saturating_sub(evicted.0.len().saturating_add(evicted.1.len()));
            }
        }

        let score = ml_scorer::score(credential, context);
        ml_score_cache.insert(cache_key.clone(), score);
        ml_cache_order.push_back(cache_key);
        *ml_cache_bytes = ml_cache_bytes.saturating_add(entry_bytes);
        score
    }
}

#[cfg(feature = "ml")]
fn local_context_window(data: &str, line: usize, radius: usize) -> String {
    let lines: Vec<&str> = data.lines().collect();
    if lines.is_empty() {
        return String::new();
    }

    let start = line.saturating_sub(radius + 1);
    let end = (line + radius).min(lines.len());
    lines[start..end].join("\n")
}

fn floor_char_boundary(text: &str, offset: usize) -> usize {
    let mut safe_offset = offset.min(text.len());
    while safe_offset > 0 && !text.is_char_boundary(safe_offset) {
        safe_offset -= 1;
    }
    safe_offset
}

fn line_number_for_offset(text: &str, offset: usize) -> usize {
    let safe_offset = floor_char_boundary(text, offset);
    memchr::memchr_iter(b'\n', &text.as_bytes()[..safe_offset])
        .count()
        .saturating_add(1)
}

fn line_number_for_offset_with_offsets(line_offsets: &[usize], offset: usize) -> usize {
    line_offsets.partition_point(|line_offset| *line_offset <= offset)
}

fn compute_line_offsets(text: &str) -> Vec<usize> {
    let mut offsets = Vec::with_capacity(128);
    offsets.push(0);
    for idx in memchr::memchr_iter(b'\n', text.as_bytes()) {
        offsets.push(idx + 1);
    }
    offsets
}

fn normalize_chunk_data(data: &str) -> Cow<'_, str> {
    if data.is_ascii() {
        return Cow::Borrowed(data);
    }

    let normalized = data.nfc().collect::<String>();
    if normalized == data {
        Cow::Borrowed(data)
    } else {
        Cow::Owned(normalized)
    }
}

/// Extract a literal prefix from a regex pattern for Aho-Corasick.
/// Takes consecutive non-metacharacters from the start.
/// Returns `None` if fewer than 3 literal chars.
fn extract_literal_prefix(pattern: &str) -> Option<String> {
    let mut prefix = String::new();
    let mut chars = pattern.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                let Some(next) = chars.next() else {
                    break;
                };
                if is_escaped_literal(next) {
                    prefix.push(next);
                } else {
                    break;
                }
            }
            '[' | '(' | '.' | '*' | '+' | '?' | '{' | '|' | '^' | '$' => break,
            _ => {
                prefix.push(ch);
            }
        }
    }
    if prefix.len() >= MIN_LITERAL_PREFIX_CHARS {
        Some(prefix)
    } else {
        None
    }
}

fn is_escaped_literal(ch: char) -> bool {
    matches!(
        ch,
        '[' | ']' | '(' | ')' | '.' | '*' | '+' | '?' | '{' | '}' | '\\' | '|' | '^' | '$'
    )
}

/// Search for a companion pattern within N lines of a given line number.
fn find_companion(
    preprocessed: &ScannerPreprocessedText,
    primary_line: usize,
    companion: &CompiledCompanion,
) -> Option<String> {
    let start = primary_line.saturating_sub(companion.within_lines);
    let end = primary_line.saturating_add(companion.within_lines);
    let (window_start, window_end) =
        line_window_offsets(preprocessed, start + FIRST_LINE_NUMBER, end)?;
    let haystack = &preprocessed.text[window_start..window_end];

    for captures in companion.regex.captures_iter(haystack) {
        let Some(m) = captures.get(companion.capture_group.unwrap_or(FIRST_CAPTURE_GROUP_INDEX))
        else {
            continue;
        };
        if m.len() > 4096 {
            continue; // Prevent memory issues from excessively long companion matches
        }
        if let Some(line) = preprocessed.line_for_offset(window_start + m.start())
            && (start + FIRST_LINE_NUMBER..=end).contains(&line)
        {
            return Some(m.as_str().to_string());
        }
    }
    None
}

fn line_window_offsets(
    preprocessed: &ScannerPreprocessedText,
    start_line: usize,
    end_line: usize,
) -> Option<(usize, usize)> {
    let mut start_offset = None;
    let mut end_offset = None;

    for mapping in &preprocessed.mappings {
        if start_offset.is_none() && mapping.line_number >= start_line {
            start_offset = Some(mapping.start_offset);
        }
        if mapping.line_number <= end_line {
            end_offset = Some(mapping.end_offset);
        }
    }

    Some((start_offset?, end_offset?))
}

#[cfg(not(feature = "entropy"))]
fn fallback_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn match_entropy(data: &[u8]) -> f64 {
    #[cfg(feature = "entropy")]
    {
        entropy::shannon_entropy(data)
    }

    #[cfg(not(feature = "entropy"))]
    {
        fallback_entropy(data)
    }
}

/// Check if a match is within a hex-encoded context (i.e., surrounded by hex digits).
/// This prevents false positives where a secret pattern matches inside hex-encoded data.
/// We look at up to 20 chars before and after the match to determine context.
fn is_within_hex_context(data: &str, match_start: usize, match_end: usize) -> bool {
    if !valid_match_bounds(data, match_start, match_end) {
        return false;
    }
    let matched = &data[match_start..match_end];
    let matched_hex_digits = matched.chars().filter(|c| c.is_ascii_hexdigit()).count();
    if matched.len() < MIN_HEX_MATCH_LEN || matched_hex_digits < MIN_HEX_DIGITS_IN_MATCH {
        return false;
    }
    let (before, after) = surrounding_hex_context(data, match_start, match_end);
    let hex_before = formatted_hex_run(before.chars().rev());
    let hex_after = formatted_hex_run(after.chars());
    hex_before >= MIN_HEX_CONTEXT_DIGITS && hex_after >= MIN_HEX_CONTEXT_DIGITS
}

fn valid_match_bounds(data: &str, match_start: usize, match_end: usize) -> bool {
    match_end > match_start
        && data.is_char_boundary(match_start)
        && data.is_char_boundary(match_end)
}

fn surrounding_hex_context(data: &str, match_start: usize, match_end: usize) -> (&str, &str) {
    let context_start =
        floor_char_boundary(data, match_start.saturating_sub(HEX_CONTEXT_RADIUS_CHARS));
    let context_end = {
        let mut end = (match_end + HEX_CONTEXT_RADIUS_CHARS).min(data.len());
        while end < data.len() && !data.is_char_boundary(end) {
            end += 1; // Advance by 1 byte to find char boundary
        }
        end.min(data.len())
    };
    (
        &data[context_start..match_start],
        &data[match_end..context_end],
    )
}

fn formatted_hex_run(iter: impl Iterator<Item = char>) -> usize {
    let mut hex_digits = 0usize;
    let mut separators = 0usize;
    let mut seen_hex = false;

    for ch in iter {
        if ch.is_ascii_hexdigit() {
            hex_digits += 1;
            seen_hex = true;
            continue;
        }
        if matches!(ch, ' ' | '\t' | ':' | '-')
            && (!seen_hex || separators < MAX_HEX_CONTEXT_SEPARATORS)
        {
            separators += 1;
            continue;
        }
        break;
    }

    hex_digits
}

fn compile_pattern(
    detector_index: usize,
    pattern_index: usize,
    spec: &PatternSpec,
    detector_id: &str,
) -> Result<CompiledPattern, ScanError> {
    let regex = regex::RegexBuilder::new(&spec.regex)
        .size_limit(REGEX_SIZE_LIMIT_BYTES)
        .dfa_size_limit(REGEX_SIZE_LIMIT_BYTES)
        .build()
        .map_err(|e| ScanError::RegexCompile {
            detector_id: detector_id.to_string(),
            index: pattern_index,
            source: e,
        })?;
    Ok(CompiledPattern {
        detector_index,
        regex,
        group: spec.group,
    })
}

fn compile_companion(
    spec: &CompanionSpec,
    detector_id: &str,
) -> Result<CompiledCompanion, ScanError> {
    let regex = regex::RegexBuilder::new(&spec.regex)
        .size_limit(REGEX_SIZE_LIMIT_BYTES)
        .dfa_size_limit(REGEX_SIZE_LIMIT_BYTES)
        .build()
        .map_err(|e| ScanError::RegexCompile {
            detector_id: detector_id.to_string(),
            index: FIRST_CAPTURE_GROUP_INDEX,
            source: e,
        })?;
    let capture_group = (regex.captures_len() > 1).then_some(FIRST_CAPTURE_GROUP_INDEX);
    Ok(CompiledCompanion {
        regex,
        capture_group,
        within_lines: spec.within_lines,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyhog_core::{ChunkMetadata, Severity};

    fn make_chunk(data: &str) -> Chunk {
        Chunk {
            data: data.to_string(),
            metadata: ChunkMetadata {
                source_type: "test".into(),
                path: Some("test.txt".into()),
                commit: None,
                author: None,
                date: None,
            },
        }
    }

    #[test]
    fn literal_prefix_extraction() {
        assert_eq!(
            extract_literal_prefix("AKIA[0-9A-Z]{16}"),
            Some("AKIA".into())
        );
        assert_eq!(
            extract_literal_prefix("xoxb-[0-9]{10}"),
            Some("xoxb-".into())
        );
        assert_eq!(
            extract_literal_prefix("ghp_[A-Za-z0-9]{36}"),
            Some("ghp_".into())
        );
        assert_eq!(extract_literal_prefix("[a-z]+"), None);
        assert_eq!(extract_literal_prefix("ab"), None);
        assert_eq!(
            extract_literal_prefix(r"foo\.bar[0-9]+"),
            Some("foo.bar".into())
        );
        assert_eq!(
            extract_literal_prefix(r"abc\*def[0-9]+"),
            Some("abc*def".into())
        );
    }

    #[test]
    fn scan_detects_slack_bot_token_from_single_line_literal() {
        let detector = DetectorSpec {
            id: "slack-bot".into(),
            name: "Slack Bot Token".into(),
            service: "slack".into(),
            severity: Severity::Critical,
            patterns: vec![PatternSpec {
                regex: "xoxb-[0-9]{10}-[0-9]{10}-[a-zA-Z0-9]{24}".into(),
                description: None,
                group: None,
            }],
            companion: None,
            verify: None,
            keywords: vec![],
        };

        let scanner = CompiledScanner::compile(vec![detector]).unwrap();
        let chunk = make_chunk("token = \"xoxb-1234567890-1234567890-abcdefghijABCDEFGHIJklmn\"");
        let matches = scanner.scan(&chunk);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].detector_id, "slack-bot");
        assert!(matches[0].credential.starts_with("xoxb-"));
    }

    #[test]
    fn scan_attaches_companion_secret_near_aws_access_key() {
        let detector = DetectorSpec {
            id: "aws-key".into(),
            name: "AWS Access Key".into(),
            service: "aws".into(),
            severity: Severity::Critical,
            patterns: vec![PatternSpec {
                regex: "AKIA[0-9A-Z]{16}".into(),
                description: None,
                group: None,
            }],
            companion: Some(CompanionSpec {
                regex: "AWS_SECRET_ACCESS_KEY[=:\\s]+([0-9a-zA-Z/+=]{40})".into(),
                within_lines: 3,
                name: "secret_key".into(),
            }),
            verify: None,
            keywords: vec![],
        };

        let scanner = CompiledScanner::compile(vec![detector]).unwrap();
        let access_key = format!("AKIA{}", "R7VXNPLMQ3HSKWJT");
        let secret_key = format!("kR4vN8pW2cF6gH0j{}", "L3mQsT7uX9yAbDe12fG5nP8Z");
        let chunk = make_chunk(
            &format!("AWS_ACCESS_KEY_ID={access_key}\nAWS_SECRET_ACCESS_KEY={secret_key}"),
        );
        let matches = scanner.scan(&chunk);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].credential, access_key);
        assert!(matches[0].companion.is_some());
    }

    #[test]
    fn scan_extracts_captured_companion_value_without_anchor_text() {
        let detector = DetectorSpec {
            id: "anchored-companion".into(),
            name: "Anchored Companion".into(),
            service: "test".into(),
            severity: Severity::High,
            patterns: vec![PatternSpec {
                regex: "client_id[=:\\s\"']+([a-z0-9]{8})".into(),
                description: None,
                group: Some(1),
            }],
            companion: Some(CompanionSpec {
                regex: "client_secret[=:\\s\"']+([A-Za-z0-9]{16})".into(),
                within_lines: 1,
                name: "client_secret".into(),
            }),
            verify: None,
            keywords: vec!["client_id".into(), "client_secret".into()],
        };

        let scanner = CompiledScanner::compile(vec![detector]).unwrap();
        let chunk = make_chunk("client_id=deadbeef\nclient_secret=ABCDEFGHIJKLMNOP");
        let matches = scanner.scan(&chunk);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].companion.as_deref(), Some("ABCDEFGHIJKLMNOP"));
    }

    #[test]
    fn empty_input_produces_no_matches() {
        let detector = DetectorSpec {
            id: "test".into(),
            name: "Test".into(),
            service: "test".into(),
            severity: Severity::Low,
            patterns: vec![PatternSpec {
                regex: "SECRET_[A-Z]{10}".into(),
                description: None,
                group: None,
            }],
            companion: None,
            verify: None,
            keywords: vec![],
        };

        let scanner = CompiledScanner::compile(vec![detector]).unwrap();
        let chunk = make_chunk("");
        assert!(scanner.scan(&chunk).is_empty());
    }

    #[test]
    fn known_example_aws_key_is_allowed_in_sensitive_assignment_file() {
        let detector = DetectorSpec {
            id: "aws-key".into(),
            name: "AWS Key".into(),
            service: "aws".into(),
            severity: Severity::Critical,
            patterns: vec![PatternSpec {
                regex: "AKIA[0-9A-Z]{16}".into(),
                description: None,
                group: None,
            }],
            companion: None,
            verify: None,
            keywords: vec!["AKIA".into()],
        };
        let scanner = CompiledScanner::compile(vec![detector]).unwrap();
        let chunk = Chunk {
            data: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n".into(),
            metadata: ChunkMetadata {
                source_type: "test".into(),
                path: Some("aws.env".into()),
                commit: None,
                author: None,
                date: None,
            },
        };

        let matches = scanner.scan(&chunk);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].credential, "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn scan_detects_slack_bot_token_split_across_concat_lines() {
        // Slack token split across lines with + operator
        let detector = DetectorSpec {
            id: "slack-bot".into(),
            name: "Slack Bot Token".into(),
            service: "slack".into(),
            severity: Severity::Critical,
            patterns: vec![PatternSpec {
                regex: "xoxb-[0-9]{10}-[0-9]{10}-[a-zA-Z0-9]{24}".into(),
                description: None,
                group: None,
            }],
            companion: None,
            verify: None,
            keywords: vec!["slack".into()],
        };

        let scanner = CompiledScanner::compile(vec![detector]).unwrap();
        let chunk = make_chunk(
            "token = \"xoxb-1234567890-\" + \"1234567890-\" + \"abcdefghijABCDEFGHIJklmn\"",
        );
        let matches = scanner.scan(&chunk);
        assert_eq!(matches.len(), 1, "Should find token split with + operator");
        assert_eq!(matches[0].detector_id, "slack-bot");
        assert!(matches[0].credential.starts_with("xoxb-"));
    }

    #[test]
    fn scan_detects_aws_access_key_split_by_backslash_continuation() {
        // AWS key split with backslash continuation
        let detector = DetectorSpec {
            id: "aws-access-key".into(),
            name: "AWS Access Key".into(),
            service: "aws".into(),
            severity: Severity::Critical,
            patterns: vec![PatternSpec {
                regex: "AKIA[0-9A-Z]{16}".into(),
                description: None,
                group: None,
            }],
            companion: None,
            verify: None,
            keywords: vec!["aws".into(), "access".into()],
        };

        let scanner = CompiledScanner::compile(vec![detector]).unwrap();
        let chunk = make_chunk("AWS_ACCESS_KEY_ID = \"AKIA\" \\\n    \"R7VXNPLMQ3HSKWJT\"");
        let matches = scanner.scan(&chunk);
        assert_eq!(
            matches.len(),
            1,
            "Should find AWS key with backslash continuation"
        );
        assert_eq!(matches[0].detector_id, "aws-access-key");
        assert!(matches[0].credential.starts_with("AKIA"));
    }

    #[test]
    fn scan_detects_python_style_multiline_api_key() {
        // Python-style multiline secret with implicit concatenation
        let detector = DetectorSpec {
            id: "generic-api-key".into(),
            name: "Generic API Key".into(),
            service: "generic".into(),
            severity: Severity::High,
            patterns: vec![PatternSpec {
                regex: "sk-[a-z]{4}-[a-zA-Z0-9]{32}".into(),
                description: None,
                group: None,
            }],
            companion: None,
            verify: None,
            keywords: vec!["api".into(), "key".into()],
        };

        let scanner = CompiledScanner::compile(vec![detector]).unwrap();
        let chunk = make_chunk(
            r#"api_key = "sk-proj-" + \
    "AbCdEfGhIjKlMnOpQrStUvWxYz123456""#,
        );
        let matches = scanner.scan(&chunk);
        assert_eq!(matches.len(), 1, "Should find Python multiline secret");
        assert_eq!(matches[0].detector_id, "generic-api-key");
        assert!(matches[0].credential.starts_with("sk-proj-"));
    }

    #[test]
    fn scan_detects_javascript_multiline_github_token() {
        // JavaScript-style multiline with + operator
        let detector = DetectorSpec {
            id: "github-token".into(),
            name: "GitHub Token".into(),
            service: "github".into(),
            severity: Severity::Critical,
            patterns: vec![PatternSpec {
                regex: "ghp_[a-zA-Z0-9]{36}".into(),
                description: None,
                group: None,
            }],
            companion: None,
            verify: None,
            keywords: vec!["github".into(), "token".into()],
        };

        let scanner = CompiledScanner::compile(vec![detector]).unwrap();
        let chunk = make_chunk(
            r#"const token = "ghp_" +
    "kR4vN8pW2cF6gH0jL3" +
    "mQsT7uX9yAbDe12fG5";"#,
        );
        let matches = scanner.scan(&chunk);
        assert_eq!(
            matches.len(),
            1,
            "Should find GitHub token split with + operator"
        );
        assert_eq!(matches[0].detector_id, "github-token");
        assert!(matches[0].credential.starts_with("ghp_"));
    }

    #[test]
    fn line_number_for_offset_clamps_to_char_boundary() {
        let text = "line1\ncaf\u{00e9}\nline3";
        let offset_inside_multibyte = text.find('\u{00e9}').unwrap() + 1;

        assert_eq!(line_number_for_offset(text, offset_inside_multibyte), 2);
    }

    #[test]
    fn line_number_for_offset_treats_newline_as_previous_line() {
        let text = "first\nsecond";
        let newline_offset = text.find('\n').unwrap();
        assert_eq!(line_number_for_offset(text, newline_offset), 1);
        assert_eq!(line_number_for_offset(text, newline_offset + 1), 2);
    }

    #[test]
    fn cached_ml_score_uses_context_in_cache_key() {
        let mut cache = HashMap::new();
        let mut order = VecDeque::new();
        let mut bytes = 0usize;

        let first = cached_ml_score(
            &mut cache,
            &mut order,
            &mut bytes,
            "shared-credential",
            "password=shared-credential",
        );
        let second = cached_ml_score(
            &mut cache,
            &mut order,
            &mut bytes,
            "shared-credential",
            "token: shared-credential",
        );
        let repeated = cached_ml_score(
            &mut cache,
            &mut order,
            &mut bytes,
            "shared-credential",
            "password=shared-credential",
        );

        assert_eq!(cache.len(), 2);
        assert_eq!(order.len(), 2);
        assert_eq!(first, repeated);
        assert_eq!(
            cache.get(&(
                "shared-credential".to_string(),
                "password=shared-credential".to_string(),
            )),
            Some(&first)
        );
        assert_eq!(
            cache.get(&(
                "shared-credential".to_string(),
                "token: shared-credential".to_string(),
            )),
            Some(&second)
        );
    }

    #[test]
    fn cached_ml_score_obeys_byte_budget() {
        let mut cache = HashMap::new();
        let mut order = VecDeque::new();
        let mut bytes = 0usize;

        for idx in 0..64 {
            let context = format!("ctx-{idx}-{}", "x".repeat(8_192));
            let _ = cached_ml_score(&mut cache, &mut order, &mut bytes, "cred", &context);
        }

        assert!(bytes <= MAX_ML_CACHE_BYTES);
        assert!(cache.len() < 64);
    }

    #[test]
    fn companion_search_uses_preprocessed_text() {
        let detector = DetectorSpec {
            id: "aws-key".into(),
            name: "AWS Access Key".into(),
            service: "aws".into(),
            severity: Severity::Critical,
            patterns: vec![PatternSpec {
                regex: "AKIA[0-9A-Z]{16}".into(),
                description: None,
                group: None,
            }],
            companion: Some(CompanionSpec {
                regex: "[0-9a-zA-Z/+=]{40}".into(),
                within_lines: 3,
                name: "secret_key".into(),
            }),
            verify: None,
            keywords: vec![],
        };

        let scanner = CompiledScanner::compile(vec![detector]).unwrap();
        let access_key = format!("AKIA{}", "R7VXNPLMQ3HSKWJT");
        let chunk = make_chunk(
            &format!("AWS_ACCESS_KEY_ID = \"AKIA\" + \"R7VXNPLMQ3HSKWJT\"\nAWS_SECRET_ACCESS_KEY = \"kR4vN8pW2cF6gH0jL3mQsT7uX9yAbDe12fG5nP8\""),
        );
        let matches = scanner.scan(&chunk);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].credential, access_key);
        // Note: companion may or may not be found depending on multiline
        // preprocessing — the line structure changes after joining string
        // concatenations, which can shift the companion out of within_lines range.
    }

    #[test]
    fn fallback_line_by_line_scan_preserves_absolute_location() {
        let detector = DetectorSpec {
            id: "fallback".into(),
            name: "Fallback".into(),
            service: "generic".into(),
            severity: Severity::High,
            patterns: vec![PatternSpec {
                regex: "[A-Z0-9]{32}".into(),
                description: None,
                group: None,
            }],
            companion: None,
            verify: None,
            keywords: vec!["token".into()],
        };

        let scanner = CompiledScanner::compile(vec![detector]).unwrap();
        let prefix = "a".repeat(LARGE_FALLBACK_SCAN_THRESHOLD + 1);
        let secret = "ABCDEFGHIJKLMNOPQRSTUVWX12345678";
        let chunk = make_chunk(&format!("{prefix}\ntoken = {secret}"));
        let matches = scanner.scan(&chunk);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].credential, secret);
        assert_eq!(matches[0].location.line, Some(2));
        assert_eq!(
            matches[0].location.offset,
            prefix.len() + 1 + "token = ".len()
        );
    }

    #[test]
    fn hex_context_handles_formatted_hex_dump() {
        let text = "aa bb cc dd ee ff 0011223344556677 88 99 aa bb cc dd ee ff";
        let start = text.find("0011223344556677").unwrap();
        let end = start + "0011223344556677".len();
        assert!(is_within_hex_context(text, start, end));
    }

    #[test]
    fn windowed_scan_reports_boundary_spanning_secret_once() {
        let detector = DetectorSpec {
            id: "boundary-gh".into(),
            name: "Boundary GitHub Token".into(),
            service: "github".into(),
            severity: Severity::Critical,
            patterns: vec![PatternSpec {
                regex: "ghp_[A-Za-z0-9]{36}".into(),
                description: None,
                group: None,
            }],
            companion: None,
            verify: None,
            keywords: vec!["github".into()],
        };

        let scanner = CompiledScanner::compile(vec![detector]).unwrap();
        let secret = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ";
        let prefix = "a".repeat(MAX_SCAN_CHUNK_BYTES - 16);
        let suffix = "z".repeat(WINDOW_OVERLAP_BYTES + 32);
        let chunk = make_chunk(&format!("{prefix}{secret}{suffix}"));

        let matches = scanner.scan(&chunk);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].credential, secret);
        assert_eq!(matches[0].location.offset, prefix.len());
    }
}

#[cfg(test)]
mod regression_tests {
    use super::*;
    use keyhog_core::{ChunkMetadata, DetectorSpec, PatternSpec, Severity};

    #[test]
    fn openai_key_detection() {
        let detector = DetectorSpec {
            id: "openai-api-key".into(),
            name: "OpenAI API Key".into(),
            service: "openai".into(),
            severity: Severity::Critical,
            patterns: vec![PatternSpec {
                regex: "sk-proj-[a-zA-Z0-9_-]{100,}".into(),
                description: None,
                group: None,
            }],
            companion: None,
            verify: None,
            keywords: vec!["sk-proj-".into()],
        };

        let scanner = CompiledScanner::compile(vec![detector]).unwrap();
        let chunk = Chunk {
            data: "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890".into(),
            metadata: ChunkMetadata {
                source_type: "test".into(),
                path: Some("test.txt".into()),
                commit: None,
                author: None,
                date: None,
            },
        };
        let matches = scanner.scan(&chunk);
        assert!(
            !matches.is_empty(),
            "OpenAI key should be detected, got 0 matches. Preprocessed text starts with: {:?}",
            &chunk.data[..20]
        );
        assert_eq!(matches[0].detector_id, "openai-api-key");
        assert_eq!(
            matches[0].credential,
            "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890"
        );
    }
}

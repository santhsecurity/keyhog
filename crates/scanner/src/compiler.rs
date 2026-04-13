//! Logic for compiling detector specifications into an efficient scanning engine.

use crate::error::{Result, ScanError};
use crate::types::*;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use keyhog_core::{CompanionSpec, DetectorSpec, PatternSpec};
use regex::Regex;
use warpstate::PatternSet;

pub struct CompileState {
    pub ac_literals: Vec<String>,
    pub ac_map: Vec<CompiledPattern>,
    pub fallback: Vec<(CompiledPattern, Vec<String>)>,
    pub companions: Vec<Vec<CompiledCompanion>>,
    pub quality_warnings: Vec<String>,
}

pub fn build_compile_state(detectors: &[DetectorSpec]) -> Result<CompileState> {
    use rayon::prelude::*;

    // Phase 1: Pre-compile all regexes in parallel (the expensive part).
    let compiled_results: Vec<Result<(Vec<CompiledPattern>, Vec<CompiledCompanion>)>> = detectors
        .par_iter()
        .enumerate()
        .map(|(detector_index, detector)| {
            let companions = compile_detector_companions(detector)?;
            let mut patterns = Vec::new();
            for (pattern_index, pattern) in detector.patterns.iter().enumerate() {
                patterns.push(compile_pattern(
                    detector_index,
                    pattern_index,
                    pattern,
                    &detector.id,
                )?);
            }
            Ok((patterns, companions))
        })
        .collect();

    // Phase 2: Assemble results sequentially (fast, no regex compilation).
    let mut ac_literals = Vec::new();
    let mut ac_map = Vec::new();
    let mut fallback = Vec::new();
    let mut companions = Vec::with_capacity(detectors.len());
    let mut quality_warnings = Vec::new();

    for (detector_index, (result, detector)) in compiled_results
        .into_iter()
        .zip(detectors.iter())
        .enumerate()
    {
        let (compiled_patterns, detector_companions) = result?;
        companions.push(detector_companions);

        for (pattern_index, (compiled, pattern)) in compiled_patterns
            .into_iter()
            .zip(detector.patterns.iter())
            .enumerate()
        {
            let prefixes = extract_literal_prefixes(&pattern.regex);

            // Homoglyph expansion for high-confidence patterns
            for prefix in &prefixes {
                if prefix.len() >= 3 {
                    let expanded_prefix = crate::homoglyph::expand_homoglyphs(prefix);
                    if expanded_prefix != *prefix
                        && let Ok(re) = Regex::new(&format!("^{}", expanded_prefix))
                    {
                        let expanded_pattern = CompiledPattern {
                            detector_index,
                            regex: re,
                            group: pattern.group,
                        };
                        fallback.push((expanded_pattern, detector.keywords.clone()));
                    }
                }
            }

            if !prefixes.is_empty() {
                for prefix in prefixes {
                    ac_literals.push(prefix);
                    ac_map.push(compiled.clone());
                }
            } else {
                if detector.keywords.is_empty() {
                    quality_warnings.push(format!(
                        "Detector {} pattern {pattern_index} has no literal prefix and no keywords.",
                        detector.id
                    ));
                }
                fallback.push((compiled, detector.keywords.clone()));
            }
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

pub fn build_ac_pattern_set(literals: &[String]) -> Result<Option<PatternSet>> {
    if literals.is_empty() {
        return Ok(None);
    }
    let mut builder = PatternSet::builder();
    for lit in literals {
        builder = builder.literal(lit);
    }
    Ok(Some(builder.build()?))
}

/// Build a complete PatternSet containing ALL patterns (AC regexes + fallback regexes)
/// for GPU matching. Falls back to None if compilation fails (e.g., overly complex regexes).
/// Build a GPU PatternSet from AC LITERAL prefixes (not regexes).
///
/// The GPU shader runs an AC automaton on wgpu compute cores — pattern count
/// is irrelevant because all patterns are evaluated in parallel. Uses
/// `.literal()` which builds an AC trie (no DFA state explosion).
///
/// The regex-based `.regex()` builder uses regex-automata DFA internally
/// which explodes at >100 patterns. We NEVER use that for GPU.
pub fn build_gpu_pattern_set(ac_literals: &[String]) -> Option<PatternSet> {
    if ac_literals.is_empty() {
        return None;
    }
    let mut builder = PatternSet::builder();
    for lit in ac_literals {
        if !lit.is_empty() {
            builder = builder.literal(lit);
        }
    }
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| builder.build())) {
        Ok(Ok(ps)) => {
            tracing::info!(
                patterns = ac_literals.len(),
                "GPU PatternSet compiled (AC literals)"
            );
            Some(ps)
        }
        Ok(Err(e)) => {
            tracing::warn!("GPU PatternSet error: {e}");
            None
        }
        Err(_) => {
            tracing::warn!("GPU PatternSet panicked");
            None
        }
    }
}

pub fn build_detector_to_patterns(
    ac_map: &[CompiledPattern],
    detector_count: usize,
) -> Vec<Vec<usize>> {
    let mut map = vec![Vec::new(); detector_count];
    for (pat_idx, entry) in ac_map.iter().enumerate() {
        map[entry.detector_index].push(pat_idx);
    }
    map
}

pub fn build_same_prefix_patterns(literals: &[String]) -> Vec<Vec<usize>> {
    let mut groups: std::collections::HashMap<&str, Vec<usize>> = std::collections::HashMap::new();
    for (i, lit) in literals.iter().enumerate() {
        groups.entry(lit.as_str()).or_default().push(i);
    }
    let mut map = vec![Vec::new(); literals.len()];
    for indices in groups.values() {
        if indices.len() > 1 {
            for &i in indices {
                map[i] = indices.iter().copied().filter(|&j| j != i).collect();
            }
        }
    }
    map
}

pub fn build_prefix_propagation(literals: &[String]) -> Vec<Vec<usize>> {
    let mut map = vec![Vec::new(); literals.len()];
    // Sort indices by literal length (shortest first) for efficient prefix matching.
    let mut sorted: Vec<(usize, &str)> = literals
        .iter()
        .enumerate()
        .map(|(i, s)| (i, s.as_str()))
        .collect();
    sorted.sort_by_key(|(_, s)| s.len());
    // For each longer string, check if any shorter string is its prefix.
    for a in 0..sorted.len() {
        for b in (a + 1)..sorted.len() {
            let (j, short) = sorted[a];
            let (i, long) = sorted[b];
            if short != long && long.starts_with(short) {
                map[j].push(i);
            }
        }
    }
    map
}

pub fn build_fallback_keyword_ac(
    fallback: &[(CompiledPattern, Vec<String>)],
) -> (Option<AhoCorasick>, Vec<Vec<usize>>) {
    let mut all_keywords = Vec::new();
    let mut keyword_to_patterns = Vec::new();
    let mut keyword_map: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    for (pattern_idx, (_, keywords)) in fallback.iter().enumerate() {
        for kw in keywords {
            if kw.len() < 4 {
                continue;
            }
            let idx = *keyword_map.entry(kw.clone()).or_insert_with(|| {
                all_keywords.push(kw.clone());
                keyword_to_patterns.push(Vec::new());
                all_keywords.len() - 1
            });
            keyword_to_patterns[idx].push(pattern_idx);
        }
    }

    if all_keywords.is_empty() {
        return (None, Vec::new());
    }

    let ac = AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build(all_keywords)
        .ok();

    (ac, keyword_to_patterns)
}

pub fn log_quality_warnings(warnings: &[String]) {
    for warning in warnings {
        tracing::warn!(target: "keyhog::scanner::quality", "{}", warning);
    }
}

pub fn compile_detector_companions(detector: &DetectorSpec) -> Result<Vec<CompiledCompanion>> {
    detector
        .companions
        .iter()
        .map(|companion| compile_companion(companion, &detector.id))
        .collect()
}

#[allow(clippy::too_many_arguments, dead_code)]
pub fn compile_detector_pattern(
    detector_index: usize,
    detector: &DetectorSpec,
    pattern_index: usize,
    pattern: &PatternSpec,
    ac_literals: &mut Vec<String>,
    ac_map: &mut Vec<CompiledPattern>,
    fallback: &mut Vec<(CompiledPattern, Vec<String>)>,
    quality_warnings: &mut Vec<String>,
) -> Result<()> {
    let detector_id = &detector.id;
    let compiled = compile_pattern(detector_index, pattern_index, pattern, detector_id)?;

    // Prefix extraction for Aho-Corasick prefiltering
    let prefixes = extract_literal_prefixes(&pattern.regex);

    // Proactive Homoglyph Expansion:
    // For high-confidence patterns (with literal prefixes), add an expanded
    // version that handles common Unicode lookalike characters.
    for prefix in &prefixes {
        if prefix.len() >= 3 {
            let expanded_prefix = crate::homoglyph::expand_homoglyphs(prefix);
            if expanded_prefix != *prefix
                && let Ok(re) = Regex::new(&format!("^{}", expanded_prefix))
            {
                let expanded_pattern = CompiledPattern {
                    detector_index,
                    regex: re,
                    group: pattern.group,
                };
                // Always put homoglyph variants in fallback (they are regexes)
                fallback.push((expanded_pattern, detector.keywords.clone()));
            }
        }
    }

    if !prefixes.is_empty() {
        tracing::debug!(
            detector_id,
            ?prefixes,
            mode = "AC",
            "compiled detector pattern"
        );
        for prefix in prefixes {
            ac_literals.push(prefix);
            ac_map.push(compiled.clone());
        }
    } else {
        // No literal prefix. With Hyperscan, these will be compiled directly
        // into the HS database alongside the AC-prefix patterns. Without
        // Hyperscan, they go to the keyword-gated regex fallback.
        if detector.keywords.is_empty() {
            quality_warnings.push(format!(
                "Detector {detector_id} pattern {pattern_index} has no literal prefix and no keywords."
            ));
        }
        fallback.push((compiled, detector.keywords.clone()));
    }
    Ok(())
}

pub fn compile_pattern(
    detector_index: usize,
    pattern_index: usize,
    spec: &PatternSpec,
    detector_id: &str,
) -> Result<CompiledPattern> {
    let regex = regex::RegexBuilder::new(&spec.regex)
        .size_limit(REGEX_SIZE_LIMIT_BYTES)
        .dfa_size_limit(REGEX_SIZE_LIMIT_BYTES)
        .crlf(true)
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

pub fn compile_companion(spec: &CompanionSpec, detector_id: &str) -> Result<CompiledCompanion> {
    let regex = regex::RegexBuilder::new(&spec.regex)
        .size_limit(REGEX_SIZE_LIMIT_BYTES)
        .dfa_size_limit(REGEX_SIZE_LIMIT_BYTES)
        .crlf(true)
        .build()
        .map_err(|e| ScanError::RegexCompile {
            detector_id: detector_id.to_string(),
            index: FIRST_CAPTURE_GROUP_INDEX,
            source: e,
        })?;
    let capture_group = (regex.captures_len() > 1).then_some(FIRST_CAPTURE_GROUP_INDEX);
    Ok(CompiledCompanion {
        name: spec.name.clone(),
        regex,
        capture_group,
        within_lines: spec.within_lines,
        required: spec.required,
    })
}

/// Extract literal prefixes from a regex pattern for Aho-Corasick.
/// Handles simple literals and top-level groups like (AKIA|ASIA).
pub fn extract_literal_prefixes(pattern: &str) -> Vec<String> {
    // Strip leading inline flags like (?i), (?m), (?s), (?x), (?im), etc.
    // These set regex modes but don't consume input.
    let pattern = strip_leading_inline_flags(pattern);

    if pattern.starts_with('(') && pattern.contains('|') {
        // Handle (A|B|C)
        let mut depth = 0;
        let mut end_idx = None;
        for (i, ch) in pattern.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end_idx = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }

        if let Some(end) = end_idx {
            let mut inner = &pattern[1..end];
            // Strip non-capturing group prefix (?:, (?i:, (?im:, etc.)
            if inner.starts_with("?:") {
                inner = &inner[2..];
            } else if inner.starts_with("?i:")
                || inner.starts_with("?m:")
                || inner.starts_with("?s:")
            {
                inner = &inner[3..];
            } else if inner.starts_with("?im:")
                || inner.starts_with("?is:")
                || inner.starts_with("?ms:")
            {
                inner = &inner[4..];
            }
            // Split by |, but only at depth 0
            let mut parts = Vec::new();
            let mut start = 0;
            let mut d = 0;
            for (i, ch) in inner.char_indices() {
                match ch {
                    '(' => d += 1,
                    ')' => d -= 1,
                    '|' if d == 0 => {
                        parts.push(&inner[start..i]);
                        start = i + 1;
                    }
                    _ => {}
                }
            }
            parts.push(&inner[start..]);

            let mut results = Vec::new();
            for part in parts {
                if let Some(p) = extract_literal_prefix(part) {
                    results.push(p);
                }
            }
            if !results.is_empty() {
                return results;
            }
        }
    }

    // Default: try to extract a single prefix from the start
    extract_literal_prefix(pattern).into_iter().collect()
}

/// Strip leading inline flags like `(?i)`, `(?m)`, `(?ims)` from a regex.
/// These set modes for the rest of the pattern but don't produce a group.
fn strip_leading_inline_flags(pattern: &str) -> &str {
    if !pattern.starts_with("(?") {
        return pattern;
    }
    // (?i), (?m), (?s), (?x), (?im), (?ims), (?imsx) etc. — flags only, no ':'
    let bytes = pattern.as_bytes();
    if bytes.len() < 4 || bytes[0] != b'(' || bytes[1] != b'?' {
        return pattern;
    }
    let mut i = 2;
    while i < bytes.len() && matches!(bytes[i], b'i' | b'm' | b's' | b'x' | b'u' | b'U') {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b')' {
        // (?flags) — strip the entire inline flag group
        &pattern[i + 1..]
    } else {
        pattern
    }
}

pub fn extract_literal_prefix(pattern: &str) -> Option<String> {
    let mut prefix = String::new();
    let mut chars = pattern.chars().peekable();
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
            '[' | '.' | '*' | '+' | '?' | '{' | '|' | '^' | '$' => break,
            '(' => {
                // Mid-pattern alternation: try to extend the prefix with
                // the group's alternatives. This turns "secret_(key|token)"
                // into prefix "secret_key" (the longest common prefix after
                // expanding alternatives). If the group has no pipe, continue
                // extracting the literal inside it.
                let group_start = chars.clone().collect::<String>();
                if let Some(alternatives) = extract_group_alternatives(&group_start) {
                    // Find the longest common prefix of all alternatives
                    if let Some(first) = alternatives.first() {
                        let common: String = first.chars()
                            .enumerate()
                            .take_while(|(i, c)| {
                                alternatives.iter().all(|alt| {
                                    alt.chars().nth(*i) == Some(*c)
                                })
                            })
                            .map(|(_, c)| c)
                            .collect();
                        if !common.is_empty() {
                            prefix.push_str(&common);
                        }
                    }
                }
                break;
            }
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

/// Extract literal alternatives from a group at the start of a string.
/// Input: "key|token)rest..." → Some(["key", "token"])
/// Returns None if the group contains regex metacharacters.
fn extract_group_alternatives(s: &str) -> Option<Vec<String>> {
    // Strip optional non-capturing prefix
    let inner = s.strip_prefix("?:")
        .or_else(|| s.strip_prefix("?i:"))
        .or_else(|| s.strip_prefix("?im:"))
        .unwrap_or(s);

    let mut depth = 0i32;
    let mut end = None;
    for (i, ch) in inner.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                if depth == 0 {
                    end = Some(i);
                    break;
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    let end = end?;
    let group_content = &inner[..end];

    // Split by | at depth 0
    let mut parts = Vec::new();
    let mut start = 0;
    let mut d = 0i32;
    for (i, ch) in group_content.char_indices() {
        match ch {
            '(' => d += 1,
            ')' => d -= 1,
            '|' if d == 0 => {
                parts.push(&group_content[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&group_content[start..]);

    // Extract literal prefix from each alternative
    let literals: Vec<String> = parts.iter()
        .filter_map(|part| {
            let mut lit = String::new();
            for ch in part.chars() {
                match ch {
                    'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' | '.' | ':' | '=' | ' ' => {
                        lit.push(ch);
                    }
                    '\\' => break, // escaped char — stop
                    _ => break, // metachar — stop
                }
            }
            if lit.is_empty() { None } else { Some(lit) }
        })
        .collect();

    if literals.len() == parts.len() && !literals.is_empty() {
        Some(literals)
    } else {
        None
    }
}

pub fn is_escaped_literal(ch: char) -> bool {
    matches!(
        ch,
        '[' | ']' | '(' | ')' | '.' | '*' | '+' | '?' | '{' | '}' | '\\' | '|' | '^' | '$'
    )
}

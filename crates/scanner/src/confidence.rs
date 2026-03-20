//! Confidence scoring: combines multiple signals into a 0.0–1.0 score.
//! Higher confidence means more likely to be a real secret.

const SCORE_ZERO: f64 = 0.0;
const CONFIDENCE_MIN: f64 = 0.0;
const CONFIDENCE_MAX: f64 = 1.0;
const LITERAL_PREFIX_WEIGHT: f64 = 0.35;
const CONTEXT_ANCHOR_WEIGHT: f64 = 0.20;
const ENTROPY_WEIGHT: f64 = 0.20;
const HIGH_ENTROPY_PARTIAL_WEIGHT: f64 = 0.12;
const MODERATE_ENTROPY_THRESHOLD: f64 = 3.0;
const MODERATE_ENTROPY_WEIGHT: f64 = 0.05;
const LOW_ENTROPY_THRESHOLD: f64 = 2.0;
const LOW_ENTROPY_MIN_MATCH_LENGTH: usize = 10;
const LOW_ENTROPY_PENALTY: f64 = 0.6;
const KEYWORD_NEARBY_WEIGHT: f64 = 0.10;
const SENSITIVE_FILE_WEIGHT: f64 = 0.10;
const COMPANION_WEIGHT: f64 = 0.05;
const HIGH_ENTROPY_THRESHOLD: f64 = 4.5;
const VERY_HIGH_ENTROPY_THRESHOLD: f64 = 5.5;

/// Confidence signals for a potential match.
pub struct ConfidenceSignals {
    /// Pattern has a distinctive literal prefix (e.g., sk-proj-, ghp_)
    pub has_literal_prefix: bool,
    /// Pattern uses a capture group with context anchoring
    pub has_context_anchor: bool,
    /// Shannon entropy of the matched credential
    pub entropy: f64,
    /// A secret-related keyword appears nearby
    pub keyword_nearby: bool,
    /// File extension suggests config/env/secret file
    pub sensitive_file: bool,
    /// Matched credential length
    pub match_length: usize,
    /// Companion credential was found
    pub has_companion: bool,
}

/// Compute a confidence score from 0.0 to 1.0.
///
/// The hand-tuned weights below were calibrated against the adversarial test
/// corpus before the scanner blends this heuristic score with the ML model:
/// literal prefixes dominate, context and entropy are secondary, and file/path
/// hints plus companion matches provide smaller incremental adjustments.
pub fn compute_confidence(signals: &ConfidenceSignals) -> f64 {
    let mut score = SCORE_ZERO;
    let mut max_possible = SCORE_ZERO;

    // Literal prefix: strongest signal. If it starts with "sk-proj-", it's almost certainly real.
    // Literal prefix is the strongest signal: sk-proj-, ghp_, AKIA are nearly certain.
    // Weight: 0.35 (largest single factor). Validated by ML classifier agreement.
    max_possible += LITERAL_PREFIX_WEIGHT;
    if signals.has_literal_prefix {
        score += LITERAL_PREFIX_WEIGHT;
    }

    // Context anchor: "API_KEY=..." near the value.
    max_possible += CONTEXT_ANCHOR_WEIGHT;
    if signals.has_context_anchor {
        score += CONTEXT_ANCHOR_WEIGHT;
    }

    // Entropy: high entropy = likely random/secret, low entropy = likely placeholder.
    max_possible += ENTROPY_WEIGHT;
    if signals.entropy >= VERY_HIGH_ENTROPY_THRESHOLD {
        score += ENTROPY_WEIGHT;
    } else if signals.entropy >= HIGH_ENTROPY_THRESHOLD {
        score += HIGH_ENTROPY_PARTIAL_WEIGHT;
    } else if signals.entropy >= MODERATE_ENTROPY_THRESHOLD {
        score += MODERATE_ENTROPY_WEIGHT;
    }
    // Very low entropy is a negative signal: multiply down the score.
    // Applied after normalization so the weighted-average math stays consistent.
    let low_entropy_penalty = if signals.entropy < LOW_ENTROPY_THRESHOLD
        && signals.match_length > LOW_ENTROPY_MIN_MATCH_LENGTH
    {
        LOW_ENTROPY_PENALTY
    } else {
        CONFIDENCE_MAX
    };

    // Keyword proximity.
    max_possible += KEYWORD_NEARBY_WEIGHT;
    if signals.keyword_nearby {
        score += KEYWORD_NEARBY_WEIGHT;
    }

    // Sensitive file type (.env, .secrets, credentials.json, etc.)
    max_possible += SENSITIVE_FILE_WEIGHT;
    if signals.sensitive_file {
        score += SENSITIVE_FILE_WEIGHT;
    }

    // Companion found (e.g., AWS secret key near access key).
    max_possible += COMPANION_WEIGHT;
    if signals.has_companion {
        score += COMPANION_WEIGHT;
    }

    // Normalize to 0.0 - 1.0.
    if max_possible == SCORE_ZERO {
        return SCORE_ZERO;
    }
    let normalized_score: f64 = (score / max_possible) * low_entropy_penalty;
    normalized_score.clamp(CONFIDENCE_MIN, CONFIDENCE_MAX)
}

/// Check if a file path suggests a sensitive file.
pub fn is_sensitive_path(path: &str) -> bool {
    let path_bytes = path.as_bytes();
    const SENSITIVE_NAMES: &[&[u8]] = &[
        b".env",
        b".env.local",
        b".env.production",
        b".env.staging",
        b"credentials",
        b"secrets",
        b"apikeys",
        b"api_keys",
        b".npmrc",
        b".pypirc",
        b".netrc",
        b".pgpass",
        b"terraform.tfvars",
        b"variables.tf",
        b"docker-compose",
        b"application.yml",
        b"application.properties",
        b"config.json",
        b"config.yaml",
    ];

    for name in SENSITIVE_NAMES {
        if path_bytes
            .windows(name.len())
            .any(|w| w.eq_ignore_ascii_case(name))
        {
            return true;
        }
    }
    const SENSITIVE_EXTENSIONS: &[&[u8]] = &[b".env", b".pem", b".key", b".p12", b".pfx", b".jks"];
    for ext in SENSITIVE_EXTENSIONS {
        if path_bytes.len() >= ext.len()
            && path_bytes[path_bytes.len() - ext.len()..].eq_ignore_ascii_case(ext)
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_confidence_with_prefix_and_entropy() {
        let signals = ConfidenceSignals {
            has_literal_prefix: true,
            has_context_anchor: false,
            entropy: 5.2,
            keyword_nearby: true,
            sensitive_file: true,
            match_length: 50,
            has_companion: false,
        };
        let score = compute_confidence(&signals);
        assert!(score > 0.6, "score was {}", score);
    }

    #[test]
    fn low_confidence_generic_hex() {
        let signals = ConfidenceSignals {
            has_literal_prefix: false,
            has_context_anchor: false,
            entropy: 3.5,
            keyword_nearby: false,
            sensitive_file: false,
            match_length: 32,
            has_companion: false,
        };
        let score = compute_confidence(&signals);
        assert!(score < 0.3, "score was {}", score);
    }

    #[test]
    fn medium_confidence_with_context() {
        let signals = ConfidenceSignals {
            has_literal_prefix: false,
            has_context_anchor: true,
            entropy: 4.8,
            keyword_nearby: true,
            sensitive_file: false,
            match_length: 40,
            has_companion: false,
        };
        let score = compute_confidence(&signals);
        assert!(score > 0.4 && score < 0.8, "score was {}", score);
    }

    #[test]
    fn sensitive_paths() {
        assert!(is_sensitive_path(".env.production"));
        assert!(is_sensitive_path("config/credentials.json"));
        assert!(is_sensitive_path("server.key"));
        assert!(!is_sensitive_path("src/main.rs"));
        assert!(!is_sensitive_path("README.md"));
    }

    #[test]
    fn low_entropy_penalty() {
        let signals = ConfidenceSignals {
            has_literal_prefix: true,
            has_context_anchor: false,
            entropy: 1.5, // Very low — likely "aaaaaaa..." or placeholder
            keyword_nearby: false,
            sensitive_file: false,
            match_length: 32,
            has_companion: false,
        };
        let score = compute_confidence(&signals);
        // Should be penalized despite having prefix
        assert!(score < 0.5, "score was {}", score);
    }

    #[test]
    fn confidence_is_zero_without_positive_signals() {
        let signals = ConfidenceSignals {
            has_literal_prefix: false,
            has_context_anchor: false,
            entropy: 0.0,
            keyword_nearby: false,
            sensitive_file: false,
            match_length: 0,
            has_companion: false,
        };
        assert_eq!(compute_confidence(&signals), 0.0);
    }

    #[test]
    fn confidence_clamps_to_one_for_all_positive_signals() {
        let signals = ConfidenceSignals {
            has_literal_prefix: true,
            has_context_anchor: true,
            entropy: 8.0,
            keyword_nearby: true,
            sensitive_file: true,
            match_length: 128,
            has_companion: true,
        };
        assert_eq!(compute_confidence(&signals), 1.0);
    }

    #[test]
    fn very_high_entropy_gets_full_entropy_weight() {
        let signals = ConfidenceSignals {
            has_literal_prefix: false,
            has_context_anchor: false,
            entropy: VERY_HIGH_ENTROPY_THRESHOLD,
            keyword_nearby: false,
            sensitive_file: false,
            match_length: 32,
            has_companion: false,
        };
        let score = compute_confidence(&signals);
        assert!((score - 0.2).abs() < 1e-9, "score was {}", score);
    }

    #[test]
    fn high_entropy_gets_partial_entropy_weight() {
        let signals = ConfidenceSignals {
            has_literal_prefix: false,
            has_context_anchor: false,
            entropy: HIGH_ENTROPY_THRESHOLD,
            keyword_nearby: false,
            sensitive_file: false,
            match_length: 32,
            has_companion: false,
        };
        let score = compute_confidence(&signals);
        assert!((score - 0.12).abs() < 1e-9, "score was {}", score);
    }

    #[test]
    fn moderate_entropy_gets_small_weight() {
        let signals = ConfidenceSignals {
            has_literal_prefix: false,
            has_context_anchor: false,
            entropy: 3.0,
            keyword_nearby: false,
            sensitive_file: false,
            match_length: 32,
            has_companion: false,
        };
        let score = compute_confidence(&signals);
        assert!((score - 0.05).abs() < 1e-9, "score was {}", score);
    }

    #[test]
    fn entropy_below_moderate_threshold_adds_no_weight() {
        let signals = ConfidenceSignals {
            has_literal_prefix: false,
            has_context_anchor: false,
            entropy: 2.99,
            keyword_nearby: false,
            sensitive_file: false,
            match_length: 32,
            has_companion: false,
        };
        assert_eq!(compute_confidence(&signals), 0.0);
    }

    #[test]
    fn low_entropy_penalty_requires_length_above_threshold() {
        let signals = ConfidenceSignals {
            has_literal_prefix: true,
            has_context_anchor: false,
            entropy: 1.0,
            keyword_nearby: false,
            sensitive_file: false,
            match_length: 10,
            has_companion: false,
        };
        let score = compute_confidence(&signals);
        assert!((score - 0.35).abs() < 1e-9, "score was {}", score);
    }

    #[test]
    fn low_entropy_penalty_applies_only_below_threshold() {
        let signals = ConfidenceSignals {
            has_literal_prefix: true,
            has_context_anchor: false,
            entropy: 2.0,
            keyword_nearby: false,
            sensitive_file: false,
            match_length: 64,
            has_companion: false,
        };
        let score = compute_confidence(&signals);
        assert!((score - 0.35).abs() < 1e-9, "score was {}", score);
    }

    #[test]
    fn low_entropy_penalty_scales_nonzero_score() {
        let signals = ConfidenceSignals {
            has_literal_prefix: true,
            has_context_anchor: true,
            entropy: 1.0,
            keyword_nearby: false,
            sensitive_file: false,
            match_length: 11,
            has_companion: false,
        };
        let score = compute_confidence(&signals);
        assert!((score - 0.33).abs() < 1e-9, "score was {}", score);
    }

    #[test]
    fn companion_signal_adds_expected_weight() {
        let signals = ConfidenceSignals {
            has_literal_prefix: false,
            has_context_anchor: false,
            entropy: 0.0,
            keyword_nearby: false,
            sensitive_file: false,
            match_length: 24,
            has_companion: true,
        };
        let score = compute_confidence(&signals);
        assert!((score - 0.03).abs() < 1e-9, "score was {}", score);
    }

    #[test]
    fn context_and_keyword_signals_stack_linearly() {
        let signals = ConfidenceSignals {
            has_literal_prefix: false,
            has_context_anchor: true,
            entropy: 0.0,
            keyword_nearby: true,
            sensitive_file: false,
            match_length: 20,
            has_companion: false,
        };
        let score = compute_confidence(&signals);
        assert!((score - 0.18).abs() < 1e-9, "score was {}", score);
    }

    #[test]
    fn sensitive_path_matches_case_insensitively() {
        assert!(is_sensitive_path("CONFIG/.ENV.PRODUCTION"));
        assert!(is_sensitive_path("Secrets/CREDENTIALS.JSON"));
        assert!(is_sensitive_path("keys/CLIENT.P12"));
    }

    #[test]
    fn sensitive_path_rejects_empty_and_non_sensitive_values() {
        assert!(!is_sensitive_path(""));
        assert!(!is_sensitive_path("notes/environment.txt"));
        assert!(!is_sensitive_path("docs/secretary.txt"));
    }

    #[test]
    fn sensitive_path_detects_embedded_sensitive_names_with_special_characters() {
        assert!(is_sensitive_path("deploy/docker-compose.override.yml"));
        assert!(is_sensitive_path("dir/my api_keys-backup.txt"));
        assert!(is_sensitive_path("nested/application.properties.template"));
    }

    #[test]
    fn sensitive_path_handles_huge_input() {
        let long_prefix = "a/".repeat(4096);
        let long_sensitive = format!("{long_prefix}terraform.tfvars");
        let long_non_sensitive = format!("{long_prefix}plain-text-file.txt");
        assert!(is_sensitive_path(&long_sensitive));
        assert!(!is_sensitive_path(&long_non_sensitive));
    }
}

//! Confidence scoring: combines multiple signals into a 0.0–1.0 score.
//! Higher confidence means more likely to be a real secret.

mod penalties;
mod prefixes;
mod signals;

pub use penalties::apply_path_confidence_penalties;
pub use penalties::apply_post_ml_penalties;
pub use prefixes::known_prefix_confidence_floor;
pub use signals::ConfidenceSignals;

use crate::entropy::{HIGH_ENTROPY_THRESHOLD, VERY_HIGH_ENTROPY_THRESHOLD};
pub use penalties::{char_diversity, contains_placeholder_word, max_repeat_run};
pub use signals::is_sensitive_path;

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

/// Compute a confidence score from `0.0` to `1.0`.
pub fn compute_confidence(signals: &ConfidenceSignals) -> f64 {
    let mut score = SCORE_ZERO;
    let mut max_possible = SCORE_ZERO;

    max_possible += LITERAL_PREFIX_WEIGHT;
    if signals.has_literal_prefix {
        score += LITERAL_PREFIX_WEIGHT;
    }

    max_possible += CONTEXT_ANCHOR_WEIGHT;
    if signals.has_context_anchor {
        score += CONTEXT_ANCHOR_WEIGHT;
    }

    max_possible += ENTROPY_WEIGHT;
    if signals.entropy >= VERY_HIGH_ENTROPY_THRESHOLD {
        score += ENTROPY_WEIGHT;
    } else if signals.entropy >= HIGH_ENTROPY_THRESHOLD {
        score += HIGH_ENTROPY_PARTIAL_WEIGHT;
    } else if signals.entropy >= MODERATE_ENTROPY_THRESHOLD {
        score += MODERATE_ENTROPY_WEIGHT;
    }
    let low_entropy_penalty = if signals.entropy < LOW_ENTROPY_THRESHOLD
        && signals.match_length > LOW_ENTROPY_MIN_MATCH_LENGTH
    {
        LOW_ENTROPY_PENALTY
    } else {
        CONFIDENCE_MAX
    };

    max_possible += KEYWORD_NEARBY_WEIGHT;
    if signals.keyword_nearby {
        score += KEYWORD_NEARBY_WEIGHT;
    }

    max_possible += SENSITIVE_FILE_WEIGHT;
    if signals.sensitive_file {
        score += SENSITIVE_FILE_WEIGHT;
    }

    max_possible += COMPANION_WEIGHT;
    if signals.has_companion {
        score += COMPANION_WEIGHT;
    }

    if max_possible == SCORE_ZERO {
        return SCORE_ZERO;
    }
    let normalized_score = (score / max_possible) * low_entropy_penalty;
    normalized_score.clamp(CONFIDENCE_MIN, CONFIDENCE_MAX)
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
    fn low_entropy_penalty_variants() {
        let penalized = ConfidenceSignals {
            has_literal_prefix: true,
            has_context_anchor: false,
            entropy: 1.5,
            keyword_nearby: false,
            sensitive_file: false,
            match_length: 32,
            has_companion: false,
        };
        assert!(compute_confidence(&penalized) < 0.5);

        let no_penalty = ConfidenceSignals {
            match_length: 10,
            entropy: 1.0,
            ..penalized
        };
        let score = compute_confidence(&no_penalty);
        assert!((score - 0.35).abs() < 1e-9, "score was {}", score);
    }

    #[test]
    fn edge_weight_cases() {
        let zero = ConfidenceSignals {
            has_literal_prefix: false,
            has_context_anchor: false,
            entropy: 0.0,
            keyword_nearby: false,
            sensitive_file: false,
            match_length: 0,
            has_companion: false,
        };
        assert_eq!(compute_confidence(&zero), 0.0);

        let full = ConfidenceSignals {
            has_literal_prefix: true,
            has_context_anchor: true,
            entropy: 8.0,
            keyword_nearby: true,
            sensitive_file: true,
            match_length: 128,
            has_companion: true,
        };
        assert_eq!(compute_confidence(&full), 1.0);
    }

    #[test]
    fn entropy_weight_tiers() {
        let very_high = ConfidenceSignals {
            has_literal_prefix: false,
            has_context_anchor: false,
            entropy: VERY_HIGH_ENTROPY_THRESHOLD,
            keyword_nearby: false,
            sensitive_file: false,
            match_length: 32,
            has_companion: false,
        };
        assert!((compute_confidence(&very_high) - 0.2).abs() < 1e-9);

        let high = ConfidenceSignals {
            entropy: HIGH_ENTROPY_THRESHOLD,
            ..very_high
        };
        assert!((compute_confidence(&high) - 0.12).abs() < 1e-9);

        let moderate = ConfidenceSignals {
            entropy: 3.0,
            ..very_high
        };
        assert!((compute_confidence(&moderate) - 0.05).abs() < 1e-9);
    }

    #[test]
    fn context_keyword_and_companion_weights_stack() {
        let stacked = ConfidenceSignals {
            has_literal_prefix: false,
            has_context_anchor: true,
            entropy: 0.0,
            keyword_nearby: true,
            sensitive_file: false,
            match_length: 20,
            has_companion: false,
        };
        assert!((compute_confidence(&stacked) - 0.18).abs() < 1e-9);

        let companion = ConfidenceSignals {
            has_context_anchor: false,
            keyword_nearby: false,
            match_length: 24,
            has_companion: true,
            ..stacked
        };
        assert!((compute_confidence(&companion) - 0.03).abs() < 1e-9);
    }
}

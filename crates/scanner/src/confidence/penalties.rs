const PLACEHOLDER_WORDS: &[&[u8]] = &[
    b"example",
    b"test",
    b"dummy",
    b"fake",
    b"sample",
    b"placeholder",
    b"changeme",
    b"default",
    b"admin",
    b"root",
    b"qwerty",
    b"password",
];

use super::{CONFIDENCE_MAX, CONFIDENCE_MIN};

/// Check if a credential contains a known placeholder word (case-insensitive).
pub fn contains_placeholder_word(credential: &str) -> bool {
    PLACEHOLDER_WORDS
        .iter()
        .any(|word| contains_ascii_case_insensitive(credential, word))
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

/// Compute the ratio of unique bytes to total bytes.
pub fn char_diversity(credential: &str) -> f64 {
    let len = credential.len();
    if len == 0 {
        return 1.0;
    }
    let mut seen = [false; 256];
    let mut unique = 0usize;
    for &byte in credential.as_bytes() {
        let slot = &mut seen[byte as usize];
        if !*slot {
            *slot = true;
            unique += 1;
        }
    }
    unique as f64 / len as f64
}

/// Compute the length of the longest run of identical characters divided by the total length.
pub fn max_repeat_run(credential: &str) -> f64 {
    let bytes = credential.as_bytes();
    let len = bytes.len();
    if len == 0 {
        return 0.0;
    }
    let mut max_run = 1usize;
    let mut current_run = 1usize;
    for index in 1..len {
        if bytes[index] == bytes[index - 1] {
            current_run += 1;
            if current_run > max_run {
                max_run = current_run;
            }
        } else {
            current_run = 1;
        }
    }
    max_run as f64 / len as f64
}

/// Apply post-ML penalties based on hard-coded placeholder heuristics.
pub fn apply_post_ml_penalties(score: f64, credential: &str) -> f64 {
    if credential.is_empty() {
        return score;
    }
    let mut adjusted = score;
    if contains_placeholder_word(credential) {
        adjusted *= 0.05;
    }
    if char_diversity(credential) < 0.3 {
        adjusted *= 0.1;
    }
    if max_repeat_run(credential) > 0.5 {
        adjusted *= 0.1;
    }
    adjusted.clamp(CONFIDENCE_MIN, CONFIDENCE_MAX)
}

/// Apply path-based confidence penalties for matches in test, example, or dummy directories.
pub fn apply_path_confidence_penalties(score: f64, path: Option<&str>) -> f64 {
    let Some(path) = path else { return score };
    let lower = path.to_lowercase();
    let mut adjusted = score;

    let is_test_like = lower.split(['/', '\\']).any(|component| {
        matches!(
            component,
            "test" | "tests" | "example" | "examples" | "sample" | "samples" | "dummy"
        )
    });

    if is_test_like {
        adjusted *= 0.5;
    }

    adjusted.clamp(CONFIDENCE_MIN, CONFIDENCE_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_words_detected_case_insensitive() {
        assert!(contains_placeholder_word("ghp_example_0001"));
        assert!(contains_placeholder_word("MY_TEST_KEY"));
        assert!(contains_placeholder_word("dummy_value"));
        assert!(contains_placeholder_word("fake_token"));
        assert!(contains_placeholder_word("sample_secret"));
        assert!(!contains_placeholder_word("ghp_real_key_123"));
    }

    #[test]
    fn char_diversity_values() {
        assert!((char_diversity("aaa") - 1.0 / 3.0).abs() < 1e-9);
        assert!((char_diversity("abcdef") - 1.0).abs() < 1e-9);
        assert!((char_diversity("") - 1.0).abs() < 1e-9);
    }

    #[test]
    fn max_repeat_run_values() {
        assert!((max_repeat_run("aaaa") - 1.0).abs() < 1e-9);
        assert!((max_repeat_run("aabba") - 0.4).abs() < 1e-9);
        assert_eq!(max_repeat_run(""), 0.0);
    }

    #[test]
    fn post_ml_penalties_crush_placeholders() {
        let score = apply_post_ml_penalties(0.9, "ghp_example_0001_xxxxxxxxxxxxxxxxxxxx");
        assert!(score < 0.1, "score was {}", score);

        let score = apply_post_ml_penalties(0.9, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(score < 0.1, "score was {}", score);

        let score = apply_post_ml_penalties(0.9, "abc");
        assert!((score - 0.9).abs() < 1e-9, "score was {}", score);
    }
}

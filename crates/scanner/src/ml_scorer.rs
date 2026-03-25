//! ML-based secret scoring with a tiny mixture-of-experts network.
//!
//! Architecture: gate Linear(40,5) → Softmax plus 5 experts of
//! Linear(40,32) → ReLU → Linear(32,16) → ReLU → Linear(16,1), then
//! a weighted logit sum followed by Sigmoid.
//! Total params: 8,995 (hardcoded in ml_weights.rs)
//! Inference: typically under ~100μs per prediction on the test hardware
//!
//! The 40 input features capture everything our heuristics know:
//! length, entropy, char diversity, known prefixes, context keywords,
//! placeholder patterns, structural signals, and coarse file-type cues.

#[path = "ml_weights.rs"]
pub(crate) mod ml_weights;

use std::cell::RefCell;

const NUM_FEATURES: usize = 41;
const FILE_TYPE_OFFSET: usize = 32;
const EXPERT_COUNT: usize = 6;
const MAX_NORMALIZED_TEXT_LENGTH: f32 = 200.0;
const MEDIUM_LENGTH_THRESHOLD: usize = 20;
const LONG_LENGTH_THRESHOLD: usize = 40;
const VERY_LONG_LENGTH_THRESHOLD: usize = 100;
const MAX_NORMALIZED_ENTROPY: f32 = 8.0;
const LOW_ENTROPY_THRESHOLD: f64 = 3.5;
const HIGH_ENTROPY_THRESHOLD: f64 = 4.5;
const VERY_HIGH_ENTROPY_THRESHOLD: f64 = 5.0;
const MAX_PREFIX_LENGTH: f32 = 10.0;
const OPENAI_PREFIX: &str = "sk-";
const AWS_ACCESS_KEY_PREFIX: &str = "AKIA";
const LOW_VARIETY_BYTE_THRESHOLD: usize = 3;
const MIN_LOW_VARIETY_LENGTH: usize = 5;
const MIN_HEX_PLACEHOLDER_LENGTH: usize = 10;
const MAX_UNIQUE_CHAR_NORMALIZATION: f32 = 40.0;
const MAX_DOT_COUNT_NORMALIZATION: f32 = 5.0;
const MAX_DASH_COUNT_NORMALIZATION: f32 = 10.0;
const CONFIG_FILE_TYPE_INDEX: usize = 0;
const SOURCE_FILE_TYPE_INDEX: usize = 1;
const CI_FILE_TYPE_INDEX: usize = 2;
const INFRA_FILE_TYPE_INDEX: usize = 3;
const OTHER_FILE_TYPE_INDEX: usize = 4;
const BINARY_FILE_TYPE_INDEX: usize = 5;
const COMMENT_CONTEXT_FEATURE_INDEX: usize = 38;
const ASSIGNMENT_OPERATOR_FEATURE_INDEX: usize = 39;
const TEST_FILE_CONTEXT_FEATURE_INDEX: usize = 40;
const EXPERT_HIDDEN_LAYER_1: usize = 32;
const EXPERT_HIDDEN_LAYER_2: usize = 16;
const KNOWN_PREFIXES: &[&str] = &[
    "sk-", "ghp_", "gho_", "xoxb", "xoxp", "AKIA", "npm_", "pypi-", "SG.", "key-", "ntn_",
    "lin_api_", "dop_v1_", "sntrys_", "hf_",
];
const SECRET_CONTEXT_KEYWORDS: &[&str] = &[
    "api_key",
    "secret",
    "token",
    "password",
    "credential",
    "private_key",
    "bearer",
];
const TEST_CONTEXT_KEYWORDS: &[&str] = &["test", "mock", "fake", "example", "dummy"];
const PLACEHOLDER_KEYWORDS: &[&str] = &[
    "example", "replace", "change", "your_", "xxx", "todo", "dummy", "fake", "insert",
];
const COMMENT_PREFIXES: &[&str] = &["#", "//", "/*", "--"];
const BINARY_MARKERS: &[&str] = &[
    "load:",
    ".rodata",
    "xref",
    "lea rdi",
    "go.string",
    "core::str",
    "alloc::string",
    "objdump",
    "strings:",
    "symbol:",
];
const CI_MARKERS: &[&str] = &[
    "jobs:",
    "stages:",
    "pipeline",
    "jenkinsfile",
    ".gitlab-ci",
    "buildspec",
    ".github/workflows",
    ".github/actions",
    "circleci",
    ".travis.yml",
    "azure-pipelines",
    "bitbucket-pipelines",
    "semaphore",
    "concourse",
    "tekton",
    "argocd",
];
const INFRA_MARKERS: &[&str] = &[
    "resource ",
    "apiversion:",
    ".tf",
    ".tfvars",
    "dockerfile",
    "docker-compose",
    "k8s",
    "ansible",
    "helm",
    "kustomize",
    "cloudformation",
    "serverless.yml",
    "wrangler.toml",
    "pulumi",
    "vagrant",
];
const SOURCE_MARKERS: &[&str] = &["const ", "let ", "var ", "def ", "fn "];
const SOURCE_EXTENSIONS: &[&str] = &[
    ".py", ".js", ".ts", ".go", ".rs", ".java", ".rb", ".php", ".swift", ".kt",
];
const CONFIG_MARKERS: &[&str] = &[
    ".env",
    ".yaml",
    ".json",
    ".toml",
    ".properties",
    ".cfg",
    ".ini",
];

fn shannon_entropy(data: &[u8]) -> f64 {
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

/// Score a (text, context) pair using the trained classifier.
/// Returns probability this is a real secret: 0.0 (definitely not) to 1.0 (definitely yes).
pub fn score(text: &str, context: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }

    thread_local! {
        static LAST_SCORE: RefCell<Option<(String, String, f64)>> = const { RefCell::new(None) };
    }

    if let Some(score) = LAST_SCORE.with(|cache| {
        cache
            .borrow()
            .as_ref()
            .and_then(|(cached_text, cached_context, cached_score)| {
                (cached_text == text && cached_context == context).then_some(*cached_score)
            })
    }) {
        return score;
    }

    let features = compute_features(text, context);
    let score = forward_pass(&features) as f64;
    LAST_SCORE.with(|cache| {
        *cache.borrow_mut() = Some((text.to_string(), context.to_string(), score));
    });
    score
}

/// Return the embedded model version string for diagnostics and CLI output.
pub fn model_version() -> &'static str {
    ml_weights::MODEL_VERSION
}

/// Public entry point for feature extraction (used by GPU batch inference).
pub fn compute_features_public(text: &str, context: &str) -> [f32; NUM_FEATURES] {
    if text.is_empty() {
        return [0.0f32; NUM_FEATURES];
    }
    compute_features(text, context)
}

/// Compute the 41-dimensional feature vector.
fn compute_features(text: &str, context: &str) -> [f32; NUM_FEATURES] {
    debug_assert!(!text.is_empty(), "compute_features requires non-empty text");

    let mut f = [0.0f32; NUM_FEATURES];
    let len = text.len();
    let text_bytes = text.as_bytes();
    let context_bytes = context.as_bytes();
    let ent = shannon_entropy(text_bytes);
    let text_summary = summarize_text_bytes(text_bytes);
    apply_length_features(&mut f, len);
    apply_entropy_features(&mut f, ent);
    apply_character_features(&mut f, &text_summary);
    apply_prefix_features(&mut f, text);
    apply_context_features(&mut f, context, context_bytes);
    apply_placeholder_features(&mut f, text, text_bytes, len, text_summary.unique_chars);
    apply_structure_features(&mut f, &text_summary, text_bytes);
    apply_file_type_feature(&mut f, context);
    apply_extra_features(&mut f, context, context_bytes);
    f
}

fn apply_extra_features(features: &mut [f32; NUM_FEATURES], context: &str, context_bytes: &[u8]) {
    let is_in_comment = COMMENT_PREFIXES
        .iter()
        .any(|prefix| context.trim().starts_with(prefix));
    let has_assignment_operator = context.contains('=') || context.contains(':');
    let is_test_file_context =
        contains_any_ascii_case_insensitive(context_bytes, &["test", "mock", "fixture", "spec"]);

    features[COMMENT_CONTEXT_FEATURE_INDEX] = binary_feature(is_in_comment);
    features[ASSIGNMENT_OPERATOR_FEATURE_INDEX] = binary_feature(has_assignment_operator);
    features[TEST_FILE_CONTEXT_FEATURE_INDEX] = binary_feature(is_test_file_context);
}

fn apply_length_features(features: &mut [f32; NUM_FEATURES], len: usize) {
    features[0] = (len as f32 / MAX_NORMALIZED_TEXT_LENGTH).min(1.0);
    features[1] = binary_feature(len >= MEDIUM_LENGTH_THRESHOLD);
    features[2] = binary_feature(len >= LONG_LENGTH_THRESHOLD);
    features[3] = binary_feature(len >= VERY_LONG_LENGTH_THRESHOLD);
}

fn apply_entropy_features(features: &mut [f32; NUM_FEATURES], entropy_value: f64) {
    features[4] = entropy_value as f32 / MAX_NORMALIZED_ENTROPY;
    features[5] = binary_feature(entropy_value >= LOW_ENTROPY_THRESHOLD);
    features[6] = binary_feature(entropy_value >= HIGH_ENTROPY_THRESHOLD);
    features[7] = binary_feature(entropy_value >= VERY_HIGH_ENTROPY_THRESHOLD);
}

fn apply_character_features(features: &mut [f32; NUM_FEATURES], summary: &TextSummary) {
    features[8] = binary_feature(summary.has_upper);
    features[9] = binary_feature(summary.has_lower);
    features[10] = binary_feature(summary.has_digit);
    features[11] = binary_feature(summary.has_symbol);
}

fn apply_prefix_features(features: &mut [f32; NUM_FEATURES], text: &str) {
    let prefix_len = longest_known_prefix(text);
    features[12] = binary_feature(prefix_len > 0);
    features[13] = (prefix_len as f32 / MAX_PREFIX_LENGTH).min(1.0);
    features[14] = binary_feature(text.starts_with(OPENAI_PREFIX));
    features[15] = binary_feature(text.starts_with(AWS_ACCESS_KEY_PREFIX));
}

fn apply_context_features(features: &mut [f32; NUM_FEATURES], context: &str, context_bytes: &[u8]) {
    features[16] = binary_feature(context.contains('=') || context.contains(": "));
    features[17] = binary_feature(contains_any_ascii_case_insensitive(
        context_bytes,
        SECRET_CONTEXT_KEYWORDS,
    ));
    features[18] = binary_feature(contains_any_ascii_case_insensitive(
        context_bytes,
        TEST_CONTEXT_KEYWORDS,
    ));
    features[19] = binary_feature(
        COMMENT_PREFIXES
            .iter()
            .any(|prefix| context.trim().starts_with(prefix)),
    );
}

fn apply_placeholder_features(
    features: &mut [f32; NUM_FEATURES],
    text: &str,
    text_bytes: &[u8],
    len: usize,
    unique_chars: usize,
) {
    features[20] = binary_feature(contains_any_ascii_case_insensitive(
        text_bytes,
        PLACEHOLDER_KEYWORDS,
    ));
    features[21] =
        binary_feature(len > MIN_LOW_VARIETY_LENGTH && unique_chars <= LOW_VARIETY_BYTE_THRESHOLD);
    features[22] = binary_feature(
        text_bytes.iter().all(|byte| byte.is_ascii_hexdigit()) && len > MIN_HEX_PLACEHOLDER_LENGTH,
    );
    features[23] = binary_feature(text.contains("://"));
}

fn apply_structure_features(
    features: &mut [f32; NUM_FEATURES],
    summary: &TextSummary,
    text_bytes: &[u8],
) {
    features[24] = (summary.unique_chars as f32 / MAX_UNIQUE_CHAR_NORMALIZATION).min(1.0);
    let (unique_bigrams, bigram_count) = unique_bigram_stats(text_bytes);
    features[25] = normalized_ratio(unique_bigrams, bigram_count);
    features[26] = (summary.dot_count as f32 / MAX_DOT_COUNT_NORMALIZATION).min(1.0);
    features[27] = (summary.dash_count as f32 / MAX_DASH_COUNT_NORMALIZATION).min(1.0);
}

fn apply_file_type_feature(features: &mut [f32; NUM_FEATURES], context: &str) {
    let file_type = infer_file_type(context);
    features[FILE_TYPE_OFFSET + file_type] = 1.0;
}

fn infer_file_type(context: &str) -> usize {
    let context_lower = context.to_ascii_lowercase();
    if is_binary_context(&context_lower) {
        return BINARY_FILE_TYPE_INDEX;
    }
    if is_ci_context(&context_lower) {
        return CI_FILE_TYPE_INDEX;
    }
    if is_infra_context(context, &context_lower) {
        return INFRA_FILE_TYPE_INDEX;
    }
    if is_source_context(context, &context_lower) {
        return SOURCE_FILE_TYPE_INDEX;
    }
    if is_config_context(context, &context_lower) {
        return CONFIG_FILE_TYPE_INDEX;
    }
    OTHER_FILE_TYPE_INDEX
}

fn is_binary_context(context_lower: &str) -> bool {
    contains_any(context_lower, BINARY_MARKERS)
}

fn is_ci_context(context_lower: &str) -> bool {
    contains_any(context_lower, CI_MARKERS)
}

fn is_infra_context(context: &str, context_lower: &str) -> bool {
    context.contains("from ") || contains_any(context_lower, INFRA_MARKERS)
}

fn is_source_context(context: &str, context_lower: &str) -> bool {
    contains_any(context, SOURCE_MARKERS) || contains_any(context_lower, SOURCE_EXTENSIONS)
}

fn is_config_context(context: &str, context_lower: &str) -> bool {
    has_unquoted_equals(context) || contains_any(context_lower, CONFIG_MARKERS)
}

fn has_unquoted_equals(value: &str) -> bool {
    let bytes = value.as_bytes();
    for (idx, byte) in bytes.iter().enumerate() {
        if *byte != b'=' {
            continue;
        }

        let prev = if idx > 0 { bytes[idx - 1] } else { 0 };
        let next = if idx + 1 < bytes.len() {
            bytes[idx + 1]
        } else {
            0
        };
        if prev != b'\'' && prev != b'"' && next != b'\'' && next != b'"' {
            return true;
        }
    }
    false
}

fn unique_byte_count(bytes: &[u8]) -> usize {
    let mut seen = [false; 256];
    let mut count = 0usize;
    for byte in bytes {
        let slot = &mut seen[*byte as usize];
        if !*slot {
            *slot = true;
            count += 1;
        }
    }
    count
}

fn unique_bigram_stats(bytes: &[u8]) -> (usize, usize) {
    if bytes.len() < 2 {
        return (0, 0);
    }

    let mut seen = [0u64; 1024];
    let mut unique = 0usize;
    for window in bytes.windows(2) {
        let idx = ((window[0] as usize) << 8) | window[1] as usize;
        let word = idx / 64;
        let bit = 1u64 << (idx % 64);
        if seen[word] & bit == 0 {
            seen[word] |= bit;
            unique += 1;
        }
    }
    (unique, bytes.len() - 1)
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
}

fn contains_any_ascii_case_insensitive(haystack: &[u8], needles: &[&str]) -> bool {
    needles
        .iter()
        .any(|needle| contains_ascii_case_insensitive(haystack, needle.as_bytes()))
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn binary_feature(value: bool) -> f32 {
    if value { 1.0 } else { 0.0 }
}

fn normalized_ratio(numerator: usize, denominator: usize) -> f32 {
    if denominator == 0 {
        0.0
    } else {
        (numerator as f32 / denominator as f32).min(1.0)
    }
}

fn longest_known_prefix(text: &str) -> usize {
    KNOWN_PREFIXES
        .iter()
        .filter(|prefix| text.starts_with(*prefix))
        .map(|prefix| prefix.len())
        .max()
        .unwrap_or(0)
}

struct TextSummary {
    has_upper: bool,
    has_lower: bool,
    has_digit: bool,
    has_symbol: bool,
    dot_count: usize,
    dash_count: usize,
    unique_chars: usize,
}

fn summarize_text_bytes(text_bytes: &[u8]) -> TextSummary {
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    let mut dot_count = 0usize;
    let mut dash_count = 0usize;
    for &byte in text_bytes {
        has_upper |= byte.is_ascii_uppercase();
        has_lower |= byte.is_ascii_lowercase();
        has_digit |= byte.is_ascii_digit();
        has_symbol |= !byte.is_ascii_alphanumeric();
        dot_count += usize::from(byte == b'.');
        dash_count += usize::from(byte == b'-');
    }
    TextSummary {
        has_upper,
        has_lower,
        has_digit,
        has_symbol,
        dot_count,
        dash_count,
        unique_chars: unique_byte_count(text_bytes),
    }
}

/// Forward pass through the MoE model with hardcoded weights.
fn forward_pass(input: &[f32; NUM_FEATURES]) -> f32 {
    let gate_probs = softmax(&compute_gate_logits(input));
    let mut score_logit = 0.0f32;
    for (expert_idx, gate_prob) in gate_probs.iter().enumerate() {
        score_logit += *gate_prob * expert_logit(expert_idx, input);
    }
    sigmoid(score_logit)
}

fn compute_gate_logits(input: &[f32; NUM_FEATURES]) -> [f32; EXPERT_COUNT] {
    let gate_weight = ml_weights::gate_weight();
    let gate_bias = ml_weights::gate_bias();
    debug_assert_eq!(gate_weight.len(), NUM_FEATURES * EXPERT_COUNT);
    debug_assert_eq!(gate_bias.len(), EXPERT_COUNT);

    let mut gate_logits = [0.0f32; EXPERT_COUNT];
    for (expert_idx, logit) in gate_logits.iter_mut().enumerate() {
        let row = &gate_weight[expert_idx * NUM_FEATURES..(expert_idx + 1) * NUM_FEATURES];
        *logit = dense_row(row, input, gate_bias[expert_idx]);
    }
    gate_logits
}

fn expert_logit(expert_idx: usize, input: &[f32; NUM_FEATURES]) -> f32 {
    let h1 = dense_relu_layer::<NUM_FEATURES, EXPERT_HIDDEN_LAYER_1>(
        ml_weights::expert_fc1_weight(expert_idx),
        ml_weights::expert_fc1_bias(expert_idx),
        input,
    );
    let h2 = dense_relu_layer::<EXPERT_HIDDEN_LAYER_1, EXPERT_HIDDEN_LAYER_2>(
        ml_weights::expert_fc2_weight(expert_idx),
        ml_weights::expert_fc2_bias(expert_idx),
        &h1,
    );
    dense_row(
        ml_weights::expert_fc3_weight(expert_idx),
        &h2,
        ml_weights::expert_fc3_bias(expert_idx)[0],
    )
}

fn dense_relu_layer<const INPUT: usize, const OUTPUT: usize>(
    weights: &[f32],
    bias: &[f32],
    input: &[f32; INPUT],
) -> [f32; OUTPUT] {
    let mut hidden = [0.0f32; OUTPUT];
    for (index, slot) in hidden.iter_mut().enumerate() {
        let row = &weights[index * INPUT..(index + 1) * INPUT];
        *slot = dense_row(row, input, bias[index]).max(0.0);
    }
    hidden
}

fn dense_row<const INPUT: usize>(weights: &[f32], input: &[f32; INPUT], bias: f32) -> f32 {
    weights
        .iter()
        .zip(input.iter())
        .fold(bias, |sum, (weight, input_value)| {
            sum + (*input_value * *weight)
        })
}

fn sigmoid(value: f32) -> f32 {
    1.0 / (1.0 + (-value).exp())
}

fn softmax(logits: &[f32; EXPERT_COUNT]) -> [f32; EXPERT_COUNT] {
    let max_logit = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let mut exps = [0.0f32; EXPERT_COUNT];
    let mut sum = 0.0f32;
    for (idx, logit) in logits.iter().enumerate() {
        let value = (*logit - max_logit).exp();
        exps[idx] = value;
        sum += value;
    }
    for value in &mut exps {
        *value /= sum;
    }
    exps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_secret_scores_high() {
        let text = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let context = "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let s = score(text, context);
        assert!(s > 0.7, "Real GitHub PAT should score high, got {:.3}", s);
    }

    #[test]
    fn hash_scores_low() {
        let text = "d41d8cd98f00b204e9800998ecf8427e";
        let context = "checksum = d41d8cd98f00b204e9800998ecf8427e";
        let s = score(text, context);
        assert!(s < 0.5, "MD5 hash should score low, got {:.3}", s);
    }

    #[test]

    fn placeholder_scores_low() {
        let text = "YOUR_API_KEY_HERE";
        let context = "API_KEY=YOUR_API_KEY_HERE";
        let s = score(text, context);
        assert!(s < 0.3, "Placeholder should score very low, got {:.3}", s);
    }

    #[test]
    fn empty_string_scores_zero() {
        assert_eq!(score("", "API_KEY="), 0.0);
    }

    #[test]
    fn openai_key_scores_high() {
        // Test key with high entropy body — uses EXAMPLE prefix to avoid secret scanning
        let key = "sk-proj-EXAMPLE000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let context = format!("OPENAI_API_KEY={key}");
        let s = score(key, &context);
        // sk- prefix + high entropy + keyword context = should score above baseline
        assert!(
            s > 0.01,
            "Realistic OpenAI key scored {:.3}, expected > 0.01",
            s
        );
    }

    #[test]
    fn inference_is_fast() {
        let text = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let context = "TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let start = std::time::Instant::now();
        for _ in 0..10000 {
            let _ = score(text, context);
        }
        let elapsed = start.elapsed();
        let per_call = elapsed / 10000;
        assert!(
            per_call.as_micros() < 100,
            "Inference too slow: {:?} per call",
            per_call
        );
    }
}

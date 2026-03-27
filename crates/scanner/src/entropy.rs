//! Shannon entropy analysis for distinguishing secrets from ordinary text.
//!
//! Real secrets have high entropy (4.5+), while hashes, UUIDs, and placeholders
//! have characteristic entropy profiles that help separate true positives.

/// Shannon entropy in bits per byte. Range: 0.0 (constant) to 8.0 (perfectly random).
/// Compute Shannon entropy in bits per byte.
///
/// # Examples
///
/// ```rust
/// use keyhog_scanner::entropy::shannon_entropy;
///
/// assert_eq!(shannon_entropy(b""), 0.0);
/// ```
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts0 = [0u64; 256];
    let mut counts1 = [0u64; 256];
    let mut counts2 = [0u64; 256];
    let mut counts3 = [0u64; 256];

    let mut chunks = data.chunks_exact(4);
    for chunk in &mut chunks {
        counts0[usize::from(chunk[0])] += 1;
        counts1[usize::from(chunk[1])] += 1;
        counts2[usize::from(chunk[2])] += 1;
        counts3[usize::from(chunk[3])] += 1;
    }

    let mut counts = [0u64; 256];
    for &byte in chunks.remainder() {
        counts[usize::from(byte)] += 1;
    }

    for i in 0..256 {
        counts[i] += counts0[i] + counts1[i] + counts2[i] + counts3[i];
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

/// Normalized entropy: Shannon entropy divided by max possible entropy
/// for the number of unique characters. Range: 0.0 to 1.0.
/// Better than raw Shannon for comparing strings of different lengths/charsets.
/// Compute entropy normalized to the range `0.0..=1.0`.
///
/// # Examples
///
/// ```rust
/// use keyhog_scanner::entropy::normalized_entropy;
///
/// assert_eq!(normalized_entropy(b""), 0.0);
/// ```
pub fn normalized_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let unique_chars = {
        let mut seen = [false; 256];
        for &b in data {
            seen[b as usize] = true;
        }
        seen.iter().filter(|&&v| v).count()
    };

    if unique_chars <= 1 {
        return 0.0;
    }

    let max_entropy = (unique_chars as f64).log2();
    if max_entropy == 0.0 {
        return 0.0;
    }

    shannon_entropy(data) / max_entropy
}

/// Entropy thresholds for credential detection.
/// 4.5 is aggressive enough to catch real secrets (which are typically > 4.5)
/// while avoiding most false positives (hex hashes ~3.5-4.0, UUIDs ~3.8-4.2).
/// Threshold for keyword-context entropy detection.
/// Derivation: English text ~1.5-2.0 bits/byte, hex hashes ~3.5-4.0,
/// real API keys ~4.5-5.5, random bytes ~7.5-8.0.
/// 4.5 sits above hashes and below real secrets. Validated against
/// 79 adversarial tests + 0 FP on express.js + 196 findings on TruffleHog repo.
pub const HIGH_ENTROPY_THRESHOLD: f64 = 4.5;
/// Threshold for keyword-independent detection. Must be very high to avoid
/// FPs on code strings (function names, import paths, constants).
/// Only truly random-looking strings pass this bar.
/// Threshold for keyword-INDEPENDENT entropy detection (no context signal).
/// Higher than HIGH_ENTROPY_THRESHOLD because without keyword context,
/// we need stronger statistical evidence. 5.5 captures real API keys
/// (typically 5.0-6.5) while rejecting most code identifiers (3.0-5.0).
pub const VERY_HIGH_ENTROPY_THRESHOLD: f64 = 5.5;
const CREDENTIAL_CONTEXT_THRESHOLD: f64 = 3.5;
const CREDENTIAL_CONTEXT_MIN_LEN: usize = 16;
const KEYWORD_FREE_MIN_LEN: usize = 30;
const MIN_PASSWORD_LEN: usize = 8;
const FIRST_SOURCE_LINE_NUMBER: usize = 1;
const KEYWORD_FREE_LABEL: &str = "none (high-entropy)";

/// Keywords that indicate a string near them might be a secret.
const SECRET_KEYWORDS: &[&str] = &[
    "api_key",
    "apikey",
    "api-key",
    "api_token",
    "api-token",
    "secret",
    "secret_key",
    "secretkey",
    "token",
    "access_token",
    "auth_token",
    "auth-token",
    "password",
    "passwd",
    "pwd",
    "credential",
    "credentials",
    "private_key",
    "privatekey",
    "client_secret",
    "jwt_secret",
    "jwtsecret",
    "session_key",
    "session-key",
    "signing_key",
    "encryption_key",
    "oauth_token",
    "bearer",
    "authorization",
    "webhook_secret",
    "database_url",
    "connection_string",
    "dsn",
];

/// A high-entropy string found near a secret keyword.
#[derive(Debug, Clone)]
/// Entropy-based candidate match returned by fallback secret detection.
///
/// # Examples
///
/// ```rust,ignore
/// use keyhog_scanner::entropy::EntropyMatch;
/// let _ = std::mem::size_of::<EntropyMatch>();
/// ```
pub struct EntropyMatch {
    /// The candidate string that exceeded the entropy threshold.
    pub value: String,
    /// Shannon entropy measured for `value`.
    pub entropy: f64,
    /// The keyword context that caused the candidate to be evaluated.
    pub keyword: String,
    /// One-based source line number for the match.
    pub line: usize,
    /// Byte offset of the start of the containing line.
    pub offset: usize,
}

/// Check if a file path suggests a config/secret file (where entropy scanning is useful).
/// Source code files have too many high-entropy strings (function names, imports, constants)
/// for entropy to be reliable without ML.
/// Decide whether entropy scanning should run for the given path.
///
/// # Examples
///
/// ```rust
/// use keyhog_scanner::entropy::is_entropy_appropriate;
///
/// assert!(is_entropy_appropriate(Some(".env")));
/// ```
pub fn is_entropy_appropriate(path: Option<&str>) -> bool {
    let Some(path) = path else { return true }; // stdin = scan
    let lower = path.to_lowercase();
    // Config/secret files: entropy is highly useful
    const CONFIG_EXTENSIONS: &[&str] = &[
        ".env",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".properties",
        ".cfg",
        ".conf",
        ".ini",
        ".config",
        ".secrets",
        ".pem",
        ".key",
        ".tfvars",
        ".hcl",
    ];
    for ext in CONFIG_EXTENSIONS {
        if lower.ends_with(ext) {
            return true;
        }
    }
    // Check FILENAME (not full path) for config-like names.
    // "docker_auth_config_test.go" should NOT match just because it contains "config".
    let filename = lower.rsplit('/').next().unwrap_or(&lower);
    const CONFIG_FILENAMES: &[&str] = &[
        ".env",
        "credentials",
        "secrets",
        "apikeys",
        "docker-compose",
        ".npmrc",
        ".pypirc",
        ".netrc",
    ];
    for name in CONFIG_FILENAMES {
        if filename.starts_with(name) || filename == *name {
            return true;
        }
    }
    // Source code files: skip entropy (too noisy without ML)
    false
}

/// Find high-entropy strings near secret keywords in text.
/// This catches secrets that have no known pattern — the TruffleHog gap.
/// Find secret-like tokens using entropy heuristics near likely credential context.
///
/// # Examples
///
/// ```rust
/// use keyhog_scanner::entropy::find_entropy_secrets;
///
/// let matches = find_entropy_secrets("API_KEY=abcdEFGH12345678", 16, 1);
/// assert!(!matches.is_empty());
/// ```
pub fn find_entropy_secrets(
    text: &str,
    min_length: usize,
    context_lines: usize,
) -> Vec<EntropyMatch> {
    let lines: Vec<&str> = text.lines().collect();
    let line_offsets = cumulative_line_offsets(&lines);
    let mut matches = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let keyword_lines = find_keyword_assignment_lines(&lines);

    scan_keyword_contexts(
        &lines,
        &line_offsets,
        &keyword_lines,
        min_length,
        context_lines,
        &mut seen,
        &mut matches,
    );
    scan_keyword_free_candidates(&lines, &line_offsets, &mut seen, &mut matches);
    matches
}

fn find_keyword_assignment_lines<'a>(lines: &'a [&str]) -> Vec<(usize, &'a str)> {
    lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| is_keyword_assignment_line(line).then_some((index, *line)))
        .collect()
}

fn is_keyword_assignment_line(line: &str) -> bool {
    let line_bytes = line.as_bytes();
    let has_keyword = SECRET_KEYWORDS.iter().any(|keyword| {
        let keyword_bytes = keyword.as_bytes();
        line_bytes
            .windows(keyword_bytes.len())
            .any(|window| window.eq_ignore_ascii_case(keyword_bytes))
    });
    let trimmed = line.trim();
    let is_import = trimmed.starts_with("import")
        || trimmed.starts_with("package")
        || trimmed.starts_with("use ")
        || trimmed.starts_with("from ")
        || trimmed.starts_with("require(");
    has_keyword && (line.contains('=') || line.contains(": ")) && !is_import
}

fn scan_keyword_contexts(
    lines: &[&str],
    line_offsets: &[usize],
    keyword_lines: &[(usize, &str)],
    min_length: usize,
    context_lines: usize,
    seen: &mut std::collections::HashSet<String>,
    matches: &mut Vec<EntropyMatch>,
) {
    for (keyword_line_index, keyword_line) in keyword_lines {
        let context = keyword_context(keyword_line, min_length);
        let start = keyword_line_index.saturating_sub(context_lines);
        let end = (*keyword_line_index + context_lines + 1).min(lines.len());
        for line_idx in start..end {
            collect_line_candidates(
                lines[line_idx],
                line_idx,
                line_offsets[line_idx],
                &context,
                seen,
                matches,
            );
        }
    }
}

fn scan_keyword_free_candidates(
    lines: &[&str],
    line_offsets: &[usize],
    seen: &mut std::collections::HashSet<String>,
    matches: &mut Vec<EntropyMatch>,
) {
    let keyword_free_context = KeywordContext {
        keyword: KEYWORD_FREE_LABEL.to_string(),
        threshold: VERY_HIGH_ENTROPY_THRESHOLD,
        min_len: KEYWORD_FREE_MIN_LEN,
        is_credential_context: false,
    };
    for (line_idx, line) in lines.iter().enumerate() {
        collect_line_candidates(
            line,
            line_idx,
            line_offsets[line_idx],
            &keyword_free_context,
            seen,
            matches,
        );
    }
}

struct KeywordContext {
    keyword: String,
    threshold: f64,
    min_len: usize,
    is_credential_context: bool,
}

fn keyword_context(keyword_line: &str, min_length: usize) -> KeywordContext {
    const CREDENTIAL_KEYWORDS: &[&str] = &[
        "password",
        "passwd",
        "pwd",
        "db_pass",
        "db_password",
        "api_key",
        "apikey",
        "api-key",
        "_key",
        "-key",
        "token",
        "_token",
        "-token",
        "secret",
        "_secret",
        "-secret",
    ];

    let lowered = keyword_line.to_lowercase();
    let keyword = SECRET_KEYWORDS
        .iter()
        .find(|keyword| lowered.contains(*keyword))
        .copied()
        .unwrap_or("unknown");
    let is_credential_context = CREDENTIAL_KEYWORDS
        .iter()
        .any(|credential_keyword| lowered.contains(credential_keyword));
    KeywordContext {
        keyword: keyword.to_string(),
        threshold: if is_credential_context {
            CREDENTIAL_CONTEXT_THRESHOLD
        } else {
            HIGH_ENTROPY_THRESHOLD
        },
        min_len: if is_credential_context {
            CREDENTIAL_CONTEXT_MIN_LEN
        } else {
            min_length
        },
        is_credential_context,
    }
}

fn collect_line_candidates(
    line: &str,
    line_idx: usize,
    line_offset: usize,
    context: &KeywordContext,
    seen: &mut std::collections::HashSet<String>,
    matches: &mut Vec<EntropyMatch>,
) {
    for candidate in extract_candidates(line, context.min_len) {
        let entropy = shannon_entropy(candidate.as_bytes());
        if !candidate_is_plausible(&candidate, entropy, context) || !seen.insert(candidate.clone())
        {
            continue;
        }
        matches.push(EntropyMatch {
            value: candidate,
            entropy,
            keyword: context.keyword.clone(),
            line: line_idx + FIRST_SOURCE_LINE_NUMBER,
            offset: line_offset,
        });
    }
}

fn candidate_is_plausible(candidate: &str, entropy: f64, context: &KeywordContext) -> bool {
    if entropy < context.threshold {
        return false;
    }
    if context.is_credential_context {
        return candidate.len() >= MIN_PASSWORD_LEN;
    }
    candidate.len() >= KEYWORD_FREE_MIN_LEN.min(context.min_len) && is_secret_plausible(candidate)
}

fn cumulative_line_offsets(lines: &[&str]) -> Vec<usize> {
    let mut offsets = Vec::with_capacity(lines.len());
    let mut current = 0usize;
    for line in lines {
        offsets.push(current);
        // Chunks are already resident in memory, so the practical upper bound
        // is `usize::MAX` bytes on the current host architecture.
        current = current.saturating_add(line.len().saturating_add(1));
    }
    offsets
}

/// Extract candidate secret strings from a line.
/// Looks for values after `=`, `:`, or inside quotes.
fn extract_candidates(line: &str, min_length: usize) -> Vec<String> {
    let mut candidates = Vec::new();

    // Skip lines that appear to be part of a string concatenation sequence.
    // These are lines with just quoted string fragments, not complete secrets.
    if is_likely_concatenation_fragment(line) {
        return candidates;
    }

    // Extract values after assignment operators (common in config files).
    // Search for `=` first because `:` appears inside secret values (URLs,
    // base64) and splitting there would extract only the tail fragment.
    // For `: ` (YAML/JSON mapping), require the trailing space to avoid
    // matching colons inside values like `postgres://host:5432`.
    if let Some(eq_pos) = line.find('=').or_else(|| line.find(": ")) {
        let sep_len = if line.as_bytes().get(eq_pos) == Some(&b'=') {
            1
        } else {
            2 // ": "
        };
        let value_part = line[eq_pos + sep_len..].trim();
        let cleaned = value_part
            .trim_matches(|c: char| c == '"' || c == '\'' || c == '`' || c == ';' || c == ',');
        if cleaned.len() >= min_length && is_candidate_plausible(cleaned) {
            candidates.push(cleaned.to_string());
        }
    }

    // Extract quoted strings.
    for quote in &['"', '\''] {
        let mut start = None;
        for (i, ch) in line.char_indices() {
            if ch == *quote {
                match start {
                    None => start = Some(i + 1),
                    Some(s) => {
                        let content = &line[s..i];
                        if content.len() >= min_length && is_secret_plausible(content) {
                            candidates.push(content.to_string());
                        }
                        start = None;
                    }
                }
            }
        }
    }

    candidates
}

/// Check if a line is likely a string concatenation fragment.
/// These are lines that contain just a quoted string, often part of a multi-line
/// concatenation in Python, JavaScript, or JSON with line continuations.
fn is_likely_concatenation_fragment(line: &str) -> bool {
    let trimmed = line.trim();

    // Check for Python/Javascript-style: "string" or "string" + or "string" \
    // Pattern: optional whitespace, quote, content, quote, optional + or \ or ,
    if trimmed.starts_with('"') || trimmed.starts_with('\'') {
        // Count quotes in the line
        let double_quotes = trimmed.matches('"').count();
        let single_quotes = trimmed.matches('\'').count();

        // If there's exactly one pair of quotes (2 quotes), it's likely just a quoted string
        if (double_quotes == 2 && single_quotes == 0) || (single_quotes == 2 && double_quotes == 0)
        {
            // Check if the entire line is just the quoted string with optional trailing punctuation
            // Pattern: "content" or 'content' optionally followed by + , \ or )
            let after_quote = if double_quotes == 2 {
                trimmed
                    .rfind('"')
                    .map(|i| &trimmed[i + 1..])
                    .unwrap_or("")
                    .trim()
            } else {
                trimmed
                    .rfind('\'')
                    .map(|i| &trimmed[i + 1..])
                    .unwrap_or("")
                    .trim()
            };

            // If after the closing quote we only have + , \ ) or nothing, it's a fragment
            let is_fragment_suffix = after_quote.is_empty()
                || after_quote == "+"
                || after_quote == "\\"
                || after_quote == ","
                || after_quote == ")"
                || after_quote.starts_with('+')
                || after_quote.starts_with(')');

            if is_fragment_suffix {
                return true;
            }
        }
    }

    // Check for JSON line continuation pattern
    if trimmed.ends_with("\\\"") || trimmed.ends_with("-\\") {
        return true;
    }

    false
}

/// Shared plausibility filter with two modes:
/// - candidate mode: allows hex strings so keyword-guided extraction can inspect them later
/// - secret mode: rejects hex-only strings and requires high entropy
///
/// Controls how strict plausibility filtering is.
enum PlausibilityMode {
    /// Lenient: allows hex strings, used for keyword-context candidates.
    Lenient,
    /// Strict: rejects hex, requires high entropy. Used for keyword-independent scan.
    Strict,
}
fn passes_plausibility_checks(s: &str, mode: PlausibilityMode) -> bool {
    if matches_universal_rejection(s) {
        return false;
    }

    if is_placeholder_ci(s.as_bytes()) || has_low_alnum_ratio(s) {
        return false;
    }

    if matches!(mode, PlausibilityMode::Strict) && !passes_strict_secret_checks(s) {
        return false;
    }

    true
}

fn matches_universal_rejection(s: &str) -> bool {
    s.contains("://")
        || s.starts_with('/')
        || s.starts_with("./")
        || s.starts_with("../")
        || s.starts_with("${{")
        || s.starts_with("{{")
        || s.starts_with("${")
        || s.starts_with("(?")
        || s.starts_with('^')
        || s.starts_with("ssh-")
        || s.starts_with("ecdsa-")
        || (s.starts_with("eyJ") && s.matches('.').count() == 2)
        || s.starts_with("$ANSIBLE_VAULT")
        || s.starts_with("ENC[")
        || s.starts_with("-----BEGIN")
        || (s.starts_with("Ag") && s.len() > 40)
        || s.starts_with("age1")
        || s.starts_with("vault:")
        || s.starts_with("AQI")
        || s.starts_with("CiQ")
        // Reject Windows drive paths like "C:\..." — single ASCII letter + colon.
        || (s.len() > 2
            && s.as_bytes()[1] == b':'
            && s.as_bytes()[0].is_ascii_alphabetic()
            && (s.as_bytes()[2] == b'\\' || s.as_bytes()[2] == b'/'))
        || s.starts_with("```")
        || s.starts_with("---")
        || s.starts_with("===")
}

fn has_low_alnum_ratio(s: &str) -> bool {
    let alnum = s.chars().filter(|c| c.is_alphanumeric()).count() as f64 / s.len().max(1) as f64;
    alnum < 0.5
}

fn passes_strict_secret_checks(s: &str) -> bool {
    if s.chars().all(|c| c.is_ascii_hexdigit()) && s.len() > 10 {
        return false;
    }
    if s.len() > 4
        && let Some(first) = s.chars().next()
        && s.chars().all(|c| c == first)
    {
        return false;
    }
    if s.len() > 16 && unique_char_count(s) < 8 {
        return false;
    }
    if s.len() > 16 && second_half_entropy(s) < 2.5 {
        return false;
    }

    shannon_entropy(s.as_bytes()) >= HIGH_ENTROPY_THRESHOLD
}

fn unique_char_count(s: &str) -> usize {
    let mut seen = std::collections::HashSet::new();
    for ch in s.chars() {
        seen.insert(ch);
    }
    seen.len()
}

fn second_half_entropy(s: &str) -> f64 {
    let mid = s.len() / 2;
    let half_start = s.floor_char_boundary(mid);
    shannon_entropy(&s.as_bytes()[half_start..])
}

/// For extract_candidates: lightweight filter (allows hex for password context).
fn is_candidate_plausible(s: &str) -> bool {
    passes_plausibility_checks(s, PlausibilityMode::Lenient)
}

/// For keyword-independent entropy scan: strict filter (rejects hex, requires entropy).
fn is_secret_plausible(s: &str) -> bool {
    passes_plausibility_checks(s, PlausibilityMode::Strict)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_constant_string() {
        assert!(shannon_entropy(b"aaaaaaaaaa") < 0.1);
    }

    #[test]
    fn entropy_random_string() {
        // High entropy string (looks like an API key)
        let key = b"aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJ";
        assert!(shannon_entropy(key) > 4.0);
    }

    #[test]
    fn entropy_hex_hash() {
        let hash = b"d41d8cd98f00b204e9800998ecf8427e";
        let e = shannon_entropy(hash);
        // Hex hashes have moderate entropy (only 16 possible chars)
        assert!(e > 3.0);
        assert!(e < 5.0);
    }

    #[test]
    fn find_secrets_near_keywords() {
        let text = r#"
# Config
DATABASE_URL=postgres://localhost/mydb
API_KEY=aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkL
DEBUG=true
"#;
        let matches = find_entropy_secrets(text, 16, 2);
        assert!(
            !matches.is_empty(),
            "should find high-entropy string near API_KEY"
        );
        assert_eq!(matches[0].value, "aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkL");
        // The matched value should be the API key content.
        assert!(
            matches.iter().any(|m| m.entropy > 4.0),
            "should have high entropy match"
        );
    }

    #[test]
    fn skip_placeholders() {
        let text = r#"
API_KEY=YOUR_API_KEY_HERE
SECRET=change_me_placeholder
TOKEN=xxxxxxxxxxxxxxxxxxxx
"#;
        let matches = find_entropy_secrets(text, 16, 2);
        assert!(matches.is_empty());
    }

    #[test]
    fn plausible_secret_filter() {
        assert!(!is_secret_plausible("https://example.com/api"));
        assert!(!is_secret_plausible("/usr/local/bin/python"));
        assert!(!is_secret_plausible("your_api_key_here"));
        assert!(is_secret_plausible("aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJ"));
    }

    #[test]
    fn candidate_mode_skips_strict_secret_checks() {
        assert!(is_candidate_plausible("0123456789abcdef"));
        assert!(!is_secret_plausible("0123456789abcdef"));
    }

    #[test]
    fn detect_db_password_hex() {
        let text = "DB_PASSWORD=8ae31cacf141669ddfb5da\n";
        let matches = find_entropy_secrets(text, 8, 2);
        assert!(
            !matches.is_empty(),
            "Should detect hex password near DB_PASSWORD keyword. Got 0 matches."
        );
        assert!(
            matches[0].value.contains("8ae31cac"),
            "Should extract the password value"
        );
    }

    #[test]
    fn entropy_match_offsets_are_cumulative() {
        let text = "first=line\nAPI_KEY=aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkL\n";
        let matches = find_entropy_secrets(text, 16, 2);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].value, "aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkL");
        assert_eq!(matches[0].offset, "first=line\n".len());
    }

    #[test]
    fn entropy_empty_input_is_zero() {
        assert_eq!(shannon_entropy(b""), 0.0);
    }

    #[test]
    fn entropy_single_unique_byte_is_zero() {
        assert_eq!(shannon_entropy(b"zzzzzzzz"), 0.0);
    }

    #[test]
    fn entropy_all_byte_values_is_near_eight() {
        let all_bytes: Vec<u8> = (0u8..=255).collect();
        let entropy = shannon_entropy(&all_bytes);
        assert!((entropy - 8.0).abs() < 1e-9, "entropy was {}", entropy);
    }

    #[test]
    fn entropy_huge_repeated_input_stays_low() {
        let repeated = vec![b'A'; 100_000];
        assert_eq!(shannon_entropy(&repeated), 0.0);
    }

    #[test]
    fn normalized_entropy_empty_input_is_zero() {
        assert_eq!(normalized_entropy(b""), 0.0);
    }

    #[test]
    fn normalized_entropy_single_unique_byte_is_zero() {
        assert_eq!(normalized_entropy(b"aaaaaaaaaaaaaaaa"), 0.0);
    }

    #[test]
    fn normalized_entropy_binary_pattern_reaches_one() {
        let entropy = normalized_entropy(b"abababababababab");
        assert!((entropy - 1.0).abs() < 1e-9, "entropy was {}", entropy);
    }

    #[test]
    fn normalized_entropy_all_unique_bytes_reaches_one() {
        let all_bytes: Vec<u8> = (0u8..=255).collect();
        let entropy = normalized_entropy(&all_bytes);
        assert!((entropy - 1.0).abs() < 1e-9, "entropy was {}", entropy);
    }

    #[test]
    fn normalized_entropy_stays_bounded_for_large_mixed_input() {
        let mut data = Vec::with_capacity(16_000);
        for _ in 0..500 {
            data.extend_from_slice(b"abc123XYZ!@#$%^&*()");
        }
        let entropy = normalized_entropy(&data);
        assert!((0.0..=1.0).contains(&entropy), "entropy was {}", entropy);
    }

    #[test]
    fn entropy_is_appropriate_for_stdin() {
        assert!(is_entropy_appropriate(None));
    }

    #[test]
    fn entropy_is_appropriate_for_config_extensions_case_insensitively() {
        assert!(is_entropy_appropriate(Some("CONFIG/SETTINGS.YAML")));
        assert!(is_entropy_appropriate(Some("keys/server.PEM")));
        assert!(is_entropy_appropriate(Some("infra/secrets.TFVARS")));
    }

    #[test]
    fn entropy_is_appropriate_for_sensitive_filenames_only() {
        assert!(is_entropy_appropriate(Some("/tmp/.npmrc.backup")));
        assert!(is_entropy_appropriate(Some("nested/docker-compose.prod")));
        assert!(is_entropy_appropriate(Some("config/apikeys.txt")));
    }

    #[test]
    fn entropy_is_not_appropriate_for_source_files_even_with_config_substrings() {
        assert!(!is_entropy_appropriate(Some(
            "src/docker_auth_config_test.go"
        )));
        assert!(!is_entropy_appropriate(Some(
            "lib/application_yaml_parser.rs"
        )));
        assert!(!is_entropy_appropriate(Some("src/main.rs")));
    }

    #[test]
    fn entropy_secret_scan_empty_input_returns_no_matches() {
        assert!(find_entropy_secrets("", 16, 2).is_empty());
    }

    #[test]

    fn keyword_free_scan_detects_long_high_entropy_strings() {
        let secret = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@";
        let text = format!("prefix\n  value: \"{secret}\"\nsuffix\n");
        let matches = find_entropy_secrets(&text, 16, 0);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].value, secret);
        assert_eq!(matches[0].keyword, "none (high-entropy)");
        assert_eq!(matches[0].line, 2);
    }

    #[test]
    fn keyword_free_scan_rejects_short_high_entropy_strings() {
        let text = "ZxCvBn123!@#AsDfGh456$%^QwErTy789";
        assert!(find_entropy_secrets(text, 16, 0).is_empty());
    }

    #[test]
    fn duplicate_secret_value_is_reported_once() {
        let secret = "aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkL";
        let text = format!("API_KEY={secret}\nTOKEN={secret}\n");
        let matches = find_entropy_secrets(&text, 16, 1);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].value, secret);
    }

    #[test]
    fn import_statements_with_keywords_are_ignored() {
        let text = "import API_KEY from \"aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkL\"\n";
        assert!(find_entropy_secrets(text, 16, 1).is_empty());
    }

    #[test]
    fn url_like_values_are_rejected_even_in_keyword_context() {
        let text = "DATABASE_URL=https://example.com/super/secret/path/value\n";
        assert!(find_entropy_secrets(text, 16, 1).is_empty());
    }

    #[test]
    fn context_lines_zero_limits_scan_to_keyword_line() {
        let secret = "aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkL";
        let text = format!("API_KEY=placeholder\n\"{secret}\"\n");
        assert!(find_entropy_secrets(&text, 16, 0).is_empty());
    }

    #[test]

    fn context_lines_include_neighboring_lines() {
        let secret = "aK7xP9mQ2wE5rT8yU1iO3pA6sD4fG0hJkL";
        let text = format!("API_KEY=placeholder\n  value: \"{secret}\"\n");
        let matches = find_entropy_secrets(&text, 16, 1);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].value, secret);
        assert_eq!(matches[0].line, 2);
    }

    #[test]
    fn special_character_placeholders_are_rejected() {
        let text = "SECRET=<replace-with-real-secret>\nTOKEN=${{ secrets.API_TOKEN }}\n";
        assert!(find_entropy_secrets(text, 8, 1).is_empty());
    }

    #[test]
    fn large_input_preserves_line_and_offset_for_match() {
        let filler = "abcd1234\n".repeat(2000);
        let secret = "QwErTy123!@#ZxCvBn456$%^AsDfGh789&*(YuIoP0)_+LmNoPqRsTuV";
        let text = format!("{filler}API_KEY={secret}\n");
        let matches = find_entropy_secrets(&text, 16, 0);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].value, secret);
        assert_eq!(matches[0].line, 2001);
        assert_eq!(matches[0].offset, filler.len());
    }
}

/// Case-insensitive placeholder check without heap allocation.
fn is_placeholder_ci(bytes: &[u8]) -> bool {
    const PLACEHOLDERS: &[&[u8]] = &[
        b"example",
        b"placeholder",
        b"change_me",
        b"changeme",
        b"your_",
        b"your-",
        b"xxx",
        b"todo",
        b"fixme",
        b"replace",
        b"insert",
        b"enter_",
        b"enter-",
        b"dummy",
        b"sample",
        b"demo",
        b"fake",
        b"mock",
        b"goes-here",
        b"fill_in",
        b"not-a-real",
        b"not_a_real",
    ];
    PLACEHOLDERS
        .iter()
        .any(|p| bytes.windows(p.len()).any(|w| w.eq_ignore_ascii_case(p)))
        || bytes.contains(&b'<')
        || bytes.contains(&b'>')
        || matches!(
            bytes,
            b"null" | b"none" | b"undefined" | b"empty" | b"default" | b"secret" | b"password"
        )
}

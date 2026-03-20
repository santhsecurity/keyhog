//! Structural context analysis: understand WHERE in code a potential secret appears.
//!
//! Instead of treating code as flat text, we infer the structural context of
//! each match (assignment, comment, test code, encrypted block, documentation)
//! and adjust confidence accordingly. Not an AST parser — just fast,
//! language-agnostic structural inference.

const ASSIGNMENT_CONFIDENCE_MULTIPLIER: f64 = 1.0;
const STRING_LITERAL_CONFIDENCE_MULTIPLIER: f64 = 0.9;
const UNKNOWN_CONFIDENCE_MULTIPLIER: f64 = 0.8;
const DOCUMENTATION_CONFIDENCE_MULTIPLIER: f64 = 0.3;
const COMMENT_CONFIDENCE_MULTIPLIER: f64 = 0.4;
const TEST_CODE_CONFIDENCE_MULTIPLIER: f64 = 0.3;
const ENCRYPTED_CONFIDENCE_MULTIPLIER: f64 = 0.05;
const TEST_PREFIX_LEN: usize = 5;

const ENCRYPTED_BLOCK_LOOKBACK_LINES: usize = 10;
const TEST_FUNCTION_LOOKBACK_LINES: usize = 30;
const DOCSTRING_TOGGLE_REMAINDER: usize = 2;
const DOCSTRING_TOGGLE_MATCH: usize = 1;

/// The structural context of a code location.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CodeContext {
    /// Direct assignment: key = value, key: value, KEY=value
    Assignment,
    /// Inside a comment (// # /* -- etc.)
    Comment,
    /// Inside a test function or test file
    TestCode,
    /// Inside an encrypted/sealed block
    Encrypted,
    /// Inside documentation (docstring, markdown code fence)
    Documentation,
    /// Inside a string literal (normal code)
    StringLiteral,
    /// Unknown / unstructured context
    Unknown,
}

impl CodeContext {
    /// Confidence multiplier for this context.
    /// Assignment = boost. Test/comment/encrypted = reduce.
    pub fn confidence_multiplier(&self) -> f64 {
        match self {
            Self::Assignment => ASSIGNMENT_CONFIDENCE_MULTIPLIER,
            Self::StringLiteral => STRING_LITERAL_CONFIDENCE_MULTIPLIER,
            Self::Unknown => UNKNOWN_CONFIDENCE_MULTIPLIER,
            Self::Documentation => DOCUMENTATION_CONFIDENCE_MULTIPLIER,
            Self::Comment => COMMENT_CONFIDENCE_MULTIPLIER,
            Self::TestCode => TEST_CODE_CONFIDENCE_MULTIPLIER,
            Self::Encrypted => ENCRYPTED_CONFIDENCE_MULTIPLIER,
        }
    }
}

/// Infer the structural context of a match at a given line.
pub fn infer_context(lines: &[&str], line_idx: usize, file_path: Option<&str>) -> CodeContext {
    let documentation_lines = documentation_line_flags(lines);
    infer_context_with_documentation(lines, line_idx, file_path, &documentation_lines)
}

/// Returns true if the match is in a context that indicates a false positive (lockfile, regex def, etc).
pub fn is_false_positive_match_context(
    text: &str,
    match_start: usize,
    file_path: Option<&str>,
) -> bool {
    let window = surrounding_line_window(text, match_start, 1);
    let lower = window.to_ascii_lowercase();
    let path_lower = file_path.map(str::to_ascii_lowercase);

    is_go_sum_checksum(&lower, path_lower.as_deref())
        || is_integrity_hash(&lower)
        || is_configmap_binary_data(&lower)
        || is_git_lfs_pointer_context(&lower)
        || is_renovate_digest_context(&lower)
        || is_cors_header(&lower)
        || is_http_cache_header(&lower)
}

/// Known example/documentation credentials that are intentionally public and
/// should never be flagged. These are published in official vendor docs, SDKs,
/// and test suites. Every major scanner (TruffleHog, Gitleaks) suppresses them.
///
/// Matching is exact and case-sensitive for prefixed keys (AWS, GitHub, Stripe)
/// and case-insensitive for hex hashes. This is a credential-value check, not a
/// context check — it runs before expensive context analysis.
pub fn is_known_example_credential(credential: &str) -> bool {
    // AWS official example keys from documentation
    if credential == "AKIAIOSFODNN7EXAMPLE"
        || credential == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    {
        return true;
    }

    // Stripe test-mode keys from docs (always start with sk_test_ or pk_test_
    // followed by a known example suffix)
    if credential == "sk_test_FAKE"
        || credential == "pk_test_FAKE"
        || credential == "sk_test_FAKE_2"
        || credential == "sk_test_FAKE_1"
    {
        return true;
    }

    // GitHub official example PATs from docs
    if credential == "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01"
        || credential == "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        || credential == "ghp_1234567890abcdefghij1234567890abcdef"
        || credential == "ghp_1234567890abcdefghij1234567890abcdefgh"
        || credential == "github_pat_11AAAAAA0xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    {
        return true;
    }

    // Suffix-based: keys ending in EXAMPLE, example, _test, _sample, _demo
    if credential.ends_with("EXAMPLE")
        || credential.ends_with("EXAMPLEKEY")
        || credential.ends_with("example")
    {
        return true;
    }

    // All-x placeholders (any prefix)
    {
        let body = credential.as_bytes();
        let x_count = body.iter().filter(|&&b| b == b'x' || b == b'X').count();
        if body.len() >= 16 && x_count > body.len() * 3 / 4 {
            return true;
        }
    }

    // Hex-sequential placeholders: a1b2c3d4e5f6..., 8f3a9b2c1d4e...
    // These are commonly used in test fixtures and documentation.
    // Detect by checking if the credential body (minus prefix) is entirely hex
    // and consists of incrementing hex nibble pairs.
    if is_hex_sequential_placeholder(credential) {
        return true;
    }

    // Well-known hashes that appear everywhere (case-insensitive)
    let lower = credential.to_ascii_lowercase();
    // MD5 of empty string
    if lower == "d41d8cd98f00b204e9800998ecf8427e" {
        return true;
    }
    // SHA-256 of "password"
    if lower == "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" {
        return true;
    }
    // SHA-1 of empty string
    if lower == "da39a3ee5e6b4b0d3255bfef95601890afd80709" {
        return true;
    }
    // SHA-256 of empty string
    if lower == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
        return true;
    }

    // Well-known JWT from jwt.io documentation
    if credential.starts_with("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiw") {
        return true;
    }
    if credential.starts_with("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0") {
        return true;
    }

    // Sequential/placeholder pattern: strip prefix, check if remainder is sequential hex/alphanum
    if is_sequential_placeholder(credential) {
        return true;
    }

    false
}

/// Detect placeholder credentials with sequential or repetitive character patterns.
/// E.g. `ghp_1234567890abcdefghij...`, `sk-proj-a1b2c3d4e5f6a7b8...`, `0xA0b86a33E...5E5E5E`
fn is_sequential_placeholder(credential: &str) -> bool {
    // Strip common prefixes to get the "secret part"
    let body = credential
        .strip_prefix("ghp_")
        .or_else(|| credential.strip_prefix("gho_"))
        .or_else(|| credential.strip_prefix("ghs_"))
        .or_else(|| credential.strip_prefix("ghu_"))
        .or_else(|| credential.strip_prefix("github_pat_"))
        .or_else(|| credential.strip_prefix("sk-proj-"))
        .or_else(|| credential.strip_prefix("sk-"))
        .or_else(|| credential.strip_prefix("sk_test_"))
        .or_else(|| credential.strip_prefix("sk_live_"))
        .or_else(|| credential.strip_prefix("pk_test_"))
        .or_else(|| credential.strip_prefix("pk_live_"))
        .or_else(|| credential.strip_prefix("AKIA"))
        .or_else(|| credential.strip_prefix("xoxb-"))
        .or_else(|| credential.strip_prefix("xoxp-"))
        .or_else(|| credential.strip_prefix("0x"))
        .unwrap_or(credential);
    if body.len() < 16 {
        return false;
    }

    let bytes = body.as_bytes();

    // Check for repeating single character (xxxxxxxxxx)
    if bytes.iter().all(|&b| b == bytes[0]) {
        return true;
    }

    // Check for repeating 2-char pattern (e.g., "5E5E5E5E")
    if bytes.len() >= 8 {
        let pair = &bytes[..2];
        if bytes.chunks(2).all(|chunk| chunk == pair || chunk.len() < 2) {
            return true;
        }
    }

    false
}

/// Detect hex-sequential placeholder credentials like `a1b2c3d4e5f6a7b8...`
/// or `8f3a9b2c1d4e5f60...`. These are commonly used in test fixtures.
fn is_hex_sequential_placeholder(credential: &str) -> bool {
    // Strip known prefixes
    let body = credential
        .strip_prefix("sk-proj-")
        .or_else(|| credential.strip_prefix("sk-"))
        .or_else(|| credential.strip_prefix("ghp_"))
        .or_else(|| credential.strip_prefix("0x"))
        .unwrap_or(credential);

    if body.len() < 16 {
        return false;
    }

    // Must be all hex characters
    if !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }

    // Check if it's a repeating hex pattern with incrementing nibbles
    // Pattern: each pair of hex chars increments: a1, b2, c3, d4, e5, f6, a7, b8...
    let bytes: Vec<u8> = body.bytes().collect();
    let pairs: Vec<&[u8]> = bytes.chunks(2).filter(|c| c.len() == 2).collect();
    if pairs.len() < 8 {
        return false;
    }

    // Check if the first hex char of each pair follows an ascending pattern
    let first_chars: Vec<u8> = pairs.iter().map(|p| p[0].to_ascii_lowercase()).collect();
    let ascending = first_chars.windows(2).filter(|w| {
        w[1] == w[0] + 1 || (w[0] == b'f' && w[1] == b'a')
            || (w[0] == b'9' && w[1] == b'a')
            || (w[0] == b'9' && w[1] == b'0')
    }).count();

    // Or check second hex char ascending
    let second_chars: Vec<u8> = pairs.iter().map(|p| p[1].to_ascii_lowercase()).collect();
    let ascending2 = second_chars.windows(2).filter(|w| {
        w[1] == w[0] + 1 || (w[0] == b'f' && w[1] == b'0')
            || (w[0] == b'9' && w[1] == b'0')
            || (w[0] == b'9' && w[1] == b'a')
    }).count();

    // Require 75%+ ascending to avoid false-suppressing real hex hashes.
    // True placeholders like "a1b2c3d4e5f6..." score 90%+.
    ascending > pairs.len() * 3 / 4 || ascending2 > pairs.len() * 3 / 4
}

/// Returns true if the match at the given line should be suppressed as a false positive.
pub fn is_false_positive_context(lines: &[&str], line_idx: usize, file_path: Option<&str>) -> bool {
    let path_lower = file_path.map(str::to_ascii_lowercase);
    is_false_positive_context_with_path(lines, line_idx, path_lower.as_deref())
}

/// Same as `is_false_positive_context` but accepts a pre-lowered path to avoid
/// re-allocating for every match in the same chunk.
pub fn is_false_positive_context_with_path(lines: &[&str], line_idx: usize, path_lower: Option<&str>) -> bool {
    if line_idx >= lines.len() {
        return false;
    }

    let line = lines[line_idx];
    let lower = line.to_ascii_lowercase();

    is_go_sum_checksum(&lower, path_lower.as_deref())
        || is_integrity_hash_context(lines, line_idx, &lower)
        || is_configmap_binary_data_context(lines, line_idx, &lower)
        || is_git_lfs_pointer_context_with_lines(lines, line_idx, &lower)
        || is_renovate_digest_context_with_lines(lines, line_idx, &lower)
        || is_cors_header(&lower)
        || is_http_cache_header_context(lines, line_idx, &lower)
}

/// Infer the structural context of a match, considering documentation blocks.
pub fn infer_context_with_documentation(
    lines: &[&str],
    line_idx: usize,
    file_path: Option<&str>,
    documentation_lines: &[bool],
) -> CodeContext {
    if line_idx >= lines.len() {
        return CodeContext::Unknown;
    }

    let line = lines[line_idx];
    let trimmed = line.trim();

    if file_path.is_some_and(is_test_file) {
        return CodeContext::TestCode;
    }

    if is_in_encrypted_block(lines, line_idx) {
        return CodeContext::Encrypted;
    }

    if is_comment_line(trimmed) {
        return CodeContext::Comment;
    }

    if documentation_lines.get(line_idx).copied().unwrap_or(false) {
        return CodeContext::Documentation;
    }

    if is_in_test_function(lines, line_idx) {
        return CodeContext::TestCode;
    }

    if is_assignment_line(trimmed) {
        return CodeContext::Assignment;
    }

    infer_default_context(trimmed)
}

/// Pre-compute which lines are inside documentation blocks (markdown fences, docstrings).
pub fn documentation_line_flags(lines: &[&str]) -> Vec<bool> {
    let mut flags = vec![false; lines.len()];
    let mut in_markdown_code_block = false;
    let mut in_docstring = false;

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let is_fence = trimmed.starts_with("```");
        let triple_count = trimmed.matches("\"\"\"").count() + trimmed.matches("'''").count();
        let toggles_docstring = triple_count % DOCSTRING_TOGGLE_REMAINDER == DOCSTRING_TOGGLE_MATCH;

        if is_fence || in_markdown_code_block || in_docstring {
            flags[idx] = true;
        }

        if is_fence {
            in_markdown_code_block = !in_markdown_code_block;
        }
        if toggles_docstring {
            in_docstring = !in_docstring;
        }
    }

    flags
}

fn is_test_file(path: &str) -> bool {
    // Extract filename without allocation
    let filename = path.rsplit('/').next().unwrap_or(path);
    let stem = filename.split('.').next().unwrap_or(filename);

    // Safe prefix/suffix checks — `starts_with` and `ends_with` never panic
    // on multi-byte UTF-8, unlike byte-index slicing.
    stem.eq_ignore_ascii_case("test")
        || stem.len() > TEST_PREFIX_LEN && stem.as_bytes().get(..TEST_PREFIX_LEN).is_some_and(|b| b.eq_ignore_ascii_case(b"test_"))
        || filename.ends_with("_test.go") || filename.ends_with("_test.rs")
        || filename.ends_with("_test.py") || filename.ends_with("_test.rb")
        || filename.ends_with(".test.js") || filename.ends_with(".test.ts")
        || filename.ends_with(".spec.js") || filename.ends_with(".spec.ts")
        || path.split('/').any(|component| {
            component.eq_ignore_ascii_case("test")
                || component.eq_ignore_ascii_case("tests")
                || component.eq_ignore_ascii_case("__tests__")
                || component.eq_ignore_ascii_case("fixtures")
                || component.eq_ignore_ascii_case("testdata")
                || component.eq_ignore_ascii_case("spec")
        })
}

fn infer_default_context(trimmed: &str) -> CodeContext {
    if memchr::memchr(b'"', trimmed.as_bytes()).is_some() || memchr::memchr(b'\'', trimmed.as_bytes()).is_some() {
        CodeContext::StringLiteral
    } else {
        CodeContext::Unknown
    }
}

fn is_go_sum_checksum(lower: &str, path_lower: Option<&str>) -> bool {
    memchr::memmem::find(lower.as_bytes(), b"h1:").is_some() || path_lower.is_some_and(|path| path.ends_with(".sum"))
}

fn is_integrity_hash_context(lines: &[&str], line_idx: usize, lower: &str) -> bool {
    is_integrity_hash(lower)
        || surrounding_lines_contain(lines, line_idx, 2, |candidate| {
            is_integrity_hash(&candidate.to_ascii_lowercase())
        })
}

fn is_integrity_hash(lower: &str) -> bool {
    memchr::memmem::find(lower.as_bytes(), b"integrity").is_some() && (memchr::memmem::find(lower.as_bytes(), b"sha256-").is_some() || memchr::memmem::find(lower.as_bytes(), b"sha512-").is_some())
}

fn is_configmap_binary_data_context(lines: &[&str], line_idx: usize, lower: &str) -> bool {
    is_configmap_binary_data(lower)
        || nearby_lines_contain(lines, line_idx, 8, |candidate| {
            let candidate = candidate.trim().to_ascii_lowercase();
            is_configmap_binary_data(&candidate)
        })
}

fn is_configmap_binary_data(lower: &str) -> bool {
    memchr::memmem::find(lower.as_bytes(), b"binarydata:").is_some()
}

fn is_git_lfs_pointer_context_with_lines(lines: &[&str], line_idx: usize, lower: &str) -> bool {
    is_git_lfs_pointer_context(lower)
        || nearby_lines_contain(lines, line_idx, 3, |candidate| {
            is_git_lfs_pointer_context(&candidate.to_ascii_lowercase())
        })
}

fn is_git_lfs_pointer_context(lower: &str) -> bool {
    memchr::memmem::find(lower.as_bytes(), b"oid sha256:").is_some() || memchr::memmem::find(lower.as_bytes(), b"git-lfs").is_some()
}

fn is_renovate_digest_context_with_lines(lines: &[&str], line_idx: usize, lower: &str) -> bool {
    is_renovate_digest_context(lower)
        || surrounding_lines_contain(lines, line_idx, 2, |candidate| {
            is_renovate_digest_context(&candidate.to_ascii_lowercase())
        })
}

fn is_renovate_digest_context(lower: &str) -> bool {
    memchr::memmem::find(lower.as_bytes(), b"renovate/").is_some() && contains_hex_sequence(lower)
}

fn is_cors_header(lower: &str) -> bool {
    memchr::memmem::find(lower.as_bytes(), b"access-control-").is_some()
}

fn is_http_cache_header_context(lines: &[&str], line_idx: usize, lower: &str) -> bool {
    is_http_cache_header(lower)
        || surrounding_lines_contain(lines, line_idx, 1, |candidate| {
            is_http_cache_header(&candidate.to_ascii_lowercase())
        })
}

fn is_http_cache_header(lower: &str) -> bool {
    memchr::memmem::find(lower.as_bytes(), b"etag:").is_some()
        || lower.trim_start().starts_with("etag")
        || memchr::memmem::find(lower.as_bytes(), b" etag").is_some()
        || memchr::memmem::find(lower.as_bytes(), b"\"etag\"").is_some()
}

fn contains_hex_sequence(lower: &str) -> bool {
    let mut run = 0usize;
    for ch in lower.chars() {
        if ch.is_ascii_hexdigit() {
            run += 1;
            if run >= 8 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn nearby_lines_contain(
    lines: &[&str],
    line_idx: usize,
    lookback_lines: usize,
    predicate: impl Fn(&str) -> bool,
) -> bool {
    let start = line_idx.saturating_sub(lookback_lines);
    lines
        .iter()
        .take(line_idx + 1)
        .skip(start)
        .copied()
        .any(predicate)
}

fn surrounding_lines_contain(
    lines: &[&str],
    line_idx: usize,
    radius: usize,
    predicate: impl Fn(&str) -> bool,
) -> bool {
    let start = line_idx.saturating_sub(radius);
    let end = (line_idx + radius + 1).min(lines.len());
    lines[start..end].iter().copied().any(predicate)
}

fn surrounding_line_window(text: &str, offset: usize, radius: usize) -> String {
    let safe_offset = offset.min(text.len());
    let line_idx = memchr::memchr_iter(b'\n', text[..safe_offset].as_bytes()).count();
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return String::new();
    }

    let start = line_idx.saturating_sub(radius);
    let end = (line_idx + radius + 1).min(lines.len());
    lines[start..end].join("\n")
}

fn is_comment_line(trimmed: &str) -> bool {
    trimmed.starts_with("//")
        || trimmed.starts_with('#')
        || (trimmed.starts_with("--") && !trimmed.starts_with("---"))
        || trimmed.starts_with("/*")
        || trimmed.starts_with("<!--")
        || trimmed.starts_with("<#")
        // Block comment continuation: "* text" or "*/", but NOT bare "*" which
        // matches Markdown list items, shell globs, and Makefile rules.
        || trimmed.starts_with("* ") || trimmed.starts_with("*/")
        || trimmed.starts_with("rem ")
        || trimmed.starts_with("REM ")
}

fn is_assignment_line(trimmed: &str) -> bool {
    has_assignment_operator(trimmed) || has_yaml_mapping(trimmed)
}

fn has_assignment_operator(trimmed: &str) -> bool {
    for operator in [":=", "->", "="] {
        if let Some(pos) = trimmed.find(operator)
            && !is_comparison_operator(trimmed, pos, operator)
        {
            return true;
        }
    }
    false
}

fn has_yaml_mapping(trimmed: &str) -> bool {
    memchr::memmem::find(trimmed.as_bytes(), b": ").is_some() && !trimmed.starts_with("- ")
}

fn is_comparison_operator(trimmed: &str, pos: usize, operator: &str) -> bool {
    if operator != "=" {
        return false;
    }

    let before = trimmed[..pos].chars().last();
    let after = trimmed[pos + operator.len()..].chars().next();
    matches!(before, Some('=' | '!' | '>' | '<')) || matches!(after, Some('='))
}

fn is_in_encrypted_block(lines: &[&str], line_idx: usize) -> bool {
    // Look back up to 10 lines for encryption markers.
    let start = line_idx.saturating_sub(ENCRYPTED_BLOCK_LOOKBACK_LINES);
    for line in lines.iter().take(line_idx + 1).skip(start) {
        let trimmed = line.trim();
        if trimmed.starts_with("$ANSIBLE_VAULT")
            || trimmed.starts_with("ENC[")
            || memchr::memmem::find(trimmed.as_bytes(), b"sops:").is_some()
            || memchr::memmem::find(trimmed.as_bytes(), b"sealed-secrets").is_some()
            || trimmed.starts_with("-----BEGIN PGP MESSAGE-----")
            || trimmed.starts_with("-----BEGIN AGE ENCRYPTED")
        {
            return true;
        }
    }
    false
}

fn is_in_test_function(lines: &[&str], line_idx: usize) -> bool {
    // Look back for test function definition.
    let start = line_idx.saturating_sub(TEST_FUNCTION_LOOKBACK_LINES);
    for candidate_line_idx in (start..line_idx).rev() {
        let trimmed = lines[candidate_line_idx].trim();

        // Python: def test_*, class Test*
        if trimmed.starts_with("def test_") || trimmed.starts_with("class Test") {
            return true;
        }
        // JavaScript: it(', describe(', test('
        if trimmed.starts_with("it(")
            || trimmed.starts_with("describe(")
            || trimmed.starts_with("test(")
        {
            return true;
        }
        // Rust: #[test], #[cfg(test)]
        if trimmed == "#[test]" || trimmed == "#[cfg(test)]" {
            return true;
        }
        // Go: func Test*
        if trimmed.starts_with("func Test") {
            return true;
        }
        // Java: @Test
        if trimmed == "@Test" {
            return true;
        }
        // If we hit a non-test function definition, stop looking.
        if (trimmed.starts_with("def ")
            || trimmed.starts_with("func ")
            || trimmed.starts_with("fn ")
            || trimmed.starts_with("function "))
            && memchr::memmem::find(trimmed.as_bytes(), b"test").is_none()
        {
            return false;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignment_context() {
        let lines = vec!["API_KEY = sk-proj-abc123"];
        assert_eq!(infer_context(&lines, 0, None), CodeContext::Assignment);
    }

    #[test]
    fn comment_context() {
        let lines = vec!["# old key: sk-proj-abc123"];
        assert_eq!(infer_context(&lines, 0, None), CodeContext::Comment);
    }

    #[test]
    fn test_file_context() {
        let lines = vec!["key = sk-proj-abc123"];
        assert_eq!(
            infer_context(&lines, 0, Some("tests/test_auth.py")),
            CodeContext::TestCode
        );
    }

    #[test]
    fn encrypted_block_context() {
        let lines = vec!["$ANSIBLE_VAULT;1.1;AES256", "6162636465666768"];
        assert_eq!(infer_context(&lines, 1, None), CodeContext::Encrypted);
    }

    #[test]
    fn documentation_context() {
        let lines = vec![
            "```bash",
            "curl -H 'Authorization: Bearer sk-proj-abc'",
            "```",
        ];
        assert_eq!(infer_context(&lines, 1, None), CodeContext::Documentation);
    }

    #[test]
    fn test_function_context() {
        let lines = vec![
            "def test_api_call():",
            "    key = 'sk-proj-abc123'",
            "    assert call(key)",
        ];
        assert_eq!(infer_context(&lines, 1, None), CodeContext::TestCode);
    }

    #[test]
    fn confidence_multipliers() {
        assert!(
            CodeContext::Assignment.confidence_multiplier()
                > CodeContext::Comment.confidence_multiplier()
        );
        assert!(
            CodeContext::Comment.confidence_multiplier()
                > CodeContext::Encrypted.confidence_multiplier()
        );
        assert!(
            CodeContext::TestCode.confidence_multiplier()
                < CodeContext::Assignment.confidence_multiplier()
        );
    }

    #[test]
    fn false_positive_context_detects_go_sum() {
        let lines = vec!["github.com/example/module v1.0.0 h1:AKIAIOSFODNN7EXAMPLEabc"];
        assert!(is_false_positive_context(&lines, 0, Some("deps/go.sum")));
    }

    #[test]
    fn false_positive_context_detects_configmap_binary_data_block() {
        let lines = vec![
            "kind: ConfigMap",
            "binaryData:",
            "  cert-fingerprint-sha256: Z2hwX2FiYw==",
        ];
        assert!(is_false_positive_context(&lines, 2, None));
    }

    #[test]
    fn false_positive_context_detects_git_lfs_pointer() {
        let lines = vec![
            "version https://git-lfs.github.com/spec/v1",
            "oid sha256:sk-proj-abcdefghijklmnopqrstuvwxyz123456",
        ];
        assert!(is_false_positive_context(&lines, 1, None));
    }

    #[test]
    fn false_positive_context_detects_integrity_hash() {
        let lines = vec!["integrity sha512-sk-proj-abcdefghijklmnopqrstuvwxyz123456"];
        assert!(is_false_positive_context(&lines, 0, None));
    }

    #[test]
    fn false_positive_context_detects_sum_file_path() {
        let lines = vec!["github.com/example/module v1.0.0 checksum"];
        assert!(is_false_positive_context(
            &lines,
            0,
            Some("deps/vendor.sum")
        ));
    }

    #[test]
    fn false_positive_context_detects_renovate_digest() {
        let lines = vec![r#""branchName": "renovate/node-8f3a9b2c1d4e5f60""#];
        assert!(is_false_positive_context(&lines, 0, None));
    }

    #[test]
    fn false_positive_context_detects_cors_header() {
        let lines = vec!["Access-Control-Allow-Headers: Authorization, X-API-Key"];
        assert!(is_false_positive_context(&lines, 0, None));
    }

    #[test]
    fn false_positive_context_detects_http_cache_header() {
        let lines = vec![r#"ETag: W/"xoxb-8f3a9b2c1d4e5f60718293a4b5c6d7e8f9a0b""#];
        assert!(is_false_positive_context(&lines, 0, None));
    }
}

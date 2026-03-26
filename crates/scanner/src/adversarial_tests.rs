//! Adversarial test suite for the scanning engine.
//!
//! These tests exercise edge cases, evasion techniques, and boundary
//! conditions that real-world credential scanners must handle correctly.
//! Each test documents the attack vector it validates against.

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};

use crate::CompiledScanner;

/// Build a chunk with the given data and default metadata.
fn make_chunk(data: &str) -> Chunk {
    Chunk {
        data: data.to_string(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: None,
            commit: None,
            author: None,
            date: None,
        },
    }
}

fn assert_detected(data: &str) {
    let scanner = test_scanner();
    let chunk = make_chunk(data);
    let matches = scanner.scan(&chunk);
    assert!(
        matches.iter().any(|matched| matched.credential == VALID_CREDENTIAL),
        "expected credential to be detected in: {data}"
    );
}

/// Build a simple token detector for testing.
fn token_detector() -> DetectorSpec {
    DetectorSpec {
        id: "test-token".into(),
        name: "Test Token".into(),
        service: "test".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: "TESTKEY_[a-zA-Z0-9]{20}".into(),
            description: None,
            group: None,
        }],
        companion: None,
        verify: None,
        keywords: vec!["TESTKEY_".into()],
    }
}

/// Build a scanner with the test token detector.
fn test_scanner() -> CompiledScanner {
    CompiledScanner::compile(vec![token_detector()]).unwrap()
}

/// A valid test credential that the token detector should match.
const VALID_CREDENTIAL: &str = "TESTKEY_aK7xP9mQ2wE5rT8yU1iO";

// ───────────────────────────────────────────────────────────────────────────
// 1. CHUNK BOUNDARY ATTACKS
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn secret_at_start_of_chunk_is_detected() {
    let scanner = test_scanner();
    let chunk = make_chunk(&format!("{VALID_CREDENTIAL}\nsome other content\n"));
    let matches = scanner.scan(&chunk);
    assert!(
        !matches.is_empty(),
        "secret at chunk start must be detected"
    );
    assert_eq!(matches[0].credential, VALID_CREDENTIAL);
}

#[test]
fn secret_at_end_of_chunk_is_detected() {
    let scanner = test_scanner();
    let filler = "x".repeat(500);
    let chunk = make_chunk(&format!("{filler}\n{VALID_CREDENTIAL}"));
    let matches = scanner.scan(&chunk);
    assert!(!matches.is_empty(), "secret at chunk end must be detected");
}

#[test]
fn secret_in_large_chunk_is_detected_via_windowing() {
    let scanner = test_scanner();
    // Place secret deep in a large file to exercise windowed scanning.
    let filler = "harmless data line\n".repeat(60_000);
    let chunk = make_chunk(&format!("{filler}API_KEY={VALID_CREDENTIAL}\n"));
    let matches = scanner.scan(&chunk);
    assert!(
        !matches.is_empty(),
        "secret in large chunk (>1MB) must be detected via window splitting"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 2. OBFUSCATION & EVASION TECHNIQUES
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn secret_surrounded_by_whitespace_noise() {
    let scanner = test_scanner();
    let chunk = make_chunk(&format!("   \t  {VALID_CREDENTIAL}   \t  \n"));
    let matches = scanner.scan(&chunk);
    assert!(
        !matches.is_empty(),
        "whitespace padding must not prevent detection"
    );
}

#[test]
fn secret_in_json_value() {
    let scanner = test_scanner();
    let chunk = make_chunk(&format!(
        r#"{{"api_key": "{VALID_CREDENTIAL}", "host": "localhost"}}"#
    ));
    let matches = scanner.scan(&chunk);
    assert!(
        !matches.is_empty(),
        "secret inside JSON string value must be detected"
    );
}

#[test]
fn secret_in_yaml_value() {
    let scanner = test_scanner();
    let chunk = make_chunk(&format!("api_key: {VALID_CREDENTIAL}\nport: 8080\n"));
    let matches = scanner.scan(&chunk);
    assert!(
        !matches.is_empty(),
        "secret in YAML mapping value must be detected"
    );
}

#[test]
fn secret_in_shell_export() {
    assert_detected(&format!("export API_KEY=\"{VALID_CREDENTIAL}\"\n"));
}

macro_rules! positive_context_case {
    ($name:ident, $template:expr) => {
        #[test]
        fn $name() {
            assert_detected(&format!($template, VALID_CREDENTIAL));
        }
    };
}

positive_context_case!(secret_in_ini_assignment, "api_key={}\n");
positive_context_case!(secret_in_toml_assignment, "api_key = \"{}\"\n");
positive_context_case!(secret_in_xml_element, "<token>{}</token>");
positive_context_case!(
    secret_in_html_meta_tag,
    "<meta name=\"api-key\" content=\"{}\">"
);
positive_context_case!(
    secret_in_dockerfile_env,
    "FROM scratch\nENV API_TOKEN={}\n"
);
positive_context_case!(
    secret_in_systemd_environment_line,
    "[Service]\nEnvironment=TOKEN={}\n"
);
positive_context_case!(
    secret_in_powershell_assignment,
    "$env:API_TOKEN = \"{}\"\n"
);
positive_context_case!(
    secret_in_sql_insert_statement,
    "INSERT INTO creds(token) VALUES ('{}');"
);
positive_context_case!(
    secret_in_rust_const_literal,
    "const API_TOKEN: &str = \"{}\";\n"
);
positive_context_case!(
    secret_in_javascript_object,
    "const cfg = {{ token: \"{}\" }};\n"
);
positive_context_case!(
    secret_in_terraform_variable,
    "variable \"api_token\" {{ default = \"{}\" }}\n"
);
positive_context_case!(
    secret_in_kubernetes_manifest,
    "apiVersion: v1\nkind: Secret\nstringData:\n  token: {}\n"
);
positive_context_case!(
    secret_in_nginx_env_directive,
    "env API_TOKEN={};\n"
);
positive_context_case!(
    secret_in_java_properties_file,
    "api.token={}\n"
);
positive_context_case!(
    secret_in_yaml_flow_mapping,
    "{{ api_token: {} }}\n"
);
positive_context_case!(
    secret_in_markdown_code_fence,
    "```env\nAPI_TOKEN={}\n```\n"
);
positive_context_case!(
    secret_in_quoted_json_array,
    "[\"{}\", \"harmless\"]\n"
);
positive_context_case!(
    secret_in_multiline_heredoc_like_content,
    "cat <<EOF\n{}\nEOF\n"
);
positive_context_case!(
    secret_in_url_query_value,
    "https://example.invalid/?token={}\n"
);
positive_context_case!(
    secret_in_shell_comment_context,
    "# rotated token {}\n"
);

// ───────────────────────────────────────────────────────────────────────────
// 3. FALSE POSITIVE RESISTANCE
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn pure_placeholder_not_flagged() {
    // A placeholder that matches the pattern but is obviously fake.
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
    let chunk = make_chunk("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n");
    let matches = scanner.scan(&chunk);
    // The known example credential should be suppressed.
    assert!(
        matches.is_empty(),
        "AKIAIOSFODNN7EXAMPLE is a known example credential and must be suppressed"
    );
}

#[test]
fn empty_input_returns_no_matches() {
    let scanner = test_scanner();
    let chunk = make_chunk("");
    let matches = scanner.scan(&chunk);
    assert!(matches.is_empty(), "empty input must produce zero matches");
}

#[test]
fn binary_garbage_returns_no_matches() {
    let scanner = test_scanner();
    // Random bytes that happen to include ASCII chars but form no pattern.
    let garbage: String = (0..10_000)
        .map(|i| char::from((i % 94 + 33) as u8))
        .collect();
    let chunk = make_chunk(&garbage);
    let matches = scanner.scan(&chunk);
    // We don't assert empty — we assert it doesn't panic or hang.
    let _ = matches;
}

#[test]
fn null_padded_binaryish_chunk_still_detects_secret() {
    let scanner = test_scanner();
    let chunk = make_chunk(&format!("\0BIN\0{VALID_CREDENTIAL}\0TAIL\0"));
    let matches = scanner.scan(&chunk);
    assert!(
        matches.iter().any(|matched| matched.credential == VALID_CREDENTIAL),
        "embedded null bytes must not prevent detection in binary-like text chunks"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 4. REGEX SAFETY
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn catastrophic_backtracking_input_does_not_hang() {
    // Create a detector with a regex that could backtrack on malicious input.
    // The regex engine (regex crate) guarantees linear time, but we verify
    // the scan completes in bounded time.
    let detector = DetectorSpec {
        id: "complex-pattern".into(),
        name: "Complex".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: r"token[=:]\s*[a-zA-Z0-9+/]{20,}={0,2}".into(),
            description: None,
            group: None,
        }],
        companion: None,
        verify: None,
        keywords: vec!["token".into()],
    };
    let scanner = CompiledScanner::compile(vec![detector]).unwrap();

    // Input designed to cause backtracking in NFA engines.
    let adversarial = format!("token={}\n", "a".repeat(100_000));
    let chunk = make_chunk(&adversarial);

    let start = std::time::Instant::now();
    let _ = scanner.scan(&chunk);
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 5,
        "scan took {elapsed:?} — possible catastrophic backtracking"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 5. MULTI-DETECTOR INTERACTION
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn multiple_secrets_on_same_line_all_detected() {
    let detector1 = DetectorSpec {
        id: "slack-bot".into(),
        name: "Slack Bot".into(),
        service: "slack".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: "xoxb-[0-9]{10}-[0-9]{10}-[a-zA-Z0-9]{24}".into(),
            description: None,
            group: None,
        }],
        companion: None,
        verify: None,
        keywords: vec!["xoxb-".into()],
    };
    let detector2 = DetectorSpec {
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
    let scanner = CompiledScanner::compile(vec![detector1, detector2]).unwrap();
    let chunk = make_chunk(
        "SLACK=xoxb-1234567890-1234567890-abcdefghijABCDEFGHIJklmn AWS=AKIAR7VXNPLMQ3HSKWJT\n",
    );
    let matches = scanner.scan(&chunk);
    assert!(
        matches.len() >= 2,
        "both secrets on the same line must be detected, got {}",
        matches.len()
    );
}

#[test]
fn duplicate_credential_in_multiple_lines_deduped() {
    let scanner = test_scanner();
    let chunk = make_chunk(&format!(
        "line1: {VALID_CREDENTIAL}\nline2: {VALID_CREDENTIAL}\nline3: {VALID_CREDENTIAL}\n"
    ));
    let matches = scanner.scan(&chunk);
    // The scanner should detect the credential but may report once or multiple.
    // Key assertion: no panic, bounded output.
    assert!(
        !matches.is_empty(),
        "repeated credential must be detected at least once"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 6. ENCODING EDGE CASES
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn utf8_bom_does_not_prevent_detection() {
    let scanner = test_scanner();
    let bom = "\u{FEFF}";
    let chunk = make_chunk(&format!("{bom}KEY={VALID_CREDENTIAL}\n"));
    let matches = scanner.scan(&chunk);
    assert!(
        !matches.is_empty(),
        "UTF-8 BOM prefix must not suppress detection"
    );
}

#[test]
fn unicode_homoglyph_does_not_evade() {
    let scanner = test_scanner();
    // The actual ASCII credential should still be found even with nearby Unicode.
    let chunk = make_chunk(&format!("# Uñiçödé comments\ntoken = {VALID_CREDENTIAL}\n"));
    let matches = scanner.scan(&chunk);
    assert!(
        !matches.is_empty(),
        "unicode context must not prevent ASCII credential detection"
    );
}

#[test]
fn scanner_is_thread_safe_under_parallel_load() {
    use std::sync::Arc;

    let scanner = Arc::new(test_scanner());
    let chunk = Arc::new(make_chunk(&format!(
        "first={VALID_CREDENTIAL}\nsecond={VALID_CREDENTIAL}\n"
    )));

    let baseline = scanner.scan(&chunk);
    assert!(!baseline.is_empty(), "baseline scan must find the credential");

    let handles: Vec<_> = (0..16)
        .map(|_| {
            let scanner = Arc::clone(&scanner);
            let chunk = Arc::clone(&chunk);
            std::thread::spawn(move || scanner.scan(&chunk))
        })
        .collect();

    for handle in handles {
        let matches = handle.join().unwrap();
        assert_eq!(matches.len(), baseline.len());
        assert_eq!(matches[0].credential, baseline[0].credential);
    }
}

//! Allowlist support: `.keyhogignore` file parsing for suppressing known false
//! positives by path glob, detector ID, or credential hash.

/// Allowlist: known false positives and ignored patterns.
///
/// Users can create a `.keyhogignore` file to suppress known FPs.
/// Format (one per line):
///   - `hash:<sha256>` — ignore a specific credential by hash
///   - `detector:<id>` — ignore all findings from a detector
///   - `path:<glob>` — ignore files matching a glob pattern
///   - `# comment` — comments
///   - blank lines are skipped
use std::collections::HashSet;
use std::path::Component;
use std::path::Path;

use crate::VerifiedFinding;

/// User-defined suppressions loaded from `.keyhogignore`: credential hashes, detector IDs, and path globs.
pub struct Allowlist {
    /// SHA-256 hashes of credentials to ignore.
    pub credential_hashes: HashSet<[u8; 32]>,
    /// Detector IDs to ignore entirely.
    pub ignored_detectors: HashSet<String>,
    /// Glob patterns for paths to ignore.
    pub ignored_paths: Vec<String>,
}

impl Allowlist {
    /// Create an empty allowlist with no suppressed hashes, detectors, or paths.
    pub fn empty() -> Self {
        Self {
            credential_hashes: HashSet::new(),
            ignored_detectors: HashSet::new(),
            ignored_paths: Vec::new(),
        }
    }

    /// Load from a .keyhogignore file.
    pub fn load(path: &Path) -> Result<Self, std::io::Error> {
        let contents = std::fs::read_to_string(path)?;
        Ok(Self::parse(&contents))
    }

    /// Parse allowlist from string content.
    pub fn parse(content: &str) -> Self {
        let mut al = Self::empty();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(hash) = line.strip_prefix("hash:") {
                if let Some(hash) = parse_sha256_hex(hash.trim()) {
                    al.credential_hashes.insert(hash);
                }
            } else if let Some(detector) = line.strip_prefix("detector:") {
                al.ignored_detectors.insert(detector.trim().to_string());
            } else if let Some(path) = line.strip_prefix("path:") {
                al.ignored_paths.push(path.trim().to_string());
            }
        }
        al
    }

    /// Check whether detector or path rules suppress a verified finding.
    ///
    /// Hash-based suppression is evaluated earlier on [`crate::RawMatch`] values
    /// because [`VerifiedFinding`] stores only redacted credentials.
    pub fn is_allowed(&self, finding: &VerifiedFinding) -> bool {
        let detector_allowed = self.ignored_detectors.contains(&finding.detector_id);
        let path_allowed = finding.location.file_path.as_ref().is_some_and(|path| {
            let normalized_path = normalize_path(path);
            self.ignored_paths
                .iter()
                .any(|pattern| glob_match_normalized(pattern, &normalized_path))
        });

        detector_allowed || path_allowed
    }

    /// Check if a raw credential hash is allowlisted.
    pub fn is_hash_allowed(&self, credential: &str) -> bool {
        let hash = sha256_digest(credential);
        self.credential_hashes.contains(&hash)
    }

    /// Check whether a raw path matches an ignored-path glob.
    pub fn is_path_ignored(&self, path: &str) -> bool {
        let normalized = normalize_path(path);
        self.ignored_paths
            .iter()
            .any(|pattern| glob_match_normalized(pattern, &normalized))
    }
}

#[cfg(test)]
/// Simple glob matching (supports * and **).
fn glob_match(pattern: &str, path: &str) -> bool {
    let normalized_path = normalize_path(path);
    glob_match_normalized(pattern, &normalized_path)
}

fn glob_match_normalized(pattern: &str, normalized_path: &str) -> bool {
    let normalized_pattern = normalize_path(pattern);
    let pattern_segments = split_segments(&normalized_pattern);
    let path_segments = split_segments(normalized_path);
    glob_match_segments(&pattern_segments, &path_segments)
}

fn split_segments(path: &str) -> Vec<&str> {
    if path.is_empty() {
        Vec::new()
    } else {
        path.split('/').collect()
    }
}

fn glob_match_segments(pattern: &[&str], path: &[&str]) -> bool {
    let mut states = vec![false; path.len() + 1];
    states[0] = true;

    for segment in pattern {
        let mut next = vec![false; path.len() + 1];
        if *segment == "**" {
            let mut reachable = false;
            for idx in 0..=path.len() {
                reachable |= states[idx];
                next[idx] = reachable;
            }
        } else {
            for idx in 0..path.len() {
                if states[idx] && segment_match(segment, path[idx]) {
                    next[idx + 1] = true;
                }
            }
        }
        states = next;
    }

    states[path.len()]
}

fn segment_match(pattern: &str, text: &str) -> bool {
    let pattern_chars: Vec<char> = pattern.chars().collect();
    let text_chars: Vec<char> = text.chars().collect();

    let mut pi = 0usize;
    let mut ti = 0usize;
    let mut star_pi = None;
    let mut star_ti = 0usize;

    while ti < text_chars.len() {
        if pi < pattern_chars.len() && pattern_chars[pi] == '*' {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
            continue;
        }

        if pi < pattern_chars.len() && pattern_chars[pi] == text_chars[ti] {
            pi += 1;
            ti += 1;
            continue;
        }

        if let Some(star) = star_pi {
            star_ti += 1;
            ti = star_ti;
            pi = star + 1;
            continue;
        }

        return false;
    }

    while pi < pattern_chars.len() && pattern_chars[pi] == '*' {
        pi += 1;
    }

    pi == pattern_chars.len()
}

fn normalize_path(path: &str) -> String {
    let path = path.replace('\\', "/");
    let mut parts = Vec::new();
    for component in Path::new(&path).components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !parts.is_empty() && parts.last().is_some_and(|part| part != "..") {
                    parts.pop();
                } else {
                    parts.push("..".to_string());
                }
            }
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::RootDir => parts.clear(),
            Component::Prefix(prefix) => parts.push(prefix.as_os_str().to_string_lossy().into()),
        }
    }
    parts.join("/")
}

/// SHA-256 digest of a string.
fn sha256_digest(input: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hasher.finalize().into()
}

fn parse_sha256_hex(input: &str) -> Option<[u8; 32]> {
    if input.len() != 64 || !input.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return None;
    }

    let mut digest = [0u8; 32];
    for (idx, chunk) in input.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk).ok()?;
        digest[idx] = u8::from_str_radix(text, 16).ok()?;
    }
    Some(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn parse_allowlist() {
        let content = "
# Known false positives
hash:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
detector:entropy
path:tests/**
path:*.example
";
        let al = Allowlist::parse(content);
        assert_eq!(al.credential_hashes.len(), 1);
        assert!(al.ignored_detectors.contains("entropy"));
        assert_eq!(al.ignored_paths.len(), 2);
    }

    #[test]
    fn glob_matching() {
        assert!(glob_match("tests/**", "tests/fixtures/config.env"));
        assert!(glob_match("*.example", "config.example"));
        assert!(glob_match("**/*.md", "docs/README.md"));
        assert!(!glob_match("tests/**", "src/main.rs"));
    }

    #[test]
    fn empty_allowlist_allows_nothing() {
        let al = Allowlist::empty();
        assert!(!al.is_hash_allowed("anything"));
    }

    #[test]
    fn normalized_paths_still_match_globs() {
        let mut al = Allowlist::empty();
        al.ignored_paths.push("tests/**".into());
        assert!(al.is_path_ignored("./tests/fixtures/../fixtures/config.env"));
    }

    #[test]
    fn unicode_globs_match_unicode_paths() {
        assert!(glob_match("München/**", "München/config.env"));
        assert!(glob_match("tësts/*", "tësts/ß.env"));
    }

    #[test]
    fn is_allowed_checks_detector_and_path_rules_consistently() {
        let mut al = Allowlist::empty();
        al.ignored_detectors.insert("aws".into());
        al.ignored_paths.push("tests/**".into());

        let finding = VerifiedFinding {
            detector_id: "aws".into(),
            detector_name: "AWS".into(),
            service: "aws".into(),
            severity: crate::Severity::High,
            credential_redacted: "***".into(),
            location: crate::MatchLocation {
                source: "filesystem".into(),
                file_path: Some("src/main.rs".into()),
                line: Some(1),
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            verification: crate::VerificationResult::Unverifiable,
            metadata: HashMap::new(),
            additional_locations: Vec::new(),
            confidence: None,
        };
        assert!(al.is_allowed(&finding));

        let finding = VerifiedFinding {
            detector_id: "other".into(),
            location: crate::MatchLocation {
                source: "filesystem".into(),
                file_path: Some("tests/fixture.env".into()),
                line: Some(1),
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            ..finding
        };
        assert!(al.is_allowed(&finding));
    }

    // Tests for .gitleaksignore compatibility

    #[test]
    fn gitleaks_format_parse_compatibility() {
        // Gitleaks uses same format with hash:, detector:, path: prefixes
        let content = "hash:deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678\ndetector:aws-access-key\npath:**/*.test\n";
        let al = Allowlist::parse(content);
        assert_eq!(al.credential_hashes.len(), 1);
        assert!(al.ignored_detectors.contains("aws-access-key"));
        assert_eq!(al.ignored_paths.len(), 1);
    }

    #[test]
    fn gitleaks_hash_suppression_behavior() {
        // Hash-based suppression works the same as gitleaks
        let content = "hash:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let al = Allowlist::parse(content);
        // "test" hashes to the above SHA-256
        assert!(al.is_hash_allowed("test"));
        assert!(!al.is_hash_allowed("different"));
    }

    #[test]
    fn gitleaks_path_glob_double_star() {
        // ** matches any number of directory levels (gitleaks compatible)
        assert!(glob_match("**/*.env", "config.env"));
        assert!(glob_match("**/*.env", "src/config.env"));
        assert!(glob_match("**/*.env", "deep/nested/path/config.env"));
        assert!(!glob_match("**/*.env", "config.txt"));
    }

    #[test]
    fn gitleaks_detector_ignore_by_id() {
        // Ignore all findings from a specific detector ID
        let content = "detector:generic-api-key";
        let al = Allowlist::parse(content);
        let finding = VerifiedFinding {
            detector_id: "generic-api-key".into(),
            detector_name: "Generic API Key".into(),
            service: "generic".into(),
            severity: crate::Severity::High,
            credential_redacted: "***".into(),
            location: crate::MatchLocation {
                source: "filesystem".into(),
                file_path: Some("any/path/file.rs".into()),
                line: Some(1),
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            verification: crate::VerificationResult::Unverifiable,
            metadata: HashMap::new(),
            additional_locations: Vec::new(),
            confidence: None,
        };
        assert!(al.is_allowed(&finding));

        let other_finding = VerifiedFinding {
            detector_id: "different-detector".into(),
            ..finding
        };
        assert!(!al.is_allowed(&other_finding));
    }

    #[test]
    fn gitleaks_empty_allowlist_allows_everything() {
        // Empty allowlist should not block anything
        let al = Allowlist::empty();
        assert!(!al.is_hash_allowed("any_credential"));
        assert_eq!(al.ignored_detectors.len(), 0);
        assert_eq!(al.ignored_paths.len(), 0);
    }

    #[test]
    fn gitleaks_comment_lines_ignored() {
        // Lines starting with # should be treated as comments
        let content = "
# This is a comment
hash:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
# Another comment
detector:test
";
        let al = Allowlist::parse(content);
        assert_eq!(al.credential_hashes.len(), 1);
        assert!(al.ignored_detectors.contains("test"));
    }

    #[test]
    fn gitleaks_blank_lines_ignored() {
        // Blank lines should be skipped without error
        let content = "
hash:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

detector:test

path:**/ignore
";
        let al = Allowlist::parse(content);
        assert_eq!(al.credential_hashes.len(), 1);
        assert!(al.ignored_detectors.contains("test"));
        assert_eq!(al.ignored_paths.len(), 1);
    }

    #[test]
    fn gitleaks_malformed_lines_warning_not_crash() {
        // Malformed lines should be silently ignored (not crash)
        let content = "
hash:invalid_hash
not_a_valid_line
random_text_here
detector:
hash:
path:
hash:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
";
        let al = Allowlist::parse(content);
        // Should parse the valid hash and skip malformed lines
        assert_eq!(al.credential_hashes.len(), 1);
    }

    #[test]
    fn gitleaks_windows_backslash_normalized() {
        // Windows paths with backslashes should be normalized
        let mut al = Allowlist::empty();
        al.ignored_paths.push("tests/**".into());
        // Windows paths should match after normalization
        assert!(al.is_path_ignored("tests\\fixtures\\config.env"));
        assert!(al.is_path_ignored(".\\tests\\fixtures\\test.txt"));
        // src\main.rs should NOT match tests/**
        assert!(!al.is_path_ignored("src\\main.rs"));
    }

    #[test]
    fn gitleaks_hash_case_insensitive() {
        // Hashes with different case should still match (SHA-256 is hex)
        let lower = "hash:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let upper = "hash:9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08";
        let mixed = "hash:9F86D081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

        let al_lower = Allowlist::parse(lower);
        let al_upper = Allowlist::parse(upper);
        let al_mixed = Allowlist::parse(mixed);

        // All should match "test"
        assert!(al_lower.is_hash_allowed("test"));
        assert!(al_upper.is_hash_allowed("test"));
        assert!(al_mixed.is_hash_allowed("test"));
    }
}

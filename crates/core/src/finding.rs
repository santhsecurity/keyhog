//! Scanner findings: the output type for detected secrets with location,
//! confidence, detector metadata, and optional verification status.

use serde::Serialize;
use std::collections::HashMap;

use crate::Severity;

/// A credential match found by the scanner, before verification.
#[derive(Debug, Clone, Serialize)]
pub struct RawMatch {
    /// Stable detector identifier.
    pub detector_id: String,
    /// Human-readable detector name.
    pub detector_name: String,
    /// Service namespace associated with the detector.
    pub service: String,
    /// Detector severity level.
    pub severity: Severity,
    /// Matched credential bytes before redaction.
    pub credential: String,
    /// Companion credential or context value extracted nearby.
    pub companion: Option<String>,
    /// Source location for the match.
    pub location: MatchLocation,
    /// Shannon entropy of the matched credential (0.0 - 8.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy: Option<f64>,
    /// Confidence score (0.0 - 1.0) combining entropy, keyword proximity, file type, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
}

/// Where a credential was found: file path, line number, commit, and author.
#[derive(Debug, Clone, Serialize)]
pub struct MatchLocation {
    /// Logical source backend, such as `filesystem` or `git`.
    pub source: String,
    /// File path, object key, or logical path when available.
    pub file_path: Option<String>,
    /// One-based line number when known.
    pub line: Option<usize>,
    /// Byte offset from the start of the source chunk.
    pub offset: usize,
    /// Commit identifier for history-derived matches.
    pub commit: Option<String>,
    /// Commit author when available.
    pub author: Option<String>,
    /// Commit timestamp when available.
    pub date: Option<String>,
}

/// A finding after verification — the final output.
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedFinding {
    /// Stable detector identifier.
    pub detector_id: String,
    /// Human-readable detector name.
    pub detector_name: String,
    /// Service namespace associated with the detector.
    pub service: String,
    /// Detector severity level.
    pub severity: Severity,
    /// Redacted credential string suitable for output.
    pub credential_redacted: String,
    /// Primary source location for the finding.
    pub location: MatchLocation,
    /// Verification outcome for the credential.
    pub verification: VerificationResult,
    /// Extra metadata extracted from verification responses.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
    /// Additional duplicate locations that resolved into the same finding.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub additional_locations: Vec<MatchLocation>,
    /// Confidence score (0.0 - 1.0) combining entropy, keyword proximity, file type, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
}

/// Result of live verification: whether the credential is active, revoked, or untested.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationResult {
    /// The credential was verified as active.
    Live,
    /// The credential was checked and appears invalid.
    Dead,
    /// Verification was throttled by the upstream service.
    RateLimited,
    /// Verification failed before a conclusive result was produced.
    Error(String),
    /// The detector has no live verification path.
    Unverifiable,
    /// Verification was disabled for this scan.
    Skipped,
}

impl RawMatch {
    /// Deduplication key: same detector + same credential = same finding.
    /// Git history includes commit ID so the same secret in different commits stays distinct.
    pub fn deduplication_key(&self) -> (String, String) {
        if self.location.source == "git-history" {
            (
                format!(
                    "{}:{}",
                    self.detector_id,
                    self.location.commit.clone().unwrap_or_default()
                ),
                self.credential.clone(),
            )
        } else {
            (self.detector_id.clone(), self.credential.clone())
        }
    }
}

/// Redact a credential for safe display without leaking type prefixes or exact length.
pub fn redact(credential: &str) -> String {
    if credential.is_empty() {
        return "*".repeat(8);
    }
    if credential.len() <= SHORT_SECRET_MAX_LEN {
        return redact_short_secret(credential);
    }
    redact_with_prefix_preservation(credential)
}

const SHORT_SECRET_MAX_LEN: usize = 8;
const SHORT_SECRET_EDGE_CHARS: usize = 2;
const DEFAULT_REDACTION_EDGE_CHARS: usize = 4;
const MAX_VISIBLE_PREFIX_CHARS: usize = 8;
const REDACTION_SEPARATOR: &str = "...";

fn redact_short_secret(credential: &str) -> String {
    let start = first_chars(credential, SHORT_SECRET_EDGE_CHARS);
    let end = last_chars(credential, SHORT_SECRET_EDGE_CHARS);
    format!("{start}{REDACTION_SEPARATOR}{end}")
}

fn redact_with_prefix_preservation(credential: &str) -> String {
    let prefix_len = visible_prefix_len(credential);
    let suffix_len = last_chars(credential, DEFAULT_REDACTION_EDGE_CHARS).len();
    if prefix_len == 0 || credential.len() <= prefix_len + suffix_len {
        return redact_without_prefix_preservation(credential);
    }
    let prefix = &credential[..prefix_len];
    let suffix = &credential[credential.len() - suffix_len..];
    format!("{prefix}{REDACTION_SEPARATOR}{suffix}")
}

fn visible_prefix_len(credential: &str) -> usize {
    credential
        .char_indices()
        .take_while(|(_, ch)| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        .take(MAX_VISIBLE_PREFIX_CHARS)
        .last()
        .map(|(idx, ch)| idx + ch.len_utf8())
        .unwrap_or(0)
        .min(
            credential
                .len()
                .saturating_sub(DEFAULT_REDACTION_EDGE_CHARS),
        )
}

fn redact_without_prefix_preservation(credential: &str) -> String {
    let start = first_chars(credential, DEFAULT_REDACTION_EDGE_CHARS);
    let end = last_chars(credential, DEFAULT_REDACTION_EDGE_CHARS);
    if start == end {
        format!("{start}{REDACTION_SEPARATOR}")
    } else {
        format!("{start}{REDACTION_SEPARATOR}{end}")
    }
}

fn first_chars(value: &str, count: usize) -> String {
    value.chars().take(count).collect()
}

fn last_chars(value: &str, count: usize) -> String {
    let total = value.chars().count();
    value.chars().skip(total.saturating_sub(count)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction() {
        assert_eq!(redact("xoxb-1234567890-abc"), "xoxb-123...-abc");
        assert_eq!(redact("short"), "sh...rt");
        assert_eq!(redact("AKIA1234567890ABCDEF"), "AKIA1234...CDEF");
        assert_eq!(
            redact("sk-proj-abcdefghijklmnopqrstuvwxyz1234"),
            "sk-proj-...1234"
        );
    }

    #[test]
    fn deduplication_key_groups_same_credential() {
        let m1 = RawMatch {
            detector_id: "aws".into(),
            detector_name: "AWS".into(),
            service: "aws".into(),
            severity: Severity::Critical,
            credential: "AKIAIOSFODNN7EXAMPLE".into(),
            companion: None,
            location: MatchLocation {
                source: "fs".into(),
                file_path: Some("file1.py".into()),
                line: Some(10),
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            entropy: None,
            confidence: None,
        };
        let m2 = RawMatch {
            location: MatchLocation {
                file_path: Some("file2.py".into()),
                line: Some(20),
                ..m1.location.clone()
            },
            ..m1.clone()
        };
        assert_eq!(m1.deduplication_key(), m2.deduplication_key());
    }
}

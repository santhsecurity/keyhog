//! Scanner findings: the output type for detected secrets with location,
//! confidence, detector metadata, and optional verification status.

use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use crate::Severity;

/// A raw pattern match before verification or deduplication.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RawMatch {
    /// Stable detector identifier.
    #[serde(with = "serde_arc_str")]
    pub detector_id: Arc<str>,
    /// Human-readable detector name.
    #[serde(with = "serde_arc_str")]
    pub detector_name: Arc<str>,
    /// Service namespace associated with the detector.
    #[serde(with = "serde_arc_str")]
    pub service: Arc<str>,
    /// Detector severity level.
    pub severity: Severity,
    /// Matched credential bytes before redaction.
    #[serde(with = "serde_arc_str")]
    pub credential: Arc<str>,
    /// SHA-256 hash of the credential for allowlisting and deduplication.
    pub credential_hash: String,
    /// Companion credential or context value extracted nearby.
    pub companions: std::collections::HashMap<String, String>,
    /// Source location for the match.
    pub location: MatchLocation,
    /// Shannon entropy of the matched credential (0.0 - 8.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy: Option<f64>,
    /// Confidence score (0.0 - 1.0) combining entropy, keyword proximity, file type, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
}

impl Eq for RawMatch {}

impl PartialOrd for RawMatch {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RawMatch {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Higher confidence first
        let self_conf = self.confidence.unwrap_or(0.0);
        let other_conf = other.confidence.unwrap_or(0.0);

        if (self_conf - other_conf).abs() > f64::EPSILON {
            return other_conf
                .partial_cmp(&self_conf)
                .unwrap_or(std::cmp::Ordering::Equal);
        }

        // Then higher severity first (Critical > High > Medium > Low > Info)
        match other.severity.cmp(&self.severity) {
            std::cmp::Ordering::Equal => {}
            ord => return ord,
        }

        // Finally, deterministic sort by detector and credential
        match self.detector_id.cmp(&other.detector_id) {
            std::cmp::Ordering::Equal => self.credential.cmp(&other.credential),
            ord => ord,
        }
    }
}

/// Where a credential was found: file path, line number, commit, and author.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MatchLocation {
    /// Logical source backend, such as `filesystem` or `git`.
    #[serde(with = "serde_arc_str")]
    pub source: Arc<str>,
    /// File path, object key, or logical path when available.
    #[serde(with = "serde_arc_str_opt")]
    pub file_path: Option<Arc<str>>,
    /// One-based line number when known.
    pub line: Option<usize>,
    /// Byte offset from the start of the source chunk.
    pub offset: usize,
    /// Commit identifier for history-derived matches.
    #[serde(with = "serde_arc_str_opt")]
    pub commit: Option<Arc<str>>,
    /// Commit author when available.
    #[serde(with = "serde_arc_str_opt")]
    pub author: Option<Arc<str>>,
    /// Commit timestamp when available.
    #[serde(with = "serde_arc_str_opt")]
    pub date: Option<Arc<str>>,
}

/// A finding after verification — the final output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedFinding {
    /// Stable detector identifier.
    #[serde(with = "serde_arc_str")]
    pub detector_id: Arc<str>,
    /// Human-readable detector name.
    #[serde(with = "serde_arc_str")]
    pub detector_name: Arc<str>,
    /// Service namespace associated with the detector.
    #[serde(with = "serde_arc_str")]
    pub service: Arc<str>,
    /// Detector severity level.
    pub severity: Severity,
    /// Redacted version of the credential for reporting.
    pub credential_redacted: Cow<'static, str>,
    /// SHA-256 hash of the original credential for internal correlation.
    pub credential_hash: String,
    /// Source location for the match.
    pub location: MatchLocation,
    /// Verification result.
    pub verification: VerificationResult,
    /// Additional provider-specific metadata (e.g. account ID, scope).
    pub metadata: HashMap<String, String>,
    /// Additional duplicate locations found for this credential.
    pub additional_locations: Vec<MatchLocation>,
    /// Confidence score (0.0 - 1.0) combining entropy, keyword proximity, file type, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
}

/// Result of live verification: whether the credential is active, revoked, or untested.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationResult {
    /// Credential is active and verified by the provider.
    Live,
    /// Credential is valid but has been explicitly revoked or disabled.
    Revoked,
    /// Credential was rejected by the provider (invalid password/token).
    Dead,
    /// Provider returned a rate-limit error (e.g. 429).
    RateLimited,
    /// Verification failed due to network error or timeout.
    Error(String),
    /// Detector does not support live verification.
    Unverifiable,
    /// Verification was not attempted (e.g. disabled via flag).
    Skipped,
}

impl RawMatch {
    /// Get unique key for deduplication.
    pub fn deduplication_key(&self) -> (&str, &str) {
        (&self.detector_id, &self.credential)
    }
}

pub mod serde_arc_str {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::sync::Arc;

    pub fn serialize<S>(val: &Arc<str>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        val.as_ref().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Arc<str>, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Arc::from)
    }
}

pub mod serde_arc_str_opt {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::sync::Arc;

    pub fn serialize<S>(val: &Option<Arc<str>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        val.as_ref().map(|s| s.as_ref()).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Arc<str>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer).map(|opt| opt.map(Arc::from))
    }
}

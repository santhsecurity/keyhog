//! Match deduplication: group raw matches by (detector, credential) with
//! configurable scope (credential-level, file-level, or no deduplication).
//!
//! This module provides the canonical [`DedupedMatch`] type and
//! [`dedup_matches`] function.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::{MatchLocation, RawMatch, Severity};

/// Deduplication scope for grouping findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DedupScope {
    /// No deduplication: every raw match is reported as a unique finding.
    None,
    /// Deduplicate within each file: same secret in same file is one finding.
    File,
    /// Deduplicate across entire scan: same secret across all files is one finding.
    Credential,
}

/// A group of related raw matches representing a single distinct secret finding.
#[derive(Debug, Clone, Serialize)]
pub struct DedupedMatch {
    /// Stable detector identifier.
    #[serde(with = "crate::finding::serde_arc_str")]
    pub detector_id: Arc<str>,
    /// Human-readable detector name.
    #[serde(with = "crate::finding::serde_arc_str")]
    pub detector_name: Arc<str>,
    /// Service namespace associated with the detector.
    #[serde(with = "crate::finding::serde_arc_str")]
    pub service: Arc<str>,
    /// Severity preserved from the original match.
    pub severity: Severity,
    /// Unredacted credential for verification.
    #[serde(with = "crate::finding::serde_arc_str")]
    pub credential: Arc<str>,
    /// SHA-256 hash of the original credential for internal correlation.
    pub credential_hash: String,
    /// Optional companion credentials extracted nearby.
    pub companions: HashMap<String, String>,
    /// Primary source location.
    pub primary_location: MatchLocation,
    /// Additional duplicate locations.
    pub additional_locations: Vec<MatchLocation>,
    /// Confidence score (0.0 - 1.0) combining entropy, keyword proximity, file type, etc.
    pub confidence: Option<f64>,
}

/// Deduplicate raw matches according to the given [`DedupScope`].
pub fn dedup_matches(matches: Vec<RawMatch>, scope: &DedupScope) -> Vec<DedupedMatch> {
    if *scope == DedupScope::None {
        return matches
            .into_iter()
            .map(|m| {
                let credential_hash = sha256_hash(&m.credential);
                DedupedMatch {
                    detector_id: m.detector_id,
                    detector_name: m.detector_name,
                    service: m.service,
                    severity: m.severity,
                    credential: m.credential,
                    credential_hash,
                    companions: m.companions,
                    primary_location: m.location,
                    additional_locations: Vec::new(),
                    confidence: m.confidence,
                }
            })
            .collect();
    }

    // Key is (detector_id, credential, optional_file_path)
    #[allow(clippy::type_complexity)]
    let mut groups: HashMap<(Arc<str>, Arc<str>, Option<Arc<str>>), DedupedMatch> = HashMap::new();

    for matched in matches {
        let detector_id_arc = Arc::clone(&matched.detector_id);
        let credential_arc = Arc::clone(&matched.credential);

        let key = match scope {
            DedupScope::Credential => (detector_id_arc, credential_arc, None),
            DedupScope::File => {
                let file = matched
                    .location
                    .file_path
                    .as_ref()
                    .map(|p| Arc::<str>::from(p.as_ref()));
                (detector_id_arc, credential_arc, file)
            }
            DedupScope::None => {
                unreachable!("DedupScope::None handled by early return above");
            }
        };

        match groups.get_mut(&key) {
            Some(existing) => {
                existing.additional_locations.push(matched.location);
                for (name, val) in matched.companions {
                    existing.companions.entry(name).or_insert(val);
                }
            }
            None => {
                let credential_hash = sha256_hash(&matched.credential);
                groups.insert(
                    key,
                    DedupedMatch {
                        detector_id: matched.detector_id,
                        detector_name: matched.detector_name,
                        service: matched.service,
                        severity: matched.severity,
                        credential: matched.credential,
                        credential_hash,
                        companions: matched.companions,
                        primary_location: matched.location,
                        additional_locations: Vec::new(),
                        confidence: matched.confidence,
                    },
                );
            }
        }
    }

    groups.into_values().collect()
}

fn sha256_hash(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

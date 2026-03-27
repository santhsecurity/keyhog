//! Match deduplication: group raw matches by (detector, credential) with
//! configurable scope (credential-level, file-level, or no deduplication).
//!
//! This module provides the canonical [`DedupedMatch`] type and
//! [`dedup_matches`] function used by both the scanner pipeline and the
//! verification engine. Moving dedup into `keyhog-core` eliminates the
//! duplicate struct that previously existed in the CLI and verifier crates.

use std::collections::HashMap;

use crate::{MatchLocation, RawMatch, Severity};

/// Deduplication scope controlling how raw matches are grouped into findings.
///
/// # Examples
///
/// ```rust
/// use keyhog_core::DedupScope;
///
/// let scope = DedupScope::Credential;
/// assert!(matches!(scope, DedupScope::Credential));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DedupScope {
    /// Same credential across all files = one finding (default, best for git history).
    Credential,
    /// Same credential in different files = separate findings (best for filesystem).
    File,
    /// No deduplication — report every pattern match.
    None,
}

/// A group of raw matches with the same (detector_id, credential),
/// collapsed into a single finding with one primary location and
/// zero or more additional locations.
///
/// # Examples
///
/// ```rust
/// use keyhog_core::{DedupScope, DedupedMatch, MatchLocation, RawMatch, Severity, dedup_matches};
///
/// let matches = vec![RawMatch {
///     detector_id: "demo-token".into(),
///     detector_name: "Demo Token".into(),
///     service: "demo".into(),
///     severity: Severity::High,
///     credential: "demo_ABC12345".into(),
///     companion: None,
///     location: MatchLocation {
///         source: "filesystem".into(),
///         file_path: Some(".env".into()),
///         line: Some(1),
///         offset: 0,
///         commit: None,
///         author: None,
///         date: None,
///     },
///     entropy: None,
///     confidence: Some(0.9),
/// }];
///
/// let groups = dedup_matches(matches, &DedupScope::Credential);
/// assert_eq!(groups.len(), 1);
/// assert_eq!(groups[0].detector_id, "demo-token");
/// ```
#[derive(Debug, Clone)]
pub struct DedupedMatch {
    /// Stable detector identifier.
    pub detector_id: String,
    /// Human-readable detector name.
    pub detector_name: String,
    /// Service namespace associated with the detector.
    pub service: String,
    /// Severity preserved from the original match.
    pub severity: Severity,
    /// Unredacted credential for verification.
    pub credential: String,
    /// Optional companion credential or nearby value.
    pub companion: Option<String>,
    /// Primary source location.
    pub primary_location: MatchLocation,
    /// Additional duplicate locations.
    pub additional_locations: Vec<MatchLocation>,
    /// Confidence score (0.0 - 1.0) combining entropy, keyword proximity, file type, etc.
    pub confidence: Option<f64>,
}

/// Deduplicate raw matches according to the given [`DedupScope`].
///
/// - [`DedupScope::Credential`]: group by (detector_id, credential) across all files.
/// - [`DedupScope::File`]: group by (detector_id, credential, file_path).
/// - [`DedupScope::None`]: every match becomes its own group (no deduplication).
///
/// # Examples
///
/// ```rust
/// use keyhog_core::{DedupScope, MatchLocation, RawMatch, Severity, dedup_matches};
///
/// let matches = vec![
///     RawMatch {
///         detector_id: "aws".into(),
///         detector_name: "AWS".into(),
///         service: "aws".into(),
///         severity: Severity::Critical,
///         credential: "AKIAIOSFODNN7EXAMPLE".into(),
///         companion: None,
///         location: MatchLocation {
///             source: "filesystem".into(),
///             file_path: Some("a.py".into()),
///             line: Some(1),
///             offset: 0,
///             commit: None,
///             author: None,
///             date: None,
///         },
///         entropy: None,
///         confidence: None,
///     },
///     RawMatch {
///         detector_id: "aws".into(),
///         detector_name: "AWS".into(),
///         service: "aws".into(),
///         severity: Severity::Critical,
///         credential: "AKIAIOSFODNN7EXAMPLE".into(),
///         companion: None,
///         location: MatchLocation {
///             source: "filesystem".into(),
///             file_path: Some("b.py".into()),
///             line: Some(5),
///             offset: 0,
///             commit: None,
///             author: None,
///             date: None,
///         },
///         entropy: None,
///         confidence: None,
///     },
/// ];
///
/// // Credential-level: both collapse into one group
/// let credential_groups = dedup_matches(matches.clone(), &DedupScope::Credential);
/// assert_eq!(credential_groups.len(), 1);
/// assert_eq!(credential_groups[0].additional_locations.len(), 1);
///
/// // File-level: different files = separate groups
/// let file_groups = dedup_matches(matches.clone(), &DedupScope::File);
/// assert_eq!(file_groups.len(), 2);
///
/// // No dedup: one group per match
/// let no_dedup = dedup_matches(matches, &DedupScope::None);
/// assert_eq!(no_dedup.len(), 2);
/// ```
pub fn dedup_matches(matches: Vec<RawMatch>, scope: &DedupScope) -> Vec<DedupedMatch> {
    if *scope == DedupScope::None {
        return matches
            .into_iter()
            .map(|m| DedupedMatch {
                detector_id: m.detector_id,
                detector_name: m.detector_name,
                service: m.service,
                severity: m.severity,
                credential: m.credential,
                companion: m.companion,
                primary_location: m.location,
                additional_locations: Vec::new(),
                confidence: m.confidence,
            })
            .collect();
    }

    let mut groups: HashMap<String, DedupedMatch> = HashMap::new();

    for matched in matches {
        let key = match scope {
            DedupScope::Credential => {
                let (d, c) = matched.deduplication_key();
                format!("{d}:{c}")
            }
            DedupScope::File => {
                let (d, c) = matched.deduplication_key();
                let file = matched.location.file_path.as_deref().unwrap_or("stdin");
                format!("{d}:{c}:{file}")
            }
            DedupScope::None => {
                unreachable!("DedupScope::None handled by early return above");
            }
        };

        match groups.get_mut(&key) {
            Some(existing) => {
                existing.additional_locations.push(matched.location);
                if existing.companion.is_none() && matched.companion.is_some() {
                    existing.companion = matched.companion;
                }
            }
            None => {
                groups.insert(
                    key,
                    DedupedMatch {
                        detector_id: matched.detector_id,
                        detector_name: matched.detector_name,
                        service: matched.service,
                        severity: matched.severity,
                        credential: matched.credential,
                        companion: matched.companion,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_match(detector_id: &str, credential: &str, file: &str) -> RawMatch {
        RawMatch {
            detector_id: detector_id.into(),
            detector_name: format!("{detector_id} detector"),
            service: "test".into(),
            severity: Severity::High,
            credential: credential.into(),
            companion: None,
            location: MatchLocation {
                source: "filesystem".into(),
                file_path: Some(file.into()),
                line: Some(1),
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            entropy: None,
            confidence: Some(0.9),
        }
    }

    #[test]
    fn credential_scope_merges_across_files() {
        let matches = vec![
            make_match("aws", "AKIA_SECRET", "a.py"),
            make_match("aws", "AKIA_SECRET", "b.py"),
        ];
        let groups = dedup_matches(matches, &DedupScope::Credential);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].additional_locations.len(), 1);
    }

    #[test]
    fn file_scope_separates_different_files() {
        let matches = vec![
            make_match("aws", "AKIA_SECRET", "a.py"),
            make_match("aws", "AKIA_SECRET", "b.py"),
        ];
        let groups = dedup_matches(matches, &DedupScope::File);
        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn no_scope_keeps_every_match() {
        let matches = vec![
            make_match("aws", "AKIA_SECRET", "a.py"),
            make_match("aws", "AKIA_SECRET", "a.py"),
        ];
        let groups = dedup_matches(matches, &DedupScope::None);
        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn companion_is_preserved_from_later_match() {
        let mut m1 = make_match("aws", "AKIA_SECRET", "a.py");
        m1.companion = None;
        let mut m2 = make_match("aws", "AKIA_SECRET", "b.py");
        m2.companion = Some("secret_key_companion".into());

        let groups = dedup_matches(vec![m1, m2], &DedupScope::Credential);
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].companion.as_deref(),
            Some("secret_key_companion")
        );
    }

    #[test]
    fn different_detectors_same_credential_stay_separate() {
        let matches = vec![
            make_match("aws", "AKIA_SECRET", "a.py"),
            make_match("github", "AKIA_SECRET", "a.py"),
        ];
        let groups = dedup_matches(matches, &DedupScope::Credential);
        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn empty_input_returns_empty() {
        let groups = dedup_matches(Vec::new(), &DedupScope::Credential);
        assert!(groups.is_empty());
    }
}

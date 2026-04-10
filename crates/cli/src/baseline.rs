//! Baseline scanning support for the KeyHog CLI.
//!
//! Baselines allow teams to suppress known/acknowledged secrets so that
//! scanning an existing repository does not produce overwhelming noise.
//! A finding is suppressed if its `(detector_id, credential_hash)` pair
//! exists in the baseline. File path and line number are stored for
//! reference only — secrets may move between lines.

use anyhow::{Context, Result};
use keyhog_core::VerifiedFinding;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

const BASELINE_VERSION: u32 = 1;

/// A baseline file containing acknowledged secrets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Baseline {
    pub version: u32,
    pub created: String,
    pub entries: Vec<BaselineEntry>,
}

/// A single entry in a baseline file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct BaselineEntry {
    pub detector_id: String,
    pub credential_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(default = "default_status")]
    pub status: String,
}

fn default_status() -> String {
    "acknowledged".to_string()
}

impl Baseline {
    /// Create an empty baseline with the current timestamp.
    pub fn empty() -> Self {
        Self {
            version: BASELINE_VERSION,
            created: chrono::Utc::now().to_rfc3339(),
            entries: Vec::new(),
        }
    }

    /// Load a baseline from a JSON file.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading baseline file {}", path.display()))?;
        let baseline: Baseline = serde_json::from_str(&content)
            .with_context(|| format!("parsing baseline file {}", path.display()))?;
        if baseline.version != BASELINE_VERSION {
            anyhow::bail!(
                "unsupported baseline version {} (expected {})",
                baseline.version,
                BASELINE_VERSION
            );
        }
        Ok(baseline)
    }

    /// Save the baseline to a JSON file (pretty-printed).
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::File::create(path)
            .with_context(|| format!("creating baseline file {}", path.display()))?;
        let writer = std::io::BufWriter::new(file);
        serde_json::to_writer_pretty(writer, self)
            .with_context(|| format!("writing baseline file {}", path.display()))?;
        Ok(())
    }

    /// Build a new baseline from a slice of findings.
    /// Entries are deduplicated by `(detector_id, credential_hash)`.
    pub fn from_findings(findings: &[VerifiedFinding]) -> Self {
        let mut entries: Vec<BaselineEntry> = findings
            .iter()
            .map(|f| BaselineEntry {
                detector_id: f.detector_id.to_string(),
                credential_hash: format!("sha256:{}", f.credential_hash),
                file_path: f.location.file_path.as_ref().map(|p| p.to_string()),
                line: f.location.line,
                status: "acknowledged".to_string(),
            })
            .collect();

        entries.sort_by(|a, b| {
            a.detector_id
                .cmp(&b.detector_id)
                .then(a.credential_hash.cmp(&b.credential_hash))
        });
        entries.dedup_by(|a, b| {
            a.detector_id == b.detector_id && a.credential_hash == b.credential_hash
        });

        Self {
            version: BASELINE_VERSION,
            created: chrono::Utc::now().to_rfc3339(),
            entries,
        }
    }

    /// Merge new findings into an existing baseline.
    /// New entries are added; existing entries are preserved.
    pub fn merge(&mut self, findings: &[VerifiedFinding]) {
        let existing: HashSet<(String, String)> = self
            .entries
            .iter()
            .map(|e| (e.detector_id.clone(), e.credential_hash.clone()))
            .collect();

        for finding in findings {
            let key = (
                finding.detector_id.to_string(),
                format!("sha256:{}", finding.credential_hash),
            );
            if !existing.contains(&key) {
                self.entries.push(BaselineEntry {
                    detector_id: finding.detector_id.to_string(),
                    credential_hash: key.1,
                    file_path: finding.location.file_path.as_ref().map(|p| p.to_string()),
                    line: finding.location.line,
                    status: "acknowledged".to_string(),
                });
            }
        }

        self.entries.sort_by(|a, b| {
            a.detector_id
                .cmp(&b.detector_id)
                .then(a.credential_hash.cmp(&b.credential_hash))
        });
        self.entries.dedup_by(|a, b| {
            a.detector_id == b.detector_id && a.credential_hash == b.credential_hash
        });
    }

    /// Returns `true` if the given finding matches an entry in the baseline.
    /// Matching is based solely on `(detector_id, credential_hash)`.
    pub fn contains(&self, finding: &VerifiedFinding) -> bool {
        let hash = format!("sha256:{}", finding.credential_hash);
        self.entries
            .iter()
            .any(|e| e.detector_id == finding.detector_id.as_ref() && e.credential_hash == hash)
    }

    /// Filter a slice of findings, returning only those **not** present in the baseline.
    pub fn filter_new(&self, findings: &[VerifiedFinding]) -> Vec<VerifiedFinding> {
        findings
            .iter()
            .filter(|f| !self.contains(f))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyhog_core::{MatchLocation, Severity, VerificationResult};
    use std::collections::HashMap;
    use std::sync::Arc;

    fn make_finding(
        detector_id: &str,
        credential_hash: &str,
        file_path: Option<&str>,
    ) -> VerifiedFinding {
        VerifiedFinding {
            detector_id: Arc::from(detector_id),
            detector_name: Arc::from("Test Detector"),
            service: Arc::from("test"),
            severity: Severity::High,
            credential_redacted: "***".into(),
            credential_hash: credential_hash.to_string(),
            location: MatchLocation {
                source: Arc::from("filesystem"),
                file_path: file_path.map(Arc::from),
                line: Some(42),
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            verification: VerificationResult::Skipped,
            metadata: HashMap::new(),
            additional_locations: Vec::new(),
            confidence: None,
        }
    }

    #[test]
    fn baseline_creation_produces_expected_entries() {
        let findings = vec![
            make_finding("github-pat", "abc123", Some("src/config.py")),
            make_finding("aws-key", "def456", Some("src/aws.py")),
        ];

        let baseline = Baseline::from_findings(&findings);
        assert_eq!(baseline.version, 1);
        assert_eq!(baseline.entries.len(), 2);
        assert_eq!(baseline.entries[0].detector_id, "aws-key");
        assert_eq!(baseline.entries[0].credential_hash, "sha256:def456");
        assert_eq!(
            baseline.entries[0].file_path,
            Some("src/aws.py".to_string())
        );
        assert_eq!(baseline.entries[0].line, Some(42));
        assert_eq!(baseline.entries[0].status, "acknowledged");
    }

    #[test]
    fn baseline_creation_dedupes_duplicate_credentials() {
        let findings = vec![
            make_finding("github-pat", "abc123", Some("src/config.py")),
            make_finding("github-pat", "abc123", Some("src/other.py")),
        ];

        let baseline = Baseline::from_findings(&findings);
        assert_eq!(baseline.entries.len(), 1);
        assert_eq!(baseline.entries[0].detector_id, "github-pat");
    }

    #[test]
    fn baseline_suppresses_known_findings() {
        let findings = vec![
            make_finding("github-pat", "abc123", Some("src/config.py")),
            make_finding("aws-key", "def456", Some("src/aws.py")),
        ];

        let baseline = Baseline::from_findings(&findings);
        let suppressed = baseline.filter_new(&findings);
        assert!(suppressed.is_empty());
    }

    #[test]
    fn baseline_does_not_suppress_new_findings() {
        let baseline =
            Baseline::from_findings(&[make_finding("github-pat", "abc123", Some("src/config.py"))]);

        let new_findings = vec![
            make_finding("github-pat", "abc123", Some("src/config.py")),
            make_finding("github-pat", "newhash", Some("src/new.py")),
        ];

        let filtered = baseline.filter_new(&new_findings);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].credential_hash, "newhash");
    }

    #[test]
    fn baseline_update_adds_new_findings() {
        let mut baseline =
            Baseline::from_findings(&[make_finding("github-pat", "abc123", Some("src/config.py"))]);

        let new_findings = vec![
            make_finding("github-pat", "abc123", Some("src/config.py")),
            make_finding("aws-key", "def456", Some("src/aws.py")),
        ];

        baseline.merge(&new_findings);
        assert_eq!(baseline.entries.len(), 2);
        let ids: Vec<_> = baseline
            .entries
            .iter()
            .map(|e| e.detector_id.as_str())
            .collect();
        assert!(ids.contains(&"github-pat"));
        assert!(ids.contains(&"aws-key"));
    }

    #[test]
    fn baseline_save_and_load_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("baseline.json");

        let findings = vec![make_finding("github-pat", "abc123", Some("src/config.py"))];
        let baseline = Baseline::from_findings(&findings);
        baseline.save(&path).unwrap();

        let loaded = Baseline::load(&path).unwrap();
        assert_eq!(loaded, baseline);
    }

    #[test]
    fn baseline_matching_ignores_file_path_and_line() {
        let findings = vec![make_finding("github-pat", "abc123", Some("src/config.py"))];
        let baseline = Baseline::from_findings(&findings);

        let moved_finding = make_finding("github-pat", "abc123", Some("src/moved.py"));
        assert!(baseline.contains(&moved_finding));
    }
}

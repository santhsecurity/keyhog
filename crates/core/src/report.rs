//! Reporting logic for scan results.
//!
//! Provides the [`Reporter`] trait and several built-in implementations
//! for different output formats (JSONL, Text, SARIF).

use anyhow::Result;
use serde_json::json;
use std::io::Write;

use crate::VerifiedFinding;

/// Common trait for all finding reporters.
pub trait Reporter: Send {
    /// Report a single finding.
    fn report(&mut self, finding: &VerifiedFinding) -> Result<()>;
    /// Finalize the report (e.g. close JSON arrays, print summary).
    fn finish(&mut self) -> Result<()>;
}

/// A reporter that prints findings in a human-readable text format.
pub struct TextReporter<W: Write + Send> {
    writer: W,
    #[allow(dead_code)]
    use_color: bool,
    count: usize,
}

impl<W: Write + Send> TextReporter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            use_color: false,
            count: 0,
        }
    }

    pub fn with_color(writer: W, enabled: bool) -> Self {
        Self {
            writer,
            use_color: enabled,
            count: 0,
        }
    }
}

impl<W: Write + Send> Reporter for TextReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<()> {
        self.count += 1;
        let status = match finding.verification {
            crate::VerificationResult::Live => "LIVE",
            crate::VerificationResult::Revoked => "REVOKED",
            crate::VerificationResult::Dead => "DEAD",
            crate::VerificationResult::RateLimited => "RATE_LIMITED",
            crate::VerificationResult::Error(_) => "ERROR",
            crate::VerificationResult::Unverifiable => "UNVERIFIABLE",
            crate::VerificationResult::Skipped => "SKIPPED",
        };

        writeln!(
            self.writer,
            "[{}] {} in {}:{} (confidence: {:.2})",
            status,
            finding.detector_name,
            finding.location.file_path.as_deref().unwrap_or("unknown"),
            finding.location.line.unwrap_or(0),
            finding.confidence.unwrap_or(0.0)
        )?;
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        if self.count == 0 {
            writeln!(self.writer, "No secrets found. You are secure!")?;
        } else {
            writeln!(
                self.writer,
                "\n✨ Scan complete! {} secret{} found.",
                self.count,
                if self.count == 1 { "" } else { "s" }
            )?;
        }
        Ok(())
    }
}

/// A reporter that prints findings as a stream of JSON objects (JSONL).
pub struct JsonlReporter<W: Write + Send> {
    writer: W,
}

impl<W: Write + Send> JsonlReporter<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }
}

impl<W: Write + Send> Reporter for JsonlReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<()> {
        let json = serde_json::to_string(finding)?;
        writeln!(self.writer, "{}", json)?;
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        Ok(())
    }
}

/// A reporter that prints findings as a single JSON array.
pub struct JsonArrayReporter<W: Write + Send> {
    writer: W,
    first: bool,
}

impl<W: Write + Send> JsonArrayReporter<W> {
    pub fn new(mut writer: W) -> Self {
        let _ = write!(writer, "[");
        Self {
            writer,
            first: true,
        }
    }
}

impl<W: Write + Send> Reporter for JsonArrayReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<()> {
        if !self.first {
            write!(self.writer, ",")?;
        }
        serde_json::to_writer(&mut self.writer, finding)?;
        self.first = false;
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        write!(self.writer, "]")?;
        Ok(())
    }
}

/// Alias for [`JsonArrayReporter`] for standard JSON output.
pub type JsonReporter<W> = JsonArrayReporter<W>;

/// A reporter that outputs findings in the Static Analysis Results Interchange Format (SARIF).
pub struct SarifReporter<W: Write + Send> {
    writer: W,
    findings: Vec<VerifiedFinding>,
}

impl<W: Write + Send> SarifReporter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            findings: Vec::new(),
        }
    }
}

impl<W: Write + Send> Reporter for SarifReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<()> {
        self.findings.push(finding.clone());
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        let rules: Vec<_> = self
            .findings
            .iter()
            .map(|f| {
                json!({
                    "id": f.detector_id.as_ref(),
                    "name": f.detector_name.as_ref(),
                    "shortDescription": { "text": f.detector_name.as_ref() },
                    "properties": {
                        "service": f.service.as_ref(),
                        "severity": format!("{:?}", f.severity)
                    }
                })
            })
            .collect();

        let results: Vec<_> = self.findings.iter()
            .map(|f| {
                let level = match f.severity {
                    crate::Severity::Critical | crate::Severity::High => "error",
                    crate::Severity::Medium => "warning",
                    crate::Severity::Low | crate::Severity::Info => "note",
                };

                let mut locations = vec![json!({
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.location.file_path.as_deref().unwrap_or("unknown")
                        },
                        "region": {
                            "startLine": f.location.line.unwrap_or(1),
                            "startColumn": 1
                        }
                    }
                })];

                if let Some(ref commit) = f.location.commit {
                    locations[0]["logicalLocations"] = json!([
                        { "kind": "commit", "name": commit.as_ref() },
                        { "kind": "author", "name": f.location.author.as_deref().unwrap_or("unknown") },
                        { "kind": "date", "name": f.location.date.as_deref().unwrap_or("unknown") }
                    ]);
                }

                let mut res = json!({
                    "ruleId": f.detector_id.as_ref(),
                    "level": level,
                    "message": {
                        "text": format!("Potential {} for {} found in {}", f.detector_name, f.service, f.location.file_path.as_deref().unwrap_or("unknown"))
                    },
                    "locations": locations,
                    "properties": {
                        "verification": format!("{:?}", f.verification).to_lowercase(),
                        "confidence": f.confidence.unwrap_or(0.0)
                    }
                });

                for (k, v) in &f.metadata {
                    res["properties"][format!("metadata.{}", k)] = json!(v);
                }

                if !f.additional_locations.is_empty() {
                    res["relatedLocations"] = json!(f.additional_locations.iter().map(|loc| {
                        json!({
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": loc.file_path.as_deref().unwrap_or("unknown")
                                },
                                "region": {
                                    "startLine": loc.line.unwrap_or(1)
                                }
                            }
                        })
                    }).collect::<Vec<_>>());
                }

                res
            })
            .collect();

        let sarif = json!({
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1.0/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "keyhog",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/santhsecurity/keyhog",
                        "rules": rules
                    }
                },
                "results": results
            }]
        });

        serde_json::to_writer_pretty(&mut self.writer, &sarif)?;
        Ok(())
    }
}

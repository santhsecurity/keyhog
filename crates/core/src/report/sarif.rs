//! SARIF reporter for code-scanning platforms such as GitHub code scanning,
//! Azure DevOps, and IDE integrations.

use std::collections::HashMap;
use std::io::Write;

use crate::{MatchLocation, Severity, VerifiedFinding};

use super::{BufferedFindingReporter, ReportError, Reporter, WriterBackedReporter};

/// SARIF v2.1.0 reporter for integration with GitHub, Azure DevOps, and IDEs.
pub struct SarifReporter<W: Write + Send> {
    writer: W,
    findings: Vec<VerifiedFinding>,
    rules: HashMap<String, SarifRule>,
}

/// A SARIF rule (tool component rule).
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRule {
    id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    short_description: Option<SarifMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    full_description: Option<SarifMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    help: Option<SarifMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifMessage {
    text: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifTool {
    driver: SarifToolDriver,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifToolDriver {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    information_uri: Option<String>,
    rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    related_locations: Option<Vec<SarifLocation>>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    logical_locations: Option<Vec<SarifLogicalLocation>>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_location: Option<SarifArtifactLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<SarifRegion>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifArtifactLocation {
    uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    uri_base_id: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    #[serde(skip_serializing_if = "Option::is_none")]
    start_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    snippet: Option<SarifSnippet>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifSnippet {
    text: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLogicalLocation {
    name: String,
    kind: String,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLog {
    version: String,
    #[serde(rename = "$schema")]
    schema: String,
    runs: Vec<SarifRun>,
}

impl<W: Write + Send> SarifReporter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            findings: Vec::new(),
            rules: HashMap::new(),
        }
    }

    fn severity_to_level(severity: Severity) -> &'static str {
        match severity {
            Severity::Critical => "error",
            Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low => "note",
            Severity::Info => "note",
        }
    }

    fn build_rule(finding: &VerifiedFinding) -> SarifRule {
        SarifRule {
            id: finding.detector_id.to_string(),
            name: finding.detector_name.to_string(),
            short_description: Some(SarifMessage {
                text: format!("{} secret detected", finding.service),
            }),
            full_description: Some(SarifMessage {
                text: format!(
                    "A {} secret was detected by the {} detector",
                    finding.service, finding.detector_name
                ),
            }),
            help: Some(SarifMessage {
                text: format!(
                    "Review and rotate the exposed {} credential.",
                    finding.service
                ),
            }),
            properties: Some({
                let mut props = serde_json::Map::new();
                props.insert(
                    "service".to_string(),
                    serde_json::Value::String(finding.service.to_string()),
                );
                props.insert(
                    "severity".to_string(),
                    serde_json::Value::String(format!("{:?}", finding.severity).to_lowercase()),
                );
                props
            }),
        }
    }

    fn location_to_sarif(loc: &MatchLocation) -> SarifLocation {
        let uri = loc
            .file_path
            .as_ref()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "stdin".to_string());

        let artifact_location = Some(SarifArtifactLocation {
            uri,
            uri_base_id: None,
        });

        let region = loc.line.map(|line| SarifRegion {
            start_line: Some(line),
            start_column: None,
            end_line: None,
            end_column: None,
            snippet: None,
        });

        let mut logical_locations = Vec::new();

        if let Some(commit) = &loc.commit {
            logical_locations.push(SarifLogicalLocation {
                name: commit.to_string(),
                kind: "commit".to_string(),
            });
        }

        if let Some(author) = &loc.author {
            logical_locations.push(SarifLogicalLocation {
                name: author.to_string(),
                kind: "author".to_string(),
            });
        }

        if let Some(date) = &loc.date {
            logical_locations.push(SarifLogicalLocation {
                name: date.to_string(),
                kind: "date".to_string(),
            });
        }

        SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location,
                region,
            },
            logical_locations: if logical_locations.is_empty() {
                None
            } else {
                Some(logical_locations)
            },
        }
    }
}

impl<W: Write + Send> Reporter for SarifReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        let detector_id = finding.detector_id.as_ref();
        if !self.rules.contains_key(detector_id) {
            let rule = Self::build_rule(finding);
            self.rules.insert(detector_id.to_string(), rule);
        }

        self.push_finding(finding);
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        let results: Vec<SarifResult> = self
            .findings
            .iter()
            .map(|finding| {
                let locations = vec![Self::location_to_sarif(&finding.location)];

                let related_locations: Vec<SarifLocation> = finding
                    .additional_locations
                    .iter()
                    .map(Self::location_to_sarif)
                    .collect();

                let mut properties = serde_json::Map::new();
                properties.insert(
                    "verification".to_string(),
                    serde_json::Value::String(format!("{:?}", finding.verification).to_lowercase()),
                );

                if let Some(confidence) = finding.confidence {
                    properties.insert(
                        "confidence".to_string(),
                        serde_json::Value::Number(
                            serde_json::Number::from_f64(confidence).unwrap_or_else(|| 0.into()),
                        ),
                    );
                }

                for (key, value) in &finding.metadata {
                    properties.insert(
                        format!("metadata.{}", key),
                        serde_json::Value::String(value.to_string()),
                    );
                }

                SarifResult {
                    rule_id: finding.detector_id.to_string(),
                    level: Self::severity_to_level(finding.severity).to_string(),
                    message: SarifMessage {
                        text: format!(
                            "{} secret detected: {}",
                            finding.service, finding.credential_redacted
                        ),
                    },
                    locations,
                    properties: Some(properties),
                    related_locations: if related_locations.is_empty() {
                        None
                    } else {
                        Some(related_locations)
                    },
                }
            })
            .collect();

        let mut rules: Vec<SarifRule> = self.rules.values().cloned().collect();
        rules.sort_by(|a, b| a.id.cmp(&b.id));

        let sarif_log = SarifLog {
            version: "2.1.0".to_string(),
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1.0/sarif-schema-2.1.0.json".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifToolDriver {
                        name: "keyhog".to_string(),
                        version: Some(env!("CARGO_PKG_VERSION").to_string()),
                        information_uri: Some("https://github.com/keyhog/keyhog".to_string()),
                        rules,
                    },
                },
                results,
            }],
        };

        serde_json::to_writer_pretty(&mut self.writer, &sarif_log)?;
        writeln!(self.writer)?;
        self.flush_writer()
    }
}

impl<W: Write + Send> BufferedFindingReporter for SarifReporter<W> {
    fn findings_mut(&mut self) -> &mut Vec<VerifiedFinding> {
        &mut self.findings
    }
}

impl<W: Write + Send> WriterBackedReporter for SarifReporter<W> {
    type Writer = W;

    fn writer_mut(&mut self) -> &mut Self::Writer {
        &mut self.writer
    }
}

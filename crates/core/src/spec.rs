//! Detector specification: TOML-based pattern definitions with regex, keywords,
//! verification endpoints, and companion patterns.

mod load;
mod validate;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use load::{
    load_detector_cache, load_detectors, load_detectors_with_gate, save_detector_cache,
};
pub use validate::{QualityIssue, validate_detector};

/// A single detector specification, parsed from a TOML file.
/// Each file in the `detectors/` directory produces one of these.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorFile {
    /// Parsed detector payload from the TOML file.
    pub detector: DetectorSpec,
}

/// Full detector definition loaded from TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorSpec {
    /// Stable detector identifier.
    pub id: String,
    /// Human-readable detector name.
    pub name: String,
    /// Service namespace used for grouping and verification limits.
    pub service: String,
    /// Severity reported for matches from this detector.
    pub severity: Severity,
    /// One or more regex patterns that identify the credential.
    pub patterns: Vec<PatternSpec>,
    #[serde(default)]
    /// Optional nearby companion requirement.
    pub companion: Option<CompanionSpec>,
    #[serde(default)]
    /// Optional live-verification configuration.
    pub verify: Option<VerifySpec>,
    #[serde(default)]
    /// Context keywords that help lower false positives.
    pub keywords: Vec<String>,
}

/// One regex pattern entry inside a detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternSpec {
    /// Regex used to detect the credential.
    pub regex: String,
    #[serde(default)]
    /// Optional human-readable description for the pattern.
    pub description: Option<String>,
    #[serde(default)]
    /// Capture group index to use as the credential payload.
    pub group: Option<usize>,
}

/// A secondary pattern that must appear near the primary match.
/// Example: AWS secret key found within 5 lines of an access key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanionSpec {
    /// Regex used to locate the companion value.
    pub regex: String,
    #[serde(default = "default_within_lines")]
    /// Search radius in lines around the primary match.
    pub within_lines: usize,
    /// Logical companion name used for interpolation.
    pub name: String,
}

fn default_within_lines() -> usize {
    5
}

/// Verification HTTP request and success criteria for a detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifySpec {
    /// HTTP method to use for verification.
    pub method: HttpMethod,
    /// URL template for the verification request.
    pub url: String,
    /// Authentication scheme for the request.
    pub auth: AuthSpec,
    #[serde(default)]
    /// Additional request headers.
    pub headers: Vec<HeaderSpec>,
    #[serde(default)]
    /// Optional request body template.
    pub body: Option<String>,
    /// Success criteria for the response.
    pub success: SuccessSpec,
    #[serde(default)]
    /// Metadata extraction rules for live responses.
    pub metadata: Vec<MetadataSpec>,
    #[serde(default)]
    /// Optional per-detector timeout override in milliseconds.
    pub timeout_ms: Option<u64>,
}

/// One extra request header to attach during verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderSpec {
    /// Header name.
    pub name: String,
    /// Header value template.
    pub value: String,
}

/// How to attach the credential to the verification request.
/// The `field` values are interpolation references:
///   - `"match"` — the primary matched credential
///   - `"companion.<name>"` — a companion match
///   - anything else — literal string
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthSpec {
    /// Send the request without explicit auth decoration.
    None,
    /// Put the resolved credential in an `Authorization: Bearer` header.
    Bearer {
        /// Interpolation field supplying the bearer token.
        field: String,
    },
    /// Send HTTP basic auth.
    Basic {
        /// Username field or literal.
        username: String,
        /// Password field or literal.
        password: String,
    },
    /// Put the credential into a custom header.
    Header {
        /// Header name.
        name: String,
        /// Header value template.
        template: String,
    },
    /// Put the credential into a query parameter.
    Query {
        /// Query parameter name.
        param: String,
        /// Interpolation field supplying the parameter value.
        field: String,
    },
    /// Use a lightweight AWS SigV4 liveness probe.
    AwsV4 {
        /// Access-key interpolation field.
        access_key: String,
        /// Secret-key interpolation field.
        secret_key: String,
        #[serde(default = "default_aws_region")]
        /// AWS region for the probe.
        region: String,
        /// AWS service identifier to sign for.
        service: String,
    },
}

fn default_aws_region() -> String {
    "us-east-1".to_string()
}

/// Conditions that must ALL be true for verification to succeed.
/// All fields are optional; present fields form an implicit AND.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessSpec {
    #[serde(default)]
    /// Required HTTP status code.
    pub status: Option<u16>,
    #[serde(default)]
    /// Forbidden HTTP status code.
    pub status_not: Option<u16>,
    #[serde(default)]
    /// Substring that must appear in the response body.
    pub body_contains: Option<String>,
    #[serde(default)]
    /// Substring that must not appear in the response body.
    pub body_not_contains: Option<String>,
    #[serde(default)]
    /// JSON path that must resolve successfully.
    pub json_path: Option<String>,
    #[serde(default)]
    /// Optional stringified value expected at `json_path`.
    pub equals: Option<String>,
}

/// Metadata extraction rule applied to a verification response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataSpec {
    /// Output metadata key.
    pub name: String,
    #[serde(default)]
    /// JSON path to extract from the response body.
    pub json_path: Option<String>,
    #[serde(default)]
    /// Header name to extract when header capture is supported.
    pub header: Option<String>,
    #[serde(default)]
    /// Optional regex applied to the extracted value.
    pub regex: Option<String>,
    #[serde(default)]
    /// Optional capture-group index for the metadata regex.
    pub group: Option<usize>,
}

/// Severity level attached to detector matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational finding.
    Info,
    /// Low-severity finding.
    Low,
    /// Medium-severity finding.
    Medium,
    /// High-severity finding.
    High,
    /// Critical finding.
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// HTTP methods supported by detector verification specs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    /// HTTP GET.
    Get,
    /// HTTP POST.
    Post,
    /// HTTP PUT.
    Put,
    /// HTTP DELETE.
    Delete,
    /// HTTP HEAD.
    Head,
    /// HTTP PATCH.
    Patch,
}

/// Errors that occur while loading detector specs from disk.
#[derive(Debug, Error)]
pub enum SpecError {
    #[error("failed to read detector file {path}: {source}")]
    ReadFile {
        path: String,
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    #[test]
    fn parse_bearer_auth() {
        let toml_str = r#"
[detector]
id = "slack-bot-token"
name = "Slack Bot Token"
service = "slack"
severity = "critical"

[[detector.patterns]]
regex = "xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"

[detector.verify]
method = "POST"
url = "https://slack.com/api/auth.test"

[detector.verify.auth]
type = "bearer"
field = "match"

[detector.verify.success]
status = 200
json_path = "ok"
equals = "true"

[[detector.verify.metadata]]
name = "team"
json_path = "team"
"#;
        let file: DetectorFile = toml::from_str(toml_str).unwrap();
        assert_eq!(file.detector.id, "slack-bot-token");
        assert_eq!(file.detector.severity, Severity::Critical);
        assert!(file.detector.verify.is_some());
        let verify = file.detector.verify.unwrap();
        assert!(matches!(verify.auth, AuthSpec::Bearer { .. }));
    }

    #[test]
    fn parse_basic_auth() {
        let toml_str = r#"
[detector]
id = "stripe-secret-key"
name = "Stripe Secret Key"
service = "stripe"
severity = "critical"

[[detector.patterns]]
regex = "sk_live_[a-zA-Z0-9]{24,}"

[detector.verify]
method = "GET"
url = "https://api.stripe.com/v1/charges?limit=1"

[detector.verify.auth]
type = "basic"
username = "match"
password = ""

[detector.verify.success]
status = 200
"#;
        let file: DetectorFile = toml::from_str(toml_str).unwrap();
        assert_eq!(file.detector.id, "stripe-secret-key");
        assert!(matches!(
            file.detector.verify.unwrap().auth,
            AuthSpec::Basic { .. }
        ));
    }

    #[test]
    fn parse_companion_spec() {
        let toml_str = r#"
[detector]
id = "aws-access-key"
name = "AWS Access Key"
service = "aws"
severity = "critical"

[[detector.patterns]]
regex = "(AKIA|ASIA)[0-9A-Z]{16}"

[detector.companion]
regex = "[0-9a-zA-Z/+=]{40}"
within_lines = 5
name = "secret_key"

[detector.verify]
method = "GET"
url = "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15"

[detector.verify.auth]
type = "aws_v4"
access_key = "match"
secret_key = "companion.secret_key"
region = "us-east-1"
service = "sts"

[detector.verify.success]
status = 200
"#;
        let file: DetectorFile = toml::from_str(toml_str).unwrap();
        assert!(file.detector.companion.is_some());
        let comp = file.detector.companion.unwrap();
        assert_eq!(comp.name, "secret_key");
        assert_eq!(comp.within_lines, 5);
    }

    #[test]
    fn injects_github_classic_pat_compat_detector() {
        let mut detectors = vec![DetectorSpec {
            id: "github-pat-fine-grained".into(),
            name: "GitHub Fine-Grained PAT".into(),
            service: "github".into(),
            severity: Severity::Critical,
            patterns: vec![PatternSpec {
                regex: "github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}".into(),
                description: None,
                group: None,
            }],
            companion: None,
            verify: None,
            keywords: vec!["github_pat_".into(), "github".into()],
        }];

        load::inject_github_classic_pat_detector(&mut detectors);

        let compat = detectors
            .iter()
            .find(|d| d.id == "github-classic-pat")
            .expect("compat detector missing");
        assert_eq!(compat.service, "github");
        assert_eq!(compat.patterns[0].regex, "ghp_[a-zA-Z0-9]{36}");
    }

    #[test]
    fn supabase_anon_detector_requires_context_anchor() {
        let file: DetectorFile =
            toml::from_str(include_str!("../../../detectors/supabase-anon-key.toml"))
                .expect("supabase detector should parse");
        assert_eq!(file.detector.patterns.len(), 1);
        let regex = Regex::new(&file.detector.patterns[0].regex).unwrap();
        assert!(
            regex.is_match("SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.signature")
        );
        assert!(!regex.is_match("eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.signature"));
    }

    #[test]
    fn ceph_companion_requires_ceph_secret_context() {
        let file: DetectorFile = toml::from_str(include_str!(
            "../../../detectors/ceph-rados-gateway-credentials.toml"
        ))
        .expect("ceph detector should parse");
        let companion = file.detector.companion.expect("ceph companion missing");
        let regex = Regex::new(&companion.regex).unwrap();
        assert!(regex.is_match("CEPH_SECRET_KEY=abcdEFGHijklMNOPqrstUVWXyz0123456789/+=="));
        assert!(!regex.is_match("abcdEFGHijklMNOPqrstUVWXyz0123456789/+=="));
    }

    #[test]
    fn lepton_secondary_pattern_needs_lepton_specific_context() {
        let file: DetectorFile =
            toml::from_str(include_str!("../../../detectors/leptonai-api-token.toml"))
                .expect("lepton detector should parse");
        let regex = Regex::new(&file.detector.patterns[1].regex).unwrap();
        assert!(regex.is_match("LEPTON_TOKEN=abcdefghijklmnopqrstuvwxyz123456 lepton.ai"));
        assert!(!regex.is_match("token=abcdefghijklmnopqrstuvwxyz123456 example.com"));
    }

    #[test]
    fn infura_detector_uses_basic_auth_with_companion_secret() {
        let file: DetectorFile = toml::from_str(include_str!(
            "../../../detectors/infura-project-credentials.toml"
        ))
        .expect("infura detector should parse");
        let verify = file.detector.verify.expect("infura verify missing");
        match verify.auth {
            AuthSpec::Basic { username, password } => {
                assert_eq!(username, "match");
                assert_eq!(password, "companion.infura_project_secret");
            }
            other => panic!("unexpected auth spec: {other:?}"),
        }
    }

    #[test]
    fn retool_detector_is_unverifiable_without_deployment_domain() {
        let file: DetectorFile =
            toml::from_str(include_str!("../../../detectors/retool-api-key.toml"))
                .expect("retool detector should parse");
        assert!(file.detector.verify.is_none());
    }
}

//! Command-line argument parsing for KeyHog.

use clap::{Parser, ValueEnum};
use keyhog_core::DedupScope;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "keyhog",
    about = "KeyHog: The developer-first secret scanner.\nFind leaked credentials in your code before hackers do. Fast, accurate, and verifying.",
    after_help = "EXIT CODES:\n  0   Success (no secrets found)\n  1   Secrets found (unverified or verification skipped)\n  2   Runtime error (e.g., config error, unreadable path)\n  10  Live credentials found (requires --verify)",
    disable_version_flag = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Print version, build information, and statistics
    #[arg(short = 'V', long)]
    pub version: bool,
}

#[derive(clap::Subcommand)]
pub enum Command {
    /// 🔍 Scan files, directories, or repositories for secrets
    #[command(verbatim_doc_comment)]
    Scan(Box<ScanArgs>),

    /// 🪝 Manage git pre-commit hooks
    #[command(verbatim_doc_comment)]
    Hook {
        #[command(subcommand)]
        command: crate::subcommands::hook::HookCommand,
    },

    /// 📋 List all loaded secret detectors
    #[command(verbatim_doc_comment)]
    Detectors(DetectorArgs),
}

#[derive(Parser)]
pub struct ScanArgs {
    /// Detector TOML directory
    #[arg(short, long, default_value = "detectors")]
    pub detectors: PathBuf,

    /// Positional shorthand for `--path`
    #[arg(value_name = "PATH", conflicts_with = "path")]
    pub input: Option<PathBuf>,

    /// Scan a directory or file
    #[arg(short, long)]
    pub path: Option<PathBuf>,

    /// Scan binary files for hardcoded strings
    #[cfg(feature = "binary")]
    #[arg(long)]
    pub binary: bool,

    /// Scan stdin
    #[arg(long)]
    pub stdin: bool,

    /// Scan reachable git blobs from repository history (deduplicated by blob ID)
    #[cfg(feature = "git")]
    #[arg(long)]
    pub git_blobs: Option<PathBuf>,

    /// Scan only changed lines between two git refs (e.g., --git-diff main)
    #[cfg(feature = "git")]
    #[arg(long, value_name = "BASE_REF")]
    pub git_diff: Option<String>,

    /// Scan full git history commit-by-commit using added lines from patches
    #[cfg(feature = "git")]
    #[arg(long, value_name = "PATH")]
    pub git_history: Option<PathBuf>,

    /// Scan only staged files in the current git repository
    #[cfg(feature = "git")]
    #[arg(long)]
    pub git_staged: bool,

    /// Path to git repository for --git-diff (defaults to current directory)
    #[cfg(feature = "git")]
    #[arg(long, requires = "git_diff")]
    pub git_diff_path: Option<PathBuf>,

    /// Scan all repositories in a GitHub organization
    #[cfg(feature = "github")]
    #[arg(long, requires = "github_token", value_name = "ORG")]
    pub github_org: Option<String>,

    /// GitHub personal access token for --github-org
    #[cfg(feature = "github")]
    #[arg(long, requires = "github_org", value_name = "PAT")]
    pub github_token: Option<String>,

    /// Scan a public or path-style S3 bucket via ListObjectsV2
    #[cfg(feature = "s3")]
    #[arg(long, value_name = "BUCKET")]
    pub s3_bucket: Option<String>,

    /// Optional S3 object prefix to limit the scan
    #[cfg(feature = "s3")]
    #[arg(long, requires = "s3_bucket", value_name = "PREFIX")]
    pub s3_prefix: Option<String>,

    /// Optional S3 endpoint for S3-compatible APIs
    #[cfg(feature = "s3")]
    #[arg(long, requires = "s3_bucket", value_name = "URL")]
    pub s3_endpoint: Option<String>,

    /// Scan a Docker image by unpacking `docker image save`
    #[cfg(feature = "docker")]
    #[arg(long, value_name = "IMAGE")]
    pub docker_image: Option<String>,

    /// Scan JavaScript, source maps, or WASM binaries at URLs for secrets
    #[cfg(feature = "web")]
    #[arg(long, value_name = "URL", num_args = 1..)]
    pub url: Option<Vec<String>>,

    /// Max git commits to traverse
    #[cfg(feature = "git")]
    #[arg(long, default_value = "1000")]
    pub max_commits: usize,

    /// Verify discovered credentials via API calls
    #[cfg(feature = "verify")]
    #[arg(long)]
    pub verify: bool,

    /// Show full credentials (default: redacted)
    #[arg(long)]
    pub show_secrets: bool,

    /// Output format
    #[arg(long, default_value = "text", value_enum)]
    pub format: OutputFormat,

    /// Show progress bar
    #[arg(long)]
    pub progress: bool,

    /// Write findings to file
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Verification timeout in seconds
    #[arg(long, default_value = "5")]
    pub timeout: u64,

    /// Max concurrent verification requests per service
    #[arg(long, default_value = "5")]
    pub rate: usize,

    /// Min severity to report: info, low, medium, high, critical
    #[arg(short, long, value_enum)]
    pub severity: Option<SeverityFilter>,

    /// Maximum file size to scan (default: 10MB).
    #[arg(long, value_name = "SIZE", value_parser = crate::utils::parse_byte_size)]
    pub max_file_size: Option<usize>,

    /// Custom input sources to enable (pluggable).
    #[arg(long, value_name = "NAME")]
    pub source: Option<Vec<String>>,

    /// Fast mode: pattern matching only. No decode, no entropy. Maximum speed.
    #[cfg_attr(feature = "full", arg(long, conflicts_with_all = ["deep", "no_decode", "no_entropy"]))]
    #[cfg_attr(not(feature = "full"), arg(long, conflicts_with_all = ["deep", "no_decode"]))]
    pub fast: bool,

    /// Deep mode: all features enabled.
    #[cfg_attr(feature = "full", arg(long, conflicts_with_all = ["fast", "no_decode", "no_entropy"]))]
    #[cfg_attr(not(feature = "full"), arg(long, conflicts_with_all = ["fast", "no_decode"]))]
    pub deep: bool,

    /// Skip decoding base64/hex encoded content
    #[arg(long)]
    pub no_decode: bool,

    /// Disable entropy-based detection
    #[cfg(feature = "full")]
    #[arg(long)]
    pub no_entropy: bool,

    /// Minimum ML confidence score for generic entropy secrets (0.0 to 1.0)
    #[cfg(feature = "full")]
    #[arg(long, default_value = "0.5", value_name = "THRESHOLD")]
    pub ml_threshold: f64,

    /// Minimum confidence score (0.0 - 1.0) to report findings
    #[arg(long, value_name = "FLOAT", value_parser = crate::utils::parse_min_confidence)]
    pub min_confidence: Option<f64>,

    /// Number of parallel scanning threads (default: number of CPU cores)
    #[arg(long, value_name = "N")]
    pub threads: Option<usize>,

    /// Deduplication scope for findings.
    #[arg(long, default_value = "credential", value_enum)]
    pub dedup: CliDedupScope,

    /// Load configuration from a specific file path.
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Suppress findings that match an existing baseline file
    #[arg(long, value_name = "PATH", conflicts_with_all = ["create_baseline", "update_baseline"])]
    pub baseline: Option<PathBuf>,

    /// Create a new baseline file from current findings and exit
    #[arg(long, value_name = "PATH", conflicts_with_all = ["baseline", "update_baseline"])]
    pub create_baseline: Option<PathBuf>,

    /// Update an existing baseline file with new findings
    #[arg(long, value_name = "PATH", conflicts_with_all = ["baseline", "create_baseline"])]
    pub update_baseline: Option<PathBuf>,

    /// Maximum depth for recursive decoding (1-10, default: 4).
    #[arg(long, value_name = "DEPTH", value_parser = crate::utils::parse_decode_depth)]
    pub decode_depth: Option<usize>,

    /// Maximum file size for decode-through scanning (default: 64KB).
    #[arg(long, value_name = "SIZE", value_parser = crate::utils::parse_byte_size)]
    pub decode_size_limit: Option<usize>,

    /// Enable entropy scanning in source code files.
    #[cfg(feature = "full")]
    #[arg(long)]
    pub entropy_source_files: bool,

    /// Disable default file exclusion patterns (lock files, minified files, build outputs, etc.)
    #[arg(long)]
    pub no_default_excludes: bool,

    /// Explicit paths or glob patterns to exclude from scanning.
    #[arg(long, value_name = "PATH", num_args = 1..)]
    pub exclude_paths: Option<Vec<String>>,

    /// Entropy threshold in bits per byte (default: 4.5).
    #[cfg(feature = "full")]
    #[arg(long, value_name = "BITS")]
    pub entropy_threshold: Option<f64>,

    /// Disable Unicode normalization (not recommended).
    #[arg(long)]
    pub no_unicode_norm: bool,

    /// Disable ML-based confidence scoring.
    #[arg(long)]
    pub no_ml: bool,

    /// Run the built-in backend benchmark corpus and exit.
    #[arg(long)]
    pub benchmark: bool,

    /// ML weight for confidence scoring, 0.0-1.0 (default: 0.6).
    #[arg(long, value_name = "WEIGHT")]
    pub ml_weight: Option<f64>,

    /// Known secret prefixes (internal use for config merge)
    #[arg(skip)]
    pub known_prefixes: Vec<String>,
    /// Secret keywords (internal use for config merge)
    #[arg(skip)]
    pub secret_keywords: Vec<String>,
    /// Test keywords (internal use for config merge)
    #[arg(skip)]
    pub test_keywords: Vec<String>,
    /// Placeholder keywords (internal use for config merge)
    #[arg(skip)]
    pub placeholder_keywords: Vec<String>,
}

#[derive(Parser)]
pub struct DetectorArgs {
    /// Detector TOML directory
    #[arg(short, long, default_value = "detectors")]
    pub detectors: PathBuf,
}

#[derive(Clone, ValueEnum)]
pub enum SeverityFilter {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityFilter {
    pub fn to_severity(&self) -> keyhog_core::Severity {
        match self {
            Self::Info => keyhog_core::Severity::Info,
            Self::Low => keyhog_core::Severity::Low,
            Self::Medium => keyhog_core::Severity::Medium,
            Self::High => keyhog_core::Severity::High,
            Self::Critical => keyhog_core::Severity::Critical,
        }
    }
}

#[derive(Clone, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Jsonl,
    Sarif,
}

#[derive(Clone, ValueEnum, PartialEq)]
pub enum CliDedupScope {
    Credential,
    File,
    None,
}

impl CliDedupScope {
    pub fn to_core(&self) -> DedupScope {
        match self {
            Self::Credential => DedupScope::Credential,
            Self::File => DedupScope::File,
            Self::None => DedupScope::None,
        }
    }
}

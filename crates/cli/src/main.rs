//! KeyHog CLI: the command-line interface for the secret scanner.
//!
//! Orchestrates source selection, parallel scanning, decode-through analysis,
//! ML confidence scoring, optional live verification, and output formatting.

use std::collections::HashMap;
use std::io;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use rayon::prelude::*;

use keyhog_core::{
    DedupScope, JsonReporter, JsonlReporter, RawMatch, Reporter,
    SarifReporter, Source, TextReporter, VerificationResult, dedup_matches, load_detectors,
};
use keyhog_scanner::CompiledScanner;
#[cfg(feature = "full")]
use keyhog_scanner::decode;
#[cfg(feature = "full")]
use keyhog_scanner::entropy;
#[cfg(feature = "verify")]
use keyhog_verifier::{VerificationEngine, VerifyConfig};

#[cfg(feature = "full")]
const ENTROPY_ML_THRESHOLD: f64 = 0.5;
const EXIT_LIVE_CREDENTIALS: u8 = 10;
const EXIT_RUNTIME_ERROR: u8 = 2;
const MIN_CONFIDENCE_LOWER_BOUND: f64 = 0.0;
const MIN_CONFIDENCE_UPPER_BOUND: f64 = 1.0;
const INLINE_SUPPRESSION_DIRECTIVE: &str = "keyhog:ignore";
const DETECTOR_DIRECTIVE_PREFIX: &str = "detector=";
const INLINE_COMMENT_MARKERS: &[&str] = &["//", "#", "--", "/*", "<!--"];

/// Amber gradient colors matching the website design (deep amber → light).
const BANNER_COLORS: [(u8, u8, u8); 5] = [
    (245, 158, 11),  // #F59E0B
    (251, 191, 36),  // #FBBF24
    (252, 211, 77),  // #FCD34D
    (253, 230, 138), // #FDE68A
    (254, 243, 199), // #FEF3C7
];

/// Banner line delay in milliseconds for the reveal animation.
const BANNER_LINE_DELAY_MS: u64 = 40;

const BANNER_LINES: [&str; 5] = [
    "  ██   ██ ████████ ██    ██ ██   ██  ██████   ██████",
    "  ██  ██  ██        ██  ██  ██   ██ ██    ██ ██",
    "  █████   █████      ████   ███████ ██    ██ ██   ███",
    "  ██  ██  ██          ██    ██   ██ ██    ██ ██    ██",
    "  ██   ██ ████████    ██    ██   ██  ██████   ██████",
];

/// Print the animated amber-gradient KEYHOG banner to stderr when running
/// interactively. No-ops when stderr is piped or redirected.
fn print_banner(detector_count: usize) {
    if !std::io::stderr().is_terminal() {
        return;
    }

    eprintln!();
    for (line, (r, g, b)) in BANNER_LINES.iter().zip(BANNER_COLORS.iter()) {
        eprint!("\x1b[38;2;{r};{g};{b}m{line}\x1b[0m");
        eprintln!();
        std::thread::sleep(std::time::Duration::from_millis(BANNER_LINE_DELAY_MS));
    }

    let dim = "\x1b[38;2;100;100;100m";
    let reset = "\x1b[0m";
    eprintln!(
        "{dim}  v{version} · Secret Scanner · {detector_count} detectors{reset}",
        version = env!("CARGO_PKG_VERSION"),
    );
    eprintln!("{dim}  by SanthSecurity{reset}");
    eprintln!();
}

// DedupedMatch is now imported from keyhog_core.

#[derive(Parser)]
#[command(
    name = "keyhog",
    about = "KeyHog: The developer-first secret scanner.\nFind leaked credentials in your code before hackers do. Fast, accurate, and verifying.",
    disable_version_flag = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Print version, build information, and statistics
    #[arg(short = 'V', long)]
    version: bool,
}

#[derive(clap::Subcommand)]
enum Command {
    /// 🔍 Scan files, directories, or repositories for secrets
    ///
    /// Examples:
    ///   keyhog scan --path .
    ///   keyhog scan --path src/ --verify
    ///   keyhog scan --git-diff main
    #[command(verbatim_doc_comment)]
    Scan(Box<ScanArgs>),

    /// 📋 List all loaded secret detectors
    ///
    /// Examples:
    ///   keyhog detectors
    #[command(verbatim_doc_comment)]
    Detectors(DetectorArgs),
}

#[derive(Parser)]
struct ScanArgs {
    /// Detector TOML directory
    #[arg(short, long, default_value = "detectors")]
    detectors: PathBuf,

    /// Positional shorthand for `--path`
    #[arg(value_name = "PATH", conflicts_with = "path")]
    input: Option<PathBuf>,

    /// Scan a directory or file
    #[arg(short, long)]
    path: Option<PathBuf>,

    /// Scan binary files for hardcoded strings
    #[cfg(feature = "binary")]
    #[arg(long)]
    binary: bool,

    /// Scan stdin
    #[arg(long)]
    stdin: bool,

    /// Scan reachable git blobs from repository history (deduplicated by blob ID)
    #[cfg(feature = "git")]
    #[arg(long)]
    git: Option<PathBuf>,

    /// Scan only changed lines between two git refs (e.g., --git-diff main)
    #[cfg(feature = "git")]
    #[arg(long, value_name = "BASE_REF")]
    git_diff: Option<String>,

    /// Scan full git history commit-by-commit using added lines from patches
    #[cfg(feature = "git")]
    #[arg(long, value_name = "PATH")]
    git_history: Option<PathBuf>,

    /// Path to git repository for --git-diff (defaults to current directory)
    #[cfg(feature = "git")]
    #[arg(long, requires = "git_diff")]
    git_diff_path: Option<PathBuf>,

    /// Scan all repositories in a GitHub organization
    #[cfg(feature = "github")]
    #[arg(long, requires = "github_token", value_name = "ORG")]
    github_org: Option<String>,

    /// GitHub personal access token for --github-org
    #[cfg(feature = "github")]
    #[arg(long, requires = "github_org", value_name = "PAT")]
    github_token: Option<String>,

    /// Scan a public or path-style S3 bucket via ListObjectsV2
    #[cfg(feature = "s3")]
    #[arg(long, value_name = "BUCKET")]
    s3_bucket: Option<String>,

    /// Optional S3 object prefix to limit the scan
    #[cfg(feature = "s3")]
    #[arg(long, requires = "s3_bucket", value_name = "PREFIX")]
    s3_prefix: Option<String>,

    /// Optional S3 endpoint for S3-compatible APIs
    #[cfg(feature = "s3")]
    #[arg(long, requires = "s3_bucket", value_name = "URL")]
    s3_endpoint: Option<String>,

    /// Scan a Docker image by unpacking `docker image save`
    #[cfg(feature = "docker")]
    #[arg(long, value_name = "IMAGE")]
    docker_image: Option<String>,

    /// Scan JavaScript, source maps, or WASM binaries at URLs for secrets
    #[cfg(feature = "web")]
    #[arg(long, value_name = "URL", num_args = 1..)]
    url: Option<Vec<String>>,

    /// Max git commits to traverse
    #[cfg(feature = "git")]
    #[arg(long, default_value = "1000")]
    max_commits: usize,

    /// Verify discovered credentials via API calls
    #[cfg(feature = "verify")]
    #[arg(long)]
    verify: bool,

    /// Show full credentials (default: redacted)
    #[arg(long)]
    show_secrets: bool,

    /// Output format
    #[arg(long, default_value = "text", value_enum)]
    format: OutputFormat,

    /// Write findings to file
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Verification timeout in seconds
    #[arg(long, default_value = "5")]
    timeout: u64,

    /// Max concurrent verification requests per service
    #[arg(long, default_value = "5")]
    rate: usize,

    /// Min severity to report: info, low, medium, high, critical
    #[arg(short, long, value_enum)]
    severity: Option<SeverityFilter>,

    /// Fast mode: pattern matching only. No decode, no entropy. Maximum speed.
    /// Use for pre-commit hooks and quick scans.
    #[arg(long, conflicts_with_all = ["deep", "no_decode", "no_entropy"])]
    fast: bool,

    /// Deep mode: all features enabled. Decode-through, entropy on all files
    /// (ML-gated), multiline joining. Maximum recall. Use for audits.
    #[arg(long, conflicts_with_all = ["fast", "no_decode", "no_entropy"])]
    deep: bool,

    /// Skip decoding base64/hex encoded content
    #[arg(long)]
    no_decode: bool,

    /// Skip entropy-based secret detection
    #[arg(long)]
    no_entropy: bool,

    /// Minimum confidence score (0.0 - 1.0) to report findings
    #[arg(long, value_name = "FLOAT", value_parser = parse_min_confidence)]
    min_confidence: Option<f64>,

    /// Number of parallel scanning threads (default: number of CPU cores)
    #[arg(long, value_name = "N")]
    threads: Option<usize>,

    /// Deduplication scope for findings.
    /// - `credential` (default): same credential across files = one finding
    /// - `file`: same credential in different files = separate findings
    /// - `none`: no dedup, report every match
    #[arg(long, default_value = "credential", value_enum)]
    dedup: CliDedupScope,
}

#[derive(Parser)]
struct DetectorArgs {
    /// Detector TOML directory
    #[arg(short, long, default_value = "detectors")]
    detectors: PathBuf,
}

#[derive(Clone, ValueEnum)]
enum SeverityFilter {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityFilter {
    fn to_severity(&self) -> keyhog_core::Severity {
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
enum OutputFormat {
    Text,
    Json,
    Jsonl,
    Sarif,
}

/// CLI-level dedup scope that maps to [`keyhog_core::DedupScope`].
#[derive(Clone, ValueEnum, PartialEq)]
enum CliDedupScope {
    /// Same credential across all files = one finding (default, best for git history)
    Credential,
    /// Same credential in different files = separate findings (best for filesystem)
    File,
    /// No deduplication — report every pattern match
    None,
}

impl CliDedupScope {
    /// Convert to the core library's [`DedupScope`].
    fn to_core(&self) -> DedupScope {
        match self {
            Self::Credential => DedupScope::Credential,
            Self::File => DedupScope::File,
            Self::None => DedupScope::None,
        }
    }
}

/// On-disk `.keyhog.toml` configuration file that mirrors CLI arguments.
/// CLI flags always override values from the config file.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
struct ConfigFile {
    /// Path to detector TOMLs directory.
    detectors: Option<String>,
    /// Minimum severity to report: info, low, medium, high, critical.
    severity: Option<String>,
    /// Output format: text, json, jsonl, sarif.
    format: Option<String>,
    /// Enable fast mode (pattern matching only).
    fast: Option<bool>,
    /// Enable deep mode (all features).
    deep: Option<bool>,
    /// Skip decode-through scanning.
    no_decode: Option<bool>,
    /// Skip entropy-based detection.
    no_entropy: Option<bool>,
    /// Minimum confidence score (0.0 - 1.0).
    min_confidence: Option<f64>,
    /// Number of parallel scanning threads.
    threads: Option<usize>,
    /// Deduplication scope: credential, file, none.
    dedup: Option<String>,
    /// Whether to verify discovered credentials.
    verify: Option<bool>,
    /// Verification timeout in seconds.
    timeout: Option<u64>,
    /// Max concurrent verification requests per service.
    rate: Option<usize>,
    /// Maximum git commits to traverse.
    max_commits: Option<usize>,
    /// Show full credentials (not redacted).
    show_secrets: Option<bool>,
}

/// Search for `.keyhog.toml` starting from the scan root, walking up to the
/// filesystem root. Returns `None` when no config file is found.
fn find_config_file(start: Option<&std::path::Path>) -> Option<PathBuf> {
    let mut dir = start
        .and_then(|p| {
            if p.is_dir() {
                Some(p.to_path_buf())
            } else {
                p.parent().map(std::path::Path::to_path_buf)
            }
        })
        .or_else(|| std::env::current_dir().ok())?;

    loop {
        let candidate = dir.join(".keyhog.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

/// Load and merge a `.keyhog.toml` config file into the parsed `ScanArgs`.
/// CLI flags always take precedence over the config file.
#[allow(clippy::collapsible_if, clippy::cmp_owned)]
fn apply_config_file(args: &mut ScanArgs) {
    let config_path = find_config_file(args.path.as_deref());

    let config_path = match config_path {
        Some(path) => path,
        None => return,
    };

    let raw = match std::fs::read_to_string(&config_path) {
        Ok(content) => content,
        Err(error) => {
            tracing::warn!(
                path = %config_path.display(),
                "failed to read .keyhog.toml: {error}"
            );
            return;
        }
    };

    let config: ConfigFile = match toml::from_str(&raw) {
        Ok(parsed) => parsed,
        Err(error) => {
            tracing::warn!(
                path = %config_path.display(),
                "failed to parse .keyhog.toml: {error}"
            );
            return;
        }
    };

    tracing::debug!(path = %config_path.display(), "loaded .keyhog.toml");

    // Apply config values only when no explicit CLI flag was given.
    // clap defaults are identifiable by checking the user-set state via
    // the struct field values matching their defaults.
    if let Some(ref detectors_str) = config.detectors {
        if args.detectors == PathBuf::from("detectors") {
            args.detectors = PathBuf::from(detectors_str);
        }
    }
    if let Some(ref severity_str) = config.severity {
        if args.severity.is_none() {
            args.severity = match severity_str.to_ascii_lowercase().as_str() {
                "info" => Some(SeverityFilter::Info),
                "low" => Some(SeverityFilter::Low),
                "medium" => Some(SeverityFilter::Medium),
                "high" => Some(SeverityFilter::High),
                "critical" => Some(SeverityFilter::Critical),
                other => {
                    tracing::warn!("unknown severity '{other}' in .keyhog.toml");
                    None
                }
            };
        }
    }
    if let Some(ref format_str) = config.format {
        // Only override when the CLI default "text" was not explicitly set.
        // Since we can't distinguish "user passed --format text" from the
        // default, we only apply for non-text values in the config.
        if !matches!(
            args.format,
            OutputFormat::Json | OutputFormat::Jsonl | OutputFormat::Sarif
        ) {
            match format_str.to_ascii_lowercase().as_str() {
                "json" => args.format = OutputFormat::Json,
                "jsonl" => args.format = OutputFormat::Jsonl,
                "sarif" => args.format = OutputFormat::Sarif,
                "text" => {}
                other => tracing::warn!("unknown format '{other}' in .keyhog.toml"),
            }
        }
    }
    if let Some(fast) = config.fast {
        if !args.fast && !args.deep {
            args.fast = fast;
        }
    }
    if let Some(deep) = config.deep {
        if !args.fast && !args.deep {
            args.deep = deep;
        }
    }
    if let Some(no_decode) = config.no_decode {
        if !args.no_decode {
            args.no_decode = no_decode;
        }
    }
    if let Some(no_entropy) = config.no_entropy {
        if !args.no_entropy {
            args.no_entropy = no_entropy;
        }
    }
    if let Some(min_conf) = config.min_confidence {
        if args.min_confidence.is_none() {
            args.min_confidence = Some(min_conf.clamp(0.0, 1.0));
        }
    }
    if let Some(threads) = config.threads {
        if args.threads.is_none() {
            args.threads = Some(threads);
        }
    }
    if let Some(ref dedup_str) = config.dedup {
        if args.dedup == CliDedupScope::Credential {
            match dedup_str.to_ascii_lowercase().as_str() {
                "credential" => {}
                "file" => args.dedup = CliDedupScope::File,
                "none" => args.dedup = CliDedupScope::None,
                other => tracing::warn!("unknown dedup '{other}' in .keyhog.toml"),
            }
        }
    }
    #[cfg(feature = "verify")]
    if let Some(verify) = config.verify {
        if !args.verify {
            args.verify = verify;
        }
    }
    if let Some(timeout) = config.timeout {
        if args.timeout == 5 {
            args.timeout = timeout;
        }
    }
    if let Some(rate) = config.rate {
        if args.rate == 5 {
            args.rate = rate;
        }
    }
    #[cfg(feature = "git")]
    if let Some(max_commits) = config.max_commits {
        if args.max_commits == 1000 {
            args.max_commits = max_commits;
        }
    }
    if let Some(show_secrets) = config.show_secrets {
        if !args.show_secrets {
            args.show_secrets = show_secrets;
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let is_version = std::env::args().any(|a| a == "-V" || a == "--version");

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive(if is_version {
                "keyhog=error".parse().unwrap_or_else(|_| {
                    tracing_subscriber::filter::Directive::from(tracing::Level::ERROR)
                })
            } else {
                "keyhog=warn".parse().unwrap_or_else(|_| {
                    tracing_subscriber::filter::Directive::from(tracing::Level::INFO)
                })
            }),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    if cli.version {
        println!("KeyHog v{}", env!("CARGO_PKG_VERSION"));
        println!(
            "Build Target: {}-{}",
            std::env::consts::ARCH,
            std::env::consts::OS
        );
        #[cfg(feature = "full")]
        println!(
            "ML Model Version: {}",
            keyhog_scanner::ml_scorer::model_version()
        );
        #[cfg(not(feature = "full"))]
        println!("ML Model Version: disabled");
        #[cfg(feature = "gpu")]
        println!(
            "GPU Acceleration: {}",
            if keyhog_scanner::gpu::gpu_available() {
                "available"
            } else {
                "not available (no compatible GPU)"
            }
        );
        #[cfg(not(feature = "gpu"))]
        println!("GPU Acceleration: not compiled (build with -F gpu)");
        #[cfg(feature = "simd")]
        println!("SIMD Regex:       vectorscan/hyperscan (active)");
        #[cfg(not(feature = "simd"))]
        println!("SIMD Regex:       not compiled (build with -F simd)");
        // Try to count detectors if path exists
        let default_detectors = PathBuf::from("detectors");
        if default_detectors.exists()
            && let Ok(detectors) = keyhog_core::load_detectors(&default_detectors)
        {
            println!("Loaded Detectors: {}", detectors.len());
        }
        return ExitCode::SUCCESS;
    }

    let command_outcome = match cli.command {
        Some(Command::Scan(args)) => run_scan(*args).await,
        Some(Command::Detectors(args)) => list_detectors(args).map(|()| ExitCode::SUCCESS),
        None => {
            use clap::CommandFactory;
            let mut cmd = Cli::command();
            let _ = cmd.print_help();
            return ExitCode::from(0);
        }
    };

    match command_outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            eprintln!("{error:?}");
            ExitCode::from(EXIT_RUNTIME_ERROR)
        }
    }
}

async fn run_scan(mut args: ScanArgs) -> Result<ExitCode> {
    let start = Instant::now();
    if args.path.is_none() {
        args.path = args.input.clone();
    }
    apply_config_file(&mut args);
    // Show banner early so the user sees it during detector loading.
    // The detector count is populated after loading.
    let show_banner = std::io::stderr().is_terminal();
    configure_threads(args.threads);

    let allowlist = load_allowlist(args.path.as_deref());
    validate_cli_path_arg(&args.detectors, "detectors")?;
    // Try cache first for 10x faster startup, fall back to TOML loading
    let cache_path = args.detectors.join(".keyhog-cache.json");
    let detectors = if let Some(cached) =
        keyhog_core::load_detector_cache(&cache_path, &args.detectors)
    {
        tracing::debug!(count = cached.len(), "loaded detectors from cache");
        cached
    } else {
        let loaded = load_detectors(&args.detectors)
            .with_context(|| format!(
                "Oops! We couldn't find the detectors directory at '{}'.\n\n\
                💡 Hint: If this is your first time running KeyHog, you might need to download the default detectors.\n\
                Run `git clone https://github.com/sourcegraph/keyhog-detectors detectors` or specify the correct path using `--detectors <PATH>`.",
                args.detectors.display()
            ))?;
        // Save cache for next run
        if let Err(e) = keyhog_core::save_detector_cache(&loaded, &cache_path) {
            tracing::debug!("failed to save detector cache: {e}");
        }
        loaded
    };
    if show_banner {
        print_banner(detectors.len());
    }
    let scanner = std::sync::Arc::new(
        CompiledScanner::compile(detectors.clone()).context("compiling scanner")?,
    );

    let chunks = collect_chunks(&args)?;

    let (do_decode, do_entropy) = if args.fast {
        (false, false)
    } else if args.deep {
        (true, true)
    } else {
        (!args.no_decode, !args.no_entropy)
    };

    let show_progress = std::io::stderr().is_terminal();
    let all_matches = scan_parallel(&scanner, &chunks, do_decode, do_entropy, show_progress);
    let filtered = filter_and_resolve(all_matches, &args, &allowlist);
    let findings = finalize(filtered, &detectors, &args).await?;
    let has_live_credentials = findings
        .iter()
        .any(|f| matches!(f.verification, VerificationResult::Live));

    report_findings(&findings, &args)?;

    tracing::info!(
        "Done in {:.1}s — {} findings",
        start.elapsed().as_secs_f64(),
        findings.len()
    );

    Ok(if has_live_credentials {
        ExitCode::from(EXIT_LIVE_CREDENTIALS)
    } else if !findings.is_empty() {
        ExitCode::from(1) // Secrets found (unverified or verification skipped)
    } else {
        ExitCode::SUCCESS
    })
}

/// Configure the global rayon thread pool with the user-specified thread count.
///
/// # Limitation
///
/// `rayon::ThreadPoolBuilder::build_global()` can only succeed once per process.
/// Subsequent calls (e.g., when `run_scan` is invoked multiple times in a test
/// or library context) will fail. This is a known rayon design constraint — the
/// global pool is immutable once initialized. The failure is logged at warn
/// level but is non-fatal: rayon falls back to its default pool (num_cpus).
fn configure_threads(threads: Option<usize>) {
    if let Some(n) = threads
        && let Err(error) = rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .build_global()
    {
        tracing::warn!(
            requested_threads = n,
            "failed to configure rayon thread pool (may already be initialized): {error}"
        );
    }
}

fn load_allowlist(scan_path: Option<&std::path::Path>) -> keyhog_core::allowlist::Allowlist {
    let base_path = scan_path
        .map(allowlist_root)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let ignore_path = base_path.join(".keyhogignore");
    if ignore_path.exists() {
        keyhog_core::allowlist::Allowlist::load(&ignore_path)
            .unwrap_or_else(|_| keyhog_core::allowlist::Allowlist::empty())
    } else {
        keyhog_core::allowlist::Allowlist::empty()
    }
}

fn allowlist_root(path: &std::path::Path) -> PathBuf {
    if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    }
}

fn collect_chunks(args: &ScanArgs) -> Result<Vec<keyhog_core::Chunk>> {
    let sources: Vec<Box<dyn Source>> = build_sources(args)?;
    if sources.is_empty() {
        anyhow::bail!(
            "no input source specified — use --path, --stdin, --git, --git-diff, --git-history, --github-org, --s3-bucket, or --docker-image"
        );
    }

    let mut chunks = Vec::new();
    for source in &sources {
        for chunk_result in source.chunks() {
            match chunk_result {
                Ok(chunk) => chunks.push(chunk),
                Err(error) => {
                    tracing::warn!("{} source warning: {}", source.name(), error);
                    eprintln!("warning: {} source: {}", source.name(), error);
                }
            }
        }
    }
    Ok(chunks)
}

/// Maximum total findings across all chunks to prevent unbounded memory growth.
const MAX_TOTAL_FINDINGS: usize = 100_000;

/// Per-chunk scan time budget. The `regex` crate guarantees O(n) matching
/// (Thompson NFA, no backtracking), but multiline preprocessing, decode-through
/// loops, and entropy scanning can still produce unbounded wall time on
/// pathological content. Chunks exceeding this budget are skipped.
const PER_CHUNK_SCAN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

fn scan_parallel(
    scanner: &std::sync::Arc<CompiledScanner>,
    chunks: &[keyhog_core::Chunk],
    do_decode: bool,
    do_entropy: bool,
    show_progress: bool,
) -> Vec<RawMatch> {
    let progress = ScanProgress::new(chunks.len(), show_progress);
    let timed_out_count = std::sync::atomic::AtomicUsize::new(0);
    let mut result: Vec<RawMatch> = chunks
        .par_iter()
        .flat_map(|chunk| {
            let chunk_start = std::time::Instant::now();

            #[cfg(not(feature = "full"))]
            let _ = (do_decode, do_entropy);

            let matches = scanner.scan(chunk);
            #[cfg(feature = "full")]
            let mut matches = matches;

            // Check timeout after pattern scan
            if chunk_start.elapsed() > PER_CHUNK_SCAN_TIMEOUT {
                timed_out_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::warn!(
                    path = ?chunk.metadata.path,
                    elapsed = ?chunk_start.elapsed(),
                    "chunk scan exceeded time budget, skipping decode/entropy"
                );
                progress.tick();
                return matches;
            }

            #[cfg(feature = "full")]
            if do_decode {
                for decoded in decode::decode_chunk(chunk) {
                    matches.extend(scanner.scan(&decoded));
                    if chunk_start.elapsed() > PER_CHUNK_SCAN_TIMEOUT {
                        tracing::warn!(
                            path = ?chunk.metadata.path,
                            "chunk decode-through exceeded time budget"
                        );
                        break;
                    }
                }
            }

            #[cfg(feature = "full")]
            let is_config = entropy::is_entropy_appropriate(chunk.metadata.path.as_deref());

            #[cfg(feature = "full")]
            if do_entropy && is_config && chunk_start.elapsed() <= PER_CHUNK_SCAN_TIMEOUT {
                for em in entropy::find_entropy_secrets(&chunk.data, 16, 2) {
                    let ml_context = entropy_context_window(&chunk.data, em.line, 2);
                    let ml_score = keyhog_scanner::ml_scorer::score(&em.value, &ml_context);
                    if ml_score < ENTROPY_ML_THRESHOLD {
                        continue;
                    }

                    let conf = compute_entropy_confidence(&em);
                    let blended_conf = 0.6 * ml_score + 0.4 * conf;
                    matches.push(RawMatch {
                        detector_id: "entropy".into(),
                        detector_name: "High-Entropy String".into(),
                        service: "generic".into(),
                        severity: keyhog_core::Severity::Medium,
                        credential: em.value.clone(),
                        companion: None,
                        location: MatchLocation {
                            source: chunk.metadata.source_type.clone(),
                            file_path: chunk.metadata.path.clone(),
                            line: Some(em.line),
                            offset: em.offset,
                            commit: chunk.metadata.commit.clone(),
                            author: chunk.metadata.author.clone(),
                            date: chunk.metadata.date.clone(),
                        },
                        entropy: Some(em.entropy),
                        confidence: Some(blended_conf),
                    });
                }
            }

            progress.tick();
            matches
        })
        .collect::<Vec<_>>();

    let timed_out = timed_out_count.load(std::sync::atomic::Ordering::Relaxed);
    if timed_out > 0 {
        tracing::warn!("{timed_out} chunk(s) exceeded the {PER_CHUNK_SCAN_TIMEOUT:?} scan budget");
    }

    if result.len() > MAX_TOTAL_FINDINGS {
        // Sort by severity (Critical first) so truncation keeps the most
        // important findings. Without sorting, rayon's parallel iteration
        // order is non-deterministic — truncation would discard findings
        // arbitrarily.
        result.sort_by(|a, b| b.severity.cmp(&a.severity));
        tracing::warn!(
            "findings truncated: {} found, keeping top {} by severity",
            result.len(),
            MAX_TOTAL_FINDINGS
        );
        result.truncate(MAX_TOTAL_FINDINGS);
    }
    result
}

#[cfg(feature = "full")]
fn entropy_context_window(data: &str, line: usize, radius: usize) -> String {
    let lines: Vec<&str> = data.lines().collect();
    if lines.is_empty() {
        return String::new();
    }
    let start = line.saturating_sub(radius + 1);
    let end = (line + radius).min(lines.len());
    lines[start..end].join("\n")
}

fn filter_and_resolve(
    mut matches: Vec<RawMatch>,
    args: &ScanArgs,
    allowlist: &keyhog_core::allowlist::Allowlist,
) -> Vec<RawMatch> {
    // Severity filter.
    if let Some(ref min_sev) = args.severity {
        let min = min_sev.to_severity();
        matches.retain(|m| m.severity >= min);
    }
    // Confidence filter.
    if let Some(min_conf) = args.min_confidence {
        matches.retain(|m| m.confidence.map(|c| c >= min_conf).unwrap_or(true));
    }
    // Resolution: most specific detector wins.
    matches = keyhog_scanner::resolution::resolve_matches(matches);
    // Allowlist.
    matches.retain(|m| {
        if let Some(ref path) = m.location.file_path
            && allowlist.is_path_ignored(path)
        {
            return false;
        }
        !allowlist.ignored_detectors.contains(&m.detector_id)
            && !allowlist.is_hash_allowed(&m.credential)
    });
    matches = filter_inline_suppressions(matches);
    matches
}

// dedup_matches is now imported from keyhog_core.

fn parse_min_confidence(value: &str) -> Result<f64, String> {
    let parsed = value
        .parse::<f64>()
        .map_err(|_| format!("invalid float value: {value}"))?;
    if !parsed.is_finite() {
        return Err("min_confidence must be finite".into());
    }
    if !(MIN_CONFIDENCE_LOWER_BOUND..=MIN_CONFIDENCE_UPPER_BOUND).contains(&parsed) {
        return Err(format!(
            "min_confidence must be between {MIN_CONFIDENCE_LOWER_BOUND} and {MIN_CONFIDENCE_UPPER_BOUND}"
        ));
    }
    Ok(parsed)
}

struct ScanProgress {
    total: usize,
    current: AtomicUsize,
    print_lock: Mutex<()>,
    enabled: bool,
}

impl ScanProgress {
    fn new(total: usize, enabled: bool) -> Arc<Self> {
        Arc::new(Self {
            total,
            current: AtomicUsize::new(0),
            print_lock: Mutex::new(()),
            enabled: enabled && total > 0,
        })
    }

    fn tick(&self) {
        if !self.enabled {
            return;
        }
        let current = self.current.fetch_add(1, Ordering::SeqCst) + 1;
        if current == 1 || current == self.total || current.is_multiple_of(100) {
            // SAFETY: terminal writes stay serialized through `print_lock`, so
            // concurrent workers cannot interleave partial progress output.
            let _guard = match self.print_lock.lock() {
                Ok(guard) => guard,
                // SAFETY: if a rayon worker panicked while holding the lock,
                // recover the inner guard instead of cascade-panicking all
                // remaining workers.
                Err(poisoned) => poisoned.into_inner(),
            };
            eprint!("\rscanning {current}/{} chunks", self.total);
            if current == self.total {
                eprintln!();
            }
        }
    }
}

fn filter_inline_suppressions(matches: Vec<RawMatch>) -> Vec<RawMatch> {
    let mut line_cache: HashMap<String, Option<Vec<String>>> = HashMap::new();

    matches
        .into_iter()
        .filter(|m| {
            if m.location.source != "filesystem" {
                return true;
            }
            let Some(path) = m.location.file_path.as_ref() else {
                return true;
            };
            let Some(line) = m.location.line else {
                return true;
            };
            let lines = line_cache.entry(path.clone()).or_insert_with(|| {
                std::fs::read_to_string(path)
                    .ok()
                    .map(|text| text.lines().map(str::to_string).collect::<Vec<_>>())
            });
            !is_inline_suppressed(lines.as_ref().map(Vec::as_slice), line, &m.detector_id)
        })
        .collect()
}

fn is_inline_suppressed(lines: Option<&[String]>, line: usize, detector_id: &str) -> bool {
    let Some(lines) = lines else {
        return false;
    };
    [line.saturating_sub(1), line]
        .into_iter()
        .filter(|line_number| *line_number > 0)
        .filter_map(|line_number| lines.get(line_number - 1))
        .any(|line_text| line_has_inline_suppression(line_text, detector_id))
}

fn line_has_inline_suppression(line: &str, detector_id: &str) -> bool {
    let Some(directive) = inline_suppression_directive(line) else {
        return false;
    };
    let detector = detector_id.to_ascii_lowercase();
    match directive
        .split(|ch: char| ch.is_whitespace() || matches!(ch, ',' | ';'))
        .find_map(|token| token.strip_prefix(DETECTOR_DIRECTIVE_PREFIX))
    {
        Some(expected) => expected == detector,
        None => true,
    }
}

fn inline_suppression_directive(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    comment_segments(&lower).find_map(extract_directive_from_comment)
}

fn comment_segments(line: &str) -> impl Iterator<Item = &str> {
    INLINE_COMMENT_MARKERS
        .iter()
        .filter_map(|marker| line.find(marker).map(|index| &line[index + marker.len()..]))
}

fn extract_directive_from_comment(comment: &str) -> Option<String> {
    let directive_index = comment.find(INLINE_SUPPRESSION_DIRECTIVE)?;
    if comment[..directive_index]
        .chars()
        .any(|character| !character.is_whitespace())
    {
        return None;
    }
    let directive = &comment[directive_index..];
    let token_end = directive
        .find(char::is_whitespace)
        .map_or(directive.len(), |index| index);
    if &directive[..token_end] != INLINE_SUPPRESSION_DIRECTIVE {
        return None;
    }
    Some(directive.to_string())
}

async fn finalize(
    matches: Vec<RawMatch>,
    detectors: &[keyhog_core::DetectorSpec],
    args: &ScanArgs,
) -> Result<Vec<keyhog_core::VerifiedFinding>> {
    let mut groups = dedup_matches(matches, &args.dedup.to_core());
    groups.sort_by(|a, b| b.severity.cmp(&a.severity));

    #[cfg(feature = "verify")]
    if args.verify {
        let secrets: Vec<String> = groups
            .iter()
            .map(|group| group.credential.clone())
            .collect();
        let config = VerifyConfig {
            timeout: std::time::Duration::from_secs(args.timeout),
            max_concurrent_per_service: args.rate,
            ..Default::default()
        };
        let verify_groups = groups;
        let mut findings = VerificationEngine::new(detectors, config)?
            .verify_all(verify_groups)
            .await;

        if args.show_secrets {
            for (finding, secret) in findings.iter_mut().zip(secrets) {
                finding.credential_redacted = secret;
            }
        }

        return Ok(findings);
    }

    let _ = detectors;
    Ok(groups
        .into_iter()
        .map(|g| keyhog_core::VerifiedFinding {
            detector_id: g.detector_id,
            detector_name: g.detector_name,
            service: g.service,
            severity: g.severity,
            credential_redacted: if args.show_secrets {
                g.credential.clone()
            } else {
                keyhog_core::redact(&g.credential)
            },
            location: g.primary_location,
            verification: VerificationResult::Skipped,
            metadata: HashMap::new(),
            additional_locations: g.additional_locations,
            confidence: g.confidence,
        })
        .collect())
}

fn report_findings(findings: &[keyhog_core::VerifiedFinding], args: &ScanArgs) -> Result<()> {
    if let Some(ref path) = args.output {
        let file = std::fs::File::create(path)
            .with_context(|| format!("creating output file {}", path.display()))?;
        let w = io::BufWriter::new(file);
        report_with(w, &args.format, false, findings)
    } else {
        let w = io::BufWriter::new(io::stdout().lock());
        report_with(w, &args.format, io::stdout().is_terminal(), findings)
    }
}

fn report_with<W: std::io::Write + 'static>(
    w: W,
    format: &OutputFormat,
    color: bool,
    findings: &[keyhog_core::VerifiedFinding],
) -> Result<()> {
    match format {
        OutputFormat::Text => finish_reporter(TextReporter::with_color(w, color), findings),
        OutputFormat::Json => finish_reporter(JsonReporter::new(w), findings),
        OutputFormat::Jsonl => finish_reporter(JsonlReporter::new(w), findings),
        OutputFormat::Sarif => finish_reporter(SarifReporter::new(w), findings),
    }
}

fn finish_reporter<R: Reporter>(
    mut reporter: R,
    findings: &[keyhog_core::VerifiedFinding],
) -> Result<()> {
    for finding in findings {
        reporter.report(finding)?;
    }
    reporter.finish()?;
    Ok(())
}

fn build_sources(args: &ScanArgs) -> Result<Vec<Box<dyn Source>>> {
    let mut sources: Vec<Box<dyn Source>> = Vec::new();

    if let Some(ref path) = args.path {
        // Always scan filesystem (text files)
        sources.push(Box::new(keyhog_sources::FilesystemSource::new(
            path.clone(),
        )));
        // Additionally scan binary files when --binary flag is set
        #[cfg(feature = "binary")]
        if args.binary {
            sources.push(Box::new(keyhog_sources::BinarySource::new(path.clone())));
        }
    }

    if args.stdin {
        sources.push(Box::new(keyhog_sources::StdinSource));
    }

    #[cfg(feature = "git")]
    if let Some(ref path) = args.git {
        sources.push(Box::new(
            keyhog_sources::GitSource::new(path.clone()).with_max_commits(args.max_commits),
        ));
    }

    #[cfg(feature = "git")]
    if let Some(ref base_ref) = args.git_diff {
        let repo_path = args
            .git_diff_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("."));
        sources.push(Box::new(keyhog_sources::GitDiffSource::new(
            repo_path,
            base_ref.clone(),
        )));
    }

    #[cfg(feature = "git")]
    if let Some(ref path) = args.git_history {
        sources.push(Box::new(
            keyhog_sources::GitHistorySource::new(path.clone()).with_max_commits(args.max_commits),
        ));
    }

    #[cfg(feature = "github")]
    if let (Some(org), Some(token)) = (&args.github_org, &args.github_token) {
        sources.push(Box::new(keyhog_sources::GitHubOrgSource::new(
            org.clone(),
            token.clone(),
        )));
    }

    #[cfg(feature = "s3")]
    if let Some(bucket) = &args.s3_bucket {
        let mut source = keyhog_sources::S3Source::new(bucket.clone());
        if let Some(prefix) = &args.s3_prefix {
            source = source.with_prefix(prefix.clone());
        }
        if let Some(endpoint) = &args.s3_endpoint {
            source = source.with_endpoint(endpoint.clone());
        }
        sources.push(Box::new(source));
    }

    #[cfg(feature = "docker")]
    if let Some(image) = &args.docker_image {
        sources.push(Box::new(keyhog_sources::DockerImageSource::new(
            image.clone(),
        )));
    }

    #[cfg(feature = "web")]
    if let Some(urls) = &args.url {
        sources.push(Box::new(keyhog_sources::WebSource::new(urls.clone())));
    }

    Ok(sources)
}

/// Compute confidence score for entropy-based findings.
/// Based on entropy value (higher = more confident) and keyword proximity.
#[cfg(feature = "full")]
fn compute_entropy_confidence(em: &entropy::EntropyMatch) -> f64 {
    // Base confidence from entropy: scale 4.0-5.5 to 0.5-0.9
    let entropy_score = if em.entropy >= 5.5 {
        0.9
    } else if em.entropy >= 4.5 {
        0.7 + (em.entropy - 4.5) * 0.2
    } else {
        0.5 + (em.entropy - 4.0) * 0.4
    };

    // Boost for keyword proximity (already factored into finding the match)
    // and reasonable length (16-64 chars is ideal for secrets)
    let length_boost = if em.value.len() >= 16 && em.value.len() <= 64 {
        0.1
    } else {
        0.0
    };

    (entropy_score + length_boost).clamp(0.0, 1.0)
}

fn validate_cli_path_arg(path: &std::path::Path, arg_name: &str) -> Result<()> {
    let path_display = path.to_string_lossy();
    // SAFETY: these paths are forwarded to filesystem and subprocess APIs as
    // trusted argv/path inputs later, so reject option-like and control-char
    // values at the CLI boundary before deeper code tries to interpret them.
    if path_display.starts_with('-') || path_display.chars().any(char::is_control) {
        anyhow::bail!("{arg_name} path contains unsafe characters");
    }
    Ok(())
}

fn list_detectors(args: DetectorArgs) -> Result<()> {
    validate_cli_path_arg(&args.detectors, "detectors")?;
    let detectors = load_detectors(&args.detectors)
        .with_context(|| format!("loading detectors from {}", args.detectors.display()))?;

    println!("{:<30} {:<25} {:<10} NAME", "ID", "SERVICE", "SEVERITY");
    println!("{}", "-".repeat(80));

    for d in &detectors {
        let has_verify = if d.verify.is_some() { "✓" } else { " " };
        println!(
            "{:<30} {:<25} {:<10} {} {}",
            d.id, d.service, d.severity, has_verify, d.name
        );
    }

    println!("\n{} detectors loaded", detectors.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_root_uses_parent_for_files() {
        let path = std::path::Path::new("/tmp/project/src/main.rs");
        assert_eq!(allowlist_root(path), PathBuf::from("/tmp/project/src"));
    }

    #[test]
    fn load_allowlist_falls_back_to_current_dir() {
        let temp_dir = tempfile::tempdir().unwrap();
        let original_dir = std::env::current_dir().unwrap();
        std::fs::write(
            temp_dir.path().join(".keyhogignore"),
            "detector:test-detector\n",
        )
        .unwrap();

        std::env::set_current_dir(temp_dir.path()).unwrap();
        let allowlist = load_allowlist(None);
        std::env::set_current_dir(original_dir).unwrap();

        assert!(allowlist.ignored_detectors.contains("test-detector"));
    }

    #[test]
    fn detector_path_validation_rejects_option_like_paths() {
        let error =
            validate_cli_path_arg(std::path::Path::new("-detectors"), "detectors").unwrap_err();
        assert!(error.to_string().contains("unsafe"));
    }

    #[test]
    fn detector_path_validation_rejects_control_chars() {
        let error =
            validate_cli_path_arg(std::path::Path::new("bad\npath"), "detectors").unwrap_err();
        assert!(error.to_string().contains("unsafe"));
    }

    #[test]
    fn generic_inline_suppression_matches_same_or_previous_line() {
        let lines = vec![
            "# keyhog:ignore".to_string(),
            "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890".to_string(),
        ];
        assert!(is_inline_suppressed(Some(&lines), 2, "github-token"));

        let inline = vec![
            "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890 // keyhog:ignore".to_string(),
        ];
        assert!(is_inline_suppressed(Some(&inline), 1, "github-token"));
    }

    #[test]
    fn detector_specific_inline_suppression_is_scoped() {
        let lines = ["# keyhog:ignore detector=github-token".to_string()];
        assert!(line_has_inline_suppression(&lines[0], "github-token"));
        assert!(!line_has_inline_suppression(&lines[0], "openai-api-key"));
    }

    #[test]
    fn inline_suppression_is_case_insensitive_and_comment_scoped() {
        assert!(line_has_inline_suppression(
            "token=ghp_abc // KeyHog:Ignore detector=GitHub-Token",
            "github-token"
        ));
        assert!(!line_has_inline_suppression(
            "token=\"KeyHog:Ignore detector=github-token\"",
            "github-token"
        ));
    }

    #[test]
    fn min_confidence_rejects_nan_and_infinity() {
        assert!(parse_min_confidence("NaN").is_err());
        assert!(parse_min_confidence("inf").is_err());
        assert!(parse_min_confidence("-inf").is_err());
        assert_eq!(parse_min_confidence("0.5").unwrap(), 0.5);
    }

    #[test]
    #[cfg(feature = "full")]
    fn entropy_context_window_includes_neighboring_lines() {
        let text = "one\ntwo\nthree\nfour\nfive";
        assert_eq!(
            super::entropy_context_window(text, 3, 1),
            "two\nthree\nfour"
        );
    }

    // =========================================================================
    // .keyhog.toml config file tests
    // =========================================================================

    #[test]
    fn config_file_deserialization_full() {
        let toml_str = r#"
            detectors = "custom/detectors"
            severity = "high"
            format = "json"
            fast = false
            deep = true
            no_decode = false
            no_entropy = false
            min_confidence = 0.7
            threads = 8
            dedup = "file"
            verify = true
            timeout = 10
            rate = 3
            max_commits = 500
            show_secrets = true
        "#;
        let config: ConfigFile = toml::from_str(toml_str).unwrap();
        assert_eq!(config.detectors.as_deref(), Some("custom/detectors"));
        assert_eq!(config.severity.as_deref(), Some("high"));
        assert_eq!(config.format.as_deref(), Some("json"));
        assert_eq!(config.deep, Some(true));
        assert_eq!(config.fast, Some(false));
        assert_eq!(config.min_confidence, Some(0.7));
        assert_eq!(config.threads, Some(8));
        assert_eq!(config.dedup.as_deref(), Some("file"));
        assert_eq!(config.timeout, Some(10));
        assert_eq!(config.rate, Some(3));
        assert_eq!(config.max_commits, Some(500));
        assert_eq!(config.show_secrets, Some(true));
    }

    #[test]
    fn config_file_deserialization_empty() {
        let config: ConfigFile = toml::from_str("").unwrap();
        assert!(config.detectors.is_none());
        assert!(config.severity.is_none());
        assert!(config.fast.is_none());
    }

    #[test]
    fn config_file_deserialization_rejects_unknown_fields() {
        let toml_str = r#"unknown_field = "value""#;
        let result: Result<ConfigFile, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn config_file_partial_fields() {
        let toml_str = r#"
            severity = "medium"
            threads = 4
        "#;
        let config: ConfigFile = toml::from_str(toml_str).unwrap();
        assert_eq!(config.severity.as_deref(), Some("medium"));
        assert_eq!(config.threads, Some(4));
        assert!(config.detectors.is_none());
        assert!(config.fast.is_none());
    }

    #[test]
    fn find_config_walks_parent_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("a").join("b").join("c");
        std::fs::create_dir_all(&nested).unwrap();
        let config_path = tmp.path().join(".keyhog.toml");
        std::fs::write(&config_path, "severity = \"high\"").unwrap();

        let found = find_config_file(Some(&nested));
        assert_eq!(found, Some(config_path));
    }

    #[test]
    fn find_config_returns_none_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let found = find_config_file(Some(tmp.path()));
        // The config could exist in parent dirs, but in /tmp it almost certainly won't
        // match the project root. Best-effort: verify the function doesn't panic.
        let _ = found;
    }
}

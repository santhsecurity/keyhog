//! Core scanning orchestration logic for the KeyHog CLI.

use crate::args::ScanArgs;
use crate::baseline::Baseline;
use crate::config::apply_config_file;
use anyhow::{Context, Result};
#[cfg(feature = "verify")]
use keyhog_core::DedupedMatch;
use keyhog_core::{
    DetectorSpec, RawMatch, Source, VerificationResult, VerifiedFinding, dedup_matches,
    load_detectors,
};
use keyhog_scanner::{CompiledScanner, ScannerConfig};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

const EXIT_LIVE_CREDENTIALS: u8 = 10;

pub struct ScanOrchestrator {
    args: ScanArgs,
    detectors: Vec<DetectorSpec>,
    scanner: Arc<CompiledScanner>,
}

impl ScanOrchestrator {
    pub fn new(mut args: ScanArgs) -> Result<Self> {
        if args.path.is_none() {
            args.path = args.input.clone();
        }
        #[cfg(feature = "git")]
        if args.git_staged && args.path.is_none() {
            args.path = Some(PathBuf::from("."));
        }
        apply_config_file(&mut args);

        let hw = keyhog_scanner::hw_probe::probe_hardware();
        configure_threads(args.threads, hw.physical_cores);

        let detectors_path = auto_discover_detectors(&args.detectors)?;
        let detectors = load_detectors_with_cache(&detectors_path)?;

        let mut scanner_config = build_scanner_config(&args);

        // Graceful degradation: reduce memory-heavy settings on low-RAM systems.
        if let Some(mem_mb) = hw.total_memory_mb
            && mem_mb < 4096
        {
            scanner_config.max_matches_per_chunk = scanner_config.max_matches_per_chunk.min(500);
            scanner_config.max_decode_bytes = scanner_config.max_decode_bytes.min(256 * 1024);
        }

        let scanner = Arc::new(
            CompiledScanner::compile(detectors.clone())
                .context("compiling scanner")?
                .with_config(scanner_config),
        );

        Ok(Self {
            args,
            detectors,
            scanner,
        })
    }

    pub fn scanner(&self) -> &CompiledScanner {
        self.scanner.as_ref()
    }

    pub fn args(&self) -> &ScanArgs {
        &self.args
    }

    pub async fn run(self) -> Result<std::process::ExitCode> {
        let start = Instant::now();
        let show_progress = std::io::stderr().is_terminal();

        let hw = keyhog_scanner::hw_probe::probe_hardware();
        if show_progress {
            let _ = keyhog_core::banner::print_banner(
                &mut std::io::stderr(),
                true,
                true,
                self.detectors.len(),
            );
            eprintln!(
                "⚡ {}",
                keyhog_scanner::hw_probe::startup_banner(
                    hw,
                    self.detectors.len(),
                    self.scanner.pattern_count(),
                )
            );
        }

        if self.args.benchmark {
            let results = crate::benchmark::run_benchmark(&self)?;
            for result in results {
                eprintln!(
                    "benchmark | backend={} | throughput={:.2} MiB/s | findings={} | bytes={}",
                    result.backend.label(),
                    result.mb_per_sec,
                    result.findings,
                    result.bytes_scanned
                );
            }
            return Ok(std::process::ExitCode::SUCCESS);
        }

        let allowlist = load_allowlist(self.args.path.as_deref());
        let sources = crate::sources::build_sources(&self.args, allowlist.ignored_paths.clone())?;
        if sources.is_empty() {
            anyhow::bail!(
                "no input source specified — use --path, --stdin, --git, --git-diff, --git-history, --github-org, --s3-bucket, or --docker-image"
            );
        }

        let all_matches = self.scan_sources(sources, show_progress);
        let filtered = self.filter_and_resolve(all_matches, &allowlist);
        let findings = self.finalize(filtered).await?;

        // Baseline handling: create, update, or filter
        if let Some(ref path) = self.args.create_baseline {
            let baseline = Baseline::from_findings(&findings);
            baseline.save(path)?;
            if show_progress {
                eprintln!(
                    "\n📝 Baseline created with {} entries at {}",
                    baseline.entries.len(),
                    path.display()
                );
            }
            return Ok(std::process::ExitCode::SUCCESS);
        }

        let (report_findings, has_new_entries) = if let Some(ref path) = self.args.update_baseline {
            let mut baseline = if path.exists() {
                Baseline::load(path)?
            } else {
                Baseline::empty()
            };
            let new_findings = baseline.filter_new(&findings);
            let had_new = !new_findings.is_empty();
            baseline.merge(&findings);
            baseline.save(path)?;
            if show_progress {
                eprintln!(
                    "\n📝 Baseline updated: added {} new entries at {}",
                    new_findings.len(),
                    path.display()
                );
            }
            (new_findings, had_new)
        } else if let Some(ref path) = self.args.baseline {
            let baseline = Baseline::load(path)?;
            let filtered_findings = baseline.filter_new(&findings);
            let suppressed_count = findings.len() - filtered_findings.len();
            let has_new = !filtered_findings.is_empty();
            if show_progress && suppressed_count > 0 {
                eprintln!("\n  Suppressed {} baseline finding(s)", suppressed_count);
            }
            (filtered_findings, has_new)
        } else {
            let has_findings = !findings.is_empty();
            (findings, has_findings)
        };

        let has_live_credentials = report_findings
            .iter()
            .any(|f| matches!(f.verification, VerificationResult::Live));

        crate::reporting::report_findings(&report_findings, &self.args)?;

        let elapsed = start.elapsed().as_secs_f64();
        if show_progress {
            report_completion_summary(report_findings.len(), elapsed);
        }

        tracing::info!(
            "Done in {:.1}s — {} findings",
            elapsed,
            report_findings.len()
        );

        Ok(if has_live_credentials {
            std::process::ExitCode::from(EXIT_LIVE_CREDENTIALS)
        } else if has_new_entries {
            std::process::ExitCode::from(1)
        } else {
            std::process::ExitCode::SUCCESS
        })
    }

    pub(crate) fn scan_sources(
        &self,
        sources: Vec<Box<dyn Source>>,
        _show_progress: bool,
    ) -> Vec<RawMatch> {
        // Collect all chunks, then coalesced scan.
        let mut all_chunks = Vec::new();
        for source in &sources {
            for chunk_result in source.chunks() {
                match chunk_result {
                    Ok(c) if c.data.len() <= 512 * 1024 * 1024 => all_chunks.push(c),
                    Ok(_) => {}
                    Err(e) => tracing::warn!("source: {e}"),
                }
            }
        }

        // Coalesced scan: parallel HS per-file, zero overhead for non-hit files.
        // scan_coalesced checks internally if HS is available.
        let per_chunk = self.scanner().scan_coalesced(&all_chunks);
        per_chunk.into_iter().flatten().collect()
    }

    fn filter_and_resolve(
        &self,
        matches: Vec<RawMatch>,
        allowlist: &keyhog_core::allowlist::Allowlist,
    ) -> Vec<RawMatch> {
        let mut filtered = matches
            .into_iter()
            .filter(|m| {
                if let Some(path) = m.location.file_path.as_deref()
                    && allowlist.is_path_ignored(path)
                {
                    return false;
                }
                if allowlist.is_raw_hash_ignored(&m.credential_hash) {
                    return false;
                }
                // Default confidence threshold: 0.3 filters out low-quality generic matches
                // that dominate false positives on real codebases. Override with --min-confidence.
                if let Some(conf) = m.confidence
                    && conf < self.args.min_confidence.unwrap_or(0.3)
                {
                    return false;
                }
                if let Some(min_severity) = &self.args.severity
                    && m.severity < min_severity.to_severity()
                {
                    return false;
                }
                true
            })
            .collect::<Vec<_>>();

        filtered = keyhog_scanner::resolution::resolve_matches(filtered);
        crate::utils::filter_inline_suppressions(filtered)
    }

    async fn finalize(&self, mut matches: Vec<RawMatch>) -> Result<Vec<VerifiedFinding>> {
        matches.sort_by(|a, b| b.severity.cmp(&a.severity));
        let scope = self.args.dedup.to_core();
        let deduped = dedup_matches(matches, &scope);

        #[cfg(feature = "verify")]
        if self.args.verify {
            return self.verify_findings(deduped).await;
        }

        Ok(deduped
            .into_iter()
            .map(|m| VerifiedFinding {
                detector_id: m.detector_id,
                detector_name: m.detector_name,
                service: m.service,
                severity: m.severity,
                credential_redacted: if self.args.show_secrets {
                    m.credential.to_string().into()
                } else {
                    keyhog_core::redact(&m.credential)
                },
                credential_hash: m.credential_hash,
                location: m.primary_location,
                verification: VerificationResult::Skipped,
                metadata: std::collections::HashMap::new(),
                additional_locations: m.additional_locations,
                confidence: m.confidence,
            })
            .collect())
    }

    #[cfg(feature = "verify")]
    async fn verify_findings(&self, groups: Vec<DedupedMatch>) -> Result<Vec<VerifiedFinding>> {
        use keyhog_verifier::{VerificationEngine, VerifyConfig};

        // Gate verification behind confidence threshold.
        // Low-confidence matches (< 0.3) are almost always false positives —
        // verifying them wastes HTTP budget and can trigger API rate limiting.
        const MIN_VERIFY_CONFIDENCE: f64 = 0.3;
        let (verify_candidates, skip_candidates): (Vec<_>, Vec<_>) = groups
            .into_iter()
            .partition(|m| m.confidence.unwrap_or(0.0) >= MIN_VERIFY_CONFIDENCE);

        let skipped_count = skip_candidates.len();
        if skipped_count > 0 {
            tracing::info!(
                skipped = skipped_count,
                threshold = MIN_VERIFY_CONFIDENCE,
                "skipping low-confidence findings from verification"
            );
        }

        let verifier = VerificationEngine::new(
            &self.detectors,
            VerifyConfig {
                timeout: Duration::from_secs(self.args.timeout),
                max_concurrent_per_service: self.args.rate,
                ..Default::default()
            },
        )
        .context("initializing verification engine")?;

        let mut findings = verifier.verify_all(verify_candidates).await;

        // Include low-confidence matches as unverified findings
        for m in skip_candidates {
            findings.push(keyhog_core::VerifiedFinding {
                detector_id: m.detector_id,
                detector_name: m.detector_name,
                service: m.service,
                severity: m.severity,
                credential_redacted: keyhog_core::redact(&m.credential),
                credential_hash: m.credential_hash,
                location: m.primary_location,
                additional_locations: m.additional_locations,
                verification: keyhog_core::VerificationResult::Skipped,
                metadata: std::collections::HashMap::new(),
                confidence: m.confidence,
            });
        }

        Ok(findings)
    }
}

fn configure_threads(threads: Option<usize>, physical_cores: usize) {
    let n = threads.unwrap_or(physical_cores);

    #[allow(unused_mut)]
    let mut builder = rayon::ThreadPoolBuilder::new()
        .num_threads(n)
        .stack_size(8 * 1024 * 1024);

    #[cfg(target_os = "macos")]
    {
        // Name threads so GCD can reason about our footprint.
        builder = builder.thread_name(|i| format!("keyhog-worker-{i}"));
    }

    if let Err(error) = builder.build_global() {
        tracing::warn!(
            requested_threads = n,
            "failed to configure rayon thread pool: {error}"
        );
    }
}

fn auto_discover_detectors(path: &Path) -> Result<PathBuf> {
    // Check KEYHOG_DETECTORS env var first
    if let Ok(env_path) = std::env::var("KEYHOG_DETECTORS") {
        let p = PathBuf::from(&env_path);
        if p.exists() && p.is_dir() {
            return Ok(p);
        }
    }

    if path == Path::new("detectors") && !path.exists() {
        let default_dirs = [
            dirs::home_dir().map(|h| h.join(".keyhog/detectors")),
            Some(PathBuf::from("/usr/share/keyhog/detectors")),
            Some(PathBuf::from("/usr/local/share/keyhog/detectors")),
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.join("detectors"))),
        ];

        for dir in default_dirs.into_iter().flatten() {
            if dir.exists() && dir.is_dir() {
                eprintln!("Auto-detected: using detectors directory {}", dir.display());
                return Ok(dir);
            }
        }
    }
    Ok(path.to_path_buf())
}

fn load_detectors_with_cache(path: &Path) -> Result<Vec<DetectorSpec>> {
    // Try loading from filesystem first
    if path.exists() && path.is_dir() {
        let cache_path = path.join(".keyhog-cache.json");
        if let Some(cached) = keyhog_core::load_detector_cache(&cache_path, path) {
            return Ok(cached);
        }
        let loaded = load_detectors(path)?;
        let _ = keyhog_core::save_detector_cache(&loaded, &cache_path);
        return Ok(loaded);
    }

    // Fall back to embedded detectors (compiled into the binary)
    let embedded = keyhog_core::embedded_detector_tomls();
    if !embedded.is_empty() {
        eprintln!(
            "Using {} embedded detectors (no external detectors directory found)",
            embedded.len()
        );
        let mut detectors = Vec::new();
        for (name, toml_content) in embedded {
            match toml::from_str::<keyhog_core::DetectorFile>(toml_content) {
                Ok(file) => detectors.push(file.detector),
                Err(e) => tracing::debug!("failed to parse embedded detector {}: {}", name, e),
            }
        }
        if detectors.is_empty() {
            anyhow::bail!("no detectors loaded from embedded data");
        }
        return Ok(detectors);
    }

    anyhow::bail!(
        "detectors directory '{}' not found and no embedded detectors available. \
         Fix: specify --detectors <path> or set KEYHOG_DETECTORS env var",
        path.display()
    )
}

fn build_scanner_config(args: &ScanArgs) -> ScannerConfig {
    let mut config = if args.fast {
        ScannerConfig::fast()
    } else if args.deep {
        ScannerConfig::thorough()
    } else {
        ScannerConfig::default()
    };

    if !args.fast && !args.deep {
        if let Some(depth) = args.decode_depth {
            config.max_decode_depth = depth;
        }
        if let Some(size) = args.decode_size_limit {
            config.max_decode_bytes = size;
        }
        if let Some(conf) = args.min_confidence {
            config.min_confidence = conf;
        }

        #[cfg(feature = "full")]
        {
            config.entropy_enabled = !args.no_entropy;
            if let Some(threshold) = args.entropy_threshold {
                config.entropy_threshold = threshold;
            }
            config.entropy_in_source_files = args.entropy_source_files;
            config.ml_enabled = !args.no_ml;
            if let Some(weight) = args.ml_weight {
                config.ml_weight = weight;
            }
            config.unicode_normalization = !args.no_unicode_norm;

            if !args.known_prefixes.is_empty() {
                config.known_prefixes = args.known_prefixes.clone();
            }
            if !args.secret_keywords.is_empty() {
                config.secret_keywords = args.secret_keywords.clone();
            }
            if !args.test_keywords.is_empty() {
                config.test_keywords = args.test_keywords.clone();
            }
            if !args.placeholder_keywords.is_empty() {
                config.placeholder_keywords = args.placeholder_keywords.clone();
            }
        }
    }
    config
}

fn load_allowlist(scan_path: Option<&Path>) -> keyhog_core::allowlist::Allowlist {
    let base_path = scan_path
        .map(allowlist_root)
        .unwrap_or_else(|| PathBuf::from("."));
    let ignore_path = base_path.join(".keyhogignore");
    if ignore_path.exists() {
        keyhog_core::allowlist::Allowlist::load(&ignore_path)
            .unwrap_or_else(|_| keyhog_core::allowlist::Allowlist::empty())
    } else {
        keyhog_core::allowlist::Allowlist::empty()
    }
}

fn allowlist_root(path: &Path) -> PathBuf {
    if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    }
}

fn report_completion_summary(count: usize, elapsed: f64) {
    if count == 0 {
        eprintln!(
            "\n✨ Scan complete! Found \x1b[1;32m0\x1b[0m secrets in \x1b[33m{:.2}s\x1b[0m. You are secure!",
            elapsed
        );
    } else {
        eprintln!(
            "\n✨ Scan complete! Found \x1b[1;31m{}\x1b[0m secrets in \x1b[33m{:.2}s\x1b[0m.",
            count, elapsed
        );
    }
}

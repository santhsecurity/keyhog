//! Detector loading pipeline: read TOML files, run the quality gate, and inject
//! small compatibility shims for legacy token formats when needed.

use std::path::{Path, PathBuf};

use rayon::prelude::*;

use super::{DetectorFile, DetectorSpec, PatternSpec, QualityIssue, SpecError, validate_detector};

/// Save detectors to a JSON cache file for fast subsequent loads.
pub fn save_detector_cache(
    detectors: &[DetectorSpec],
    cache_path: &Path,
) -> Result<(), std::io::Error> {
    let json = serde_json::to_vec(detectors)?;
    std::fs::write(cache_path, json)
}

/// Load detectors from a JSON cache file. Returns None if cache is stale or missing.
pub fn load_detector_cache(
    cache_path: &Path,
    source_dir: &Path,
) -> Option<Vec<DetectorSpec>> {
    let cache_meta = std::fs::metadata(cache_path).ok()?;
    let cache_mtime = cache_meta.modified().ok()?;

    // Check if any TOML in source_dir is newer than the cache
    let entries = std::fs::read_dir(source_dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "toml") {
            if let Ok(meta) = std::fs::metadata(&path) {
                if let Ok(mtime) = meta.modified() {
                    if mtime > cache_mtime {
                        return None; // Cache is stale
                    }
                }
            }
        }
    }

    let data = std::fs::read(cache_path).ok()?;
    serde_json::from_slice(&data).ok()
}

/// Load all detector specs from a directory of TOML files.
/// Runs quality gate on each detector. Rejects detectors with errors, warns on issues.
pub fn load_detectors(dir: &Path) -> Result<Vec<DetectorSpec>, SpecError> {
    load_detectors_with_gate(dir, true)
}

/// Load detectors with optional quality gate enforcement.
/// When `enforce_gate` is `true`, detectors with quality errors are skipped.
pub fn load_detectors_with_gate(
    dir: &Path,
    enforce_gate: bool,
) -> Result<Vec<DetectorSpec>, SpecError> {
    // Phase 1: collect all TOML file paths (fast, sequential)
    let entries = std::fs::read_dir(dir).map_err(|e| SpecError::ReadFile {
        path: dir.display().to_string(),
        source: e,
    })?;
    let toml_paths: Vec<PathBuf> = entries
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "toml") {
                Some(path)
            } else {
                None
            }
        })
        .collect();

    // Phase 2: read + parse all TOMLs in parallel
    let parsed: Vec<Option<DetectorSpec>> = toml_paths
        .par_iter()
        .map(|path| {
            let mut skipped = 0;
            let mut errors = Vec::new();
            read_detector_file(path, &mut skipped, &mut errors)
        })
        .collect();

    // Phase 3: validate + filter (sequential for logging)
    let mut load_state = DetectorLoadState::default();
    let mut detectors = Vec::with_capacity(parsed.len());

    for spec in parsed.into_iter().flatten() {
        if should_reject_detector(
            &spec,
            enforce_gate,
            &mut load_state.gate_rejected,
            &mut load_state.total_warnings,
        ) {
            continue;
        }
        detectors.push(spec);
    }

    if should_inject_github_classic_pat_detector(&detectors) {
        inject_github_classic_pat_detector(&mut detectors);
    }

    log_load_summary(&load_state);

    detectors.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(detectors)
}

#[derive(Default)]
struct DetectorLoadState {
    skipped: usize,
    load_errors: Vec<String>,
    gate_rejected: usize,
    total_warnings: usize,
}

fn log_load_summary(state: &DetectorLoadState) {
    if state.skipped > 0 {
        tracing::info!("skipped {} unparseable files", state.skipped);
    }
    for error in &state.load_errors {
        tracing::info!("detector load issue: {error}");
    }
    if state.gate_rejected > 0 {
        tracing::info!("quality gate: rejected {} detectors", state.gate_rejected);
    }
    if state.total_warnings > 0 {
        tracing::debug!("quality gate: {} warnings", state.total_warnings);
    }
}

fn read_detector_file(
    path: &Path,
    skipped: &mut usize,
    load_errors: &mut Vec<String>,
) -> Option<DetectorSpec> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) => {
            let message = format!("failed to read {}: {}", path.display(), error);
            tracing::debug!("{message}");
            load_errors.push(message);
            *skipped += 1;
            return None;
        }
    };

    match toml::from_str::<DetectorFile>(&contents) {
        Ok(file) => Some(file.detector),
        Err(error) => {
            let message = format!("failed to parse {}: {}", path.display(), error);
            tracing::debug!("{message}");
            load_errors.push(message);
            *skipped += 1;
            None
        }
    }
}

fn should_reject_detector(
    spec: &DetectorSpec,
    enforce_gate: bool,
    gate_rejected: &mut usize,
    total_warnings: &mut usize,
) -> bool {
    let mut has_errors = false;
    for issue in validate_detector(spec) {
        match issue {
            QualityIssue::Warning(warning) => {
                tracing::debug!("quality: {} — {}", spec.id, warning);
                *total_warnings += 1;
            }
            QualityIssue::Error(error) => {
                tracing::warn!("failed to validate detector: {}: {}", spec.id, error);
                has_errors = true;
            }
        }
    }

    if has_errors && enforce_gate {
        *gate_rejected += 1;
        return true;
    }

    false
}

pub(super) fn inject_github_classic_pat_detector(detectors: &mut Vec<DetectorSpec>) {
    let Some(github_fine_grained) = detectors
        .iter()
        .find(|d| d.id == "github-pat-fine-grained")
        .cloned()
    else {
        return;
    };

    let mut compat = github_fine_grained;
    compat.id = "github-classic-pat".into();
    compat.name = "GitHub Classic PAT".into();
    compat.keywords = vec!["ghp_".into(), "github".into()];
    compat.patterns = vec![PatternSpec {
        regex: "ghp_[a-zA-Z0-9]{36}".into(),
        description: Some("GitHub classic personal access token".into()),
        group: None,
    }];

    detectors.push(compat);
}

fn should_inject_github_classic_pat_detector(detectors: &[DetectorSpec]) -> bool {
    !detectors.iter().any(|d| d.id == "github-classic-pat")
        && detectors.iter().any(|d| d.id == "github-pat-fine-grained")
}

//! Shared git utilities.

use keyhog_core::SourceError;
use std::path::{Path, PathBuf};
use std::process::Command;

mod diff;
mod history;
mod source;

pub use diff::GitDiffSource;
pub use history::GitHistorySource;
pub use source::GitSource;

pub(crate) fn validate_repo_path(repo_path: &Path) -> Result<String, SourceError> {
    let path = repo_path.to_str().unwrap_or(".");
    if path.starts_with('-') || path.chars().any(char::is_control) {
        return Err(SourceError::Other(
            "repository path contains unsafe characters".into(),
        ));
    }
    Ok(path.to_string())
}

pub(crate) fn canonical_repo_root(repo_path: &Path) -> Result<PathBuf, SourceError> {
    std::fs::canonicalize(repo_path).map_err(SourceError::Io)
}

pub(crate) fn validate_ref_name(ref_name: &str) -> Result<String, SourceError> {
    let ref_name = ref_name.trim();
    if ref_name.is_empty() {
        return Err(SourceError::Git("git ref cannot be empty".into()));
    }

    if ref_name.starts_with('-')
        || ref_name
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
        || ref_name.contains("..")
        || ref_name.contains(':')
        || ref_name.contains('?')
        || ref_name.contains('*')
        || ref_name.contains('[')
        || ref_name.contains('\\')
    {
        return Err(SourceError::Git(format!("unsafe git ref '{ref_name}'")));
    }

    Ok(ref_name.to_string())
}

pub(crate) fn verify_ref(repo_path: &str, ref_name: &str) -> Result<(), SourceError> {
    let output = Command::new("git")
        .args(["-C", repo_path, "rev-parse", "--verify", "--end-of-options"])
        .arg(format!("{ref_name}^{{commit}}"))
        .output()
        .map_err(SourceError::Io)?;

    if !output.status.success() {
        return Err(SourceError::Git(format!(
            "ref '{}' not found in repository",
            ref_name
        )));
    }

    Ok(())
}

pub(crate) fn get_commit_hash(repo_path: &str, ref_name: &str) -> Result<String, SourceError> {
    let output = Command::new("git")
        .args(["-C", repo_path, "rev-parse", "--verify", "--end-of-options"])
        .arg(format!("{ref_name}^{{commit}}"))
        .output()
        .map_err(SourceError::Io)?;

    if !output.status.success() {
        return Err(SourceError::Git(format!(
            "failed to resolve ref: {}",
            ref_name
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub(crate) fn get_commit_author(repo_path: &str, ref_name: &str) -> Result<String, SourceError> {
    let output = Command::new("git")
        .args([
            "-C",
            repo_path,
            "log",
            "-1",
            "--format=%an",
            "--end-of-options",
        ])
        .arg(ref_name)
        .output()
        .map_err(SourceError::Io)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SourceError::Git(format!(
            "failed to read commit author for '{}': {}",
            ref_name,
            stderr.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub(crate) fn get_commit_date(repo_path: &str, ref_name: &str) -> Result<String, SourceError> {
    let output = Command::new("git")
        .args([
            "-C",
            repo_path,
            "log",
            "-1",
            "--format=%aI",
            "--end-of-options",
        ])
        .arg(ref_name)
        .output()
        .map_err(SourceError::Io)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SourceError::Git(format!(
            "failed to read commit date for '{}': {}",
            ref_name,
            stderr.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

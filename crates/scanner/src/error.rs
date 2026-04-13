//! Specialized error types for the scanner engine.

use thiserror::Error;
use warpstate::Error as WarpstateError;

#[derive(Debug, Error)]
/// Errors returned while compiling detector patterns into a scanner.
pub enum ScanError {
    #[error(
        "failed to compile regex for detector {detector_id} pattern {index}: {source}. Fix: correct the detector regex or capture group configuration"
    )]
    RegexCompile {
        detector_id: String,
        index: usize,
        source: regex::Error,
    },
    #[error(
        "failed to compile scanner regex set: {0}. Fix: simplify the detector regex set or remove the invalid pattern"
    )]
    RegexSetCompile(#[from] regex::Error),
    #[error(
        "failed to build warpstate automaton: {0}. Fix: reduce detector complexity or remove unsupported regex constructs"
    )]
    Warpstate(#[from] WarpstateError),
    #[error(
        "failed to build Aho-Corasick literal matcher: {0}. Fix: check for empty or invalid detector keywords"
    )]
    AhoCorasick(#[from] aho_corasick::BuildError),
}

/// Specialized Result type for scanning operations.
pub type Result<T> = std::result::Result<T, ScanError>;

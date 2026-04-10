//! Core types shared across all KeyHog crates.
//!
//! Defines the [`Source`] trait for pluggable input backends, [`DetectorSpec`]
//! for TOML-based pattern definitions, [`Finding`] for scanner output,
//! [`DedupedMatch`] for grouped findings, and [`Report`] for structured result
//! formatting.

/// Credential/path allowlist parsing and matching.
pub mod allowlist;
pub mod banner;
/// Configuration system for KeyHog scanning options.
pub mod config;
mod dedup;
mod finding;
pub mod report;
mod source;
mod spec;
use std::borrow::Cow;

pub mod registry;

pub use allowlist::*;
pub use config::*;
pub use dedup::*;
pub use finding::*;
pub use report::*;
pub use source::*;
pub use spec::*;

// Embedded detectors compiled into the binary at build time.
// These are used when no external detectors directory is found.
mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_detectors.rs"));
}

/// Load detectors from embedded data (compiled into the binary).
/// Returns detector TOML strings that can be parsed by the spec loader.
pub fn embedded_detector_tomls() -> &'static [(&'static str, &'static str)] {
    embedded::EMBEDDED_DETECTORS
}

/// Redact a sensitive credential string for safe display.
pub fn redact(s: &str) -> Cow<'static, str> {
    let char_count = s.chars().count();

    if char_count <= 8 {
        return Cow::Borrowed("****");
    }

    let first_four: String = s.chars().take(4).collect();
    let last_four: String = s.chars().skip(char_count.saturating_sub(4)).collect();

    Cow::Owned(format!("{}...{}", first_four, last_four))
}

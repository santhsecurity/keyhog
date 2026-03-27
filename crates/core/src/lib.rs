//! Core types shared across all KeyHog crates.
//!
//! Defines the [`Source`] trait for pluggable input backends, [`DetectorSpec`]
//! for TOML-based pattern definitions, [`Finding`] for scanner output,
//! [`DedupedMatch`] for grouped findings, and [`Report`] for structured result
//! formatting.

/// Credential/path allowlist parsing and matching.
pub mod allowlist;
mod dedup;
mod finding;
mod report;
mod source;
mod spec;

pub use dedup::*;
pub use finding::*;
pub use report::*;
pub use source::*;
pub use spec::*;

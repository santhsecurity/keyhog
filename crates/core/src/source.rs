//! Source trait and chunk types: the abstraction for pluggable input backends.

use serde::Serialize;
use thiserror::Error;

/// A scannable chunk of text with metadata about where it came from.
#[derive(Debug, Clone, Serialize)]
pub struct Chunk {
    /// UTF-8 text content to scan.
    pub data: String,
    /// Provenance details used in findings and reporters.
    pub metadata: ChunkMetadata,
}

/// Metadata that tracks the source location for a scanned chunk.
#[derive(Debug, Clone, Serialize)]
pub struct ChunkMetadata {
    /// Logical source backend, such as `filesystem` or `git`.
    pub source_type: String,
    /// Best-effort file path or object key.
    pub path: Option<String>,
    /// Commit identifier for git-derived chunks.
    pub commit: Option<String>,
    /// Author name when available from history sources.
    pub author: Option<String>,
    /// Source timestamp when available from history sources.
    pub date: Option<String>,
}

/// Produces chunks of text for the scanner to process.
/// Each implementation handles a different input source.
pub trait Source {
    /// Human-readable source name used in warnings and telemetry.
    fn name(&self) -> &str;
    /// Yield all readable chunks from this source.
    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_>;
}

/// Errors returned by input sources while enumerating or reading content.
#[derive(Debug, Error)]
pub enum SourceError {
    #[error("failed to read source: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to access git source: {0}")]
    Git(String),
    #[error("failed to read source: {0}")]
    Other(String),
}

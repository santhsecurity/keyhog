//! Pluggable input sources for KeyHog.
//!
//! Each source implements the [`keyhog_core::Source`] trait and yields [`keyhog_core::Chunk`]
//! values for the scanner. Sources are gated behind cargo features so only the
//! transitive dependencies you actually need are compiled.

#[cfg(feature = "binary")]
mod binary;
#[cfg(feature = "docker")]
mod docker;
mod filesystem;
mod strings;
#[cfg(feature = "git")]
mod git;
#[cfg(feature = "git")]
mod git_diff;
#[cfg(feature = "git")]
mod git_history;
#[cfg(feature = "github")]
mod github_org;
#[cfg(feature = "s3")]
mod s3;
mod stdin;

#[cfg(feature = "binary")]
pub use binary::BinarySource;
#[cfg(feature = "docker")]
pub use docker::DockerImageSource;
pub use filesystem::FilesystemSource;
#[cfg(feature = "git")]
pub use git::GitSource;
#[cfg(feature = "git")]
pub use git_diff::GitDiffSource;
#[cfg(feature = "git")]
pub use git_history::GitHistorySource;
#[cfg(feature = "github")]
pub use github_org::GitHubOrgSource;
#[cfg(feature = "s3")]
pub use s3::S3Source;
pub use stdin::StdinSource;

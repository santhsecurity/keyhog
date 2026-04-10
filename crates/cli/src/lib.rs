use std::sync::atomic::AtomicUsize;

pub static SCANNED_CHUNKS: AtomicUsize = AtomicUsize::new(0);
pub static TOTAL_CHUNKS: AtomicUsize = AtomicUsize::new(0);
pub static FINDINGS_COUNT: AtomicUsize = AtomicUsize::new(0);

pub mod args;
pub mod baseline;
pub mod benchmark;
pub mod config;
pub mod orchestrator;
pub mod reporting;
pub mod sources;
pub mod subcommands;
pub mod utils;

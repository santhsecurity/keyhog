//! KeyHog CLI: the developer-first secret scanner.

pub static SCANNED_CHUNKS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
pub static TOTAL_CHUNKS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
pub static FINDINGS_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub mod args;
pub mod baseline;
pub mod benchmark;
pub mod config;
pub mod orchestrator;
pub mod reporting;
pub mod sources;
pub mod subcommands;
pub mod utils;

use clap::Parser;
use std::io::IsTerminal;
use std::process::ExitCode;

use crate::args::{Cli, Command};

const EXIT_RUNTIME_ERROR: u8 = 2;

#[tokio::main]
async fn main() -> ExitCode {
    tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            let scanned = crate::SCANNED_CHUNKS.load(std::sync::atomic::Ordering::SeqCst);
            let total = crate::TOTAL_CHUNKS.load(std::sync::atomic::Ordering::SeqCst);
            let findings = crate::FINDINGS_COUNT.load(std::sync::atomic::Ordering::SeqCst);
            eprintln!(
                "\nScan interrupted. {}/{} files scanned. {} findings.",
                scanned, total, findings
            );
            std::process::exit(130);
        }
    });

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
        print_version_info();
        return ExitCode::SUCCESS;
    }

    let command_outcome = match cli.command {
        Some(Command::Scan(args)) => subcommands::scan::run(*args).await,
        Some(Command::Hook { command }) => subcommands::hook::run(command),
        Some(Command::Detectors(args)) => {
            subcommands::detectors::run(args).map(|()| ExitCode::SUCCESS)
        }
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

fn print_version_info() {
    println!("KeyHog v{}", env!("CARGO_PKG_VERSION"));
    println!(
        "Build Target: {}-{}",
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    println!(
        "ML Model Version: {}",
        keyhog_scanner::ml_scorer::model_version()
    );
    let hw = keyhog_scanner::hw_probe::probe_hardware();
    if hw.gpu_available {
        println!(
            "GPU Acceleration: {} ({})",
            hw.gpu_name.as_deref().unwrap_or("available"),
            hw.gpu_vram_mb
                .map(|mb| format!("{mb} MB VRAM"))
                .unwrap_or_default()
        );
    } else {
        println!("GPU Acceleration: not detected");
    }
    if hw.hyperscan_available {
        println!("SIMD Regex:       vectorscan/hyperscan (active)");
    } else if hw.has_avx512 || hw.has_avx2 || hw.has_neon {
        let simd = if hw.has_avx512 {
            "AVX-512"
        } else if hw.has_avx2 {
            "AVX2"
        } else {
            "NEON"
        };
        println!("SIMD Regex:       {simd} (no Hyperscan)");
    } else {
        println!("SIMD Regex:       not available");
    }
    if hw.io_uring_available {
        println!("io_uring:         available");
    }
}

/// Print the animated amber-gradient KEYHOG banner to stderr.
pub fn print_banner(detector_count: usize) {
    if !std::io::stderr().is_terminal() {
        return;
    }

    let mut stderr = std::io::stderr();
    let _ = keyhog_core::banner::print_banner(&mut stderr, true, true, detector_count);
    eprintln!();
}

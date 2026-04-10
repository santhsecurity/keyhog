//! Logic for the `detectors` subcommand.

use crate::args::DetectorArgs;
use anyhow::Result;

pub fn run(args: DetectorArgs) -> Result<()> {
    let detectors = if args.detectors.exists() && args.detectors.is_dir() {
        keyhog_core::load_detectors(&args.detectors)?
    } else {
        // Fall back to embedded detectors
        let embedded = keyhog_core::embedded_detector_tomls();
        if embedded.is_empty() {
            anyhow::bail!(
                "detector directory '{}' not found and no embedded detectors available",
                args.detectors.display()
            );
        }
        let mut dets = Vec::new();
        for (name, toml_content) in embedded {
            match toml::from_str::<keyhog_core::DetectorFile>(toml_content) {
                Ok(file) => dets.push(file.detector),
                Err(e) => eprintln!("warning: failed to parse embedded detector {name}: {e}"),
            }
        }
        dets
    };
    let source = if args.detectors.exists() {
        format!("{}", args.detectors.display())
    } else {
        "embedded".to_string()
    };
    println!("Loaded {} detectors ({source}):", detectors.len());

    let mut by_service: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for d in detectors {
        by_service.entry(d.service.clone()).or_default().push(d.id);
    }

    let mut services: Vec<_> = by_service.keys().collect();
    services.sort();

    for service in services {
        if let Some(ids) = by_service.get(service) {
            println!("  - {} ({} detectors)", service, ids.len());
            for id in ids {
                println!("    - {}", id);
            }
        }
    }

    Ok(())
}

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // Look for detectors in multiple locations:
    // 1. Inside the crate (for crates.io packages): crates/core/detectors/
    // 2. Workspace root (for local development): ../../detectors/
    let candidates = [
        Path::new(&manifest_dir).join("detectors"),
        Path::new(&manifest_dir)
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("detectors"))
            .unwrap_or_default(),
    ];

    let detectors_dir = candidates.iter().find(|p| p.exists() && p.is_dir());

    let Some(detectors_dir) = detectors_dir else {
        println!("cargo:warning=detectors/ directory not found, embedded detectors will be empty");
        let out_dir = env::var("OUT_DIR").unwrap();
        fs::write(
            Path::new(&out_dir).join("embedded_detectors.rs"),
            "pub const EMBEDDED_DETECTORS: &[(&str, &str)] = &[];\n",
        )
        .unwrap();
        return;
    };

    let mut entries = Vec::new();
    for entry in fs::read_dir(detectors_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "toml") {
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            let content = fs::read_to_string(&path).unwrap();
            entries.push((name, content));
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let out_dir = env::var("OUT_DIR").unwrap();
    let mut code = String::from("pub const EMBEDDED_DETECTORS: &[(&str, &str)] = &[\n");
    for (name, content) in &entries {
        let escaped = content.replace('\\', "\\\\").replace('"', "\\\"");
        code.push_str(&format!("    (\"{name}\", \"{escaped}\"),\n"));
    }
    code.push_str("];\n");

    fs::write(Path::new(&out_dir).join("embedded_detectors.rs"), code).unwrap();

    // Rerun if any detector file changes
    println!("cargo:rerun-if-changed={}", detectors_dir.display());
    println!(
        "cargo:warning=Embedded {} detectors ({} bytes)",
        entries.len(),
        entries.iter().map(|(_, c)| c.len()).sum::<usize>()
    );
}

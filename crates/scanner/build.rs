use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=src/weights.bin");

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("model_version.rs");

    if let Ok(bytes) = fs::read("src/weights.bin") {
        // Compute a simple deterministic hash (FNV-1a 64-bit)
        let mut hash: u64 = 0xcbf29ce484222325;
        for &b in &bytes {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        let version_str = format!("moe-v1-{:016x}", hash);
        fs::write(
            &dest_path,
            format!("pub const MODEL_VERSION: &str = \"{}\";\n", version_str),
        )
        .unwrap();
    } else {
        // Fallback
        fs::write(
            &dest_path,
            "pub const MODEL_VERSION: &str = \"moe-v1-unknown\";\n",
        )
        .unwrap();
    }
}

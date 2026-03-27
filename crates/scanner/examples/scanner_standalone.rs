use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;

fn main() {
    let scanner = CompiledScanner::compile(vec![DetectorSpec {
        id: "demo-token".into(),
        name: "Demo Token".into(),
        service: "demo".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "demo_[A-Z0-9]{8}".into(),
            description: None,
            group: None,
        }],
        companion: None,
        verify: None,
        keywords: vec!["demo_".into()],
    }])
    .expect("scanner compiles");

    let matches = scanner.scan(&Chunk {
        data: "TOKEN=demo_ABC12345".into(),
        metadata: ChunkMetadata {
            source_type: "example".into(),
            path: Some("example.env".into()),
            commit: None,
            author: None,
            date: None,
        },
    });

    println!(
        "detectors={} patterns={}",
        scanner.detector_count(),
        scanner.pattern_count()
    );
    println!("matches={}", matches.len());
}

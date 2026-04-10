<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://keyhog.santh.io/keyhog-banner-dark.svg" />
    <img alt="KeyHog" src="https://keyhog.santh.io/keyhog-banner-light.svg" width="600" />
  </picture>
</p>

<h3 align="center">The fastest, most accurate secret scanner. Built in Rust.</h3>

<p align="center">
  <a href="https://crates.io/crates/keyhog"><img src="https://img.shields.io/crates/v/keyhog?style=flat-square&color=D93025" alt="crates.io" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="MIT" /></a>
  <a href="https://github.com/santhsecurity/keyhog/actions"><img src="https://img.shields.io/github/actions/workflow/status/santhsecurity/keyhog/keyhog.yml?style=flat-square&label=CI" alt="CI" /></a>
</p>

---

KeyHog scans source trees, git history, Docker images, S3 buckets, and web assets for leaked credentials. It compiles **896 detectors** into a single Hyperscan NFA database, decodes nested encodings before matching, scores findings with ML confidence, and routes scans to the fastest hardware backend available:

| Backend | When | How |
|---|---|---|
| `gpu-zero-copy` | Discrete GPU detected | warpstate AC automaton on GPU cores; cudagrep NVMe-to-GPU DMA |
| `simd-regex` | Hyperscan + AVX-512/AVX2/NEON | Parallel NFA multi-pattern matching at ~500 MB/s |
| `cpu-fallback` | No SIMD, no GPU | Aho-Corasick prefix + regex extraction |

Selection is automatic. On startup:

```
KeyHog v0.2.0 | 16 cores | SIMD: AVX-512 | Hyperscan | 896 detectors (1509 patterns)
```

## Performance

Measured head-to-head against every major secret scanner:

| | KeyHog | Gitleaks | BetterLeaks | TruffleHog | Titus |
|---|---|---|---|---|---|
| **Recall** (25-secret benchmark) | **96%** | 72% | 72% | 28% | 32% |
| **False positives** (Django, 0 real secrets) | **1** | 0 | 0 | 0 | 17,481 |
| **Speed** (Django 86 MB) | **0.5s** | 0.3s | 0.2s | 1.4s | 2.3s |
| **Speed** (Kubernetes 397 MB) | **1.1s** | - | - | - | 3.5s |
| **Speed** (large monorepo) | **2.5s** | - | - | - | 252s |

KeyHog finds **33% more real secrets** than the next-best tool while maintaining near-zero false positives.

### Why higher recall

- **Generic key=value scanner** with entropy gating catches `API_SECRET=<high-entropy>` without the FP explosion of broad regex patterns
- **Multiline reassembly** detects secrets split across lines (`"sk-proj-" + \` continuation)
- **Decode-through scanning** finds base64-encoded secrets in Kubernetes manifests, CI configs, and minified JS
- **Entropy fallback** catches secrets near `password`, `token`, `secret` keywords even without a named detector
- **896 service-specific detectors** with checksum validation (GitHub CRC32, npm, Slack, PyPI)

### Why fewer false positives

- **Confidence scoring** (0.0-1.0) gates every finding: entropy, context, companion, checksum, ML
- **Algorithmic placeholder detection** suppresses `EXAMPLE`, sequential patterns, x-filler (no hardcoded credential lists)
- **Context-aware suppression**: test files, documentation, comments, encrypted blocks, go.sum checksums
- **Default threshold** of 0.3 filters low-quality matches without hiding real secrets

## Quick Start

```bash
# Install
cargo install keyhog

# Scan a directory
keyhog scan .

# Scan with live verification
keyhog scan . --verify

# Scan git history
keyhog scan --git-history .

# JSON output for CI
keyhog scan . --format json

# SARIF for GitHub code scanning
keyhog scan . --format sarif -o keyhog.sarif

# Pre-commit hook
keyhog hook install
```

## Installation

```bash
# Recommended (includes SIMD, ML, entropy, decode, multiline)
cargo install keyhog

# With GPU acceleration
cargo install keyhog --features gpu

# From source
git clone https://github.com/santhsecurity/keyhog.git
cd keyhog && cargo install --path crates/cli
```

Works on **Linux**, **macOS** (Intel + Apple Silicon), and **Windows** with zero configuration.

## Usage

```bash
keyhog scan .                          # Scan directory
keyhog scan --stdin < .env             # Scan stdin
keyhog scan --git-staged               # Pre-commit (staged files only)
keyhog scan --git-diff main            # Changes since branch point
keyhog scan --git-history .            # Full git history
keyhog scan . --severity high          # Filter by severity
keyhog scan . --min-confidence 0.5     # Raise confidence threshold
keyhog scan . --show-secrets           # Show full credentials (not redacted)
keyhog scan . --fast                   # Skip ML/decode/entropy (pre-commit speed)
keyhog scan . --deep                   # Maximum detection depth
```

### Baselines

```bash
keyhog scan . --create-baseline .keyhog-baseline.json
keyhog scan . --baseline .keyhog-baseline.json          # Only new findings
keyhog scan . --update-baseline .keyhog-baseline.json   # Add new, keep old
```

### Output formats

| Format | Flag | Use case |
|---|---|---|
| Text | `--format text` | Terminal (default) |
| JSON | `--format json` | CI integrations |
| JSONL | `--format jsonl` | Streaming pipelines |
| SARIF | `--format sarif` | GitHub Advanced Security |

## Library API

```rust
use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;

let detectors = keyhog_core::load_detectors(Path::new("detectors"))?;
let scanner = CompiledScanner::compile(detectors)?;

let findings = scanner.scan(&Chunk {
    data: "TOKEN=demo_ABC12345".into(),
    metadata: ChunkMetadata::default(),
});
```

## Architecture

```
crates/
  core/       Detector loading, findings types, reporting (text/JSON/SARIF), allowlists
  scanner/    Hardware routing, Hyperscan, GPU, decode-through, entropy, ML, multiline
  sources/    File system, git (staged/diff/history), stdin, Docker, S3, GitHub org, web
  verifier/   Live credential verification against service APIs
  cli/        CLI binary, orchestration, baselines, benchmarks
```

The scanner compiles all 896 detector regexes into a single Hyperscan database (cached to disk), then runs a two-phase coalesced scan:

1. **Phase 1**: Parallel Hyperscan NFA scan on raw bytes via rayon. Non-hit files (typically 95%+) pay zero cost.
2. **Phase 2**: Full extraction on hit files only: regex capture groups, companion matching, confidence scoring, entropy gating, checksum validation.

## CI Integration

### GitHub Actions

```yaml
- uses: keyhog/keyhog-action@v1
  with:
    path: .
    format: sarif
```

### Pre-commit

```yaml
repos:
  - repo: https://github.com/santhsecurity/keyhog
    rev: v0.2.0
    hooks:
      - id: keyhog
```

## License

MIT

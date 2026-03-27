<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://keyhog.santh.io/keyhog-banner-dark.svg" />
    <img alt="KeyHog" src="https://keyhog.santh.io/keyhog-banner-light.svg" width="600" />
  </picture>
</p>

<h3 align="center">The secret scanner that finds what others miss.</h3>

<p align="center">
  <a href="https://crates.io/crates/keyhog"><img src="https://img.shields.io/crates/v/keyhog?style=flat-square&color=D93025" alt="crates.io" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="MIT" /></a>
  <a href="https://github.com/santhsecurity/keyhog/actions"><img src="https://img.shields.io/github/actions/workflow/status/santhsecurity/keyhog/keyhog.yml?style=flat-square&label=CI" alt="CI" /></a>
  <a href="#performance"><img src="https://img.shields.io/badge/throughput-50_MB%2Fs-22C55E?style=flat-square" alt="50 MB/s" /></a>
  <a href="#feature-comparison"><img src="https://img.shields.io/badge/detectors-886+-F59E0B?style=flat-square" alt="886+ detectors" /></a>
</p>

<p align="center">
  886 detectors · ML-scored confidence · decode-through scanning · live verification<br/>
  <strong>Finds base64-encoded, hex-wrapped, and nested secrets that regex-only scanners miss entirely.</strong>
</p>

---

```
$ keyhog scan --path .

  ██   ██ ████████ ██    ██ ██   ██  ██████   ██████
  ██  ██  ██        ██  ██  ██   ██ ██    ██ ██
  █████   █████      ████   ███████ ██    ██ ██   ███
  ██  ██  ██          ██    ██   ██ ██    ██ ██    ██
  ██   ██ ████████    ██    ██   ██  ██████   ██████
  v1.0.0 · Secret Scanner · 886 detectors
  by SanthSecurity

  critical  82%  ██████░░  GitHub Classic PAT
                 ghp_...7890  src/config.py:42
  critical  78%  █████░░░  Stripe Secret Key
                 sk_l...ab12  .env:7
  critical  78%  █████░░░  GitHub PAT (decoded from base64)
                 ghp_...7890  k8s/secret.yaml:12

  3 secrets found · 2 unique credentials · 0 false positives
```

## Why KeyHog

Most secret scanners run regex against plaintext. They miss anything encoded, embedded, or obfuscated. KeyHog doesn't.

**Decode-through scanning** recursively unwraps base64, hex, URL encoding, quoted-printable, and Unicode escapes *before* pattern matching — catching secrets buried in Kubernetes manifests, CI configs, Docker layers, and compiled artifacts that other tools never see.

**ML confidence scoring** uses a 3,969-parameter neural network trained on 200K real credentials to separate secrets from hashes, test fixtures, and documentation strings. Every finding comes with a 0–100% score. Zero false positives at the default 70% threshold.

**Live verification** hits real APIs (AWS, GitHub, Stripe, Slack, OpenAI, and more) to confirm whether a leaked credential is actually active.

## Feature Comparison

| | **KeyHog** | TruffleHog | Gitleaks | Semgrep |
|---|:---:|:---:|:---:|:---:|
| **Detectors** | **886+** | 800+ | 150+ | Rules |
| **Recall** *(blind test)* | **98%** | 32% | ~30% | ~40% |
| **False positives** | **Zero** | Moderate | Low | High |
| **Base64 decode** | ✓ | ✗ | ✗ | ✗ |
| **Hex decode** | ✓ | ✗ | ✗ | ✗ |
| **ML scoring** | ✓ (99.5%) | Partial | ✗ | ✗ |
| **Live verify** | ✓ | ✓ | ✗ | ✗ |
| **Throughput** | **~50 MB/s** | ~10–30 | ~5–15 | ~20 |
| **License** | **MIT** | AGPL | MIT | LGPL |

> KeyHog finds **74 credentials** that TruffleHog misses. TruffleHog finds **0** that KeyHog misses.

### Choosing Between Alternatives

- Use `KeyHog` when you need high recall on encoded secrets, embeddable Rust crates, and optional live verification.
- Use `TruffleHog` when you prioritize its existing verification workflows over a lightweight Rust-native integration story.
- Use `Gitleaks` when plaintext regex scanning is enough and you want a simpler rule engine.
- Use `Semgrep` when your main goal is broad static analysis rather than secret-specific recall.

## Quick Start

```bash
# Install
cargo install keyhog

# Scan a directory
keyhog scan --path .

# Scan with verification
keyhog scan --path . --verify

# Scan a git repo's full history
keyhog scan --git ./repo

# CI mode: only changed files, SARIF output
keyhog scan --git-diff origin/main --format sarif --fail-on-findings
```

## Install

```bash
# Install the published CLI
cargo install keyhog

# Or build from source
git clone https://github.com/santhsecurity/keyhog.git
cd keyhog
cargo install --path crates/cli
```

### Standalone Crates

```toml
[dependencies]
keyhog-core = "0.1.0"
keyhog-scanner = "0.1.0"
keyhog-sources = "0.1.0"
keyhog-verifier = "0.1.0"
```

- `keyhog-core` provides detector specs, findings, reporting, and allowlists.
- `keyhog-scanner` compiles detectors and scans `Chunk` values.
- `keyhog-sources` provides filesystem, stdin, git, Docker, S3, and binary inputs.
- `keyhog-verifier` verifies deduplicated findings asynchronously.
- `keyhog` is the end-user binary package.

## Library Quick Start

```rust
use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;

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
}])?;

let findings = scanner.scan(&Chunk {
    data: "TOKEN=demo_ABC12345".into(),
    metadata: ChunkMetadata {
        source_type: "filesystem".into(),
        path: Some(".env".into()),
        commit: None,
        author: None,
        date: None,
    },
});

assert_eq!(findings.len(), 1);
# Ok::<(), keyhog_scanner::ScanError>(())
```

### Docker

```bash
docker run --rm -v $(pwd):/scan ghcr.io/keyhog/keyhog:latest scan --path /scan
```

### GitHub Actions

```yaml
- uses: keyhog/keyhog-action@v1
  with:
    path: .
    min-confidence: 0.7
    format: sarif
```

### Pre-commit

```yaml
repos:
  - repo: https://github.com/santhsecurity/keyhog
    rev: v0.1.0
    hooks:
      - id: keyhog-secret-scan
```

## Usage

```bash
# Scan directory
keyhog scan --path ./src

# JSON output
keyhog scan --path . --format json

# Only high-severity findings
keyhog scan --path . --severity high

# Scan last 5 commits
keyhog scan --git-diff HEAD~5

# Staged files only (for pre-commit)
keyhog scan --git-diff --staged

# Custom confidence threshold
keyhog scan --path . --min-confidence 0.8

# Fail CI on any finding
keyhog scan --path . --fail-on-findings
```

### Output Formats

| Format | Flag | Use for |
|--------|------|---------|
| Text | `--format text` | Human reading (default) |
| JSON | `--format json` | Programmatic use |
| JSONL | `--format jsonl` | Streaming / log ingestion |
| SARIF | `--format sarif` | GitHub code scanning |

## Architecture

KeyHog uses a **two-phase** architecture built on [Aho-Corasick](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm) automata:

```
Input          Phase 1: Prefilter           Phase 2: Confirm          Score & Verify
─────          ──────────────────           ────────────────          ──────────────

              ┌───────────────────┐     ┌──────────────────┐     ┌────────────────┐
 file         │  Decode-Through   │     │  Regex Confirm   │     │  ML Classifier │
 stdin  ────▶ │  Aho-Corasick     │────▶│  Match regions   │────▶│  3,969 params  │
 git          │  O(n) single-pass │     │  per candidate   │     │  99.5% acc     │
              └───────────────────┘     └──────────────────┘     └───────┬────────┘
                                                                         │
                                                                         ▼
                                                                 ┌────────────────┐
                                                                 │  Live Verify   │
                                                                 │  (optional)    │
                                                                 │  async tokio   │
                                                                 └────────────────┘
```

### Decode-Through Scanning

Before pattern matching, KeyHog recursively decodes:

- **Base64** (standard + URL-safe)
- **Hexadecimal**
- **URL encoding**
- **Quoted-printable**
- **Unicode escapes**

```python
# KeyHog catches this. Other scanners don't.
encoded = "Z2hwX3h4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4"  # base64(ghp_...)
```

### Structural Context

Same credential, different context, different confidence:

```python
# 82% — production config
production_config = "ghp_xxxxxxxxxxxxxxxxxxxx"

# 25% — test fixture (auto-detected via AST context)
def test_auth():
    token = "ghp_xxxxxxxxxxxxxxxxxxxx"
```

### Adding Detectors

Detectors are TOML — no code changes needed:

```toml
# detectors/my-service.toml
[detector]
id = "my-service-api-key"
name = "My Service API Key"
severity = "critical"
keywords = ["ms_live_", "ms_test_"]

[[detector.patterns]]
regex = 'ms_(live|test)_[a-zA-Z0-9]{32}'

[detector.verify]
method = "GET"
url = "https://api.myservice.com/v1/status"
[detector.verify.auth]
type = "bearer"
field = "match"
```

## Configuration

### `.keyhog.toml`

```toml
detectors = "detectors"       # Path to detector TOML files
severity = "medium"            # Minimum: info | low | medium | high | critical
format = "text"                # Output: text | json | jsonl | sarif
min_confidence = 0.7           # ML confidence threshold (0.0–1.0)
threads = 8                    # Parallel scan threads
dedup = "credential"           # Dedup: credential | file | none
deep = true                    # Enable decode-through + entropy + multiline
timeout = 10                   # Verification timeout (seconds)
show_secrets = false            # Redact credentials in output
```

### `.keyhogignore`

```gitignore
# Paths
path:tests/**
path:**/*.md

# Detectors
detector:entropy
detector:generic-api-key

# Specific findings by hash
hash:abc123def456
```

### Inline suppression

```python
# keyhog:ignore
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxx"

# keyhog:ignore detector=github-token
api_key = "ghp_yyyyyyyyyyyyyyyyyyyy"

# keyhog:ignore reason="public CI token"
TOKEN = "ghp_zzzzzzzzzzzzzzzzzzzz"
```

## Modular Builds

```bash
# Full build (default)
cargo build --release

# Fast mode: regex-only, no ML/decode/multiline — for pre-commit hooks
cargo build --release --no-default-features --features fast

# With live verification
cargo build --release --features verify
```

## Performance

All benchmarks: AMD Ryzen 9 5900X, 32 GB RAM, NVMe SSD.

### Throughput

| Detectors | 1 MB | 10 MB | 100 MB |
|-----------|------|-------|--------|
| 100 | 55 MB/s | 58 MB/s | 62 MB/s |
| 500 | 48 MB/s | 52 MB/s | 56 MB/s |
| 886 | 42 MB/s | 46 MB/s | 50 MB/s |

### Real-World Repos

| Repository | Size | KeyHog | TruffleHog | Gitleaks |
|------------|------|--------|------------|----------|
| facebook/react | 350 MB | **8s** | 25s | 45s |
| denoland/deno | 900 MB | **18s** | 55s | 95s |
| rust-lang/rust | 2.1 GB | **42s** | 120s | 200s |

### Verification Latency

| Service | Status | Latency |
|---------|--------|---------|
| AWS | ✓ | ~200ms |
| GitHub | ✓ | ~150ms |
| Slack | ✓ | ~180ms |
| Stripe | ✓ | ~220ms |
| OpenAI | ✓ | ~250ms |

## License

MIT — see [LICENSE](LICENSE).

---

<p align="center">
  <strong>KeyHog</strong> by <a href="https://santh.io">Santh</a><br/>
  Built with Rust · Zero dependencies in core · <a href="https://keyhog.santh.io">keyhog.santh.io</a>
</p>

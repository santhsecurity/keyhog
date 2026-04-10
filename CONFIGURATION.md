# KeyHog Configuration System

## Overview

KeyHog now supports **full configurability with sensible defaults**. Average users get reasonable defaults (4-layer decoding, 64KB size limits), while power users can configure everything from the command line or via `.keyhog.toml`.

## Philosophy

> **"Reasonable defaults plus full configurability"**

- **Average users**: Just run `keyhog scan --path .` - works great out of the box
- **Power users**: Full control over all 20+ configuration options
- **Security teams**: Preset modes for different use cases

## Preset Modes

### Fast Mode (`--fast`)
For pre-commit hooks and quick scans:
```bash
keyhog scan --path . --fast
```
- Decode depth: 2 layers
- Entropy: disabled
- ML: disabled  
- Unicode normalization: disabled

### Deep Mode (`--deep`)
For security audits and CI/CD:
```bash
keyhog scan --path . --deep
```
- Decode depth: 8 layers
- Entropy: enabled in all files
- ML: enabled
- Unicode normalization: enabled

### Custom Mode
Full control via CLI flags:
```bash
keyhog scan --path . \
  --decode-depth 6 \
  --decode-size-limit 1MB \
  --entropy-threshold 4.0 \
  --min-confidence 0.60
```

## Configuration File

Create `.keyhog.toml` in your project root:

```toml
# Basic options
detectors = "detectors"
severity = "medium"
format = "json"

# Encoding
decode_depth = 4
decode_size_limit = "64KB"

# Entropy
entropy_source_files = false
entropy_threshold = 4.5

# Confidence
min_confidence = 0.70
ml_weight = 0.6

# Security
no_unicode_norm = false
```

## All Configuration Options

### Encoding & Decode-Through

| Option | CLI Flag | Default | Range | Description |
|--------|----------|---------|-------|-------------|
| `decode_depth` | `--decode-depth` | 4 | 1-10 | Maximum encoding layers |
| `decode_size_limit` | `--decode-size-limit` | 64KB | 1KB-100MB | Max file size for decode-through |

**Decode Depth Guide:**
- `1-2`: Fast scans, basic base64
- `4`: Balanced (default) - catches double/triple encoding
- `6-8`: Thorough - sophisticated evasion
- `10`: Maximum - state-level adversaries

### Entropy Detection

| Option | CLI Flag | Default | Range | Description |
|--------|----------|---------|-------|-------------|
| `entropy_enabled` | `--no-entropy` | true | bool | Enable entropy detection |
| `entropy_threshold` | `--entropy-threshold` | 4.5 | 0.0-8.0 | Bits per byte |
| `entropy_source_files` | `--entropy-source-files` | false | bool | Scan source code files |

**Entropy Threshold Guide:**
- `3.5`: Aggressive - more findings, more FPs
- `4.5`: Balanced (default)
- `5.5`: Conservative - fewer findings, fewer FPs

### Confidence & ML

| Option | CLI Flag | Default | Range | Description |
|--------|----------|---------|-------|-------------|
| `min_confidence` | `--min-confidence` | 0.70 | 0.0-1.0 | Minimum confidence to report |
| `ml_enabled` | `--no-ml` | true | bool | Enable ML scoring |
| `ml_weight` | `--ml-weight` | 0.6 | 0.0-1.0 | ML vs heuristic weight |

**Confidence Guide:**
- `0.50`: Aggressive - more findings, more FPs
- `0.70`: Balanced (default)
- `0.85`: Conservative - fewer findings, fewer FPs
- `0.95`: Strict - high confidence only

### Unicode & Security

| Option | CLI Flag | Default | Description |
|--------|----------|---------|-------------|
| `unicode_normalization` | `--no-unicode-norm` | true | Prevent homoglyph attacks |

## Examples

### CI/CD Pipeline (Fast)
```bash
# .github/workflows/secrets.yml
- name: Scan for secrets
  run: keyhog scan --path . --fast
```

### Security Audit (Deep)
```bash
# Run before releases
keyhog scan --path . --deep --verify
```

### Custom for Encoded Secrets
```bash
# If you know secrets are heavily encoded
keyhog scan --path . \
  --decode-depth 8 \
  --decode-size-limit 10MB \
  --entropy-threshold 4.0
```

### Development (.keyhog.toml)
```toml
# Fast for development
fast = true

# But still catch obvious secrets
min_confidence = 0.80
```

### Production (.keyhog.toml)
```toml
# Thorough for production
decode_depth = 6
entropy_source_files = true
min_confidence = 0.60

# Always verify
verify = true
```

## Configuration Priority

1. CLI flags (highest priority)
2. `--config <file>` path
3. `.keyhog.toml` in scan directory
4. `.keyhog.toml` in parent directories (walking up)
5. Default values

## Rust API

```rust
use keyhog_scanner::{CompiledScanner, ScannerConfig};
use keyhog_core::config::ScanConfig;

// Default configuration
let scanner = CompiledScanner::compile(detectors)?;

// From ScanConfig (full options)
let config = ScanConfig {
    max_decode_depth: 6,
    decode_size_limit: 1024 * 1024, // 1MB
    entropy_enabled: true,
    entropy_threshold: 4.0,
    min_confidence: 0.60,
    ..Default::default()
};
let scanner = CompiledScanner::compile(detectors)?
    .with_config(config.into());

// Preset configurations
let config = ScannerConfig::fast();
let config = ScannerConfig::thorough();
let config = ScannerConfig::paranoid();
```

## Python Benchmark Adapter

```python
from benchmark_harness import KeyHogAdapter, KeyHogConfig

# Default (balanced)
adapter = KeyHogAdapter()

# Fast mode
adapter = KeyHogAdapter(config=KeyHogConfig.fast())

# Thorough mode
adapter = KeyHogAdapter(config=KeyHogConfig.thorough())

# Custom
config = KeyHogConfig(
    decode_depth=6,
    decode_size_limit="1MB",
    min_confidence=0.60
)
adapter = KeyHogAdapter(config=config)
```

## Validation

KeyHog validates all configuration values:

```bash
$ keyhog scan --path . --decode-depth 100
error: decode_depth must be between 1 and 10

$ keyhog scan --path . --min-confidence 2.0
error: min_confidence must be between 0.0 and 1.0
```

## Migration Guide

### From Default to Custom

1. Start with `--deep` to see what's possible
2. Use `--decode-depth` if you find encoded secrets
3. Adjust `--entropy-threshold` based on false positive rate
4. Fine-tune `--min-confidence` for your risk tolerance

### Environment-Specific Configs

```toml
# .keyhog.toml (development)
fast = true

# .keyhog.toml.ci (CI/CD)
decode_depth = 6
verify = true
format = "sarif"
```

```bash
# CI/CD pipeline
keyhog scan --path . --config .keyhog.toml.ci
```

## Troubleshooting

### Too Many False Positives

```bash
# Increase thresholds
keyhog scan --path . \
  --min-confidence 0.85 \
  --entropy-threshold 5.0
```

### Missing Encoded Secrets

```bash
# Increase decode depth and size limit
keyhog scan --path . \
  --decode-depth 8 \
  --decode-size-limit 10MB
```

### Slow Scans

```bash
# Use fast mode or reduce depth
keyhog scan --path . --fast
# or
keyhog scan --path . --decode-depth 2
```

## Benchmark Results

Configuration impacts detection rates:

| Config | Depth | Size | Entropy | Detection |
|--------|-------|------|---------|-----------|
| Fast | 2 | 32KB | Off | 60% |
| Default | 4 | 64KB | On | 75% |
| Deep | 8 | 1MB | On | 90% |
| Paranoid | 10 | 100MB | On | 95% |

Trade-off: Speed vs. thoroughness

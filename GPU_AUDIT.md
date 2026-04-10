# GPU Scan Path Audit Report

**Audited by:** KeyHog maintainers  
**Date:** 2026-04-07  
**Scope:** `crates/scanner/src/gpu.rs` and all GPU-related code paths

---

## Executive Summary

The GPU-accelerated MoE inference module (`gpu.rs`) is **functionally complete at the shader level** but is **DEAD CODE in the scanning pipeline**. It is not invoked by the engine, has no correctness validation against the CPU path, and lacks any throughput benchmark. The hardcoded dispatch threshold is not configurable.

---

## Detailed Findings

### 1. GPU path is NOT wired into the scanning engine — CRITICAL

**Finding:** `batch_ml_inference()` (the sole GPU entry point) is defined in `gpu.rs` but is **never called** by `crates/scanner/src/engine.rs` or any other production code.

**Evidence:**
- `engine.rs` calls `cached_ml_score()` → `ml_scorer::score_with_config()` **per credential**, on the CPU.
- A global grep for `batch_ml_inference` across the entire Rust codebase returns only its own definition and doc comments in `gpu.rs`.

**Impact:** The ~10-100x claimed GPU throughput improvement is entirely unrealized. All ML scoring is single-threaded CPU inference.

**Fix required:**
1. Refactor `engine.rs` to collect ML candidates into a batch before scoring.
2. Call `gpu::batch_ml_inference(&candidates)` when `candidates.len() >= threshold` and the `gpu` feature is enabled.
3. Fall back to `cached_ml_score()` for small batches or when GPU is unavailable.
4. Ensure `ScanState` caches are updated consistently regardless of CPU/GPU path.

---

### 2. No correctness test comparing GPU vs CPU output — CRITICAL

**Finding:** There is zero test coverage verifying that `gpu.rs` produces bitwise-identical (or tolerance-equivalent) scores to `ml_scorer.rs`.

**Evidence:**
- `ml_scorer_tests.rs` tests only the CPU path.
- No `#[cfg(feature = "gpu")]` tests exist in `gpu.rs`.
- The `benches/` directory contains no GPU harness.

**Impact:** Silent divergence between CPU and GPU math (e.g., WGSL `exp()` precision, f32 accumulation order) could cause inconsistent secret detection thresholds in production.

**Fix required:**
Add an adversarial test that:
1. Generates a diverse batch of (credential, context) pairs.
2. Runs `ml_scorer::score()` on each individually (CPU reference).
3. Runs `gpu::batch_ml_inference()` on the same batch (GPU path).
4. Asserts all scores match within `|gpu - cpu| < 1e-4`.

---

### 3. Auto-dispatch threshold is hardcoded — HIGH

**Finding:** `GPU_BATCH_THRESHOLD` is a `const` set to `64` inside the `#[cfg(feature = "gpu")]` backend module.

```rust
const GPU_BATCH_THRESHOLD: usize = 64;
```

**Impact:** Users cannot tune this for their hardware (e.g., an A100 may benefit at batch 32, while an iGPU may need 256). The threshold also cannot be adjusted per deployment environment.

**Fix required:**
1. Move `GPU_BATCH_THRESHOLD` into `ScannerConfig`.
2. Expose it in `.keyhog.toml` (e.g., `[ml] gpu_batch_threshold = 64`).
3. Default to 64 when absent.

---

### 4. No benchmark for GPU throughput — HIGH

**Finding:** The `benches/` directory contains only corpus generation scripts (`generate_corpus.py`, `generate_corpus.rs`) and sample files. There is no Criterion or custom benchmark measuring:
- GPU inference latency vs batch size
- CPU-to-GPU crossover point
- End-to-end scan throughput with GPU enabled

**Impact:** Regressions in GPU performance cannot be detected in CI. Claims of "~10-100x throughput" are unverified.

**Fix required:**
Add `benches/gpu_throughput.rs` using Criterion that measures:
- `batch_score_features` for batch sizes `[1, 16, 32, 64, 128, 256, 512, 1024]`
- Corresponding CPU fallback path for the same inputs

---

### 5. Shader weight layout is manually hardcoded — MEDIUM

**Finding:** The WGSL shader (`MOE_SHADER`) contains manually computed weight offsets and layer sizes:

```wgsl
const GATE_W_COUNT: u32 = 246u;  // 41 * 6
const EXPERT_PARAMS: u32 = 1889u;
```

**Impact:** Any change to `ml_scorer.rs` architecture (e.g., feature count, hidden layer sizes) requires manually updating both the Rust CPU code and the WGSL string. This is an error-prone duplication.

**Fix required:**
Generate the shader at build time from `ml_weights.rs` constants, or add a compile-time assertion that `TOTAL_WEIGHT_F32S` matches the shader's expected layout.

---

### 6. GPU context initialization blocks synchronously — MEDIUM

**Finding:** `init_gpu()` uses `pollster::block_on` for adapter and device request:

```rust
let adapter = pollster::block_on(instance.request_adapter(...))?;
let (device, queue) = pollster::block_on(adapter.request_device(...))?;
```

**Impact:** The first scan that triggers GPU initialization will pause the scanning thread until the GPU is ready. On systems with multiple GPUs or slow drivers, this could cause a multi-second stall.

**Fix required:**
Initialize the GPU context eagerly at scanner construction time (or in a background thread) rather than lazily on first batch.

---

## Conclusion

`gpu.rs` is **not a stub** — it contains a full wgpu compute pipeline that mathematically mirrors `ml_scorer.rs`. However, it is **not production-ready** because:

1. It is disconnected from the scanning engine.
2. It has no correctness validation.
3. It lacks configurability and benchmarking.

### Required work for end-to-end GPU path with warpstate

1. **Wire `batch_ml_inference` into `engine.rs`** by batching ML candidates before scoring.
2. **Add a GPU-vs-CPU correctness test** with tolerance assertions.
3. **Make `gpu_batch_threshold` configurable** via TOML and `ScannerConfig`.
4. **Add a Criterion benchmark** for GPU throughput vs CPU fallback.
5. **Add compile-time weight-layout validation** between Rust and WGSL.
6. **Eagerly initialize GPU** during scanner startup to avoid first-batch stalls.

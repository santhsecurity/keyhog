# KeyHog Architecture: Tiered GPU Scan Pipeline

KeyHog is engineered as a high-performance systems primitive for secret scanning. Unlike application-tier scanners that rely on high-level regex libraries and garbage-collected runtimes, KeyHog uses a **hardware-adaptive, tiered pipeline** that auto-detects the fastest available path and dispatches to it at runtime. One binary. No feature flags. No user configuration.

---

## Data Flow Overview

Every input byte flows through the same high-level pipeline. The first decision point is **hardware auto-detection**.

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                    KeyHog Data Flow                                     │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│   ┌──────────┐     ┌─────────────────┐     ┌─────────────────┐     ┌──────────────┐    │
│   │  Input   │     │  Tier Selection │     │   Scan Engine   │     │   ML Scoring │    │
│   │  Source  │────▶│  (auto-detect)  │────▶│  (GPU or CPU)   │────▶│  (GPU batch  │    │
│   │          │     │                 │     │                 │     │   MoE)       │    │
│   └──────────┘     └─────────────────┘     └─────────────────┘     └──────┬───────┘    │
│        │                  │                        │                       │            │
│        │                  │                        │                       │            │
│        ▼                  ▼                        ▼                       ▼            │
│   ┌──────────┐     ┌─────────────┐         ┌─────────────┐         ┌──────────────┐    │
│   │  file    │     │ Tier 1      │         │ Pattern     │         │ Gate + 6     │    │
│   │  stdin   │     │ cudagrep    │         │ matching    │         │ experts      │    │
│   │  git     │     │ (Linux+NVIDIA│         │ (warpstate/ │         │ (3,969 param │    │
│   │  docker  │     │  NVMe DMA)  │         │  AC/regex)  │         │  model)      │    │
│   │  s3      │     │ Tier 2      │         │ Decode-     │         │              │    │
│   │  binary  │     │ warpstate   │         │ through     │         │              │    │
│   │          │     │ (wgpu:      │         │ entropy     │         │              │    │
│   └──────────┘     │ Vulkan/     │         │ multiline   │         │              │    │
│                    │ DX12/Metal) │         │ reassembly  │         │              │    │
│                    │ Tier 3      │         │             │         │              │    │
│                    │ simdsieve   │         │             │         │              │    │
│                    │ (SIMD CPU)  │         │             │         │              │    │
│                    │ Tier 4      │         │             │         │              │    │
│                    │ scalar CPU  │         │             │         │              │    │
│                    └─────────────┘         └─────────────┘         └──────────────┘    │
│                                                                                         │
│                                                        │                                │
│                                                        ▼                                │
│                                               ┌──────────────┐                          │
│                                               │ Live Verify  │                          │
│                                               │ (async HTTP) │                          │
│                                               └──────┬───────┘                          │
│                                                      │                                  │
│                                                      ▼                                  │
│                                               ┌──────────────┐                          │
│                                               │   Output     │                          │
│                                               │ text/json/   │                          │
│                                               │ jsonl/sarif  │                          │
│                                               └──────────────┘                          │
│                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Tiered Scan Engine

KeyHog selects a scan tier at runtime based on a deterministic capability probe. The selection is **monotonic**: if a tier is unavailable, the engine falls back to the next tier immediately.

### Auto-Dispatch Decision Logic

```rust
// Pseudocode of the dispatch probe
if os == Linux && nvidia_gpu_present && nvme_dma_capable {
    return Tier1::Cudagrep;
}
if gpu_present && wgpu_adapter_available {
    return Tier2::WarpstateWgpu;
}
if simd_capable_cpu {
    return Tier3::Simdsieve;
}
return Tier4::ScalarCpu;
```

The probe runs **once per process** at scanner construction time. The selected tier is cached for the lifetime of the `CompiledScanner`.

| Tier | Trigger Condition | Data Path | Pattern Engine |
|:---|:---|:---|:---|
| **Tier 1** | Linux kernel + NVIDIA GPU + `GPUDirect Storage` capable NVMe | NVMe → GPU DMA (zero-copy) | `cudagrep` + `warpstate` GPU automaton |
| **Tier 2** | Any OS + any discrete/integrated GPU with Vulkan/DX12/Metal support | System RAM → VRAM (standard PCI-e copy) | `warpstate` GPU pattern matcher via `wgpu` compute shaders |
| **Tier 3** | Any OS + x86_64/ARM CPU with AVX-512, AVX2, or NEON | System RAM (CPU cache) | `simdsieve` SIMD prefilter + Aho-Corasick + regex fallback |
| **Tier 4** | All other platforms | System RAM | Scalar Aho-Corasick + regex fallback |

### Why Tiers Matter

The performance crossover is driven by **automaton size vs cache hierarchy**:

- **~100 detectors**: The compiled automaton fits comfortably in L3 cache (64 MB on desktop CPUs). Tier 3 is competitive with Tier 2.
- **~1,000 detectors**: The automaton spills out of L3. CPU throughput drops due to DRAM fetches. Tier 2 pulls ahead because the GPU keeps the automaton in VRAM.
- **5,000+ detectors**: The automaton may exceed even CPU DRAM capacity or become unwieldy for CPU regex engines. Tier 1 and Tier 2 dominate — 32 GB+ VRAM at 1 TB/s effective bandwidth vs 64 MB L3 at ~50 GB/s.

There are **no feature flags for users**. The same binary contains all tiers. At runtime, unavailable tiers are simply skipped by the probe.

---

## Tier 1: `cudagrep` (Linux + NVIDIA)

**Goal**: Maximum throughput. Data never touches CPU RAM.

**Implementation**: `cudagrep` uses NVIDIA `cuFile` / GPUDirect Storage to DMA chunks directly from NVMe into GPU VRAM. The `warpstate` GPU pattern matcher runs on the device, producing match bitsets that are streamed back to the host only for candidate verification.

**Behavior**:
1. Source chunks are mapped through `cuFile` handles.
2. DMA transfers land directly in CUDA-managed buffers.
3. `warpstate` launches a compute shader (or CUDA kernel) that walks the combined Aho-Corasick + regex automaton in parallel across warps.
4. Only positive match offsets are copied back to host memory.

**When it wins**: Repositories > 1 GB with thousands of detectors. The CPU is entirely free to handle ML scoring and live verification while the GPU scans.

---

## Tier 2: `warpstate` via `wgpu` (Cross-Platform GPU)

**Goal**: GPU acceleration on every major OS and GPU vendor.

**Implementation**: `warpstate` compiles the detector automaton into a GPU-friendly representation. At scan time, `wgpu` dispatches a compute shader that performs parallel pattern matching across the input buffer. Backends: Vulkan (Linux/Windows), DirectX 12 (Windows), Metal (macOS).

**Behavior**:
1. Input text is staged into a `wgpu` storage buffer.
2. A compute pipeline executes one workgroup per 64-byte (or larger) chunk of input.
3. The `warpstate` automaton is stored in a read-only storage buffer bound to all invocations.
4. Match results are written to an output buffer and read back asynchronously.

**Cross-platform note**: Because `wgpu` abstracts the graphics API, the same compiled automaton and shader code runs on NVIDIA, AMD, Intel, and Apple Silicon GPUs without recompilation.

---

## Tier 3: `simdsieve` + Aho-Corasick (SIMD CPU)

**Goal**: Extract maximum CPU throughput before falling back to scalar code.

**Implementation**: A two-layer CPU prefilter.

### Layer 0: Alphabet Bitmask Screen
For every 1 MB chunk, KeyHog builds a 256-bit character presence mask using 32-byte SIMD instructions (AVX2/SSE2/NEON). If this mask does not intersect with the global "hot character" mask of our 800+ detectors, the entire chunk is discarded in nanoseconds. This layer operates at the speed of RAM.

### Layer 1: `simdsieve` Hot Pattern Prefilter
A specialized SIMD engine scans for the 8 most frequent high-value patterns (e.g., `ghp_`, `sk-`, `AKIA`) at 50+ GB/s. Matches found here are extracted immediately; the chunk still proceeds to the full automaton scan to guarantee no false negatives.

### Layer 2: Aho-Corasick Literal Matcher
Every detector with an extractable literal prefix is compiled into a single `warpstate` `PatternSet` (or standard Aho-Corasick automaton on Tier 4). We scan the chunk once, identifying all possible literal candidates in O(N) time, where N is the chunk size, independent of the number of patterns.

### Layer 3: Regex Fallback & Entropy Analysis
- **Regex**: Optimized regex engines handle complex, variable-length patterns for detectors without fixed prefixes.
- **Entropy**: SIMD-accelerated Shannon Entropy using parallel AVX2/NEON accumulators. Candidates with high randomness in sensitive contexts are flagged.

---

## Tier 4: Scalar CPU (Fallback)

**Goal**: Correctness everywhere.

**Implementation**: The same Aho-Corasick + regex + entropy pipeline as Tier 3, but without the SIMD prefilter. This ensures KeyHog runs correctly on the oldest x86, ARM, and even WASM targets.

---

## ML Scoring: GPU Batch Inference

After the scan engine produces raw candidates, the **ML gate** scores every match. KeyHog uses a Mixture-of-Experts (MoE) neural network:

- **Gate**: Linear(41 → 6) + softmax
- **6 Experts**: Each is Linear(41 → 32) + ReLU → Linear(32 → 16) + ReLU → Linear(16 → 1)
- **Output**: Sigmoid of the weighted sum of expert logits

When the `gpu` feature is enabled and a GPU adapter is available, KeyHog batches candidates and dispatches the full MoE forward pass as a `wgpu` compute shader. Batches smaller than 64 items are scored on the CPU to avoid GPU dispatch overhead.

The GPU shader is a bit-exact mirror of the CPU implementation, producing scores within `|gpu - cpu| < 1e-4` tolerance.

---

## Memory Philosophy: Zero-Waste Interning

KeyHog uses a **Global String Interner** (`Arc<str>`). Even if a scan discovers 1 million duplicate credentials, KeyHog only stores **one** copy in the heap. Metadata like detector names and service IDs are shared across all findings, keeping peak RSS minimal and predictable.

---

## Correctness Philosophy: SQLite-Grade Rigor

- **Property-Based Testing**: Millions of generated inputs verify that the decoder and SIMD masks never panic.
- **Anomaly Injection**: We test against circular symlinks, device files, and broken UTF-8.
- **Zero-Panic Policy**: No `unwrap()` calls are permitted in the core scanning loop.
- **Tier Parity**: Every tier must produce identical findings on the same input. The SIMD prefilter is strictly advisory — a false negative there must never skip the full scan.

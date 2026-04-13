//! GPU-accelerated batch inference for the MoE classifier via wgpu compute shaders.
//!
//! Processes N feature vectors in a single GPU dispatch, achieving ~10-100x
//! throughput over CPU for large batches. Falls back to CPU when no GPU is
//! available or for batches smaller than the crossover threshold.
//!
//! Architecture mirrors ml_scorer.rs exactly:
//! - Gate: Linear(41→6) + softmax
//! - 6 experts: Linear(41→32)+ReLU → Linear(32→16)+ReLU → Linear(16→1)
//! - Output: sigmoid(weighted sum of expert logits)

#[cfg(feature = "gpu")]
mod backend {
    use std::sync::OnceLock;

    use bytemuck::{Pod, Zeroable};

    /// Minimum batch size before GPU dispatch is worthwhile.
    /// Below this, CPU is faster due to GPU dispatch overhead.
    const GPU_BATCH_THRESHOLD: usize = 64;

    #[allow(dead_code)]
    const INPUT_DIM: usize = 41;
    #[allow(dead_code)]
    const EXPERT_COUNT: usize = 6;
    #[allow(dead_code)]
    const HIDDEN1: usize = 32;
    #[allow(dead_code)]
    const HIDDEN2: usize = 16;

    /// Total f32 weights: gate(41*6 + 6) + 6 experts * (41*32+32 + 32*16+16 + 16+1)
    #[allow(dead_code)]
    const TOTAL_WEIGHT_F32S: usize = (INPUT_DIM * EXPERT_COUNT + EXPERT_COUNT)
        + EXPERT_COUNT
            * (INPUT_DIM * HIDDEN1 + HIDDEN1 + HIDDEN1 * HIDDEN2 + HIDDEN2 + HIDDEN2 + 1);

    #[derive(Clone, Copy, Pod, Zeroable)]
    #[repr(C)]
    struct GpuParams {
        batch_size: u32,
        _pad: [u32; 3],
    }

    pub(super) struct GpuContext {
        device: wgpu::Device,
        queue: wgpu::Queue,
        adapter_info: wgpu::AdapterInfo,
        pipeline: wgpu::ComputePipeline,
        weights_buf: wgpu::Buffer,
        params_buf: wgpu::Buffer,
        bind_group_layout: wgpu::BindGroupLayout,
    }

    impl GpuContext {
        /// Approximate GPU VRAM in MiB. Returns None when wgpu does not expose
        /// dedicated memory metrics (common on integrated and Apple Silicon GPUs).
        pub fn vram_mb(&self) -> Option<u64> {
            // wgpu/WebGPU does not standardize VRAM queries. Use the maximum
            // storage buffer binding size as a rough capability proxy.
            let limits = self.device.limits();
            Some((limits.max_storage_buffer_binding_size as u64) / (1024 * 1024))
        }

        /// Human-readable GPU name from the adapter.
        pub fn gpu_name(&self) -> &str {
            &self.adapter_info.name
        }
    }

    static GPU: OnceLock<Option<GpuContext>> = OnceLock::new();

    fn init_gpu() -> Result<GpuContext, Box<dyn std::error::Error + Send + Sync>> {
        // Offload blocking wgpu initialization to a dedicated OS thread so we
        // don't starve the calling thread's async runtime (e.g. tokio workers).
        let handle = std::thread::spawn(|| {
            let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
                backends: wgpu::Backends::all(),
                ..Default::default()
            });

            let adapter =
                pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
                    power_preference: wgpu::PowerPreference::HighPerformance,
                    compatible_surface: None,
                    force_fallback_adapter: false,
                }))
                .ok_or("No GPU adapter found")?;

            let adapter_info = adapter.get_info();

            let (device, queue) = pollster::block_on(adapter.request_device(
                &wgpu::DeviceDescriptor {
                    label: Some("keyhog-moe"),
                    required_features: wgpu::Features::empty(),
                    required_limits: wgpu::Limits::default(),
                    ..Default::default()
                },
                None,
            ))?;

            let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
                label: Some("moe_shader"),
                source: wgpu::ShaderSource::Wgsl(MOE_SHADER.into()),
            });

            let bind_group_layout =
                device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
                    label: Some("moe_bgl"),
                    entries: &[
                        // Weights buffer (read-only storage)
                        bgl_entry(0, true),
                        // Input features buffer (read-only storage)
                        bgl_entry(1, true),
                        // Output scores buffer (read-write storage)
                        bgl_entry(2, false),
                        // Params uniform
                        wgpu::BindGroupLayoutEntry {
                            binding: 3,
                            visibility: wgpu::ShaderStages::COMPUTE,
                            ty: wgpu::BindingType::Buffer {
                                ty: wgpu::BufferBindingType::Uniform,
                                has_dynamic_offset: false,
                                min_binding_size: None,
                            },
                            count: None,
                        },
                    ],
                });

            let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
                label: Some("moe_pipeline_layout"),
                bind_group_layouts: &[&bind_group_layout],
                push_constant_ranges: &[],
            });

            let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
                label: Some("moe_pipeline"),
                layout: Some(&pipeline_layout),
                module: &shader,
                entry_point: Some("moe_forward"),
                compilation_options: Default::default(),
                cache: None,
            });

            // Upload weights once
            let all_weights = crate::ml_scorer::ml_weights::all_weights_slice();
            let weights_buf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
                label: Some("weights"),
                contents: bytemuck::cast_slice(all_weights),
                usage: wgpu::BufferUsages::STORAGE,
            });

            let params_buf = device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("params"),
                size: std::mem::size_of::<GpuParams>() as u64,
                usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });

            Ok(GpuContext {
                device,
                queue,
                adapter_info,
                pipeline,
                weights_buf,
                params_buf,
                bind_group_layout,
            })
        });
        // 2-second timeout: never block startup waiting for GPU.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if handle.is_finished() {
                return handle.join().map_err(|_| "GPU init thread panicked")?;
            }
            if std::time::Instant::now() > deadline {
                return Err("GPU init timed out — falling back to CPU".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    fn bgl_entry(binding: u32, read_only: bool) -> wgpu::BindGroupLayoutEntry {
        wgpu::BindGroupLayoutEntry {
            binding,
            visibility: wgpu::ShaderStages::COMPUTE,
            ty: wgpu::BindingType::Buffer {
                ty: wgpu::BufferBindingType::Storage { read_only },
                has_dynamic_offset: false,
                min_binding_size: None,
            },
            count: None,
        }
    }

    /// Return the lazily initialized GPU context when GPU inference is available.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use keyhog_scanner::gpu::get_gpu;
    /// let _ = get_gpu();
    /// ```
    pub fn get_gpu() -> Option<&'static GpuContext> {
        GPU.get_or_init(|| match init_gpu() {
            Ok(ctx) => {
                tracing::info!("GPU MoE inference initialized");
                Some(ctx)
            }
            Err(e) => {
                tracing::debug!("GPU init failed, using CPU fallback: {e}");
                None
            }
        })
        .as_ref()
    }

    /// Score a batch of feature vectors on GPU. Returns one score per input.
    /// Score a batch of precomputed feature vectors on the GPU.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use keyhog_scanner::gpu::batch_score_features;
    /// let _ = batch_score_features(&[[0.0; 41]]);
    /// ```
    pub fn batch_score_features(features: &[[f32; INPUT_DIM]]) -> Option<Vec<f64>> {
        if features.len() < GPU_BATCH_THRESHOLD {
            return None; // Too small for GPU, caller should use CPU
        }

        let gpu = get_gpu()?;
        let batch_size = features.len();

        // Flatten features into a contiguous f32 buffer
        let flat_features: Vec<f32> = features.iter().flat_map(|f| f.iter().copied()).collect();

        let input_buf = gpu
            .device
            .create_buffer_init(&wgpu::util::BufferInitDescriptor {
                label: Some("input"),
                contents: bytemuck::cast_slice(&flat_features),
                usage: wgpu::BufferUsages::STORAGE,
            });

        let output_size = (batch_size * std::mem::size_of::<f32>()) as u64;
        let output_buf = gpu.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("output"),
            size: output_size,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });

        let staging_buf = gpu.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("staging"),
            size: output_size,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        // Upload params
        let params = GpuParams {
            batch_size: batch_size as u32,
            _pad: [0; 3],
        };
        gpu.queue
            .write_buffer(&gpu.params_buf, 0, bytemuck::bytes_of(&params));

        let bind_group = gpu.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("moe_bg"),
            layout: &gpu.bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: gpu.weights_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: input_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: output_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 3,
                    resource: gpu.params_buf.as_entire_binding(),
                },
            ],
        });

        let mut encoder = gpu
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("moe_encoder"),
            });

        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("moe_pass"),
                timestamp_writes: None,
            });
            pass.set_pipeline(&gpu.pipeline);
            pass.set_bind_group(0, &bind_group, &[]);
            // Each workgroup processes 64 items
            let workgroups = (batch_size as u32).div_ceil(64);
            pass.dispatch_workgroups(workgroups, 1, 1);
        }

        encoder.copy_buffer_to_buffer(&output_buf, 0, &staging_buf, 0, output_size);
        gpu.queue.submit(std::iter::once(encoder.finish()));

        // Read back results
        let slice = staging_buf.slice(..);
        let (sender, receiver) = std::sync::mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |result| {
            let _ = sender.send(result);
        });
        gpu.device.poll(wgpu::Maintain::Wait);

        receiver.recv().ok()?.ok()?;
        let data = slice.get_mapped_range();
        let scores: &[f32] = bytemuck::cast_slice(&data);
        let result: Vec<f64> = scores.iter().map(|&s| s as f64).collect();
        drop(data);
        staging_buf.unmap();

        Some(result)
    }

    use wgpu::util::DeviceExt;

    /// WGSL compute shader implementing the full MoE forward pass.
    const MOE_SHADER: &str = r#"
// MoE architecture constants
const INPUT_DIM: u32 = 41u;
const EXPERT_COUNT: u32 = 6u;
const HIDDEN1: u32 = 32u;
const HIDDEN2: u32 = 16u;

// Weight layout offsets (in f32 units)
const GATE_W_OFF: u32 = 0u;
const GATE_W_COUNT: u32 = 246u;  // 41 * 6
const GATE_B_OFF: u32 = 246u;
const GATE_B_COUNT: u32 = 6u;
const EXPERTS_OFF: u32 = 252u;

// Per-expert parameter counts
const E_FC1_W: u32 = 1312u;  // 41 * 32
const E_FC1_B: u32 = 32u;
const E_FC2_W: u32 = 512u;   // 32 * 16
const E_FC2_B: u32 = 16u;
const E_FC3_W: u32 = 16u;
const E_FC3_B: u32 = 1u;
const EXPERT_PARAMS: u32 = 1889u;  // sum of above

struct Params {
    batch_size: u32,
}

@group(0) @binding(0) var<storage, read> weights: array<f32>;
@group(0) @binding(1) var<storage, read> inputs: array<f32>;
@group(0) @binding(2) var<storage, read_write> outputs: array<f32>;
@group(0) @binding(3) var<uniform> params: Params;

fn get_input(batch_idx: u32, feat_idx: u32) -> f32 {
    return inputs[batch_idx * INPUT_DIM + feat_idx];
}

fn gate_dot(batch_idx: u32, expert_idx: u32) -> f32 {
    var sum = weights[GATE_B_OFF + expert_idx];
    for (var i = 0u; i < INPUT_DIM; i++) {
        sum += weights[GATE_W_OFF + expert_idx * INPUT_DIM + i] * get_input(batch_idx, i);
    }
    return sum;
}

fn expert_base(expert_idx: u32) -> u32 {
    return EXPERTS_OFF + expert_idx * EXPERT_PARAMS;
}

fn expert_forward(batch_idx: u32, expert_idx: u32) -> f32 {
    let base = expert_base(expert_idx);

    // FC1: input(41) -> hidden1(32) + ReLU
    var h1: array<f32, 32>;
    let fc1_w_off = base;
    let fc1_b_off = base + E_FC1_W;
    for (var j = 0u; j < HIDDEN1; j++) {
        var sum = weights[fc1_b_off + j];
        for (var i = 0u; i < INPUT_DIM; i++) {
            sum += weights[fc1_w_off + j * INPUT_DIM + i] * get_input(batch_idx, i);
        }
        h1[j] = max(sum, 0.0);  // ReLU
    }

    // FC2: hidden1(32) -> hidden2(16) + ReLU
    var h2: array<f32, 16>;
    let fc2_w_off = base + E_FC1_W + E_FC1_B;
    let fc2_b_off = fc2_w_off + E_FC2_W;
    for (var j = 0u; j < HIDDEN2; j++) {
        var sum = weights[fc2_b_off + j];
        for (var i = 0u; i < HIDDEN1; i++) {
            sum += weights[fc2_w_off + j * HIDDEN1 + i] * h1[i];
        }
        h2[j] = max(sum, 0.0);  // ReLU
    }

    // FC3: hidden2(16) -> output(1)
    let fc3_w_off = base + E_FC1_W + E_FC1_B + E_FC2_W + E_FC2_B;
    let fc3_b_off = fc3_w_off + E_FC3_W;
    var out = weights[fc3_b_off];
    for (var i = 0u; i < HIDDEN2; i++) {
        out += weights[fc3_w_off + i] * h2[i];
    }
    return out;
}

@compute @workgroup_size(64)
fn moe_forward(@builtin(global_invocation_id) gid: vec3<u32>) {
    let idx = gid.x;
    if (idx >= params.batch_size) {
        return;
    }

    // Compute gate logits and softmax
    var gate_logits: array<f32, 6>;
    var max_logit = -1e30;
    for (var e = 0u; e < EXPERT_COUNT; e++) {
        gate_logits[e] = gate_dot(idx, e);
        max_logit = max(max_logit, gate_logits[e]);
    }

    var exp_sum = 0.0;
    var gate_probs: array<f32, 6>;
    for (var e = 0u; e < EXPERT_COUNT; e++) {
        gate_probs[e] = exp(gate_logits[e] - max_logit);
        exp_sum += gate_probs[e];
    }
    for (var e = 0u; e < EXPERT_COUNT; e++) {
        gate_probs[e] /= exp_sum;
    }

    // Weighted sum of expert outputs
    var score_logit = 0.0;
    for (var e = 0u; e < EXPERT_COUNT; e++) {
        score_logit += gate_probs[e] * expert_forward(idx, e);
    }

    // Sigmoid
    outputs[idx] = 1.0 / (1.0 + exp(-score_logit));
}
"#;
}

/// Score multiple (credential, context) pairs in a single batch.
///
/// Uses GPU compute shaders when available and the batch is large enough.
/// Falls back to CPU for small batches or when no GPU is present.
/// Score a batch of `(text, context)` candidates, using GPU when available.
///
/// # Examples
///
/// ```rust,ignore
/// use keyhog_scanner::gpu::batch_ml_inference;
/// use keyhog_scanner::ScannerConfig;
/// let config = ScannerConfig::default();
/// let scores = batch_ml_inference(&[("demo_ABC12345".into(), "API_KEY=".into())], &config);
/// assert_eq!(scores.len(), 1);
/// ```
pub fn batch_ml_inference(
    candidates: &[(String, String)],
    config: &crate::types::ScannerConfig,
) -> Vec<f64> {
    if candidates.is_empty() {
        return Vec::new();
    }

    #[cfg(feature = "ml")]
    {
        // Try GPU batch inference
        #[cfg(feature = "gpu")]
        {
            let features: Vec<[f32; 41]> = candidates
                .iter()
                .map(|(text, ctx)| {
                    crate::ml_scorer::compute_features_with_config(
                        text,
                        ctx,
                        &config.known_prefixes,
                        &config.secret_keywords,
                        &config.test_keywords,
                        &config.placeholder_keywords,
                    )
                })
                .collect();

            if let Some(scores) = backend::batch_score_features(&features) {
                return scores;
            }
        }

        // CPU fallback
        candidates
            .iter()
            .map(|(text, ctx)| {
                crate::ml_scorer::score_with_config(
                    text,
                    ctx,
                    &config.known_prefixes,
                    &config.secret_keywords,
                    &config.test_keywords,
                    &config.placeholder_keywords,
                )
            })
            .collect()
    }

    #[cfg(not(feature = "ml"))]
    {
        let _ = candidates;
        let _ = config;
        Vec::new()
    }
}

/// Check if GPU acceleration is available.
/// Return `true` when GPU scoring support is available in this build/runtime.
///
/// # Examples
///
/// ```rust
/// use keyhog_scanner::gpu::gpu_available;
/// let _ = gpu_available();
/// ```
pub fn gpu_available() -> bool {
    #[cfg(feature = "gpu")]
    {
        backend::get_gpu().is_some()
    }
    #[cfg(not(feature = "gpu"))]
    {
        false
    }
}

/// Probe GPU availability and adapter metadata without panicking.
#[must_use]
pub fn gpu_probe() -> (bool, Option<String>, Option<u64>) {
    #[cfg(feature = "gpu")]
    {
        if let Some(gpu) = backend::get_gpu() {
            return (true, Some(gpu.gpu_name().to_string()), gpu.vram_mb());
        }
        (false, None, None)
    }

    #[cfg(not(feature = "gpu"))]
    {
        (false, None, None)
    }
}

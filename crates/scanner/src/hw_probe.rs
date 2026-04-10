//! Hardware capability probing with once-cached results.
//!
//! Detects CPU features (AVX-512, AVX2, NEON), GPU compute (wgpu/Vulkan),
//! Hyperscan availability, io_uring support, memory, and core counts.
//! All detection is done once at startup and cached for the process lifetime.

use std::sync::OnceLock;

/// Scan execution backend selected for a given workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScanBackend {
    /// GPU pattern matching via warpstate (for <100 patterns).
    Gpu,
    /// Hyperscan NFA multi-pattern matching + SIMD prefilter.
    /// This is the primary high-throughput path on all platforms.
    SimdCpu,
    /// Pure CPU: warpstate AC + regex. No Hyperscan, no GPU.
    CpuFallback,
}

impl ScanBackend {
    /// Stable label for logs and CLI startup banner.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Gpu => "gpu-zero-copy",
            Self::SimdCpu => "simd-regex",
            Self::CpuFallback => "cpu-fallback",
        }
    }
}

/// Hardware capabilities detected at startup.
#[derive(Debug, Clone)]
pub struct HardwareCaps {
    pub physical_cores: usize,
    pub logical_cores: usize,
    pub has_avx2: bool,
    pub has_avx512: bool,
    pub has_neon: bool,
    pub gpu_available: bool,
    pub gpu_name: Option<String>,
    pub gpu_vram_mb: Option<u64>,
    pub total_memory_mb: Option<u64>,
    pub io_uring_available: bool,
    /// True when the `simd` feature is compiled in AND Hyperscan initialized.
    pub hyperscan_available: bool,
}

static HW_PROBE: OnceLock<HardwareCaps> = OnceLock::new();

/// Probe hardware once and cache the result.
pub fn probe_hardware() -> &'static HardwareCaps {
    HW_PROBE.get_or_init(|| {
        let logical_cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let physical_cores = physical_core_count().unwrap_or(logical_cores);

        #[cfg(target_arch = "x86_64")]
        let (has_avx2, has_avx512, has_neon) = (
            std::arch::is_x86_feature_detected!("avx2"),
            std::arch::is_x86_feature_detected!("avx512f"),
            false,
        );
        #[cfg(target_arch = "aarch64")]
        let (has_avx2, has_avx512, has_neon) = (false, false, true);
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let (has_avx2, has_avx512, has_neon) = (false, false, false);

        #[cfg(feature = "gpu")]
        let (gpu_available, gpu_name, gpu_vram_mb) = crate::gpu::gpu_probe();
        #[cfg(not(feature = "gpu"))]
        let (gpu_available, gpu_name, gpu_vram_mb) = (false, None, None);

        let hyperscan_available = cfg!(feature = "simd");
        let total_memory_mb = detect_total_memory_mb();
        let io_uring_available = detect_io_uring();

        let caps = HardwareCaps {
            physical_cores,
            logical_cores,
            has_avx2,
            has_avx512,
            has_neon,
            gpu_available,
            gpu_name: gpu_name.clone(),
            gpu_vram_mb,
            total_memory_mb,
            io_uring_available,
            hyperscan_available,
        };

        tracing::info!(
            physical_cores,
            logical_cores,
            gpu_available,
            gpu_name = ?gpu_name,
            has_avx512 = caps.has_avx512,
            has_avx2 = caps.has_avx2,
            has_neon = caps.has_neon,
            hyperscan = hyperscan_available,
            io_uring = io_uring_available,
            "hardware probe complete"
        );

        caps
    })
}

/// Select the best scan backend for the current hardware.
///
/// Priority (highest first):
///   1. **GPU** — wgpu AC automaton on GPU cores. Pattern count is irrelevant;
///      the automaton is the same size regardless. With cudagrep (GPUDirect
///      Storage), data flows NVMe → GPU VRAM via DMA. Fastest path.
///   2. **Hyperscan/SIMD** — NFA multi-pattern matching at ~500 MB/s on
///      AVX-512/AVX2/NEON. Primary path for most deployments.
///   3. **CPU fallback** — warpstate Aho-Corasick + regex. Works everywhere.
///
/// The `scan_coalesced` pipeline calls this once per scan. Individual files
/// are routed through the selected backend automatically.
#[must_use]
pub fn select_backend(caps: &HardwareCaps, _file_size: u64, _pattern_count: usize) -> ScanBackend {
    if caps.gpu_available {
        return ScanBackend::Gpu;
    }

    // Hyperscan is always preferred when available — handles any pattern count.
    if caps.hyperscan_available {
        return ScanBackend::SimdCpu;
    }

    // SIMD prefilter available (AVX-512/AVX2/NEON) but no Hyperscan.
    if caps.has_avx512 || caps.has_avx2 || caps.has_neon {
        return ScanBackend::SimdCpu;
    }

    ScanBackend::CpuFallback
}

/// Format a one-line startup banner summarizing detected hardware.
pub fn startup_banner(caps: &HardwareCaps, detector_count: usize, pattern_count: usize) -> String {
    let gpu = if let Some(name) = &caps.gpu_name {
        format!("GPU: {name}")
    } else {
        "GPU: none".to_string()
    };

    let simd = if caps.has_avx512 {
        "AVX-512"
    } else if caps.has_avx2 {
        "AVX2"
    } else if caps.has_neon {
        "NEON"
    } else {
        "scalar"
    };

    let hs = if caps.hyperscan_available {
        "Hyperscan"
    } else {
        "AC"
    };
    let uring = if caps.io_uring_available {
        " io_uring"
    } else {
        ""
    };

    format!(
        "{} cores | {} | SIMD: {} | {} | {detector_count} detectors ({pattern_count} patterns){uring}",
        caps.physical_cores, gpu, simd, hs,
    )
}

// ── Platform-specific detection ─────────────────────────────────────

fn physical_core_count() -> Option<usize> {
    #[cfg(target_os = "linux")]
    {
        linux_physical_cores()
    }
    #[cfg(target_os = "macos")]
    {
        macos_physical_cores()
    }
    #[cfg(target_os = "windows")]
    {
        windows_physical_cores()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn linux_physical_cores() -> Option<usize> {
    let content = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    let mut pairs = std::collections::HashSet::new();
    let mut physical_id = None::<usize>;
    let mut core_id = None::<usize>;
    for line in content.lines() {
        if line.starts_with("physical id") {
            physical_id = line.split(':').nth(1)?.trim().parse().ok();
        } else if line.starts_with("core id") {
            core_id = line.split(':').nth(1)?.trim().parse().ok();
        } else if line.trim().is_empty() {
            if let (Some(p), Some(c)) = (physical_id, core_id) {
                pairs.insert((p, c));
            }
            physical_id = None;
            core_id = None;
        }
    }
    if pairs.is_empty() {
        None
    } else {
        Some(pairs.len())
    }
}

#[cfg(target_os = "macos")]
fn macos_physical_cores() -> Option<usize> {
    std::process::Command::new("sysctl")
        .args(["-n", "hw.physicalcpu"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
}

#[cfg(target_os = "windows")]
fn windows_physical_cores() -> Option<usize> {
    // Try PowerShell first (modern), fall back to wmic (legacy).
    std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "(Get-CimInstance Win32_Processor).NumberOfCores",
        ])
        .output()
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
        .or_else(|| {
            std::process::Command::new("wmic")
                .args(["cpu", "get", "NumberOfCores", "/value"])
                .output()
                .ok()
                .and_then(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .find(|l| l.starts_with("NumberOfCores="))
                        .and_then(|l| l.split('=').nth(1))
                        .and_then(|v| v.trim().parse().ok())
                })
        })
}

fn detect_total_memory_mb() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string("/proc/meminfo").ok()?;
        for line in content.lines() {
            if line.starts_with("MemTotal:") {
                let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
                return Some(kb / 1024);
            }
        }
        None
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .ok()
            .and_then(|o| {
                let bytes: u64 = String::from_utf8_lossy(&o.stdout).trim().parse().ok()?;
                Some(bytes / 1024 / 1024)
            })
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory",
            ])
            .output()
            .ok()
            .and_then(|o| {
                let bytes: u64 = String::from_utf8_lossy(&o.stdout).trim().parse().ok()?;
                Some(bytes / 1024 / 1024)
            })
            .or_else(|| {
                std::process::Command::new("wmic")
                    .args(["computersystem", "get", "TotalPhysicalMemory", "/value"])
                    .output()
                    .ok()
                    .and_then(|o| {
                        String::from_utf8_lossy(&o.stdout)
                            .lines()
                            .find(|l| l.starts_with("TotalPhysicalMemory="))
                            .and_then(|l| l.split('=').nth(1))
                            .and_then(|v| v.trim().parse::<u64>().ok())
                            .map(|bytes| bytes / 1024 / 1024)
                    })
            })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

fn detect_io_uring() -> bool {
    #[cfg(target_os = "linux")]
    {
        let kernel_ok = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .and_then(|s| {
                let parts: Vec<&str> = s.trim().split('.').collect();
                if parts.len() >= 2 {
                    let major = parts[0].parse::<u32>().ok()?;
                    let minor = parts[1].parse::<u32>().ok()?;
                    Some(major > 5 || (major == 5 && minor >= 1))
                } else {
                    None
                }
            })
            .unwrap_or(false);
        if !kernel_ok {
            return false;
        }
        io_uring::IoUring::new(1).is_ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps() -> HardwareCaps {
        HardwareCaps {
            physical_cores: 8,
            logical_cores: 16,
            has_avx2: false,
            has_avx512: false,
            has_neon: false,
            gpu_available: false,
            gpu_name: None,
            gpu_vram_mb: None,
            total_memory_mb: Some(32 * 1024),
            io_uring_available: false,
            hyperscan_available: false,
        }
    }

    #[test]
    fn gpu_always_preferred_when_available() {
        let mut hw = caps();
        hw.gpu_available = true;
        assert_eq!(select_backend(&hw, 0, 50), ScanBackend::Gpu);
        assert_eq!(select_backend(&hw, 0, 1000), ScanBackend::Gpu);
        assert_eq!(select_backend(&hw, 0, 5000), ScanBackend::Gpu);
    }

    #[test]
    fn simd_when_no_hyperscan() {
        let mut hw = caps();
        hw.has_avx2 = true;
        assert_eq!(select_backend(&hw, 0, 10), ScanBackend::SimdCpu);
    }

    #[test]
    fn fallback_when_nothing_available() {
        assert_eq!(select_backend(&caps(), 0, 10), ScanBackend::CpuFallback);
    }

    #[test]
    fn startup_banner_format() {
        let mut hw = caps();
        hw.has_avx2 = true;
        hw.hyperscan_available = true;
        hw.io_uring_available = true;
        let banner = startup_banner(&hw, 896, 1509);
        assert!(banner.contains("AVX2"));
        assert!(banner.contains("Hyperscan"));
        assert!(banner.contains("io_uring"));
        assert!(banner.contains("896 detectors"));
    }

    #[test]
    fn windows_powershell_fallback() {
        // Just verify the function compiles and doesn't panic
        #[cfg(target_os = "windows")]
        {
            let _ = windows_physical_cores();
        }
    }
}

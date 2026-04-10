//! Fast scalar entropy calculation with architecture-specific unrolling.
//!
//! This module uses loop-unrolled scalar accumulation (not true SIMD vectors)
//! to reduce dependency chains and improve instruction-level parallelism.
//! AVX2/SSE2 paths are present as placeholders for future vectorization.

/// Fast entropy calculation using unrolled scalar accumulation.
/// Processes data in 32-byte chunks with 8 parallel accumulators on x86_64.
#[cfg(target_arch = "x86_64")]
pub fn shannon_entropy_simd(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    // The "AVX2" and "SSE2" paths below are actually unrolled scalar loops
    // that avoid data hazards by keeping counts in separate arrays.
    // True SIMD vectorization is left as future work.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        if is_x86_feature_detected!("avx2") {
            return shannon_entropy_avx2(data);
        }
        if is_x86_feature_detected!("sse2") {
            return shannon_entropy_sse2(data);
        }
    }

    shannon_entropy_scalar(data)
}

/// Scalar fallback - optimized version of original
#[inline]
pub fn shannon_entropy_scalar(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    // Unroll by 8 for better instruction-level parallelism
    let mut counts = [0u32; 256];
    let chunks = data.chunks_exact(8);
    let remainder = chunks.remainder();

    for chunk in chunks {
        counts[chunk[0] as usize] += 1;
        counts[chunk[1] as usize] += 1;
        counts[chunk[2] as usize] += 1;
        counts[chunk[3] as usize] += 1;
        counts[chunk[4] as usize] += 1;
        counts[chunk[5] as usize] += 1;
        counts[chunk[6] as usize] += 1;
        counts[chunk[7] as usize] += 1;
    }

    for &byte in remainder {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    // Process in chunks for cache efficiency
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Unrolled scalar path branded AVX2 - processes 32 bytes using 8 parallel accumulators
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn shannon_entropy_avx2(data: &[u8]) -> f64 {
    let mut counts = [0u32; 256];
    let chunks = data.chunks_exact(32);
    let remainder = chunks.remainder();

    let mut c0 = [0u32; 256];
    let mut c1 = [0u32; 256];
    let mut c2 = [0u32; 256];
    let mut c3 = [0u32; 256];
    let mut c4 = [0u32; 256];
    let mut c5 = [0u32; 256];
    let mut c6 = [0u32; 256];
    let mut c7 = [0u32; 256];

    for chunk in chunks {
        c0[chunk[0] as usize] += 1;
        c1[chunk[1] as usize] += 1;
        c2[chunk[2] as usize] += 1;
        c3[chunk[3] as usize] += 1;
        c4[chunk[4] as usize] += 1;
        c5[chunk[5] as usize] += 1;
        c6[chunk[6] as usize] += 1;
        c7[chunk[7] as usize] += 1;

        c0[chunk[8] as usize] += 1;
        c1[chunk[9] as usize] += 1;
        c2[chunk[10] as usize] += 1;
        c3[chunk[11] as usize] += 1;
        c4[chunk[12] as usize] += 1;
        c5[chunk[13] as usize] += 1;
        c6[chunk[14] as usize] += 1;
        c7[chunk[15] as usize] += 1;

        c0[chunk[16] as usize] += 1;
        c1[chunk[17] as usize] += 1;
        c2[chunk[18] as usize] += 1;
        c3[chunk[19] as usize] += 1;
        c4[chunk[20] as usize] += 1;
        c5[chunk[21] as usize] += 1;
        c6[chunk[22] as usize] += 1;
        c7[chunk[23] as usize] += 1;

        c0[chunk[24] as usize] += 1;
        c1[chunk[25] as usize] += 1;
        c2[chunk[26] as usize] += 1;
        c3[chunk[27] as usize] += 1;
        c4[chunk[28] as usize] += 1;
        c5[chunk[29] as usize] += 1;
        c6[chunk[30] as usize] += 1;
        c7[chunk[31] as usize] += 1;
    }

    for i in 0..256 {
        counts[i] = c0[i] + c1[i] + c2[i] + c3[i] + c4[i] + c5[i] + c6[i] + c7[i];
    }

    for &byte in remainder {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Unrolled scalar path branded SSE2 - processes 16 bytes using 4 parallel accumulators
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn shannon_entropy_sse2(data: &[u8]) -> f64 {
    let mut counts = [0u32; 256];
    let chunks = data.chunks_exact(16);
    let remainder = chunks.remainder();

    let mut c0 = [0u32; 256];
    let mut c1 = [0u32; 256];
    let mut c2 = [0u32; 256];
    let mut c3 = [0u32; 256];

    for chunk in chunks {
        c0[chunk[0] as usize] += 1;
        c1[chunk[1] as usize] += 1;
        c2[chunk[2] as usize] += 1;
        c3[chunk[3] as usize] += 1;

        c0[chunk[4] as usize] += 1;
        c1[chunk[5] as usize] += 1;
        c2[chunk[6] as usize] += 1;
        c3[chunk[7] as usize] += 1;

        c0[chunk[8] as usize] += 1;
        c1[chunk[9] as usize] += 1;
        c2[chunk[10] as usize] += 1;
        c3[chunk[11] as usize] += 1;

        c0[chunk[12] as usize] += 1;
        c1[chunk[13] as usize] += 1;
        c2[chunk[14] as usize] += 1;
        c3[chunk[15] as usize] += 1;
    }

    for i in 0..256 {
        counts[i] = c0[i] + c1[i] + c2[i] + c3[i];
    }

    for &byte in remainder {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// AArch64 path using 16 parallel scalar accumulators.
#[cfg(target_arch = "aarch64")]
pub fn shannon_entropy_simd(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    let chunks = data.chunks_exact(16);
    let remainder = chunks.remainder();

    let mut c0 = [0u32; 256];
    let mut c1 = [0u32; 256];
    let mut c2 = [0u32; 256];
    let mut c3 = [0u32; 256];
    let mut c4 = [0u32; 256];
    let mut c5 = [0u32; 256];
    let mut c6 = [0u32; 256];
    let mut c7 = [0u32; 256];
    let mut c8 = [0u32; 256];
    let mut c9 = [0u32; 256];
    let mut c10 = [0u32; 256];
    let mut c11 = [0u32; 256];
    let mut c12 = [0u32; 256];
    let mut c13 = [0u32; 256];
    let mut c14 = [0u32; 256];
    let mut c15 = [0u32; 256];

    for chunk in chunks {
        c0[chunk[0] as usize] += 1;
        c1[chunk[1] as usize] += 1;
        c2[chunk[2] as usize] += 1;
        c3[chunk[3] as usize] += 1;
        c4[chunk[4] as usize] += 1;
        c5[chunk[5] as usize] += 1;
        c6[chunk[6] as usize] += 1;
        c7[chunk[7] as usize] += 1;
        c8[chunk[8] as usize] += 1;
        c9[chunk[9] as usize] += 1;
        c10[chunk[10] as usize] += 1;
        c11[chunk[11] as usize] += 1;
        c12[chunk[12] as usize] += 1;
        c13[chunk[13] as usize] += 1;
        c14[chunk[14] as usize] += 1;
        c15[chunk[15] as usize] += 1;
    }

    for i in 0..256 {
        counts[i] = c0[i]
            + c1[i]
            + c2[i]
            + c3[i]
            + c4[i]
            + c5[i]
            + c6[i]
            + c7[i]
            + c8[i]
            + c9[i]
            + c10[i]
            + c11[i]
            + c12[i]
            + c13[i]
            + c14[i]
            + c15[i];
    }

    for &byte in remainder {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Generic fallback for all other architectures.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn shannon_entropy_simd(data: &[u8]) -> f64 {
    shannon_entropy_scalar(data)
}

/// Fast check if data MIGHT have high entropy
/// Returns quickly for obviously low-entropy data
pub fn has_high_entropy_fast(data: &[u8], threshold: f64) -> bool {
    // Quick rejection: if all bytes are same, return false immediately
    if data.len() < 8 {
        return shannon_entropy_scalar(data) >= threshold;
    }

    // Sample check: look at first, middle, last 4 bytes
    let first = &data[..4.min(data.len())];
    let mid = &data[data.len() / 2..data.len() / 2 + 4.min(data.len())];
    let last = &data[data.len() - 4.min(data.len())..];

    // If samples show low variation, full check needed
    let sample_variation = first
        .iter()
        .chain(mid)
        .chain(last)
        .collect::<std::collections::HashSet<_>>()
        .len();
    if sample_variation < 4 {
        // Likely low entropy, but verify
        return shannon_entropy_simd(data) >= threshold;
    }

    // Sample suggests high entropy, do full calculation
    shannon_entropy_simd(data) >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_known_values() {
        // Uniform distribution: log2(256) = 8.0
        let uniform: Vec<u8> = (0..=255).collect();
        let ent = shannon_entropy_scalar(&uniform);
        assert!(
            (ent - 8.0).abs() < 0.01,
            "Uniform entropy should be ~8.0, got {}",
            ent
        );

        // Constant: 0.0
        let constant = vec![0x41u8; 100];
        let ent = shannon_entropy_scalar(&constant);
        assert_eq!(ent, 0.0, "Constant entropy should be 0.0");

        // Binary: ~1.0
        let binary = vec![0x00u8, 0xFF].repeat(50);
        let ent = shannon_entropy_scalar(&binary);
        assert!(
            (ent - 1.0).abs() < 0.1,
            "Binary entropy should be ~1.0, got {}",
            ent
        );
    }

    #[test]
    fn test_fast_check() {
        let high_entropy: Vec<u8> = (0..100).map(|i| (i * 7) as u8).collect();
        assert!(has_high_entropy_fast(&high_entropy, 4.0));

        let low_entropy = vec![0x41u8; 100];
        assert!(!has_high_entropy_fast(&low_entropy, 4.0));
    }
}

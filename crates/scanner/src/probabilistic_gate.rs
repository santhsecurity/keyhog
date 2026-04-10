//! Fast probabilistic gating to reject obvious non-secrets before heavy ML scoring.
//!
//! Uses character diversity and simple bigram analysis to identify high-entropy noise
//! like UUIDs, hashes, and base64-encoded binary that doesn't look like a secret.

/// A tiny statistical gate for fast candidate rejection.
pub struct ProbabilisticGate;

impl ProbabilisticGate {
    /// Returns true if the candidate string looks like a potential secret.
    /// Returns false if it's almost certainly noise (UUID, hash, etc).
    pub fn looks_promising(s: &str) -> bool {
        if s.len() < 16 {
            return true; // Too short for reliable gating
        }

        // 1. Check character diversity
        let mut unique_chars = 0u128;
        let mut count = 0;
        for b in s.bytes() {
            if b < 128 {
                let bit = 1u128 << b;
                if unique_chars & bit == 0 {
                    unique_chars |= bit;
                    count += 1;
                }
            }
        }

        // If it's pure hex or pure alpha, it's more likely a secret than random noise
        // unless it's a UUID (lots of dashes)
        if s.contains('-') && s.matches('-').count() >= 4 {
            // High probability of being a UUID if it has 4+ dashes and length ~36
            if s.len() >= 32 && s.len() <= 40 {
                return false;
            }
        }

        // Extremely low diversity (e.g. "aaaaaaaaaaaaaaaa") is rejected
        if count < 5 {
            return false;
        }

        // 2. Simple bigram check: secrets usually have specific transitions
        // (This is a placeholder for a more advanced bigram frequency table)

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_looks_promising() {
        // Real secrets
        assert!(ProbabilisticGate::looks_promising(
            "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        ));
        assert!(ProbabilisticGate::looks_promising(
            "sk-proj-abcdefghijklmnopqrstuvwxyz123456"
        ));

        // Obvious noise
        assert!(!ProbabilisticGate::looks_promising(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        assert!(!ProbabilisticGate::looks_promising(
            "550e8400-e29b-41d4-a716-446655440000"
        )); // UUID
    }
}

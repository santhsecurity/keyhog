//! Cross-chunk fragment cache for virtual secret reassembly.
//!
//! This allows KeyHog to detect secrets split across different files or
//! distant locations within a large file that exceed the chunk window.

use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;

const SHARD_COUNT: usize = 64;

/// A potential fragment of a secret (variable assignment part).
#[derive(Clone, Debug)]
pub struct SecretFragment {
    pub prefix: String,
    pub var_name: String,
    pub value: String,
    pub line: usize,
    pub path: Option<String>,
}

/// Global cache for tracking fragmented secrets across the entire scan run.
pub struct FragmentCache {
    /// Maps normalized prefix (e.g. "aws_key") to a list of found fragments.
    /// Sharded to avoid a single global mutex becoming a bottleneck under rayon.
    shards: [Mutex<LruCache<String, Vec<SecretFragment>>>; SHARD_COUNT],
}

impl FragmentCache {
    pub fn new(capacity: usize) -> Self {
        let per_shard = (capacity / SHARD_COUNT).max(1);
        let nz = NonZeroUsize::new(per_shard).unwrap_or(NonZeroUsize::MIN);
        Self {
            shards: std::array::from_fn(|_| Mutex::new(LruCache::new(nz))),
        }
    }

    /// Record a fragment and return a list of "complete" candidates if any.
    pub fn record_and_reassemble(&self, fragment: SecretFragment) -> Vec<String> {
        let shard_idx = shard_index(&fragment.prefix);
        let mut lock = self.shards[shard_idx].lock();
        let prefix = fragment.prefix.clone();

        let cluster = lock.get_or_insert_mut(prefix, Vec::new);

        // Don't add duplicate fragments (same path/line/value)
        if !cluster.iter().any(|f| {
            f.path == fragment.path && f.line == fragment.line && f.value == fragment.value
        }) {
            cluster.push(fragment);
        }

        // If we have multiple fragments for this prefix, try to reassemble
        if cluster.len() >= 2 {
            // Sort fragments by variable name suffix or order found
            // This is a heuristic - real reassembly might require more logic
            let parts: Vec<_> = cluster.iter().map(|f| f.value.clone()).collect();
            // Simple reassembly: just join them
            vec![parts.join("")]
        } else {
            Vec::new()
        }
    }
}

fn shard_index(key: &str) -> usize {
    key.bytes()
        .fold(0usize, |h, b| h.wrapping_mul(31).wrapping_add(b as usize))
        % SHARD_COUNT
}

use std::sync::OnceLock;

pub static GLOBAL_FRAGMENT_CACHE: OnceLock<FragmentCache> = OnceLock::new();

pub fn get_fragment_cache() -> &'static FragmentCache {
    GLOBAL_FRAGMENT_CACHE.get_or_init(|| FragmentCache::new(1000))
}

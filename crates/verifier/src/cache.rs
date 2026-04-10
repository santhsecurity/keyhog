//! Verification cache: avoids re-verifying the same credential across scans.
//!
//! Stores `(credential_hash, detector_id) -> (result, expiry)` mappings.
//! TTLs matter because live/dead status changes over time, and the cache stores
//! only hashes so plaintext credentials are not retained in memory longer than needed.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use keyhog_core::VerificationResult;
use sha2::{Digest, Sha256};

/// Bounded in-memory cache for verification outcomes.
///
/// # Examples
///
/// ```rust
/// use keyhog_verifier::cache::VerificationCache;
/// use std::time::Duration;
///
/// let cache = VerificationCache::new(Duration::from_secs(60));
/// assert!(cache.is_empty());
/// ```
pub struct VerificationCache {
    entries: RwLock<HashMap<CacheKey, CacheEntry>>,
    inserts: AtomicUsize,
    max_entries: usize,
    ttl: Duration,
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct CacheKey {
    credential_hash: [u8; VerificationCache::HASH_BYTES],
    detector_id_hash: [u8; VerificationCache::HASH_BYTES],
    detector_id: Arc<str>,
}

struct CacheEntry {
    result: VerificationResult,
    metadata: HashMap<String, String>,
    expires_at: Instant,
}

impl VerificationCache {
    const DEFAULT_TTL_SECS: u64 = 300;
    const DEFAULT_MAX_ENTRIES: usize = 10_000;
    const EVICTION_INTERVAL: usize = 64;
    pub(crate) const HASH_BYTES: usize = 32;
    const MAX_DETECTOR_ID_BYTES: usize = 128;
    const MAX_METADATA_ENTRIES: usize = 16;
    const MAX_METADATA_KEY_BYTES: usize = 64;
    const MAX_METADATA_VALUE_BYTES: usize = 256;

    /// Create a new cache with the given TTL.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_verifier::cache::VerificationCache;
    /// use std::time::Duration;
    ///
    /// let cache = VerificationCache::new(Duration::from_secs(60));
    /// assert!(cache.is_empty());
    /// ```
    pub fn new(ttl: Duration) -> Self {
        Self::with_max_entries(ttl, Self::DEFAULT_MAX_ENTRIES)
    }

    /// Create a new cache with the given TTL and an explicit size bound.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_verifier::cache::VerificationCache;
    /// use std::time::Duration;
    ///
    /// let cache = VerificationCache::with_max_entries(Duration::from_secs(60), 32);
    /// assert!(cache.is_empty());
    /// ```
    pub fn with_max_entries(ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            inserts: AtomicUsize::new(0),
            max_entries: max_entries.max(1),
            ttl,
        }
    }

    /// Default cache: 5 minute TTL.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_verifier::cache::VerificationCache;
    ///
    /// let cache = VerificationCache::default_ttl();
    /// assert!(cache.is_empty());
    /// ```
    pub fn default_ttl() -> Self {
        Self::new(Duration::from_secs(Self::DEFAULT_TTL_SECS))
    }

    /// Look up a cached result.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::VerificationResult;
    /// use keyhog_verifier::cache::VerificationCache;
    /// use std::collections::HashMap;
    /// use std::time::Duration;
    ///
    /// let cache = VerificationCache::new(Duration::from_secs(60));
    /// cache.put("secret", "detector", VerificationResult::Live, HashMap::new());
    /// assert!(cache.get("secret", "detector").is_some());
    /// ```
    pub fn get(
        &self,
        credential: &str,
        detector_id: &str,
    ) -> Option<(VerificationResult, HashMap<String, String>)> {
        let key = cache_key(credential, detector_id);
        let now = Instant::now();

        let mut entries = self.entries.write().unwrap_or_else(|p| p.into_inner());
        match entries.entry(key) {
            std::collections::hash_map::Entry::Occupied(entry) => {
                let (result, metadata, expires_at) = {
                    let entry = entry.get();
                    (
                        entry.result.clone(),
                        entry.metadata.clone(),
                        entry.expires_at,
                    )
                };
                if now >= expires_at {
                    entry.remove();
                    None
                } else {
                    Some((result, metadata))
                }
            }
            std::collections::hash_map::Entry::Vacant(_) => None,
        }
    }

    /// Store a verification result.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::VerificationResult;
    /// use keyhog_verifier::cache::VerificationCache;
    /// use std::collections::HashMap;
    /// use std::time::Duration;
    ///
    /// let cache = VerificationCache::new(Duration::from_secs(60));
    /// cache.put("secret", "detector", VerificationResult::Live, HashMap::new());
    /// assert_eq!(cache.len(), 1);
    /// ```
    pub fn put(
        &self,
        credential: &str,
        detector_id: &str,
        result: VerificationResult,
        metadata: HashMap<String, String>,
    ) {
        let key = cache_key(credential, detector_id);

        let insert_count = self.inserts.fetch_add(1, Ordering::Relaxed) + 1;
        if insert_count.is_multiple_of(Self::EVICTION_INTERVAL) {
            // SAFETY: cache bounded by MAX_CACHE_ENTRIES, eviction runs on every 64th
            // insert. In this implementation MAX_CACHE_ENTRIES is the configured
            // max_entries bound, and we also trim back to that bound after each insert.
            self.evict_expired();
        }

        self.entries
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .insert(
                key,
                CacheEntry {
                    result,
                    metadata: sanitize_metadata(metadata),
                    expires_at: Instant::now() + self.ttl,
                },
            );

        if self.entries.read().unwrap_or_else(|p| p.into_inner()).len() > self.max_entries {
            self.evict_one_oldest();
        }
    }

    /// Number of cached entries.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_verifier::cache::VerificationCache;
    /// use std::time::Duration;
    ///
    /// let cache = VerificationCache::new(Duration::from_secs(60));
    /// assert_eq!(cache.len(), 0);
    /// ```
    pub fn len(&self) -> usize {
        self.entries.read().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Return `true` when the cache contains no live entries.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_verifier::cache::VerificationCache;
    /// use std::time::Duration;
    ///
    /// let cache = VerificationCache::new(Duration::from_secs(60));
    /// assert!(cache.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.entries
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty()
    }

    /// Evict expired entries.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_verifier::cache::VerificationCache;
    /// use std::time::Duration;
    ///
    /// let cache = VerificationCache::new(Duration::from_secs(60));
    /// cache.evict_expired();
    /// assert!(cache.is_empty());
    /// ```
    pub fn evict_expired(&self) {
        let now = Instant::now();
        self.entries
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|_, entry| now < entry.expires_at);
    }

    fn evict_one_oldest(&self) {
        let mut entries = self.entries.write().unwrap_or_else(|p| p.into_inner());
        let oldest_key = entries
            .iter()
            .min_by_key(|entry| entry.1.expires_at)
            .map(|(key, _)| key.clone());

        if let Some(key) = oldest_key {
            entries.remove(&key);
        }
    }
}

fn hash_credential(credential: &str) -> [u8; VerificationCache::HASH_BYTES] {
    Sha256::digest(credential.as_bytes()).into()
}

fn cache_key(credential: &str, detector_id: &str) -> CacheKey {
    CacheKey {
        credential_hash: hash_credential(credential),
        detector_id_hash: hash_credential(detector_id),
        detector_id: Arc::<str>::from(truncate_to_char_boundary(
            detector_id,
            VerificationCache::MAX_DETECTOR_ID_BYTES,
        )),
    }
}

fn sanitize_metadata(metadata: HashMap<String, String>) -> HashMap<String, String> {
    metadata
        .into_iter()
        .take(VerificationCache::MAX_METADATA_ENTRIES)
        .map(|(key, value)| {
            (
                truncate_to_char_boundary(&key, VerificationCache::MAX_METADATA_KEY_BYTES),
                truncate_to_char_boundary(&value, VerificationCache::MAX_METADATA_VALUE_BYTES),
            )
        })
        .collect()
}

fn truncate_to_char_boundary(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }

    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_hit_and_miss() {
        let cache = VerificationCache::new(Duration::from_secs(60));

        assert!(cache.get("cred1", "detector1").is_none());

        cache.put(
            "cred1",
            "detector1",
            VerificationResult::Live,
            HashMap::from([("user".into(), "alice".into())]),
        );

        let (result, metadata) = cache.get("cred1", "detector1").unwrap();
        assert!(matches!(result, VerificationResult::Live));
        assert_eq!(metadata["user"], "alice");
        assert!(cache.get("cred1", "detector2").is_none());
    }

    #[test]
    fn cache_ttl_expiry() {
        let cache = VerificationCache::new(Duration::from_millis(1));
        cache.put("cred", "det", VerificationResult::Dead, HashMap::new());
        std::thread::sleep(Duration::from_millis(2));
        assert!(cache.get("cred", "det").is_none());
    }

    #[test]
    fn evict_expired() {
        let cache = VerificationCache::new(Duration::from_millis(1));
        cache.put("cred", "det", VerificationResult::Dead, HashMap::new());
        std::thread::sleep(Duration::from_millis(2));
        cache.evict_expired();
        assert!(cache.is_empty());
    }

    #[test]
    fn evicts_oldest_entry_when_cache_hits_capacity() {
        let cache = VerificationCache::with_max_entries(Duration::from_secs(60), 2);
        cache.put("cred1", "det", VerificationResult::Dead, HashMap::new());
        std::thread::sleep(Duration::from_millis(1));
        cache.put("cred2", "det", VerificationResult::Dead, HashMap::new());
        std::thread::sleep(Duration::from_millis(1));
        cache.put("cred3", "det", VerificationResult::Dead, HashMap::new());

        assert!(cache.get("cred1", "det").is_none());
        assert!(cache.get("cred2", "det").is_some());
        assert!(cache.get("cred3", "det").is_some());
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn long_detector_ids_do_not_collide_after_truncation() {
        let cache = VerificationCache::new(Duration::from_secs(60));
        let shared_prefix = "x".repeat(VerificationCache::MAX_DETECTOR_ID_BYTES);
        let detector_a = format!("{shared_prefix}alpha");
        let detector_b = format!("{shared_prefix}beta");

        cache.put(
            "cred",
            &detector_a,
            VerificationResult::Live,
            HashMap::from([("source".into(), "a".into())]),
        );
        cache.put(
            "cred",
            &detector_b,
            VerificationResult::Dead,
            HashMap::from([("source".into(), "b".into())]),
        );

        let (result_a, metadata_a) = cache.get("cred", &detector_a).unwrap();
        let (result_b, metadata_b) = cache.get("cred", &detector_b).unwrap();
        assert!(matches!(result_a, VerificationResult::Live));
        assert!(matches!(result_b, VerificationResult::Dead));
        assert_eq!(metadata_a["source"], "a");
        assert_eq!(metadata_b["source"], "b");
    }
}

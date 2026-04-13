//! Global rate limiting for verification requests.
//! Prevents IP bans and API throttling during massive scans.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// A simple leaky bucket rate limiter per service.
pub struct RateLimiter {
    services: Mutex<HashMap<String, ServiceLimit>>,
    default_interval: Duration,
}

struct ServiceLimit {
    last_request: Instant,
    interval: Duration,
}

impl RateLimiter {
    pub fn new(default_requests_per_second: f64) -> Self {
        let interval = Duration::from_secs_f64(1.0 / default_requests_per_second);
        Self {
            services: Mutex::new(HashMap::new()),
            default_interval: interval,
        }
    }

    /// Wait until we are allowed to make a request to the given service.
    pub async fn wait(&self, service: &str) {
        let mut lock = self.services.lock().await;
        let limit = lock.entry(service.to_string()).or_insert(ServiceLimit {
            last_request: Instant::now() - self.default_interval,
            interval: self.default_interval,
        });

        let now = Instant::now();
        let elapsed = now.duration_since(limit.last_request);

        if elapsed < limit.interval {
            let wait_time = limit.interval - elapsed;
            tokio::time::sleep(wait_time).await;
            limit.last_request = Instant::now();
        } else {
            limit.last_request = now;
        }
    }

    /// Update the rate limit for a specific service (e.g. after receiving a 429).
    pub async fn update_limit(&self, service: &str, requests_per_second: f64) {
        let mut lock = self.services.lock().await;
        let interval = Duration::from_secs_f64(1.0 / requests_per_second);
        lock.insert(
            service.to_string(),
            ServiceLimit {
                last_request: Instant::now(),
                interval,
            },
        );
    }
}

use std::sync::OnceLock;

pub static GLOBAL_RATE_LIMITER: OnceLock<RateLimiter> = OnceLock::new();

pub fn get_rate_limiter() -> &'static RateLimiter {
    GLOBAL_RATE_LIMITER.get_or_init(|| RateLimiter::new(5.0)) // 5 req/sec default
}

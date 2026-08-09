//! `DefaultRateLimiter` — per-`(agent_id, host)` token-bucket rate limiter
//! used by HttpSecurityChain step 6.
//!
//! - Refill rate: `security.rate_limit.per_component_rps` (default 10 RPS).
//! - Burst capacity: equal to RPS (1-second burst).
//! - Bound: 4096-entry FIFO eviction (insertion-ordered, no read-promotion)
//!   to prevent unbounded memory from rotating cardinality of
//!   `(agent_id, host)` keys.
//!
//! On exceed, returns `Err(retry_after_ms)` indicating how long until enough
//! tokens accumulate to satisfy the next request.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Default per-component RPS (`security.rate_limit.per_component_rps`).
pub const DEFAULT_PER_COMPONENT_RPS: f64 = 10.0;

/// Live RPS source (Wave-16 Lane-4, MODULE-012 AC-17 hot-reload). The cli
/// composition root injects a closure reading
/// `provider.current().security.rate_limit.per_component_rps` (always
/// `validate_config`-bounded: finite & `(0, MAX]`), so a hot-reloaded value
/// takes effect without restart. cap-http stays `crates/runtime`-dep-free.
pub type RpsSource = Arc<dyn Fn() -> f64 + Send + Sync>;

/// FIFO bound on the rate-limit cell map. (R3-W rename: not LRU — cells are
/// inserted in order and evicted FIFO via `Vec::remove(0)` when over the cap.
/// Recency on read is not tracked. Eviction also rebuilds the index map,
/// making evictions O(N); acceptable for Slice C since eviction only fires
/// when an attacker rotates >4096 distinct `(agent_id, host)` cells. A
/// future slice could promote to true LRU if cardinality churn becomes a
/// production hotspot.)
pub const RATE_LIMIT_MAX_CELLS: usize = 4096;

/// Trait abstraction over the rate limiter so HttpSecurityChain can be
/// unit-tested with a stub limiter that always allows or always denies.
pub trait RateLimiter: Send + Sync {
    /// Request a token for the given `(agent_id, host)` cell. Returns Ok if
    /// a token was consumed; Err(retry_after_ms) if not.
    fn check(&self, agent_id: &str, host: &str) -> Result<(), u64>;
}

/// Token-bucket rate limiter — `DefaultRateLimiter`.
pub struct DefaultRateLimiter {
    rps: f64,
    /// Optional live RPS source (MODULE-012 AC-17 hot-reload). `None` → the
    /// fixed `rps` field (prior behaviour).
    rps_source: Option<RpsSource>,
    state: Mutex<RateState>,
}

struct RateState {
    /// Insertion-ordered buckets keyed by `(agent_id, host)`. FIFO evicted by
    /// `Vec::remove(0)` when len > RATE_LIMIT_MAX_CELLS (no read-promotion).
    cells: Vec<(String, Bucket)>,
    /// Index for O(1) lookup; rebuilt on insertion/eviction.
    index: HashMap<String, usize>,
}

#[derive(Clone, Copy)]
struct Bucket {
    /// Tokens currently in the bucket.
    tokens: f64,
    /// Last time the bucket was refilled.
    last: Instant,
}

impl DefaultRateLimiter {
    pub fn new() -> Self {
        Self::with_rps(DEFAULT_PER_COMPONENT_RPS)
    }

    pub fn with_rps(rps: f64) -> Self {
        Self {
            rps,
            rps_source: None,
            state: Mutex::new(RateState {
                cells: Vec::with_capacity(64),
                index: HashMap::new(),
            }),
        }
    }

    /// Wire a live RPS source (MODULE-012 AC-17 hot-reload). Builder-style,
    /// additive — `new()` / `with_rps()` keep the fixed-rps behaviour.
    pub fn with_rps_source(mut self, source: RpsSource) -> Self {
        self.rps_source = Some(source);
        self
    }

    /// Effective RPS: the live source if wired, else the fixed `rps`. Read once
    /// per `check` so a single request sees one consistent value (and a
    /// hot-reloaded value takes effect on the next request).
    fn rps(&self) -> f64 {
        match &self.rps_source {
            Some(f) => f(),
            None => self.rps,
        }
    }

    fn key(agent_id: &str, host: &str) -> String {
        let mut s = String::with_capacity(agent_id.len() + 1 + host.len());
        s.push_str(agent_id);
        s.push('|');
        s.push_str(host);
        s
    }
}

impl Default for DefaultRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter for DefaultRateLimiter {
    fn check(&self, agent_id: &str, host: &str) -> Result<(), u64> {
        let key = Self::key(agent_id, host);
        let now = Instant::now();
        // AC-17: read the effective RPS ONCE per check (live source when wired,
        // else the fixed field) so all refill/burst/retry math uses one
        // consistent value; a hot-reloaded value applies on the next request.
        let rps = self.rps();
        let mut state = self.state.lock().unwrap();

        // Refill + consume in-place.
        let bucket_idx = match state.index.get(&key).copied() {
            Some(i) => Some(i),
            None => None,
        };

        match bucket_idx {
            Some(i) => {
                let elapsed_secs = now.duration_since(state.cells[i].1.last).as_secs_f64();
                let new_tokens = (state.cells[i].1.tokens + elapsed_secs * rps).min(rps);
                if new_tokens >= 1.0 {
                    state.cells[i].1.tokens = new_tokens - 1.0;
                    state.cells[i].1.last = now;
                    Ok(())
                } else {
                    let needed = 1.0 - new_tokens;
                    let retry_secs = needed / rps;
                    let retry_after_ms = (retry_secs * 1000.0).ceil() as u64;
                    state.cells[i].1.tokens = new_tokens;
                    state.cells[i].1.last = now;
                    Err(retry_after_ms.max(1))
                }
            }
            None => {
                // First request from this cell — bucket starts at full
                // (rps tokens) minus 1 for this consumption.
                let bucket = Bucket {
                    tokens: (rps - 1.0).max(0.0),
                    last: now,
                };
                state.cells.push((key.clone(), bucket));
                let new_idx = state.cells.len() - 1;
                state.index.insert(key, new_idx);

                // Evict FIFO (oldest-inserted) if over bound.
                while state.cells.len() > RATE_LIMIT_MAX_CELLS {
                    let evicted_key = state.cells.remove(0).0;
                    state.index.remove(&evicted_key);
                    // Rebuild index since indices shifted.
                    let rebuilt: Vec<(String, usize)> = state
                        .cells
                        .iter()
                        .enumerate()
                        .map(|(i, (k, _))| (k.clone(), i))
                        .collect();
                    for (k, i) in rebuilt {
                        state.index.insert(k, i);
                    }
                }
                Ok(())
            }
        }
    }
}

/// Stub rate limiter for tests — `AlwaysAllow` permits every request without
/// state.
pub struct AlwaysAllow;

impl RateLimiter for AlwaysAllow {
    fn check(&self, _agent_id: &str, _host: &str) -> Result<(), u64> {
        Ok(())
    }
}

/// Stub rate limiter for tests — `AlwaysDeny` rejects every request with the
/// given retry-after-ms.
pub struct AlwaysDeny(pub u64);

impl RateLimiter for AlwaysDeny {
    fn check(&self, _agent_id: &str, _host: &str) -> Result<(), u64> {
        Err(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_request_allowed() {
        let rl = DefaultRateLimiter::with_rps(10.0);
        assert!(rl.check("a1", "example.com").is_ok());
    }

    #[test]
    fn burst_then_block() {
        let rl = DefaultRateLimiter::with_rps(2.0);
        // Burst capacity = rps = 2 (allows the first request, then 1 more
        // immediately because new buckets start at rps - 1 tokens).
        assert!(rl.check("a1", "example.com").is_ok()); // first → ok (cell created at rps-1=1)
        assert!(rl.check("a1", "example.com").is_ok()); // second → consumes the remaining 1
                                                        // Third should be denied.
        let r = rl.check("a1", "example.com");
        assert!(r.is_err());
        let retry = r.unwrap_err();
        assert!(retry > 0);
    }

    #[test]
    fn distinct_cells_independent() {
        let rl = DefaultRateLimiter::with_rps(1.0);
        assert!(rl.check("a1", "x.com").is_ok());
        // Different agent_id same host — independent cell.
        assert!(rl.check("a2", "x.com").is_ok());
        // Different host same agent_id — independent cell.
        assert!(rl.check("a1", "y.com").is_ok());
    }

    #[test]
    fn always_allow_stub() {
        let rl = AlwaysAllow;
        for _ in 0..1000 {
            assert!(rl.check("a", "x.com").is_ok());
        }
    }

    #[test]
    fn always_deny_stub() {
        let rl = AlwaysDeny(500);
        let r = rl.check("a", "x.com");
        assert_eq!(r, Err(500));
    }
}

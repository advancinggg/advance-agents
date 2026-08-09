//! Injectable monotonic-ish wall clock (milliseconds since the Unix epoch).
//!
//! Time is injected so idempotency-TTL and session-expiry logic is deterministic under test
//! (no `SystemTime::now()` in the hot path, no wall-clock sleeps in tests).

use std::sync::atomic::{AtomicU64, Ordering};

/// A source of the current time in milliseconds since the Unix epoch.
pub trait Clock: Send + Sync {
    fn now_millis(&self) -> u64;
}

/// Production clock backed by the OS wall clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_millis(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

/// Deterministic clock for tests. Starts at a fixed instant and only advances explicitly.
#[derive(Debug)]
pub struct TestClock {
    millis: AtomicU64,
}

impl TestClock {
    pub fn new(start_millis: u64) -> Self {
        Self {
            millis: AtomicU64::new(start_millis),
        }
    }

    /// Advance the clock forward by `by_millis`.
    pub fn advance(&self, by_millis: u64) {
        self.millis.fetch_add(by_millis, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now_millis(&self) -> u64 {
        self.millis.load(Ordering::SeqCst)
    }
}

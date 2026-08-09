//! Wall-clock injection seam for [`crate::cooldown::FailureCooldown`].
//!
//! Internal cap-memory trait — NOT promoted to `shared-types`. Production wiring
//! uses [`SystemClock`] which returns `SystemTime::now()`; tests inject
//! [`MutableClock`] to get deterministic cooldown-window assertions without real
//! sleeps.

use std::sync::Mutex;
use std::time::SystemTime;

pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;
}

#[derive(Clone, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Deterministic clock for tests that exposes an interior-mutable timestamp.
/// Tests construct it with a fixed `SystemTime`, drive `run()` calls, then
/// `advance` the clock to simulate elapsed wall-clock time without sleeping.
pub struct MutableClock {
    now: Mutex<SystemTime>,
}

impl MutableClock {
    pub fn new(initial: SystemTime) -> Self {
        Self {
            now: Mutex::new(initial),
        }
    }

    /// Advance the clock by `delta`. Test seam — production should never call
    /// this on a `SystemClock`.
    pub fn advance(&self, delta: std::time::Duration) {
        let mut guard = self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = guard
            .checked_add(delta)
            .expect("MutableClock advance overflowed SystemTime");
    }
}

impl Clock for MutableClock {
    fn now(&self) -> SystemTime {
        *self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Format a [`Clock`]'s `now()` as a SECOND-granularity `Z`-form RFC3339 string
/// — the canonical `created_at` representation across cap-memory (slice
/// m011-memory-persist AC-42; extracted as the shared helper in slice
/// m011-mem-product).
///
/// `to_rfc3339_opts(Secs, true)` → e.g. `2026-06-06T08:59:43Z`. Two format
/// decisions, both forced by the fact that `created_at` is compared
/// **lexicographically** (raw string) in `store.rs::recall_at`/`rollback`:
/// 1. **`Z` form, not `+00:00`** (the `true` arg): bare `to_rfc3339()` emits
///    `+00:00`, which would mis-order against the `Z`-form timestamps used
///    everywhere else.
/// 2. **SECOND granularity, not millis** (`Secs`): every `created_at` in the
///    `knowledge.jsonl` schema is second-granularity `Z`. A millis form
///    (`…43.123Z`) is NOT lexicographically monotonic against a second bound
///    (`…43Z`) because `'.'` (0x2E) < `'Z'` (0x5A), so `…43.123Z` < `…43Z`
///    mis-classifies a same-second entry at a same-second `recall_at`/`rollback`
///    boundary.
///
/// No new `chrono` dep — uses the `advance_shared_types::chrono` re-export.
/// Reused by `wit_impl::created_at_now` (the remember-handler path) AND
/// `post_processor::mechanical_digest_fallback` (the LLM-unavailable degraded
/// path) so both emit the IDENTICAL `created_at` form.
pub fn clock_now_rfc3339_z(clock: &dyn Clock) -> String {
    use advance_shared_types::chrono::{DateTime, SecondsFormat, Utc};
    let dt: DateTime<Utc> = clock.now().into();
    dt.to_rfc3339_opts(SecondsFormat::Secs, true)
}

//! Per-agent LLM-failure cooldown tracker — MODULE-011 §2.10
//! `memory.post_processor.llm_failure_cooldown_sec` (default 600 s = 10 min).
//!
//! When the post-processor's Step 2 `BatchExtractor::extract` returns
//! `BatchExtractorError::LlmFailure`, [`FailureCooldown::record_failure`] sets a
//! per-agent timestamp. Subsequent Step 2 invocations consult
//! [`FailureCooldown::is_cooling_down`] to short-circuit the LLM call and fall
//! through to the mechanical-digest fallback path (AC-09 partial degrade).
//!
//! Internal cap-memory module — NOT promoted to `shared-types`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// Default cooldown: 600 s = 10 min per MODULE-011 §2.10
/// `memory.post_processor.llm_failure_cooldown_sec`.
pub const DEFAULT_COOLDOWN_SECS: u64 = 600;

pub struct FailureCooldown {
    cooldown: Duration,
    last_failures: Mutex<HashMap<String, SystemTime>>,
}

impl FailureCooldown {
    pub fn new(cooldown_secs: u64) -> Self {
        Self {
            cooldown: Duration::from_secs(cooldown_secs),
            last_failures: Mutex::new(HashMap::new()),
        }
    }

    pub fn record_failure(&self, agent_id: &str, now: SystemTime) {
        let mut guard = self
            .last_failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.insert(agent_id.to_string(), now);
    }

    /// Returns `true` iff `record_failure` was called within the last
    /// `cooldown_secs` for `agent_id`. Round-13 adversarial-fix #7:
    /// FAIL-CLOSED on clock regression — a `now` value earlier than the
    /// recorded `last` (NTP backstep, leap-second correction, operator clock
    /// adjustment) is treated as STILL COOLING DOWN rather than "cooldown
    /// elapsed". The earlier "fail-open" posture was a defense-in-depth gap:
    /// an attacker who can manipulate wall-clock would have bypassed the
    /// 10-min rate limiter on each LLM-failure retry.
    pub fn is_cooling_down(&self, agent_id: &str, now: SystemTime) -> bool {
        let guard = self
            .last_failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match guard.get(agent_id) {
            Some(last) => match now.duration_since(*last) {
                Ok(elapsed) => elapsed < self.cooldown,
                Err(_) => true,
            },
            None => false,
        }
    }
}

impl Default for FailureCooldown {
    fn default() -> Self {
        Self::new(DEFAULT_COOLDOWN_SECS)
    }
}

impl std::fmt::Debug for FailureCooldown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.last_failures.lock().map(|g| g.len()).unwrap_or(0);
        f.debug_struct("FailureCooldown")
            .field("cooldown", &self.cooldown)
            .field("tracked_agents", &count)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_failure_recorded_returns_false() {
        let cd = FailureCooldown::default();
        assert!(!cd.is_cooling_down("agent:x", SystemTime::UNIX_EPOCH));
    }

    #[test]
    fn cooldown_window_active_returns_true() {
        let cd = FailureCooldown::new(600);
        let t0 = SystemTime::UNIX_EPOCH;
        cd.record_failure("agent:x", t0);
        assert!(cd.is_cooling_down("agent:x", t0 + Duration::from_secs(300)));
    }

    #[test]
    fn cooldown_elapsed_returns_false() {
        let cd = FailureCooldown::new(600);
        let t0 = SystemTime::UNIX_EPOCH;
        cd.record_failure("agent:x", t0);
        assert!(!cd.is_cooling_down("agent:x", t0 + Duration::from_secs(601)));
    }

    #[test]
    fn boundary_secs_returns_false() {
        // Exactly cooldown_secs elapsed → NOT cooling down (strict <).
        let cd = FailureCooldown::new(600);
        let t0 = SystemTime::UNIX_EPOCH;
        cd.record_failure("agent:x", t0);
        assert!(!cd.is_cooling_down("agent:x", t0 + Duration::from_secs(600)));
    }

    #[test]
    fn per_agent_isolation() {
        let cd = FailureCooldown::new(600);
        let t0 = SystemTime::UNIX_EPOCH;
        cd.record_failure("agent:a", t0);
        assert!(cd.is_cooling_down("agent:a", t0 + Duration::from_secs(10)));
        assert!(!cd.is_cooling_down("agent:b", t0 + Duration::from_secs(10)));
    }

    #[test]
    fn clock_regression_fails_closed() {
        // Round-13 adversarial-fix #7: clock regression (NTP backstep, leap
        // second, etc.) MUST be treated as "still cooling down" to defend
        // against wall-clock manipulation attacks that would otherwise reset
        // the 10-min rate limiter.
        let cd = FailureCooldown::new(600);
        let t1 = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000);
        cd.record_failure("agent:x", t1);
        let earlier = SystemTime::UNIX_EPOCH + Duration::from_secs(5_000);
        assert!(
            cd.is_cooling_down("agent:x", earlier),
            "clock regression must FAIL CLOSED (treat as still cooling down), not bypass cooldown"
        );
    }
}

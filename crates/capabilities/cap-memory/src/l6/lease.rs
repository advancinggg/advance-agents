//! L6 single-flight lease (AC-13). MODULE-011 §1.3.6 / §2.10
//! `memory.l6.lease_timeout_min` (10 min). Internal cap-memory seam.
//!
//! Observable two-phase: `begin_acquire` → `Pending` (stake), `confirm_acquire`
//! → `Active` (promote). A live (Pending or Active, non-expired) lease blocks a
//! second `begin_acquire` (`AlreadyHeld`). `release` is token-checked — a
//! stale-token release is a no-op (this is the primitive the L6 runnable's
//! Step 6 late-`component.finished` mis-clearing defense builds on).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use uuid::Uuid;

/// Default lease TTL — 10 min per §2.10 `memory.l6.lease_timeout_min`.
pub const DEFAULT_LEASE_TTL_SECS: u64 = 600;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseState {
    Pending,
    Active,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeaseDecision {
    Acquired { token: String },
    AlreadyHeld,
}

pub trait LeaseStore: Send + Sync {
    /// Phase 1 — stake a `Pending` lease. `Acquired{token}` iff no live
    /// (Pending or Active, non-expired) lease for `agent_id`.
    fn begin_acquire(&self, agent_id: &str, now: SystemTime, ttl: Duration) -> LeaseDecision;
    /// Phase 2 — promote `Pending` → `Active` for a matching token. Returns
    /// `false` (no-op) if the token does not match the current lease.
    fn confirm_acquire(&self, agent_id: &str, token: &str) -> bool;
    /// Clear the lease ONLY if `token` matches the current lease's token.
    /// Stale-token release is a no-op (returns `false`).
    fn release(&self, agent_id: &str, token: &str) -> bool;
    /// Current lease token if a live (non-expired) lease exists.
    fn current_token(&self, agent_id: &str, now: SystemTime) -> Option<String>;
    /// Observable lease state (AC-13 two-phase visibility).
    fn state(&self, agent_id: &str, now: SystemTime) -> Option<LeaseState>;
}

#[derive(Clone, Debug)]
struct LeaseSlot {
    token: String,
    state: LeaseState,
    deadline: SystemTime,
}

#[derive(Default)]
pub struct InMemoryLeaseStore {
    inner: Mutex<HashMap<String, LeaseSlot>>,
}

impl InMemoryLeaseStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// A slot is live iff present AND `now < deadline`. Expired slots are
    /// treated as free.
    fn live<'a>(slot: Option<&'a LeaseSlot>, now: SystemTime) -> Option<&'a LeaseSlot> {
        match slot {
            Some(s) if now < s.deadline => Some(s),
            _ => None,
        }
    }
}

impl LeaseStore for InMemoryLeaseStore {
    fn begin_acquire(&self, agent_id: &str, now: SystemTime, ttl: Duration) -> LeaseDecision {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if Self::live(guard.get(agent_id), now).is_some() {
            return LeaseDecision::AlreadyHeld;
        }
        let token = Uuid::new_v4().simple().to_string();
        let deadline = now.checked_add(ttl).unwrap_or(now);
        guard.insert(
            agent_id.to_string(),
            LeaseSlot {
                token: token.clone(),
                state: LeaseState::Pending,
                deadline,
            },
        );
        LeaseDecision::Acquired { token }
    }

    fn confirm_acquire(&self, agent_id: &str, token: &str) -> bool {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match guard.get_mut(agent_id) {
            Some(slot) if slot.token == token => {
                slot.state = LeaseState::Active;
                true
            }
            _ => false,
        }
    }

    fn release(&self, agent_id: &str, token: &str) -> bool {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match guard.get(agent_id) {
            Some(slot) if slot.token == token => {
                guard.remove(agent_id);
                true
            }
            _ => false,
        }
    }

    fn current_token(&self, agent_id: &str, now: SystemTime) -> Option<String> {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::live(guard.get(agent_id), now).map(|s| s.token.clone())
    }

    fn state(&self, agent_id: &str, now: SystemTime) -> Option<LeaseState> {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::live(guard.get(agent_id), now).map(|s| s.state)
    }
}

impl std::fmt::Debug for InMemoryLeaseStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.inner.lock().map(|g| g.len()).unwrap_or(0);
        f.debug_struct("InMemoryLeaseStore")
            .field("tracked_agents", &n)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(s)
    }
    fn ttl() -> Duration {
        Duration::from_secs(DEFAULT_LEASE_TTL_SECS)
    }

    #[test]
    fn two_phase_pending_then_active() {
        let ls = InMemoryLeaseStore::new();
        let t0 = at(1000);
        let token = match ls.begin_acquire("a", t0, ttl()) {
            LeaseDecision::Acquired { token } => token,
            other => panic!("expected Acquired, got {other:?}"),
        };
        assert_eq!(ls.state("a", t0), Some(LeaseState::Pending));
        assert!(ls.confirm_acquire("a", &token));
        assert_eq!(ls.state("a", t0), Some(LeaseState::Active));
    }

    #[test]
    fn second_begin_while_live_is_already_held() {
        let ls = InMemoryLeaseStore::new();
        let t0 = at(1000);
        let _ = ls.begin_acquire("a", t0, ttl());
        // Pending blocks.
        assert_eq!(ls.begin_acquire("a", t0, ttl()), LeaseDecision::AlreadyHeld);
        let tok = ls.current_token("a", t0).unwrap();
        ls.confirm_acquire("a", &tok);
        // Active also blocks.
        assert_eq!(ls.begin_acquire("a", t0, ttl()), LeaseDecision::AlreadyHeld);
    }

    #[test]
    fn expiry_allows_fresh_acquire() {
        let ls = InMemoryLeaseStore::new();
        let t0 = at(1000);
        let LeaseDecision::Acquired { token: t1 } = ls.begin_acquire("a", t0, ttl()) else {
            panic!()
        };
        // After TTL+1s the slot is free.
        let later = at(1000 + DEFAULT_LEASE_TTL_SECS + 1);
        let LeaseDecision::Acquired { token: t2 } = ls.begin_acquire("a", later, ttl()) else {
            panic!("expired lease must be re-acquirable")
        };
        assert_ne!(t1, t2);
    }

    #[test]
    fn release_only_on_token_match() {
        let ls = InMemoryLeaseStore::new();
        let t0 = at(1000);
        let LeaseDecision::Acquired { token } = ls.begin_acquire("a", t0, ttl()) else {
            panic!()
        };
        ls.confirm_acquire("a", &token);
        assert!(!ls.release("a", "stale-token"), "stale release is a no-op");
        assert_eq!(
            ls.state("a", t0),
            Some(LeaseState::Active),
            "lease still held after stale release"
        );
        assert!(ls.release("a", &token), "matching release clears");
        assert_eq!(ls.state("a", t0), None);
    }

    #[test]
    fn per_agent_isolation() {
        let ls = InMemoryLeaseStore::new();
        let t0 = at(1000);
        let _ = ls.begin_acquire("a", t0, ttl());
        // agent b is unaffected by a's held lease.
        assert!(matches!(
            ls.begin_acquire("b", t0, ttl()),
            LeaseDecision::Acquired { .. }
        ));
    }
}

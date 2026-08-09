//! Wave-18 Lane 2 — production M015→M017 SkillRollback integration bridge.
//!
//! Closes the Wave-17 strict-hold (no production `impl SkillRollback`) and the
//! MODULE-017 §3.6 (xx) AutoLoop-bridge invariant mismatch. Two seams, both
//! composition-root adapters (cli is the only crate that depends on BOTH
//! `advance-scheduler-auto-loop` and `cap-skills`, so the dependency-inversion
//! is honored — neither library crate gains a dep on the other):
//!
//! - [`DriverPreActivationObserver`] (record side, MODULE-017-AC-06): forwards
//!   the cap-skills [`SkillPreActivationObserver`] callback (fired at the agent
//!   activate path BEFORE the mutation) to
//!   [`DefaultAutoLoopDriver::record_skill_pre_activation`]. The driver gates on
//!   session existence, so it is a no-op outside a live auto iteration.
//! - [`SkillPersistenceRollbackBridge`] (write side, MODULE-017-AC-07 + the
//!   MODULE-003-AC-21 micro lane): implements the auto-loop [`SkillRollback`]
//!   trait over an [`SkillPersistenceCoordinator`] using `Initiator::AutoLoop`,
//!   so a discard restore produces a `[micro] [runtime:auto-loop]` git commit
//!   (durable BEFORE the `skill.rolled_back` / `skill.deleted` event — the
//!   coordinator awaits the commit receiver before emitting) over the REAL
//!   `SkillStore`.
//!
//! §3.6 (xx) invariant reconciliation lives here (MODULE-017 §3.6 (xx)/(bbb)):
//! - **no-op delete when absent** (invariant 2): `SkillStore::delete` returns
//!   `SkillNotFound` on an absent skill → mapped to `Ok(())`.
//! - **idempotent rollback when already at target** (invariant 1): the bridge
//!   reads the current active version under a SCOPED lock on the shared store
//!   (released BEFORE the coordinator re-locks the same non-reentrant
//!   `tokio::Mutex` → no deadlock) and no-ops (no version bump / commit / event)
//!   when `current == target`.
//! - **deleted-then-restore is fail-closed**: a `Version(n)` pre-state whose
//!   skill is absent at discard cannot be restored by `SkillStore::rollback`
//!   (no re-create) → surfaced as an error, never a fake `Ok`.
//!
//! Disclosed boundaries (dormant `advance auto start` ingress, the
//! `default-agent` / `agent:default` grammar split, the version-read TOCTOU, and
//! the `Weak`-broken record-side reference cycle): MODULE-017 §3.6 (bbb).

use std::sync::{Arc, Weak};

use advance_scheduler_auto_loop::{DefaultAutoLoopDriver, SkillRollback, SkillTrackerError};
use async_trait::async_trait;
use cap_skills::{
    Initiator, SkillError, SkillPersistenceCoordinator, SkillPreActivationObserver, SkillStore,
};

const DISCARD_REASON: &str = "auto-loop iteration discard";

/// Record-side observer: forwards a pre-activation snapshot to the auto-loop
/// driver.
///
/// Holds a **`Weak`** driver handle, NOT an `Arc` — wiring the two seams forms a
/// cycle (`driver`→OnceLock `skill_rollback`→bridge→coordinator→observer→driver).
/// A strong cycle would never be reclaimed; in the daemon that is merely a
/// process-lifetime leak, but it also keeps the cap-skills `DefaultGitCommitQueue`
/// (held transitively via the coordinator) alive forever, so its blocking-pool
/// worker never exits and a tokio runtime teardown (every `#[tokio::test]`)
/// hangs in `BlockingPool::shutdown`. `Weak` breaks the cycle: the driver is a
/// daemon-lifetime singleton (also held by the `RunManager`), so an in-iteration
/// `upgrade()` always succeeds while it is live, and once it is dropped the
/// observe is a correct no-op (no live session ⇒ nothing to record). See
/// MODULE-017 §3.6 (bbb).
pub struct DriverPreActivationObserver {
    driver: Weak<DefaultAutoLoopDriver>,
}

impl DriverPreActivationObserver {
    pub fn new(driver: &Arc<DefaultAutoLoopDriver>) -> Self {
        Self {
            driver: Arc::downgrade(driver),
        }
    }
}

impl SkillPreActivationObserver for DriverPreActivationObserver {
    fn observe_pre_activation(&self, agent_id: &str, skill_id: &str, prev_version: Option<u32>) {
        // No-op if the driver has been dropped (no live auto session to record
        // into). When live, the driver itself is session-gated: a no-op when no
        // auto session exists for `agent_id` (turn lane byte-identical).
        if let Some(driver) = self.driver.upgrade() {
            driver.record_skill_pre_activation(agent_id, skill_id, prev_version);
        }
    }
}

/// Write-side bridge: the auto-loop discard path drives this; it routes to the
/// cap-skills persistence coordinator on the `Initiator::AutoLoop` (micro) lane.
pub struct SkillPersistenceRollbackBridge {
    coordinator: Arc<SkillPersistenceCoordinator>,
    /// An `Arc::clone` of the SAME shared store the coordinator wraps (the value
    /// `provider.get()` returns). Read-only here, used for the idempotent-
    /// rollback version guard; the lock is always released before the
    /// coordinator re-locks it.
    store: Arc<tokio::sync::Mutex<SkillStore>>,
}

impl SkillPersistenceRollbackBridge {
    pub fn new(
        coordinator: Arc<SkillPersistenceCoordinator>,
        store: Arc<tokio::sync::Mutex<SkillStore>>,
    ) -> Self {
        Self { coordinator, store }
    }

    /// Current active version of `skill_id` (`None` ⇒ absent). Scoped lock —
    /// released at the end of the block so the subsequent coordinator call can
    /// re-acquire the non-reentrant `tokio::Mutex` without deadlocking.
    async fn current_version(&self, skill_id: &str) -> Option<u32> {
        let guard = self.store.lock().await;
        guard.get(skill_id).await.ok().map(|s| s.version)
    }
}

#[async_trait]
impl SkillRollback for SkillPersistenceRollbackBridge {
    async fn rollback_skill(
        &self,
        _agent_id: &str,
        skill_id: &str,
        target_version: u32,
    ) -> Result<(), SkillTrackerError> {
        match self.current_version(skill_id).await {
            // Idempotent rollback (invariant 1): already at target → no-op (no
            // version bump / commit / event). `SkillStore::rollback` would
            // otherwise history-append a new version even for rollback-to-current.
            Some(v) if v == target_version => Ok(()),
            // Deleted-then-restore is unsupported by `SkillStore::rollback`
            // (cannot re-create) → fail-closed, never a fake `Ok`.
            None => Err(SkillTrackerError::Rollback(format!(
                "rollback {skill_id}: skill absent at discard \
                 (deleted-then-restore unsupported)"
            ))),
            Some(_) => self
                .coordinator
                .rollback_skill_with_persistence(
                    Initiator::AutoLoop,
                    skill_id,
                    target_version,
                    DISCARD_REASON,
                )
                .await
                .map(|_| ())
                .map_err(|e| SkillTrackerError::Rollback(format!("rollback {skill_id}: {e}"))),
        }
    }

    async fn delete_skill(&self, _agent_id: &str, skill_id: &str) -> Result<(), SkillTrackerError> {
        match self
            .coordinator
            .delete_skill_with_persistence(Initiator::AutoLoop, skill_id, DISCARD_REASON)
            .await
        {
            Ok(_) => Ok(()),
            // No-op delete when absent (invariant 2).
            Err(SkillError::SkillNotFound(_)) => Ok(()),
            Err(e) => Err(SkillTrackerError::Rollback(format!(
                "delete {skill_id}: {e}"
            ))),
        }
    }
}

/// Build the production write-side bridge wrapping an EXISTING coordinator `Arc`
/// (the same instance the turn lane uses → one shared `SkillStore` mutex) plus
/// an `Arc::clone` of that shared store. Used by BOTH the cli `wire_capabilities`
/// composition and the witnesses (single source of the production wiring).
pub fn build_auto_skill_rollback_bridge(
    coordinator: Arc<SkillPersistenceCoordinator>,
    store: Arc<tokio::sync::Mutex<SkillStore>>,
) -> Arc<dyn SkillRollback> {
    Arc::new(SkillPersistenceRollbackBridge::new(coordinator, store))
}

/// Build the production record-side observer forwarding to the auto-loop driver.
/// Takes the driver by reference and stores a `Weak` (cycle-breaking — see
/// [`DriverPreActivationObserver`]).
pub fn build_pre_activation_observer(
    driver: &Arc<DefaultAutoLoopDriver>,
) -> Arc<dyn SkillPreActivationObserver> {
    Arc::new(DriverPreActivationObserver::new(driver))
}

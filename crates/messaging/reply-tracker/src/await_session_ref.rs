//! Backbone Step 4b (2026-06-08) — `AwaitSessionManagerRef`: the production
//! [`advance_shared_types::await_session::AwaitSessionRef`] (CONTRACT-060
//! read-only/cascade surface) impl over [`AwaitSessionManagerImpl`].
//!
//! This is the M007→M008 close-cascade bridge: MODULE-008 `RunManager`
//! (`with_await_session_ref`) consumes `Arc<dyn AwaitSessionRef>`; its
//! `pause_run`/`cancel_run` branch-(a) (Suspended) calls `close(session_id)`,
//! which resolves the parked `await-replies` `start` with `Err(SessionClosed)`
//! — the SYS-AC-016/017 + MODULE-007-AC-22 path.
//!
//! ## Faithfulness
//!
//! - **`close`** is FAITHFUL: it delegates to the existing async
//!   [`AwaitSessionManagerImpl::close`], which sends `Err(SessionClosed)` over
//!   the session oneshot (idempotent — a second close returns `Err(NotFound)`,
//!   propagated here, not swallowed).
//! - **`exists` / `walk_tree`** are BEST-EFFORT: they are SYNC trait methods but
//!   `AwaitSessionManagerImpl.sessions` is an async `tokio::RwLock`, so they
//!   delegate to the `try_read()`-based `exists_best_effort` /
//!   `walk_tree_best_effort` helpers (return `false` / `None` under writer
//!   contention). The faithful sync-shadow-index design is deferred (MODULE-007
//!   §3.6). They are NOT on any witnessed path — only `RunManager::run_status`'s
//!   await-tree projection (AC-18, out of scope) consumes them, best-effort
//!   during a live suspension.
//!
//!   **CAVEAT for a future recovery-wiring slice:** `RunManager::recover_on_startup`
//!   calls `AwaitSessionRef::exists` to decide whether a Suspended run's session is
//!   still alive (a `false` → reset to Active + emit `run.interrupted`). A
//!   `try_read` false-negative under writer contention would mis-judge a LIVE
//!   session as absent → a SPURIOUS `run.interrupted` + an orphaned live await.
//!   Until the faithful sync-shadow-index lands, this `AwaitSessionManagerRef`
//!   MUST NOT be wired into `recover_on_startup` (or recovery must tolerate
//!   `exists` false-negatives). This slice does NOT wire recovery, so it is not
//!   reachable here (§5.2 adversarial finding, disclosed).

use std::sync::Arc;

use async_trait::async_trait;

use advance_shared_types::await_session::{
    AwaitSessionRef, AwaitTreeSummary, OrchestrationError, SessionId,
};

use crate::manager::{AwaitSessionManager, AwaitSessionManagerImpl};

/// Production [`AwaitSessionRef`] impl wrapping an [`AwaitSessionManagerImpl`].
/// Constructed at a composition root (this slice: TEST-SIDE in the
/// `system-acceptance` harness) and wired into M008 via
/// `RunManager::with_await_session_ref`.
pub struct AwaitSessionManagerRef {
    manager: Arc<AwaitSessionManagerImpl>,
}

impl AwaitSessionManagerRef {
    pub fn new(manager: Arc<AwaitSessionManagerImpl>) -> Self {
        Self { manager }
    }
}

#[async_trait]
impl AwaitSessionRef for AwaitSessionManagerRef {
    fn exists(&self, session_id: &SessionId) -> bool {
        // Best-effort sync read (see module doc + MODULE-007 §3.6).
        self.manager.exists_best_effort(session_id)
    }

    fn walk_tree(&self, session_id: &SessionId) -> Option<AwaitTreeSummary> {
        // Best-effort sync read (see module doc + MODULE-007 §3.6).
        self.manager.walk_tree_best_effort(session_id)
    }

    async fn close(&self, session_id: &SessionId, reason: &str) -> Result<(), OrchestrationError> {
        // Faithful: delegate to the existing async close. Idempotent — a second
        // close returns Err(NotFound), which we PROPAGATE (not swallow) so the
        // caller's idempotency assertion holds.
        self.manager.close(session_id, reason).await
    }
}

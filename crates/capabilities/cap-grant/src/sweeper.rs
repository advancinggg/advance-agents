//! TTL sweeper background task (MODULE-013 §1.6, AC-13).
//!
//! Test seam: `tick(now)` is callable directly with a deterministic
//! timestamp. Production: `spawn(interval)` periodically calls
//! `tick(Utc::now())` from inside `tokio::task::spawn_blocking` so the
//! synchronous SQLite write path inside `store.expire_ids` does not
//! block the Tokio worker thread.

use std::sync::Arc;
use std::time::Duration;

use advance_shared_types::traits::EventBusEmit;
use chrono::{DateTime, Utc};
use tokio::task::JoinHandle;

use crate::store::GrantStore;

#[allow(dead_code)] // event_bus is held to keep its Arc alive for the spawned task
pub struct TtlSweeper {
    store: Arc<GrantStore>,
    event_bus: Arc<dyn EventBusEmit>,
}

impl TtlSweeper {
    pub fn new(store: Arc<GrantStore>, event_bus: Arc<dyn EventBusEmit>) -> Arc<Self> {
        Arc::new(Self { store, event_bus })
    }

    /// Synchronous tick — collects expired grant ids and bulk-flips them
    /// via `store.expire_ids`. Test seam: callable directly with a
    /// deterministic `now` value.
    pub fn tick(self: &Arc<Self>, now: DateTime<Utc>) {
        let ids = self.store.collect_expired_ids(now);
        if ids.is_empty() {
            return;
        }
        // Best-effort: SQLite errors are not propagated through the
        // tokio::time::interval loop, but we don't panic either —
        // log/swallow at the spawn level. Slice A relies on the test
        // suite to exercise the success path; production hardening of
        // the failure path lands in slice B's resolver work.
        let _ = self.store.expire_ids(&ids);
    }

    /// Spawn a periodic ticker on the current Tokio runtime. The
    /// per-tick body wraps `tick(Utc::now())` in `tokio::task::spawn_blocking`
    /// so the SQLite I/O inside `store.expire_ids` does not block the
    /// Tokio worker thread.
    ///
    /// Uses `Arc::downgrade` so the spawned task does NOT keep the
    /// sweeper alive past the caller's drop point. Drop the strong Arc
    /// returned by `new()` to stop the ticker on its next tick.
    ///
    /// **Tokio runtime requirement**: must be called from a context with
    /// an active Tokio runtime, else `tokio::spawn` panics.
    pub fn spawn(self: Arc<Self>, interval: Duration) -> JoinHandle<()> {
        let weak = Arc::downgrade(&self);
        drop(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let Some(this) = weak.upgrade() else { break };
                let res = tokio::task::spawn_blocking(move || {
                    this.tick(Utc::now());
                })
                .await;
                if res.is_err() {
                    break;
                }
            }
        })
    }
}

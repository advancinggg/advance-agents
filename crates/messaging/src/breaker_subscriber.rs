//! Slice-D AC-13 production driver — `BreakerSubscriber`.
//!
//! Consumes `CircuitBreakerBus::subscribe()`'s `mpsc::UnboundedReceiver<BreakerEvent>`
//! and routes per-agent BreakerEvent records to `Mailbox::freeze` / `unfreeze`
//! via a three-state matrix. Closes MODULE-006-AC-13 end-to-end together with
//! the slice-C Layer-1 dispatcher CB query.
//!
//! # Routing matrix
//!
//! | BreakerScope | new_state | Action |
//! |---|---|---|
//! | Agent | Open | `store.get_or_create(target)?.freeze()` (race-resilient lazy-create) |
//! | Agent | Closed | `store.get(target).map(|mb| mb.unfreeze())` (lazy: no-op if no mailbox) |
//! | Agent | HalfOpen | `store.get(target).map(|mb| mb.unfreeze())` (probe-mode unfreeze) |
//! | Capability / ComponentType | * | ignored (Layer-4 freeze is agent-scope only) |
//!
//! # HalfOpen → unfreeze rationale
//!
//! Dispatcher's Layer-1 CB query (`MailboxDispatcherImpl::deliver` / `reply` /
//! `deliver_notify`) calls `bus.is_open_agent(target)` which returns
//! `Some(reason)` ONLY for `BreakerState::Open` (per CONTRACT-002 at
//! `crates/runtime/src/circuit_breaker.rs:11-13` + line 192). For HalfOpen,
//! `is_open_agent` returns `None` → dispatcher passes through and accepts new
//! deliveries (standard CB probe-mode semantics). If the subscriber left the
//! mailbox frozen during HalfOpen while the dispatcher accepted deliveries,
//! the result would be a split-state silent failure: new messages would queue
//! into a frozen mailbox that `recv` refuses to drain. Aligning the subscriber
//! to unfreeze on HalfOpen restores Layer-1 + Layer-4 consistency.
//! See MODULE-006 §3.8 (g).
//!
//! # Cooperative shutdown
//!
//! `BreakerSubscriber` exposes `handle() -> &JoinHandle<()>` for explicit
//! `.abort()`. ADDITIONALLY, `impl Drop` calls `self.handle.abort()` on drop —
//! callers that forget explicit abort still get task cleanup. `JoinHandle::abort`
//! is idempotent; the explicit-abort + Drop's abort sequence is safe.
//!
//! # Single-spawn-per-(bus, store) invariant
//!
//! `spawn` does NOT mechanically prevent multiple spawn calls for the same
//! `(bus, store)` pair. `DefaultCircuitBreakerBus::subscribe()` is append-only
//! (each call appends a new sender); two spawns produce two independent tasks
//! that BOTH freeze/unfreeze on every event. Operational impact is benign
//! (freeze/unfreeze are idempotent at mailbox level) but wastes work + redundant
//! `get_or_create` calls on Open. Production callers MUST spawn exactly one
//! subscriber per `(bus, store)` (natural lifecycle: spawn at bootstrap, drop at
//! shutdown). Not mechanically enforced; documented per MODULE-006 §3.8 (g) +
//! §3.6 residual row.

use std::sync::Arc;

use advance_runtime::circuit_breaker::{BreakerScope, BreakerState, CircuitBreakerBus};
use tokio::task::JoinHandle;

use crate::mailbox::MailboxStore;

/// Slice-D AC-13 production driver: consumes BreakerEvent stream from the
/// CircuitBreakerBus and routes per-agent freeze/unfreeze to the MailboxStore.
///
/// See module docs for routing matrix, HalfOpen rationale, shutdown semantics,
/// and the single-spawn invariant.
pub struct BreakerSubscriber {
    handle: JoinHandle<()>,
}

impl BreakerSubscriber {
    /// Spawn a tokio task that consumes `bus.subscribe()` events and routes
    /// `BreakerScope::Agent` events per the three-state matrix in module docs.
    ///
    /// The spawned task holds `Arc` clones of `store` (via the closure capture)
    /// and exits naturally when (a) the bus drops all senders (subscriber
    /// receives `None` from `recv().await`), (b) the JoinHandle is aborted
    /// explicitly via `handle().abort()`, or (c) the `BreakerSubscriber` is
    /// dropped (Drop impl aborts).
    pub fn spawn(bus: Arc<dyn CircuitBreakerBus>, store: Arc<MailboxStore>) -> Self {
        let mut rx = bus.subscribe();
        let handle = tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if event.scope != BreakerScope::Agent {
                    // Layer-4 freeze is agent-scope; capability/component
                    // breakers operate via Layer 1 dispatcher gate elsewhere.
                    continue;
                }
                match event.new_state {
                    BreakerState::Open => {
                        // Race-resilient lazy-create: ensure the mailbox EXISTS
                        // even for never-used agents so the freeze is
                        // observable. Trade-off documented in MODULE-006 §3.6
                        // (lazy-create row) — bounded by MAX_MAILBOXES.
                        if let Ok(mb) = store.get_or_create(&event.target) {
                            mb.freeze();
                        }
                    }
                    BreakerState::Closed | BreakerState::HalfOpen => {
                        // Lazy `get`: no-op if no mailbox exists for this
                        // agent (nothing to unfreeze). HalfOpen unfreezes
                        // because dispatcher accepts deliveries during probe
                        // mode (`is_open_agent` returns None for HalfOpen);
                        // leaving frozen would create a split-state bug
                        // (dispatcher delivers but recv blocks). See
                        // MODULE-006 §3.8 (g).
                        if let Some(mb) = store.get(&event.target) {
                            mb.unfreeze();
                        }
                    }
                }
            }
        });
        Self { handle }
    }

    /// Returns a reference to the spawned task's JoinHandle for cooperative
    /// shutdown via `handle().abort()`. `JoinHandle::abort()` is idempotent
    /// — calling it more than once (including after Drop fires) is safe.
    pub fn handle(&self) -> &JoinHandle<()> {
        &self.handle
    }
}

impl Drop for BreakerSubscriber {
    /// Idiomatic tokio-service Drop=cleanup pattern. Eliminates production-time
    /// task-leak vector when callers drop the subscriber without explicit
    /// `.abort()`. Idempotent with explicit `handle().abort()`.
    fn drop(&mut self) {
        self.handle.abort();
    }
}

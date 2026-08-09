//! AC-19 (Wave-19 Lane 3 / slice m007-G) — [`ComponentResolutionSink`]: the
//! MODULE-007 provider of CONTRACT-184 [`RunCompletionSink`].
//!
//! Realizes the MODULE-007 §2.3 component-finished resolution path. When
//! MODULE-008 `complete_run` fires this sink on `run.completed`, it resolves the
//! matching `await-replies` `ComponentFinished` slot **status-only** via
//! [`AwaitSessionManagerImpl::resolve_component_finished`] — the slot is marked
//! `reply-status::completed` with an EMPTY payload (PRD §9.2 / §2.3: the
//! component output is NOT delivered through the AwaitSession; the caller reads
//! `output-dir/result.bin` directly via MODULE-002 agent-fs).
//!
//! **Join key**: the completed run's `task_id` == the awaited `component_id`
//! (the 1-component==1-run keying — `ensure_run(id, id)`).
//!
//! **Sync→async bridge**: [`RunCompletionSink::on_run_completed`] is sync (the
//! trait shape, mirroring `RunInterruptSink`), but the resolution is async (the
//! manager's `sessions` is a `tokio::sync::RwLock` and `on_reply` is async), so
//! it is SPAWNED onto the current tokio runtime — fire-and-forget; the parked
//! `await-replies` future unblocks when the spawned task calls `on_reply`.
//! Best-effort: outside a tokio runtime it logs and no-ops (uses
//! `Handle::try_current()`, never `current()`, so it never panics).
//!
//! **Production COMPOSITION landed (Wave-24 `req270-sink`)**: the `advance start`
//! daemon composition root (`cli/src/wiring.rs`) now constructs this sink + passes
//! it to `RunManager::with_run_completion_sink`, gated on the messaging
//! `await_manager`. The DI-composition dormancy is closed. **The component-completion
//! DRIVER that would exercise the sink end-to-end is still UNBUILT**, however: a
//! submitted component creates NO `RunManager` run (`scheduler::submit_component`),
//! the WIT `complete-run` host-fn is unwired, and the only production-code
//! `complete_run` callsite outside that WIT surface is auto-settle — whose tick
//! loop is composed and running, but whose settlement pass is dormant because
//! session registration has no production caller. Its colon `auto:{agent}` task_ids
//! are also skipped by the short-circuit
//! below. Thus no reachable production path resolves a `ComponentFinished` slot
//! through this sink yet (REQ-270 stays Partial; MODULE-007
//! §3.6:1099/:1100 + §3.8). The composition-root witness
//! (`cli/tests/run_completion_sink_wiring.rs`) drives `complete_run` over the real
//! `wire_capabilities` `RunManager`; the slice-G witness drives the resolution path
//! over a real `RunManager` + this sink.
//!
//! **§3.6 prerequisites status (Wave-24 `req270-sink` — see MODULE-007 §3.6:1100).**
//! The confused-deputy + ordering + scale hazards are all UNREACHABLE in-lane: the
//! WIT `complete-run` surface is unwired, the auto-settle callsite is behind a dormant
//! session registry (and would short-circuit its colon-only ids below), and a submitted
//! component creates no `RunManager` run — so nothing drives the sink. Per-prerequisite:
//! - **SECURITY / owner-binding — DISPOSITIONED** to the future component-completion
//!   driver lane. Resolution keys on `component_id == task_id` with NO owner binding,
//!   but no sound gate can be built here: components create no runs, so no component-run
//!   controller convention exists to bind against (the future driver — which builds
//!   component-run creation — must co-design it). The `on_reply` `source` check is
//!   tautological on this path and adds no authorization.
//! - **ORDERING — DISPOSITIONED** to the driver lane (park-before-complete inversion
//!   needs an independent component-completion driver; the completed-run buffer is that
//!   lane's remedy).
//! - **AUDIT / DoS-index — DISPOSITIONED** to the driver lane (no production resolution
//!   occurs yet; a typed event expands the M019 taxonomy). The colon short-circuit
//!   below PARTIAL-SATISFIES DoS for the existing auto-settle codepath by skipping its
//!   spawn/scan if session registration is later activated.
//! - **ON-RUNTIME — DISPOSITIONED** to the driver lane: there is no reachable production
//!   caller from which to establish the guarantee. The composition witness proves the
//!   sink works when invoked in-runtime; off-runtime, `Handle::try_current()` no-ops.
//! - **INTEGRITY empty-payload — SATISFIED**: `on_reply` rejects a non-empty payload
//!   for a `ComponentFinished` slot. The character-set intersection proves only that a
//!   colon `task_id` can never join. **JOIN LENGTH — DISPOSITIONED** to the driver lane:
//!   component ids admit up to 256 bytes while run task ids cap at 128, so the driver
//!   must mint/validate an equal join key within the 128-byte intersection.

use std::sync::Arc;

use advance_shared_types::mailbox::{MsgError, RunCompletionSink};

use crate::manager::AwaitSessionManagerImpl;

/// MODULE-007 provider of [`RunCompletionSink`] (CONTRACT-184). Wraps an
/// `Arc<AwaitSessionManagerImpl>`; see the module docs for the resolution
/// contract, join key, and the sync→async bridge.
pub struct ComponentResolutionSink {
    manager: Arc<AwaitSessionManagerImpl>,
}

impl ComponentResolutionSink {
    /// Build a sink over an existing await-session manager. Wire it into
    /// MODULE-008 via `RunManager::with_run_completion_sink(Arc::new(sink))`.
    pub fn new(manager: Arc<AwaitSessionManagerImpl>) -> Self {
        Self { manager }
    }
}

impl RunCompletionSink for ComponentResolutionSink {
    fn on_run_completed(
        &self,
        _controller_agent: &str,
        _run_id: &str,
        task_id: &str,
        outcome: &str,
    ) -> Result<(), MsgError> {
        // Wave-24 `req270-sink` (DoS/scale — MODULE-007 §3.6:1100 prereq 4).
        // Colon short-circuit: a `ComponentFinished` `component_id` is admitted
        // `is_safe_opaque_id` (colon-FREE), so a `task_id` containing `:` can NEVER
        // join a parked slot. The only production-code `complete_run` callsite outside
        // the unwired WIT surface is auto-settle, whose session registry is currently
        // dormant; if activated, it settles `auto:{agent}` (colon) runs. Skip the
        // detached spawn + full-map scan for those ids. A colon-free `task_id`
        // still spawns + scans exactly as before (may or may not match).
        if task_id.contains(':') {
            return Ok(());
        }
        // Join key: the completed run's `task_id` IS the awaited `component_id`.
        let component_id = task_id.to_string();
        let outcome = outcome.to_string();
        let manager = Arc::clone(&self.manager);
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                // Fire-and-forget: detach the JoinHandle. The async resolution
                // calls `on_reply`, which fires the parked session's oneshot.
                handle.spawn(async move {
                    let _ = manager
                        .resolve_component_finished(&component_id, &outcome)
                        .await;
                });
                Ok(())
            }
            Err(_) => {
                // No tokio runtime in scope — best-effort no-op (never panic).
                // Defense-in-depth (adversarial r10): escape + length-cap the id
                // in the log so a future direct caller passing control chars can't
                // forge log lines (the RunManager path validates task_id, but this
                // public port does not re-validate). Mirrors on_reply's
                // sanitize-on-log discipline.
                let safe_id: String = component_id.escape_default().take(128).collect();
                eprintln!(
                    "ComponentResolutionSink::on_run_completed: no tokio runtime in scope; \
                     skipping ComponentFinished resolution for component_id={safe_id}"
                );
                Ok(())
            }
        }
    }
}

//! await-leg B-2 (2026-06-22) — production composition glue for the
//! `await-replies` ↔ MODULE-008 Run suspend/resume lifecycle. Closes the named
//! MODULE-007 §3.6 R9 production-daemon-wiring gap.
//!
//! The [`RunManagerSuspendSink`] ADAPTER (impl of the reply-tracker-local
//! `RunSuspendSink` PORT over the real [`RunManager`]) was previously test-side
//! only (`crates/system-acceptance/tests/step4b_support`); R9 names its promotion
//! to the cli composition root. cli is the only crate that depends on BOTH
//! `advance-reply-tracker` (for the port) AND `advance-run-manager` (for the
//! adapter target), so the adapter lives here — not in reply-tracker (which
//! deliberately takes no run-manager dependency).
//!
//! [`build_await_messaging_chain`] constructs the per-process messaging chain
//! (`MailboxStore` + `MailboxDispatcherImpl` + `AwaitSessionManagerImpl`) that the
//! `await-replies`/`heartbeat` host-fns delegate to. await-leg B-4a (2026-06-22)
//! added `messaging` to the guest CapRequest injector
//! (`agent_config::KNOWN_CAPABILITIES`), so a `messaging`-declaring guest now LINKS
//! the interface and its `await-replies` parks the Run through this chain's suspend
//! sink. DORMANT only for shipped agents (no shipped guest imports `agent-messaging`,
//! no shipped `.agent/config.yaml` declares `messaging:true`).

use std::sync::Arc;

use advance_messaging::{
    AgentIdBridge, MailboxDispatcher, MailboxDispatcherImpl, MailboxStore, TurnMailboxDispatchPort,
};
use advance_reply_tracker::{
    AwaitSessionManagerImpl, AwaitSessionManagerRef, ManagerOptions, RunSuspendSink,
};
use advance_run_manager::{RunId, RunManager};
use advance_shared_types::agent_tree::{AgentTreeReader, AgentTreeSnapshot};
use advance_shared_types::await_session::{AwaitSessionRef, SessionId};
use advance_shared_types::traits::EventBusEmit;

/// Production ADAPTER for the reply-tracker-local `RunSuspendSink` PORT: drives the
/// MODULE-008 Run suspend/resume lifecycle by delegating to
/// [`RunManager::suspend_run`] / [`RunManager::resume_run_if_suspended`] (the
/// atomic Suspended-only await-completion resume). Built on the test-side
/// `step4b_support` adapter; this is its production-daemon home (R9). It adds a
/// **session-scoped resume guard** (audit r4) the bare test adapter lacks — see
/// [`RunSuspendSink::on_await_resolve`] below.
pub struct RunManagerSuspendSink {
    rm: Arc<RunManager>,
}

impl RunManagerSuspendSink {
    pub fn new(rm: Arc<RunManager>) -> Self {
        Self { rm }
    }
}

impl RunSuspendSink for RunManagerSuspendSink {
    fn on_await_start(&self, run_id: &str, session_id: &SessionId) -> bool {
        // `RunId::from_string` takes an owned String; the port hands us a `&str`.
        match RunId::from_string(run_id.to_string()) {
            Ok(rid) => self.rm.suspend_run(&rid, &session_id.0).is_ok(),
            Err(_) => false,
        }
    }

    fn on_await_resolve(&self, run_id: &str, session_id: &SessionId) {
        let Ok(rid) = RunId::from_string(run_id.to_string()) else {
            return;
        };
        // Session-scoped guard (audit r4): resume ONLY if THIS session is the one the
        // run is currently parked on (`WitRunState.root_await == session_id`). Without
        // it, the status-only `resume_run_if_suspended` would resume ANY currently
        // Suspended run — so an OLDER await resolving late could clear a NEWER
        // suspension's `root_await` on the same run and flip it Active incorrectly.
        // The subsequent resume is STILL atomic Suspended-only, so a concurrent
        // operator pause/cancel that already left Suspended is never clobbered (the
        // Backbone Step 4b resume-vs-pause race fix is preserved). Best-effort: a
        // session mismatch, a `run_status` error, a no-op `Ok(false)`, or a resume
        // error are all non-fatal for the await path.
        //
        // RESIDUAL (audit r5, accepted): the check (`run_status` read lock) and the
        // resume (`resume_run_if_suspended` write lock) are two separate RunManager
        // calls, so a microsecond TOCTOU remains — root_await could flip from this
        // session to a NEWER one between the read and the resume. This is UNREACHABLE
        // in the current model: a run has ONE controller fiber, parked at exactly one
        // await; an operator `resume_run("manual")` flips run status but does NOT
        // unpark that fiber, so the controller cannot issue a concurrent second await
        // on the same run — there is never an S1-parked-while-S2-suspended interleave.
        // B-4a (2026-06-22) activated the path (guests can now drive await-replies),
        // but the interleave above is still UNREACHABLE by the single-controller fiber
        // argument, and shipped agents stay dormant. The fully atomic fix is a
        // session-scoped resume INSIDE RunManager's single write-lock critical section
        // (`resume_run_if_suspended` checking root_await==session) — a MODULE-008 change
        // OUT of B-4a's (cli + reply-tracker) scope, kept as a Wave-11 B-4b item (B-4b
        // owns the ledger/SYS-AC flips and may land the run-manager atomic fix).
        let parked_on_this_session = self
            .rm
            .run_status(&rid)
            .map(|s| s.root_await.as_deref() == Some(session_id.0.as_str()))
            .unwrap_or(false);
        if parked_on_this_session {
            let _ = self
                .rm
                .resume_run_if_suspended(&rid, "await_complete".to_string());
        }
    }
}

/// Build the production `await-replies` messaging chain: a per-process
/// [`MailboxStore`] + [`MailboxDispatcherImpl`] (over the shared agent `tree`)
/// feeding an [`AwaitSessionManagerImpl`]. Returns the manager (for host-fn
/// registration via `register_reply_tracker_host_fns_with_suspend_sink`) and an
/// `AwaitSessionRef` (for [`RunManager::with_await_session_ref`], which enables the
/// pause/cancel-while-suspended close cascade — prod parity for SYS-AC-016).
///
/// **EventBus ownership (current)**: the manager owns one direct clone via
/// `ManagerOptions.event_emitter` (for `orchestration.await_idle_timeout`) and one
/// transitive clone through the `MailboxDispatcherImpl` installed with
/// `.with_event_bus`. At the `wiring.rs` call site the same manager allocation is
/// retained by registry-held host functions, the `RunManager` await reference and
/// `ComponentResolutionSink`, and the additive `await_manager_handle`. Therefore the
/// `builder.build()` error path MUST drop `run_manager`, then `registry`, then
/// `await_manager_handle` before `shutdown_event_bus_on_error` attempts
/// `Arc::try_unwrap`; success moves the latter handle into `WiringHandles`.
/// Wave-20 Lane `messagingabi`: also accepts an optional [`AgentIdBridge`] (the
/// colon/bare equivalence resolver — seam (a)/(b)) and RETURNS the shared concrete
/// [`MailboxDispatcherImpl`] so the cli composition root can register the `notify`
/// host-fns against the SAME dispatcher (one store, one tree, one bridge). `None`
/// bridge → byte-identical to the pre-Wave-20 behaviour.
///
/// **W24 `perchild-daemon-2` (SYS-AC-280 + SYS-AC-282)**: two seam-d′ arms, both
/// active ONLY on this messaging/per-child path (the chain is built only under
/// `declares_messaging`, `wiring.rs` — so the default no-messaging daemon is
/// unaffected): (1) the dispatcher is now built WITH `.with_event_bus(event_bus)`
/// so the wired per-child deliveries emit `msg.received` + `delivery_latency_ms`
/// (the PRD §15.3.3 SLO signal — M019 owns the `mailbox.delivery_slow` breach
/// mirror, so we do not double-publish); (2) `ManagerOptions.agent_tree` is now
/// wired (was prod-dormant `None`), ARMING the await-deadlock ancestry gate on the
/// daemon — safe after the `forms_cycle` direction fix (deadlock.rs walks upward
/// from the CALLER, so a downward parent→child delegation admits and only an
/// upward await-to-ancestor is rejected). `None` `agent_tree` → the gate stays
/// skipped (the non-arming path).
pub fn build_await_messaging_chain(
    store: Arc<MailboxStore>,
    tree: Arc<dyn AgentTreeReader>,
    event_bus: Arc<dyn EventBusEmit>,
    id_bridge: Option<Arc<AgentIdBridge>>,
    agent_tree: Option<Arc<dyn AgentTreeSnapshot>>,
) -> (
    Arc<AwaitSessionManagerImpl>,
    Arc<dyn AwaitSessionRef>,
    Arc<MailboxDispatcherImpl>,
) {
    let mut disp = MailboxDispatcherImpl::new(store, tree);
    // Wave-23 `perchild-daemon-1` (C1 fix): the SAME bridge feeds both the
    // dispatcher (target resolution) AND the manager's `ManagerOptions.id_bridge`
    // (genuine-send `from` canonicalization), so a real root send stamps the
    // canonical `agent:default` — not the mechanical `agent:default-agent` that
    // would fail the parent→child adjacency check. `None` → byte-identical.
    let manager_bridge = id_bridge.clone();
    if let Some(bridge) = id_bridge {
        disp = disp.with_id_bridge(bridge);
    }
    // W24 seam d′ (SYS-AC-282 SLO): arm the dispatcher's event bus so the wired
    // per-child `deliver`/`reply`/`deliver_notify` emit `msg.received` carrying
    // `delivery_latency_ms` (the p99<1s witness signal). Active on this messaging
    // path only.
    disp = disp.with_event_bus(event_bus.clone());
    let dispatcher_concrete = Arc::new(disp);
    let dispatcher: Arc<dyn MailboxDispatcher> = dispatcher_concrete.clone();
    let protected_dispatch: Arc<dyn TurnMailboxDispatchPort> = dispatcher_concrete.clone();
    let manager = Arc::new(
        AwaitSessionManagerImpl::new(
            dispatcher,
            ManagerOptions {
                event_emitter: Some(event_bus),
                id_bridge: manager_bridge,
                // W24 seam d′ (SYS-AC-280): arm the await-deadlock ancestry gate on the
                // daemon (was prod-dormant `None`); safe after the `forms_cycle` fix.
                agent_tree,
                ..ManagerOptions::default()
            },
        )
        .with_turn_mailbox_dispatch(protected_dispatch),
    );
    let aref: Arc<dyn AwaitSessionRef> =
        Arc::new(AwaitSessionManagerRef::new(Arc::clone(&manager)));
    (manager, aref, dispatcher_concrete)
}

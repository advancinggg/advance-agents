//! Wave-18 — the production `CrashCascadeSink` (MODULE-001 composition root).
//!
//! [`build_crash_cascade_sink`] is the SOLE production impl of the scheduler's
//! [`CrashCascadeSink`] seam (`scheduler/src/hook.rs`). It is the bridge that turns a
//! child guest trap (surfaced by `AgentLoopDriverImpl::handle_trap` on
//! `TrapError::Crash`) into a real parent crash-report by REUSING the cap-lifecycle
//! `DefaultTerminateController::handle_crash` → `notify_parent_crash` cascade (it does
//! NOT re-implement the cascade — this un-orphans `handle_crash`, which previously had
//! no production caller; see MODULE-005 §3.7).
//!
//! ## Two-id-space bridge (MODULE-001 §3.8)
//! The scheduler hands `handle_trap` the COLON-keyed messaging id the agent is served
//! under (`agent:{name}`); cap-lifecycle's `AgentTreeStore` is BARE-keyed
//! (`validate_agent_id` rejects a colon). The sink bridges the two at exactly this
//! seam, changing NO cap-lifecycle source:
//! - it strips the `agent:` prefix → bare child for `handle_crash` (which does
//!   `set_status(bare, Failed)` + `parent_of` over the bare tree), then
//! - `notify_parent_crash` re-derives the parent's served mailbox key from the bare
//!   parent id via an injected **key-resolver** `Fn(&str) -> String` (NOT a hardcoded
//!   `agent:{bare}` prefix — the production root is bare `default-agent` served at
//!   colon `agent:default`, a SPECIAL mapping; the resolver makes the served-key
//!   policy the caller's responsibility).
//!
//! **W24 perchild-daemon-2 (seam f): NOW WIRED into `advance start`** — built in
//! `wiring.rs` with the root-aware resolver, attached to the ROOT loop
//! (`start.rs::try_spawn_agent_loop → with_crash_cascade`) AND every spawned/boot child
//! loop (`PerChildLoopManager::with_crash_sink`) on the messaging/lifecycle path; still
//! unwired for the DEFAULT no-messaging daemon (no tree/store). The daemon no longer
//! serves the single root only either (Wave-23 seam-d runtime children + this wave's
//! `serve_existing_children` boot leg). Also witnessed via the system-acceptance harness
//! driving the production `AgentLoopDriverImpl` with a real trapping guest (drive-prod-fn
//! precedent 098/101/109/202), flipping SYS-AC-030.

use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use advance_messaging::MailboxStore;
use advance_scheduler::CrashCascadeSink;
use advance_shared_types::mailbox::{Message, MessageKind};
use cap_lifecycle::{
    AgentTreeStore, DefaultTerminateController, GrantCascadeRevoke, LifecycleError, MailboxCascade,
    RunCascade, TerminateController, WorkspaceCleanup,
};

/// Build the production crash-cascade sink.
///
/// `tree` is the SAME `AgentTreeStore` the spawn/await wiring records nodes into
/// (`DefaultTerminateController::new` takes it by value; `AgentTreeStore` is `Clone`
/// over an interior `Arc`, so the clone shares state). `mailbox_store` is the shared
/// Step-7 `MailboxStore` the served loops read. `key_resolver` maps a bare
/// tree-parent id to the served mailbox key the parent polls (e.g. the symmetric
/// `|b| format!("agent:{b}")` for spawned children).
pub fn build_crash_cascade_sink(
    tree: AgentTreeStore,
    mailbox_store: Arc<MailboxStore>,
    key_resolver: impl Fn(&str) -> String + Send + Sync + 'static,
) -> Arc<dyn CrashCascadeSink> {
    let mailbox: Arc<dyn MailboxCascade> = Arc::new(CliCrashMailboxCascade {
        store: mailbox_store,
        resolver: Arc::new(key_resolver),
    });
    let controller = DefaultTerminateController::new(
        tree,
        Arc::new(NoopGrantCascade),
        mailbox,
        Arc::new(NoopRunCascade),
        Arc::new(NoopWorkspaceCleanup),
    );
    Arc::new(CrashCascadeSinkImpl { controller })
}

/// The `CrashCascadeSink` impl: strip colon→bare and drive the real cap-lifecycle
/// `handle_crash`. Any `Err` (e.g. an absent node → `NotFound`, or a root parent →
/// `Ok` with no message) is swallowed — a crash cascade must NEVER panic the serve
/// loop (and on a root/None parent `handle_crash` returns `Ok` with no notification).
struct CrashCascadeSinkImpl {
    controller: DefaultTerminateController,
}

impl CrashCascadeSink for CrashCascadeSinkImpl {
    fn handle_crash(&self, agent_id: &str, reason: &str) {
        let bare = agent_id.strip_prefix("agent:").unwrap_or(agent_id);
        if let Err(e) = self.controller.handle_crash(bare, reason) {
            eprintln!(
                "build_crash_cascade_sink: handle_crash({bare}) → {e:?} (swallowed — \
                 crash cascade is best-effort, must not panic the serve loop)"
            );
        }
    }
}

/// cli colon-aware `MailboxCascade`: delivers the AC-18 `component.terminated` System
/// message to the parent's SERVED mailbox key (resolved from the bare tree-parent id
/// by the injected resolver). Mirrors the cap-lifecycle `MailboxFlushCascade`
/// message shape exactly, differing ONLY in the resolver-mapped delivery key — so the
/// colon/bare bridge lives at the cli seam, not in colon-rejecting cap-lifecycle.
struct CliCrashMailboxCascade {
    store: Arc<MailboxStore>,
    resolver: Arc<dyn Fn(&str) -> String + Send + Sync>,
}

impl MailboxCascade for CliCrashMailboxCascade {
    fn flush_mailbox(&self, _agent_id: &str) -> Result<(), LifecycleError> {
        // `handle_crash` never invokes `flush_mailbox` (only `notify_parent_crash`),
        // so the crash sink leaves the mailbox untouched. No-op.
        Ok(())
    }

    fn notify_parent_crash(
        &self,
        parent_id: &str,
        child_id: &str,
        reason: &str,
    ) -> Result<(), LifecycleError> {
        // `parent_id` + `child_id` arrive BARE (handle_crash passes the tree ids
        // through). Map the bare parent → its served mailbox key; the child stays bare
        // in the payload (the parent reads `child` as the bare tree id).
        let key = (self.resolver)(parent_id);
        let mb = self.store.get_or_create(&key).map_err(|e| {
            LifecycleError::CascadePartial(format!("get parent mailbox {key}: {e:?}"))
        })?;
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let payload = serde_json::json!({
            "event": "component.terminated",
            "child": child_id,
            "reason": reason,
        })
        .to_string()
        .into_bytes();
        let msg = Message {
            id: format!("sys-crash:{child_id}:{nanos}"),
            kind: MessageKind::System,
            from: "system".to_string(),
            to: key.clone(),
            payload,
            context: None,
            timestamp: SystemTime::now(),
            origin: None,
        };
        mb.deliver(msg).map_err(|e| {
            LifecycleError::CascadePartial(format!("deliver crash notice to {key}: {e:?}"))
        })
    }
}

// --- No-op cascades: `handle_crash` only touches the tree + the MailboxCascade, so
// the grant/run/workspace seams are never invoked on the crash path. Trivial Ok impls
// keep `DefaultTerminateController::new`'s 5-arg shape satisfied without pulling
// cap-grant / run-manager wiring into the crash sink. ---

struct NoopGrantCascade;
impl GrantCascadeRevoke for NoopGrantCascade {
    fn revoke_for_agent(&self, _agent_id: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
}

struct NoopRunCascade;
impl RunCascade for NoopRunCascade {
    fn ensure_run(&self, _agent_id: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn cancel_run(&self, _agent_id: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
}

struct NoopWorkspaceCleanup;
impl WorkspaceCleanup for NoopWorkspaceCleanup {
    fn remove_sub_workspace(&self, _workspace_path: &Path) -> Result<(), LifecycleError> {
        Ok(())
    }
}

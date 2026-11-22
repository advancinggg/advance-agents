//! Slice C — terminate-cascade (MODULE-005 AC-03/18/20, REQ-030/066/270).
//!
//! `TerminateController` drives a TOP-DOWN live-tree freeze followed by a
//! single removal snapshot and a post-order cascade. The terminate↔spawn
//! race is closed TRANSITIVELY for every descendant by
//! `AgentTreeStore::insert_child`'s parent-status guard (atomic with
//! `set_status` under the same write-lock; each node is frozen BEFORE its
//! children are read — see MODULE-005 §2.7 terminate-child Flow).
//!
//! All cascade hooks are sync dependency-inversion seams with NO library-side
//! impl (Slice A `SpawnerSubsetGate` / Slice B `WorkspaceRollbackGate`
//! discipline); tests provide recorder impls.

use std::sync::Arc;

use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentStatus, AgentTreeReader, AgentTreeSnapshot,
};

use crate::error::LifecycleError;
use crate::identifier::validate_agent_id;
use crate::tree::AgentTreeStore;

/// Cascade: revoke the terminated agent's own grants.
pub trait GrantCascadeRevoke: Send + Sync {
    /// Contract: revoke ONLY grants whose `grantee == agent_id`. Do NOT
    /// recursively revoke grants delegated to descendants — those cascade
    /// with each descendant's own terminate (post-order guarantees the
    /// descendant terminated first).
    fn revoke_for_agent(&self, agent_id: &str) -> Result<(), LifecycleError>;
}

/// Cascade: mailbox flush + parent crash notification.
pub trait MailboxCascade: Send + Sync {
    fn flush_mailbox(&self, agent_id: &str) -> Result<(), LifecycleError>;
    /// AC-18 — push a crash-notification message into the parent's mailbox.
    fn notify_parent_crash(
        &self,
        parent_id: &str,
        child_id: &str,
        reason: &str,
    ) -> Result<(), LifecycleError>;
}

/// Cascade: run lifecycle (AC-20 surface `ensure_run` + teardown).
pub trait RunCascade: Send + Sync {
    fn ensure_run(&self, agent_id: &str) -> Result<(), LifecycleError>;
    fn cancel_run(&self, agent_id: &str) -> Result<(), LifecycleError>;
}

/// Cascade: remove an ephemeral Sub's `/.sub/{uuid}/` workspace (AC-03).
pub trait WorkspaceCleanup: Send + Sync {
    fn remove_sub_workspace(&self, workspace_path: &std::path::Path) -> Result<(), LifecycleError>;
}

/// Cascade (M011-AC-29): archive a terminating Sub's memory into a surviving
/// parent's `.agent/memory/archive/<sub_id>/` BEFORE its workspace is removed —
/// so sub-agent memory is PRESERVED (not deleted) and remains visible to the
/// parent's memory load (cap-memory's level-2 `archive/<sub_id>/` scan).
/// Injected as `Option` on `DefaultTerminateController` (default `None` =
/// byte-identical pre-existing teardown), so existing terminate behaviour is
/// unchanged unless an archiver is wired in.
pub trait MemoryArchiver: Send + Sync {
    /// Copy/merge the Sub `sub_id`'s on-disk memory (under `sub_workspace`) into
    /// `parent_workspace`'s `.agent/memory/archive/<sub_id>/knowledge.jsonl`.
    /// Best-effort at the cascade call-site: an `Err` is swallowed and does NOT
    /// abort termination (teardown correctness wins).
    fn archive_sub_memory(
        &self,
        sub_id: &str,
        sub_workspace: &std::path::Path,
        parent_workspace: &std::path::Path,
    ) -> Result<(), LifecycleError>;

    /// MODULE-010 D4 (owner decision 2026-11-17: a terminated Sub or Child is archived to
    /// its parent, its history as its knowledge) — move the task history of the terminated
    /// agent `agent_id` (the `.agent/tasks/` of `agent_workspace`: the turn logs, summaries
    /// and turn indexes of its tasks, PRD §11.2) to `parent_workspace`'s
    /// `.agent/tasks/archived-agents/<agent_id>/`. Best effort at the cascade call-site, as
    /// [`Self::archive_sub_memory`] is. The default archives nothing.
    fn archive_agent_tasks(
        &self,
        agent_id: &str,
        agent_workspace: &std::path::Path,
        parent_workspace: &std::path::Path,
    ) -> Result<(), LifecycleError> {
        let _ = (agent_id, agent_workspace, parent_workspace);
        Ok(())
    }
}

/// Cascade (seam f — MODULE-001-AC-22): stop a terminating agent's per-agent
/// SERVE loop, then tear down its dynamic routing + mailbox. `terminate_child`
/// operates on the BARE tree, but the loop-registry / colon routing / mailbox are
/// COLON-keyed, so the impl (the cli-spine `PerChildLoopManager`-backed adapter)
/// resolves bare→colon internally. Injected as `Option` on
/// `DefaultTerminateController` (default `None` = byte-identical pre-existing
/// teardown — there is no serve loop to tear down when unwired), so existing
/// terminate behaviour is unchanged unless a loop cascade is wired in.
///
/// Two calls per node (MODULE-005 terminate-child flow): [`Self::stop_loop`] for
/// every node of the subtree, in removal order, before the cascade's first step
/// that can fail (each node's run cancel, mailbox flush, grant revoke and workspace
/// removal); then [`Self::abort_loop`] for each node once those steps of that node
/// have succeeded, right before its tree removal. A cascade that stops part-way
/// leaves no loop serving a half-removed agent, and no stopped loop consumes a message
/// mid-termination; a node it leaves in the tree keeps its routing and records — and its
/// mailbox, unless the cascade's flush of it ran before the step that failed — for a
/// retry to remove.
pub trait LoopCascade: Send + Sync {
    /// Stop `agent_id`'s serve loop (if any), and tear nothing down: its routing, its
    /// mailbox and what the agent is remembered by stay as they are until
    /// [`Self::abort_loop`]. A turn under way is cut off. `agent_id` is the BARE tree id —
    /// the impl maps it to the colon serve key.
    fn stop_loop(&self, agent_id: &str);
    /// Tear down what `agent_id`'s serve loop leaves: the loop itself (stopped here
    /// when [`Self::stop_loop`] did not stop it), its routing and mailbox, and what
    /// the agent is remembered by. `agent_id` is the BARE tree id.
    fn abort_loop(&self, agent_id: &str);
    /// Held by the cascade for the whole of one terminate — from its start, before it marks
    /// the subtree, to its end, after its last [`Self::abort_loop`], however it ends — and
    /// dropped then: an implementation that lets go of what a teardown needs (a shutdown)
    /// waits for it. `None` by default.
    fn terminate_scope(&self) -> Option<Box<dyn Send>> {
        None
    }
}

pub trait TerminateController: Send + Sync {
    fn terminate_child(&self, caller_id: &str, child_id: &str) -> Result<(), LifecycleError>;

    fn terminate_agent(&self, caller_id: &str, agent_id: &str) -> Result<(), LifecycleError>;

    /// AC-18 — parent-notification + tree state flip. MUST NOT persist agent
    /// state (M005 never had `new_state` to write; the agent-loop
    /// state-journal is MODULE-014 `handle_trap`, out-of-M005-scope). A crash
    /// of an agent inside a terminate — marked `Terminated`, or below an agent
    /// so marked — changes nothing and notifies no one.
    fn handle_crash(&self, crashed_agent_id: &str, reason: &str) -> Result<(), LifecycleError>;
}

#[derive(Clone)]
pub struct DefaultTerminateController {
    tree: AgentTreeStore,
    grant: Arc<dyn GrantCascadeRevoke>,
    mailbox: Arc<dyn MailboxCascade>,
    run: Arc<dyn RunCascade>,
    workspace: Arc<dyn WorkspaceCleanup>,
    /// M011-AC-29 archive-on-cleanup port. `None` (the `new()` default) →
    /// pre-existing teardown behaviour byte-identical (no archive step).
    memory_archiver: Option<Arc<dyn MemoryArchiver>>,
    /// seam-f per-child serve-loop teardown port. `None` (the `new()` default) →
    /// pre-existing teardown byte-identical (no serve loop exists to tear down).
    loop_cascade: Option<Arc<dyn LoopCascade>>,
}

impl DefaultTerminateController {
    pub fn new(
        tree: AgentTreeStore,
        grant: Arc<dyn GrantCascadeRevoke>,
        mailbox: Arc<dyn MailboxCascade>,
        run: Arc<dyn RunCascade>,
        workspace: Arc<dyn WorkspaceCleanup>,
    ) -> Self {
        Self {
            tree,
            grant,
            mailbox,
            run,
            workspace,
            memory_archiver: None,
            loop_cascade: None,
        }
    }

    /// Inject the M011-AC-29 archive-on-cleanup port (additive builder; the
    /// 5-arg `new()` signature is unchanged). When set, a terminating Sub's
    /// memory is archived into its parent's `.agent/memory/archive/<sub_id>/`
    /// BEFORE its workspace is removed.
    pub fn with_memory_archiver(mut self, archiver: Arc<dyn MemoryArchiver>) -> Self {
        self.memory_archiver = Some(archiver);
        self
    }

    /// Inject the seam-f per-child serve-loop teardown port (additive builder; the
    /// 5-arg `new()` signature is unchanged). When set, `terminate_child` stops the
    /// serve loop of every node of the subtree before the cascade's first step that
    /// can fail, and tears each node's loop down — routing, mailbox, records — once
    /// that node's steps have succeeded ([`LoopCascade`]).
    pub fn with_loop_cascade(mut self, loop_cascade: Arc<dyn LoopCascade>) -> Self {
        self.loop_cascade = Some(loop_cascade);
        self
    }

    pub fn tree(&self) -> &AgentTreeStore {
        &self.tree
    }

    /// Post-order DFS over the captured snapshot's `children_of`, rooted at
    /// `root` — grandchildren first, `root` last (so `tree.remove`'s
    /// leaf-only invariant holds at every step).
    fn post_order(
        snap: &advance_shared_types::agent_tree::AgentTreeSnapshotData,
        root: &AgentId,
    ) -> Vec<AgentId> {
        let mut out = Vec::new();
        // Iterative post-order: (node, expanded?).
        let mut stack: Vec<(AgentId, bool)> = vec![(root.clone(), false)];
        while let Some((node, expanded)) = stack.pop() {
            if expanded {
                out.push(node);
                continue;
            }
            stack.push((node.clone(), true));
            if let Some(kids) = snap.children_of.get(&node) {
                for k in kids {
                    stack.push((k.clone(), false));
                }
            }
        }
        out
    }
}

impl DefaultTerminateController {
    /// Hand the task history of the terminated `id` to its parent, when an archiver is wired
    /// and `id` is a Sub or a Child (MODULE-010 D4). `false` only when it could not be
    /// handed over: the failure is logged, and the history stays in the agent's workspace.
    fn archive_history(
        &self,
        snap: &advance_shared_types::agent_tree::AgentTreeSnapshotData,
        id: &AgentId,
        kind: Option<&AgentKind>,
    ) -> bool {
        let Some(archiver) = &self.memory_archiver else {
            return true;
        };
        if !matches!(kind, Some(AgentKind::Sub | AgentKind::Child)) {
            return true;
        }
        let Some(node) = snap.nodes.iter().find(|n| &n.id == id) else {
            return true;
        };
        let parent_ws = node.parent.as_ref().and_then(|pid| {
            snap.nodes
                .iter()
                .find(|n| &n.id == pid)
                .map(|n| n.workspace_path.clone())
        });
        let Some(parent_ws) = parent_ws else {
            eprintln!(
                "cap-lifecycle: no parent workspace found for {:?} during the archive of its \
                 task history; the history stays in its workspace",
                id.0
            );
            return false;
        };
        match archiver.archive_agent_tasks(&id.0, &node.workspace_path, &parent_ws) {
            // A history the archiver left — where an older release kept it, say — stays,
            // and so does a Sub's workspace.
            Ok(()) if crate::task_history_left(&node.workspace_path) => {
                eprintln!(
                    "cap-lifecycle: {:?} still holds task history after its archive; it stays in \
                     its workspace",
                    id.0
                );
                false
            }
            Ok(()) => true,
            Err(e) => {
                eprintln!(
                    "cap-lifecycle: archive_agent_tasks failed for {:?}; its task history \
                     stays in its workspace: {e}",
                    id.0
                );
                false
            }
        }
    }
}

impl TerminateController for DefaultTerminateController {
    fn terminate_child(&self, caller_id: &str, child_id: &str) -> Result<(), LifecycleError> {
        // seam (f): held until this returns, however it returns — from before the subtree is
        // marked, so a shutdown that comes while it is marked waits for the whole terminate:
        // what lets go of the stores a teardown needs waits for it.
        let _scope = self
            .loop_cascade
            .as_ref()
            .and_then(|lc| lc.terminate_scope());
        if validate_agent_id(caller_id).is_err() {
            return Err(LifecycleError::PermissionDenied(format!(
                "invalid caller id: {caller_id}"
            )));
        }
        if validate_agent_id(child_id).is_err() {
            return Err(LifecycleError::NotFound(format!(
                "invalid child id: {child_id}"
            )));
        }
        let caller = AgentId(caller_id.to_string());
        let child = AgentId(child_id.to_string());

        // Permission check FIRST — a non-parent must not be able to freeze
        // an arbitrary subtree via the set_status call below.
        let snap = self.tree.snapshot();
        if !snap.parent_of.contains_key(&child) {
            return Err(LifecycleError::NotFound(format!("agent {child_id}")));
        }
        match snap.parent_of.get(&child).and_then(|p| p.clone()) {
            Some(p) if p == caller => {}
            _ => {
                return Err(LifecycleError::PermissionDenied(format!(
                    "{caller_id} is not the parent of {child_id}"
                )));
            }
        }

        // Top-down freeze on the LIVE tree (closes the terminate↔spawn race
        // TRANSITIVELY, not just at the subtree root). Freezing a node makes
        // `insert_child` reject new children under it — and because
        // `set_status` and `insert_child` serialize on the same write-lock,
        // reading a node's children AFTER freezing it yields the FINAL child
        // set: a racing `spawn_child(parent=N)` is either ordered before
        // `set_status(N, Terminated)` (then N's child appears in
        // `children_of(N)` and is frozen+included) or after it (atomically
        // rejected). Each node is frozen BEFORE its children are enumerated
        // for recursion, so no concurrently-spawned descendant can escape the
        // removal set (no orphaned, un-revoked, still-running agent).
        let mut stack = vec![child.clone()];
        while let Some(id) = stack.pop() {
            // `set_status` fails ONLY when the node is absent (its sole error
            // path). A node that vanished mid-freeze was concurrently
            // `tree.remove`'d — and `tree.remove` is leaf-only, so a vanished
            // node had NO children: there is nothing to freeze and no
            // descendant that could escape. Tolerate it (skip, do not
            // recurse) — matching the original Slice-C robustness — rather
            // than fail-fast and abandon a partially-frozen, un-cascaded
            // subtree (which would itself manufacture the orphaned/
            // un-revoked state this freeze exists to prevent). Any node that
            // is still present is frozen here and will be cascaded below.
            if self.tree.set_status(&id, AgentStatus::Terminated).is_err() {
                continue;
            }
            for c in self.tree.children_of(&id.0) {
                stack.push(AgentId(c));
            }
        }

        // Whole subtree now frozen + topology stable → snapshot for the
        // post-order removal sequence (children-before-parent so
        // `tree.remove`'s leaf-only invariant holds at every step).
        let snap = self.tree.snapshot();
        let removal_order = Self::post_order(&snap, &child);

        // seam (f): stop every serve loop of the subtree before the first step below that
        // can fail (MODULE-005 terminate-child flow). Each of those steps can stop the
        // cascade part-way (`?`); a loop still running then would serve on for an agent
        // whose run, mailbox or grants are half torn down, and for the nodes after the
        // failing one, which stay in the tree marked terminated. Stopping cannot fail and
        // tears nothing down: what a node's loop leaves — its routing, mailbox and records —
        // is torn down only once that node's own steps have succeeded (`abort_loop` below),
        // so a node a failed terminate leaves in the tree keeps it, but for what the steps
        // for that node that ran removed (its runs; its mailbox's messages, once flushed),
        // and a retry removes the node. No stopped loop consumes a message mid-termination.
        if let Some(lc) = &self.loop_cascade {
            for id in &removal_order {
                lc.stop_loop(&id.0);
            }
        }

        // Post-order cascade + remove (leaf-guaranteed). Every descendant is
        // in `removal_order` (the top-down freeze above guarantees no escapee),
        // so every node's run is cancelled, mailbox flushed, and grants
        // revoked — no privilege retention.
        for id in &removal_order {
            let kind = snap
                .nodes
                .iter()
                .find(|n| &n.id == id)
                .map(|n| n.kind.clone());
            self.run.cancel_run(&id.0)?;
            self.mailbox.flush_mailbox(&id.0)?;
            self.grant.revoke_for_agent(&id.0)?;
            // MODULE-010 D4: a terminated Sub or Child hands its task history to its parent
            // ([`MemoryArchiver::archive_agent_tasks`]) before a Sub's workspace is removed —
            // and before the Client API removes a Child's `.agent/`, once the cascade is done.
            // Post-order: what a descendant handed over is in this agent's history already,
            // so it moves on with it. As with the memory archive, a Sub whose history could
            // not be archived keeps its workspace; a Child's history stays where it was (the
            // Client API delete keeps the `.agent/` of a Child whose history is still there,
            // `task_history_left`).
            let history_ok = self.archive_history(&snap, id, kind.as_ref());
            if kind == Some(AgentKind::Sub) {
                if let Some(node) = snap.nodes.iter().find(|n| &n.id == id) {
                    // M011-AC-29: archive this Sub's memory into its parent's
                    // `.agent/memory/archive/<sub_id>/` BEFORE the workspace is
                    // removed (archived, NOT deleted). When an archiver is wired,
                    // the workspace removal is GATED on archive success: a mid-copy
                    // archive error must NOT be followed by deletion — that would
                    // lose the un-archived entries and violate the AC's
                    // "archived, NOT deleted" promise on the error path. On archive
                    // error (or a missing parent — post-order keeps the parent alive
                    // until its children are removed, so this should not happen) we
                    // LOG and PRESERVE the sub workspace (its memory survives on disk
                    // for recovery); the tree node is still removed (logical
                    // termination) and the cascade is NOT aborted (teardown is not
                    // blocked forever on a persistent archive fault). The default
                    // (no archiver wired) path removes unconditionally —
                    // byte-identical to pre-Wave-17.
                    let archive_ok = match &self.memory_archiver {
                        None => true,
                        Some(archiver) => {
                            let parent_ws = node.parent.as_ref().and_then(|pid| {
                                snap.nodes
                                    .iter()
                                    .find(|n| &n.id == pid)
                                    .map(|n| n.workspace_path.clone())
                            });
                            match parent_ws {
                                Some(parent_ws) => {
                                    match archiver.archive_sub_memory(
                                        &id.0,
                                        &node.workspace_path,
                                        &parent_ws,
                                    ) {
                                        Ok(()) => true,
                                        Err(e) => {
                                            eprintln!(
                                                "cap-lifecycle: archive_sub_memory failed for sub {:?}; \
                                                 PRESERVING its workspace (memory NOT deleted) for recovery: {e}",
                                                id.0
                                            );
                                            false
                                        }
                                    }
                                }
                                None => {
                                    eprintln!(
                                        "cap-lifecycle: no parent workspace found for sub {:?} during \
                                         archive; PRESERVING its workspace (memory NOT deleted)",
                                        id.0
                                    );
                                    false
                                }
                            }
                        }
                    };
                    if archive_ok && history_ok {
                        self.workspace.remove_sub_workspace(&node.workspace_path)?;
                    }
                }
            }
            // seam (f): this node's steps that can fail have succeeded — tear down what its
            // stopped loop leaves (routing, mailbox, records) while the node still holds its
            // ids, right before it leaves the tree. The impl maps the BARE id to the colon
            // serve key and unfreezes-before-drain.
            if let Some(lc) = &self.loop_cascade {
                lc.abort_loop(&id.0);
            }
            self.tree
                .remove(id)
                .map_err(|e| LifecycleError::CascadePartial(format!("remove {:?}: {e}", id)))?;
        }
        Ok(())
    }

    fn terminate_agent(&self, caller_id: &str, agent_id: &str) -> Result<(), LifecycleError> {
        if validate_agent_id(agent_id).is_err() {
            return Err(LifecycleError::NotFound(format!(
                "invalid agent id: {agent_id}"
            )));
        }
        let snap = self.tree.snapshot();
        let id = AgentId(agent_id.to_string());
        let node = snap
            .nodes
            .iter()
            .find(|n| n.id == id)
            .ok_or_else(|| LifecycleError::NotFound(format!("agent {agent_id}")))?;
        if node.kind == AgentKind::Root {
            return Err(LifecycleError::PermissionDenied(
                "Root agent cannot be terminated".to_string(),
            ));
        }
        let parent = snap
            .parent_of
            .get(&id)
            .and_then(|p| p.clone())
            .ok_or_else(|| LifecycleError::PermissionDenied(format!("{agent_id} has no parent")))?;
        // Generalizes terminate-child; still requires the WIT caller to be
        // the actual parent.
        if parent.0 != caller_id {
            return Err(LifecycleError::PermissionDenied(format!(
                "{caller_id} is not the parent of {agent_id}"
            )));
        }
        self.terminate_child(&parent.0, agent_id)
    }

    fn handle_crash(&self, crashed_agent_id: &str, reason: &str) -> Result<(), LifecycleError> {
        if validate_agent_id(crashed_agent_id).is_err() {
            return Err(LifecycleError::NotFound(format!(
                "invalid agent id: {crashed_agent_id}"
            )));
        }
        let crashed = AgentId(crashed_agent_id.to_string());
        // Flip to Failed FIRST. If the node is absent, map to NotFound and
        // NEVER notify — keeps the observable state consistent (no crash
        // message for an agent that isn't `Failed`). Likewise a node inside a
        // terminate — marked `Terminated`, or below a node so marked — is left
        // as it is and no one is told: it is being torn down, and its loop's
        // crash on the way out is no crash to report (`mark_failed` is atomic
        // with the freeze's marking).
        let marked = self
            .tree
            .mark_failed(&crashed)
            .map_err(|_| LifecycleError::NotFound(format!("agent {crashed_agent_id}")))?;
        if !marked {
            return Ok(());
        }
        let snap = self.tree.snapshot();
        match snap.parent_of.get(&crashed).and_then(|p| p.clone()) {
            None => Ok(()), // Root crash: status set, no parent to notify.
            Some(parent) => self
                .mailbox
                .notify_parent_crash(&parent.0, crashed_agent_id, reason),
        }
    }
}

//! Wave-19 — the production `WorkspaceRollbackSink` (MODULE-001 composition root, SYS-AC-028).
//!
//! [`build_workspace_rollback_sink`] is the SOLE production impl of the scheduler's
//! [`WorkspaceRollbackSink`] seam (`scheduler/src/hook.rs`). When a child guest traps
//! mid-turn (surfaced by `AgentLoopDriverImpl::handle_trap` on `TrapError::Crash`, AFTER
//! the crash cascade), it rolls the child territory's COMMITTED subtree back to the turn's
//! pre-turn state via the **forward-rollback-commit** design (MODULE-014 §3.8 (z)):
//!
//! 1. `mark_pre_turn` (called before `handle_message`) records the pre-turn HEAD by writing
//!    a per-agent `NamedCheckpoint` (CONTRACT-022) — delete-then-create so the marker is
//!    refreshed to the current HEAD each turn. The cli has NO DIRECT `git2::` import in its
//!    production source (MODULE-003 §1.1: "no other module imports git2 directly"; `git2` is a
//!    cli dev-dep + is linked transitively via `advance-git`, but no production `git2::` call),
//!    so HEAD is captured through the checkpoint surface, never a raw `git2` open.
//! 2. `rollback_on_crash` (called on `Crash`):
//!    a. reverts the child subtree in the worktree to the pre-turn checkpoint via
//!       `WorkspaceRollback::rollback(FullDirectory)` (CONTRACT-021) — removes the turn's
//!       added data files, returns their repo-relative paths;
//!    b. FullDirectory EXCLUDES `.meta.yaml` (one per directory). For EACH directory the turn
//!       wrote into (the parent dir of a reverted path), the dir's `.meta.yaml` is stale.
//!       The sink removes that sidecar **only when the dir is now empty of other regular
//!       content** after the rollback (the skeleton/first-write case the SYS-AC-028 witness
//!       exercises, where the sidecar is wholly added this turn). If the dir still holds OTHER
//!       regular files (a non-empty / 2nd+-turn baseline), the sidecar is LEFT intact and a
//!       warning is logged — clobbering it would lose a pre-existing committed `.meta.yaml`,
//!       and a byte-exact restore needs the pre-turn blob (the cli has no direct production
//!       `git2::` access + the sidecar carries
//!       user-set `description`/`tags`, so a reconcile cannot reproduce it). That blob-RESTORE
//!       path is the deferred Wave-19 daemon-wiring concern (MODULE-014 §3.6); the fail-safe
//!       here is NO silent data loss, NOT a full general-case restore.
//!    c. submits ONE compensating `CommitType::Micro` (`[micro]`, non-`[turn]`) `CommitRequest`
//!       over the SHARED commit queue (CONTRACT-020) whose `affected_paths` = the reverted
//!       paths ++ the removed `.meta.yaml` paths — the index-driven worker stages exactly those
//!       (`remove_path` for the now-absent files), so the child territory's full committed
//!       subtree returns to pre-turn (siblings preserved, no history reset).
//!
//! Disclosed spec-reading (MODULE-014 §3.8 (z)): the per-write `[turn]` write commit survives
//! in history; the witness proves committed-subtree equality, not the strict "no surviving turn
//! commit". This rollback sink is NOT wired into `advance start` (its own daemon wiring is
//! a later lane — the per-child serve loop itself landed Wave-23/24, but this sink is separate);
//! exercised via the system-acceptance harness only (drive-prod-fn precedent 098/101/109/202),
//! flipping SYS-AC-028.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_git::{
    CommitRequest, CommitType, DefaultNamedCheckpoint, DefaultWorkspaceRollback, GitCommitQueue,
    NamedCheckpoint, RollbackMode, RollbackTarget, WorkspaceRollback,
};
use advance_scheduler::WorkspaceRollbackSink;

/// The per-agent checkpoint label the sink uses to mark the pre-turn HEAD. The checkpoint
/// namespace is already per-agent (keyed on `agent_id`), so a single fixed label is safe
/// across agents; `mark_pre_turn` delete-then-creates it so it tracks the latest HEAD.
const PRE_TURN_LABEL: &str = "pre-turn";

/// Map the scheduler's colon-keyed served id (`agent:{name}`) to the bare tree/territory id.
fn bare(agent_id: &str) -> &str {
    agent_id.strip_prefix("agent:").unwrap_or(agent_id)
}

/// True if `dir` contains any regular FILE other than its own `.meta.yaml` (subdirectories —
/// e.g. the agent-identity `.agent/` — and the sidecar itself do not count). Used to decide
/// whether a stale `.meta.yaml` is wholly added-this-turn (safe to remove) vs. sitting over a
/// pre-existing non-empty directory (leave it; clobbering would lose committed metadata).
fn dir_has_other_regular_files(dir: &Path) -> bool {
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        // Fail-safe: an unreadable dir → assume it HOLDS content (KEEP the sidecar). Erring
        // toward removal would be the data-loss direction the whole guard exists to prevent.
        Err(_) => return true,
    };
    for entry in read.flatten() {
        let name = entry.file_name();
        if name == ".meta.yaml" {
            continue;
        }
        match entry.file_type() {
            Ok(ft) if ft.is_file() => return true,
            _ => continue,
        }
    }
    false
}

/// Build the production workspace-rollback sink.
///
/// `queue` is the shared `DefaultGitCommitQueue` the served fs path commits through (the SAME
/// repo). `repo_path` is the workspace repo root. The rollback + checkpoint helpers are
/// constructed lazily per call (cheap path-canonicalize) and any construction error is
/// swallowed — a workspace rollback is best-effort and must NEVER panic the serve loop.
pub fn build_workspace_rollback_sink(
    queue: Arc<dyn GitCommitQueue>,
    repo_path: PathBuf,
) -> Arc<dyn WorkspaceRollbackSink> {
    Arc::new(WorkspaceRollbackSinkImpl {
        queue,
        repo_path,
        fresh: std::sync::Mutex::new(std::collections::HashSet::new()),
    })
}

struct WorkspaceRollbackSinkImpl {
    queue: Arc<dyn GitCommitQueue>,
    repo_path: PathBuf,
    /// Per-(bare)-agent set of ids whose pre-turn `NamedCheckpoint` was FRESHLY created this turn.
    /// `mark_pre_turn` inserts on a successful create and removes on any failure; `rollback_on_crash`
    /// rolls back ONLY when the id is present (then consumes it). This makes the rollback fail-safe
    /// against an over-rollback: a stale/un-refreshed marker (e.g. a failed delete-then-create that
    /// leaves the tag pointed at an OLDER commit) → the id is absent → no-op (the trapping turn's
    /// write persists = retention, never a silent rollback to — and loss of — a PRIOR turn's work).
    fresh: std::sync::Mutex<std::collections::HashSet<String>>,
}

#[async_trait::async_trait]
impl WorkspaceRollbackSink for WorkspaceRollbackSinkImpl {
    fn mark_pre_turn(&self, agent_id: &str) {
        let bare = bare(agent_id).to_string();
        let repo_path = self.repo_path.clone();
        // The `NamedCheckpoint` ops take the process-global per-repo coord mutex via
        // `.lock().expect("git coord mutex poisoned …")` — a POISONED mutex (from a prior
        // panic-while-locked in ANY lock-holding section: commit worker / rollback / checkpoint)
        // would PANIC here, not return `Err`. `mark_pre_turn` runs INLINE on the serve-loop task
        // (unlike `rollback_on_crash`, whose coord-lock `.expect()` is isolated inside the git
        // crate's `spawn_blocking` → surfaces as a swallowed `JoinError`). So wrap in
        // `catch_unwind` to uphold the sink's "must NEVER panic the serve loop" invariant: a
        // poisoned mutex degrades to a swallowed no-op (`rollback_on_crash` then finds no marker
        // → no-op), rather than killing the agent's serve task.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let checkpoint = DefaultNamedCheckpoint::new(repo_path)
                .map_err(|e| format!("checkpoint ctor → {e:?}"))?;
            // delete-then-create: the prior turn's marker (if any) is replaced so the checkpoint
            // tracks the CURRENT HEAD. A delete of an absent label is a benign Err → ignored.
            let _ = checkpoint.delete(&bare, PRE_TURN_LABEL);
            if let Err(e) = checkpoint.create(&bare, PRE_TURN_LABEL, None) {
                // The marker was NOT refreshed to this turn's HEAD. Clear any STALE prior-turn
                // checkpoint so a subsequent `rollback_on_crash` no-ops (NotFound) instead of
                // over-rolling-back to an older commit (which would discard earlier committed
                // turns' writes under the child domain).
                let _ = checkpoint.delete(&bare, PRE_TURN_LABEL);
                return Err(format!("create({bare}) → {e:?} (any stale marker cleared)"));
            }
            Ok::<(), String>(())
        }));
        match outcome {
            Ok(Ok(())) => {
                // Marker freshly created @ this turn's pre-state → ARM rollback_on_crash.
                if let Ok(mut g) = self.fresh.lock() {
                    g.insert(bare);
                }
            }
            Ok(Err(msg)) => {
                // Refresh failed → DISARM (a stale prior-turn tag must not drive a rollback).
                if let Ok(mut g) = self.fresh.lock() {
                    g.remove(&bare);
                }
                eprintln!(
                    "build_workspace_rollback_sink: mark_pre_turn {msg} \
                     (swallowed; rollback_on_crash no-ops for this turn)"
                );
            }
            Err(_panic) => {
                if let Ok(mut g) = self.fresh.lock() {
                    g.remove(&bare);
                }
                eprintln!(
                    "build_workspace_rollback_sink: mark_pre_turn PANICKED (poisoned git coord mutex?) \
                     — swallowed to honor the no-panic invariant; rollback_on_crash no-ops this turn"
                );
            }
        }
    }

    async fn rollback_on_crash(&self, agent_id: &str) {
        let bare = bare(agent_id);
        // Fail-safe vs over-rollback: roll back ONLY if mark_pre_turn ARMED a fresh marker THIS
        // turn (consume it here). A stale/un-refreshed marker → no-op (the trapping turn's write
        // persists = retention, never a silent rollback to — and loss of — a PRIOR turn's work).
        let armed = self
            .fresh
            .lock()
            .map(|mut g| g.remove(bare))
            .unwrap_or(false);
        if !armed {
            eprintln!(
                "build_workspace_rollback_sink: rollback_on_crash({bare}) — no fresh pre-turn \
                 marker armed this turn → no-op (fail-safe against over-rollback)"
            );
            return;
        }
        let rollback = match DefaultWorkspaceRollback::new(self.repo_path.clone()) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "build_workspace_rollback_sink: rollback_on_crash rollback ctor → {e:?} \
                     (swallowed — best-effort, must not panic the serve loop)"
                );
                return;
            }
        };
        // (a) Revert the child subtree content to the pre-turn checkpoint (worktree-only;
        //     returns the repo-relative reverted/removed paths — incl. the turn's added files).
        let reverted = match rollback
            .rollback(
                bare,
                RollbackTarget::Checkpoint(PRE_TURN_LABEL.to_string()),
                RollbackMode::FullDirectory,
            )
            .await
        {
            Ok(paths) => paths,
            Err(e) => {
                eprintln!("build_workspace_rollback_sink: rollback({bare}) → {e:?} (swallowed)");
                return;
            }
        };
        // (b) FullDirectory excludes `.meta.yaml`. For each directory the turn wrote into (the
        //     parent dir of a reverted path), remove its now-stale sidecar ONLY when the dir is
        //     empty of other regular content (the wholly-added-this-turn / skeleton case);
        //     otherwise leave it + log (no silent data loss — see the module docstring).
        let mut affected = reverted.clone();
        let mut meta_dirs: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
        for p in &reverted {
            let abs = if p.is_absolute() {
                p.clone()
            } else {
                self.repo_path.join(p)
            };
            if let Some(parent) = abs.parent() {
                meta_dirs.insert(parent.to_path_buf());
            }
        }
        for dir in meta_dirs {
            let meta = dir.join(".meta.yaml");
            if !meta.exists() {
                continue;
            }
            if dir_has_other_regular_files(&dir) {
                eprintln!(
                    "build_workspace_rollback_sink: {} retains regular content after rollback — \
                     leaving its .meta.yaml (a byte-exact restore of a pre-existing committed \
                     sidecar needs the pre-turn blob; deferred to the Wave-19 daemon wiring; NO \
                     data loss)",
                    dir.display()
                );
                continue;
            }
            match std::fs::remove_file(&meta) {
                Ok(()) => affected.push(meta),
                Err(e) => eprintln!(
                    "build_workspace_rollback_sink: remove sidecar {} → {e:?} (swallowed)",
                    meta.display()
                ),
            }
        }
        // (c) Compensating non-`[turn]` commit. The index-driven worker stages exactly
        //     `affected_paths` (remove_path for the now-absent files) → committed subtree ==
        //     pre-turn. CommitType::Micro → `[micro]` prefix (NOT `[turn]`).
        if affected.is_empty() {
            return;
        }
        let req = CommitRequest::new(
            bare,
            format!("workspace rollback (child trap) for {bare}"),
            affected,
            CommitType::Micro,
            "runtime:rollback",
        );
        match self.queue.submit(req).await {
            Ok(Ok(_oid)) => {}
            other => eprintln!(
                "build_workspace_rollback_sink: compensating commit for {bare} → {other:?} \
                 (swallowed — best-effort)"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::dir_has_other_regular_files;

    /// Wave-19 audit r5 (W1): pin the keep/remove predicate that decides whether a stale
    /// `.meta.yaml` is safe to remove (content-empty dir, the witnessed skeleton case) or must
    /// be KEPT (a non-empty / pre-existing baseline — the fail-safe that avoids clobbering a
    /// committed sidecar). The end-to-end remove path is exercised by sys_j10 T028-A; this pins
    /// the decision both arms hinge on (incl. the fail-safe direction).
    #[test]
    fn dir_has_other_regular_files_gates_meta_removal() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path();
        // Only a `.meta.yaml` → content-empty → false (the sidecar is wholly added → REMOVE).
        std::fs::write(dir.join(".meta.yaml"), b"x").expect("write meta");
        assert!(
            !dir_has_other_regular_files(dir),
            "only .meta.yaml present → content-empty → remove branch"
        );
        // A subdirectory (e.g. the agent-identity `.agent/`) does NOT count as content.
        std::fs::create_dir(dir.join(".agent")).expect("mkdir .agent");
        assert!(
            !dir_has_other_regular_files(dir),
            "a subdir does not count → still content-empty → remove branch"
        );
        // A regular file → true (a non-empty / pre-existing baseline → KEEP the sidecar).
        std::fs::write(dir.join("keep.txt"), b"y").expect("write keep");
        assert!(
            dir_has_other_regular_files(dir),
            "a regular file present → non-empty → keep branch (no data loss)"
        );
    }
}

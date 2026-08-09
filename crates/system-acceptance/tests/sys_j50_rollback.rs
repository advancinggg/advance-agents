//! Track C — SYS-J-50 (workspace rollback) witness.
//!
//! Witnesses **SYS-AC-159, SYS-AC-160, SYS-AC-161, SYS-AC-239** end-to-end against the REAL
//! `advance_git` rollback provider (`DefaultWorkspaceRollback`) — the production
//! struct, the production `WorkspaceRollback::rollback` method, and the
//! production `git.rollback` event emit gate — driven over a self-built temp git
//! repository with a real agent territory.
//!
//! ## Real-provider witness (NOT a guest turn)
//!
//! Per the HF-sanctioned `mode_agents_smoke.rs` pattern + the `sys_j47`
//! witness-floor discipline, this drives the REAL provider DIRECTLY from the
//! test. The guest→host reply / run-loop that would issue a rollback from a
//! live agent turn is the upstream-blocked surface (crate README "HF fast-follow
//! blockers"); the git rollback provider, however, operates on any plain repo
//! path and needs no `SystemUnderTest`, so the faithful witness bar is to seed a
//! real repo + a real `.agent/config.yaml`-bearing agent territory and call the
//! production `DefaultWorkspaceRollback`. No module in the chain is mocked or
//! stubbed: the repo is a real libgit2 repository (`advance_git::bootstrap_repo_at`),
//! the base commit is a real git2 commit, the rollback is the real checkout, and
//! the `git.rollback` event is observed through a tiny test-owned `EventBusEmit`
//! sink (the seam IS `EventBusEmit`, exactly as in `sys_j47`).
//!
//! ## Event-sink rule
//!
//! The git provider takes an injected `Arc<dyn EventBusEmit>`. There is no
//! harness EventBus here (no `SystemUnderTest`), so I inject my OWN
//! `CapturingEventBus` (`Arc<Mutex<Vec<Event>>>`, defined INSIDE this file —
//! every `tests/*.rs` is its own integration binary) and assert on THAT sink,
//! never `assert_db_event`. The provider stays the real production type; only the
//! sink is observed.
//!
//! ## SYS-AC-160 (recall reflects the revert) — FLIPPED (Wave-16 Lane 3)
//!
//! Both AND-clauses of the criterion now hold against the REAL provider. The
//! `.with_sqlite_index()` axis wires the real cap-fs triple-sync trio and
//! `sut.boot_reconcile()` runs the REAL `WorkspaceReconciler` + `IndexRebuild`
//! (SYS-AC-148 witnesses recall-reflects-on-disk via the same seam), so the
//! REVERTED-FILE clause is real (seed child territory → index → recall the v2
//! content as pre-revert discriminator → real `DefaultWorkspaceRollback`
//! FullDirectory → re-reconcile → recall reflects the reverted on-disk truth).
//! The OTHER clause — "a file added after the target is gone" — is now also real:
//! the FullDirectory **rollback-removal** (`git/src/rollback.rs` `do_rollback`
//! tree-diff `expand_full_domain(HEAD) ∖ expand_full_domain(target)`) deletes
//! `child/added.md` (committed in v2 after the target) from the worktree; after
//! re-reconcile it is absent on disk AND no longer recall-able. The test below
//! drives the REAL provider for both clauses (no mock for the removal).
//!
//! ## What this deliberately does NOT assert (deferred legs)
//!
//! - **SYS-AC-238** (rollback ~100 files < 500 ms) — a strict perf-SLO unreliable
//!   on this shared, disk-pressured, parallel-worktree CI; recorded deferral.
//! - The rollback is issued by calling the provider directly; this is NOT a
//!   witness of a guest-turn-initiated rollback nor of any run-loop commit/event
//!   that would accompany one (upstream-blocked).
//!
//! ## Error-wording note (SYS-AC-239)
//!
//! The real provider surfaces a malformed/unresolvable commit revision as
//! `RollbackError::InvalidTarget { target, reason }` (`Oid::from_str` failure at
//! `git/src/rollback.rs:792-797`). This maps the SYS-AC-239 ledger's
//! "lifecycle-error (invalid-state)" wording onto the git module's own typed
//! discriminant for an unresolvable target — the access is rejected fail-closed
//! and the worktree is left byte-identical, which is the criterion's observable.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use advance_git::{
    bootstrap_repo_at, DefaultWorkspaceRollback, DeniedReason, RollbackError, RollbackMode,
    RollbackTarget, WorkspaceRollback,
};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use git2::{Repository, Signature};
use system_acceptance::{Cap, SystemUnderTest};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Test-owned capturing EventBus sink (the `EventBusEmit` seam, sys_j47-style).
// Defined INSIDE this file so the binary is fully self-contained.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct CapturingEventBus {
    events: Mutex<Vec<Event>>,
}

impl CapturingEventBus {
    fn new() -> Self {
        Self::default()
    }

    fn snapshot(&self) -> Vec<Event> {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl EventBusEmit for CapturingEventBus {
    fn emit(&self, event: Event) {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(event);
    }
}

// ---------------------------------------------------------------------------
// Repo / territory / commit fixtures (real libgit2, no mocks).
// ---------------------------------------------------------------------------

/// Bootstrap a single-branch repo (leaves an UNBORN HEAD — 0 commits) and
/// return the tempdir guard + the repo path.
fn bootstrap() -> (TempDir, PathBuf) {
    let td = TempDir::new().expect("tempdir");
    let p = td.path().to_path_buf();
    bootstrap_repo_at(&p).expect("bootstrap single-branch repo");
    (td, p)
}

/// Direct git2 commit helper (avoids the async commit queue — the test only
/// needs a deterministic base commit to roll back to). Mirrors the proven
/// `git/tests/rollback_event_emit.rs::seed_commit` pattern. Files are written to
/// disk under `p` and staged by relative path; HEAD is advanced (creating the
/// branch on the first call, which transitions the unborn HEAD).
fn seed_commit(p: &Path, files: &[(&str, &str)], msg: &str) -> git2::Oid {
    let repo = Repository::open(p).unwrap();
    for (rel, content) in files {
        if let Some(parent) = Path::new(rel).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(p.join(parent)).unwrap();
            }
        }
        std::fs::write(p.join(rel), content).unwrap();
    }
    let mut idx = repo.index().unwrap();
    for (rel, _) in files {
        idx.add_path(Path::new(rel)).unwrap();
    }
    idx.write().unwrap();
    let tree_id = idx.write_tree().unwrap();
    let tree = repo.find_tree(tree_id).unwrap();
    let sig = Signature::now("t", "t@x").unwrap();
    let parents: Vec<git2::Commit> = match repo.head() {
        Ok(h) => vec![h.peel_to_commit().unwrap()],
        Err(_) => vec![],
    };
    let parent_refs: Vec<&git2::Commit> = parents.iter().collect();
    repo.commit(Some("HEAD"), &sig, &sig, msg, &tree, &parent_refs)
        .unwrap()
}

/// Layout used by all three tests: a NON-root agent `worker` whose territory is
/// `<repo>/worker/` (resolved via `<repo>/worker/.agent/config.yaml`), containing
///   - writable files `worker/report.md`, `worker/data/notes.md`,
///   - the agent's own private subtree `worker/.agent/**` (excluded from rollback),
///   - a GRANDCHILD territory `worker/gc/` (detected by its `worker/gc/.agent/`
///     marker), holding `worker/gc/result.md` (untouched by `worker`'s rollback).
///
/// `init_child_workspace` (cap-lifecycle) writes NO `agent_id`, so the test
/// writes a valid `config.yaml` itself — otherwise `resolve_agent_root` would
/// `NotFound`. The repo root deliberately has NO `<repo>/.agent/config.yaml`, so
/// `worker` is resolved by the BFS scan (NOT the root sentinel).
///
/// Returns the base-commit Oid (the rollback target).
fn seed_worker_territory(p: &Path) -> git2::Oid {
    seed_commit(
        p,
        &[
            ("worker/.agent/config.yaml", "agent_id: worker\n"),
            ("worker/report.md", "base-report"),
            ("worker/data/notes.md", "base-notes"),
            ("worker/gc/.agent/config.yaml", "agent_id: gc\n"),
            ("worker/gc/result.md", "gc-base-result"),
        ],
        "base: worker territory + grandchild gc",
    )
}

// ---------------------------------------------------------------------------
// SYS-AC-159 — FullDirectory rollback reverts writable files, excludes
// `.agent/` + grandchild, and emits a `git.rollback` event with affected_paths.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_159_full_directory_rollback_reverts_writable_excludes_agent_and_grandchild() {
    let (_td, p) = bootstrap();
    let target = seed_worker_territory(&p);

    // DIVERGE the worktree from the target so affected_paths is non-empty (else
    // `rollback` SKIPS the `git.rollback` emit, rollback.rs:560-575):
    //   - modify a writable file,
    //   - mutate the agent's own `.agent/` file (must be left as-is by rollback),
    //   - mutate the grandchild territory file (must be left as-is by rollback).
    std::fs::write(p.join("worker/report.md"), "DRIFT-report").unwrap();
    std::fs::write(p.join("worker/data/notes.md"), "DRIFT-notes").unwrap();
    std::fs::write(
        p.join("worker/.agent/config.yaml"),
        "agent_id: worker\nlocal_edit: drift\n",
    )
    .unwrap();
    std::fs::write(p.join("worker/gc/result.md"), "DRIFT-gc").unwrap();

    let sink = Arc::new(CapturingEventBus::new());
    let rb = DefaultWorkspaceRollback::with_event_bus(p.clone(), sink.clone() as Arc<_>).unwrap();

    let affected = rb
        .rollback(
            "worker",
            RollbackTarget::Commit(target.to_string()),
            RollbackMode::FullDirectory,
        )
        .await
        .expect("FullDirectory rollback of worker territory succeeds");

    // Writable files inside the agent's domain were reverted to the base commit.
    assert_eq!(
        std::fs::read_to_string(p.join("worker/report.md")).unwrap(),
        "base-report",
        "writable file reverted to base commit content"
    );
    assert_eq!(
        std::fs::read_to_string(p.join("worker/data/notes.md")).unwrap(),
        "base-notes",
        "nested writable file reverted to base commit content"
    );

    // The agent's own `.agent/**` subtree is UNTOUCHED (PRD §7.2 single-signal rule).
    assert_eq!(
        std::fs::read_to_string(p.join("worker/.agent/config.yaml")).unwrap(),
        "agent_id: worker\nlocal_edit: drift\n",
        "agent's own .agent/ must NOT be reverted by a workspace rollback"
    );
    // The GRANDCHILD territory is UNTOUCHED.
    assert_eq!(
        std::fs::read_to_string(p.join("worker/gc/result.md")).unwrap(),
        "DRIFT-gc",
        "grandchild-territory file must NOT be reverted by the parent's rollback"
    );

    // The returned affected-path set excludes `.agent/` and the grandchild.
    let strs: Vec<String> = affected
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    assert!(
        strs.iter().any(|s| s == "worker/report.md"),
        "worker/report.md is in the affected set: {strs:?}"
    );
    assert!(
        !strs
            .iter()
            .any(|s| s.contains("/.agent/") || s.starts_with(".agent/")),
        "no .agent/ path may appear in the affected set: {strs:?}"
    );
    assert!(
        !strs.iter().any(|s| s.starts_with("worker/gc/")),
        "no grandchild-territory path may appear in the affected set: {strs:?}"
    );

    // The sink captured exactly one `git.rollback` event carrying affected_paths.
    let events = sink.snapshot();
    let rollback_events: Vec<&Event> = events
        .iter()
        .filter(|e| e.event_type == "git.rollback")
        .collect();
    assert_eq!(
        rollback_events.len(),
        1,
        "exactly one git.rollback event emitted; got {:?}",
        events.iter().map(|e| &e.event_type).collect::<Vec<_>>()
    );
    let ev = rollback_events[0];
    assert_eq!(
        ev.agent_id, "worker",
        "event.agent_id is the rolling-back agent"
    );
    let payload = ev
        .payload
        .as_object()
        .expect("git.rollback payload is a JSON object");
    assert_eq!(
        payload.get("target_kind").and_then(|v| v.as_str()),
        Some("version"),
        "Commit target → target_kind=version"
    );
    assert_eq!(
        payload.get("target_ref").and_then(|v| v.as_str()),
        Some(target.to_string().as_str()),
        "target_ref is the commit hex"
    );
    let affected_payload = payload
        .get("affected_paths")
        .and_then(|v| v.as_array())
        .expect("payload carries an affected_paths array");
    assert!(
        !affected_payload.is_empty(),
        "git.rollback event carries a non-empty affected_paths list"
    );
    assert!(
        affected_payload
            .iter()
            .any(|v| v.as_str() == Some("worker/report.md")),
        "affected_paths in the event includes the reverted writable file: {affected_payload:?}"
    );
    assert!(
        !affected_payload.iter().any(|v| v
            .as_str()
            .map(|s| s.contains("/.agent/") || s.starts_with("worker/gc/"))
            .unwrap_or(false)),
        "affected_paths excludes .agent/ + grandchild: {affected_payload:?}"
    );
}

// ---------------------------------------------------------------------------
// SYS-AC-161 — (a) a PathScoped rollback whose paths overlap the grandchild
// territory is rejected with ChildTerritoryOverlap; (b) a rollback issued by a
// NON-parent agent id is permission-denied (no matching `.agent/config.yaml`).
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_161_pathscoped_grandchild_overlap_and_non_parent_denied() {
    let (_td, p) = bootstrap();
    let target = seed_worker_territory(&p);

    let sink = Arc::new(CapturingEventBus::new());
    let rb = DefaultWorkspaceRollback::with_event_bus(p.clone(), sink.clone() as Arc<_>).unwrap();

    // (a) PathScoped path is interpreted relative to the agent root (`worker/`),
    // so `gc/result.md` rebases to `worker/gc/result.md`, which lives inside the
    // detected grandchild territory `worker/gc` → ChildTerritoryOverlap.
    let overlap_err = rb
        .rollback(
            "worker",
            RollbackTarget::Commit(target.to_string()),
            RollbackMode::PathScoped(vec![PathBuf::from("gc/result.md")]),
        )
        .await
        .expect_err("PathScoped overlap with grandchild territory must be rejected");
    assert!(
        matches!(
            overlap_err,
            RollbackError::PermissionDenied {
                reason: DeniedReason::ChildTerritoryOverlap,
                ..
            }
        ),
        "expected PermissionDenied(ChildTerritoryOverlap); got {overlap_err:?}"
    );

    // (b) A non-parent / unknown agent id has no `<dir>/.agent/config.yaml` whose
    // `agent_id` matches, so `resolve_agent_root` fails closed (NotFound) — the
    // rollback is denied (no agent root to act on). This is how the provider
    // detects "rollback issued by a non-parent agent": identity is resolved
    // exclusively via the on-disk config.yaml ownership signal, never trusted
    // from the caller string.
    let non_parent_err = rb
        .rollback(
            "ghost",
            RollbackTarget::Commit(target.to_string()),
            RollbackMode::FullDirectory,
        )
        .await
        .expect_err("rollback by an agent with no owning territory must be denied");
    assert!(
        matches!(non_parent_err, RollbackError::NotFound { .. }),
        "non-parent / unowned agent id is denied (NotFound — no matching territory); got {non_parent_err:?}"
    );

    // No `git.rollback` event is emitted on either rejected path.
    let events = sink.snapshot();
    assert!(
        !events.iter().any(|e| e.event_type == "git.rollback"),
        "rejected rollbacks emit NO git.rollback event; got {:?}",
        events.iter().map(|e| &e.event_type).collect::<Vec<_>>()
    );

    // The grandchild file was not touched by the rejected overlap attempt.
    assert_eq!(
        std::fs::read_to_string(p.join("worker/gc/result.md")).unwrap(),
        "gc-base-result",
        "rejected overlap rollback leaves the grandchild file unchanged"
    );
}

// ---------------------------------------------------------------------------
// SYS-AC-239 — an unresolvable / malformed commit revision is rejected with
// InvalidTarget, and NO files change (worktree byte-identical to pre-call).
// (See the module docstring: InvalidTarget maps the ledger's
// "lifecycle-error (invalid-state)" wording for an unresolvable target.)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_239_malformed_revision_errors_and_changes_nothing() {
    let (_td, p) = bootstrap();
    seed_worker_territory(&p);

    // Diverge the worktree so there would be something to revert IF the call
    // were (wrongly) honored — strengthens the "nothing changed" assertion.
    std::fs::write(p.join("worker/report.md"), "PRE-CALL-DRIFT").unwrap();
    std::fs::write(p.join("worker/data/notes.md"), "PRE-CALL-NOTES").unwrap();

    // Snapshot the writable-file worktree state immediately before the call.
    let pre_report = std::fs::read_to_string(p.join("worker/report.md")).unwrap();
    let pre_notes = std::fs::read_to_string(p.join("worker/data/notes.md")).unwrap();
    let pre_gc = std::fs::read_to_string(p.join("worker/gc/result.md")).unwrap();

    let sink = Arc::new(CapturingEventBus::new());
    let rb = DefaultWorkspaceRollback::with_event_bus(p.clone(), sink.clone() as Arc<_>).unwrap();

    // Malformed hex — `Oid::from_str` rejects it at the crate boundary BEFORE
    // any agent-root resolution or checkout (rollback.rs:792-797).
    let err = rb
        .rollback(
            "worker",
            RollbackTarget::Commit("zzznotahex/../malformed".to_string()),
            RollbackMode::FullDirectory,
        )
        .await
        .expect_err("malformed commit revision must be rejected");
    assert!(
        matches!(err, RollbackError::InvalidTarget { .. }),
        "malformed revision → RollbackError::InvalidTarget; got {err:?}"
    );

    // No file changed — worktree is byte-identical to the pre-call snapshot.
    assert_eq!(
        std::fs::read_to_string(p.join("worker/report.md")).unwrap(),
        pre_report,
        "writable file unchanged after rejected rollback"
    );
    assert_eq!(
        std::fs::read_to_string(p.join("worker/data/notes.md")).unwrap(),
        pre_notes,
        "nested writable file unchanged after rejected rollback"
    );
    assert_eq!(
        std::fs::read_to_string(p.join("worker/gc/result.md")).unwrap(),
        pre_gc,
        "grandchild file unchanged after rejected rollback"
    );

    // No `git.rollback` event on the error path.
    let events = sink.snapshot();
    assert!(
        !events.iter().any(|e| e.event_type == "git.rollback"),
        "an InvalidTarget rollback emits NO git.rollback event; got {:?}",
        events.iter().map(|e| &e.event_type).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// SYS-AC-160 — after a rollback, a recall/list over the child territory returns
// the REVERTED on-disk state: a file added after the target is gone AND a
// reverted file matches the target, proving .meta.yaml + SQLite were re-synced.
// Both clauses now hold against the REAL provider (the FullDirectory
// rollback-removal tree-diff in `do_rollback` deletes the post-target addition;
// `boot_reconcile` re-syncs disk→index). Driven on the SUT's `.with_sqlite_index()`
// repo: index v2 disk → recall v2 (post-target) state (PRE-revert discriminators)
// → real DefaultWorkspaceRollback to T → boot_reconcile → recall reflects the
// reverted, removal-applied on-disk truth.
// ---------------------------------------------------------------------------

// SYS-AC-160 — FLIPPED (Wave-16 Lane 3). Both AND-clauses of the criterion now
// hold against the REAL provider. The FullDirectory rollback-removal (tree-diff
// `expand_full_domain(HEAD) ∖ expand_full_domain(target)` in git/src/rollback.rs
// `do_rollback`) makes "a file added after the target is gone" true —
// `child/added.md`, committed in v2 after the target T, is REMOVED by the
// rollback — while the reverted-file clause ("a reverted file matches the
// target") was already real. After re-reconcile, recall reflects BOTH: the
// reverted target content is recall-able and the removed (v2/added) content is
// not. Real `DefaultWorkspaceRollback` + real `boot_reconcile` — no mocks.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_160_recall_after_rollback_reflects_reverted_state() {
    const J01_SKELETON: &[u8] =
        include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .with_sqlite_index()
        .build(J01_SKELETON)
        .await;
    let ws = sut.workspace_root().to_path_buf();

    // T (rollback target): child territory — config.yaml + keepme.md (base).
    let target = seed_commit(
        &ws,
        &[
            ("child/.agent/config.yaml", "agent_id: child\n"),
            ("child/keepme.md", "keepbase uniquebaseword base body"),
        ],
        "base: child territory (target T)",
    );
    // v2 (HEAD): modify keepme (tracked) so a checkout to T reverts its content,
    // AND add a NEW tracked file `child/added.md` after the target — the "a file
    // added after the target is gone" clause the FullDirectory rollback-removal
    // now satisfies.
    seed_commit(
        &ws,
        &[
            ("child/keepme.md", "keepv2 uniquev2word v2 body"),
            (
                "child/added.md",
                "addedv2 uniqueaddedword added-after-target body",
            ),
        ],
        "v2: modify keepme + add added.md",
    );

    // Untracked minimal .meta.yaml so reconcile populates _entries from disk.
    std::fs::write(
        ws.join("child/.meta.yaml"),
        "_scope:\n  description: child scope\n",
    )
    .unwrap();

    // Index the v2 disk. PRE-rollback recall finds the v2 (post-target) content.
    sut.boot_reconcile().await;
    assert!(
        sut.fts_recall("child", "uniquev2word")
            .await
            .iter()
            .any(|r| r.file_path.as_deref() == Some("/child/keepme.md")),
        "PRE-rollback: the v2 keepme content is recall-able (discriminator)"
    );
    assert!(
        sut.fts_recall("child", "uniquebaseword").await.is_empty(),
        "PRE-rollback: the target (base) content is NOT yet recall-able (discriminator)"
    );
    assert!(
        sut.fts_recall("child", "uniqueaddedword")
            .await
            .iter()
            .any(|r| r.file_path.as_deref() == Some("/child/added.md")),
        "PRE-rollback: the post-target added.md content IS recall-able (discriminator)"
    );

    // Roll the child territory back to T via the REAL provider.
    let sink = Arc::new(CapturingEventBus::new());
    let rb = DefaultWorkspaceRollback::with_event_bus(ws.clone(), sink.clone() as Arc<_>).unwrap();
    let affected = rb
        .rollback(
            "child",
            RollbackTarget::Commit(target.to_string()),
            RollbackMode::FullDirectory,
        )
        .await
        .expect("FullDirectory rollback of child to T");
    assert!(
        affected
            .iter()
            .any(|p| p.to_string_lossy().contains("keepme.md")),
        "rollback affected the reverted keepme.md: {affected:?}"
    );
    // The post-target added file is in the affected set (it was removed).
    assert!(
        affected
            .iter()
            .any(|p| p.to_string_lossy().contains("added.md")),
        "rollback affected (removed) the post-target added.md: {affected:?}"
    );
    // On-disk truth reverted: keepme back to the target content.
    assert_eq!(
        std::fs::read_to_string(ws.join("child/keepme.md")).unwrap(),
        "keepbase uniquebaseword base body",
        "keepme.md reverted to the target content"
    );
    // ... and the post-target added file is GONE from disk ("a file added after
    // the target is gone").
    assert!(
        !ws.join("child/added.md").exists(),
        "the post-target added.md is removed from disk by the FullDirectory rollback"
    );

    // Re-reconcile → recall reflects the reverted on-disk truth (re-synced):
    // the v2 content is gone from the index, the target content is back.
    sut.boot_reconcile().await;
    assert!(
        sut.fts_recall("child", "uniquev2word").await.is_empty(),
        "POST-rollback: the v2 content is no longer recall-able (reverted + re-synced)"
    );
    assert!(
        sut.fts_recall("child", "uniquebaseword")
            .await
            .iter()
            .any(|r| r.file_path.as_deref() == Some("/child/keepme.md")),
        "POST-rollback: the reverted (target) content IS recall-able — proves .meta.yaml + SQLite re-synced"
    );
    // The removed added.md is no longer recall-able (gone from disk + re-synced):
    // the "a file added after the target is gone" clause, proven through recall.
    assert!(
        sut.fts_recall("child", "uniqueaddedword").await.is_empty(),
        "POST-rollback: the removed added.md content is no longer recall-able (added file is gone + re-synced)"
    );
}

//! Wave-20 (build-only) — TP-01..11 build-lane witnesses for
//! `SkillTurnPersistenceDriver` (MODULE-017-AC-22 legs (b)+(c); activate+rollback
//! commit-failure compensation) + the `SkillStore::snapshot_live`/`restore_live`/
//! `flush_draft` name-validation + snapshot-key-bind + content-cap gates +
//! the restore-failure-still-re-enqueues guarantee (adversarial-round hardening).
//!
//! These bind an INDEPENDENT oracle (real `DiskSkillStorage` on disk + a
//! recording event bus + a real git tree for TP-04) over the REAL per-op
//! coordinator chain. They prove the BUILT durability legs; they do NOT flip
//! AC-22 (HELD — spec20 leg-a unlanded + lease_id/delete-sidecar deferred;
//! §3.6 (ccc)). REQ-275 stays Partial.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use advance_git::{
    bootstrap_repo_at, CommitRequest, CommitType, DefaultGitCommitQueue, GitCommitQueue, GitError,
};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use async_trait::async_trait;
use chrono::Utc;
use git2::Oid;
use tempfile::TempDir;
use tokio::sync::oneshot;

use cap_skills::persistence::{DiskSkillStorage, DraftBlob, SkillBlob, SkillStorage};
use cap_skills::persistence_phase::SkillPersistenceCoordinator;
use cap_skills::{
    LiveSnapshot, Provenance, RuntimePrivateFlush, SkillError, SkillStore,
    SkillTurnPersistenceDriver, StoreDraftFlush, TrustLevel, TurnSkillOp,
};

// ── test doubles ────────────────────────────────────────────────────────

/// Captures every emitted event.
#[derive(Default)]
struct CollectingEventBus {
    events: Mutex<Vec<Event>>,
}
impl CollectingEventBus {
    fn new() -> Self {
        Self::default()
    }
    fn len(&self) -> usize {
        self.events.lock().unwrap().len()
    }
}
impl EventBusEmit for CollectingEventBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

/// Commit queue whose `submit` eager-sends a scripted result (default `Ok(zero)`
/// once the script is drained) and counts calls. Mirrors the SH-03/SH-16
/// inline pattern; lets us force commit failure / success deterministically.
struct ScriptedCommitQueue {
    results: Mutex<VecDeque<Result<Oid, GitError>>>,
    calls: Mutex<usize>,
}
impl ScriptedCommitQueue {
    fn new(results: Vec<Result<Oid, GitError>>) -> Arc<Self> {
        Arc::new(Self {
            results: Mutex::new(VecDeque::from(results)),
            calls: Mutex::new(0),
        })
    }
    fn call_count(&self) -> usize {
        *self.calls.lock().unwrap()
    }
}
impl GitCommitQueue for ScriptedCommitQueue {
    fn submit(&self, _req: CommitRequest) -> oneshot::Receiver<Result<Oid, GitError>> {
        *self.calls.lock().unwrap() += 1;
        let (tx, rx) = oneshot::channel();
        let result = self
            .results
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Ok(Oid::zero()));
        let _ = tx.send(result);
        rx
    }
}

/// A runtime-private flusher that FAILS its first `fail_first` calls, then
/// succeeds — to witness leg-(b) retry-once-then-error. Counts calls.
struct FlakyFlush {
    fail_first: Mutex<u32>,
    calls: Mutex<u32>,
}
impl FlakyFlush {
    fn new(fail_first: u32) -> Arc<Self> {
        Arc::new(Self {
            fail_first: Mutex::new(fail_first),
            calls: Mutex::new(0),
        })
    }
    fn call_count(&self) -> u32 {
        *self.calls.lock().unwrap()
    }
}
#[async_trait]
impl RuntimePrivateFlush for FlakyFlush {
    async fn flush(&self, _overlay: &[DraftBlob]) -> Result<(), SkillError> {
        *self.calls.lock().unwrap() += 1;
        let mut left = self.fail_first.lock().unwrap();
        if *left > 0 {
            *left -= 1;
            Err(SkillError::InvalidTransition(
                "simulated flush IO failure".into(),
            ))
        } else {
            Ok(())
        }
    }
}

/// A commit queue whose `submit` returns a receiver whose sender is DROPPED
/// immediately — so the coordinator's `rx.await` yields `RecvError`, which it
/// maps to `InvalidTransition("commit worker closed")` (the git worker died
/// before replying). The store is mutated but no commit landed.
struct WorkerClosedQueue;
impl GitCommitQueue for WorkerClosedQueue {
    fn submit(&self, _req: CommitRequest) -> oneshot::Receiver<Result<Oid, GitError>> {
        let (_tx, rx) = oneshot::channel();
        rx // _tx dropped here → the await resolves to RecvError
    }
}

// ── helpers ─────────────────────────────────────────────────────────────

fn valid_skill_content() -> String {
    "---\nname: web-search\ndescription: a test skill\n---\n# Body\n".to_string()
}

fn draft_blob(name: &str) -> DraftBlob {
    DraftBlob {
        name: name.to_string(),
        content: valid_skill_content(),
        tags: vec![],
        parent: None,
        reason: None,
        created_at: Utc::now(),
    }
}

/// A shared `Arc<Mutex<SkillStore>>` over a real `DiskSkillStorage` rooted at
/// `root`, plus the canonical root. The store + every coordinator/driver built
/// over it share ONE mutex.
async fn shared_store(
    root: &std::path::Path,
) -> (Arc<tokio::sync::Mutex<SkillStore>>, std::path::PathBuf) {
    let canonical_root = std::fs::canonicalize(root).unwrap();
    let storage: Arc<dyn SkillStorage> = Arc::new(DiskSkillStorage::with_default_writer(
        canonical_root.clone(),
    ));
    let store = SkillStore::with_storage(storage);
    (Arc::new(tokio::sync::Mutex::new(store)), canonical_root)
}

fn coordinator_over(
    agent_root: std::path::PathBuf,
    shared: Arc<tokio::sync::Mutex<SkillStore>>,
    queue: Arc<dyn GitCommitQueue>,
    bus: Arc<dyn EventBusEmit>,
) -> Arc<SkillPersistenceCoordinator> {
    Arc::new(SkillPersistenceCoordinator::with_shared_store(
        "root".into(),
        agent_root,
        shared,
        queue,
        bus,
    ))
}

// ── TP-01 — leg (b): flush retry-once-then-error ──────────────────────────

#[tokio::test]
async fn tp_01a_flush_fails_once_then_succeeds() {
    let dir = TempDir::new().unwrap();
    let (shared, root) = shared_store(dir.path()).await;
    let bus = Arc::new(CollectingEventBus::new());
    let queue = ScriptedCommitQueue::new(vec![]);
    let coordinator = coordinator_over(
        root,
        shared.clone(),
        queue.clone() as Arc<dyn GitCommitQueue>,
        bus.clone() as Arc<dyn EventBusEmit>,
    );
    let flusher = FlakyFlush::new(1); // fail once, then succeed
    let mut driver = SkillTurnPersistenceDriver::new(
        shared.clone(),
        coordinator,
        flusher.clone() as Arc<dyn RuntimePrivateFlush>,
    );
    driver.stage_draft(draft_blob("web-search"));

    // Draft-only turn (no git-tracked ops): the flush must retry once and
    // succeed, so the turn completes Ok.
    driver
        .run_turn_persistence(vec![])
        .await
        .expect("turn ok after one retry");

    assert_eq!(
        flusher.call_count(),
        2,
        "flush attempted twice (1 fail + 1 retry-success)"
    );
    assert_eq!(queue.call_count(), 0, "no git-tracked ops → no commit");
    assert_eq!(bus.len(), 0, "no skill.* event on a draft-only turn");
}

#[tokio::test]
async fn tp_01b_flush_fails_twice_errors_and_skips_commit() {
    let dir = TempDir::new().unwrap();
    // Seed a draft so the (would-be) activate op has something to act on.
    let (shared, root) = shared_store(dir.path()).await;
    shared
        .lock()
        .await
        .propose_draft("web-search".into(), valid_skill_content(), vec![])
        .await
        .unwrap();
    let bus = Arc::new(CollectingEventBus::new());
    let queue = ScriptedCommitQueue::new(vec![Ok(Oid::zero())]);
    let coordinator = coordinator_over(
        root,
        shared.clone(),
        queue.clone() as Arc<dyn GitCommitQueue>,
        bus.clone() as Arc<dyn EventBusEmit>,
    );
    let flusher = FlakyFlush::new(2); // fail twice → error-raise the turn
    let mut driver = SkillTurnPersistenceDriver::new(
        shared.clone(),
        coordinator,
        flusher.clone() as Arc<dyn RuntimePrivateFlush>,
    );
    driver.stage_draft(draft_blob("web-search"));

    // The turn includes an activate op, but the flush (step 1) fails twice →
    // the turn errors BEFORE steps 2/3 (commit + emit) run.
    let err = driver
        .run_turn_persistence(vec![TurnSkillOp::Activate {
            draft_id: "web-search".into(),
            reason: "promote".into(),
        }])
        .await
        .unwrap_err();
    match err {
        SkillError::InvalidTransition(msg) => {
            assert!(msg.contains("flush failed after retry"), "msg: {msg}");
        }
        other => panic!("expected flush-retry InvalidTransition, got {other:?}"),
    }

    assert_eq!(
        flusher.call_count(),
        2,
        "flush attempted exactly twice then gave up"
    );
    assert_eq!(
        queue.call_count(),
        0,
        "steps 2/3 SKIPPED — no commit submitted"
    );
    assert_eq!(bus.len(), 0, "no event when the turn errors at flush");
    // The activate op never ran → the draft is still present, no active installed.
    assert!(
        shared.lock().await.get("web-search").await.is_err(),
        "no active installed (activate never ran)"
    );
    // (adversarial-r6) the turn's op is NOT silently dropped on a flush failure —
    // it is re-enqueued for a next-turn retry once the flush recovers.
    assert_eq!(
        driver.pending().len(),
        1,
        "the turn's op is retained (re-enqueued), not silently dropped on flush failure"
    );
    assert!(matches!(
        driver.pending()[0].op,
        TurnSkillOp::Activate { .. }
    ));
}

// ── TP-02 — leg (c): commit failure → live state restored + re-enqueue ─────

#[tokio::test]
async fn tp_02_commit_failure_restores_live_state_and_reenqueues() {
    let dir = TempDir::new().unwrap();
    let (shared, root) = shared_store(dir.path()).await;
    // Seed a fresh draft (no active) → the activate is the fresh-activate path
    // whose pre-op live state is {active: None, draft: Some}.
    shared
        .lock()
        .await
        .propose_draft("web-search".into(), valid_skill_content(), vec![])
        .await
        .unwrap();
    let bus = Arc::new(CollectingEventBus::new());
    // Commit FAILS.
    let queue = ScriptedCommitQueue::new(vec![Err(GitError::Libgit2 {
        code: "-1".into(),
        message: "test-failure".into(),
    })]);
    let coordinator = coordinator_over(
        root,
        shared.clone(),
        queue.clone() as Arc<dyn GitCommitQueue>,
        bus.clone() as Arc<dyn EventBusEmit>,
    );
    let flusher = StoreDraftFlush::new(shared.clone());
    let mut driver = SkillTurnPersistenceDriver::new(
        shared.clone(),
        coordinator,
        Arc::new(flusher) as Arc<dyn RuntimePrivateFlush>,
    );

    // Compensated commit failure → Ok (the failure is HANDLED).
    driver
        .commit_op_with_compensation(TurnSkillOp::Activate {
            draft_id: "web-search".into(),
            reason: "promote".into(),
        })
        .await
        .expect("commit failure is compensated, not propagated");

    assert_eq!(queue.call_count(), 1, "the commit WAS attempted");
    assert_eq!(bus.len(), 0, "NO premature event on commit failure");

    // DISCRIMINATOR vs SH-16 (which leaves the active installed at v1): the live
    // state is RESTORED to the pre-op snapshot — no active, draft re-created.
    let guard = shared.lock().await;
    assert!(
        guard.get("web-search").await.is_err(),
        "active RESTORED to absent (NOT left-mutated at v1)"
    );
    assert!(
        guard.get_draft("web-search").await.unwrap().is_some(),
        "the consumed draft was RESTORED"
    );
    drop(guard);

    // The op was re-enqueued for the next turn.
    assert_eq!(
        driver.pending().len(),
        1,
        "op re-enqueued after compensation"
    );
    assert!(matches!(
        driver.pending()[0].op,
        TurnSkillOp::Activate { .. }
    ));
}

// ── TP-03 — leg (c): re-enqueued op drained + retried next turn → commits ──

#[tokio::test]
async fn tp_03_reenqueued_op_retried_next_turn_commits_and_emits() {
    let dir = TempDir::new().unwrap();
    let (shared, root) = shared_store(dir.path()).await;
    shared
        .lock()
        .await
        .propose_draft("web-search".into(), valid_skill_content(), vec![])
        .await
        .unwrap();
    let bus = Arc::new(CollectingEventBus::new());
    // Turn 1 commit FAILS; turn 2 commit SUCCEEDS.
    let queue = ScriptedCommitQueue::new(vec![
        Err(GitError::Libgit2 {
            code: "-1".into(),
            message: "turn1-failure".into(),
        }),
        Ok(Oid::zero()),
    ]);
    let coordinator = coordinator_over(
        root,
        shared.clone(),
        queue.clone() as Arc<dyn GitCommitQueue>,
        bus.clone() as Arc<dyn EventBusEmit>,
    );
    let flusher = StoreDraftFlush::new(shared.clone());
    let mut driver = SkillTurnPersistenceDriver::new(
        shared.clone(),
        coordinator,
        Arc::new(flusher) as Arc<dyn RuntimePrivateFlush>,
    );

    // Turn 1 — activate; commit fails → compensated + re-enqueued, no event.
    driver
        .run_turn_persistence(vec![TurnSkillOp::Activate {
            draft_id: "web-search".into(),
            reason: "promote".into(),
        }])
        .await
        .expect("turn 1 ok (commit failure compensated)");
    assert_eq!(driver.pending().len(), 1, "re-enqueued after turn 1");
    assert_eq!(bus.len(), 0, "no event on the failed turn-1 commit");

    // Turn 2 — no new ops; the pending op is drained + retried. The draft was
    // restored in turn 1, so the retry re-activates and the commit now succeeds.
    driver
        .run_turn_persistence(vec![])
        .await
        .expect("turn 2 ok");

    assert_eq!(
        queue.call_count(),
        2,
        "two commit attempts (turn 1 fail, turn 2 retry)"
    );
    assert_eq!(
        driver.pending().len(),
        0,
        "pending drained after the successful retry"
    );
    assert_eq!(
        bus.len(),
        1,
        "skill.activated emitted on the successful retry"
    );
    // The skill is now durably active.
    assert_eq!(
        shared.lock().await.get("web-search").await.unwrap().version,
        1
    );
}

// ── TP-04 — leg (a) witness: draft-only turn issues NO git commit ─────────

#[tokio::test]
async fn tp_04_draft_only_turn_issues_no_commit_real_git() {
    let dir = TempDir::new().unwrap();
    bootstrap_repo_at(dir.path()).unwrap();
    let (shared, root) = shared_store(dir.path()).await;
    let bus = Arc::new(CollectingEventBus::new());
    let queue = DefaultGitCommitQueue::spawn(root.clone()).unwrap();

    // `bootstrap_repo_at` leaves an unborn HEAD — land one real baseline commit
    // (tracking a dummy file) so the draft-only turn must add NONE on top of it.
    let dummy = root.join("README.md");
    tokio::fs::write(&dummy, b"baseline\n").await.unwrap();
    let baseline = CommitRequest::new(
        "root",
        "baseline",
        vec![dummy.clone()],
        CommitType::Turn,
        "agent:test",
    );
    let _ = queue
        .submit(baseline)
        .await
        .expect("worker")
        .expect("baseline commit");
    let commits_before = commit_count(&root);
    assert_eq!(commits_before, 1, "baseline established");

    let coordinator = coordinator_over(
        root.clone(),
        shared.clone(),
        Arc::new(queue) as Arc<dyn GitCommitQueue>,
        bus.clone() as Arc<dyn EventBusEmit>,
    );
    let flusher = StoreDraftFlush::new(shared.clone());
    let mut driver = SkillTurnPersistenceDriver::new(
        shared.clone(),
        coordinator,
        Arc::new(flusher) as Arc<dyn RuntimePrivateFlush>,
    );
    driver.stage_draft(draft_blob("web-search"));

    // Draft-only turn: flush the runtime-private overlay; NO git-tracked op.
    driver
        .run_turn_persistence(vec![])
        .await
        .expect("draft-only turn ok");

    // ORACLE — the real git tree gained NO new commit on the draft-only turn.
    let commits_after = commit_count(&root);
    assert_eq!(
        commits_after, commits_before,
        "draft-only turn issued NO git commit"
    );
    // The runtime-private draft WAS flushed to disk.
    assert!(
        shared
            .lock()
            .await
            .get_draft("web-search")
            .await
            .unwrap()
            .is_some(),
        "the runtime-private draft was flushed to disk"
    );
    assert_eq!(
        bus.len(),
        0,
        "no Git-dependent skill.* event on a draft-only turn"
    );
}

// ── TP-05 — leg (c): the "commit worker closed" path is ALSO compensated ──

#[tokio::test]
async fn tp_05_worker_closed_commit_path_is_compensated() {
    let dir = TempDir::new().unwrap();
    let (shared, root) = shared_store(dir.path()).await;
    shared
        .lock()
        .await
        .propose_draft("web-search".into(), valid_skill_content(), vec![])
        .await
        .unwrap();
    let bus = Arc::new(CollectingEventBus::new());
    // The commit worker "dies": the oneshot sender is dropped → the coordinator
    // maps `rx.await` RecvError to InvalidTransition("commit worker closed").
    let queue: Arc<dyn GitCommitQueue> = Arc::new(WorkerClosedQueue);
    let coordinator = coordinator_over(
        root,
        shared.clone(),
        queue,
        bus.clone() as Arc<dyn EventBusEmit>,
    );
    let flusher = StoreDraftFlush::new(shared.clone());
    let mut driver = SkillTurnPersistenceDriver::new(
        shared.clone(),
        coordinator,
        Arc::new(flusher) as Arc<dyn RuntimePrivateFlush>,
    );

    // The worker-closed commit failure is COMPENSATED (not propagated), exactly
    // like the "git commit failed" path — the store-mutated-but-uncommitted
    // state is rolled back.
    driver
        .commit_op_with_compensation(TurnSkillOp::Activate {
            draft_id: "web-search".into(),
            reason: "promote".into(),
        })
        .await
        .expect("worker-closed commit failure is compensated, not propagated");

    assert_eq!(
        bus.len(),
        0,
        "no premature event on worker-closed commit failure"
    );
    let guard = shared.lock().await;
    assert!(
        guard.get("web-search").await.is_err(),
        "active RESTORED to absent (not left-mutated) on the worker-closed path"
    );
    assert!(
        guard.get_draft("web-search").await.unwrap().is_some(),
        "the consumed draft was RESTORED on the worker-closed path"
    );
    drop(guard);
    assert_eq!(
        driver.pending().len(),
        1,
        "op re-enqueued after worker-closed compensation"
    );
}

// ── TP-06 — the new SkillStore helpers reject path-traversal names ────────

#[tokio::test]
async fn tp_06_traversal_names_rejected_by_snapshot_restore_flush() {
    let dir = TempDir::new().unwrap();
    let (shared, _root) = shared_store(dir.path()).await;
    let store = shared.lock().await;
    // snapshot_live rejects a traversal-shaped id BEFORE any DiskSkillStorage
    // path join (defense-in-depth, parity with get/get_draft/propose_draft).
    assert!(
        store.snapshot_live("../escape").await.is_err(),
        "snapshot_live must reject a traversal id"
    );
    // flush_draft rejects a traversal-shaped draft name.
    let bad = draft_blob("../escape");
    assert!(
        store.flush_draft(&bad).await.is_err(),
        "flush_draft must reject a traversal draft name"
    );
    // restore_live rejects a (hand-constructed) traversal-shaped snapshot id.
    let snap = cap_skills::LiveSnapshot {
        skill_id: "../escape".into(),
        active: None,
        draft: None,
    };
    assert!(
        store.restore_live(&snap).await.is_err(),
        "restore_live must reject a traversal snapshot id"
    );
}

// ── TP-07 — leg (c): ROLLBACK op commit failure is also compensated ───────

#[tokio::test]
async fn tp_07_rollback_commit_failure_restores_live_state() {
    let dir = TempDir::new().unwrap();
    let (shared, root) = shared_store(dir.path()).await;
    // Seed active v1, then activate again → active v2 (v1 archived) so a
    // rollback-to-v1 has a real prior version + a real pre-op live state (v2).
    {
        let g = shared.lock().await;
        g.propose_draft("web-search".into(), valid_skill_content(), vec![])
            .await
            .unwrap();
        g.activate("web-search").await.unwrap(); // active v1
        g.propose_draft("web-search".into(), valid_skill_content(), vec![])
            .await
            .unwrap();
        g.activate("web-search").await.unwrap(); // active v2 (v1 archived)
        assert_eq!(
            g.get("web-search").await.unwrap().version,
            2,
            "seeded active v2"
        );
    }
    let bus = Arc::new(CollectingEventBus::new());
    let queue = ScriptedCommitQueue::new(vec![Err(GitError::Libgit2 {
        code: "-1".into(),
        message: "rollback-commit-fail".into(),
    })]);
    let coordinator = coordinator_over(
        root,
        shared.clone(),
        queue.clone() as Arc<dyn GitCommitQueue>,
        bus.clone() as Arc<dyn EventBusEmit>,
    );
    let flusher = StoreDraftFlush::new(shared.clone());
    let mut driver = SkillTurnPersistenceDriver::new(
        shared.clone(),
        coordinator,
        Arc::new(flusher) as Arc<dyn RuntimePrivateFlush>,
    );

    // Rollback to v1; the commit fails → leg-(c) restores the live state to the
    // pre-rollback v2 (NOT the rolled-back content) + re-enqueues + no event.
    driver
        .commit_op_with_compensation(TurnSkillOp::Rollback {
            skill_id: "web-search".into(),
            version: 1,
            reason: "discard".into(),
        })
        .await
        .expect("rollback commit failure is compensated");

    assert_eq!(bus.len(), 0, "no event on the rollback commit failure");
    assert_eq!(
        shared.lock().await.get("web-search").await.unwrap().version,
        2,
        "active RESTORED to the pre-rollback v2 (not the coordinator's rolled-back mutation)"
    );
    assert_eq!(driver.pending().len(), 1, "the rollback op re-enqueued");
    assert!(matches!(
        driver.pending()[0].op,
        TurnSkillOp::Rollback { .. }
    ));
}

// ── TP-08 — restore_live binds blobs to the snapshot key + flush content cap ──

#[tokio::test]
async fn tp_08_restore_live_rejects_forged_snapshot_and_flush_caps_content() {
    let dir = TempDir::new().unwrap();
    let (shared, _root) = shared_store(dir.path()).await;
    let store = shared.lock().await;

    // (W1) A LiveSnapshot whose active.skill_id != snap.skill_id is REJECTED —
    // restore_live cannot be used to cross-write a DIFFERENT skill's active.
    let forged_active = LiveSnapshot {
        skill_id: "web-search".into(),
        active: Some(SkillBlob {
            skill_id: "other-skill".into(), // != snapshot key
            version: 1,
            content: valid_skill_content(),
            tags: vec![],
            provenance: Provenance::AgentCreated,
            trust_level: TrustLevel::Untrusted,
        }),
        draft: None,
    };
    assert!(
        matches!(
            store.restore_live(&forged_active).await,
            Err(SkillError::InvalidTransition(ref m)) if m.contains("does not match the snapshot key")
        ),
        "restore_live must reject a forged active.skill_id with the KEY-BIND error (not some unrelated error)"
    );

    // (W1) ditto for a draft whose name != snap.skill_id.
    let mut forged_draft_blob = draft_blob("other-skill");
    forged_draft_blob.name = "other-skill".into();
    let forged_draft = LiveSnapshot {
        skill_id: "web-search".into(),
        active: None,
        draft: Some(forged_draft_blob),
    };
    assert!(
        matches!(
            store.restore_live(&forged_draft).await,
            Err(SkillError::InvalidTransition(ref m)) if m.contains("does not match the snapshot key")
        ),
        "restore_live must reject a forged draft.name with the KEY-BIND error"
    );

    // (W4) flush_draft enforces the same MAX_CONTENT_LEN (50_000) cap as
    // propose_draft — it must not become a content-size bypass.
    let mut big = draft_blob("web-search");
    big.content = "x".repeat(60_000);
    assert!(
        matches!(
            store.flush_draft(&big).await,
            Err(SkillError::ContentTooLarge(_))
        ),
        "flush_draft must reject oversized content"
    );

    // (adversarial-r4 W3) flush_draft ALSO caps the metadata — tags / reason —
    // not just content (a hand-staged blob is the only way these grow).
    let mut many_tags = draft_blob("web-search");
    many_tags.tags = (0..40).map(|i| format!("t{i}")).collect(); // > MAX_TAGS (32)
    assert!(
        many_tags.tags.len() > 32 && store.flush_draft(&many_tags).await.is_err(),
        "flush_draft must reject more than MAX_TAGS tags"
    );
    let mut big_reason = draft_blob("web-search");
    big_reason.parent = Some("web-search".into());
    big_reason.reason = Some("r".repeat(2_000)); // > MAX_REASON_LEN (1024)
    assert!(
        store.flush_draft(&big_reason).await.is_err(),
        "flush_draft must reject an oversized reason"
    );

    // (adversarial-r5) flush_draft validates `parent` (a skill-id ref) through
    // the same name gate — a traversal-shaped parent is rejected before the join.
    let mut bad_parent = draft_blob("web-search");
    bad_parent.parent = Some("../escape".into());
    bad_parent.reason = Some("r".into());
    assert!(
        store.flush_draft(&bad_parent).await.is_err(),
        "flush_draft must reject a traversal-shaped parent"
    );
}

/// A `SkillStorage` that delegates to a real `DiskSkillStorage` but, once armed,
/// FAILS a chosen write — to fault leg-(c)'s `restore_live` (`arm()` → fail
/// `write_draft`, the draft-first restore write) OR the coordinator's `activate`
/// AFTER it has installed the active (`arm_delete_draft()` → fail `delete_draft`,
/// which `SkillStore::activate` calls AFTER `write_active`). Both arm AFTER the
/// seed (`propose_draft` also `write_draft`s) so seeding is clean.
struct FailWriteDraftStorage {
    inner: DiskSkillStorage,
    armed: AtomicBool,
    fail_delete_draft: AtomicBool,
}
impl FailWriteDraftStorage {
    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }
    fn arm_delete_draft(&self) {
        self.fail_delete_draft.store(true, Ordering::SeqCst);
    }
}
#[async_trait]
impl SkillStorage for FailWriteDraftStorage {
    async fn read_draft(&self, name: &str) -> Result<Option<DraftBlob>, SkillError> {
        self.inner.read_draft(name).await
    }
    async fn write_draft(&self, blob: &DraftBlob) -> Result<(), SkillError> {
        if self.armed.load(Ordering::SeqCst) {
            return Err(SkillError::InvalidTransition(
                "simulated write_draft IO fault".into(),
            ));
        }
        self.inner.write_draft(blob).await
    }
    async fn delete_draft(&self, name: &str) -> Result<(), SkillError> {
        if self.fail_delete_draft.load(Ordering::SeqCst) {
            return Err(SkillError::InvalidTransition(
                "simulated delete_draft IO fault".into(),
            ));
        }
        self.inner.delete_draft(name).await
    }
    async fn list_drafts(&self) -> Result<Vec<DraftBlob>, SkillError> {
        self.inner.list_drafts().await
    }
    async fn read_active(&self, skill_id: &str) -> Result<Option<SkillBlob>, SkillError> {
        self.inner.read_active(skill_id).await
    }
    async fn write_active(&self, blob: &SkillBlob) -> Result<(), SkillError> {
        self.inner.write_active(blob).await
    }
    async fn delete_active(&self, skill_id: &str) -> Result<(), SkillError> {
        self.inner.delete_active(skill_id).await
    }
    async fn list_active(&self) -> Result<Vec<SkillBlob>, SkillError> {
        self.inner.list_active().await
    }
    async fn read_version(
        &self,
        skill_id: &str,
        version: u32,
    ) -> Result<Option<String>, SkillError> {
        self.inner.read_version(skill_id, version).await
    }
    async fn write_version(
        &self,
        skill_id: &str,
        version: u32,
        content: &str,
    ) -> Result<(), SkillError> {
        self.inner.write_version(skill_id, version, content).await
    }
    async fn list_versions(&self, skill_id: &str) -> Result<Vec<u32>, SkillError> {
        self.inner.list_versions(skill_id).await
    }
}

// ── TP-09 — a restore_live fault mid-compensation STILL re-enqueues the op ──

#[tokio::test]
async fn tp_09_restore_failure_still_reenqueues_op() {
    let dir = TempDir::new().unwrap();
    let canonical_root = std::fs::canonicalize(dir.path()).unwrap();
    let faulty = Arc::new(FailWriteDraftStorage {
        inner: DiskSkillStorage::with_default_writer(canonical_root.clone()),
        armed: AtomicBool::new(false),
        fail_delete_draft: AtomicBool::new(false),
    });
    let storage: Arc<dyn SkillStorage> = faulty.clone();
    let shared = Arc::new(tokio::sync::Mutex::new(SkillStore::with_storage(storage)));
    // Seed a fresh draft (no active) → fresh-activate path: pre-op live state is
    // {active:None, draft:Some}, so restore_live writes the draft FIRST. Seed
    // BEFORE arming (propose_draft also write_drafts).
    shared
        .lock()
        .await
        .propose_draft("web-search".into(), valid_skill_content(), vec![])
        .await
        .unwrap();
    // Arm the fault: now leg-(c)'s restore_live write_draft will fail.
    faulty.arm();
    let bus = Arc::new(CollectingEventBus::new());
    let queue = ScriptedCommitQueue::new(vec![Err(GitError::Libgit2 {
        code: "-1".into(),
        message: "commit-fail".into(),
    })]);
    let coordinator = coordinator_over(
        canonical_root,
        shared.clone(),
        queue.clone() as Arc<dyn GitCommitQueue>,
        bus.clone() as Arc<dyn EventBusEmit>,
    );
    let flusher = StoreDraftFlush::new(shared.clone());
    let mut driver = SkillTurnPersistenceDriver::new(
        shared.clone(),
        coordinator,
        Arc::new(flusher) as Arc<dyn RuntimePrivateFlush>,
    );

    // Commit fails → leg-(c) restore_live writes the draft first → that write
    // FAULTS → the compensation surfaces an Err, BUT the op MUST still be
    // re-enqueued (the W3 fix — a mid-restore fault does not lose the retry).
    let result = driver
        .commit_op_with_compensation(TurnSkillOp::Activate {
            draft_id: "web-search".into(),
            reason: "x".into(),
        })
        .await;
    assert!(result.is_err(), "a mid-restore fault surfaces as Err");
    assert_eq!(
        driver.pending().len(),
        1,
        "the op is STILL re-enqueued despite the restore failure (W3 fix — retry not lost)"
    );
    assert_eq!(bus.len(), 0, "no event on the failed commit");
}

// ── TP-10 — a torn restore ABORTS the turn + re-enqueues the remaining ops ──

#[tokio::test]
async fn tp_10_torn_restore_aborts_turn_and_reenqueues_remaining() {
    // A multi-op turn where op1's restore FAULTS (torn live state) → the turn
    // must STOP (not run op2 against torn state) and re-enqueue op2 for next turn
    // (adversarial-r2 fix). Witnesses run_turn_persistence's Torn-abort path.
    let dir = TempDir::new().unwrap();
    let canonical_root = std::fs::canonicalize(dir.path()).unwrap();
    let faulty = Arc::new(FailWriteDraftStorage {
        inner: DiskSkillStorage::with_default_writer(canonical_root.clone()),
        armed: AtomicBool::new(false),
        fail_delete_draft: AtomicBool::new(false),
    });
    let storage: Arc<dyn SkillStorage> = faulty.clone();
    let shared = Arc::new(tokio::sync::Mutex::new(SkillStore::with_storage(storage)));
    // Seed two fresh drafts (a, b) BEFORE arming (propose_draft write_drafts).
    {
        let g = shared.lock().await;
        g.propose_draft("skill-a".into(), valid_skill_content(), vec![])
            .await
            .unwrap();
        g.propose_draft("skill-b".into(), valid_skill_content(), vec![])
            .await
            .unwrap();
    }
    faulty.arm();
    let bus = Arc::new(CollectingEventBus::new());
    // Only op1 reaches the commit queue (op2 is never run) → one scripted Err.
    let queue = ScriptedCommitQueue::new(vec![Err(GitError::Libgit2 {
        code: "-1".into(),
        message: "commit-fail".into(),
    })]);
    let coordinator = coordinator_over(
        canonical_root,
        shared.clone(),
        queue.clone() as Arc<dyn GitCommitQueue>,
        bus.clone() as Arc<dyn EventBusEmit>,
    );
    let flusher = StoreDraftFlush::new(shared.clone());
    let mut driver = SkillTurnPersistenceDriver::new(
        shared.clone(),
        coordinator,
        Arc::new(flusher) as Arc<dyn RuntimePrivateFlush>,
    );

    let result = driver
        .run_turn_persistence(vec![
            TurnSkillOp::Activate {
                draft_id: "skill-a".into(),
                reason: "x".into(),
            },
            TurnSkillOp::Activate {
                draft_id: "skill-b".into(),
                reason: "y".into(),
            },
        ])
        .await;

    assert!(
        result.is_err(),
        "a torn restore aborts the turn with an Err"
    );
    // op1 re-enqueued by process_pending_op + op2 re-enqueued by the turn abort.
    assert_eq!(
        driver.pending().len(),
        2,
        "the torn op AND the unreached remaining op are both re-enqueued (not lost, not run)"
    );
    // op2 (skill-b) was NOT run: its draft is untouched (a run would consume it).
    assert!(
        shared
            .lock()
            .await
            .get_draft("skill-b")
            .await
            .unwrap()
            .is_some(),
        "the remaining op did NOT run against the torn state (its draft survives)"
    );
    // Only op1 reached the commit queue; the turn aborted before op2.
    assert_eq!(
        queue.call_count(),
        1,
        "only op1 submitted a commit; op2 never ran"
    );
}

// ── TP-11 — a NON-commit coordinator error rolls back the partial mutation ──

#[tokio::test]
async fn tp_11_non_commit_coordinator_error_rolls_back_partial_mutation() {
    // SkillStore::activate writes the active THEN delete_draft. If delete_draft
    // faults, activate returns a NON-commit error with a partial mutation (active
    // installed, draft not consumed, no commit). leg-(c) now rolls it back to the
    // pre-op snapshot regardless of the error class (adversarial-r3 W2): the op
    // is dropped (non-retryable) but the store is left CLEAN — no orphaned active.
    let dir = TempDir::new().unwrap();
    let canonical_root = std::fs::canonicalize(dir.path()).unwrap();
    let faulty = Arc::new(FailWriteDraftStorage {
        inner: DiskSkillStorage::with_default_writer(canonical_root.clone()),
        armed: AtomicBool::new(false),
        fail_delete_draft: AtomicBool::new(false),
    });
    let storage: Arc<dyn SkillStorage> = faulty.clone();
    let shared = Arc::new(tokio::sync::Mutex::new(SkillStore::with_storage(storage)));
    shared
        .lock()
        .await
        .propose_draft("web-search".into(), valid_skill_content(), vec![])
        .await
        .unwrap();
    // Arm the delete_draft fault: activate write_actives THEN delete_drafts (faults).
    faulty.arm_delete_draft();
    let bus = Arc::new(CollectingEventBus::new());
    // activate errors BEFORE the commit submit → the queue is never called.
    let queue = ScriptedCommitQueue::new(vec![]);
    let coordinator = coordinator_over(
        canonical_root,
        shared.clone(),
        queue.clone() as Arc<dyn GitCommitQueue>,
        bus.clone() as Arc<dyn EventBusEmit>,
    );
    let flusher = StoreDraftFlush::new(shared.clone());
    let mut driver = SkillTurnPersistenceDriver::new(
        shared.clone(),
        coordinator,
        Arc::new(flusher) as Arc<dyn RuntimePrivateFlush>,
    );

    let result = driver
        .commit_op_with_compensation(TurnSkillOp::Activate {
            draft_id: "web-search".into(),
            reason: "x".into(),
        })
        .await;

    assert!(
        result.is_err(),
        "a non-commit coordinator error surfaces as Err"
    );
    assert!(
        shared.lock().await.get("web-search").await.is_err(),
        "the partially-installed active is ROLLED BACK (no orphaned active)"
    );
    assert!(
        shared
            .lock()
            .await
            .get_draft("web-search")
            .await
            .unwrap()
            .is_some(),
        "the draft is preserved by the rollback"
    );
    assert_eq!(
        driver.pending().len(),
        0,
        "a non-retryable (non-commit) error is NOT re-enqueued"
    );
    assert_eq!(bus.len(), 0, "no event on the failed op");
    assert_eq!(
        queue.call_count(),
        0,
        "activate errored before the commit submit"
    );
}

/// Count commits reachable from HEAD; `0` on an unborn HEAD (no commits yet).
fn commit_count(workdir: &std::path::Path) -> usize {
    let repo = git2::Repository::open(workdir).expect("open repo");
    let mut walk = repo.revwalk().expect("revwalk");
    if walk.push_head().is_err() {
        return 0; // unborn HEAD — no commits
    }
    walk.count()
}

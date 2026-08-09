//! MODULE-011 slice satC-l6 (SAT-C) — cli L6 production-wiring integration
//! tests: the REAL `GitQueueL6Committer` (a real on-disk `CommitType::L6`
//! commit through `DefaultGitCommitQueue`) + the `L6DispatchAdapter` (216
//! component.error + 070 l6_completed shapes). These prove the production
//! construction end-to-end; the satellite flips no AC, so they gate via
//! `cargo test`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use advance_cli::l6_wiring::{GitQueueL6Committer, L6DispatchAdapter};
use advance_git::{bootstrap_repo_at, DefaultGitCommitQueue, GitCommitQueue};
use advance_shared_types::event::Event;
use advance_shared_types::memory::L6Handler;
use advance_shared_types::traits::EventBusEmit;

use cap_memory::clock::MutableClock;
use cap_memory::knowledge::{MemoryEntry, MemorySource, MemoryStatus, MemoryType};
use cap_memory::l6::{
    CommitFile, ContentKind, FailingCommitter, InMemoryCommitter, InMemoryEmitter,
    InMemoryLeaseStore, InMemoryStalenessProbe, KnowledgeMap, L6ClusterBuilder, L6CommitError,
    L6Committer, L6CursorStore, L6Emitter, L6Runnable, LeaseDecision, LeaseStore, StubL6Classifier,
    StubSynthesisGenerator, UuidBatchIdSource,
};
use cap_memory::store::MemoryStore;
use cap_memory::L6Dispatch;

fn t0() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000)
}

/// File-ref- or task-turn-sourced fact (mirrors integration_l6.rs::fact) so a
/// seeded cluster passes the L6 synthesis 5-gate (≥1 file-ref source).
fn fact(id: &str, content: &str, file_ref: bool) -> MemoryEntry {
    let sources = if file_ref {
        vec![MemorySource::FileRef {
            agent_id: "agent:r".into(),
            vpath: format!("data/{id}.csv"),
            commit_ish: "abc".into(),
            blob_id: format!("blob-{id}"),
            line_range: None,
        }]
    } else {
        vec![MemorySource::TaskTurn {
            task_id: "task-1".into(),
            turn: 1,
        }]
    };
    MemoryEntry {
        id: id.into(),
        agent_id: "agent:r".into(),
        entry_type: MemoryType::Fact,
        content: content.into(),
        tags: vec!["pricing".into()],
        created_at: "2026-01-01T00:00:00Z".into(),
        task_origin: None,
        is_active: true,
        superseded_by: None,
        status: MemoryStatus::Active,
        supersession_reason: None,
        cluster_id: None,
        sources,
    }
}

/// Capturing `EventBusEmit` double — records every emitted event so a test can
/// assert presence/absence of `component.error`.
#[derive(Default)]
struct CapturingBus {
    events: Mutex<Vec<Event>>,
}

impl EventBusEmit for CapturingBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

/// CLI-01 — a REAL on-disk `CommitType::L6` commit through the live
/// `DefaultGitCommitQueue`: the committed git TREE contains the staged L6 files
/// with their contents, and the commit message carries the `[l6]` type prefix.
/// (069 real-git hard requirement; the off-runtime `blocking_recv` bridge under
/// the current-thread runtime.)
#[tokio::test]
async fn cli_01_git_queue_l6_committer_real_commit() {
    let td = tempfile::tempdir().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();

    // The L6 artifacts must exist on disk before the commit (the rooted runnable
    // would have written them; here we write them directly to isolate the
    // committer). Absolute vpaths, as the rooted runnable emits.
    std::fs::write(workdir.join("knowledge.jsonl"), b"{\"id\":\"k1\"}\n").unwrap();
    std::fs::write(workdir.join("_knowledge_map.yaml"), b"topics: []\n").unwrap();
    std::fs::create_dir_all(workdir.join("syntheses")).unwrap();
    std::fs::write(workdir.join("syntheses/topic.md"), b"# topic\n").unwrap();

    let queue: Arc<dyn GitCommitQueue> =
        Arc::new(DefaultGitCommitQueue::spawn(workdir.clone()).unwrap());
    let committer = GitQueueL6Committer::new(queue, workdir.clone());

    let files = vec![
        CommitFile {
            vpath: workdir
                .join("knowledge.jsonl")
                .to_string_lossy()
                .into_owned(),
            content_kind: ContentKind::KnowledgeJsonl,
        },
        CommitFile {
            vpath: workdir
                .join("_knowledge_map.yaml")
                .to_string_lossy()
                .into_owned(),
            content_kind: ContentKind::KnowledgeMapYaml,
        },
        CommitFile {
            vpath: workdir
                .join("syntheses/topic.md")
                .to_string_lossy()
                .into_owned(),
            content_kind: ContentKind::Synthesis {
                path: "syntheses/topic.md".into(),
            },
        },
    ];

    let oid_str = committer
        .commit("agent:r", "b0c1d2e3", &files)
        .expect("real L6 commit succeeds");
    assert!(
        !oid_str.is_empty(),
        "committer returns the commit Oid string"
    );

    // Inspect the committed tree on disk via git2 — the files are really there.
    let repo = git2::Repository::open(&workdir).unwrap();
    let head = repo.head().unwrap().peel_to_commit().unwrap();
    assert_eq!(
        head.id().to_string(),
        oid_str,
        "returned Oid == HEAD commit"
    );
    let tree = head.tree().unwrap();
    assert!(
        tree.get_path(std::path::Path::new("knowledge.jsonl"))
            .is_ok(),
        "knowledge.jsonl committed"
    );
    assert!(
        tree.get_path(std::path::Path::new("_knowledge_map.yaml"))
            .is_ok(),
        "_knowledge_map.yaml committed"
    );
    assert!(
        tree.get_path(std::path::Path::new("syntheses/topic.md"))
            .is_ok(),
        "syntheses/topic.md committed"
    );
    let msg = head.message().unwrap_or("");
    assert!(
        msg.contains("[l6]"),
        "commit carries the CommitType::L6 prefix, got: {msg}"
    );
    assert!(
        msg.contains("runtime:l6"),
        "commit carries the runtime:l6 initiator, got: {msg}"
    );
}

/// CLI-02 — a path outside the git workdir → the queue rejects it → the
/// committer maps the GitError to `L6CommitError::Failed`.
#[tokio::test]
async fn cli_02_git_queue_l6_committer_maps_error() {
    let td = tempfile::tempdir().unwrap();
    let workdir = td.path().to_path_buf();
    bootstrap_repo_at(&workdir).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let outside_file = outside.path().join("escape.md");
    std::fs::write(&outside_file, b"x").unwrap();

    let queue: Arc<dyn GitCommitQueue> =
        Arc::new(DefaultGitCommitQueue::spawn(workdir.clone()).unwrap());
    let committer = GitQueueL6Committer::new(queue, workdir.clone());

    let files = vec![CommitFile {
        vpath: outside_file.to_string_lossy().into_owned(),
        content_kind: ContentKind::Synthesis {
            path: "escape.md".into(),
        },
    }];
    let err = committer
        .commit("agent:r", "b0c1d2e3", &files)
        .expect_err("a path outside the workdir must fail");
    assert!(
        matches!(err, L6CommitError::Failed(_)),
        "GitError maps to L6CommitError::Failed, got {err:?}"
    );
}

/// Build an `L6Runnable` (NOT rooted) sharing the given clock/lease, with the
/// given committer + emitter, seeded for one synthesis-eligible cluster.
fn build_runnable_for_adapter(
    store: Arc<MemoryStore>,
    clock: Arc<dyn cap_memory::Clock + Send + Sync>,
    lease: Arc<dyn LeaseStore + Send + Sync>,
    committer: Arc<dyn L6Committer + Send + Sync>,
    emitter: Arc<dyn L6Emitter + Send + Sync>,
) -> L6Runnable {
    L6Runnable::new(
        "memory.l6",
        clock,
        Arc::new(UuidBatchIdSource),
        store,
        lease,
        Arc::new(InMemoryStalenessProbe::new()),
        Arc::new(L6ClusterBuilder::new()),
        Arc::new(StubL6Classifier::new()),
        Arc::new(StubSynthesisGenerator),
        Arc::new(Mutex::new(KnowledgeMap::new())),
        Arc::new(Mutex::new(HashMap::new())),
        committer,
        emitter,
        Arc::new(L6CursorStore::new()),
    )
}

/// CLI-03 — a mid-run commit failure (FailingCommitter) surfaces as
/// `component.error` on the bus, the lease is cleared, and NO `memory.l6_completed`
/// is emitted; the adapter returns `false` (216 shape, end-to-end through the
/// cli adapter).
#[tokio::test]
async fn cli_03_adapter_failure_emits_component_error_clears_lease_no_completed() {
    let store = Arc::new(MemoryStore::new());
    for id in ["e1", "e2", "e3"] {
        store
            .insert(
                "agent:r",
                fact(id, "rust is memory safe and fast", id == "e1"),
            )
            .unwrap();
    }
    let clock: Arc<dyn cap_memory::Clock + Send + Sync> = Arc::new(MutableClock::new(t0()));
    let lease = Arc::new(InMemoryLeaseStore::new());
    let tok = match lease.begin_acquire("agent:r", t0(), Duration::from_secs(600)) {
        LeaseDecision::Acquired { token } => token,
        other => panic!("expected Acquired, got {other:?}"),
    };
    assert!(lease.confirm_acquire("agent:r", &tok));
    let lease_dyn: Arc<dyn LeaseStore + Send + Sync> = lease.clone();

    let inmem_emitter = Arc::new(InMemoryEmitter::new());
    let emitter_dyn: Arc<dyn L6Emitter + Send + Sync> = inmem_emitter.clone();

    let runnable = build_runnable_for_adapter(
        Arc::clone(&store),
        Arc::clone(&clock),
        lease_dyn,
        Arc::new(FailingCommitter::new()),
        emitter_dyn,
    );
    let handler: Arc<dyn L6Handler + Send + Sync> = Arc::new(runnable);
    let bus_concrete = Arc::new(CapturingBus::default());
    let bus_dyn: Arc<dyn EventBusEmit> = bus_concrete.clone();
    let adapter = L6DispatchAdapter::new(handler, bus_dyn, Arc::clone(&clock));

    let ok = adapter.dispatch("agent:r", &tok).await;
    assert!(!ok, "a failed consolidation returns false (no mark_l6_ran)");

    let events = bus_concrete.events.lock().unwrap();
    assert!(
        events.iter().any(|e| e.event_type == "component.error"),
        "a mid-run failure emits component.error on the bus"
    );
    assert!(
        inmem_emitter.emitted_l6_completed().is_empty(),
        "no memory.l6_completed on the failure path"
    );
    assert_eq!(
        lease.current_token("agent:r", t0()),
        None,
        "the runnable's Err-arm released the live lease"
    );
}

/// CLI-04 — a successful consolidation (InMemoryCommitter) emits
/// `memory.l6_completed` (delta + snapshot) via the shared emitter, the adapter
/// returns `true`, and NO `component.error` is emitted (070 shape).
#[tokio::test]
async fn cli_04_adapter_success_emits_l6_completed_no_component_error() {
    let store = Arc::new(MemoryStore::new());
    for id in ["e1", "e2", "e3"] {
        store
            .insert(
                "agent:r",
                fact(id, "rust is memory safe and fast", id == "e1"),
            )
            .unwrap();
    }
    let clock: Arc<dyn cap_memory::Clock + Send + Sync> = Arc::new(MutableClock::new(t0()));
    let lease = Arc::new(InMemoryLeaseStore::new());
    let tok = match lease.begin_acquire("agent:r", t0(), Duration::from_secs(600)) {
        LeaseDecision::Acquired { token } => token,
        other => panic!("expected Acquired, got {other:?}"),
    };
    assert!(lease.confirm_acquire("agent:r", &tok));
    let lease_dyn: Arc<dyn LeaseStore + Send + Sync> = lease.clone();

    let inmem_emitter = Arc::new(InMemoryEmitter::new());
    let emitter_dyn: Arc<dyn L6Emitter + Send + Sync> = inmem_emitter.clone();

    let runnable = build_runnable_for_adapter(
        Arc::clone(&store),
        Arc::clone(&clock),
        lease_dyn,
        Arc::new(InMemoryCommitter::new()),
        emitter_dyn,
    );
    let handler: Arc<dyn L6Handler + Send + Sync> = Arc::new(runnable);
    let bus_concrete = Arc::new(CapturingBus::default());
    let bus_dyn: Arc<dyn EventBusEmit> = bus_concrete.clone();
    let adapter = L6DispatchAdapter::new(handler, bus_dyn, Arc::clone(&clock));

    let ok = adapter.dispatch("agent:r", &tok).await;
    assert!(ok, "a successful consolidation returns true");

    let completed = inmem_emitter.emitted_l6_completed();
    assert_eq!(
        completed.len(),
        1,
        "exactly one memory.l6_completed emitted on success"
    );
    let events = bus_concrete.events.lock().unwrap();
    assert!(
        !events.iter().any(|e| e.event_type == "component.error"),
        "no component.error on the success path"
    );
}

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use advance_git::{CommitRequest, GitCommitQueue, GitError};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use async_trait::async_trait;
use cap_memory::{Resolution, SkillCandidate, SkillCandidateStore};
use cap_skills::persistence::{DiskSkillStorage, SkillSidecar, SkillStorage};
use cap_skills::{
    CandidateAction, CapMemorySkillHealthFlush, NoopSkillHealthFlush, SkillError, SkillHealthFlush,
    SkillPersistenceCoordinator, SkillStore, SkillTurnPersistenceDriver, SkillTurnRuntime,
    StoreDraftFlush,
};
use git2::Oid;
use tempfile::TempDir;
use tokio::sync::oneshot;

const AGENT: &str = "default-agent";

#[derive(Default)]
struct CollectingEventBus {
    events: Mutex<Vec<Event>>,
}

impl CollectingEventBus {
    fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }
}

impl EventBusEmit for CollectingEventBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

struct LeaseInspectingEventBus {
    root: PathBuf,
    events: Mutex<Vec<Event>>,
}

impl LeaseInspectingEventBus {
    fn new(root: &std::path::Path) -> Arc<Self> {
        Arc::new(Self {
            root: root.to_path_buf(),
            events: Mutex::new(Vec::new()),
        })
    }

    fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }
}

impl EventBusEmit for LeaseInspectingEventBus {
    fn emit(&self, event: Event) {
        let index = self.events.lock().unwrap().len();
        let lease_dir = self.root.join(".agent").join("_skill_turn_leases");
        let lease_path = std::fs::read_dir(&lease_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
            .expect("active lease file exists during runtime event emit");
        let lease_json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(lease_path).unwrap()).unwrap();
        assert_eq!(
            lease_json["emitted_runtime_event_count"].as_u64(),
            Some(index as u64),
            "runtime event progress must not be marked before emit returns"
        );
        assert_ne!(
            lease_json["phase"].as_str(),
            Some("runtime_events_emitted"),
            "all-events phase must not be persisted before emitting the current event"
        );
        self.events.lock().unwrap().push(event);
    }
}

struct ScriptedCommitQueue {
    results: Mutex<VecDeque<Result<Oid, GitError>>>,
    requests: Mutex<Vec<CommitRequest>>,
}

impl ScriptedCommitQueue {
    fn new(results: Vec<Result<Oid, GitError>>) -> Arc<Self> {
        Arc::new(Self {
            results: Mutex::new(VecDeque::from(results)),
            requests: Mutex::new(Vec::new()),
        })
    }

    fn call_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

impl GitCommitQueue for ScriptedCommitQueue {
    fn submit(&self, req: CommitRequest) -> oneshot::Receiver<Result<Oid, GitError>> {
        self.requests.lock().unwrap().push(req);
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

struct FailingHealthFlush {
    remaining_failures: Mutex<u32>,
}

#[async_trait]
impl SkillHealthFlush for FailingHealthFlush {
    async fn flush(&self, _agent_id: &str, _lease_id: &str) -> Result<(), SkillError> {
        let mut remaining = self.remaining_failures.lock().unwrap();
        if *remaining > 0 {
            *remaining -= 1;
            Err(SkillError::InvalidTransition("health flush failed".into()))
        } else {
            Ok(())
        }
    }
}

fn valid_content(name: &str) -> String {
    format!("---\nname: {name}\ndescription: a test skill\n---\n# {name}\nbody\n")
}

fn valid_content_with_body(name: &str, body: &str) -> String {
    format!("---\nname: {name}\ndescription: a test skill\n---\n# {name}\n{body}\n")
}

fn commit_failure() -> GitError {
    GitError::Libgit2 {
        code: "-1".into(),
        message: "test-failure".into(),
    }
}

fn runtime_with_health(
    root: &std::path::Path,
    health: Arc<dyn SkillHealthFlush>,
    results: Vec<Result<Oid, GitError>>,
) -> (
    Arc<SkillTurnRuntime>,
    Arc<tokio::sync::Mutex<SkillStore>>,
    Arc<DiskSkillStorage>,
    Arc<ScriptedCommitQueue>,
    Arc<CollectingEventBus>,
) {
    let storage = Arc::new(DiskSkillStorage::with_default_writer(root.to_path_buf()));
    let shared = Arc::new(tokio::sync::Mutex::new(SkillStore::with_storage(
        storage.clone(),
    )));
    let queue = ScriptedCommitQueue::new(results);
    let bus = Arc::new(CollectingEventBus::default());
    let (runtime, shared, storage, queue) = runtime_with_event_bus(
        root,
        health,
        queue,
        bus.clone() as Arc<dyn EventBusEmit>,
        shared,
        storage,
    );
    (runtime, shared, storage, queue, bus)
}

fn runtime_with_event_bus(
    root: &std::path::Path,
    health: Arc<dyn SkillHealthFlush>,
    queue: Arc<ScriptedCommitQueue>,
    bus: Arc<dyn EventBusEmit>,
    shared: Arc<tokio::sync::Mutex<SkillStore>>,
    storage: Arc<DiskSkillStorage>,
) -> (
    Arc<SkillTurnRuntime>,
    Arc<tokio::sync::Mutex<SkillStore>>,
    Arc<DiskSkillStorage>,
    Arc<ScriptedCommitQueue>,
) {
    let coordinator = Arc::new(SkillPersistenceCoordinator::with_shared_store(
        AGENT.to_string(),
        root.to_path_buf(),
        shared.clone(),
        queue.clone() as Arc<dyn GitCommitQueue>,
        bus.clone(),
    ));
    let flusher = Arc::new(StoreDraftFlush::new(shared.clone()));
    let driver = SkillTurnPersistenceDriver::new(shared.clone(), coordinator, flusher);
    let runtime = Arc::new(SkillTurnRuntime::new(
        AGENT,
        root.to_path_buf(),
        shared.clone(),
        driver,
        bus,
        health,
        root.join(".agent").join("memory"),
    ));
    (runtime, shared, storage, queue)
}

fn runtime(
    root: &std::path::Path,
    results: Vec<Result<Oid, GitError>>,
) -> (
    Arc<SkillTurnRuntime>,
    Arc<tokio::sync::Mutex<SkillStore>>,
    Arc<DiskSkillStorage>,
    Arc<ScriptedCommitQueue>,
    Arc<CollectingEventBus>,
) {
    runtime_with_health(
        root,
        Arc::new(CapMemorySkillHealthFlush::new(
            root.join(".agent").join("memory"),
        )),
        results,
    )
}

async fn lease_file_count(root: &std::path::Path) -> usize {
    lease_paths_with_extension(root, "json").await.len()
}

async fn parked_lease_file_count(root: &std::path::Path) -> usize {
    lease_paths_with_extension(root, "parked").await.len()
}

async fn lease_paths_with_extension(
    root: &std::path::Path,
    extension: &str,
) -> Vec<std::path::PathBuf> {
    let dir = root.join(".agent").join("_skill_turn_leases");
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => panic!("read lease dir: {e}"),
    };
    let mut paths = Vec::new();
    while let Some(entry) = entries.next_entry().await.unwrap() {
        if entry.path().extension().and_then(|ext| ext.to_str()) == Some(extension) {
            paths.push(entry.path());
        }
    }
    paths
}

fn seed_candidate(dir: &std::path::Path, name: &str, desc: &str) -> String {
    std::fs::create_dir_all(dir).unwrap();
    let candidate = SkillCandidate::new(name, desc);
    assert!(SkillCandidateStore::in_dir(dir)
        .append_generated(&candidate)
        .expect("append candidate"));
    candidate.candidate_id
}

#[tokio::test]
async fn live01_draft_only_flushes_runtime_private_and_skips_git_commit() {
    let dir = TempDir::new().unwrap();
    let (runtime, shared, _storage, queue, bus) = runtime(dir.path(), vec![]);
    let health_writer = cap_memory::SkillHealthWriter::in_dir(dir.path().join(".agent/memory"));
    health_writer
        .write(
            "previous-agent",
            "previous-lease",
            "2026-06-30T00:00:00Z".into(),
            &[cap_memory::l6::SkillHealthEntry {
                skill: "calendar".into(),
                status: "stale".into(),
            }],
        )
        .unwrap();

    let lease = runtime.begin_turn().await.unwrap();
    let draft_id = runtime
        .stage_propose_draft("web-search".into(), valid_content("web-search"), vec![])
        .await
        .unwrap();
    assert_eq!(draft_id, "web-search");
    runtime.finish_turn(&lease).await.unwrap();

    assert_eq!(queue.call_count(), 0);
    assert!(shared
        .lock()
        .await
        .get_draft("web-search")
        .await
        .unwrap()
        .is_some());
    let health_yaml =
        std::fs::read_to_string(dir.path().join(".agent/memory/_skill_health.yaml")).unwrap();
    let health: cap_memory::SkillHealthFile = serde_yml::from_str(&health_yaml).unwrap();
    assert_eq!(health.agent_id, AGENT);
    assert_eq!(health.lease_id, lease);
    assert_eq!(
        health.entries,
        vec![cap_memory::SkillHealthYamlEntry {
            skill: "calendar".into(),
            status: "stale".into()
        }],
        "turn heartbeat must preserve existing L6 skill-health entries"
    );
    let events = bus.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "skill.draft_created");
}

#[tokio::test]
async fn live_order_activate_flush_event_commit_then_git_dependent_event() {
    let dir = TempDir::new().unwrap();
    let (runtime, shared, _storage, queue, bus) = runtime(dir.path(), vec![Ok(Oid::zero())]);

    let lease = runtime.begin_turn().await.unwrap();
    runtime
        .stage_propose_draft("web-search".into(), valid_content("web-search"), vec![])
        .await
        .unwrap();
    runtime.stage_activate("web-search".into()).await.unwrap();
    runtime.finish_turn(&lease).await.unwrap();

    assert_eq!(queue.call_count(), 1);
    assert_eq!(
        shared.lock().await.get("web-search").await.unwrap().version,
        1
    );
    let event_types: Vec<String> = bus.events().into_iter().map(|e| e.event_type).collect();
    assert_eq!(
        event_types,
        vec![
            "skill.draft_created".to_string(),
            "skill.activated".to_string()
        ]
    );
}

#[tokio::test]
async fn live03_flush_failure_retries_once_then_turn_error_before_commit() {
    let dir = TempDir::new().unwrap();
    let failing_health = Arc::new(FailingHealthFlush {
        remaining_failures: Mutex::new(2),
    });
    let (runtime, _shared, _storage, queue, bus) =
        runtime_with_health(dir.path(), failing_health, vec![Ok(Oid::zero())]);

    let lease = runtime.begin_turn().await.unwrap();
    runtime
        .stage_propose_draft("web-search".into(), valid_content("web-search"), vec![])
        .await
        .unwrap();
    let err = runtime.finish_turn(&lease).await.unwrap_err();

    assert!(err.to_string().contains("runtime-private flush failed"));
    assert_eq!(queue.call_count(), 0);
    assert!(bus.events().is_empty());
    assert!(
        !runtime.is_active_for(AGENT).await,
        "failed finalizer must not leave a stale in-memory active lease"
    );
    assert_eq!(
        lease_file_count(dir.path()).await,
        1,
        "durable lease remains for reconciliation"
    );

    let next_lease = runtime.begin_turn().await.unwrap();
    assert_ne!(
        next_lease, lease,
        "reconciliation should drain the failed lease and open a fresh turn"
    );
    assert_eq!(queue.call_count(), 0);
    assert_eq!(bus.events().len(), 1);
    assert_eq!(
        lease_file_count(dir.path()).await,
        1,
        "old lease removed and the fresh turn lease remains"
    );
    runtime.abort_turn(&next_lease).await;
}

#[tokio::test]
async fn live04_commit_failure_persists_retry_lease_and_reconciles_next_turn() {
    let dir = TempDir::new().unwrap();
    let (runtime, shared, _storage, queue, _bus) = runtime_with_health(
        dir.path(),
        Arc::new(NoopSkillHealthFlush),
        vec![Err(commit_failure()), Ok(Oid::zero())],
    );

    let lease = runtime.begin_turn().await.unwrap();
    runtime
        .stage_propose_draft("web-search".into(), valid_content("web-search"), vec![])
        .await
        .unwrap();
    runtime.stage_activate("web-search".into()).await.unwrap();
    runtime.finish_turn(&lease).await.unwrap();

    assert_eq!(queue.call_count(), 1);
    assert!(shared.lock().await.get("web-search").await.is_err());
    assert_eq!(lease_file_count(dir.path()).await, 1);

    let next_lease = runtime.begin_turn().await.unwrap();

    assert_eq!(queue.call_count(), 2);
    assert_eq!(
        shared.lock().await.get("web-search").await.unwrap().version,
        1
    );
    assert_eq!(
        lease_file_count(dir.path()).await,
        1,
        "retry lease removed and the new turn lease remains"
    );
    runtime.abort_turn(&next_lease).await;
}

#[tokio::test]
async fn live06_stale_reconcile_precondition_parks_lease_without_replay() {
    let dir = TempDir::new().unwrap();
    let (runtime, shared, _storage, _queue, _bus) =
        runtime_with_health(dir.path(), Arc::new(NoopSkillHealthFlush), vec![]);

    {
        let store = shared.lock().await;
        store
            .propose_draft(
                "web-search".into(),
                valid_content_with_body("web-search", "v1"),
                vec![],
            )
            .await
            .unwrap();
        store.activate("web-search").await.unwrap();
    }
    let lease = runtime.begin_turn().await.unwrap();
    runtime.stage_delete("web-search".into()).await.unwrap();
    assert_eq!(lease_file_count(dir.path()).await, 1);

    {
        let store = shared.lock().await;
        store
            .propose_draft(
                "web-search".into(),
                valid_content_with_body("web-search", "v2"),
                vec![],
            )
            .await
            .unwrap();
        store.activate("web-search").await.unwrap();
    }

    let (runtime_after_restart, shared_after_restart, _storage, queue, _bus) = runtime_with_health(
        dir.path(),
        Arc::new(NoopSkillHealthFlush),
        vec![Ok(Oid::zero())],
    );
    let err = runtime_after_restart.begin_turn().await.unwrap_err();

    assert!(
        err.to_string()
            .contains("turn journal precondition mismatch"),
        "unexpected error: {err}"
    );
    assert_eq!(
        queue.call_count(),
        0,
        "stale lease must not reach git commit"
    );
    assert_eq!(
        shared_after_restart
            .lock()
            .await
            .get("web-search")
            .await
            .unwrap()
            .version,
        2,
        "newer active skill must be preserved"
    );
    assert_eq!(lease_file_count(dir.path()).await, 0);
    assert_eq!(parked_lease_file_count(dir.path()).await, 1);
    runtime.abort_turn(&lease).await;
}

#[tokio::test]
async fn live07_runtime_event_progress_is_persisted_after_each_emit() {
    let dir = TempDir::new().unwrap();
    let storage = Arc::new(DiskSkillStorage::with_default_writer(
        dir.path().to_path_buf(),
    ));
    let shared = Arc::new(tokio::sync::Mutex::new(SkillStore::with_storage(
        storage.clone(),
    )));
    let queue = ScriptedCommitQueue::new(vec![]);
    let bus = LeaseInspectingEventBus::new(dir.path());
    let (runtime, _shared, _storage, queue) = runtime_with_event_bus(
        dir.path(),
        Arc::new(NoopSkillHealthFlush),
        queue,
        bus.clone() as Arc<dyn EventBusEmit>,
        shared,
        storage,
    );

    let lease = runtime.begin_turn().await.unwrap();
    runtime
        .stage_propose_draft("web-search".into(), valid_content("web-search"), vec![])
        .await
        .unwrap();
    runtime
        .stage_update_draft("web-search", valid_content_with_body("web-search", "v2"))
        .await
        .unwrap();
    runtime.finish_turn(&lease).await.unwrap();

    assert_eq!(queue.call_count(), 0);
    let event_types: Vec<String> = bus.events().into_iter().map(|e| e.event_type).collect();
    assert_eq!(
        event_types,
        vec![
            "skill.draft_created".to_string(),
            "skill.draft_updated".to_string()
        ]
    );
    assert_eq!(lease_file_count(dir.path()).await, 0);
}

#[tokio::test]
async fn live09_runtime_event_replay_resumes_after_persisted_event_count() {
    let dir = TempDir::new().unwrap();
    let (runtime, shared, _storage, _queue, _bus) =
        runtime_with_health(dir.path(), Arc::new(NoopSkillHealthFlush), vec![]);

    let lease = runtime.begin_turn().await.unwrap();
    runtime
        .stage_propose_draft("web-search".into(), valid_content("web-search"), vec![])
        .await
        .unwrap();
    runtime
        .stage_update_draft("web-search", valid_content_with_body("web-search", "v2"))
        .await
        .unwrap();
    {
        let store = shared.lock().await;
        store
            .propose_draft("web-search".into(), valid_content("web-search"), vec![])
            .await
            .unwrap();
    }
    let paths = lease_paths_with_extension(dir.path(), "json").await;
    assert_eq!(paths.len(), 1);
    let mut lease_json: serde_json::Value =
        serde_json::from_slice(&tokio::fs::read(&paths[0]).await.unwrap()).unwrap();
    lease_json["phase"] = serde_json::Value::String("runtime_private_flushed".into());
    lease_json["emitted_runtime_event_count"] = serde_json::Value::Number(1.into());
    tokio::fs::write(&paths[0], serde_json::to_vec_pretty(&lease_json).unwrap())
        .await
        .unwrap();

    let (runtime_after_restart, _shared, _storage, queue, bus) =
        runtime_with_health(dir.path(), Arc::new(NoopSkillHealthFlush), vec![]);
    let next_lease = runtime_after_restart.begin_turn().await.unwrap();

    assert_eq!(queue.call_count(), 0);
    let event_types: Vec<String> = bus.events().into_iter().map(|e| e.event_type).collect();
    assert_eq!(
        event_types,
        vec!["skill.draft_updated".to_string()],
        "replay resumes after the persisted runtime event count"
    );
    assert_eq!(lease_file_count(dir.path()).await, 1);
    runtime_after_restart.abort_turn(&next_lease).await;
    runtime.abort_turn(&lease).await;
}

#[tokio::test]
async fn live08_candidate_accept_replay_tolerates_already_resolved_partial_flush() {
    let dir = TempDir::new().unwrap();
    let candidate_dir = dir.path().join(".agent").join("memory");
    let candidate_id = seed_candidate(&candidate_dir, "summarize-pr", "Summarize a pull request");
    let (runtime, _shared, _storage, _queue, _bus) =
        runtime_with_health(dir.path(), Arc::new(NoopSkillHealthFlush), vec![]);

    let lease = runtime.begin_turn().await.unwrap();
    runtime
        .stage_resolve_candidate(&candidate_id, CandidateAction::Accept)
        .await
        .unwrap();
    SkillCandidateStore::in_dir(&candidate_dir)
        .resolve(&candidate_id, Resolution::Accept)
        .unwrap();

    let (runtime_after_restart, shared_after_restart, _storage, _queue, bus) =
        runtime_with_health(dir.path(), Arc::new(NoopSkillHealthFlush), vec![]);
    let next_lease = runtime_after_restart.begin_turn().await.unwrap();

    assert!(
        SkillCandidateStore::in_dir(&candidate_dir)
            .list_pending()
            .unwrap()
            .is_empty(),
        "candidate remains terminal after replay"
    );
    assert!(shared_after_restart
        .lock()
        .await
        .get_draft("summarize-pr")
        .await
        .unwrap()
        .is_some());
    let event_types: Vec<String> = bus.events().into_iter().map(|e| e.event_type).collect();
    assert_eq!(
        event_types,
        vec![
            "skill.draft_created".to_string(),
            "skill.candidate_resolved".to_string()
        ]
    );
    runtime_after_restart.abort_turn(&next_lease).await;
    runtime.abort_turn(&lease).await;
}

#[tokio::test]
async fn live05_delete_commit_failure_restores_sidecars_and_emits_no_delete_event() {
    let dir = TempDir::new().unwrap();
    let (runtime, shared, storage, queue, bus) = runtime_with_health(
        dir.path(),
        Arc::new(NoopSkillHealthFlush),
        vec![Err(commit_failure())],
    );

    {
        let store = shared.lock().await;
        store
            .propose_draft("web-search".into(), valid_content("web-search"), vec![])
            .await
            .unwrap();
        store.activate("web-search").await.unwrap();
    }
    storage
        .write_skill_sidecar("web-search", SkillSidecar::ToolWasm, b"wasm")
        .await
        .unwrap();

    let lease = runtime.begin_turn().await.unwrap();
    runtime.stage_delete("web-search".into()).await.unwrap();
    runtime.finish_turn(&lease).await.unwrap();

    assert_eq!(queue.call_count(), 1);
    assert!(shared.lock().await.get("web-search").await.is_ok());
    assert_eq!(
        storage
            .read_skill_sidecar("web-search", SkillSidecar::ToolWasm)
            .await
            .unwrap(),
        Some(b"wasm".to_vec())
    );
    assert!(bus
        .events()
        .into_iter()
        .all(|event| event.event_type != "skill.deleted"));
}

// ─── 2026-07-03 §3.6 (ccc) closure witnesses ────────────────────────────────
//
// LIVE-11..14: the crash-robustness fixes — a torn/corrupt lease QUARANTINES
// instead of wedging begin_turn forever; deterministic replay errors are
// bounded then parked; stale atomic-write temps are swept; and an Err turn
// leaves the DURABLE lease file as the single retry track (the in-memory
// pending queue is discarded, so nothing can replay without preconditions).

/// LIVE-11: a torn/corrupt journal (crash artifact or tampering) is parked with
/// an error file and begin_turn SUCCEEDS — the failure mode this guards against
/// is the permanent wedge where every inbound message errors at begin_turn and
/// is consumed by the scheduler.
#[tokio::test]
async fn live11_torn_lease_journal_parks_and_begin_turn_recovers() {
    let dir = TempDir::new().unwrap();
    let (runtime, _shared, _storage, _queue, _bus) =
        runtime_with_health(dir.path(), Arc::new(NoopSkillHealthFlush), vec![]);

    let lease_dir = dir.path().join(".agent").join("_skill_turn_leases");
    std::fs::create_dir_all(&lease_dir).unwrap();
    std::fs::write(lease_dir.join("torn.json"), b"{ definitely not json").unwrap();

    let lease = runtime
        .begin_turn()
        .await
        .expect("begin_turn must not wedge on a torn lease journal");

    assert_eq!(parked_lease_file_count(dir.path()).await, 1);
    assert!(lease_dir.join("torn.error.txt").exists());
    assert!(!lease_dir.join("torn.json").exists());
    runtime.abort_turn(&lease).await;

    // And a SECOND begin_turn stays clean (the parked file is never re-parsed).
    let lease = runtime.begin_turn().await.unwrap();
    runtime.abort_turn(&lease).await;
}

/// LIVE-12: a lease whose replay fails deterministically with a
/// NON-precondition error (here: a persistently-failing health flush) errors
/// begin_turn a BOUNDED number of times (MAX_RECONCILE_ATTEMPTS = 3 replays)
/// and is then parked — the message lane recovers instead of looping forever.
#[tokio::test]
async fn live12_deterministic_replay_error_parks_after_bounded_attempts() {
    let dir = TempDir::new().unwrap();
    let (runtime, _shared, _storage, _queue, _bus) = runtime_with_health(
        dir.path(),
        Arc::new(FailingHealthFlush {
            remaining_failures: Mutex::new(u32::MAX),
        }),
        vec![],
    );

    // Turn 1 leaves an unfinished lease on disk (flush fails at finish).
    let lease = runtime.begin_turn().await.unwrap();
    assert!(runtime.finish_turn(&lease).await.is_err());
    assert_eq!(lease_file_count(dir.path()).await, 1);

    // Replays 1..=3 fail (bounded), attempt 4 parks.
    for attempt in 1..=3 {
        let err = runtime
            .begin_turn()
            .await
            .expect_err("bounded replay attempt must surface the replay error");
        assert!(
            !err.to_string().contains("exceeded"),
            "attempt {attempt} is within the bound: {err}"
        );
    }
    let err = runtime
        .begin_turn()
        .await
        .expect_err("attempt past the bound must park");
    assert!(
        err.to_string().contains("exceeded 3 reconcile attempts"),
        "park error names the bound: {err}"
    );
    assert_eq!(parked_lease_file_count(dir.path()).await, 1);
    assert_eq!(lease_file_count(dir.path()).await, 0);

    // Lane recovered: the next begin_turn is clean.
    let lease = runtime.begin_turn().await.unwrap();
    runtime.abort_turn(&lease).await;
}

/// LIVE-13: a stale atomic-write temp (crash between tmp create and rename) is
/// swept by reconcile and never treated as a lease.
#[tokio::test]
async fn live13_stale_lease_tmp_file_is_swept() {
    let dir = TempDir::new().unwrap();
    let (runtime, _shared, _storage, _queue, _bus) =
        runtime_with_health(dir.path(), Arc::new(NoopSkillHealthFlush), vec![]);

    let lease_dir = dir.path().join(".agent").join("_skill_turn_leases");
    std::fs::create_dir_all(&lease_dir).unwrap();
    std::fs::write(lease_dir.join("stale.json.tmp"), b"garbage").unwrap();

    let lease = runtime.begin_turn().await.unwrap();
    assert!(!lease_dir.join("stale.json.tmp").exists());
    assert_eq!(parked_lease_file_count(dir.path()).await, 0);
    runtime.abort_turn(&lease).await;
}

/// Storage wrapper that fails `delete_active` while armed — used to tear a
/// `restore_live` mid-restore (the draft half restores, the active half does
/// not), i.e. the §3.6 (ccc) flip-blocker (B) window.
struct FailingDeleteActiveStorage {
    inner: Arc<DiskSkillStorage>,
    fail_delete_active: std::sync::atomic::AtomicU32,
}

#[async_trait]
impl SkillStorage for FailingDeleteActiveStorage {
    async fn read_draft(
        &self,
        name: &str,
    ) -> Result<Option<cap_skills::persistence::DraftBlob>, SkillError> {
        self.inner.read_draft(name).await
    }
    async fn write_draft(
        &self,
        blob: &cap_skills::persistence::DraftBlob,
    ) -> Result<(), SkillError> {
        self.inner.write_draft(blob).await
    }
    async fn delete_draft(&self, name: &str) -> Result<(), SkillError> {
        self.inner.delete_draft(name).await
    }
    async fn list_drafts(&self) -> Result<Vec<cap_skills::persistence::DraftBlob>, SkillError> {
        self.inner.list_drafts().await
    }
    async fn read_active(
        &self,
        skill_id: &str,
    ) -> Result<Option<cap_skills::persistence::SkillBlob>, SkillError> {
        self.inner.read_active(skill_id).await
    }
    async fn write_active(
        &self,
        blob: &cap_skills::persistence::SkillBlob,
    ) -> Result<(), SkillError> {
        self.inner.write_active(blob).await
    }
    async fn delete_active(&self, skill_id: &str) -> Result<(), SkillError> {
        use std::sync::atomic::Ordering;
        if self.fail_delete_active.load(Ordering::SeqCst) > 0 {
            self.fail_delete_active.fetch_sub(1, Ordering::SeqCst);
            return Err(SkillError::InvalidTransition(
                "injected delete_active fault".into(),
            ));
        }
        self.inner.delete_active(skill_id).await
    }
    async fn list_active(&self) -> Result<Vec<cap_skills::persistence::SkillBlob>, SkillError> {
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

/// LIVE-14: torn-restore end-to-end over the durable single-track — an
/// activate op whose commit fails AND whose compensating restore tears (active
/// half survives the rollback) errors the turn; the in-memory pending queue is
/// DISCARDED (single track), the durable lease replays precondition-gated on
/// the next begin_turn, detects the torn state (mismatch) and PARKS with the
/// evidence preserved — and the op is never re-executed without preconditions
/// (the git queue sees exactly one commit attempt, ever).
#[tokio::test]
async fn live14_torn_restore_single_track_parks_and_never_replays_unguarded() {
    let dir = TempDir::new().unwrap();
    let disk = Arc::new(DiskSkillStorage::with_default_writer(
        dir.path().to_path_buf(),
    ));
    let failing = Arc::new(FailingDeleteActiveStorage {
        inner: disk,
        // restore_live retries each half once → 2 injected failures tear the
        // FIRST restore; later reconciles never reach delete_active (they park
        // at the precondition gate first).
        fail_delete_active: std::sync::atomic::AtomicU32::new(2),
    });
    let shared = Arc::new(tokio::sync::Mutex::new(SkillStore::with_storage(
        failing.clone(),
    )));
    let queue = ScriptedCommitQueue::new(vec![Err(commit_failure())]);
    let bus = Arc::new(CollectingEventBus::default());
    let coordinator = Arc::new(SkillPersistenceCoordinator::with_shared_store(
        AGENT.to_string(),
        dir.path().to_path_buf(),
        shared.clone(),
        queue.clone() as Arc<dyn GitCommitQueue>,
        bus.clone() as Arc<dyn EventBusEmit>,
    ));
    let flusher = Arc::new(StoreDraftFlush::new(shared.clone()));
    let driver = SkillTurnPersistenceDriver::new(shared.clone(), coordinator, flusher);
    let runtime = Arc::new(SkillTurnRuntime::new(
        AGENT,
        dir.path().to_path_buf(),
        shared.clone(),
        driver,
        bus as Arc<dyn EventBusEmit>,
        Arc::new(NoopSkillHealthFlush),
        dir.path().join(".agent").join("memory"),
    ));

    let lease = runtime.begin_turn().await.unwrap();
    runtime
        .stage_propose_draft("web-search".into(), valid_content("web-search"), vec![])
        .await
        .unwrap();
    runtime.stage_activate("web-search".into()).await.unwrap();
    // Commit fails → leg-(c) rollback → restore tears on the active half
    // (injected delete_active fault ×2 beats the retry-once) → turn errors.
    assert!(runtime.finish_turn(&lease).await.is_err());
    assert_eq!(queue.call_count(), 1);
    assert_eq!(
        lease_file_count(dir.path()).await,
        1,
        "the ORIGINAL lease journal is the single durable retry record"
    );

    // Next begin_turn replays precondition-gated: the torn active half fails
    // the activate op's pre-state check → the lease PARKS (evidence kept).
    let err = runtime
        .begin_turn()
        .await
        .expect_err("torn state must park at the precondition gate");
    assert!(
        err.to_string().contains("precondition mismatch"),
        "parked via the precondition gate: {err}"
    );
    assert_eq!(parked_lease_file_count(dir.path()).await, 1);
    assert_eq!(lease_file_count(dir.path()).await, 0);

    // The discarded in-memory pending can never replay unguarded: a fresh
    // clean turn runs and the git queue still saw exactly ONE commit attempt.
    let lease = runtime.begin_turn().await.unwrap();
    runtime.finish_turn(&lease).await.unwrap();
    assert_eq!(
        queue.call_count(),
        1,
        "no unguarded replay of the torn op after the park"
    );
}

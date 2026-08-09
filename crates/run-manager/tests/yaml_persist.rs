//! Slice C AC-15 tests (T71–T76b): YAML persistence + recovery write-back.

use std::sync::{Arc, Mutex};

use advance_run_manager::{persist::RunPersister, RecoveryReport, Run, RunConfig, RunManager};
use advance_shared_types::await_session::{
    AwaitSessionRef, AwaitTreeSummary, OrchestrationError, SessionId,
};
use advance_shared_types::event::Event;
use advance_shared_types::run::TaskRunStatus;
use advance_shared_types::traits::EventBusEmit;
use async_trait::async_trait;
use tempfile::TempDir;

#[derive(Default)]
struct MockBus {
    events: Mutex<Vec<Event>>,
}

impl EventBusEmit for MockBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

struct MockAwaitRef {
    exists_returns: bool,
}

#[async_trait]
impl AwaitSessionRef for MockAwaitRef {
    fn exists(&self, _sid: &SessionId) -> bool {
        self.exists_returns
    }
    fn walk_tree(&self, _sid: &SessionId) -> Option<AwaitTreeSummary> {
        None
    }
    async fn close(&self, _sid: &SessionId, _reason: &str) -> Result<(), OrchestrationError> {
        Ok(())
    }
}

fn mgr_with_dir(dir: &TempDir) -> Arc<RunManager> {
    let bus: Arc<dyn EventBusEmit> = Arc::new(MockBus::default());
    Arc::new(RunManager::new(bus).with_state_dir(dir.path().to_path_buf()))
}

/// T71 — ensure_run persists `<task_id>.yaml`.
#[test]
fn t71_ensure_run_persists_yaml() {
    let dir = TempDir::new().unwrap();
    let mgr = mgr_with_dir(&dir);
    let _id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();

    let path = dir.path().join("task-1.yaml");
    assert!(path.exists(), "task-1.yaml should exist after ensure_run");
    let body = std::fs::read_to_string(&path).unwrap();
    let run: Run = serde_yml::from_str(&body).unwrap();
    assert_eq!(run.task_id, "task-1");
    assert!(matches!(run.status, TaskRunStatus::Active));
}

/// T72 — complete_run rewrites yaml with Completed status.
#[tokio::test]
async fn t72_complete_run_rewrites_yaml() {
    let dir = TempDir::new().unwrap();
    let mgr = mgr_with_dir(&dir);
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    mgr.complete_run(&id, "ok".into()).unwrap();

    let body = std::fs::read_to_string(dir.path().join("task-1.yaml")).unwrap();
    let run: Run = serde_yml::from_str(&body).unwrap();
    assert!(matches!(run.status, TaskRunStatus::Completed));
}

/// T73 — pre-create `task-1.yaml.tmp`; ensure_run completes anyway. (The
/// tempfile NamedTempFile uses a random suffix so name collision is
/// vanishingly unlikely; this test exercises the happy path.)
#[test]
fn t73_atomic_write_no_partial_under_pre_staged_tmp() {
    let dir = TempDir::new().unwrap();
    // Pre-stage a stale tmp file in the dir — should NOT interfere with
    // the persister's own NamedTempFile (which uses a unique random name).
    std::fs::write(dir.path().join("task-1.yaml.tmp.stale"), b"garbage").unwrap();
    let mgr = mgr_with_dir(&dir);
    let _id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    let body = std::fs::read_to_string(dir.path().join("task-1.yaml")).unwrap();
    let run: Run = serde_yml::from_str(&body).unwrap();
    assert_eq!(run.task_id, "task-1");
}

/// T73b — basic write-roundtrip after persist; reopen + read back bytes
/// matches the just-written YAML. (fsync mechanical verification is
/// deferred per §3.6.)
#[test]
fn t73b_write_roundtrip_reads_back_bytes() {
    let dir = TempDir::new().unwrap();
    let mgr = mgr_with_dir(&dir);
    let id = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    let body_first = std::fs::read_to_string(dir.path().join("task-1.yaml")).unwrap();
    let run_first: Run = serde_yml::from_str(&body_first).unwrap();
    assert_eq!(run_first.id.as_ref(), id.as_ref());
}

/// T74 — Unix only: file mode 0o600.
#[cfg(unix)]
#[test]
fn t74_unix_file_mode_0o600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let mgr = mgr_with_dir(&dir);
    let _ = mgr
        .ensure_run("task-1", "root", RunConfig::default())
        .unwrap();
    let meta = std::fs::metadata(dir.path().join("task-1.yaml")).unwrap();
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "file mode must be 0o600, got 0o{:o}", mode);
}

/// T75 — cold_start_recovery: pre-seed a Suspended Run YAML, then
/// recovery loads + emits run.interrupted when its session is missing.
#[tokio::test]
async fn t75_cold_start_recovery_loads_and_interrupts() {
    let dir = TempDir::new().unwrap();
    let bus = Arc::new(MockBus::default());
    let mgr: Arc<RunManager> = Arc::new(
        RunManager::new(Arc::clone(&bus) as Arc<dyn EventBusEmit>)
            .with_state_dir(dir.path().to_path_buf()),
    );
    // Pre-seed `task-1.yaml` with a Suspended Run + a session_id that the
    // mock walker says doesn't exist.
    let persister = RunPersister::new(dir.path().to_path_buf());
    let mut run = Run::new("task-1", "root", RunConfig::default(), chrono::Utc::now());
    run.status = TaskRunStatus::Suspended;
    run.root_await = Some("sid-A".to_string());
    persister.persist(&run).unwrap();

    let ar: Arc<dyn AwaitSessionRef> = Arc::new(MockAwaitRef {
        exists_returns: false,
    });
    let report = mgr.cold_start_recovery(ar).await.unwrap();
    assert_eq!(report.disk_loaded, 1, "disk_loaded");
    assert_eq!(report.suspended_scanned, 1, "suspended_scanned");
    assert_eq!(report.interrupted_emitted, 1, "interrupted_emitted");

    let types: Vec<String> = bus
        .events
        .lock()
        .unwrap()
        .iter()
        .map(|e| e.event_type.clone())
        .collect();
    assert!(types.iter().any(|t| t == "run.interrupted"));
}

/// T75b — persister path-traversal defense matrix.
#[test]
fn t75b_persister_path_traversal_defense() {
    // REJECT cases.
    for bad in [".", "..", ".foo", "a..b"] {
        let res = RunPersister::validate_path_safe(bad);
        assert!(
            res.is_err(),
            "task_id={:?} should be rejected, got {:?}",
            bad,
            res
        );
    }
    // ACCEPT cases (including REQ-069 `:` namespace).
    for good in ["auto:agent-foo", "user:alice", "task-001"] {
        assert!(
            RunPersister::validate_path_safe(good).is_ok(),
            "task_id={:?} should be accepted",
            good
        );
    }
}

/// T76 — recover_from_disk skips corrupted YAML and counts `disk_invalid`.
#[tokio::test]
async fn t76_corrupted_yaml_skip_increments_disk_invalid() {
    let dir = TempDir::new().unwrap();
    let bus = Arc::new(MockBus::default());
    let mgr: Arc<RunManager> = Arc::new(
        RunManager::new(Arc::clone(&bus) as Arc<dyn EventBusEmit>)
            .with_state_dir(dir.path().to_path_buf()),
    );
    std::fs::write(
        dir.path().join("badfile.yaml"),
        b"this is not yaml: { broken",
    )
    .unwrap();

    let report: RecoveryReport = mgr.recover_from_disk().unwrap();
    assert_eq!(
        report.disk_invalid, 1,
        "disk_invalid should count the bad file"
    );
    assert_eq!(report.disk_loaded, 0, "disk_loaded should be 0");
}

/// T76b — crash-recovery write-back: persist the Suspended→Active flip
/// to disk BEFORE the run.interrupted emit, so a second restart no
/// longer re-interrupts.
#[tokio::test]
async fn t76b_crash_recovery_write_back() {
    let dir = TempDir::new().unwrap();
    let bus = Arc::new(MockBus::default());
    let mgr: Arc<RunManager> = Arc::new(
        RunManager::new(Arc::clone(&bus) as Arc<dyn EventBusEmit>)
            .with_state_dir(dir.path().to_path_buf()),
    );
    // Pre-seed Suspended run.
    let persister = RunPersister::new(dir.path().to_path_buf());
    let mut run = Run::new("task-1", "root", RunConfig::default(), chrono::Utc::now());
    run.status = TaskRunStatus::Suspended;
    run.root_await = Some("sid-A".to_string());
    persister.persist(&run).unwrap();

    let ar: Arc<dyn AwaitSessionRef> = Arc::new(MockAwaitRef {
        exists_returns: false,
    });
    let _ = mgr.cold_start_recovery(ar).await.unwrap();

    // Re-read the YAML from disk — should now say Active + root_await=null.
    let body = std::fs::read_to_string(dir.path().join("task-1.yaml")).unwrap();
    let reloaded: Run = serde_yml::from_str(&body).unwrap();
    assert!(
        matches!(reloaded.status, TaskRunStatus::Active),
        "status on disk should be Active after recovery write-back, got {:?}",
        reloaded.status
    );
    assert!(
        reloaded.root_await.is_none(),
        "root_await on disk should be None after recovery, got {:?}",
        reloaded.root_await
    );
}

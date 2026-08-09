//! Slice C AC-19 verification: `runnable.run(config)` shared ABI across
//! the 4 non-agent driver types (cron / watcher / daemon / task), plus
//! the `output-dir/result.bin` atomic-write.
//!
//! Per driver: spawn a mock `RunnableHook` that returns
//! `RunResult { status: Completed, output: Some(b"hello-{id}") }`, drive
//! the driver pointing at a `tempfile::tempdir()` rooted `output_dir`,
//! then read `{tempdir}/result.bin` back and assert byte-for-byte
//! equality with the canned output.
//!
//! 5th sub-test: when `RunResult.output == None`, no `result.bin` file
//! is created (write-helper short-circuit).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

use advance_scheduler::cron::CronDriver;
use advance_scheduler::daemon::DaemonManager;
use advance_scheduler::hook::{HookError, RunnableHook};
use advance_scheduler::task::TaskRunner;
use advance_scheduler::trigger_bus::TriggerBusDispatchImpl;
use advance_scheduler::trigger_source::{TriggerEventSource, TriggerSource};
use advance_scheduler::types::{
    ComponentConfig, ComponentSubmitConfig, RestartPolicy, RunResult, RunStatus,
    TriggerSubscription,
};
use advance_scheduler::watcher::WatcherDriver;
use advance_scheduler::TriggerBusDispatch;
use advance_shared_types::component::ComponentType;
use advance_shared_types::event::Event;

/// Mock hook returning a canned `RunResult` with `output = Some(payload)`.
struct CannedOutputHook {
    payload: Vec<u8>,
}

#[async_trait]
impl RunnableHook for CannedOutputHook {
    async fn run_once(&self, _config: ComponentConfig) -> Result<RunResult, HookError> {
        Ok(RunResult {
            status: RunStatus::Completed,
            output: Some(self.payload.clone()),
        })
    }
}

/// Mock hook returning Completed with no output bytes (None).
struct NoneOutputHook;

#[async_trait]
impl RunnableHook for NoneOutputHook {
    async fn run_once(&self, _config: ComponentConfig) -> Result<RunResult, HookError> {
        Ok(RunResult {
            status: RunStatus::Completed,
            output: None,
        })
    }
}

fn dummy_config(id: &str) -> ComponentConfig {
    ComponentConfig {
        id: id.into(),
        config_data: None,
        trigger_context: None,
    }
}

fn dummy_submit_config(id: &str) -> ComponentSubmitConfig {
    ComponentSubmitConfig {
        sensitive_params: Vec::new(),
        id: id.into(),
        component_type: ComponentType::Task,
        binary: Vec::new(),
        capabilities: Vec::new(),
        output_dir: None,
        trigger: None,
        restart_policy: None,
        delay: None,
        initial_grants: None,
        preset: None,
        retry: None,
    }
}

async fn read_result_bin(tempdir: &TempDir) -> Option<Vec<u8>> {
    let path = tempdir.path().join("result.bin");
    if tokio::fs::try_exists(&path).await.unwrap_or(false) {
        Some(tokio::fs::read(&path).await.unwrap())
    } else {
        None
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cron_writes_result_bin_atomically() {
    let tempdir = tempfile::tempdir().unwrap();
    let hook: Arc<dyn RunnableHook> = Arc::new(CannedOutputHook {
        payload: b"hello-cron".to_vec(),
    });
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let dir = tempdir.path().to_path_buf();
    let handle = tokio::spawn(async move {
        CronDriver::run_periodic(
            "cron-output",
            Duration::from_millis(30),
            hook,
            dummy_config("cron-output"),
            Some(dir),
            cancel_clone,
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    cancel.cancel();
    let _ = handle.await.unwrap();
    let bytes = read_result_bin(&tempdir)
        .await
        .expect("result.bin must exist");
    assert_eq!(bytes, b"hello-cron");
}

#[tokio::test(flavor = "current_thread")]
async fn daemon_writes_result_bin_atomically() {
    let tempdir = tempfile::tempdir().unwrap();
    let hook: Arc<dyn RunnableHook> = Arc::new(CannedOutputHook {
        payload: b"hello-daemon".to_vec(),
    });
    let cancel = CancellationToken::new();
    let result = DaemonManager::run_daemon(
        "daemon-output",
        RestartPolicy::Never,
        hook,
        dummy_config("daemon-output"),
        Some(tempdir.path().to_path_buf()),
        cancel,
        None, // backoff (Slice D)
    )
    .await;
    assert!(result.is_ok());
    let bytes = read_result_bin(&tempdir)
        .await
        .expect("result.bin must exist");
    assert_eq!(bytes, b"hello-daemon");
}

#[tokio::test(flavor = "current_thread")]
async fn task_writes_result_bin_atomically() {
    let tempdir = tempfile::tempdir().unwrap();
    let hook: Arc<dyn RunnableHook> = Arc::new(CannedOutputHook {
        payload: b"hello-task".to_vec(),
    });
    let result = TaskRunner::run_task(
        "task-output",
        dummy_submit_config("task-output"),
        None,
        hook,
        Some(tempdir.path().to_path_buf()),
    )
    .await;
    assert!(result.is_ok());
    let bytes = read_result_bin(&tempdir)
        .await
        .expect("result.bin must exist");
    assert_eq!(bytes, b"hello-task");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watcher_writes_result_bin_atomically() {
    let tempdir = tempfile::tempdir().unwrap();
    let hook: Arc<dyn RunnableHook> = Arc::new(CannedOutputHook {
        payload: b"hello-watcher".to_vec(),
    });
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let sub = TriggerSubscription {
        event_type: "grant.issued".into(),
        filter: None,
        debounce_ms: None,
    };
    let source: Box<dyn TriggerSource> = Box::new(TriggerEventSource {
        sub,
        dispatcher: Arc::clone(&dispatcher),
    });
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let dir = tempdir.path().to_path_buf();
    let handle = tokio::spawn(async move {
        WatcherDriver::run_with_trigger_source(
            "watcher-output",
            source,
            hook,
            Some(dir),
            cancel_clone,
        )
        .await
    });
    // Yield to let the watcher subscribe + poll-loop start.
    tokio::time::sleep(Duration::from_millis(50)).await;
    // Fire a whitelisted event so the TriggerEventSource queues + the
    // watcher's drain loop dispatches the hook.
    dispatcher.dispatch(canned_event("grant.issued"));
    tokio::time::sleep(Duration::from_millis(100)).await;
    cancel.cancel();
    let _ = handle.await.unwrap();
    let bytes = read_result_bin(&tempdir)
        .await
        .expect("result.bin must exist");
    assert_eq!(bytes, b"hello-watcher");
}

#[tokio::test(flavor = "current_thread")]
async fn none_output_skips_write() {
    let tempdir = tempfile::tempdir().unwrap();
    let hook: Arc<dyn RunnableHook> = Arc::new(NoneOutputHook);
    let result = TaskRunner::run_task(
        "task-none",
        dummy_submit_config("task-none"),
        None,
        hook,
        Some(tempdir.path().to_path_buf()),
    )
    .await;
    assert!(result.is_ok());
    assert!(
        read_result_bin(&tempdir).await.is_none(),
        "None output must not create result.bin"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────

fn canned_event(event_type: &str) -> Event {
    Event {
        id: format!("evt-{event_type}"),
        timestamp: chrono::Utc::now(),
        agent_id: "agent:test".into(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: "trace-test".into(),
        span_id: "span-test".into(),
        parent_span_id: None,
        event_type: event_type.into(),
        payload: serde_json::Value::Null,
        duration_ms: None,
    }
}

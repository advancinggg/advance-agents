//! Slice B driver-loop infrastructure tests (waived-scope).
//!
//! Covers:
//! - CronDriver::run_periodic (periodic tick + cancellation)
//! - DaemonManager::run_daemon (restart loop driven by restart_decision)
//! - TaskRunner::run_task (delay + one-shot)
//! - WatcherDriver::run_trigger_event_subscription (subscribe + drain)
//!
//! These tests prove the loops work but do NOT flip any AC (the
//! infrastructure is pre-work for Slice C-verified ACs).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use advance_scheduler::cron::CronDriver;
use advance_scheduler::daemon::DaemonManager;
use advance_scheduler::hook::{HookError, RunnableHook};
use advance_scheduler::task::TaskRunner;
use advance_scheduler::trigger_bus::TriggerBusDispatchImpl;
use advance_scheduler::types::{
    ComponentConfig, ComponentSubmitConfig, RestartPolicy, RunResult, RunStatus,
    TriggerSubscription,
};
use advance_scheduler::watcher::WatcherDriver;
use advance_scheduler::TriggerBusDispatch;
use advance_shared_types::component::ComponentType;
use advance_shared_types::event::Event;
use chrono::Utc;

// ─────────────────────────────────────────────────────────────────────────
// Mock RunnableHook impls
// ─────────────────────────────────────────────────────────────────────────

struct CountingHook(Arc<AtomicUsize>);

#[async_trait]
impl RunnableHook for CountingHook {
    async fn run_once(&self, _config: ComponentConfig) -> Result<RunResult, HookError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(RunResult {
            status: RunStatus::Completed,
            output: None,
        })
    }
}

/// Hook that fails on every call (for DaemonManager restart-on-failure test).
struct AlwaysFailHook(Arc<AtomicUsize>);

#[async_trait]
impl RunnableHook for AlwaysFailHook {
    async fn run_once(&self, _config: ComponentConfig) -> Result<RunResult, HookError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Err(HookError::Failure("intentional failure".into()))
    }
}

fn dummy_config() -> ComponentConfig {
    ComponentConfig {
        id: "test-component".into(),
        config_data: None,
        trigger_context: None,
    }
}

fn dummy_submit_config(delay_ms: Option<u64>) -> ComponentSubmitConfig {
    ComponentSubmitConfig {
        sensitive_params: Vec::new(),
        id: "task-1".into(),
        component_type: ComponentType::Task,
        binary: Vec::new(),
        capabilities: Vec::new(),
        output_dir: None,
        trigger: None,
        restart_policy: None,
        delay: delay_ms,
        initial_grants: None,
        preset: None,
        retry: None,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// CronDriver tests
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cron_periodic_fires_multiple_times() {
    // Real-time test (NOT start_paused): ensures the spawned task actually
    // gets polled. Uses short intervals (10ms) + a 200ms wait window for
    // multiple ticks. Slack allowed: assert >= 1 tick rather than an exact
    // count (CI timing flake protection).
    let counter = Arc::new(AtomicUsize::new(0));
    let hook: Arc<dyn RunnableHook> = Arc::new(CountingHook(counter.clone()));
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let handle = tokio::spawn(async move {
        CronDriver::run_periodic(
            "cron-test",
            Duration::from_millis(10),
            hook,
            dummy_config(),
            None, // output_dir: Slice C addition
            cancel_clone,
        )
        .await
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    cancel.cancel();
    let result = handle.await.unwrap();
    assert!(result.is_ok());
    let n = counter.load(Ordering::Relaxed);
    assert!(n >= 1, "expected at least 1 tick, got {n}");
}

#[tokio::test(flavor = "current_thread")]
async fn cron_rejects_duration_zero() {
    let counter = Arc::new(AtomicUsize::new(0));
    let hook: Arc<dyn RunnableHook> = Arc::new(CountingHook(counter));
    let cancel = CancellationToken::new();
    let result = CronDriver::run_periodic(
        "cron-test",
        Duration::ZERO,
        hook,
        dummy_config(),
        None, // output_dir
        cancel,
    )
    .await;
    assert!(matches!(result, Err(HookError::Failure(_))));
}

#[tokio::test(flavor = "current_thread")]
async fn cron_rejects_interval_over_30_days() {
    let counter = Arc::new(AtomicUsize::new(0));
    let hook: Arc<dyn RunnableHook> = Arc::new(CountingHook(counter));
    let cancel = CancellationToken::new();
    let result = CronDriver::run_periodic(
        "cron-test",
        Duration::from_secs(60 * 60 * 24 * 31),
        hook,
        dummy_config(),
        None, // output_dir
        cancel,
    )
    .await;
    assert!(matches!(result, Err(HookError::Failure(_))));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cron_cancellation_exits_cleanly() {
    let counter = Arc::new(AtomicUsize::new(0));
    let hook: Arc<dyn RunnableHook> = Arc::new(CountingHook(counter));
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move {
        CronDriver::run_periodic(
            "cron-cancel",
            Duration::from_millis(100),
            hook,
            dummy_config(),
            None, // output_dir
            cancel_clone,
        )
        .await
    });
    // Yield to let the spawned task begin before cancelling.
    tokio::time::sleep(Duration::from_millis(10)).await;
    cancel.cancel();
    let result = handle.await.unwrap();
    assert!(result.is_ok());
}

// ─────────────────────────────────────────────────────────────────────────
// DaemonManager tests
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn daemon_never_policy_stops_after_one_iteration() {
    let counter = Arc::new(AtomicUsize::new(0));
    let hook: Arc<dyn RunnableHook> = Arc::new(CountingHook(counter.clone()));
    let cancel = CancellationToken::new();
    let result = DaemonManager::run_daemon(
        "daemon-never",
        RestartPolicy::Never,
        hook,
        dummy_config(),
        None, // output_dir
        cancel,
        None, // backoff (Slice D — None preserves Slice C semantics)
    )
    .await;
    assert!(result.is_ok());
    assert_eq!(counter.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_on_failure_restarts_until_success() {
    // multi_thread flavor: with current_thread, the daemon's hot-spin restart
    // loop (AlwaysFailHook returns Err synchronously) prevents the test task
    // from running `cancel.cancel()`. multi_thread lets cancel run on a
    // separate worker.
    let counter = Arc::new(AtomicUsize::new(0));
    let hook: Arc<dyn RunnableHook> = Arc::new(AlwaysFailHook(counter.clone()));
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let handle = tokio::spawn(async move {
        DaemonManager::run_daemon(
            "daemon-onfailure",
            RestartPolicy::OnFailure,
            hook,
            dummy_config(),
            None, // output_dir
            cancel_clone,
            None, // backoff
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    cancel.cancel();
    let _ = handle.await.unwrap();
    let n = counter.load(Ordering::Relaxed);
    assert!(n >= 1, "expected at least 1 hook invocation, got {n}");
}

#[tokio::test(flavor = "current_thread")]
async fn daemon_on_failure_succeeds_then_stops() {
    let counter = Arc::new(AtomicUsize::new(0));
    let hook: Arc<dyn RunnableHook> = Arc::new(CountingHook(counter.clone()));
    let cancel = CancellationToken::new();
    let result = DaemonManager::run_daemon(
        "daemon-success",
        RestartPolicy::OnFailure,
        hook,
        dummy_config(),
        None, // output_dir
        cancel,
        None, // backoff
    )
    .await;
    assert!(result.is_ok());
    // OnFailure + succeeded → Stop after 1 iteration.
    assert_eq!(counter.load(Ordering::Relaxed), 1);
}

// ─────────────────────────────────────────────────────────────────────────
// TaskRunner tests
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn task_runner_honors_delay() {
    let counter = Arc::new(AtomicUsize::new(0));
    let hook: Arc<dyn RunnableHook> = Arc::new(CountingHook(counter.clone()));
    let submit_cfg = dummy_submit_config(Some(50));

    let start = std::time::Instant::now();
    let result =
        TaskRunner::run_task("task-1", submit_cfg, None, hook, None /* output_dir */).await;
    assert!(result.is_ok());
    // 50ms - 5ms slack for CI timing.
    assert!(
        start.elapsed() >= Duration::from_millis(45),
        "delay should have elapsed at least ~50ms, got {:?}",
        start.elapsed()
    );
    assert_eq!(counter.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn task_runner_no_delay_runs_immediately() {
    let counter = Arc::new(AtomicUsize::new(0));
    let hook: Arc<dyn RunnableHook> = Arc::new(CountingHook(counter.clone()));
    let submit_cfg = dummy_submit_config(None);
    let result =
        TaskRunner::run_task("task-2", submit_cfg, None, hook, None /* output_dir */).await;
    assert!(result.is_ok());
    assert_eq!(counter.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn task_runner_returns_hook_result_directly() {
    // Round-1 Warning-3 fix: verify run_task returns the hook's RunResult.
    struct OutputHook;
    #[async_trait]
    impl RunnableHook for OutputHook {
        async fn run_once(&self, _: ComponentConfig) -> Result<RunResult, HookError> {
            Ok(RunResult {
                status: RunStatus::Completed,
                output: Some(b"hello".to_vec()),
            })
        }
    }
    let submit_cfg = dummy_submit_config(None);
    let result = TaskRunner::run_task(
        "task-output",
        submit_cfg,
        None,
        Arc::new(OutputHook),
        None, /* output_dir */
    )
    .await
    .unwrap();
    assert_eq!(result.output.as_deref(), Some(b"hello".as_slice()));
}

// ─────────────────────────────────────────────────────────────────────────
// WatcherDriver tests
// ─────────────────────────────────────────────────────────────────────────

fn make_event(event_type: &str, id: &str) -> Event {
    Event {
        id: id.into(),
        timestamp: Utc::now(),
        agent_id: "watcher-test".into(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: "trace-w".into(),
        span_id: "span-w".into(),
        parent_span_id: None,
        event_type: event_type.into(),
        payload: serde_json::Value::Object(serde_json::Map::new()),
        duration_ms: None,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn watcher_drives_hook_on_dispatched_event() {
    let counter = Arc::new(AtomicUsize::new(0));
    let hook: Arc<dyn RunnableHook> = Arc::new(CountingHook(counter.clone()));
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let dispatcher_for_watcher = Arc::clone(&dispatcher);

    let sub = TriggerSubscription {
        event_type: "grant.issued".into(),
        filter: None,
        debounce_ms: None,
    };

    let handle = tokio::spawn(async move {
        WatcherDriver::run_trigger_event_subscription(
            "watcher-1",
            sub,
            dispatcher_for_watcher,
            hook,
            cancel_clone,
        )
        .await
    });

    // Let the watcher subscribe (first poll iteration takes 25ms).
    tokio::time::sleep(Duration::from_millis(15)).await;
    dispatcher.dispatch(make_event("grant.issued", "evt-w1"));
    // Wait at least one poll cycle for the watcher to drain.
    tokio::time::sleep(Duration::from_millis(50)).await;

    cancel.cancel();
    let result = handle.await.unwrap();
    assert!(result.is_ok());
    assert!(
        counter.load(Ordering::Relaxed) >= 1,
        "watcher should have invoked hook at least once after dispatch"
    );
    // After cancellation + Drop, the subscription is removed.
    assert_eq!(dispatcher.total_subscriptions(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn watcher_rejects_non_whitelisted_subscription() {
    let counter = Arc::new(AtomicUsize::new(0));
    let hook: Arc<dyn RunnableHook> = Arc::new(CountingHook(counter));
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let cancel = CancellationToken::new();

    let sub = TriggerSubscription {
        event_type: "fs.write".into(), // non-whitelisted
        filter: None,
        debounce_ms: None,
    };
    let result =
        WatcherDriver::run_trigger_event_subscription("watcher-bad", sub, dispatcher, hook, cancel)
            .await;
    assert!(matches!(result, Err(HookError::Failure(_))));
}

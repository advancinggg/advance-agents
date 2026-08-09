//! sched-residue: per-driver `component.started` / `component.finished` /
//! `component.error` emission coverage over the dependency-inverted
//! `EventBusEmit` sink (cron body wiring + the new `_with_emitter` siblings
//! on daemon / task / watcher).
//!
//! Future-witness targets: the component.* observability legs of
//! SYS-AC-098/101/105 ("observable as component.started -> component.finished").
//! This slice builds + crate-tests the emitters; the e2e witnesses are the
//! future harvest slice's job (0 SYS-AC flip here).
//!
//! Lifecycle posture pinned here (component_emit.rs rustdoc): an orphan
//! `started` (no finished/error) is the NORMAL outcome of cancelling
//! mid-hook — future started→finished pairing witnesses must observe
//! `component.finished` BEFORE cancelling the driver.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use advance_scheduler::component_emit::{
    COMPONENT_ERROR_EVENT_TYPE, COMPONENT_FINISHED_EVENT_TYPE, COMPONENT_STARTED_EVENT_TYPE,
};
use advance_scheduler::cron::CronDriver;
use advance_scheduler::daemon::DaemonManager;
use advance_scheduler::hook::{HookError, RunnableHook};
use advance_scheduler::task::TaskRunner;
use advance_scheduler::trigger_emit::TRIGGER_FIRED_EVENT_TYPE;
use advance_scheduler::trigger_source::{TriggerFireEvent, TriggerSource};
use advance_scheduler::types::{
    ComponentConfig, ComponentSubmitConfig, RestartPolicy, RunResult, RunStatus,
    TriggerSubscription,
};
use advance_scheduler::watcher::WatcherDriver;
use advance_scheduler::{TriggerBusDispatch, TriggerBusDispatchImpl};
use advance_shared_types::component::ComponentType;
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;

#[derive(Default)]
struct RecordingBus {
    events: Mutex<Vec<Event>>,
}

impl RecordingBus {
    fn types(&self) -> Vec<String> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.event_type.clone())
            .collect()
    }

    fn of_type(&self, event_type: &str) -> Vec<Event> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.event_type == event_type)
            .cloned()
            .collect()
    }
}

impl EventBusEmit for RecordingBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

/// Hook returning Ok(Completed) and counting invocations.
struct OkHook(Arc<AtomicUsize>);

#[async_trait]
impl RunnableHook for OkHook {
    async fn run_once(&self, _config: ComponentConfig) -> Result<RunResult, HookError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(RunResult {
            status: RunStatus::Completed,
            output: None,
        })
    }
}

/// Hook always returning Err(Failure).
struct FailHook;

#[async_trait]
impl RunnableHook for FailHook {
    async fn run_once(&self, _config: ComponentConfig) -> Result<RunResult, HookError> {
        Err(HookError::Failure("hook exploded".into()))
    }
}

/// Hook failing on the first invocation, succeeding afterwards.
struct FailOnceHook(Arc<AtomicUsize>);

#[async_trait]
impl RunnableHook for FailOnceHook {
    async fn run_once(&self, _config: ComponentConfig) -> Result<RunResult, HookError> {
        let n = self.0.fetch_add(1, Ordering::Relaxed);
        if n == 0 {
            Err(HookError::Failure("first attempt fails".into()))
        } else {
            Ok(RunResult {
                status: RunStatus::Completed,
                output: None,
            })
        }
    }
}

/// Hook returning Ok with an application-level Failed status.
struct OkFailedStatusHook;

#[async_trait]
impl RunnableHook for OkFailedStatusHook {
    async fn run_once(&self, _config: ComponentConfig) -> Result<RunResult, HookError> {
        Ok(RunResult {
            status: RunStatus::Failed("app-level failure".into()),
            output: None,
        })
    }
}

/// Hook that blocks until cancelled (for the orphan-started pin).
struct SlowHook;

#[async_trait]
impl RunnableHook for SlowHook {
    async fn run_once(&self, _config: ComponentConfig) -> Result<RunResult, HookError> {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        Ok(RunResult {
            status: RunStatus::Completed,
            output: None,
        })
    }
}

/// One-shot trigger source: sends `n` fire events then returns Ok.
struct BurstSource(usize);

#[async_trait]
impl TriggerSource for BurstSource {
    async fn run(
        &self,
        tx: mpsc::Sender<TriggerFireEvent>,
        _cancel: CancellationToken,
    ) -> Result<(), HookError> {
        for _ in 0..self.0 {
            let _ = tx
                .send(TriggerFireEvent {
                    trigger_type: "file-watch",
                    trigger_context: None,
                })
                .await;
        }
        Ok(())
    }
}

fn dummy_config(id: &str) -> ComponentConfig {
    ComponentConfig {
        id: id.into(),
        config_data: None,
        trigger_context: None,
    }
}

fn task_cfg(id: &str, delay: Option<u64>) -> ComponentSubmitConfig {
    ComponentSubmitConfig {
        sensitive_params: Vec::new(),
        id: id.into(),
        component_type: ComponentType::Task,
        binary: Vec::new(),
        capabilities: Vec::new(),
        output_dir: None,
        trigger: None,
        restart_policy: None,
        delay,
        initial_grants: None,
        preset: None,
        retry: None,
    }
}

fn assert_started_payload(ev: &Event, id: &str, component_type: &str) {
    assert_eq!(ev.agent_id, id);
    assert_eq!(ev.payload["id"], id);
    assert_eq!(ev.payload["component_type"], component_type);
}

// ─────────────────────────────────────────────────────────────────────────
// E1/E2 — cron
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e1_cron_tick_emits_fired_started_finished_in_order() {
    let counter = Arc::new(AtomicUsize::new(0));
    let hook: Arc<dyn RunnableHook> = Arc::new(OkHook(counter.clone()));
    let recorder = Arc::new(RecordingBus::default());
    let emitter: Arc<dyn EventBusEmit> = recorder.clone();
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let handle = tokio::spawn(async move {
        CronDriver::run_periodic_with_emitter(
            "cron-e1",
            Duration::from_millis(10),
            hook,
            dummy_config("cron-e1"),
            None,
            Some(emitter),
            cancel_clone,
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(120)).await;
    cancel.cancel();
    handle.await.expect("join").expect("run Ok");

    // Per-tick ordering: trigger.fired, started, finished repeat. Check the
    // first full window plus payloads.
    let types = recorder.types();
    assert!(
        types.len() >= 3,
        "expected at least one full tick window: {types:?}"
    );
    assert_eq!(types[0], TRIGGER_FIRED_EVENT_TYPE);
    assert_eq!(types[1], COMPONENT_STARTED_EVENT_TYPE);
    assert_eq!(types[2], COMPONENT_FINISHED_EVENT_TYPE);

    let started = recorder.of_type(COMPONENT_STARTED_EVENT_TYPE);
    assert_started_payload(&started[0], "cron-e1", "cron");

    let finished = recorder.of_type(COMPONENT_FINISHED_EVENT_TYPE);
    let f = &finished[0];
    assert_eq!(f.payload["status"], "completed");
    assert!(f.payload["duration_ms"].is_u64());
    assert!(f.duration_ms.is_some());
    assert_eq!(f.payload["component_type"], "cron");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2_cron_failing_hook_emits_error_and_loop_survives() {
    let hook: Arc<dyn RunnableHook> = Arc::new(FailHook);
    let recorder = Arc::new(RecordingBus::default());
    let emitter: Arc<dyn EventBusEmit> = recorder.clone();
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let handle = tokio::spawn(async move {
        CronDriver::run_periodic_with_emitter(
            "cron-e2",
            Duration::from_millis(10),
            hook,
            dummy_config("cron-e2"),
            None,
            Some(emitter),
            cancel_clone,
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(120)).await;
    cancel.cancel();
    handle.await.expect("join").expect("run Ok");

    let errors = recorder.of_type(COMPONENT_ERROR_EVENT_TYPE);
    assert!(
        errors.len() >= 2,
        "loop must survive hook failures and emit per-tick errors: {} errors",
        errors.len()
    );
    let e = &errors[0];
    assert_eq!(e.payload["error_type"], "hook-failure");
    assert_eq!(e.payload["message"], "hook exploded");
    assert_eq!(e.payload["component_type"], "cron");
    assert!(
        recorder.of_type(COMPONENT_FINISHED_EVENT_TYPE).is_empty(),
        "no finished on Err(Failure)"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// E3/E3b — daemon
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e3_daemon_fail_then_succeed_sequence() {
    let counter = Arc::new(AtomicUsize::new(0));
    let hook: Arc<dyn RunnableHook> = Arc::new(FailOnceHook(counter));
    let recorder = Arc::new(RecordingBus::default());
    let emitter: Arc<dyn EventBusEmit> = recorder.clone();
    let cancel = CancellationToken::new();

    // OnFailure policy: restarts after the failure, stops after the success.
    DaemonManager::run_daemon_with_emitter(
        "daemon-e3",
        RestartPolicy::OnFailure,
        hook,
        dummy_config("daemon-e3"),
        None,
        Some(emitter),
        cancel,
        None,
    )
    .await
    .expect("daemon run Ok");

    let types = recorder.types();
    assert_eq!(
        types,
        vec![
            COMPONENT_STARTED_EVENT_TYPE.to_string(),
            COMPONENT_ERROR_EVENT_TYPE.to_string(),
            COMPONENT_STARTED_EVENT_TYPE.to_string(),
            COMPONENT_FINISHED_EVENT_TYPE.to_string(),
        ],
        "one started per restart iteration; error then finished"
    );
    let started = recorder.of_type(COMPONENT_STARTED_EVENT_TYPE);
    assert_started_payload(&started[0], "daemon-e3", "daemon");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e3b_daemon_ok_failed_status_is_finished_failed_not_error() {
    let hook: Arc<dyn RunnableHook> = Arc::new(OkFailedStatusHook);
    let recorder = Arc::new(RecordingBus::default());
    let emitter: Arc<dyn EventBusEmit> = recorder.clone();
    let cancel = CancellationToken::new();

    // OnFailure + Ok(Failed-status): restart_decision sees succeeded==true
    // (result.is_ok()), so the daemon stops after one iteration.
    DaemonManager::run_daemon_with_emitter(
        "daemon-e3b",
        RestartPolicy::OnFailure,
        hook,
        dummy_config("daemon-e3b"),
        None,
        Some(emitter),
        cancel,
        None,
    )
    .await
    .expect("daemon run Ok");

    let finished = recorder.of_type(COMPONENT_FINISHED_EVENT_TYPE);
    assert_eq!(finished.len(), 1, "Ok(Failed) is finished-with-status");
    assert_eq!(finished[0].payload["status"], "failed");
    assert!(
        recorder.of_type(COMPONENT_ERROR_EVENT_TYPE).is_empty(),
        "Ok(Failed) must NOT emit component.error"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// E4/E5/E6 — task
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn e4_task_ok_emits_started_finished_and_returns_result() {
    let counter = Arc::new(AtomicUsize::new(0));
    let hook: Arc<dyn RunnableHook> = Arc::new(OkHook(counter));
    let recorder = Arc::new(RecordingBus::default());
    let emitter: Arc<dyn EventBusEmit> = recorder.clone();

    let result = TaskRunner::run_task_with_emitter(
        "task-e4",
        task_cfg("task-e4", None),
        None,
        hook,
        None,
        Some(emitter),
    )
    .await
    .expect("task Ok");
    assert_eq!(result.status, RunStatus::Completed);

    let types = recorder.types();
    assert_eq!(
        types,
        vec![
            COMPONENT_STARTED_EVENT_TYPE.to_string(),
            COMPONENT_FINISHED_EVENT_TYPE.to_string(),
        ]
    );
    let started = recorder.of_type(COMPONENT_STARTED_EVENT_TYPE);
    assert_started_payload(&started[0], "task-e4", "task");
}

#[tokio::test]
async fn e5_task_err_emits_error_and_repropagates() {
    let hook: Arc<dyn RunnableHook> = Arc::new(FailHook);
    let recorder = Arc::new(RecordingBus::default());
    let emitter: Arc<dyn EventBusEmit> = recorder.clone();

    let err = TaskRunner::run_task_with_emitter(
        "task-e5",
        task_cfg("task-e5", None),
        None,
        hook,
        None,
        Some(emitter),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, HookError::Failure(_)),
        "error must repropagate unchanged"
    );

    let types = recorder.types();
    assert_eq!(
        types,
        vec![
            COMPONENT_STARTED_EVENT_TYPE.to_string(),
            COMPONENT_ERROR_EVENT_TYPE.to_string(),
        ]
    );
}

#[tokio::test]
async fn e6_task_ok_failed_status_finished_failed() {
    let hook: Arc<dyn RunnableHook> = Arc::new(OkFailedStatusHook);
    let recorder = Arc::new(RecordingBus::default());
    let emitter: Arc<dyn EventBusEmit> = recorder.clone();

    let result = TaskRunner::run_task_with_emitter(
        "task-e6",
        task_cfg("task-e6", None),
        None,
        hook,
        None,
        Some(emitter),
    )
    .await
    .expect("Ok(Failed) is still Ok at the driver layer");
    assert!(matches!(result.status, RunStatus::Failed(_)));

    let finished = recorder.of_type(COMPONENT_FINISHED_EVENT_TYPE);
    assert_eq!(finished.len(), 1);
    assert_eq!(finished[0].payload["status"], "failed");
    assert!(recorder.of_type(COMPONENT_ERROR_EVENT_TYPE).is_empty());
}

// ─────────────────────────────────────────────────────────────────────────
// E7/E8 — watcher (both entries)
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e7_watcher_trigger_source_fires_emit_started_finished() {
    let counter = Arc::new(AtomicUsize::new(0));
    let hook: Arc<dyn RunnableHook> = Arc::new(OkHook(counter.clone()));
    let recorder = Arc::new(RecordingBus::default());
    let emitter: Arc<dyn EventBusEmit> = recorder.clone();
    let cancel = CancellationToken::new();

    WatcherDriver::run_with_trigger_source_with_emitter(
        "watcher-e7",
        Box::new(BurstSource(2)),
        hook,
        None,
        Some(emitter),
        cancel,
    )
    .await
    .expect("watcher run Ok");

    assert_eq!(
        counter.load(Ordering::Relaxed),
        2,
        "both fires ran the hook"
    );
    let started = recorder.of_type(COMPONENT_STARTED_EVENT_TYPE);
    let finished = recorder.of_type(COMPONENT_FINISHED_EVENT_TYPE);
    assert_eq!(started.len(), 2);
    assert_eq!(finished.len(), 2);
    assert_started_payload(&started[0], "watcher-e7", "watcher");
    assert_eq!(finished[0].payload["component_type"], "watcher");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e8_watcher_subscription_drain_emits_and_swallows_errors() {
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let recorder = Arc::new(RecordingBus::default());
    let emitter: Arc<dyn EventBusEmit> = recorder.clone();
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let dispatcher_clone = Arc::clone(&dispatcher);

    let hook: Arc<dyn RunnableHook> = Arc::new(FailHook);
    let sub = TriggerSubscription {
        event_type: "grant.issued".into(),
        filter: None,
        debounce_ms: None,
    };
    let handle = tokio::spawn(async move {
        WatcherDriver::run_trigger_event_subscription_with_emitter(
            "watcher-e8",
            sub,
            dispatcher_clone,
            hook,
            Some(emitter),
            cancel_clone,
        )
        .await
    });

    // Let the subscription register, then dispatch two whitelisted events.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mk_event = || Event::observability("grant.issued", "issuer", serde_json::json!({}), None);
    dispatcher.dispatch(mk_event());
    // dispatch-twice-no-drain gotcha: the visited-set keys on chain id, and
    // each observability event carries a fresh uuid -> both dispatch.
    dispatcher.dispatch(mk_event());
    tokio::time::sleep(Duration::from_millis(150)).await;
    cancel.cancel();
    handle.await.expect("join").expect("watcher Ok");

    let started = recorder.of_type(COMPONENT_STARTED_EVENT_TYPE);
    let errors = recorder.of_type(COMPONENT_ERROR_EVENT_TYPE);
    assert_eq!(started.len(), 2, "one started per drained entry");
    assert_eq!(errors.len(), 2, "hook errors surface as component.error");
    assert!(
        recorder.of_type(COMPONENT_FINISHED_EVENT_TYPE).is_empty(),
        "failing hook never finishes"
    );
    assert_started_payload(&started[0], "watcher-e8", "watcher");
}

// ─────────────────────────────────────────────────────────────────────────
// E9 — orphan-started posture pin (cancel mid-hook)
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e9_cron_cancel_mid_hook_orphan_started_pinned() {
    let hook: Arc<dyn RunnableHook> = Arc::new(SlowHook);
    let recorder = Arc::new(RecordingBus::default());
    let emitter: Arc<dyn EventBusEmit> = recorder.clone();
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let handle = tokio::spawn(async move {
        CronDriver::run_periodic_with_emitter(
            "cron-e9",
            Duration::from_millis(10),
            hook,
            dummy_config("cron-e9"),
            None,
            Some(emitter),
            cancel_clone,
        )
        .await
    });
    // Wait until the first tick fired (started emitted, hook blocked).
    tokio::time::sleep(Duration::from_millis(120)).await;
    cancel.cancel();
    handle.await.expect("join").expect("run Ok");

    let started = recorder.of_type(COMPONENT_STARTED_EVENT_TYPE);
    assert_eq!(started.len(), 1, "first tick emitted started");
    assert!(
        recorder.of_type(COMPONENT_FINISHED_EVENT_TYPE).is_empty()
            && recorder.of_type(COMPONENT_ERROR_EVENT_TYPE).is_empty(),
        "cancel-mid-hook yields an orphan started — the documented accepted posture"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// E10 — legacy entries emit nothing (None delegation)
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn e10_legacy_run_task_unchanged() {
    // The legacy entry has no emitter parameter; it must still behave
    // identically (delegation with None). Smoke-pin the result surface.
    let counter = Arc::new(AtomicUsize::new(0));
    let hook: Arc<dyn RunnableHook> = Arc::new(OkHook(counter.clone()));
    let result = TaskRunner::run_task("task-e10", task_cfg("task-e10", None), None, hook, None)
        .await
        .expect("legacy run_task Ok");
    assert_eq!(result.status, RunStatus::Completed);
    assert_eq!(counter.load(Ordering::Relaxed), 1);
}

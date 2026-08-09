//! Slice C AC-14 verification: 5 trigger-config variants route correctly
//! through `resolve_trigger` and drive `WatcherDriver::run_with_trigger_source`.
//!
//! For each variant, the test constructs a synthetic trigger source via
//! `resolve_trigger`, drives the watcher with a counting hook + a
//! cancellation token (auto-cancelled after a short delay), then asserts
//! the hook fired at least once.
//!
//! Plus a rejection-path test: `TriggerEventSource` subscribing to a
//! non-whitelisted event_type → `WatcherDriver::run_with_trigger_source`
//! returns `Err(HookError::Failure(...))` (closes a Warning-class
//! adversarial gap: rejection now propagates via the JoinHandle error
//! surface).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use advance_scheduler::hook::{FileWatchSource, HookError, RunnableHook, WebhookSource};
use advance_scheduler::trigger_bus::TriggerBusDispatchImpl;
use advance_scheduler::trigger_source::{resolve_trigger, TriggerFireEvent};
use advance_scheduler::types::{
    ComponentConfig, RunResult, RunStatus, TriggerConfig, TriggerSubscription, WebhookConfig,
};
use advance_scheduler::watcher::WatcherDriver;
use advance_scheduler::TriggerBusDispatch;
use advance_shared_types::event::Event;

/// Counting hook used by all 5 variant tests.
struct CountingHook {
    counter: Arc<AtomicUsize>,
}

#[async_trait]
impl RunnableHook for CountingHook {
    async fn run_once(&self, _config: ComponentConfig) -> Result<RunResult, HookError> {
        self.counter.fetch_add(1, Ordering::Relaxed);
        Ok(RunResult {
            status: RunStatus::Completed,
            output: None,
        })
    }
}

/// Synthetic FileWatchSource that emits 1 TriggerFireEvent after 20 ms.
struct SyntheticFileWatchSource;

#[async_trait]
impl FileWatchSource for SyntheticFileWatchSource {
    async fn run(
        &self,
        _glob: String,
        tx: mpsc::Sender<TriggerFireEvent>,
        cancel: CancellationToken,
    ) -> Result<(), HookError> {
        tokio::select! {
            _ = cancel.cancelled() => Ok(()),
            _ = tokio::time::sleep(Duration::from_millis(20)) => {
                let _ = tx.send(TriggerFireEvent {
                    trigger_type: "file-watch",
                    trigger_context: None,
                }).await;
                // Hold until cancel — keeps the channel open for the
                // watcher's drain loop to consume the event.
                cancel.cancelled().await;
                Ok(())
            }
        }
    }
}

/// Synthetic WebhookSource that emits 1 TriggerFireEvent after 20 ms.
struct SyntheticWebhookSource;

#[async_trait]
impl WebhookSource for SyntheticWebhookSource {
    async fn run(
        &self,
        _cfg: WebhookConfig,
        tx: mpsc::Sender<TriggerFireEvent>,
        cancel: CancellationToken,
    ) -> Result<(), HookError> {
        tokio::select! {
            _ = cancel.cancelled() => Ok(()),
            _ = tokio::time::sleep(Duration::from_millis(20)) => {
                let _ = tx.send(TriggerFireEvent {
                    trigger_type: "webhook",
                    trigger_context: None,
                }).await;
                cancel.cancelled().await;
                Ok(())
            }
        }
    }
}

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

/// Helper: drive `resolve_trigger(cfg, ...)` through
/// `WatcherDriver::run_with_trigger_source` with auto-cancel after `wait`
/// ms. Returns the final hook counter.
async fn drive(
    cfg: TriggerConfig,
    dispatcher: Arc<TriggerBusDispatchImpl>,
    file_src: Arc<dyn FileWatchSource>,
    webhook_src: Arc<dyn WebhookSource>,
    wait: Duration,
) -> usize {
    let counter = Arc::new(AtomicUsize::new(0));
    let hook: Arc<dyn RunnableHook> = Arc::new(CountingHook {
        counter: counter.clone(),
    });
    let source = resolve_trigger(cfg, dispatcher, file_src, webhook_src).unwrap();
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move {
        WatcherDriver::run_with_trigger_source("watcher-test", source, hook, None, cancel_clone)
            .await
    });
    tokio::time::sleep(wait).await;
    cancel.cancel();
    let _ = handle.await.unwrap();
    counter.load(Ordering::Relaxed)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn schedule_variant_fires_periodically() {
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let n = drive(
        TriggerConfig::Schedule("every-50ms".into()),
        dispatcher,
        Arc::new(SyntheticFileWatchSource),
        Arc::new(SyntheticWebhookSource),
        Duration::from_millis(200),
    )
    .await;
    assert!(
        n >= 1,
        "Schedule variant should fire at least once; got {n}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn file_watch_variant_fires_on_synthetic_event() {
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let n = drive(
        TriggerConfig::FileWatch("**/*.rs".into()),
        dispatcher,
        Arc::new(SyntheticFileWatchSource),
        Arc::new(SyntheticWebhookSource),
        Duration::from_millis(150),
    )
    .await;
    assert!(
        n >= 1,
        "FileWatch variant should fire from synthetic source; got {n}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn webhook_variant_fires_on_synthetic_event() {
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let cfg = WebhookConfig {
        path: "/hooks/test".into(),
        secret: None,
    };
    let n = drive(
        TriggerConfig::Webhook(cfg),
        dispatcher,
        Arc::new(SyntheticFileWatchSource),
        Arc::new(SyntheticWebhookSource),
        Duration::from_millis(150),
    )
    .await;
    assert!(
        n >= 1,
        "Webhook variant should fire from synthetic source; got {n}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn any_of_variant_fires_from_any_child() {
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    // Schedule child fires every 50 ms; FileWatch synthetic child fires
    // at +20 ms. Either child's fire satisfies AnyOf OR-semantics.
    let cfg = TriggerConfig::AnyOf(vec![
        TriggerConfig::Schedule("every-50ms".into()),
        TriggerConfig::FileWatch("**/*.rs".into()),
    ]);
    let n = drive(
        cfg,
        dispatcher,
        Arc::new(SyntheticFileWatchSource),
        Arc::new(SyntheticWebhookSource),
        Duration::from_millis(150),
    )
    .await;
    assert!(
        n >= 1,
        "AnyOf variant should fire from at least one child; got {n}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trigger_event_variant_fires_on_dispatch() {
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let dispatcher_for_fire = Arc::clone(&dispatcher);
    let counter = Arc::new(AtomicUsize::new(0));
    let hook: Arc<dyn RunnableHook> = Arc::new(CountingHook {
        counter: counter.clone(),
    });
    let cfg = TriggerConfig::TriggerEvent(TriggerSubscription {
        event_type: "grant.issued".into(),
        filter: None,
        debounce_ms: None,
    });
    let source = resolve_trigger(
        cfg,
        Arc::clone(&dispatcher),
        Arc::new(SyntheticFileWatchSource),
        Arc::new(SyntheticWebhookSource),
    )
    .unwrap();
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let handle = tokio::spawn(async move {
        WatcherDriver::run_with_trigger_source("watcher-te", source, hook, None, cancel_clone).await
    });
    // Let the source subscribe + poll-loop start.
    tokio::time::sleep(Duration::from_millis(50)).await;
    // Fire a whitelisted event so the TriggerEventSource queues + the
    // watcher's drain loop dispatches the hook.
    dispatcher_for_fire.dispatch(canned_event("grant.issued"));
    tokio::time::sleep(Duration::from_millis(100)).await;
    cancel.cancel();
    let _ = handle.await.unwrap();
    let n = counter.load(Ordering::Relaxed);
    assert!(
        n >= 1,
        "TriggerEvent variant should fire on dispatch; got {n}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trigger_event_rejection_surfaces_via_join_handle() {
    // AC-14 rejection-path test: non-whitelisted event_type subscribe
    // → TriggerEventSource returns Err(HookError::Failure(...))
    // → WatcherDriver::run_with_trigger_source surfaces the error via
    // the JoinHandle pattern post-drain. Closes the Warning-class
    // adversarial gap: rejection no longer silently swallowed.
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let counter = Arc::new(AtomicUsize::new(0));
    let hook: Arc<dyn RunnableHook> = Arc::new(CountingHook {
        counter: counter.clone(),
    });
    let cfg = TriggerConfig::TriggerEvent(TriggerSubscription {
        event_type: "fs.write".into(), // NOT in the whitelist
        filter: None,
        debounce_ms: None,
    });
    let source = resolve_trigger(
        cfg,
        Arc::clone(&dispatcher),
        Arc::new(SyntheticFileWatchSource),
        Arc::new(SyntheticWebhookSource),
    )
    .unwrap();
    let cancel = CancellationToken::new();
    let result =
        WatcherDriver::run_with_trigger_source("watcher-rejected", source, hook, None, cancel)
            .await;
    assert!(
        matches!(result, Err(HookError::Failure(_))),
        "non-whitelisted subscription should surface Err(HookError::Failure(...)); got {:?}",
        result
    );
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}

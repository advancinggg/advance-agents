//! sched-triggers (trigger-chain product pre-build): `CronDriver` emits a
//! `trigger.fired` event (`trigger_type == "cron"`) on every tick via the
//! optional dependency-inverted `EventBusEmit` sink.
//!
//! Future-witness target: SYS-AC-099 (each cron fire emits `trigger.fired` with
//! `trigger_type == "cron"`). This slice builds + crate-tests the product; the
//! e2e witness is the future harness-witness slice's job (0 SYS-AC flip here).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use advance_scheduler::cron::CronDriver;
use advance_scheduler::hook::{HookError, RunnableHook};
use advance_scheduler::trigger_emit::TRIGGER_FIRED_EVENT_TYPE;
use advance_scheduler::types::{ComponentConfig, RunResult, RunStatus};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;

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

#[derive(Default)]
struct RecordingBus {
    events: Mutex<Vec<Event>>,
}

impl EventBusEmit for RecordingBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

fn dummy_config(id: &str) -> ComponentConfig {
    ComponentConfig {
        id: id.into(),
        config_data: None,
        trigger_context: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cron_emits_trigger_fired_with_cron_type_per_tick() {
    let counter = Arc::new(AtomicUsize::new(0));
    let hook: Arc<dyn RunnableHook> = Arc::new(CountingHook(counter.clone()));
    let recorder = Arc::new(RecordingBus::default());
    let emitter: Arc<dyn EventBusEmit> = recorder.clone();
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let handle = tokio::spawn(async move {
        CronDriver::run_periodic_with_emitter(
            "cron-emit-test",
            Duration::from_millis(10),
            hook,
            dummy_config("cron-emit-test"),
            None,          // output_dir
            Some(emitter), // sched-triggers: trigger.fired sink
            cancel_clone,
        )
        .await
    });

    // Let several ticks elapse, then cancel.
    tokio::time::sleep(Duration::from_millis(120)).await;
    cancel.cancel();
    handle.await.expect("join").expect("run_periodic Ok");

    let ticks = counter.load(Ordering::Relaxed);
    let events = recorder.events.lock().unwrap();

    // At least one fire happened, and every trigger.fired event is a cron one.
    // sched-residue: the sink now additionally carries component.* lifecycle
    // events from the same loop, so both assertions are scoped by event_type
    // (assertion-scope edit only — the trigger.fired count semantics pinned
    // below are unchanged).
    let fired: Vec<_> = events
        .iter()
        .filter(|ev| ev.event_type == TRIGGER_FIRED_EVENT_TYPE)
        .collect();
    assert!(ticks >= 1, "expected at least one tick");
    assert!(
        !fired.is_empty(),
        "expected at least one trigger.fired event"
    );
    for ev in &fired {
        assert_eq!(ev.event_type, TRIGGER_FIRED_EVENT_TYPE);
        assert_eq!(ev.payload["trigger_type"], "cron");
        assert_eq!(ev.payload["component_id"], "cron-emit-test");
        assert_eq!(ev.agent_id, "cron-emit-test");
    }
    // trigger.fired is emitted at tick time (before the hook), so the emitted
    // count tracks the fire count. It must be >= the successful-hook count and
    // within one of it (the last fire may be cancelled before the hook runs).
    let emitted = fired.len();
    assert!(
        emitted >= ticks && emitted <= ticks + 1,
        "emitted={emitted} ticks={ticks}: trigger.fired count tracks fires, not hook completions"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cron_with_no_emitter_still_fires_hook_and_emits_nothing() {
    let counter = Arc::new(AtomicUsize::new(0));
    let hook: Arc<dyn RunnableHook> = Arc::new(CountingHook(counter.clone()));
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let handle = tokio::spawn(async move {
        CronDriver::run_periodic_with_emitter(
            "cron-none",
            Duration::from_millis(10),
            hook,
            dummy_config("cron-none"),
            None,
            None, // no emitter — must behave exactly like run_periodic
            cancel_clone,
        )
        .await
    });

    tokio::time::sleep(Duration::from_millis(80)).await;
    cancel.cancel();
    handle.await.expect("join").expect("run_periodic Ok");

    assert!(
        counter.load(Ordering::Relaxed) >= 1,
        "hook still fires without an emitter"
    );
}

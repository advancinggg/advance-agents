//! Anti-fake-green-regression witness for `ComponentMaterializer` (S3 satellite).
//!
//! These crate tests do NOT by themselves flip/kill SYS-AC-109 — that fake-green
//! lives in the composition admission→persistence→`registry.list()`→(readiness
//! loop)→materialize, whose ends are waived to the mainline harvest. What this
//! suite regression-locks is the materializer's OWN data-flow: every driver
//! input (binary, id, trigger, restart policy) is EXTRACTED FROM the
//! `ComponentRegistryRow`, never minted from an id string. The recording factory
//! captures the actual binary bytes it was handed; the recording hook captures
//! the `ComponentConfig.id` it ran with; the binary-mutation discriminator
//! proves a changed submit changes the witnessed value — the exact leg the 1B
//! fake-green failed ("deleting the submit still passed").

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use advance_scheduler::hook::{
    FileWatchSource, HookError, RunnableHook, RunnableHookFactory, WebhookSource,
};
use advance_scheduler::materializer::ComponentMaterializer;
use advance_scheduler::registry::ComponentRegistryRow;
use advance_scheduler::trigger_bus::TriggerBusDispatchImpl;
use advance_scheduler::trigger_source::TriggerFireEvent;
use advance_scheduler::types::{
    ComponentConfig, ComponentId, ComponentSubmitConfig, RestartPolicy, RunResult, RunStatus,
    TriggerConfig, TriggerSubscription, WebhookConfig,
};
use advance_scheduler::TriggerBusDispatch;
use advance_shared_types::capability::{CapRequest, CapabilityId};
use advance_shared_types::component::ComponentType;
use advance_shared_types::event::Event;
use chrono::Utc;
use tokio::sync::mpsc;

// ─────────────────────────────────────────────────────────────────────────
// Recording doubles
// ─────────────────────────────────────────────────────────────────────────

/// Records the exact binary bytes handed to `build` + the ids the produced
/// hooks ran with. `hook_fails` flips the produced hook between Ok and
/// Err(Failure) — needed for the daemon OnFailure-vs-Never discriminator.
struct RecordingFactory {
    seen_binaries: Arc<Mutex<Vec<Vec<u8>>>>,
    // All THREE pinned `build(binary, component_id, caps)` args are recorded so
    // the data-driven-link witness discriminates each (adversarial round-12): a
    // wrong materializer that dropped/hardcoded component_id or caps while still
    // threading a correct driver-side ComponentConfig.id must be caught here.
    seen_component_ids: Arc<Mutex<Vec<String>>>,
    seen_caps: Arc<Mutex<Vec<Vec<String>>>>,
    ran_ids: Arc<Mutex<Vec<String>>>,
    hook_fails: bool,
}

#[async_trait]
impl RunnableHookFactory for RecordingFactory {
    async fn build(
        &self,
        binary: &[u8],
        component_id: &str,
        caps: &[CapRequest],
    ) -> Result<Arc<dyn RunnableHook>, HookError> {
        self.seen_binaries.lock().unwrap().push(binary.to_vec());
        self.seen_component_ids
            .lock()
            .unwrap()
            .push(component_id.to_owned());
        self.seen_caps.lock().unwrap().push(
            caps.iter()
                .map(|c| c.capability.as_str().to_owned())
                .collect(),
        );
        Ok(Arc::new(RecordingHook {
            ran_ids: Arc::clone(&self.ran_ids),
            fails: self.hook_fails,
        }))
    }
}

struct RecordingHook {
    ran_ids: Arc<Mutex<Vec<String>>>,
    fails: bool,
}

#[async_trait]
impl RunnableHook for RecordingHook {
    async fn run_once(&self, config: ComponentConfig) -> Result<RunResult, HookError> {
        self.ran_ids.lock().unwrap().push(config.id.clone());
        if self.fails {
            Err(HookError::Failure("intentional witness failure".into()))
        } else {
            Ok(RunResult {
                status: RunStatus::Completed,
                output: None,
            })
        }
    }
}

/// No-op trigger sources — never invoked on the TriggerEvent path (the watcher
/// witness uses a `TriggerEvent` trigger → `TriggerEventSource`, which uses the
/// bus dispatcher, not these), but required to satisfy `resolve_trigger`'s
/// 4-arg signature held by the materializer.
struct NoopFileWatchSource;

#[async_trait]
impl FileWatchSource for NoopFileWatchSource {
    async fn run(
        &self,
        _glob: String,
        _tx: mpsc::Sender<TriggerFireEvent>,
        cancel: CancellationToken,
    ) -> Result<(), HookError> {
        cancel.cancelled().await;
        Ok(())
    }
}

struct NoopWebhookSource;

#[async_trait]
impl WebhookSource for NoopWebhookSource {
    async fn run(
        &self,
        _cfg: WebhookConfig,
        _tx: mpsc::Sender<TriggerFireEvent>,
        cancel: CancellationToken,
    ) -> Result<(), HookError> {
        cancel.cancelled().await;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────

struct Recorders {
    seen_binaries: Arc<Mutex<Vec<Vec<u8>>>>,
    seen_component_ids: Arc<Mutex<Vec<String>>>,
    seen_caps: Arc<Mutex<Vec<Vec<String>>>>,
    ran_ids: Arc<Mutex<Vec<String>>>,
}

fn build_materializer(
    hook_fails: bool,
    dispatcher: Arc<TriggerBusDispatchImpl>,
) -> (Arc<ComponentMaterializer>, Recorders) {
    let seen_binaries = Arc::new(Mutex::new(Vec::new()));
    let seen_component_ids = Arc::new(Mutex::new(Vec::new()));
    let seen_caps = Arc::new(Mutex::new(Vec::new()));
    let ran_ids = Arc::new(Mutex::new(Vec::new()));
    let factory = Arc::new(RecordingFactory {
        seen_binaries: Arc::clone(&seen_binaries),
        seen_component_ids: Arc::clone(&seen_component_ids),
        seen_caps: Arc::clone(&seen_caps),
        ran_ids: Arc::clone(&ran_ids),
        hook_fails,
    });
    let materializer = Arc::new(ComponentMaterializer::new(
        factory,
        dispatcher,
        Arc::new(NoopFileWatchSource),
        Arc::new(NoopWebhookSource),
    ));
    (
        materializer,
        Recorders {
            seen_binaries,
            seen_component_ids,
            seen_caps,
            ran_ids,
        },
    )
}

/// Build a real registry row with id/binary/trigger/policy supplied (extracted
/// FROM here by the materializer — never minted from an id string).
fn make_row(
    id: &str,
    component_type: ComponentType,
    binary: &[u8],
    interval_ms: Option<i64>,
    trigger: Option<TriggerConfig>,
    restart_policy: Option<RestartPolicy>,
) -> ComponentRegistryRow {
    ComponentRegistryRow {
        id: ComponentId(id.to_owned()),
        component_type,
        submit_config: ComponentSubmitConfig {
            sensitive_params: Vec::new(),
            id: id.to_owned(),
            component_type,
            binary: binary.to_vec(),
            capabilities: Vec::new(),
            output_dir: None,
            trigger,
            restart_policy,
            delay: None,
            initial_grants: None,
            preset: None,
            retry: None,
        },
        submitter: "agent:root".to_owned(),
        submitted_at_ms: 0,
        interval_ms,
        expected_next_fire_at_ms: None,
        last_fire_at_ms: None,
    }
}

fn make_event(event_type: &str, id: &str) -> Event {
    Event {
        id: id.into(),
        timestamp: Utc::now(),
        agent_id: "materializer-test".into(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: "trace-m".into(),
        span_id: "span-m".into(),
        parent_span_id: None,
        event_type: event_type.into(),
        payload: serde_json::Value::Object(serde_json::Map::new()),
        duration_ms: None,
    }
}

/// Poll a recording vec until it reaches `target` len or ~1.5s elapses.
async fn wait_for_len<T: Send>(v: &Arc<Mutex<Vec<T>>>, target: usize) -> bool {
    for _ in 0..150 {
        if v.lock().unwrap().len() >= target {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    v.lock().unwrap().len() >= target
}

/// Run `materialize` with a never-cancelled token, BOUNDED by a 2s timeout, for
/// the fail-closed / stop-after-one cases that MUST return promptly. A wrong
/// materializer whose looping/parked future never returns (e.g. a missing
/// fail-closed reject, or a daemon policy hardcoded to a restart-capable value)
/// is then caught as a fast, message-bearing assertion failure rather than an
/// open-ended hang that relies on an external test-harness timeout (adversarial
/// round-10 witness-integrity fix). The correct impl returns its `Err`/`Ok`
/// immediately, well under the bound.
async fn materialize_bounded(
    m: Arc<ComponentMaterializer>,
    row: ComponentRegistryRow,
) -> Result<(), HookError> {
    tokio::time::timeout(
        Duration::from_secs(2),
        m.materialize(row, CancellationToken::new()),
    )
    .await
    .expect(
        "materialize did not return within 2s — a fail-closed reject or stop \
         path is missing (a wrong impl would hot-loop / park here instead of \
         returning)",
    )
}

fn snapshot<T: Clone>(v: &Arc<Mutex<Vec<T>>>) -> Vec<T> {
    v.lock().unwrap().clone()
}

// ─────────────────────────────────────────────────────────────────────────
// Cron: data-driven link + mutation discriminator
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cron_link_is_data_driven() {
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let (m, rec) = build_materializer(false, dispatcher);
    let mut row = make_row(
        "cron-materialize-1",
        ComponentType::Cron,
        b"MARKER-BYTES",
        Some(100),
        None,
        None,
    );
    // Non-empty capabilities so the caps leg of the build() contract is
    // discriminating (adversarial round-12) — not the empty-vec default.
    row.submit_config.capabilities = vec![
        CapRequest {
            capability: CapabilityId::new("fs.read"),
        },
        CapRequest {
            capability: CapabilityId::new("net.connect"),
        },
    ];

    let cancel = CancellationToken::new();
    let h = tokio::spawn(Arc::clone(&m).materialize(row, cancel.clone()));

    assert!(
        wait_for_len(&rec.ran_ids, 1).await,
        "cron driver should have fired the hook at least once"
    );
    cancel.cancel();
    let result = h.await.unwrap();
    assert!(result.is_ok(), "cancelled cron materialize returns Ok");

    // All THREE pinned build(binary, component_id, caps) args were EXTRACTED
    // FROM the row (built once, before the tick loop) — the data-driven link,
    // not an id-string coincidence. A wrong impl that dropped/hardcoded
    // component_id or caps would fail here.
    let binaries = snapshot(&rec.seen_binaries);
    assert_eq!(
        binaries.len(),
        1,
        "factory built exactly one hook for a cron row"
    );
    assert_eq!(binaries[0], b"MARKER-BYTES".to_vec());
    assert_eq!(
        snapshot(&rec.seen_component_ids),
        vec!["cron-materialize-1".to_string()],
        "build() component_id must be the row's id, not empty/hardcoded"
    );
    assert_eq!(
        snapshot(&rec.seen_caps),
        vec![vec!["fs.read".to_string(), "net.connect".to_string()]],
        "build() caps must be the row's capabilities, not dropped"
    );

    // Every run carried the row's id (driver-side ComponentConfig.id == row.id).
    let ids = snapshot(&rec.ran_ids);
    assert!(!ids.is_empty());
    assert!(
        ids.iter().all(|i| i == "cron-materialize-1"),
        "hook must run with config.id == row.id, got {ids:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_mutation_changes_recorded_value() {
    // Same row shape as the data-driven test, but a DIFFERENT binary. The
    // recorded value MUST change — the anti-fake-green discriminator the
    // SYS-AC-109 ledger demands (deleting/changing the submit must change the
    // witness).
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let (m, rec) = build_materializer(false, dispatcher);
    let row = make_row(
        "cron-materialize-1",
        ComponentType::Cron,
        b"DIFFERENT-MARKER",
        Some(100),
        None,
        None,
    );

    let cancel = CancellationToken::new();
    let h = tokio::spawn(Arc::clone(&m).materialize(row, cancel.clone()));
    assert!(wait_for_len(&rec.ran_ids, 1).await);
    cancel.cancel();
    h.await.unwrap().unwrap();

    let binaries = snapshot(&rec.seen_binaries);
    assert_eq!(binaries.len(), 1);
    assert_eq!(
        binaries[0],
        b"DIFFERENT-MARKER".to_vec(),
        "factory must record the row's ACTUAL binary"
    );
    assert_ne!(
        binaries[0],
        b"MARKER-BYTES".to_vec(),
        "a changed submit binary must change the witnessed value"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn cron_sub_floor_interval_fails_closed() {
    // A cron row that bypassed the admission floor (interval_ms < 100) must NOT
    // be materialized into a sub-floor hot tick loop — the materializer
    // re-asserts MIN_RECURRING_INTERVAL_MS at the trust boundary (adversarial
    // round-6 W2). Fails closed BEFORE building a hook.
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let (m, rec) = build_materializer(false, dispatcher);
    let row = make_row(
        "cron-subfloor-1",
        ComponentType::Cron,
        b"X",
        Some(1), // below MIN_RECURRING_INTERVAL_MS (100)
        None,
        None,
    );

    // Bounded: a regression (missing floor) would hot-loop at 1ms and never
    // return — the timeout converts that into a fast, message-bearing failure
    // instead of an indefinite hang (adversarial round-10).
    let result = materialize_bounded(Arc::clone(&m), row).await;
    assert!(
        matches!(result, Err(HookError::Failure(_))),
        "sub-floor cron interval must fail closed, got {result:?}"
    );
    assert!(
        snapshot(&rec.seen_binaries).is_empty(),
        "sub-floor reject must precede building a hook"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// output_dir confinement (adversarial round-14): the drivers write result.bin
// into output_dir per tick; an absolute or traversal output_dir from a
// non-admission row is rejected at the materializer trust boundary before any
// driver dispatch (root-relative/symlink confinement remains the composition
// root's concern — MODULE-014 §3.6).
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn absolute_output_dir_fails_closed() {
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let (m, rec) = build_materializer(false, dispatcher);
    let mut row = make_row(
        "cron-absdir-1",
        ComponentType::Cron,
        b"X",
        Some(100),
        None,
        None,
    );
    row.submit_config.output_dir = Some("/etc/cron.d".into()); // absolute → arbitrary write sink

    let result = materialize_bounded(Arc::clone(&m), row).await;
    assert!(
        matches!(result, Err(HookError::Failure(_))),
        "absolute output_dir must fail closed, got {result:?}"
    );
    assert!(
        snapshot(&rec.seen_binaries).is_empty(),
        "output_dir reject must precede building a hook"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn traversal_output_dir_fails_closed() {
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let (m, rec) = build_materializer(false, dispatcher);
    let mut row = make_row(
        "task-travdir-1",
        ComponentType::Task,
        b"X",
        None,
        None,
        None,
    );
    row.submit_config.output_dir = Some("safe/../../escape".into()); // '..' traversal

    let result = materialize_bounded(Arc::clone(&m), row).await;
    assert!(
        matches!(result, Err(HookError::Failure(_))),
        "traversal output_dir must fail closed, got {result:?}"
    );
    assert!(
        snapshot(&rec.seen_binaries).is_empty(),
        "output_dir reject must precede building a hook"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Watcher: routes via a TriggerEvent trigger through resolve_trigger + bus
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watcher_routes_via_trigger_event() {
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let (m, rec) = build_materializer(false, Arc::clone(&dispatcher));
    let row = make_row(
        "watcher-materialize-1",
        ComponentType::Watcher,
        b"WATCH-BYTES",
        None,
        Some(TriggerConfig::TriggerEvent(TriggerSubscription {
            event_type: "grant.issued".into(), // whitelisted
            filter: None,
            debounce_ms: None,
        })),
        None,
    );

    let cancel = CancellationToken::new();
    let h = tokio::spawn(Arc::clone(&m).materialize(row, cancel.clone()));

    // Let the watcher's spawned source task subscribe (TriggerEventSource
    // subscribes synchronously at the top of run, then drains every 25ms).
    tokio::time::sleep(Duration::from_millis(30)).await;
    dispatcher.dispatch(make_event("grant.issued", "evt-watch-1"));

    assert!(
        wait_for_len(&rec.ran_ids, 1).await,
        "watcher should fire the hook after a matching event is dispatched"
    );
    cancel.cancel();
    let result = h.await.unwrap();
    assert!(result.is_ok());

    let binaries = snapshot(&rec.seen_binaries);
    assert_eq!(binaries.len(), 1);
    assert_eq!(binaries[0], b"WATCH-BYTES".to_vec());
    let ids = snapshot(&rec.ran_ids);
    assert!(
        ids.iter().all(|i| i == "watcher-materialize-1"),
        "got {ids:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn watcher_sub_floor_schedule_fails_closed() {
    // A watcher row with a sub-floor Schedule trigger must NOT drive a sub-100ms
    // hot tick loop — the materializer floors Schedule-leaf intervals at the trust
    // boundary (adversarial round-10), symmetric with the cron interval re-floor
    // (a watcher Schedule interval comes from a trigger string that neither
    // admission nor resolve_trigger/ScheduleTriggerSource bounds). Fails closed
    // BEFORE building a hook.
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let (m, rec) = build_materializer(false, dispatcher);
    let row = make_row(
        "watcher-subfloor-1",
        ComponentType::Watcher,
        b"X",
        None,
        Some(TriggerConfig::Schedule("every-1ms".into())), // sub-floor
        None,
    );

    // Bounded: a regression (missing floor) would drive a 1ms watcher tick loop
    // that never returns — the timeout converts that into a fast failure
    // (adversarial round-10 witness-integrity discipline).
    let result = materialize_bounded(Arc::clone(&m), row).await;
    assert!(
        matches!(result, Err(HookError::Failure(_))),
        "sub-floor watcher schedule must fail closed, got {result:?}"
    );
    assert!(
        snapshot(&rec.seen_binaries).is_empty(),
        "sub-floor schedule reject must precede building a hook"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn watcher_over_ceiling_schedule_fails_closed() {
    // A watcher Schedule interval above the 30-day ceiling must be rejected
    // (mirrors CronDriver's 30-day reject; ScheduleTriggerSource has no ceiling).
    // Witnesses the validate_schedule_intervals upper-bound branch.
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let (m, rec) = build_materializer(false, dispatcher);
    let row = make_row(
        "watcher-overceiling-1",
        ComponentType::Watcher,
        b"X",
        None,
        Some(TriggerConfig::Schedule("every-1000h".into())), // ~41.6 days > 30-day ceiling
        None,
    );

    let result = materialize_bounded(Arc::clone(&m), row).await;
    assert!(
        matches!(result, Err(HookError::Failure(_))),
        "over-ceiling watcher schedule must fail closed, got {result:?}"
    );
    assert!(snapshot(&rec.seen_binaries).is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn watcher_anyof_nested_sub_floor_schedule_fails_closed() {
    // A sub-floor Schedule nested inside an AnyOf must still be rejected — the
    // validate_watcher_trigger walker recurses AnyOf (fail-closed on any
    // offending leaf), so a "safe" sibling does not let the sub-floor leaf
    // through. Witnesses the AnyOf-recursion branch.
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let (m, rec) = build_materializer(false, dispatcher);
    let row = make_row(
        "watcher-anyof-subfloor-1",
        ComponentType::Watcher,
        b"X",
        None,
        Some(TriggerConfig::AnyOf(vec![
            TriggerConfig::TriggerEvent(TriggerSubscription {
                event_type: "grant.issued".into(),
                filter: None,
                debounce_ms: None,
            }),
            TriggerConfig::Schedule("every-1ms".into()), // sub-floor leaf nested in AnyOf
        ])),
        None,
    );

    let result = materialize_bounded(Arc::clone(&m), row).await;
    assert!(
        matches!(result, Err(HookError::Failure(_))),
        "sub-floor schedule nested in AnyOf must fail closed, got {result:?}"
    );
    assert!(snapshot(&rec.seen_binaries).is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn watcher_empty_anyof_fails_closed() {
    // An empty AnyOf trigger is structurally guaranteed never to fire
    // (AnyOfTriggerSource::run returns immediately for zero children → the
    // watcher drain loop exits without firing the hook) → an
    // admitted-but-never-fires silent no-op. The trust boundary must refuse it
    // (adversarial round-18). Fails closed before building a hook.
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let (m, rec) = build_materializer(false, dispatcher);
    let row = make_row(
        "watcher-empty-anyof-1",
        ComponentType::Watcher,
        b"X",
        None,
        Some(TriggerConfig::AnyOf(vec![])), // empty → never fires
        None,
    );

    let result = materialize_bounded(Arc::clone(&m), row).await;
    assert!(
        matches!(result, Err(HookError::Failure(_))),
        "empty AnyOf watcher trigger must fail closed (never-fires), got {result:?}"
    );
    assert!(
        snapshot(&rec.seen_binaries).is_empty(),
        "empty-AnyOf reject must precede building a hook"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Daemon: Never-vs-OnFailure delta witnesses restart_policy flow-through
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn daemon_never_policy_stops_after_one() {
    // Never + failing hook → restart_decision(Never, false) = Stop → exactly 1
    // run, returns Ok. No spawn/cancel needed (terminates on its own).
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let (m, rec) = build_materializer(true, dispatcher);
    let row = make_row(
        "daemon-never-1",
        ComponentType::Daemon,
        b"DAEMON-BYTES",
        None,
        None,
        Some(RestartPolicy::Never),
    );

    // Bounded: a regression that hardcoded a restart-capable policy (e.g. Always)
    // instead of reading restart_policy would loop forever here — the timeout
    // turns that into a fast, message-bearing failure rather than a hang
    // (adversarial round-10).
    let result = materialize_bounded(Arc::clone(&m), row).await;
    assert!(
        result.is_ok(),
        "Never daemon stops cleanly (Ok) after 1 iteration"
    );

    assert_eq!(snapshot(&rec.seen_binaries), vec![b"DAEMON-BYTES".to_vec()]);
    let ids = snapshot(&rec.ran_ids);
    assert_eq!(
        ids,
        vec!["daemon-never-1".to_string()],
        "Never ⇒ exactly 1 run"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_onfailure_policy_restarts() {
    // IDENTICAL row to daemon_never_policy_stops_after_one EXCEPT restart_policy
    // = OnFailure (+ same failing hook, retry: None). OnFailure + failure →
    // restart_decision = Restart → ≥2 runs. The 1-vs-≥2 delta with the Never
    // test (same row, only the policy differs) witnesses that the daemon's
    // restart_policy is read FROM the row, not hardcoded.
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let (m, rec) = build_materializer(true, dispatcher);
    let row = make_row(
        "daemon-onfailure-1",
        ComponentType::Daemon,
        b"DAEMON-BYTES",
        None,
        None,
        Some(RestartPolicy::OnFailure),
    );

    let cancel = CancellationToken::new();
    let h = tokio::spawn(Arc::clone(&m).materialize(row, cancel.clone()));
    assert!(
        wait_for_len(&rec.ran_ids, 2).await,
        "OnFailure daemon must restart (≥2 runs) on a failing hook"
    );
    cancel.cancel();
    let _ = h.await.unwrap();

    // Hook is built once and reused across restart iterations.
    assert_eq!(snapshot(&rec.seen_binaries), vec![b"DAEMON-BYTES".to_vec()]);
    let ids = snapshot(&rec.ran_ids);
    assert!(ids.len() >= 2, "OnFailure ⇒ ≥2 runs, got {}", ids.len());
    assert!(ids.iter().all(|i| i == "daemon-onfailure-1"), "got {ids:?}");
}

// ─────────────────────────────────────────────────────────────────────────
// Task: one-shot
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn task_routes_one_shot() {
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let (m, rec) = build_materializer(false, dispatcher);
    let row = make_row(
        "task-materialize-1",
        ComponentType::Task,
        b"TASK-BYTES",
        None,
        None,
        None,
    );

    let result = Arc::clone(&m)
        .materialize(row, CancellationToken::new())
        .await;
    assert!(
        result.is_ok(),
        "one-shot task returns Ok after a single run"
    );

    assert_eq!(snapshot(&rec.seen_binaries), vec![b"TASK-BYTES".to_vec()]);
    assert_eq!(
        snapshot(&rec.ran_ids),
        vec!["task-materialize-1".to_string()],
        "task runs exactly once with config.id == row.id"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn task_over_cap_delay_fails_closed() {
    // A task row that bypassed the admission delay cap (delay > MAX_TASK_DELAY_MS)
    // must NOT be materialized — run_task's pre-hook sleep is not raced against
    // cancel, so an unbounded delay would park the spawned task indefinitely. The
    // materializer re-asserts the cap at the trust boundary (adversarial round-8
    // W1, symmetric with the cron sub-floor reject). Fails closed BEFORE building
    // a hook.
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let (m, rec) = build_materializer(false, dispatcher);
    let mut row = make_row(
        "task-overcap-1",
        ComponentType::Task,
        b"X",
        None,
        None,
        None,
    );
    row.submit_config.delay = Some(u64::MAX); // far above MAX_TASK_DELAY_MS

    // Bounded: a regression (missing cap) would park run_task on a
    // multi-million-year sleep and never return — the timeout converts that into
    // a fast, message-bearing failure rather than a hang (adversarial round-10).
    let result = materialize_bounded(Arc::clone(&m), row).await;
    assert!(
        matches!(result, Err(HookError::Failure(_))),
        "over-cap task delay must fail closed, got {result:?}"
    );
    assert!(
        snapshot(&rec.seen_binaries).is_empty(),
        "over-cap reject must precede building a hook"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn task_cancel_interrupts_delay() {
    // A cancelled delayed task must stop promptly — the materializer races the
    // `cancel` token it holds against run_task (adversarial round-18), symmetric
    // with the cron/watcher/daemon arms. Without that race a 1-minute delay would
    // park the spawned task for the full minute after teardown.
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let (m, rec) = build_materializer(false, dispatcher);
    let mut row = make_row("task-cancel-1", ComponentType::Task, b"X", None, None, None);
    row.submit_config.delay = Some(60_000); // 1 min (within cap) — long enough the test won't wait it out

    let cancel = CancellationToken::new();
    let h = tokio::spawn(Arc::clone(&m).materialize(row, cancel.clone()));
    // Let the task arm build the hook and enter run_task's delay sleep.
    tokio::time::sleep(Duration::from_millis(30)).await;
    cancel.cancel();

    // The cancel must interrupt the 60s delay → materialize returns well under it.
    let result = tokio::time::timeout(Duration::from_secs(2), h)
        .await
        .expect("cancel must interrupt the task delay — materialize did not return within 2s")
        .unwrap();
    assert!(
        result.is_ok(),
        "cancelled delayed task returns Ok, got {result:?}"
    );
    assert!(
        snapshot(&rec.ran_ids).is_empty(),
        "hook must NOT run when the task is cancelled during its delay"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Agent: fail-closed (no silent no-op, factory NOT called)
// ─────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn agent_fails_closed() {
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let (m, rec) = build_materializer(false, dispatcher);
    let row = make_row(
        "agent-materialize-1",
        ComponentType::Agent,
        b"AGENT-BYTES",
        None,
        None,
        None,
    );

    let result = Arc::clone(&m)
        .materialize(row, CancellationToken::new())
        .await;
    assert!(
        matches!(result, Err(HookError::Failure(_))),
        "Agent materialization must fail closed, got {result:?}"
    );
    // Fail-closed happens BEFORE building a hook — no wasted factory call, no
    // silent no-op.
    assert!(
        snapshot(&rec.seen_binaries).is_empty(),
        "factory must NOT be called for an Agent row"
    );
    assert!(snapshot(&rec.ran_ids).is_empty());
}

// ─────────────────────────────────────────────────────────────────────────
// Object-safety lock (prompt-mandated witness self-containment; the canonical
// home for seam-trait locks is tests/object_safety.rs, which also covers it).
// ─────────────────────────────────────────────────────────────────────────

fn _object_safe(_: Box<dyn RunnableHookFactory>) {}

#[test]
fn materializer_factory_is_object_safe() {
    let _f: fn(Box<dyn RunnableHookFactory>) = |_| {};
}

// ─────────────────────────────────────────────────────────────────────────
// T13 (Stage-F obs SLICE 3, SYS-AC-228): component-type breaker gate consulted
// at the materialize dispatch path — the OPEN type is fail-closed (no hook
// built) while OTHER types proceed. Observed via materialize behaviour, NOT a
// direct is_open_component_type() bus query (the sys_ac_228 witness-floor ban).
// (Default no-gate behaviour is regression-locked by the existing tests above,
// which run without a gate and proceed.)
// ─────────────────────────────────────────────────────────────────────────

use advance_scheduler::hook::ComponentTypeBreakerGate;

/// Fake gate: only the `Watcher` component-type is breaker-open.
struct WatcherOnlyBreaker;
impl ComponentTypeBreakerGate for WatcherOnlyBreaker {
    fn is_open_component_type(&self, kind: ComponentType) -> Option<String> {
        if kind == ComponentType::Watcher {
            Some("watcher breaker open (test)".to_string())
        } else {
            None
        }
    }
}

fn build_materializer_with_gate(
    dispatcher: Arc<TriggerBusDispatchImpl>,
    gate: Arc<dyn ComponentTypeBreakerGate>,
) -> (Arc<ComponentMaterializer>, Recorders) {
    let seen_binaries = Arc::new(Mutex::new(Vec::new()));
    let seen_component_ids = Arc::new(Mutex::new(Vec::new()));
    let seen_caps = Arc::new(Mutex::new(Vec::new()));
    let ran_ids = Arc::new(Mutex::new(Vec::new()));
    let factory = Arc::new(RecordingFactory {
        seen_binaries: Arc::clone(&seen_binaries),
        seen_component_ids: Arc::clone(&seen_component_ids),
        seen_caps: Arc::clone(&seen_caps),
        ran_ids: Arc::clone(&ran_ids),
        hook_fails: false,
    });
    let materializer = Arc::new(
        ComponentMaterializer::new(
            factory,
            dispatcher,
            Arc::new(NoopFileWatchSource),
            Arc::new(NoopWebhookSource),
        )
        .with_component_type_breaker_gate(gate),
    );
    (
        materializer,
        Recorders {
            seen_binaries,
            seen_component_ids,
            seen_caps,
            ran_ids,
        },
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn breaker_gate_blocks_open_type_and_lets_others_proceed() {
    let dispatcher = Arc::new(TriggerBusDispatchImpl::new());
    let (m, rec) = build_materializer_with_gate(dispatcher, Arc::new(WatcherOnlyBreaker));

    // --- OPEN type (Watcher) is fail-closed at the gate, BEFORE any hook build ---
    // (trigger=None is fine: the gate returns Err before the Watcher match arm).
    let watcher_row = make_row(
        "watcher-blocked-1",
        ComponentType::Watcher,
        b"WATCHER-BYTES",
        None,
        None,
        None,
    );
    let blocked = materialize_bounded(Arc::clone(&m), watcher_row).await;
    assert!(
        blocked.is_err(),
        "an open component-type breaker must fail-close the watcher dispatch"
    );
    let err = format!("{:?}", blocked.unwrap_err());
    assert!(
        err.contains("component-type breaker"),
        "the error must name the component-type breaker, got: {err}"
    );
    assert!(
        snapshot(&rec.seen_component_ids).is_empty(),
        "blocked watcher must NOT reach factory.build (fail-closed before the match)"
    );

    // --- A DIFFERENT type (Cron) proceeds past the gate (factory.build runs) ---
    let cron_row = make_row(
        "cron-proceeds-1",
        ComponentType::Cron,
        b"CRON-BYTES",
        Some(100),
        None,
        None,
    );
    let cancel = CancellationToken::new();
    let h = tokio::spawn(Arc::clone(&m).materialize(cron_row, cancel.clone()));
    assert!(
        wait_for_len(&rec.seen_component_ids, 1).await,
        "cron row must PROCEED past the gate and reach factory.build"
    );
    cancel.cancel();
    let _ = h.await.unwrap();
    assert_eq!(
        snapshot(&rec.seen_component_ids),
        vec!["cron-proceeds-1".to_string()],
        "only the cron row reached build — watcher was blocked, type-discriminated"
    );
}

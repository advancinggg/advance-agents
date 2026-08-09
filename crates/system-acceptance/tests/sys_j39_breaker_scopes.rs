//! SYS-J-39 — when a breaker opens for a capability/component-type/agent, new dispatch
//! is blocked and old mailbox messages frozen, while admin terminate/cancel control
//! messages still bypass it.
//! Chain: MODULE-001 → MODULE-006 → MODULE-019.
//!
//! Witnessed since the small-witness slice (2026-06-11): the SUT's injector-shared
//! `DefaultCircuitBreakerBus` now ALSO gates the REAL `MailboxDispatcherImpl`
//! (`.with_circuit_breaker_bus`, Layer 1) and drives the production
//! `BreakerSubscriber` (Layer 4 freeze/drain) — so agent-scope (125/126/127) runs
//! through the real messaging path, and capability-scope (227) through the real
//! `CapabilityInjector` host-fn gate on a real guest turn.
//!
//! Criterion-reading note (disclosed at the plan gate): the parenthetical
//! `(circuit_breaker.opened/closed)` clauses are read as the breaker STATE
//! TRANSITIONS, observed via the production `CircuitBreakerBus::subscribe()`
//! `BreakerEvent` stream — there is no production emitter of the taxonomy
//! `circuit_breaker.*` EventBus events (event-bus taxonomy constants only).
//! SYS-AC-125's notify clause: RECONCILED by the 2026-06-12 `/spec` MODULE-006
//! doc-drift rerun — the canonical 4-variant `NotifyError` has no
//! `circuit-breaker-open` arm; the criterion now names the canonical surface,
//! `notify-error::capability-denied("breaker_open")`, which this test asserts
//! verbatim alongside the send/reply `msg-error::circuit-breaker-open` legs.
//! SYS-AC-125 flipped `passed` on this witness (ledger-only flip, as predicted).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use advance_cli::runnable_walk::run_readiness_gated_walk_with_breaker_gate;
use advance_messaging::MailboxDispatcher;
use advance_runtime::circuit_breaker::{
    BreakerScope, BreakerState, CircuitBreaker, CircuitBreakerBus, DefaultCircuitBreakerBus,
};
use advance_scheduler::hook::{
    FileWatchSource, HookError, RunnableHook, RunnableHookFactory, RuntimeReadiness, WebhookSource,
};
use advance_scheduler::registry::ComponentRegistry;
use advance_scheduler::trigger_bus::TriggerBusDispatchImpl;
use advance_scheduler::trigger_source::TriggerFireEvent;
use advance_scheduler::types::{ComponentSubmitConfig, WebhookConfig};
use advance_shared_types::capability::CapRequest;
use advance_shared_types::component::ComponentType;
use advance_shared_types::mailbox::{Message, MessageKind, MessageOrigin, MsgError, NotifyError};
use chrono::Utc;
use system_acceptance::{Cap, SystemUnderTest};

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");
const AGENT: &str = "agent:harness";

fn msg(id: &str, kind: MessageKind, payload: &[u8]) -> Message {
    Message {
        id: id.to_string(),
        kind,
        from: format!("user:j39-{id}"),
        to: AGENT.to_string(),
        payload: payload.to_vec(),
        context: None,
        timestamp: SystemTime::now(),
        origin: None,
    }
}

fn open_spec(scope: BreakerScope, target: &str) -> CircuitBreaker {
    CircuitBreaker {
        scope,
        target: target.to_string(),
        state: BreakerState::Open,
        kill_existing: false,
        reason: "j39-witness".to_string(),
    }
}

/// Bounded wait until the BreakerSubscriber's freeze/unfreeze propagates.
/// 1000 x 2ms = 2s ceiling (the harness's drive_cron_fire bounded-wait precedent;
/// propagation normally lands within a few ms — adversarial r11 widened from 1s).
async fn wait_frozen(sut: &SystemUnderTest, expect_frozen: bool) {
    let store = sut.mailbox_store();
    for _ in 0..1000 {
        if let Some(mb) = store.get(AGENT) {
            if mb.is_frozen() == expect_frozen {
                return;
            }
        } else if !expect_frozen {
            return;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    panic!("BreakerSubscriber freeze={expect_frozen} did not propagate within 2s");
}

/// SYS-AC-125 — after opening an agent-scope breaker (circuit_breaker.opened), a new
/// send/reply returns msg-error::circuit-breaker-open and notify-agent returns the
/// breaker-caused notify rejection.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_125_agent_scope_rejects_send_reply_notify() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .build(CORE_BYTES)
        .await;
    let breaker = sut.circuit_breaker();
    let dispatcher = sut.dispatcher().clone();

    // Pre-open: record an inbound trace entry so the reply leg has a target
    // (reply routes to origin.adapter_id — use the SUT agent itself, which exists).
    dispatcher
        .trace()
        .record(
            "j39-inbound-1",
            MessageOrigin {
                message_id: "j39-inbound-1".to_string(),
                original_channel: "harness".to_string(),
                original_sender: "user:j39".to_string(),
                adapter_id: AGENT.to_string(),
                channel_metadata: HashMap::new(),
                received_at: Utc::now(),
                context: None,
            },
            AGENT,
        )
        .expect("trace record");

    // The breaker state transition is observable via the production
    // BreakerEvent stream (the criterion's "circuit_breaker.opened" reading).
    let mut events = breaker.subscribe();
    breaker
        .open(open_spec(BreakerScope::Agent, AGENT))
        .expect("open agent breaker");
    let opened = events.recv().await.expect("BreakerEvent emitted on open");
    assert_eq!(opened.scope, BreakerScope::Agent);
    assert_eq!(opened.target, AGENT);
    assert_eq!(opened.new_state, BreakerState::Open);

    // send (deliver, non-Control) → msg-error::circuit-breaker-open.
    let err = dispatcher
        .deliver(AGENT, msg("j39-send", MessageKind::Agent, b"blocked"))
        .await
        .expect_err("send while open must be rejected");
    assert!(
        matches!(&err, MsgError::CircuitBreakerOpen(s) if s == "agent"),
        "send → CircuitBreakerOpen(\"agent\"), got {err:?}"
    );

    // reply → msg-error::circuit-breaker-open (target = origin.adapter_id).
    let err = dispatcher
        .reply(AGENT, "j39-inbound-1", b"reply-blocked".to_vec())
        .await
        .expect_err("reply while open must be rejected");
    assert!(
        matches!(&err, MsgError::CircuitBreakerOpen(s) if s == "agent"),
        "reply → CircuitBreakerOpen(\"agent\"), got {err:?}"
    );

    // notify-agent → the breaker-caused notify rejection. Product shape:
    // NotifyError::CapabilityDenied("breaker_open") — the criterion's
    // `notify-error::circuit-breaker-open` variant does not exist canonically
    // (MODULE-006 doc-drift; 125 deferred on the naming, see module docs).
    let err = dispatcher
        .notify_agent("user:j39-notify", AGENT, b"notify-blocked".to_vec(), None)
        .await
        .expect_err("notify while open must be rejected");
    assert!(
        matches!(&err, NotifyError::CapabilityDenied(s) if s == "breaker_open"),
        "notify → CapabilityDenied(\"breaker_open\"), got {err:?}"
    );

    // Close → BreakerEvent Closed; dispatch admits again (recovery semantics).
    breaker
        .close(BreakerScope::Agent, AGENT)
        .expect("close agent breaker");
    let closed = events.recv().await.expect("BreakerEvent emitted on close");
    assert_eq!(closed.new_state, BreakerState::Closed);
    dispatcher
        .deliver(AGENT, msg("j39-send-2", MessageKind::Agent, b"admitted"))
        .await
        .expect("send admits after close");
}

/// SYS-AC-126 — messages enqueued before the breaker opened stay frozen while open,
/// then drain in priority/FIFO order once it closes (circuit_breaker.closed).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_126_frozen_while_open_drains_priority_fifo_on_close() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .build(CORE_BYTES)
        .await;
    let breaker = sut.circuit_breaker();
    let dispatcher = sut.dispatcher().clone();
    let store = sut.mailbox_store();

    // Enqueue BEFORE the breaker opens: Auto m1, Control c1, Auto m2.
    // (Auto → normal FIFO lane; Control → high-priority lane.)
    dispatcher
        .deliver(AGENT, msg("m1", MessageKind::Auto, b"m1"))
        .await
        .expect("m1");
    dispatcher
        .deliver(AGENT, msg("c1", MessageKind::Control, b"c1"))
        .await
        .expect("c1");
    dispatcher
        .deliver(AGENT, msg("m2", MessageKind::Auto, b"m2"))
        .await
        .expect("m2");

    breaker
        .open(open_spec(BreakerScope::Agent, AGENT))
        .expect("open agent breaker");
    wait_frozen(&sut, true).await;

    // Frozen: the already-queued messages stay held (poll yields nothing).
    let mb = store.get(AGENT).expect("mailbox exists");
    assert!(
        mb.poll().is_none(),
        "queued messages stay frozen while open"
    );
    assert_eq!(mb.depth(), 3, "nothing drained while frozen");

    // Close → unfreeze → drain order: high-priority Control first, then FIFO.
    breaker
        .close(BreakerScope::Agent, AGENT)
        .expect("close agent breaker");
    wait_frozen(&sut, false).await;

    let drained: Vec<String> = std::iter::from_fn(|| mb.poll()).map(|m| m.id).collect();
    assert_eq!(
        drained,
        vec!["c1".to_string(), "m1".to_string(), "m2".to_string()],
        "drain order = [Control first, then Auto FIFO]"
    );
}

/// SYS-AC-127 — a MessageKind::Control admin message (terminate/cancel) delivers
/// successfully to the same agent while the breaker is open.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_127_control_delivers_while_open() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .build(CORE_BYTES)
        .await;
    let breaker = sut.circuit_breaker();
    let dispatcher = sut.dispatcher().clone();
    let store = sut.mailbox_store();

    breaker
        .open(open_spec(BreakerScope::Agent, AGENT))
        .expect("open agent breaker");
    wait_frozen(&sut, true).await;

    // Non-Control is rejected (the discriminating control)...
    let err = dispatcher
        .deliver(AGENT, msg("j39-agent", MessageKind::Agent, b"no"))
        .await
        .expect_err("non-Control rejected while open");
    assert!(matches!(err, MsgError::CircuitBreakerOpen(_)));

    // ...while the SAME agent's Control admin message delivers successfully.
    dispatcher
        .deliver(AGENT, msg("j39-ctl", MessageKind::Control, b"cancel-run"))
        .await
        .expect("Control bypasses the open breaker");

    // It is queued (held by the Layer-4 freeze until close, in the
    // high-priority lane — Layer 1 admission is the bypass the criterion names).
    let mb = store.get(AGENT).expect("mailbox exists");
    assert_eq!(
        mb.depth(),
        1,
        "the Control message was admitted into the mailbox"
    );
    breaker.close(BreakerScope::Agent, AGENT).expect("close");
    wait_frozen(&sut, false).await;
    let first = mb.poll().expect("drains after close");
    assert_eq!(first.id, "j39-ctl");
    assert!(matches!(first.kind, MessageKind::Control));
}

/// SYS-AC-227 — after opening a capability-scope breaker (scope=capability), a guest
/// host-function call for that capability is blocked at dispatch (the
/// CapabilityInjector gate, `capability-denied("circuit-breaker: {reason}")`),
/// distinct from the agent-scope send/notify path.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_227_capability_scope_blocks_guest_host_fn_dispatch() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .build(CORE_BYTES)
        .await;
    let breaker = sut.circuit_breaker();

    // Open the CAPABILITY-scope breaker for "fs" — the agent scope stays closed
    // (the scopes are independent; this is the "distinct from agent-scope" leg).
    breaker
        .open(open_spec(BreakerScope::Capability, "fs"))
        .expect("open capability breaker");
    assert!(
        breaker.is_open_agent(AGENT).is_none(),
        "agent scope unaffected"
    );

    // A real guest turn: the j01 guest's ONE host call is agent-fs write. The
    // injector consults is_open_capability at host-fn dispatch and traps with
    // "circuit-breaker: {reason}" → the guest's write fails → no file, no commit.
    sut.inject_message("j39-blocked", b"blocked-payload").await;
    sut.run_turn().await;
    assert!(
        sut.read_workspace_file("j01.txt").is_none(),
        "guest fs.write was blocked at capability dispatch"
    );
    assert_eq!(
        sut.turn_commits().len(),
        0,
        "no turn commit for the blocked write"
    );

    // Close → the SAME guest path succeeds (discriminates breaker vs broken fixture).
    breaker
        .close(BreakerScope::Capability, "fs")
        .expect("close capability breaker");
    sut.inject_message("j39-allowed", b"allowed-payload").await;
    sut.run_turn().await;
    assert_eq!(
        sut.read_workspace_file("j01.txt").as_deref(),
        Some(b"allowed-payload".as_slice()),
        "guest fs.write lands after the capability breaker closes"
    );
}

// ───────────────────── SYS-AC-228 component-type breaker (Wave-14 harvest) ─────────────────────
//
// SYS-AC-228 — after opening a component-type-scope breaker (scope=component-type, e.g. watcher),
// NEW DISPATCH to components of that type is blocked while OTHER types continue, proving the
// component-type scope is enforced independently of the agent scope.
//
// PRODUCTION e2e witness (Wave-14 — the prior "ZERO production dispatch consumer" deferral is now
// STALE). Wave-13 Lane B wired the gate into the production boot: `advance start`
// (crates/cli/src/commands/start.rs) calls `run_readiness_gated_walk_with_breaker_gate`, which
// installs `DefaultComponentTypeBreakerGate(bus)` onto the `ComponentMaterializer`; the materializer
// CONSULTS `is_open_component_type(row.component_type)` BEFORE the per-type match and BEFORE any
// `factory.build`, Erring "dispatch blocked by component-type breaker: {reason}" for the open type.
//
// This witness drives that SAME production composition fn over a real `ComponentRegistry` + real
// `DefaultCircuitBreakerBus`, observing the per-row `tokio::spawn`ed `JoinHandle` results — NOT a
// direct `is_open_component_type` bus query (the sys_ac_228 witness-floor ban), and NOT the
// `breaker_gate.rs` unit that drives `materialize` directly. It mirrors the build-lane
// `crates/cli/tests/runnable_walk_breaker.rs` and follows the already-`passed` SYS-AC-109 precedent
// (sys_j34_runleg drives `run_readiness_gated_walk` directly). Witness floor: the peripheral doubles
// (ready probe / `UnreachableFactory` / no-op file+webhook sources) are NEVER load-bearing — the
// gate fires before the factory, and the cron-proceeds discriminator + `UnreachableFactory` (Errs if
// reached) prove the real production walk + materializer + breaker make the load-bearing decision.

struct ReadyProbe;
#[async_trait]
impl RuntimeReadiness for ReadyProbe {
    async fn is_ready(&self) -> bool {
        true
    }
}

/// Every row must Err at the gate or at per-type config validation BEFORE `factory.build` — so
/// reaching `build` is a test failure (anti-fake-green: a walk that dropped the gate would let the
/// watcher reach the factory / proceed).
struct UnreachableFactory;
#[async_trait]
impl RunnableHookFactory for UnreachableFactory {
    async fn build(
        &self,
        _binary: &[u8],
        _component_id: &str,
        _caps: &[CapRequest],
    ) -> Result<Arc<dyn RunnableHook>, HookError> {
        Err(HookError::Failure(
            "UnreachableFactory built unexpectedly".into(),
        ))
    }
}

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

/// A misconfigured submit config — once PAST the gate, each row Errs for its OWN reason (the
/// type-discrimination signal): a Watcher has no `trigger` (Errs "trigger config"); a Cron seeded
/// with `interval_ms = None` has no interval (Errs "interval_ms").
fn submit_cfg(id: &str, ct: ComponentType) -> ComponentSubmitConfig {
    ComponentSubmitConfig {
        sensitive_params: Vec::new(),
        id: id.to_owned(),
        component_type: ct,
        binary: b"x".to_vec(),
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

async fn open_registry() -> (tempfile::TempDir, ComponentRegistry) {
    let dir = tempfile::TempDir::new().unwrap();
    let registry = ComponentRegistry::open_in(dir.path(), "reg.db")
        .await
        .expect("open registry");
    (dir, registry)
}

/// Drive the PRODUCTION walk variant (`run_readiness_gated_walk_with_breaker_gate`, the fn
/// `advance start` calls at boot) over the seeded registry, and collect each spawned row's
/// `JoinHandle` Err (as a debug string) keyed by component id.
async fn walk_and_collect(
    registry: &ComponentRegistry,
    bus: Arc<dyn CircuitBreakerBus>,
) -> HashMap<String, String> {
    let cancel = CancellationToken::new();
    let handles = run_readiness_gated_walk_with_breaker_gate(
        registry,
        Arc::new(ReadyProbe),
        Arc::new(UnreachableFactory),
        Arc::new(TriggerBusDispatchImpl::new()),
        Arc::new(NoopFileWatchSource),
        Arc::new(NoopWebhookSource),
        bus,
        cancel.clone(),
    )
    .await
    .expect("ready walk returns Ok");

    let mut out = HashMap::new();
    for (id, handle) in handles {
        let res = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("materialize must resolve promptly (Err path), not hang")
            .expect("spawned task did not panic");
        out.insert(
            id.as_str().to_owned(),
            format!("{:?}", res.expect_err("row must Err in this test")),
        );
    }
    out
}

/// SYS-AC-228 — an Open `watcher` component-type breaker, carried by the PRODUCTION
/// `run_readiness_gated_walk_with_breaker_gate` onto the real materializer, BLOCKS the watcher row's
/// dispatch (its `JoinHandle` Errs naming the component-type breaker) while the cron row PROCEEDS
/// past the gate (Errs on its OWN missing interval) — type-discrimination through the product walk
/// dispatch path, proving the component-type scope is enforced independently of the agent scope.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_228_component_type_breaker_blocks_dispatch_through_walk() {
    let (_dir, registry) = open_registry().await;
    // Seed directly (bypasses admission, like the runnable_walk witness): a Watcher with no trigger
    // + a Cron with no interval.
    registry
        .insert(
            "agent:root",
            &submit_cfg("w1", ComponentType::Watcher),
            None,
        )
        .await
        .expect("insert watcher");
    registry
        .insert("agent:root", &submit_cfg("c1", ComponentType::Cron), None)
        .await
        .expect("insert cron");

    let bus: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    bus.open(open_spec(
        BreakerScope::ComponentType,
        ComponentType::Watcher.as_str(),
    ))
    .expect("open watcher breaker");

    let results = walk_and_collect(&registry, Arc::clone(&bus)).await;

    let watcher = results.get("w1").expect("watcher row spawned by the walk");
    assert!(
        watcher.contains("component-type breaker"),
        "open watcher breaker must BLOCK the watcher THROUGH the production walk, got: {watcher}"
    );

    let cron = results.get("c1").expect("cron row spawned by the walk");
    assert!(
        !cron.contains("component-type breaker"),
        "cron must NOT be blocked by the watcher breaker (component-type scope is independent), got: {cron}"
    );
    assert!(
        cron.contains("interval_ms"),
        "cron PROCEEDED past the gate and failed on its OWN missing interval, got: {cron}"
    );
}

/// SYS-AC-228 (close-recovery + fixture discriminator) — closing the watcher breaker lets the
/// watcher PROCEED past the gate on a re-walk (its `JoinHandle` now Errs on its OWN missing trigger,
/// NOT the breaker), proving the gate — not a broken fixture — caused the earlier block.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_228_close_lets_watcher_proceed() {
    let (_dir, registry) = open_registry().await;
    registry
        .insert(
            "agent:root",
            &submit_cfg("w1", ComponentType::Watcher),
            None,
        )
        .await
        .expect("insert watcher");

    let bus: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    bus.open(open_spec(
        BreakerScope::ComponentType,
        ComponentType::Watcher.as_str(),
    ))
    .expect("open watcher breaker");

    // Open: watcher blocked through the walk.
    let blocked = walk_and_collect(&registry, Arc::clone(&bus)).await;
    assert!(
        blocked
            .get("w1")
            .expect("watcher spawned")
            .contains("component-type breaker"),
        "watcher must be breaker-blocked while open"
    );

    // Close → re-walk → watcher PROCEEDS past the gate (fails on its own missing trigger).
    bus.close(BreakerScope::ComponentType, ComponentType::Watcher.as_str())
        .expect("close watcher breaker");
    let after = walk_and_collect(&registry, Arc::clone(&bus)).await;
    let w = after.get("w1").expect("watcher spawned");
    assert!(
        !w.contains("component-type breaker"),
        "after close, the watcher must no longer be breaker-blocked, got: {w}"
    );
    assert!(
        w.contains("trigger config"),
        "watcher PROCEEDED past the gate and failed on its OWN missing trigger, got: {w}"
    );
}

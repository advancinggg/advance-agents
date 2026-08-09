//! Build-lane witness for `run_readiness_gated_walk_with_breaker_gate` (Wave-13
//! Lane B / SYS-AC-228 production-composition install). Proves the component-type
//! breaker gate dispatches THROUGH the production readiness walk via the per-row
//! `JoinHandle` results — NOT a direct `is_open_component_type` bus query (the
//! sys_ac_228 witness-floor ban), and NOT a SYS-AC flip (that is the harvest's).
//!
//! Delta vs `breaker_gate.rs` T14 (which drives `ComponentMaterializer::materialize`
//! DIRECTLY with a hand-built gate): here the gate is carried by the PRODUCTION
//! walk fn (`run_readiness_gated_walk_with_breaker_gate`) onto the materializer it
//! builds, and reaches the per-row `tokio::spawn`ed task. The discriminator: a row
//! the gate BLOCKS errors with "component-type breaker"; a row that PROCEEDS past
//! the gate errors for its OWN reason (missing interval/trigger) — proving it
//! reached the per-type match arm THROUGH the walk, not the gate. A walk that
//! dropped/forgot the gate would let the watcher proceed (anti-fake-green).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use advance_cli::runnable_walk::run_readiness_gated_walk_with_breaker_gate;
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

// ─────────────────────────── test doubles ───────────────────────────

struct ReadyProbe;
#[async_trait]
impl RuntimeReadiness for ReadyProbe {
    async fn is_ready(&self) -> bool {
        true
    }
}

/// Every row must Err at the gate or at per-type config validation BEFORE
/// `factory.build` — so reaching `build` is a test failure.
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

// ─────────────────────────── helpers ───────────────────────────

/// A misconfigured submit config: a Watcher has no `trigger` (Errs "trigger
/// config" past the gate); a Cron seeded with `interval_ms = None` has no interval
/// (Errs "interval_ms" past the gate). Each Errs for its OWN reason once past the
/// gate — the type-discrimination signal.
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

fn open_spec(target: &str) -> CircuitBreaker {
    CircuitBreaker {
        scope: BreakerScope::ComponentType,
        target: target.to_owned(),
        state: BreakerState::Open,
        kill_existing: false,
        reason: "ops".to_owned(),
    }
}

async fn open_registry() -> (tempfile::TempDir, ComponentRegistry) {
    let dir = tempfile::TempDir::new().unwrap();
    let registry = ComponentRegistry::open_in(dir.path(), "reg.db")
        .await
        .expect("open registry");
    (dir, registry)
}

/// Drive the PRODUCTION walk variant over the seeded registry and collect each
/// spawned row's `JoinHandle` Err (as a debug string) keyed by component id.
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

// ─────────────────────────── tests ───────────────────────────

/// T-RWB-01 — an Open `watcher` component-type breaker, bridged through the cli
/// adapter into the PRODUCTION `run_readiness_gated_walk_with_breaker_gate`, blocks
/// the watcher row's dispatch (its `JoinHandle` Errs naming the component-type
/// breaker) while the cron row PROCEEDS past the gate (Errs on its OWN missing
/// interval) — type-discrimination through the product walk dispatch path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn walk_installs_gate_blocks_watcher_while_cron_proceeds() {
    let (_dir, registry) = open_registry().await;
    // Seed directly (bypasses admission, like the runnable_walk.rs witness): a
    // Watcher with no trigger + a Cron with no interval.
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
    bus.open(open_spec(ComponentType::Watcher.as_str()))
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
        "cron must NOT be blocked by the watcher breaker, got: {cron}"
    );
    assert!(
        cron.contains("interval_ms"),
        "cron PROCEEDED past the gate and failed on its own missing interval, got: {cron}"
    );
}

/// T-RWB-02 — closing the watcher breaker lets the watcher PROCEED past the gate
/// on a re-walk (its `JoinHandle` now Errs on its OWN missing trigger, NOT the
/// breaker) — close-recovery + discriminates the breaker from a broken fixture.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn walk_gate_close_lets_watcher_proceed() {
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
    bus.open(open_spec(ComponentType::Watcher.as_str()))
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

    // Close → re-walk → watcher PROCEEDS past the gate (fails on its own missing
    // trigger), proving the gate (not a broken fixture) caused the earlier block.
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
        "watcher PROCEEDED past the gate and failed on its own missing trigger, got: {w}"
    );
}

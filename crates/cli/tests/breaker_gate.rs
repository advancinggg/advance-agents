//! Stage-F obs SLICE 3 — T14 (SYS-AC-228): the REAL `DefaultCircuitBreakerBus`
//! bridged through the cli `DefaultComponentTypeBreakerGate` adapter into
//! `ComponentMaterializer::materialize` blocks the OPEN component-type's dispatch
//! while OTHER types proceed — observed via `materialize` behaviour (the PRODUCT
//! dispatch path), NOT a direct `is_open_component_type()` bus query (the
//! sys_ac_228 witness-floor ban).
//!
//! Discriminator: a row that the gate BLOCKS errors with "component-type breaker";
//! a row that PROCEEDS past the gate errors for its OWN reason (missing
//! interval/trigger) — proving it reached the type-match arm, not the gate.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use advance_cli::breaker_gate::DefaultComponentTypeBreakerGate;
use advance_runtime::circuit_breaker::{
    BreakerScope, BreakerState, CircuitBreaker, CircuitBreakerBus, DefaultCircuitBreakerBus,
};
use advance_scheduler::hook::{FileWatchSource, WebhookSource};
use advance_scheduler::hook::{HookError, RunnableHook, RunnableHookFactory};
use advance_scheduler::materializer::ComponentMaterializer;
use advance_scheduler::registry::ComponentRegistryRow;
use advance_scheduler::trigger_bus::TriggerBusDispatchImpl;
use advance_scheduler::trigger_source::TriggerFireEvent;
use advance_scheduler::types::{ComponentId, ComponentSubmitConfig, RestartPolicy, WebhookConfig};
use advance_shared_types::capability::CapRequest;
use advance_shared_types::component::ComponentType;
use tokio::sync::mpsc;

// A factory that must never be reached in this test (every row Errs before build).
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

fn make_row(id: &str, component_type: ComponentType) -> ComponentRegistryRow {
    ComponentRegistryRow {
        id: ComponentId(id.to_owned()),
        component_type,
        submit_config: ComponentSubmitConfig {
            sensitive_params: Vec::new(),
            id: id.to_owned(),
            component_type,
            binary: b"x".to_vec(),
            capabilities: Vec::new(),
            output_dir: None,
            // Cron has NO interval_ms + Watcher has NO trigger -> each Errs for its
            // OWN reason once past the gate (the discriminator).
            trigger: None,
            restart_policy: Some(RestartPolicy::Never),
            delay: None,
            initial_grants: None,
            preset: None,
            retry: None,
        },
        submitter: "agent:root".to_owned(),
        submitted_at_ms: 0,
        interval_ms: None,
        expected_next_fire_at_ms: None,
        last_fire_at_ms: None,
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

async fn materialize_err(m: Arc<ComponentMaterializer>, row: ComponentRegistryRow) -> String {
    let r = tokio::time::timeout(
        Duration::from_secs(2),
        m.materialize(row, CancellationToken::new()),
    )
    .await
    .expect("materialize must return promptly (Err path), not hang");
    format!("{:?}", r.expect_err("row must Err in this test"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_bus_component_type_breaker_blocks_via_materialize() {
    let bus: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let gate = Arc::new(DefaultComponentTypeBreakerGate::new(Arc::clone(&bus)));
    let m = Arc::new(
        ComponentMaterializer::new(
            Arc::new(UnreachableFactory),
            Arc::new(TriggerBusDispatchImpl::new()),
            Arc::new(NoopFileWatchSource),
            Arc::new(NoopWebhookSource),
        )
        .with_component_type_breaker_gate(gate),
    );

    // Open the WATCHER component-type breaker on the REAL bus.
    bus.open(open_spec(ComponentType::Watcher.as_str()))
        .unwrap();

    // Watcher is BLOCKED at the gate (error names the component-type breaker).
    let watcher_err = materialize_err(Arc::clone(&m), make_row("w1", ComponentType::Watcher)).await;
    assert!(
        watcher_err.contains("component-type breaker"),
        "open watcher breaker must block the watcher via materialize, got: {watcher_err}"
    );

    // Cron PROCEEDS past the gate (errors for its OWN reason: missing interval),
    // proving type-discrimination — other types continue while watcher is blocked.
    let cron_err = materialize_err(Arc::clone(&m), make_row("c1", ComponentType::Cron)).await;
    assert!(
        !cron_err.contains("component-type breaker"),
        "cron must NOT be blocked by the watcher breaker"
    );
    assert!(
        cron_err.contains("interval_ms"),
        "cron proceeded past the gate and failed on its own missing interval, got: {cron_err}"
    );

    // Close the watcher breaker → watcher now PROCEEDS past the gate (fails on its
    // own missing trigger) — discriminates the breaker from a broken fixture.
    bus.close(BreakerScope::ComponentType, ComponentType::Watcher.as_str())
        .unwrap();
    let watcher_after =
        materialize_err(Arc::clone(&m), make_row("w2", ComponentType::Watcher)).await;
    assert!(
        !watcher_after.contains("component-type breaker"),
        "after close, the watcher must no longer be breaker-blocked, got: {watcher_after}"
    );
}

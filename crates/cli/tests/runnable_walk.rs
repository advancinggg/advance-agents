//! Witness #2 for [`run_readiness_gated_walk`] (B3 satellite).
//!
//! Proves the readiness-gated walk: (T-RW-01) on a ready probe it lists the
//! registry, filters Agent rows, and spawns one materialize task per non-Agent
//! row through the REAL production factory — a row with real bytes → `Ok`, a row
//! with corrupt bytes → `Err`, the good row `Ok` DESPITE the bad row's `Err`
//! (per-row error isolation); (T-RW-02) on a not-ready probe it fail-fasts with
//! `Err(WalkError::NotReady)` and spawns NOTHING (a recording factory's
//! build-counter stays 0); (T-RW-03) an empty registry yields `Ok(vec![])`.
//!
//! Uses real `ComponentRegistry::open_in` + `insert` (the production
//! persist→`list()` path; binary round-trips through serde) and Task rows
//! (one-shot, return on their own — no cancel, no `output_dir` side effects).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use wit_component::ComponentEncoder;

use advance_cli::runnable_hook_factory::WasmRunnableHookFactory;
use advance_cli::runnable_walk::{
    run_readiness_gated_walk, start_continuous_readiness_gated_walk_with_breaker_gate, WalkError,
};
use advance_runtime::circuit_breaker::{CircuitBreakerBus, DefaultCircuitBreakerBus};
use advance_runtime::config::WasmConfig;
use advance_runtime::host_registry::{HostRegistry, InMemoryHostRegistry};
use advance_runtime::{CapabilityInjector, ComponentRuntime};
use advance_scheduler::hook::{
    FileWatchSource, HookError, RunnableHook, RunnableHookFactory, RuntimeReadiness, WebhookSource,
};
use advance_scheduler::registry::ComponentRegistry;
use advance_scheduler::trigger_bus::TriggerBusDispatchImpl;
use advance_scheduler::trigger_source::TriggerFireEvent;
use advance_scheduler::types::{
    ComponentConfig, ComponentSubmitConfig, RunResult, RunStatus, WebhookConfig,
};
use advance_shared_types::capability::{CapParams, CapRequest, GrantDecision};
use advance_shared_types::component::ComponentType;
use advance_shared_types::traits::GrantCheck;

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-minimal.core.wasm");

// ─────────────────────────── test doubles ───────────────────────────

struct ReadyProbe(bool);
#[async_trait]
impl RuntimeReadiness for ReadyProbe {
    async fn is_ready(&self) -> bool {
        self.0
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

/// Recording factory used ONLY by the not-ready witness (T-RW-02): every
/// `build` bumps `built`, so a count of 0 after the walk proves the materializer
/// was never invoked (no spawn).
struct CountingFactory {
    built: Arc<AtomicUsize>,
}
#[async_trait]
impl RunnableHookFactory for CountingFactory {
    async fn build(
        &self,
        _binary: &[u8],
        _component_id: &str,
        _caps: &[CapRequest],
    ) -> Result<Arc<dyn RunnableHook>, HookError> {
        self.built.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(TrivialHook))
    }
}

struct TrivialHook;
#[async_trait]
impl RunnableHook for TrivialHook {
    async fn run_once(&self, _config: ComponentConfig) -> Result<RunResult, HookError> {
        Ok(RunResult {
            status: RunStatus::Completed,
            output: None,
        })
    }
}

struct AllowAll;
impl GrantCheck for AllowAll {
    fn check(&self, _: &str, _: &str, _: &str, _: &CapParams) -> GrantDecision {
        GrantDecision::Allow
    }
}

// ─────────────────────────── helpers ───────────────────────────

fn wasm_cfg() -> WasmConfig {
    WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    }
}

fn component_bytes() -> Vec<u8> {
    ComponentEncoder::default()
        .validate(true)
        .module(CORE_BYTES)
        .expect("core module wraps")
        .encode()
        .expect("component encoded")
}

/// The production factory (real runtime + injector over an empty host registry —
/// the minimal fixture needs no host fns).
fn prod_factory() -> Arc<dyn RunnableHookFactory> {
    let runtime = Arc::new(ComponentRuntime::new(&wasm_cfg()).expect("runtime"));
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    let grant: Arc<dyn GrantCheck> = Arc::new(AllowAll);
    let breaker: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let injector = Arc::new(CapabilityInjector::new(registry, grant, breaker));
    Arc::new(WasmRunnableHookFactory::new(runtime, injector))
}

async fn open_registry() -> (tempfile::TempDir, ComponentRegistry) {
    let dir = tempfile::TempDir::new().unwrap();
    let registry = ComponentRegistry::open_in(dir.path(), "reg.db")
        .await
        .expect("open registry");
    (dir, registry)
}

async fn seed(registry: &ComponentRegistry, id: &str, ct: ComponentType, binary: Vec<u8>) {
    let cfg = ComponentSubmitConfig {
        sensitive_params: Vec::new(),
        id: id.to_owned(),
        component_type: ct,
        binary,
        capabilities: Vec::new(),
        output_dir: None,
        trigger: None,
        restart_policy: None,
        delay: None,
        initial_grants: None,
        preset: None,
        retry: None,
    };
    registry
        .insert("agent:root", &cfg, None)
        .await
        .expect("insert");
}

// ─────────────────────────── tests ───────────────────────────

/// T-RW-01 — happy walk + non-Agent filter + per-row error isolation. A
/// real-bytes Task row materializes to `Ok`; a corrupt-bytes Task row to `Err`
/// (factory load failure); the Agent row is filtered (not spawned). The good
/// row is `Ok` DESPITE the bad row's `Err` → per-row isolation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ready_walk_filters_agents_and_isolates_per_row_errors() {
    let (_dir, registry) = open_registry().await;
    seed(
        &registry,
        "task-good",
        ComponentType::Task,
        component_bytes(),
    )
    .await;
    seed(
        &registry,
        "task-bad",
        ComponentType::Task,
        b"corrupt-not-wasm".to_vec(),
    )
    .await;
    seed(
        &registry,
        "agent-skip",
        ComponentType::Agent,
        component_bytes(),
    )
    .await;

    let handles = run_readiness_gated_walk(
        &registry,
        Arc::new(ReadyProbe(true)),
        prod_factory(),
        Arc::new(TriggerBusDispatchImpl::new()),
        Arc::new(NoopFileWatchSource),
        Arc::new(NoopWebhookSource),
        CancellationToken::new(),
    )
    .await
    .expect("ready walk returns Ok");

    assert_eq!(
        handles.len(),
        2,
        "Agent row must be filtered out (2 spawned)"
    );

    let mut good = None;
    let mut bad = None;
    for (id, handle) in handles {
        let outcome = handle.await.expect("spawned task did not panic");
        match id.as_str() {
            "task-good" => good = Some(outcome),
            "task-bad" => bad = Some(outcome),
            other => panic!("unexpected spawned row {other:?}"),
        }
    }

    assert!(
        matches!(good, Some(Ok(()))),
        "real-bytes Task ran through the production factory→hook→TaskRunner, got {good:?}"
    );
    assert!(
        matches!(bad, Some(Err(HookError::Failure(_)))),
        "corrupt-bytes Task fails closed (factory load failure), got {bad:?}"
    );
}

/// T-RW-02 — readiness fail-fast (AC-20) + NO-SPAWN witness. A not-ready probe
/// makes the walk return `Err(WalkError::NotReady)`; a recording factory's
/// build-counter stays 0 after a yield → the materializer was never invoked
/// (a wrong impl that spawned then returned NotReady would fail this).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn not_ready_walk_fail_fasts_without_spawning() {
    let (_dir, registry) = open_registry().await;
    seed(
        &registry,
        "task-good",
        ComponentType::Task,
        component_bytes(),
    )
    .await;
    seed(
        &registry,
        "task-two",
        ComponentType::Task,
        component_bytes(),
    )
    .await;

    let built = Arc::new(AtomicUsize::new(0));
    let factory: Arc<dyn RunnableHookFactory> = Arc::new(CountingFactory {
        built: Arc::clone(&built),
    });

    let result = run_readiness_gated_walk(
        &registry,
        Arc::new(ReadyProbe(false)),
        factory,
        Arc::new(TriggerBusDispatchImpl::new()),
        Arc::new(NoopFileWatchSource),
        Arc::new(NoopWebhookSource),
        CancellationToken::new(),
    )
    .await;

    assert!(
        matches!(result, Err(WalkError::NotReady(_))),
        "not-ready probe must fail-fast, got {result:?}"
    );
    // Give any erroneously-spawned task a chance to run before asserting.
    tokio::task::yield_now().await;
    assert_eq!(
        built.load(Ordering::SeqCst),
        0,
        "no materialize/build may happen when the readiness gate fail-fasts"
    );
}

/// CONTRACT-217 production discriminator: a row committed after the daemon walk starts is
/// discovered and run without a restart.  The counter is incremented only by factory.build, so a
/// registry-only implementation that leaves the component Pending cannot pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn continuous_walk_executes_rows_committed_after_boot() {
    let (_dir, registry) = open_registry().await;
    let registry = Arc::new(registry);
    let built = Arc::new(AtomicUsize::new(0));
    let factory: Arc<dyn RunnableHookFactory> = Arc::new(CountingFactory {
        built: Arc::clone(&built),
    });
    let breaker: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let walk = start_continuous_readiness_gated_walk_with_breaker_gate(
        Arc::clone(&registry),
        Arc::new(ReadyProbe(true)),
        factory,
        Arc::new(TriggerBusDispatchImpl::new()),
        Arc::new(NoopFileWatchSource),
        Arc::new(NoopWebhookSource),
        breaker,
    )
    .await
    .unwrap();
    assert_eq!(built.load(Ordering::SeqCst), 0);

    seed(
        &registry,
        "submitted-after-boot",
        ComponentType::Task,
        component_bytes(),
    )
    .await;
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while built.load(Ordering::SeqCst) != 1 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("post-boot submission executed");

    // Reconciliation is idempotent for the same durable row.
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    assert_eq!(built.load(Ordering::SeqCst), 1);
    walk.shutdown().await;
}

/// T-RW-03 — empty registry: a ready probe with no rows yields `Ok(vec![])`
/// (no spawn, no error).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ready_walk_on_empty_registry_spawns_nothing() {
    let (_dir, registry) = open_registry().await;

    let handles = run_readiness_gated_walk(
        &registry,
        Arc::new(ReadyProbe(true)),
        prod_factory(),
        Arc::new(TriggerBusDispatchImpl::new()),
        Arc::new(NoopFileWatchSource),
        Arc::new(NoopWebhookSource),
        CancellationToken::new(),
    )
    .await
    .expect("ready walk on empty registry returns Ok");

    assert!(handles.is_empty(), "empty registry → no spawned rows");
}

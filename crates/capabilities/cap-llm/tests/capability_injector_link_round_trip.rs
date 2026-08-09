//! MODULE-009 Slice D AC-17 T18 — full `CapabilityInjector` linker round-trip
//! integration test for the `agent-llm/{generate, stream, poll-stream}` host
//! function registry.
//!
//! Closes the §3.6 "AC-17 WASM-linker round-trip" deferred entry per the §3.6.3
//! "Resolved in Slice D" block.
//!
//! Pattern mirrors `crates/runtime/tests/capability_injector.rs` lines 1-160
//! (inline `MockGrantCheck` + `MockBreakerBus`) but anchored on `register_agent_llm(...)`
//! from cap-llm so the verification surface is the agent-llm spec specifically
//! (not the generic registry-injector pair).
//!
//! Two test cases:
//! - **Positive (`t18_agent_llm_capability_resolves_via_injector`)**: register
//!   agent-llm in an InMemoryHostRegistry → `injector.inject(&mut linker,
//!   &[CapRequest { capability: CapabilityId::from("llm") }])` returns `Ok(())`.
//! - **Negative (`t18_agent_llm_capability_unknown_when_unregistered`)**: empty
//!   registry → same inject call → `Err(HostError::UnknownCapability("llm"))`.
//!
//! The positive case verifies that `register_agent_llm` correctly hooks
//! `advance:runtime/agent-llm/{generate, stream, poll-stream}` under the `llm`
//! capability key, and that the `CapabilityInjector` resolves all three specs
//! into the Wasmtime component Linker without duplicate-instance errors
//! (HashMap-grouped namespace per `capability_injector.rs:223-234`).

use std::sync::Arc;

use advance_runtime::capability_injector::{CapabilityInjector, ComponentCtx, HostError};
use advance_runtime::circuit_breaker::{
    BreakerError, BreakerEvent, BreakerScope, CircuitBreaker, CircuitBreakerBus,
};
use advance_runtime::component_loader::ComponentRuntime;
use advance_runtime::config::WasmConfig;
use advance_runtime::config::{RuntimeConfig, RuntimeConfigProvider};
use advance_runtime::host_registry::{HostRegistry, InMemoryHostRegistry};
use advance_shared_types::capability::{
    BudgetDecision, CapParams, CapRequest, CapabilityId, GrantDecision,
};
use advance_shared_types::component::ComponentType;
use advance_shared_types::event::Event;
use advance_shared_types::repetition::{OutputHash, RepetitionDecision, ToolCallSignature};
use advance_shared_types::security_validator::{
    HttpCapability, HttpError, HttpRequest, HttpResponse, HttpSecurityChain, TransportErrorKind,
};
use advance_shared_types::traits::{EventBusEmit, GrantCheck, RepetitionGuardCheck, RunBudget};
use cap_llm::{register_agent_llm, LlmGateway};

// ─────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────

fn wasm_cfg() -> WasmConfig {
    WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    }
}

struct MockGrantCheck;
impl GrantCheck for MockGrantCheck {
    fn check(
        &self,
        _agent_id: &str,
        _capability: &str,
        _function: &str,
        _params: &CapParams,
    ) -> GrantDecision {
        GrantDecision::Allow
    }
}

struct MockBreakerBus;
impl CircuitBreakerBus for MockBreakerBus {
    fn is_open_capability(&self, _cap: &str) -> Option<String> {
        None
    }
    fn is_open_component_type(&self, _kind: ComponentType) -> Option<String> {
        None
    }
    fn is_open_agent(&self, _agent_id: &str) -> Option<String> {
        None
    }
    fn open(&self, _b: CircuitBreaker) -> Result<(), BreakerError> {
        Ok(())
    }
    fn close(&self, _scope: BreakerScope, _target: &str) -> Result<(), BreakerError> {
        Ok(())
    }
    fn half_open(&self, _scope: BreakerScope, _target: &str) -> Result<(), BreakerError> {
        Ok(())
    }
    fn subscribe(&self) -> tokio::sync::mpsc::UnboundedReceiver<BreakerEvent> {
        let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
        rx
    }
}

struct StubChain;
#[async_trait::async_trait]
impl HttpSecurityChain for StubChain {
    async fn execute(
        &self,
        _agent_id: &str,
        _request: HttpRequest,
        _cap: &HttpCapability,
    ) -> Result<HttpResponse, HttpError> {
        Err(HttpError::Transport(TransportErrorKind::Other))
    }
}

struct StubBudget;
impl RunBudget for StubBudget {
    fn check(&self, _run_id: &str, _tokens: u64, _cost: f64) -> BudgetDecision {
        BudgetDecision::Allow
    }
    fn commit(&self, _run_id: &str, _tokens: u64, _cost: f64) {}
}

struct StubBus;
impl EventBusEmit for StubBus {
    fn emit(&self, _event: Event) {}
}

struct StubRepGuard;
impl RepetitionGuardCheck for StubRepGuard {
    fn record_tool_call(&self, _agent_id: &str, _sig: ToolCallSignature) -> RepetitionDecision {
        RepetitionDecision::Pass
    }
    fn record_output(&self, _agent_id: &str, _hash: OutputHash) -> RepetitionDecision {
        RepetitionDecision::Pass
    }
}

struct InlineConfigProvider(RuntimeConfig);
impl RuntimeConfigProvider for InlineConfigProvider {
    fn current(&self) -> Arc<RuntimeConfig> {
        Arc::new(self.0.clone())
    }
    fn subscribe(&self) -> tokio::sync::mpsc::Receiver<Arc<RuntimeConfig>> {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        rx
    }
    fn last_error(&self) -> Option<String> {
        None
    }
}

const FIXTURE_CFG_YAML: &str = r#"
wasm:
  max_memory_pages: 256
  epoch_interruption_ms: 100
  fuel_enabled: false
llm-providers:
  - id: openai
    endpoint: https://api.openai.com
    api-key-secret: openai-api-key
    model-aliases:
      gpt4o: gpt-4o-2024-08-06
    cost-per-mtoken-in: 2.50
    cost-per-mtoken-out: 10.00
cron:
  max_jitter_ratio: 0.1
git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10
circuit-breakers: []
secrets:
  master-key-source: keychain
  env-var-name: SECRETS_MASTER_KEY
users: []
post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600
"#;

fn make_test_gateway() -> Arc<LlmGateway> {
    let cfg: RuntimeConfig = serde_yml::from_str(FIXTURE_CFG_YAML).expect("fixture cfg parses");
    let cfg_provider: Arc<dyn RuntimeConfigProvider> = Arc::new(InlineConfigProvider(cfg));
    let chain: Arc<dyn HttpSecurityChain> = Arc::new(StubChain);
    let budget: Arc<dyn RunBudget> = Arc::new(StubBudget);
    let bus: Arc<dyn EventBusEmit> = Arc::new(StubBus);
    let rep: Arc<dyn RepetitionGuardCheck> = Arc::new(StubRepGuard);
    Arc::new(LlmGateway::new(
        cfg_provider,
        chain,
        budget,
        bus,
        rep,
        "test-agent".into(),
    ))
}

fn build_injector(registry: Arc<dyn HostRegistry>) -> CapabilityInjector {
    CapabilityInjector::new(registry, Arc::new(MockGrantCheck), Arc::new(MockBreakerBus))
}

fn new_linker(runtime: &ComponentRuntime) -> wasmtime::component::Linker<ComponentCtx> {
    wasmtime::component::Linker::new(runtime.host_engine_handle().engine())
}

// ─────────────────────────────────────────────────────────────────────────
// AC-17 T18 — Slice D linker round-trip
// ─────────────────────────────────────────────────────────────────────────

/// Positive case: agent-llm IS registered → `inject` for capability `llm` returns Ok.
#[test]
fn t18_agent_llm_capability_resolves_via_injector() {
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    register_agent_llm(&*registry, make_test_gateway());
    // Verify registry has the 3 specs (T18a precondition).
    let specs = registry.lookup("llm");
    assert_eq!(specs.len(), 3, "expected 3 agent-llm specs registered");

    let injector = build_injector(Arc::clone(&registry));
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let mut linker = new_linker(&runtime);

    let caps = vec![CapRequest {
        capability: CapabilityId::from("llm"),
    }];
    let result = injector.inject(&mut linker, &caps);
    assert!(
        result.is_ok(),
        "inject must succeed when agent-llm is registered, got {result:?}"
    );
}

/// Negative case: empty registry → `inject` for capability `llm` returns
/// `Err(HostError::UnknownCapability("llm"))`. Verifies AC-17's "only components
/// declaring `llm` capability receive the host function" — the converse: a
/// component declaring `llm` without registry support cannot link.
#[test]
fn t18_agent_llm_capability_unknown_when_unregistered() {
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    // INTENTIONALLY do NOT call register_agent_llm.
    let injector = build_injector(Arc::clone(&registry));
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let mut linker = new_linker(&runtime);

    let caps = vec![CapRequest {
        capability: CapabilityId::from("llm"),
    }];
    let result = injector.inject(&mut linker, &caps);
    match result {
        Err(HostError::UnknownCapability(c)) => assert_eq!(c, "llm"),
        other => panic!("expected UnknownCapability(\"llm\"), got {other:?}"),
    }
}

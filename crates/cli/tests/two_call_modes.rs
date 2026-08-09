//! Slice m001-slice-bootstrap (2026-05-28) — MODULE-001-AC-17 closure.
//!
//! AC-17 §1.5 criterion: "Host functions support two call modes (PRD §4.5):
//! direct call inside `handle-message` (caller waits) for Agent + direct
//! call inside `run()` for Runnable; Agent additionally supports
//! return-action fire-and-forget mode dispatched after `handle-message`
//! returns."
//!
//! Three sub-tests against the guest-rust-with-caps fixture loaded through
//! the new `instantiate_advance_host_with_capabilities_async` method:
//! - T57a Agent direct-call: handle-message calls `heartbeat`, waits, returns.
//! - T57b Runnable direct-call: run() calls `heartbeat`, waits, returns.
//! - T57c Agent return-action: handle-message returns `ActionResult` with
//!   actions; test driver invokes `AgentActionDispatcherImpl.dispatch`
//!   post-return (gate-only call-MODE witness; full action delivery is the
//!   deferred AC-19 feature per MODULE-001 §3.6 AC-17 sub-scope entry).

use std::num::NonZeroUsize;
use std::sync::Arc;

use advance_messaging::{
    AgentActionDispatcherImpl, MailboxDispatcher, MailboxDispatcherImpl, MailboxStore,
    RejectionSink,
};
use advance_reply_tracker::manager::ManagerOptions;
use advance_reply_tracker::{register_reply_tracker_host_fns, AwaitSessionManagerImpl};
use advance_runtime::capability_injector::{CapabilityInjector, ComponentCtx};
use advance_runtime::circuit_breaker::{CircuitBreakerBus, DefaultCircuitBreakerBus};
use advance_runtime::config::WasmConfig;
use advance_runtime::host_registry::{HostRegistry, InMemoryHostRegistry};
use advance_runtime::wit_bindings::with_caps::advance::runtime::types as wit_types;
use advance_runtime::ComponentRuntime;
use advance_shared_types::agent_tree::{AgentKind, AgentTreeReader, Capability};
use advance_shared_types::capability::{CapParams, CapRequest, CapabilityId, GrantDecision};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{AgentAction, AgentActionDispatcher, DispatchError};
use advance_shared_types::security_validator::{ActionValidator, SecurityError};
use advance_shared_types::traits::{EventBusEmit, GrantCheck};
use wit_component::ComponentEncoder;

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-with-caps.core.wasm");
const STATE_HEARTBEAT_OK: [u8; 4] = [0xAC, 0x17, 0xBE, 0xAF];
const ACTION_PAYLOAD: [u8; 3] = [0xAC, 0x17, 0x01];

// ---------- Test stubs ----------

struct AllowAll;
impl GrantCheck for AllowAll {
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

struct NoopEventBus;
impl EventBusEmit for NoopEventBus {
    fn emit(&self, _event: Event) {}
}

#[derive(Clone)]
struct FlatTree;
impl AgentTreeReader for FlatTree {
    fn parent_of(&self, _: &str) -> Option<String> {
        None
    }
    fn children_of(&self, _: &str) -> Vec<String> {
        vec![]
    }
    fn siblings_of(&self, _: &str) -> Vec<String> {
        vec![]
    }
    fn agent_exists(&self, _: &str) -> bool {
        true
    }
    fn agent_kind(&self, _: &str) -> Option<AgentKind> {
        Some(AgentKind::Root)
    }
    fn capabilities(&self, _: &str) -> Vec<Capability> {
        vec![]
    }
}

struct AllowAllValidator;
impl ActionValidator for AllowAllValidator {
    fn validate(&self, _agent_id: &str, _actions: &[AgentAction]) -> Result<(), SecurityError> {
        Ok(())
    }
}

struct NoopSink;
impl RejectionSink for NoopSink {
    fn record_rejection(&self, _agent_id: &str, _err: &SecurityError) {}
}

fn wasm_cfg() -> WasmConfig {
    WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    }
}

fn ctx() -> ComponentCtx {
    ComponentCtx::new("agent:test".into(), "trace-test".into(), Vec::new())
}

fn component_bytes() -> Vec<u8> {
    ComponentEncoder::default()
        .validate(true)
        .module(CORE_BYTES)
        .expect("core module wraps")
        .encode()
        .expect("component encoded")
}

fn build_injector_and_registry() -> (Arc<dyn HostRegistry>, CapabilityInjector) {
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    let mailbox_store = Arc::new(MailboxStore::new(NonZeroUsize::new(64).unwrap()));
    let tree: Arc<dyn AgentTreeReader> = Arc::new(FlatTree);
    let dispatcher: Arc<dyn MailboxDispatcher> =
        Arc::new(MailboxDispatcherImpl::new(mailbox_store, tree));
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));
    let event_bus: Arc<dyn EventBusEmit> = Arc::new(NoopEventBus);
    register_reply_tracker_host_fns(&*registry, manager, event_bus);

    let grant: Arc<dyn GrantCheck> = Arc::new(AllowAll);
    let breaker: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let injector = CapabilityInjector::new(registry.clone(), grant, breaker);
    (registry, injector)
}

fn caps_messaging() -> Vec<CapRequest> {
    vec![CapRequest {
        capability: CapabilityId::from("messaging"),
    }]
}

/// T57a — AC-17 Agent direct-call witness: handle-message calls heartbeat
/// from within the WASM fiber and waits for the result.
#[tokio::test]
async fn module_001_t57a_agent_direct_call_heartbeat() {
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let (_registry, injector) = build_injector_and_registry();
    let loaded = runtime
        .load_component(&component_bytes())
        .expect("component loads");
    let (bindings, mut store) = runtime
        .instantiate_advance_host_with_capabilities_async(
            &loaded,
            ctx(),
            &caps_messaging(),
            &injector,
        )
        .await
        .expect("instantiate");

    // init returns the config_data as state so handle-message can route.
    let cfg = wit_types::ComponentConfig {
        id: "test".into(),
        config_data: Some(b"heartbeat".to_vec()),
        trigger_context: None,
    };
    let init_state = bindings
        .advance_runtime_message_driven()
        .call_init(&mut store, &cfg)
        .await
        .expect("init call")
        .expect("init returned Ok");
    assert_eq!(init_state, b"heartbeat", "init echoed config_data");

    let msg = wit_types::Message { payload: vec![] };
    let result = bindings
        .advance_runtime_message_driven()
        .call_handle_message(&mut store, &msg, &init_state)
        .await
        .expect("handle-message call")
        .expect("handle-message Ok");
    assert_eq!(
        result.new_state, STATE_HEARTBEAT_OK,
        "Agent direct-call: heartbeat host fn returned Ok → guest returned STATE_HEARTBEAT_OK"
    );
    assert!(
        result.actions.is_empty(),
        "Agent direct-call test does not assert actions; expected empty"
    );
}

/// T57b — AC-17 Runnable direct-call witness: run() calls heartbeat from
/// within the WASM fiber and waits for the result.
#[tokio::test]
async fn module_001_t57b_runnable_direct_call_heartbeat() {
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let (_registry, injector) = build_injector_and_registry();
    let loaded = runtime
        .load_component(&component_bytes())
        .expect("component loads");
    let (bindings, mut store) = runtime
        .instantiate_advance_host_with_capabilities_async(
            &loaded,
            ctx(),
            &caps_messaging(),
            &injector,
        )
        .await
        .expect("instantiate");

    let cfg = wit_types::ComponentConfig {
        id: "test-runnable".into(),
        config_data: Some(b"heartbeat".to_vec()),
        trigger_context: None,
    };
    let result = bindings
        .advance_runtime_runnable()
        .call_run(&mut store, &cfg)
        .await
        .expect("run call")
        .expect("run returned Ok");
    let output = result.output.expect("run output present");
    assert_eq!(
        output, STATE_HEARTBEAT_OK,
        "Runnable direct-call: heartbeat host fn returned Ok → guest returned STATE_HEARTBEAT_OK"
    );
}

/// T57c — AC-17 Agent return-action witness: handle-message returns
/// `ActionResult { actions }`; test driver invokes
/// `AgentActionDispatcherImpl.dispatch` post-return. This witnesses the
/// CALL-MODE dimension of return-action fire-and-forget. The dispatcher
/// is gate-only today; full action delivery is the deferred AC-19 feature.
#[tokio::test]
async fn module_001_t57c_agent_return_action_fire_and_forget() {
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let (_registry, injector) = build_injector_and_registry();
    let loaded = runtime
        .load_component(&component_bytes())
        .expect("component loads");
    let (bindings, mut store) = runtime
        .instantiate_advance_host_with_capabilities_async(
            &loaded,
            ctx(),
            &caps_messaging(),
            &injector,
        )
        .await
        .expect("instantiate");

    let cfg = wit_types::ComponentConfig {
        id: "test-return-action".into(),
        config_data: Some(b"return-action".to_vec()),
        trigger_context: None,
    };
    let init_state = bindings
        .advance_runtime_message_driven()
        .call_init(&mut store, &cfg)
        .await
        .expect("init call")
        .expect("init Ok");
    let msg = wit_types::Message { payload: vec![] };
    let result = bindings
        .advance_runtime_message_driven()
        .call_handle_message(&mut store, &msg, &init_state)
        .await
        .expect("handle-message call")
        .expect("handle-message Ok");

    // Witness 1: the guest returned exactly one action.
    assert_eq!(result.actions.len(), 1, "expected one return action");
    assert_eq!(
        result.actions[0].payload, ACTION_PAYLOAD,
        "action payload sentinel mismatch"
    );

    // Witness 2: the test driver invokes the dispatcher post-return — the
    // gate-only validation IS the dispatch under the call-MODE dimension.
    let rust_actions: Vec<AgentAction> = result
        .actions
        .iter()
        .map(|a| AgentAction {
            payload: a.payload.clone(),
        })
        .collect();
    let validator: Arc<dyn ActionValidator> = Arc::new(AllowAllValidator);
    let sink: Arc<dyn RejectionSink> = Arc::new(NoopSink);
    let dispatcher = AgentActionDispatcherImpl::new(validator, sink);
    // Step-3 seam: dispatch carries the source Message (origin None → gate-only).
    let src = advance_shared_types::mailbox::Message {
        id: "m".into(),
        kind: advance_shared_types::mailbox::MessageKind::User,
        from: "user:test".into(),
        to: "agent:test".into(),
        payload: Vec::new(),
        context: None,
        timestamp: std::time::SystemTime::now(),
        origin: None,
    };
    let dispatch_result: Result<advance_shared_types::outbound::DeliveryReport, DispatchError> =
        dispatcher.dispatch("agent:test", &src, &rust_actions).await;
    assert!(
        dispatch_result.is_ok(),
        "gate-only AgentActionDispatcher should accept the validated batch: {:?}",
        dispatch_result
    );
}

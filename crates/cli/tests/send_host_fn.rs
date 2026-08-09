//! await-leg B-3 (2026-06-22) — the WASM `send` host-fn instantiate+invoke+route
//! witness.
//!
//! Proves (against the dedicated `guest-rust-send` fixture, which IMPORTS + CALLS
//! the agent-messaging `send`):
//!   1. **Instantiate**: with `send` (+ `await-replies`/`heartbeat`) registered,
//!      a guest that imports `send` instantiates through the production
//!      `CapabilityInjector` WITHOUT `LinkerTypecheck` failure — closing the
//!      `crates/messaging/reply-tracker/src/host_fn.rs:769-778` gap.
//!   2. **Invoke + route**: driving the guest's real `agent_messaging::send`
//!      through the typed injector path (`register_typed_send`) reaches
//!      `AwaitSessionManagerImpl::on_reply` and resolves a parked parent's await
//!      with the sent payload — the PRODUCT ingress, not a harness `on_reply`.
//!
//! Build-lane witness: proves the `send`→`on_reply` MECHANISM; flips ZERO
//! acceptance criteria (a regression guard, not an AC/SYS-AC witness). As of
//! await-leg B-4a (2026-06-22) `"messaging"` IS in `KNOWN_CAPABILITIES` (so a
//! messaging-declaring guest links the interface), but shipped agents stay dormant
//! and this test builds its caps manually (`vec![messaging]`) — independent of
//! `KNOWN_CAPABILITIES`. Mirrors `fiber_suspend_resume.rs`'s instantiate harness; the
//! shared `guest-rust-with-caps` fixture is deliberately NOT used (it is send-free).

use std::sync::Arc;
use std::time::Duration;

use advance_messaging::MailboxDispatcher;
use advance_reply_tracker::manager::ManagerOptions;
use advance_reply_tracker::{
    register_reply_tracker_host_fns, register_send_host_fn, AwaitSessionManagerImpl,
};
use advance_runtime::capability_injector::{CapabilityInjector, ComponentCtx};
use advance_runtime::circuit_breaker::{CircuitBreakerBus, DefaultCircuitBreakerBus};
use advance_runtime::config::WasmConfig;
use advance_runtime::host_registry::{HostRegistry, InMemoryHostRegistry};
use advance_runtime::wit_bindings::with_caps::advance::runtime::types as wit_types;
use advance_runtime::ComponentRuntime;
use advance_shared_types::await_session::{
    AgentAwaitRequest, AwaitMode, AwaitOptions, AwaitRequest, AwaitResult, AwaitSessionStatus,
    OrchestrationError, ReplyStatus, TimeoutPolicy,
};
use advance_shared_types::capability::{CapParams, CapRequest, CapabilityId, GrantDecision};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{Message, MessageContext, MsgError, NotifyError};
use advance_shared_types::traits::{EventBusEmit, GrantCheck};
use wit_component::ComponentEncoder;

const CORE_BYTES: &[u8] = include_bytes!("../../runtime/tests/fixtures/guest-rust-send.core.wasm");

// Must match the guest fixture (`guest-rust-send/src/lib.rs`).
const SEND_PAYLOAD: [u8; 4] = [0x5E, 0x4D, 0xB3, 0x01];
const STATE_SEND_OK: [u8; 4] = [0x5E, 0x4D, 0x0C, 0x01];

// ---------- Test stubs (mirror fiber_suspend_resume.rs) ----------

struct AllowAll;
impl GrantCheck for AllowAll {
    fn check(&self, _: &str, _: &str, _: &str, _: &CapParams) -> GrantDecision {
        GrantDecision::Allow
    }
}

struct NoopEventBus;
impl EventBusEmit for NoopEventBus {
    fn emit(&self, _event: Event) {}
}

/// Mock dispatcher returning Ok for every dispatch so the seeded parent session
/// stays Open awaiting the reply (rather than transitioning to FailedDispatch).
struct MockDispatcher;
#[async_trait::async_trait]
impl MailboxDispatcher for MockDispatcher {
    async fn deliver(&self, _target: &str, _msg: Message) -> Result<(), MsgError> {
        Ok(())
    }
    async fn reply(&self, _f: &str, _i: &str, _p: Vec<u8>) -> Result<(), MsgError> {
        Ok(())
    }
    async fn notify_agent(
        &self,
        _f: &str,
        _t: &str,
        _p: Vec<u8>,
        _c: Option<MessageContext>,
    ) -> Result<(), NotifyError> {
        Ok(())
    }
}

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
        .expect("core wraps")
        .encode()
        .expect("component encoded")
}

fn allof_options() -> AwaitOptions {
    AwaitOptions {
        mode: AwaitMode::AllOf,
        idle_timeout_secs: Some(60),
        on_idle_timeout: TimeoutPolicy::ReturnPartial,
        keep_losers: false,
    }
}

/// T-B3-instantiate: a guest importing+calling `send` instantiates without a
/// LinkerTypecheck failure (the `send` handler is now registered + typed-wired),
/// invokes `send` through the real CapabilityInjector, and the payload reaches
/// the parked parent's `on_reply`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b3_send_host_fn_instantiate_invoke_route() {
    // 1. Build the shared manager (Mock dispatcher → seeded session stays Open).
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    let dispatcher: Arc<dyn MailboxDispatcher> = Arc::new(MockDispatcher);
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));
    let event_bus: Arc<dyn EventBusEmit> = Arc::new(NoopEventBus);

    // Register all three agent-messaging host fns the guest imports. `send` is
    // the B-3 addition; without it, instantiate of a send-importing guest would
    // fail `LinkerTypecheck`.
    register_send_host_fn(&*registry, Arc::clone(&manager));
    register_reply_tracker_host_fns(&*registry, Arc::clone(&manager), event_bus);

    let grant: Arc<dyn GrantCheck> = Arc::new(AllowAll);
    let breaker: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let injector = CapabilityInjector::new(registry, grant, breaker);
    let caps = vec![CapRequest {
        capability: CapabilityId::from("messaging"),
    }];

    // 2. Seed a parent await session expecting `agent:child` BEFORE driving the
    //    guest, so the guest's `send(target="agent:parent")` (ctx.agent_id="child")
    //    routes to `on_reply`.
    let m = Arc::clone(&manager);
    let parent = tokio::spawn(async move {
        m.start_with_run(
            "parent",
            None,
            vec![AwaitRequest::AgentRequest(AgentAwaitRequest {
                target: "agent:child".to_string(),
                payload: vec![],
                correlation_id: "corr-b3".to_string(),
                context: None,
            })],
            allof_options(),
        )
        .await
    });
    // Wait for the parent session to register.
    let mut parked = false;
    for _ in 0..200 {
        if manager.session_count_for_test().await >= 1 {
            parked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(parked, "parent await session did not register");

    // 3. Build runtime + instantiate the send-importing guest as `child`.
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let loaded = runtime
        .load_component(&component_bytes())
        .expect("component loads");
    let ctx = ComponentCtx::new("child".into(), "trace-b3".into(), Vec::new());
    let (bindings, mut store) = runtime
        .instantiate_advance_host_with_capabilities_async(&loaded, ctx, &caps, &injector)
        .await
        .expect("instantiate — a send-importing guest must link without LinkerTypecheck");

    // 4. init with config_data=b"send" → routes handle-message to the send branch.
    let cfg = wit_types::ComponentConfig {
        id: "test-b3-send".into(),
        config_data: Some(b"send".to_vec()),
        trigger_context: None,
    };
    let init_state = bindings
        .advance_runtime_message_driven()
        .call_init(&mut store, &cfg)
        .await
        .expect("init call")
        .expect("init Ok");
    assert_eq!(init_state, b"send");

    // 5. handle-message → guest calls `agent_messaging::send("agent:parent", ...)`
    //    through the typed injector path → SendHandler → handle_send → on_reply.
    let msg = wit_types::Message { payload: vec![] };
    let action_result = tokio::time::timeout(
        Duration::from_secs(30),
        bindings
            .advance_runtime_message_driven()
            .call_handle_message(&mut store, &msg, &init_state),
    )
    .await
    .expect("watchdog: handle-message should complete within 30s")
    .expect("handle-message host call")
    .expect("handle-message Ok (send returned Ok)");
    assert_eq!(
        action_result.new_state, STATE_SEND_OK,
        "guest returned the send witness state → send host fn ran + returned Ok"
    );

    // 6. The parked parent resolved with the routed payload — the bytes flowed
    //    from the guest's `send` through the product ingress into `on_reply`.
    let result: Result<AwaitResult, OrchestrationError> =
        tokio::time::timeout(Duration::from_secs(5), parent)
            .await
            .expect("parent await did not resolve within 5s")
            .expect("parent task panicked");
    let await_result = result.expect("await should resolve Ok (reply routed)");
    assert_eq!(await_result.status, AwaitSessionStatus::Completed);
    assert_eq!(await_result.replies.len(), 1);
    assert_eq!(await_result.replies[0].source, "agent:child");
    assert_eq!(await_result.replies[0].payload, SEND_PAYLOAD);
    assert!(matches!(
        await_result.replies[0].status,
        ReplyStatus::Completed
    ));
}

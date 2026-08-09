//! WS-B (2026-06-04) — the FIRST guest-driven LLM turn.
//!
//! Unlike `mode_llm_smoke.rs` (which drives the gateway DIRECTLY and loads the fs-only j01
//! skeleton purely to satisfy `.build()`), this witness drives the WHOLE guest→host path:
//! a real wit-bindgen guest (`guest-rust-hello-llm`) importing `advance:runtime/agent-llm@0.1.0`
//! is wrapped to a Component via the SAME encoder the production `build-agent` tool ships
//! (`build_agent::encode_core_to_component`), loaded via `ComponentRuntime::load_component`,
//! instantiated through `instantiate_advance_host_with_capabilities_async` + `CapabilityInjector`
//! with `CapRequest{llm}`, and driven one turn. The guest calls `agent-llm/generate`, the
//! call round-trips through the real cap-llm gateway to the harness loopback backend, and the
//! scripted reply comes back as the payload of an `ActionResult` action.
//!
//! This closes the full-guest-instantiation portion of MODULE-009-AC-17 that §3.6.3 left as a
//! future M001-coordinated hardening (added witness depth — AC-17 is already `passed`; no flip).
//! Loopback-only: NO real billed LLM call. The live `advance start` turn (SYS-AC-188/189) stays
//! deferred to Track H round-2.

use std::sync::Arc;

use advance_runtime::capability_injector::CapabilityInjector;
use advance_runtime::circuit_breaker::DefaultCircuitBreakerBus;
use advance_runtime::config::WasmConfig;
use advance_runtime::host_registry::{HostRegistry, InMemoryHostRegistry};
use advance_runtime::wit_bindings::with_caps::advance::runtime::types as wit_types;
use advance_runtime::{ComponentCtx, ComponentRuntime};

use advance_shared_types::capability::{CapParams, CapRequest, CapabilityId, GrantDecision};
use advance_shared_types::event::Event;
use advance_shared_types::traits::{EventBusEmit, GrantCheck};

use cap_llm::register_agent_llm;
use system_acceptance::llm_loopback::{LoopbackLlm, ScriptedResponse};

/// No-op event sink (the loopback gateway needs an `Arc<dyn EventBusEmit>`; this turn does
/// not assert on `llm.*` events — `mode_llm_scripted_smoke.rs` covers the event surface).
struct NullBus;
impl EventBusEmit for NullBus {
    fn emit(&self, _event: Event) {}
}

/// Always-allow grant gate (`CapabilityInjector::new` requires a `GrantCheck`; the harness's
/// own `AllowAll` is private and runtime's `AllowAllGrantCheck` is not re-exported).
struct AllowAllGrant;
impl GrantCheck for AllowAllGrant {
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

/// The committed reference-guest core module (a real wit-bindgen guest importing agent-llm).
const HELLO_LLM_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-hello-llm.core.wasm");

const SCRIPTED_REPLY: &str = "scripted-reply-from-loopback";

#[tokio::test(flavor = "multi_thread")]
async fn hello_llm_guest_calls_generate_and_returns_reply_as_action() {
    // 1. Boot the loopback LLM (real cap-llm gateway + cap-http chain → in-process axum mock,
    //    reached via the DNS-override seam). Scripts exactly one OK chat completion.
    let loopback = LoopbackLlm::start(
        vec![ScriptedResponse::ok_chat(SCRIPTED_REPLY, 7, 9)],
        None,
        None,
        Arc::new(NullBus),
        "agent:hello".to_string(),
    )
    .await;

    // 2. Register agent-llm on a host registry against the loopback gateway.
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    register_agent_llm(&*registry, loopback.gateway.clone());

    // 3. The production injector (grant gate + circuit breaker) — both pass-through here.
    let injector = CapabilityInjector::new(
        registry,
        Arc::new(AllowAllGrant),
        Arc::new(DefaultCircuitBreakerBus::new()),
    );

    // 4. Encode the guest core module → Component via the SAME fn `build-agent` ships, then
    //    load it (proves the production encoder's output is `load_component`-acceptable).
    let component = build_agent::encode_core_to_component(HELLO_LLM_CORE)
        .expect("build-agent encodes the hello-llm core into a component");
    let runtime = ComponentRuntime::new(&WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    })
    .expect("construct runtime");
    let loaded = runtime
        .load_component(&component)
        .expect("load_component accepts the build-agent-encoded component");

    // 5. Instantiate through the injector with the `llm` capability so the guest's agent-llm
    //    import resolves over the real WASM linker (the CapabilityInjector + linker round-trip).
    let caps = vec![CapRequest {
        capability: CapabilityId::from("llm"),
    }];
    let ctx = ComponentCtx::new(
        "agent:hello".to_string(),
        "trace-ws-b".to_string(),
        Vec::new(),
    );
    let (bindings, mut store) = runtime
        .instantiate_advance_host_with_capabilities_async(&loaded, ctx, &caps, &injector)
        .await
        .expect("instantiate the llm-capable guest");

    // 6. init, then drive ONE turn: the guest reads the payload as the prompt and calls generate.
    let state = bindings
        .advance_runtime_message_driven()
        .call_init(
            &mut store,
            &wit_types::ComponentConfig {
                id: "agent:hello".to_string(),
                config_data: None,
                trigger_context: None,
            },
        )
        .await
        .expect("call_init does not trap")
        .expect("init returns Ok");

    let msg = wit_types::Message {
        payload: b"summarize the WS-B reference guest turn".to_vec(),
    };
    let action_result = bindings
        .advance_runtime_message_driven()
        .call_handle_message(&mut store, &msg, &state)
        .await
        .expect("call_handle_message does not trap")
        .expect("handle_message returns Ok (the guest's generate call succeeded)");

    // 7a. The guest returned the LLM reply as a single action payload.
    assert_eq!(
        action_result.actions.len(),
        1,
        "expected exactly one action carrying the LLM reply"
    );
    assert_eq!(
        action_result.actions[0].payload,
        SCRIPTED_REPLY.as_bytes(),
        "the action payload must carry the scripted loopback reply verbatim"
    );

    // 7b. The guest's generate call actually dialed the loopback exactly once (proves the
    //     guest→injector→gateway→loopback path ran — not a direct gateway call).
    assert_eq!(
        loopback.chat_request_count(),
        1,
        "the guest's agent-llm/generate must reach the loopback exactly once"
    );
}

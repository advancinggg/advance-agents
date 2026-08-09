//! Phase-2 reply-delivery slice (slice B) — the hello-llm guest's LLM reply made
//! observable through the PRODUCTION reply seam.
//!
//! Builds on `mode_llm_guest_turn.rs` (real `guest-rust-hello-llm` over the real
//! cap-llm gateway → in-process loopback backend), but instead of calling
//! `handle_message` directly it drives the turn through the REAL
//! `advance_cli::agent_loop::build_agent_loop` + `WasmMessageHandler` +
//! `run_agent`, with the production `ReplyRouterSink`/`ReplyRegistry` wired as the
//! outbound sink. Asserts the guest's LLM reply lands in the reply registry — the
//! end-to-end witness that the seam delivers a REAL guest reply. Mocks ONLY the
//! external LLM provider (the loopback). NO real billed call.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::SystemTime;

use advance_runtime::capability_injector::CapabilityInjector;
use advance_runtime::circuit_breaker::DefaultCircuitBreakerBus;
use advance_runtime::config::WasmConfig;
use advance_runtime::host_registry::{HostRegistry, InMemoryHostRegistry};
use advance_runtime::ComponentRuntime;

use advance_shared_types::capability::{CapParams, CapRequest, CapabilityId, GrantDecision};
use advance_shared_types::event::Event;
use advance_shared_types::traits::{EventBusEmit, GrantCheck};

use advance_cli::agent_loop::{build_agent_loop, WasmMessageHandler};
use advance_cli::reply::{ReplyRegistry, ReplyRouterSink};

use advance_messaging::{MailboxStore, Message, MessageKind, OutboundActionSink};
use advance_scheduler::hook::MessageHandler;
use advance_scheduler::types::{ComponentConfig, ComponentId, WasmInstance};
use advance_scheduler::AgentLoopDriver;

use cap_llm::register_agent_llm;
use system_acceptance::llm_loopback::{LoopbackLlm, ScriptedResponse};

/// No-op event sink (the loopback gateway + build_agent_loop need an
/// `Arc<dyn EventBusEmit>`; this turn does not assert on events).
struct NullBus;
impl EventBusEmit for NullBus {
    fn emit(&self, _event: Event) {}
}

/// Always-allow grant gate (the loopback turn is not testing authz).
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

const HELLO_LLM_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-hello-llm.core.wasm");

const SCRIPTED_REPLY: &str = "scripted-reply-through-the-reply-seam";

#[tokio::test(flavor = "multi_thread")]
async fn hello_llm_reply_flows_through_outbound_to_reply_registry() {
    let agent = "agent:hello";

    // 1. Loopback LLM (real cap-llm gateway + cap-http chain → in-process mock).
    let loopback = LoopbackLlm::start(
        vec![ScriptedResponse::ok_chat(SCRIPTED_REPLY, 7, 9)],
        None,
        None,
        Arc::new(NullBus),
        agent.to_string(),
    )
    .await;

    // 2. Register agent-llm against the loopback gateway + build the injector.
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    register_agent_llm(&*registry, loopback.gateway.clone());
    let injector = Arc::new(CapabilityInjector::new(
        registry,
        Arc::new(AllowAllGrant),
        Arc::new(DefaultCircuitBreakerBus::new()),
    ));

    // 3. Encode + load the real hello-llm guest; build the production WASM handler.
    let component = build_agent::encode_core_to_component(HELLO_LLM_CORE)
        .expect("build-agent encodes the hello-llm core");
    let runtime = Arc::new(
        ComponentRuntime::new(&WasmConfig {
            max_memory_pages: 256,
            epoch_interruption_ms: 100,
            fuel_enabled: false,
        })
        .expect("runtime"),
    );
    let loaded = runtime.load_component(&component).expect("load_component");
    let caps = vec![CapRequest {
        capability: CapabilityId::from("llm"),
    }];
    let handler: Arc<dyn MessageHandler> = Arc::new(WasmMessageHandler::new(
        runtime,
        loaded,
        injector,
        caps,
        agent.to_string(),
        "trace-reply-seam".to_string(),
    ));

    // 4. Wire the REAL build_agent_loop with the production ReplyRouterSink.
    let store = Arc::new(MailboxStore::new(NonZeroUsize::new(8).unwrap()));
    let reply_registry = Arc::new(ReplyRegistry::new());
    let outbound: Arc<dyn OutboundActionSink> =
        Arc::new(ReplyRouterSink::new(reply_registry.clone()));
    let bus: Arc<dyn EventBusEmit> = Arc::new(NullBus);
    let driver = build_agent_loop(store.clone(), handler, bus, Some(outbound));

    // 5. Register the reply slot, deliver an inbound prompt, drive one turn.
    let rx = reply_registry.register(agent);
    store
        .get_or_create(agent)
        .expect("mailbox")
        .deliver(Message {
            id: "m1".to_string(),
            kind: MessageKind::User,
            from: "user:test".to_string(),
            to: agent.to_string(),
            payload: b"summarize the WS-B reference guest turn".to_vec(),
            context: None,
            timestamp: SystemTime::now(),
            origin: None,
        })
        .expect("deliver");

    let cfg = ComponentConfig {
        id: agent.to_string(),
        config_data: None,
        trigger_context: None,
    };
    let instance =
        WasmInstance::new(ComponentId::new("agent-hello-inst".to_string()).expect("component id"));
    driver.run_agent(agent, cfg, instance).await;

    // 6. The guest's LLM reply reached the production outbound seam → reply registry.
    assert_eq!(
        rx.await.expect("reply slot fulfilled"),
        Some(SCRIPTED_REPLY.as_bytes().to_vec()),
        "the guest's agent-llm reply must flow through ReplyRouterSink to the registry",
    );
    // And the guest actually dialed the loopback exactly once (proves the real
    // guest→injector→gateway→loopback path ran, not a fabricated reply).
    assert_eq!(loopback.chat_request_count(), 1);
}

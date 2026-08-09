//! Phase-2 reply-delivery slice (slice B) — the reply seam end-to-end through the
//! REAL `build_agent_loop` (real `AgentLoopDriverImpl` + real
//! `AgentActionDispatcherImpl` + real `EventBusRejectionSink` + the production
//! `ReplyRouterSink`/`ReplyRegistry`), driven by a mock `MessageHandler` (no WASM
//! needed) using the PRODUCTION messaging id (`DEFAULT_MSG_AGENT_ID`) so the
//! witnessed path is the one production runs (false-green guard).
//!
//! Test 5: a turn that returns one action → the reply registry resolves with the
//!         action payload; a turn that returns no action → resolves `None`.
//! Test 6: a turn that returns an oversized action → the wired `EventBusRejectionSink`
//!         emits `security.action_rejected` (error_kind `oversized_message`) and the
//!         outbound sink is NOT called (validator-first) → the reply slot stays pending.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use async_trait::async_trait;

use advance_cli::agent_loop::{build_agent_loop, build_agent_loop_with_action_limit};
use advance_cli::commands::start::DEFAULT_MSG_AGENT_ID;
use advance_cli::reply::{ReplyRegistry, ReplyRouterSink};

use advance_messaging::{
    MailboxStore, Message, MessageKind, OutboundActionSink, MAX_PAYLOAD_BYTES,
};
use advance_scheduler::hook::{HookError, MessageHandler};
use advance_scheduler::types::{ComponentConfig, ComponentId, WasmInstance};
use advance_scheduler::AgentLoopDriver;
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{ActionResult, AgentAction};
use advance_shared_types::traits::EventBusEmit;

/// Mock `MessageHandler` (no WASM) — `init` returns empty state; `handle_message`
/// returns a fixed `ActionResult`.
struct MockHandler {
    actions: Vec<AgentAction>,
}

#[async_trait]
impl MessageHandler for MockHandler {
    async fn init(&self, _config: ComponentConfig) -> Result<Vec<u8>, HookError> {
        Ok(Vec::new())
    }
    async fn handle_message(
        &self,
        _msg: &Message,
        _state: Vec<u8>,
    ) -> Result<ActionResult, HookError> {
        Ok(ActionResult {
            new_state: Vec::new(),
            actions: self.actions.clone(),
        })
    }
}

/// `EventBusEmit` capturing emitted events for assertion.
struct CapturingBus {
    events: Mutex<Vec<Event>>,
}
impl CapturingBus {
    fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }
}
impl EventBusEmit for CapturingBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

fn inbound(agent: &str) -> Message {
    Message {
        id: "m1".to_string(),
        kind: MessageKind::User,
        from: "user:test".to_string(),
        to: agent.to_string(),
        payload: b"prompt".to_vec(),
        context: None,
        timestamp: SystemTime::now(),
        origin: None,
    }
}

fn one_turn_instance() -> (ComponentConfig, WasmInstance) {
    // ComponentConfig.id carries the cap-layer id (bare); the instance id is a
    // syntactically valid component id (no colon).
    let cfg = ComponentConfig {
        id: "default-agent".to_string(),
        config_data: None,
        trigger_context: None,
    };
    let instance =
        WasmInstance::new(ComponentId::new("agent-inst".to_string()).expect("valid component id"));
    (cfg, instance)
}

// Test 5 — a produced reply flows through the real loop to the reply registry.
#[tokio::test]
async fn reply_turn_delivers_reply_text() {
    let store = Arc::new(MailboxStore::new(NonZeroUsize::new(8).unwrap()));
    let bus: Arc<dyn EventBusEmit> = Arc::new(CapturingBus::new());
    let registry = Arc::new(ReplyRegistry::new());
    let outbound: Arc<dyn OutboundActionSink> = Arc::new(ReplyRouterSink::new(registry.clone()));
    let handler: Arc<dyn MessageHandler> = Arc::new(MockHandler {
        actions: vec![AgentAction {
            payload: b"the reply text".to_vec(),
        }],
    });
    let driver = build_agent_loop(store.clone(), handler, bus, Some(outbound));

    let agent = DEFAULT_MSG_AGENT_ID;
    let rx = registry.register(agent);
    store
        .get_or_create(agent)
        .expect("mailbox")
        .deliver(inbound(agent))
        .expect("deliver");

    let (cfg, instance) = one_turn_instance();
    driver.run_agent(agent, cfg, instance).await;

    assert_eq!(
        rx.await.expect("reply slot fulfilled"),
        Some(b"the reply text".to_vec())
    );
}

// Test 5 (no-action) — a turn that returns no action resolves the slot to None.
#[tokio::test]
async fn no_action_turn_resolves_none() {
    let store = Arc::new(MailboxStore::new(NonZeroUsize::new(8).unwrap()));
    let bus: Arc<dyn EventBusEmit> = Arc::new(CapturingBus::new());
    let registry = Arc::new(ReplyRegistry::new());
    let outbound: Arc<dyn OutboundActionSink> = Arc::new(ReplyRouterSink::new(registry.clone()));
    let handler: Arc<dyn MessageHandler> = Arc::new(MockHandler { actions: vec![] });
    let driver = build_agent_loop(store.clone(), handler, bus, Some(outbound));

    let agent = DEFAULT_MSG_AGENT_ID;
    let rx = registry.register(agent);
    store
        .get_or_create(agent)
        .expect("mailbox")
        .deliver(inbound(agent))
        .expect("deliver");

    let (cfg, instance) = one_turn_instance();
    driver.run_agent(agent, cfg, instance).await;

    assert_eq!(rx.await.expect("reply slot fulfilled"), None);
}

// Test 6 — an oversized action is rejected by the validator; the wired
// EventBusRejectionSink emits security.action_rejected and the outbound sink is
// not called (the reply slot stays pending).
#[tokio::test]
async fn oversized_action_emits_security_action_rejected() {
    let store = Arc::new(MailboxStore::new(NonZeroUsize::new(8).unwrap()));
    let bus_concrete = Arc::new(CapturingBus::new());
    let bus: Arc<dyn EventBusEmit> = bus_concrete.clone();
    let registry = Arc::new(ReplyRegistry::new());
    let outbound: Arc<dyn OutboundActionSink> = Arc::new(ReplyRouterSink::new(registry.clone()));
    // > MAX_PAYLOAD_BYTES (== DefaultActionValidator's 1 MiB cap) → OversizedMessage.
    let oversized = vec![0u8; MAX_PAYLOAD_BYTES + 1];
    let handler: Arc<dyn MessageHandler> = Arc::new(MockHandler {
        actions: vec![AgentAction { payload: oversized }],
    });
    let driver = build_agent_loop(store.clone(), handler, bus, Some(outbound));

    let agent = DEFAULT_MSG_AGENT_ID;
    let mut rx = registry.register(agent);
    store
        .get_or_create(agent)
        .expect("mailbox")
        .deliver(inbound(agent))
        .expect("deliver");

    let (cfg, instance) = one_turn_instance();
    driver.run_agent(agent, cfg, instance).await;

    let events = bus_concrete.events.lock().unwrap();
    let rejected: Vec<&Event> = events
        .iter()
        .filter(|e| e.event_type == "security.action_rejected")
        .collect();
    assert_eq!(
        rejected.len(),
        1,
        "exactly one security.action_rejected emitted"
    );
    assert_eq!(rejected[0].agent_id, agent);
    assert_eq!(
        rejected[0]
            .payload
            .get("error_kind")
            .and_then(|v| v.as_str()),
        Some("oversized_message"),
    );

    // Validator-first: the outbound sink was never called → the reply slot is
    // still pending (no Some/None ever sent).
    assert!(
        matches!(
            rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ),
        "outbound must not fulfill the reply slot on a rejected action",
    );
}

// MODULE-012-AC-17 — the PRODUCTION `build_agent_loop_with_action_limit` (which
// `commands/start.rs` calls with `config.security.action_validator.max_message_size`)
// applies that config SNAPSHOT to the real validator. A 128-byte action is REJECTED
// under a 64-byte config max but ADMITTED under the 1 MiB default — proving the config
// value (not the compile-time default) drives enforcement through the production builder,
// not just the bare `DefaultActionValidator::with_thresholds` unit (T17e).
#[tokio::test]
async fn ac17_action_validator_config_max_applied_via_production_builder() {
    // 128 bytes: above the 64-byte config max, below the 1 MiB default.
    let action_payload = vec![0u8; 128];

    // (a) small config max (64) → the production builder's validator rejects it.
    {
        let store = Arc::new(MailboxStore::new(NonZeroUsize::new(8).unwrap()));
        let bus_concrete = Arc::new(CapturingBus::new());
        let bus: Arc<dyn EventBusEmit> = bus_concrete.clone();
        let registry = Arc::new(ReplyRegistry::new());
        let outbound: Arc<dyn OutboundActionSink> =
            Arc::new(ReplyRouterSink::new(registry.clone()));
        let handler: Arc<dyn MessageHandler> = Arc::new(MockHandler {
            actions: vec![AgentAction {
                payload: action_payload.clone(),
            }],
        });
        let driver =
            build_agent_loop_with_action_limit(store.clone(), handler, bus, Some(outbound), 64);
        let agent = DEFAULT_MSG_AGENT_ID;
        let _rx = registry.register(agent);
        store
            .get_or_create(agent)
            .unwrap()
            .deliver(inbound(agent))
            .unwrap();
        let (cfg, instance) = one_turn_instance();
        driver.run_agent(agent, cfg, instance).await;
        let events = bus_concrete.events.lock().unwrap();
        let rejected = events
            .iter()
            .filter(|e| {
                e.event_type == "security.action_rejected"
                    && e.payload.get("error_kind").and_then(|v| v.as_str())
                        == Some("oversized_message")
            })
            .count();
        assert_eq!(
            rejected, 1,
            "128-byte action must be rejected under the 64-byte security.action_validator.max_message_size config snapshot"
        );
    }

    // (b) default 1 MiB max → the SAME action is admitted (delivered) — proving the
    // config value, not anything else, drove the rejection in (a).
    {
        let store = Arc::new(MailboxStore::new(NonZeroUsize::new(8).unwrap()));
        let bus: Arc<dyn EventBusEmit> = Arc::new(CapturingBus::new());
        let registry = Arc::new(ReplyRegistry::new());
        let outbound: Arc<dyn OutboundActionSink> =
            Arc::new(ReplyRouterSink::new(registry.clone()));
        let handler: Arc<dyn MessageHandler> = Arc::new(MockHandler {
            actions: vec![AgentAction {
                payload: action_payload.clone(),
            }],
        });
        let driver = build_agent_loop_with_action_limit(
            store.clone(),
            handler,
            bus,
            Some(outbound),
            1024 * 1024,
        );
        let agent = DEFAULT_MSG_AGENT_ID;
        let rx = registry.register(agent);
        store
            .get_or_create(agent)
            .unwrap()
            .deliver(inbound(agent))
            .unwrap();
        let (cfg, instance) = one_turn_instance();
        driver.run_agent(agent, cfg, instance).await;
        assert_eq!(
            rx.await.expect("reply slot fulfilled"),
            Some(action_payload),
            "the same 128-byte action is admitted under the 1 MiB max"
        );
    }
}

//! /dev Phase-2 Step-3 — SYS-J-64 persistent actor-state round-trip witnesses
//! (SYS-AC-263 + SYS-AC-264) over the REAL wired daemon path.
//!
//! Uses the `guest-rust-counter` fixture: `handle-message` reads the counter from
//! the host-passed `state` arg (NOT guest memory — no mutable global), increments,
//! and returns `new_state = (n+1) LE` + a reply action `"n+1"`.
//!
//! - **SYS-AC-263** (`counter_threads_state_across_turns_via_serve`): drive the
//!   production `AgentLoopDriverImpl::serve` loop (init ONCE, then thread each
//!   turn's `new_state` into the next turn) over ONE Wasmtime Store. Two inbound
//!   messages → replies `["1", "2"]`. The reply changes ONLY because `serve`
//!   threads `new_state` (a stateless turn would reply `"1"` twice).
//! - **SYS-AC-264** (`counter_carried_by_opaque_blob_alone_fresh_store`): the
//!   discriminator. Drive turn-1 on instance A, capture its `new_state` blob;
//!   drive turn-2 on a FRESH `WasmMessageHandler` (fresh Wasmtime Store → fresh
//!   linear memory) seeded with A's blob → reply `"2"`. Continuation across a
//!   fresh Store proves the value is carried by the opaque `state` blob ALONE
//!   (not guest memory); the harness writes no file-based context (summary.yaml /
//!   turn-index), so it also proves no file-context dependency.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use advance_runtime::capability_injector::CapabilityInjector;
use advance_runtime::circuit_breaker::DefaultCircuitBreakerBus;
use advance_runtime::config::WasmConfig;
use advance_runtime::host_registry::{HostRegistry, InMemoryHostRegistry};
use advance_runtime::ComponentRuntime;

use advance_shared_types::capability::{CapParams, GrantDecision};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{AgentAction, DispatchError, Message, MessageKind};
use advance_shared_types::outbound::DeliveryReport;
use advance_shared_types::traits::{EventBusEmit, GrantCheck};

use advance_cli::agent_loop::{build_agent_loop, WasmMessageHandler};

use advance_messaging::{MailboxStore, OutboundActionSink};
use advance_scheduler::hook::{MessageHandler, TurnObserver};
use advance_scheduler::types::{ComponentConfig, ComponentId, WasmInstance};

const COUNTER_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-counter.core.wasm");

struct NullBus;
impl EventBusEmit for NullBus {
    fn emit(&self, _event: Event) {}
}

struct AllowAllGrant;
impl GrantCheck for AllowAllGrant {
    fn check(&self, _a: &str, _c: &str, _f: &str, _p: &CapParams) -> GrantDecision {
        GrantDecision::Allow
    }
}

/// Captures each turn's first-action reply payload.
struct RecordingSink {
    replies: Arc<Mutex<Vec<Vec<u8>>>>,
}
#[async_trait::async_trait]
impl OutboundActionSink for RecordingSink {
    async fn deliver(
        &self,
        _agent_id: &str,
        _source: &Message,
        actions: &[AgentAction],
    ) -> Result<DeliveryReport, DispatchError> {
        if let Some(a) = actions.first() {
            self.replies.lock().unwrap().push(a.payload.clone());
        }
        Ok(DeliveryReport::empty())
    }
}

/// Signals each `serve` turn boundary.
struct CountObserver {
    tx: tokio::sync::mpsc::UnboundedSender<()>,
}
impl TurnObserver for CountObserver {
    fn on_turn_complete(&self, _agent_id: &str) {
        let _ = self.tx.send(());
    }
}

fn runtime() -> Arc<ComponentRuntime> {
    Arc::new(
        ComponentRuntime::new(&WasmConfig {
            max_memory_pages: 256,
            epoch_interruption_ms: 100,
            fuel_enabled: false,
        })
        .expect("runtime"),
    )
}

fn injector() -> Arc<CapabilityInjector> {
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    Arc::new(CapabilityInjector::new(
        registry,
        Arc::new(AllowAllGrant),
        Arc::new(DefaultCircuitBreakerBus::new()),
    ))
}

fn counter_handler(
    rt: Arc<ComponentRuntime>,
    inj: Arc<CapabilityInjector>,
    agent: &str,
) -> WasmMessageHandler {
    let component =
        build_agent::encode_core_to_component(COUNTER_CORE).expect("encode counter core");
    let loaded = rt
        .load_component(&component)
        .expect("load counter component");
    WasmMessageHandler::new(
        rt,
        loaded,
        inj,
        vec![],
        agent.to_string(),
        "trace-counter".into(),
    )
}

fn user_msg(id: &str, agent: &str) -> Message {
    Message {
        id: id.into(),
        kind: MessageKind::User,
        from: "user:test".into(),
        to: agent.into(),
        payload: b"tick".to_vec(),
        context: None,
        timestamp: SystemTime::now(),
        origin: None,
    }
}

// ── SYS-AC-263: cross-turn new_state threading via the production serve loop ──
#[tokio::test(flavor = "multi_thread")]
async fn counter_threads_state_across_turns_via_serve() {
    let agent = "agent:counter";
    let rt = runtime();
    let handler: Arc<dyn MessageHandler> = Arc::new(counter_handler(rt, injector(), agent));

    let store = Arc::new(MailboxStore::new(NonZeroUsize::new(8).unwrap()));
    let replies = Arc::new(Mutex::new(Vec::new()));
    let sink: Arc<dyn OutboundActionSink> = Arc::new(RecordingSink {
        replies: replies.clone(),
    });
    let (tx, mut turn_rx) = tokio::sync::mpsc::unbounded_channel();
    let observer: Arc<dyn TurnObserver> = Arc::new(CountObserver { tx });

    let driver = build_agent_loop(store.clone(), handler, Arc::new(NullBus), Some(sink))
        .with_turn_observer(observer);

    let cfg = ComponentConfig {
        id: agent.into(),
        config_data: None,
        trigger_context: None,
    };
    let instance = WasmInstance::new(ComponentId::new("counter-inst".into()).unwrap());
    let serve_task = tokio::spawn(async move { driver.serve(agent, cfg, instance).await });

    // Two inbound messages; serve threads new_state across them (one Store).
    let mb = store.get_or_create(agent).expect("mailbox");
    mb.deliver(user_msg("m1", agent)).expect("deliver m1");
    mb.deliver(user_msg("m2", agent)).expect("deliver m2");

    // Wait for two turn-completions (bounded).
    for _ in 0..2 {
        tokio::time::timeout(Duration::from_secs(10), turn_rx.recv())
            .await
            .expect("turn completed within 10s")
            .expect("observer channel open");
    }
    serve_task.abort();

    let got = replies.lock().unwrap().clone();
    assert_eq!(
        got,
        vec![b"1".to_vec(), b"2".to_vec()],
        "serve must thread new_state across turns: turn-1 reply '1', turn-2 reply '2' \
         (a stateless turn would reply '1' twice)"
    );
}

// ── SYS-AC-264: carried by the opaque blob alone — fresh-Store continuation ──
#[tokio::test(flavor = "multi_thread")]
async fn counter_carried_by_opaque_blob_alone_fresh_store() {
    let agent = "agent:counter2";
    let rt = runtime();
    let inj = injector();
    let cfg = ComponentConfig {
        id: agent.into(),
        config_data: None,
        trigger_context: None,
    };

    // Turn 1 on instance A: capture its new_state blob + reply.
    let h1 = counter_handler(rt.clone(), inj.clone(), agent);
    let state0 = h1.init(cfg.clone()).await.expect("init A");
    let r1 = h1
        .handle_message(&user_msg("m1", agent), state0)
        .await
        .expect("turn 1");
    assert_eq!(
        r1.actions.first().map(|a| a.payload.clone()),
        Some(b"1".to_vec())
    );
    let blob = r1.new_state.clone(); // the opaque actor-state blob (counter = 1)

    // Turn 2 on a FRESH instance B (fresh Wasmtime Store → fresh linear memory),
    // seeded with A's captured blob. If the value were carried by guest memory,
    // B would reply "1"; carried by the opaque blob, B replies "2".
    let h2 = counter_handler(rt, inj, agent);
    let _ = h2
        .init(cfg)
        .await
        .expect("init B (bootstrap-default state discarded)");
    let r2 = h2
        .handle_message(&user_msg("m2", agent), blob)
        .await
        .expect("turn 2 on fresh instance seeded with the blob");
    assert_eq!(
        r2.actions.first().map(|a| a.payload.clone()),
        Some(b"2".to_vec()),
        "continuation across a FRESH Store proves the value is carried by the opaque \
         state blob ALONE (not guest memory; no file-based context encodes it)"
    );
}

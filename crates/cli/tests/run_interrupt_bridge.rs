//! Wave-12 Lane B build-lane witness — the `Message::RunInterrupted`
//! crash-recovery → controller-mailbox bridge (SYS-AC-121 capability proof).
//!
//! This is NOT a SYS-AC flip (a later mainline harvest flips SYS-AC-121 on the
//! real wired chain). It proves, with the PRODUCT path:
//!
//! - **RIB-01** — product-driven delivery: a real `RunManager::recover_on_startup`
//!   over a real `MailboxRunInterruptSink` over a real `MailboxStore` lands a
//!   decodable `Message::RunInterrupted` (kind=Control) in the controller mailbox.
//! - **RIB-02** — the standard turn pipeline runs handle-message on it: the REAL
//!   `AgentLoopDriverImpl::run_agent` over the production `StoreMailboxReader`
//!   (reading the recovery-delivered store) invokes the controller's
//!   handle-message exactly once on the RunInterrupted message. Only the leaf
//!   collaborators are mocks (same shape as `scheduler/tests/agent_loop_message_pipeline.rs`).
//! - **RIB-03** — zero-flip default: a `RunManager` WITHOUT a sink recovers
//!   event-only (byte-identical report, no mailbox side effect, no panic).
//!
//! Reaches Suspended via the PUBLIC `suspend_run` (no `__test-util` feature).

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use advance_cli::agent_loop::StoreMailboxReader;
use advance_messaging::mailbox::MailboxStore;
use advance_messaging::MailboxRunInterruptSink;
use advance_run_manager::{RunConfig, RunManager};
use advance_scheduler::agent_loop::AgentLoopDriverImpl;
use advance_scheduler::hook::{BootstrapError, HookError, MessageHandler, RunBootstrap};
use advance_scheduler::types::{ComponentConfig, ComponentId, WasmInstance};
use advance_scheduler::AgentLoopDriver;
use advance_shared_types::await_session::{
    AwaitSessionRef, AwaitTreeSummary, OrchestrationError, SessionId,
};
use advance_shared_types::context::{
    AssemblyContext, AssemblyError, AssemblyResult, ContextAssembler, TierTokenCounts,
};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{
    ActionResult, AgentAction, AgentActionDispatcher, ControlMessage, DispatchError, Message,
    MessageKind,
};
use advance_shared_types::memory::{PostProcessorError, PostProcessorHook};
use advance_shared_types::outbound::DeliveryReport;
use advance_shared_types::traits::EventBusEmit;

const CONTROLLER: &str = "agent:controller";

// ───────────────────────── run-manager fixtures ─────────────────────────

#[derive(Default)]
struct MockBus {
    events: Mutex<Vec<Event>>,
}
impl MockBus {
    fn new_arc() -> Arc<Self> {
        Arc::new(Self::default())
    }
    fn count(&self, ty: &str) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.event_type == ty)
            .count()
    }
}
impl EventBusEmit for MockBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

/// AwaitSessionRef whose every session is gone → recovery fires for every
/// Suspended run with a `root_await`.
struct DeadSession;
#[async_trait]
impl AwaitSessionRef for DeadSession {
    fn exists(&self, _: &SessionId) -> bool {
        false
    }
    fn walk_tree(&self, _: &SessionId) -> Option<AwaitTreeSummary> {
        None
    }
    async fn close(&self, _: &SessionId, _: &str) -> Result<(), OrchestrationError> {
        Ok(())
    }
}

/// Drive a Suspended-with-missing-session run through real recovery + the
/// MailboxStore-backed sink. Returns the shared store so the caller can inspect
/// / drive the agent loop over it.
async fn deliver_via_recovery() -> Arc<MailboxStore> {
    let store = Arc::new(MailboxStore::new(NonZeroUsize::new(8).unwrap()));
    let sink = Arc::new(MailboxRunInterruptSink::new(Arc::clone(&store)));
    let bus = MockBus::new_arc();
    let rm = RunManager::new(bus).with_run_interrupt_sink(sink);

    let run_id = rm
        .ensure_run("task-1", CONTROLLER, RunConfig::default())
        .expect("ensure_run");
    rm.suspend_run(&run_id, "sid-x").expect("suspend_run"); // public path → Suspended + root_await

    let report = rm.recover_on_startup(Arc::new(DeadSession)).await;
    assert_eq!(report.suspended_scanned, 1);
    assert_eq!(
        report.interrupted_emitted, 1,
        "recovery flipped + emitted + delivered"
    );
    store
}

// ───────────────────────────── RIB-01 ─────────────────────────────

#[tokio::test]
async fn rib_01_recovery_delivers_run_interrupted_into_controller_mailbox() {
    let store = deliver_via_recovery().await;

    let mb = store
        .get(CONTROLLER)
        .expect("recovery+sink created the controller mailbox");
    assert_eq!(
        mb.depth(),
        1,
        "exactly one message delivered by the product path"
    );

    // The recovery-delivered Control message decodes back to RunInterrupted.
    let msg = mb.recv().await;
    assert_eq!(msg.kind, MessageKind::Control);
    assert_eq!(msg.to, CONTROLLER);
    assert_eq!(msg.from, "system");
    let decoded: ControlMessage = serde_json::from_slice(&msg.payload).expect("payload decodes");
    match decoded {
        ControlMessage::RunInterrupted { run_id, reason } => {
            assert!(run_id.starts_with("run-"), "run_id propagated: {run_id}");
            assert_eq!(reason, "crash-recovery");
        }
    }
}

// ─────────────── RIB-02: real run_agent pipeline mocks ───────────────

type Recorder = Arc<Mutex<Vec<&'static str>>>;
fn record(rec: &Recorder, tag: &'static str) {
    rec.lock().unwrap().push(tag);
}

struct RecordingBootstrap(Recorder);
#[async_trait]
impl RunBootstrap for RecordingBootstrap {
    async fn ensure_run(&self, _controller_agent: &str) -> Result<String, BootstrapError> {
        record(&self.0, "bootstrap");
        Ok("run-witness".into())
    }
}

struct RecordingMessageHandler {
    rec: Recorder,
    captured: Arc<Mutex<Option<Message>>>,
}
#[async_trait]
impl MessageHandler for RecordingMessageHandler {
    async fn init(&self, _config: ComponentConfig) -> Result<Vec<u8>, HookError> {
        record(&self.rec, "init");
        Ok(vec![0x42])
    }
    async fn handle_message(
        &self,
        msg: &Message,
        _state: Vec<u8>,
    ) -> Result<ActionResult, HookError> {
        record(&self.rec, "handle_message");
        *self.captured.lock().unwrap() = Some(msg.clone());
        Ok(ActionResult {
            new_state: Vec::new(),
            actions: Vec::new(),
        })
    }
}

struct RecordingAssembler;
#[async_trait]
impl ContextAssembler for RecordingAssembler {
    async fn assemble(&self, _ctx: AssemblyContext) -> Result<AssemblyResult, AssemblyError> {
        Ok(AssemblyResult {
            messages: Vec::new(),
            routing_method: "search".into(),
            routing_confidence: 0.0,
            is_new_task: false,
            tier_token_counts: TierTokenCounts {
                tier1a: 0,
                tier1b: 0,
                tier2: 0,
                tier3: 0,
            },
        })
    }
    fn inject_tier3_warning(&self, _agent_id: &str, _msg: &str) {}
}

struct RecordingDispatcher;
#[async_trait]
impl AgentActionDispatcher for RecordingDispatcher {
    async fn dispatch(
        &self,
        _agent_id: &str,
        _source: &Message,
        _actions: &[AgentAction],
    ) -> Result<DeliveryReport, DispatchError> {
        Ok(DeliveryReport::empty())
    }
}

struct RecordingPostProcessor;
#[async_trait]
impl PostProcessorHook for RecordingPostProcessor {
    async fn run(
        &self,
        _agent_id: &str,
        _msg: &Message,
        _result: &ActionResult,
    ) -> Result<(), PostProcessorError> {
        Ok(())
    }
}

#[tokio::test]
async fn rib_02_real_run_agent_runs_handle_message_on_run_interrupted() {
    // Product delivery: the recovery→sink path stages the RunInterrupted message.
    let store = deliver_via_recovery().await;

    let rec: Recorder = Arc::new(Mutex::new(Vec::new()));
    let captured: Arc<Mutex<Option<Message>>> = Arc::new(Mutex::new(None));

    // The REAL production single-turn driver over the PRODUCTION StoreMailboxReader
    // reading the recovery-delivered store. Only the leaf collaborators are mocks.
    let driver = AgentLoopDriverImpl::new(
        Arc::new(StoreMailboxReader::new(Arc::clone(&store))),
        Arc::new(RecordingAssembler),
        Arc::new(RecordingPostProcessor),
        Arc::new(RecordingDispatcher),
        Arc::new(RecordingBootstrap(rec.clone())),
        Arc::new(RecordingMessageHandler {
            rec: rec.clone(),
            captured: Arc::clone(&captured),
        }),
    );

    let config = ComponentConfig {
        id: "agent-controller".into(),
        config_data: None,
        trigger_context: None,
    };
    let instance = WasmInstance::new(ComponentId::new("agent-controller".into()).unwrap());

    // run_agent: bootstrap → init → recv (real StoreMailboxReader pops the
    // recovery-delivered Control message) → assemble → handle_message → ...
    driver.run_agent(CONTROLLER, config, instance).await;

    // handle-message ran exactly once.
    let order = rec.lock().unwrap().clone();
    assert_eq!(
        order.iter().filter(|t| **t == "handle_message").count(),
        1,
        "controller handle-message invoked exactly once; got {order:?}"
    );

    // ...and it ran on the recovery-delivered Message::RunInterrupted.
    let msg = captured
        .lock()
        .unwrap()
        .clone()
        .expect("handle_message captured a message");
    assert_eq!(msg.kind, MessageKind::Control);
    assert_eq!(msg.to, CONTROLLER);
    assert_eq!(msg.from, "system");
    let decoded: ControlMessage = serde_json::from_slice(&msg.payload).expect("payload decodes");
    assert!(
        matches!(decoded, ControlMessage::RunInterrupted { reason, .. } if reason == "crash-recovery"),
        "handle-message ran on the RunInterrupted control message"
    );
}

// ───────────────────────────── RIB-03 ─────────────────────────────

#[tokio::test]
async fn rib_03_no_sink_recovers_event_only_byte_identical() {
    // No sink wired → recovery emits the event and returns the SAME report,
    // with no mailbox side effect and no panic.
    let store = Arc::new(MailboxStore::new(NonZeroUsize::new(8).unwrap()));
    let bus = MockBus::new_arc();
    // bus.clone() is Arc<MockBus> → coerces to Arc<dyn EventBusEmit> at the arg
    // position (Arc::clone(&bus) would force backward inference and fail).
    let rm = RunManager::new(bus.clone()); // NO with_run_interrupt_sink

    let run_id = rm
        .ensure_run("task-3", CONTROLLER, RunConfig::default())
        .expect("ensure_run");
    rm.suspend_run(&run_id, "sid-z").expect("suspend_run");

    let report = rm.recover_on_startup(Arc::new(DeadSession)).await;
    assert_eq!(report.suspended_scanned, 1);
    assert_eq!(
        report.interrupted_emitted, 1,
        "event still emitted without a sink"
    );
    assert_eq!(
        bus.count("run.interrupted"),
        1,
        "run.interrupted emitted exactly once"
    );

    // No sink ⇒ nothing delivered into the store (the controller mailbox was
    // never even lazily created by recovery).
    assert!(
        store.get(CONTROLLER).is_none(),
        "no-sink recovery has no mailbox side effect"
    );
}

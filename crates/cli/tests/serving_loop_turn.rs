//! /dev Phase-2 Step-2 — scheduler serving loop + cross-turn state continuity.
//!
//! Drives the REAL `AgentLoopDriverImpl::serve` (the internalized canonical
//! MODULE-014 §1.4.1 multi-turn loop) through the production `build_agent_loop`
//! factory, with a stateful mock `MessageHandler` (no WASM). Proves:
//!
//! - **T1 (serving loop)**: `serve` processes MORE THAN ONE message from the
//!   shared `MailboxStore` — i.e. the agent does NOT die after turn 1 (under the
//!   pre-Phase-2 single-turn `run_agent` it would have).
//! - **T2 (cross-turn state)**: turn N+1's `handle_message` receives turn N's
//!   returned `new_state` as its `state` argument (in-process continuity).
//!
//! `serve` is an infinite loop (no mailbox-close primitive), so each test spawns
//! it on a task, delivers its messages, polls the observable side effect, then
//! aborts the task — mirroring how the production daemon runs + shuts it down.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use async_trait::async_trait;

use advance_cli::agent_loop::build_agent_loop;
use advance_cli::commands::start::DEFAULT_MSG_AGENT_ID;

use advance_messaging::{MailboxStore, Message, MessageKind};
use advance_scheduler::hook::{HookError, MessageHandler};
use advance_scheduler::types::{ComponentConfig, ComponentId, WasmInstance};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{ActionResult, AgentAction};
use advance_shared_types::traits::EventBusEmit;

/// Stateful mock handler: records the `state` arg it receives each turn, and
/// returns `new_state = msg.payload` so the NEXT turn's `state` is THIS turn's
/// inbound payload — making cross-turn state continuity directly observable.
struct StatefulHandler {
    init_state: Vec<u8>,
    seen_states: Arc<Mutex<Vec<Vec<u8>>>>,
    /// Optional action so a turn produces a (recorded-but-unused-here) reply.
    actions: Vec<AgentAction>,
}

#[async_trait]
impl MessageHandler for StatefulHandler {
    async fn init(&self, _config: ComponentConfig) -> Result<Vec<u8>, HookError> {
        Ok(self.init_state.clone())
    }
    async fn handle_message(
        &self,
        msg: &Message,
        state: Vec<u8>,
    ) -> Result<ActionResult, HookError> {
        self.seen_states.lock().unwrap().push(state);
        Ok(ActionResult {
            new_state: msg.payload.clone(),
            actions: self.actions.clone(),
        })
    }
}

/// No-op `EventBusEmit` (the rejection sink wired by `build_agent_loop` never
/// fires on the happy path; we don't assert on events here).
struct NoopBus;
impl EventBusEmit for NoopBus {
    fn emit(&self, _event: Event) {}
}

fn inbound(agent: &str, id: &str, payload: &[u8]) -> Message {
    Message {
        id: id.to_string(),
        kind: MessageKind::User,
        from: "user:test".to_string(),
        to: agent.to_string(),
        payload: payload.to_vec(),
        context: None,
        timestamp: SystemTime::now(),
        origin: None,
    }
}

fn one_instance() -> (ComponentConfig, WasmInstance) {
    let cfg = ComponentConfig {
        id: "default-agent".to_string(),
        config_data: None,
        trigger_context: None,
    };
    let instance =
        WasmInstance::new(ComponentId::new("agent-inst".to_string()).expect("valid component id"));
    (cfg, instance)
}

/// Poll the recorder until it holds `>= n` entries or the deadline elapses.
async fn await_turns(seen: &Arc<Mutex<Vec<Vec<u8>>>>, n: usize, within: Duration) {
    let deadline = Instant::now() + within;
    loop {
        if seen.lock().unwrap().len() >= n {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "serving loop processed only {} of {} messages within {:?}",
                seen.lock().unwrap().len(),
                n,
                within
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// T1 + T2: `serve` processes BOTH delivered messages (serving loop), and turn 2's
// `state` arg equals turn 1's returned `new_state` (cross-turn continuity).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_processes_multiple_messages_and_threads_state_across_turns() {
    let store = Arc::new(MailboxStore::new(NonZeroUsize::new(8).unwrap()));
    let bus: Arc<dyn EventBusEmit> = Arc::new(NoopBus);
    let seen_states = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let handler: Arc<dyn MessageHandler> = Arc::new(StatefulHandler {
        init_state: b"INIT".to_vec(),
        seen_states: seen_states.clone(),
        actions: Vec::new(),
    });
    // No outbound sink + no turn observer needed for the scheduler-loop assertions.
    let driver = build_agent_loop(store.clone(), handler, bus, None);

    let agent = DEFAULT_MSG_AGENT_ID;
    let (cfg, instance) = one_instance();
    let serve_handle = tokio::spawn(async move {
        driver.serve(agent, cfg, instance).await;
    });

    // Deliver two distinct messages. `Mailbox::deliver` → notify_one wakes the
    // loop's parked `recv`; the loop drains both serially.
    let mb = store.get_or_create(agent).expect("mailbox");
    mb.deliver(inbound(agent, "m1", b"P1")).expect("deliver m1");
    mb.deliver(inbound(agent, "m2", b"P2")).expect("deliver m2");

    await_turns(&seen_states, 2, Duration::from_secs(5)).await;
    serve_handle.abort();

    let seen = seen_states.lock().unwrap();
    // T1: the loop served BOTH messages — it did not die after turn 1.
    assert_eq!(
        seen.len(),
        2,
        "serving loop must process both messages (single-turn would stop after one)"
    );
    // T2: turn 1 saw the init state; turn 2 saw turn 1's returned new_state (= P1).
    assert_eq!(seen[0], b"INIT".to_vec(), "turn 1 receives the init state");
    assert_eq!(
        seen[1],
        b"P1".to_vec(),
        "turn 2 receives turn 1's new_state — cross-turn state continuity"
    );
}

// T1 (extended): three turns thread state transitively (INIT → A → B), proving the
// loop keeps serving and the state chain is maintained, not just a one-off.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_threads_state_across_three_turns() {
    let store = Arc::new(MailboxStore::new(NonZeroUsize::new(8).unwrap()));
    let bus: Arc<dyn EventBusEmit> = Arc::new(NoopBus);
    let seen_states = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let handler: Arc<dyn MessageHandler> = Arc::new(StatefulHandler {
        init_state: b"S0".to_vec(),
        seen_states: seen_states.clone(),
        actions: vec![AgentAction {
            payload: b"ack".to_vec(),
        }],
    });
    let driver = build_agent_loop(store.clone(), handler, bus, None);

    let agent = DEFAULT_MSG_AGENT_ID;
    let (cfg, instance) = one_instance();
    let serve_handle = tokio::spawn(async move {
        driver.serve(agent, cfg, instance).await;
    });

    let mb = store.get_or_create(agent).expect("mailbox");
    mb.deliver(inbound(agent, "m1", b"A")).expect("deliver m1");
    mb.deliver(inbound(agent, "m2", b"B")).expect("deliver m2");
    mb.deliver(inbound(agent, "m3", b"C")).expect("deliver m3");

    await_turns(&seen_states, 3, Duration::from_secs(5)).await;
    serve_handle.abort();

    let seen = seen_states.lock().unwrap();
    assert_eq!(
        seen.len(),
        3,
        "serving loop must process all three messages"
    );
    assert_eq!(seen[0], b"S0".to_vec());
    assert_eq!(seen[1], b"A".to_vec(), "turn 2 state == turn 1 new_state");
    assert_eq!(seen[2], b"B".to_vec(), "turn 3 state == turn 2 new_state");
}

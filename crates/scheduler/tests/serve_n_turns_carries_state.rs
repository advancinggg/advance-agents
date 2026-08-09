//! Backbone Step 4 — `AgentLoopDriverImpl::serve_n_turns` cross-turn state carry.
//!
//! Proves the bounded multi-turn driver: `bootstrap` + `init` run EXACTLY ONCE,
//! then `n` turns each thread the prior turn's `new_state` into the next turn.
//! A stateful `MessageHandler` returns `new_state = [prior + 1]`; over 3 turns it
//! must OBSERVE the incoming states `[0, 1, 2]` (init state 0, then each turn's
//! carried `new_state`). A re-bootstrapping driver (the old `run_turn()`×N path)
//! would instead observe `[0, 0, 0]` (init re-run, prior `new_state` discarded).
//!
//! This is the MODULE-014 unit witness for the bounded multi-turn loop; the
//! full-wired SYS-AC-004 e2e witness lives in `crates/system-acceptance`.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use advance_scheduler::agent_loop::AgentLoopDriverImpl;
use advance_scheduler::hook::{BootstrapError, HookError, MessageHandler, RunBootstrap};
use advance_scheduler::types::{ComponentConfig, ComponentId, WasmInstance};
use advance_shared_types::context::{
    AssemblyContext, AssemblyError, AssemblyResult, ContextAssembler, TierTokenCounts,
};
use advance_shared_types::mailbox::{
    ActionResult, AgentAction, AgentActionDispatcher, DispatchError, MailboxReader, Message,
    MessageKind,
};
use advance_shared_types::memory::{PostProcessorError, PostProcessorHook};
use advance_shared_types::outbound::DeliveryReport;

// ── Counters / observation ──────────────────────────────────────────────
#[derive(Default)]
struct Counts {
    bootstrap: usize,
    init: usize,
    recv: usize,
}

/// Bootstrap that counts how many times it runs (must be exactly 1).
struct CountingBootstrap(Arc<Mutex<Counts>>);
#[async_trait]
impl RunBootstrap for CountingBootstrap {
    async fn ensure_run(&self, _controller_agent: &str) -> Result<String, BootstrapError> {
        self.0.lock().unwrap().bootstrap += 1;
        Ok("run-1".into())
    }
}

/// Stateful handler: `init` → state `[0]`; `handle_message` records the INCOMING
/// state's counter byte and returns `[prior + 1]` (threading the counter).
struct CounterHandler {
    counts: Arc<Mutex<Counts>>,
    observed: Arc<Mutex<Vec<u8>>>,
}
#[async_trait]
impl MessageHandler for CounterHandler {
    async fn init(&self, _config: ComponentConfig) -> Result<Vec<u8>, HookError> {
        self.counts.lock().unwrap().init += 1;
        Ok(vec![0])
    }
    async fn handle_message(
        &self,
        _msg: &Message,
        state: Vec<u8>,
    ) -> Result<ActionResult, HookError> {
        let prior = state.first().copied().unwrap_or(0);
        self.observed.lock().unwrap().push(prior);
        Ok(ActionResult {
            new_state: vec![prior + 1],
            actions: vec![AgentAction {
                payload: vec![prior + 1],
            }],
        })
    }
}

/// Mailbox that always yields a canned message (so `serve_n_turns` is bounded
/// only by `n`, not by message availability) and counts `recv` calls.
struct CountingMailbox(Arc<Mutex<Counts>>);
#[async_trait]
impl MailboxReader for CountingMailbox {
    async fn recv(&self, agent_id: &str) -> Message {
        self.0.lock().unwrap().recv += 1;
        Message {
            id: "m".into(),
            kind: MessageKind::User,
            from: "user:test".into(),
            to: agent_id.into(),
            payload: b"tick".to_vec(),
            context: None,
            timestamp: std::time::SystemTime::UNIX_EPOCH,
            origin: None,
        }
    }
    fn poll(&self, _agent_id: &str) -> Option<Message> {
        None
    }
    fn depth(&self, _agent_id: &str) -> usize {
        0
    }
    fn freeze(&self, _agent_id: &str) {}
    fn unfreeze(&self, _agent_id: &str) {}
}

// ── Cooperative no-op stubs for the rest of the per-turn pipeline ─────────
struct OkAssembler;
#[async_trait]
impl ContextAssembler for OkAssembler {
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

struct OkDispatcher;
#[async_trait]
impl AgentActionDispatcher for OkDispatcher {
    async fn dispatch(
        &self,
        _agent_id: &str,
        _source: &Message,
        _actions: &[AgentAction],
    ) -> Result<DeliveryReport, DispatchError> {
        Ok(DeliveryReport::empty())
    }
}

struct OkPostProcessor;
#[async_trait]
impl PostProcessorHook for OkPostProcessor {
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
async fn serve_n_turns_carries_new_state_across_turns_bootstrap_once() {
    let counts = Arc::new(Mutex::new(Counts::default()));
    let observed = Arc::new(Mutex::new(Vec::new()));

    let driver = AgentLoopDriverImpl::new(
        Arc::new(CountingMailbox(counts.clone())),
        Arc::new(OkAssembler),
        Arc::new(OkPostProcessor),
        Arc::new(OkDispatcher),
        Arc::new(CountingBootstrap(counts.clone())),
        Arc::new(CounterHandler {
            counts: counts.clone(),
            observed: observed.clone(),
        }),
    );

    let config = ComponentConfig {
        id: "agent:counter".into(),
        config_data: None,
        trigger_context: None,
    };
    let instance = WasmInstance::new(ComponentId::new("serve-n-inst".into()).unwrap());

    driver
        .serve_n_turns("agent:counter", config, instance, 3)
        .await;

    // new_state threads turn→turn: each turn observes the prior turn's output.
    assert_eq!(
        observed.lock().unwrap().clone(),
        vec![0u8, 1, 2],
        "serve_n_turns must thread new_state across turns (init 0 → 1 → 2); \
         a re-bootstrapping driver would observe [0, 0, 0]"
    );

    let c = counts.lock().unwrap();
    assert_eq!(c.bootstrap, 1, "bootstrap runs ONCE, not per turn");
    assert_eq!(c.init, 1, "init runs ONCE, not per turn");
    assert_eq!(c.recv, 3, "exactly n=3 turns ran (n recv calls)");
}

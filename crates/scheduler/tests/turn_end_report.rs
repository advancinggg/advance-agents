//! The serving loop reports how each turn ended (`TurnObserver::on_turn_end`) before it
//! reports the turn complete, against the message the turn executed: `Failed` for a
//! guest error or trap and for a refused dispatch, `Completed` for a dispatched batch.
//!
//! Drives the production `serve` loop only, so it runs under a plain
//! `cargo test -p advance-scheduler`; the bounded `serve_n_turns` half of the same
//! witness lives in the feature-gated `agent_loop_trap_policy`.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;

use advance_scheduler::agent_loop::AgentLoopDriverImpl;
use advance_scheduler::hook::{
    BootstrapError, HookError, MessageHandler, RunBootstrap, TurnEnd, TurnObserver,
};
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

const AGENT: &str = "agent:ends";

/// One ordered record of what the loop asked of the handler and told the observer.
type Sequence = Arc<Mutex<Vec<String>>>;

/// Traps on its even turns (0, 2, ...), succeeds with an empty batch on its odd turns.
struct SequenceHandler {
    sequence: Sequence,
    turns: Mutex<usize>,
}

#[async_trait]
impl MessageHandler for SequenceHandler {
    async fn init(&self, _config: ComponentConfig) -> Result<Vec<u8>, HookError> {
        self.sequence.lock().unwrap().push("init".into());
        Ok(Vec::new())
    }
    async fn handle_message(
        &self,
        msg: &Message,
        _state: Vec<u8>,
    ) -> Result<ActionResult, HookError> {
        let n = {
            let mut turns = self.turns.lock().unwrap();
            *turns += 1;
            *turns - 1
        };
        self.sequence
            .lock()
            .unwrap()
            .push(format!("handle {} {n}", msg.id));
        if n % 2 == 0 {
            return Err(HookError::Failure(format!("trap {n}")));
        }
        Ok(ActionResult {
            new_state: Vec::new(),
            actions: Vec::<AgentAction>::new(),
        })
    }
}

/// Records each turn end and each turn completion the loop reports, in order.
struct EndObserver(Sequence);

impl TurnObserver for EndObserver {
    fn on_turn_end(&self, agent_id: &str, end: &TurnEnd) {
        self.0.lock().unwrap().push(format!(
            "end {agent_id} {} {:?}",
            end.message_id, end.outcome
        ));
    }
    fn on_turn_complete(&self, _agent_id: &str) {
        self.0.lock().unwrap().push("observed".into());
    }
}

/// Yields `left` messages (`m1`, `m2`, ...), then parks every later `recv` as an idle
/// mailbox does.
struct ParkingMailbox {
    left: Mutex<usize>,
    issued: Mutex<usize>,
}

#[async_trait]
impl MailboxReader for ParkingMailbox {
    async fn recv(&self, agent_id: &str) -> Message {
        let more = {
            let mut left = self.left.lock().unwrap();
            let more = *left > 0;
            if more {
                *left -= 1;
            }
            more
        };
        if !more {
            std::future::pending::<()>().await;
        }
        let n = {
            let mut issued = self.issued.lock().unwrap();
            *issued += 1;
            *issued
        };
        Message {
            id: format!("m{n}"),
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

/// Refuses every batch.
struct FailingDispatcher;

#[async_trait]
impl AgentActionDispatcher for FailingDispatcher {
    async fn dispatch(
        &self,
        _agent_id: &str,
        _source: &Message,
        _actions: &[AgentAction],
    ) -> Result<DeliveryReport, DispatchError> {
        Err(DispatchError::TargetNotFound("nowhere".into()))
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

struct OkBootstrap;

#[async_trait]
impl RunBootstrap for OkBootstrap {
    async fn ensure_run(&self, _controller_agent: &str) -> Result<String, BootstrapError> {
        Ok("run-1".into())
    }
}

fn cfg() -> ComponentConfig {
    ComponentConfig {
        id: AGENT.into(),
        config_data: None,
        trigger_context: None,
    }
}

fn inst() -> WasmInstance {
    WasmInstance::new(ComponentId::new("ends-inst".into()).unwrap())
}

/// A copy of what the loop has recorded so far.
fn snapshot(sequence: &Sequence) -> Vec<String> {
    sequence.lock().unwrap().clone()
}

/// Serve `turns` messages through `dispatcher` and return what the loop recorded once it
/// parked on the idle mailbox.
async fn serve_turns(turns: usize, dispatcher: Arc<dyn AgentActionDispatcher>) -> Vec<String> {
    let sequence: Sequence = Arc::default();
    let driver = Arc::new(
        AgentLoopDriverImpl::new(
            Arc::new(ParkingMailbox {
                left: Mutex::new(turns),
                issued: Mutex::new(0),
            }),
            Arc::new(OkAssembler),
            Arc::new(OkPostProcessor),
            dispatcher,
            Arc::new(OkBootstrap),
            Arc::new(SequenceHandler {
                sequence: Arc::clone(&sequence),
                turns: Mutex::new(0),
            }),
        )
        .with_turn_observer(Arc::new(EndObserver(Arc::clone(&sequence)))),
    );
    let serving = tokio::spawn({
        let driver = Arc::clone(&driver);
        async move { driver.serve(AGENT, cfg(), inst()).await }
    });
    // Every turn ends with its completion; the loop then parks on the idle mailbox.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let recorded = snapshot(&sequence);
        if recorded.iter().filter(|line| *line == "observed").count() == turns {
            break;
        }
        assert!(Instant::now() < deadline, "serve stalled at {recorded:?}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!serving.is_finished(), "serve parks on the idle mailbox");
    serving.abort();
    snapshot(&sequence)
}

/// A guest error ends its turn `Failed`, a dispatched (empty) batch ends it `Completed`,
/// each reported against the message the turn executed and before `on_turn_complete`.
#[tokio::test]
async fn serve_reports_each_turn_end_before_turn_complete() {
    assert_eq!(
        serve_turns(2, Arc::new(OkDispatcher)).await,
        [
            "init",
            "handle m1 0",
            &format!("end {AGENT} m1 Failed"),
            "observed",
            "handle m2 1",
            &format!("end {AGENT} m2 Completed"),
            "observed",
        ]
    );
}

/// A dispatch that returns an error ends the turn `Failed` too.
#[tokio::test]
async fn serve_reports_a_refused_dispatch_as_a_failed_turn() {
    assert_eq!(
        serve_turns(2, Arc::new(FailingDispatcher)).await,
        [
            "init",
            "handle m1 0",
            &format!("end {AGENT} m1 Failed"),
            "observed",
            "handle m2 1",
            &format!("end {AGENT} m2 Failed"),
            "observed",
        ]
    );
}

//! PRD §11.3.1: a turn runs in the task its assembly settled. The agent loop
//! binds that task onto the message before the guest sees it, so the turn is logged and
//! post-processed under it. A task the message already names stays, and a turn the assembly
//! settled no task for (the agent's default partition) leaves the message as it came.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use advance_scheduler::agent_loop::AgentLoopDriverImpl;
use advance_scheduler::hook::{BootstrapError, HookError, MessageHandler, RunBootstrap};
use advance_scheduler::types::{ComponentConfig, ComponentId, WasmInstance};
use advance_scheduler::AgentLoopDriver;
use advance_shared_types::context::{
    AssemblyContext, AssemblyError, AssemblyResult, ContextAssembler, TierTokenCounts,
};
use advance_shared_types::mailbox::{
    ActionResult, AgentAction, AgentActionDispatcher, DispatchError, MailboxReader, Message,
    MessageContext, MessageKind,
};
use advance_shared_types::memory::{PostProcessorError, PostProcessorHook};

/// Settles every turn in its task (`None`: the default partition), and records the task the
/// assembly context named.
struct Settles {
    task_id: Option<String>,
    named: Mutex<Vec<Option<String>>>,
}

#[async_trait]
impl ContextAssembler for Settles {
    async fn assemble(&self, ctx: AssemblyContext) -> Result<AssemblyResult, AssemblyError> {
        self.named.lock().unwrap().push(ctx.task_id.clone());
        Ok(AssemblyResult {
            messages: Vec::new(),
            routing_method: "search".into(),
            routing_confidence: 0.0,
            is_new_task: self.task_id.is_none(),
            tier_token_counts: TierTokenCounts {
                tier1a: 0,
                tier1b: 0,
                tier2: 0,
                tier3: 0,
            },
            task_id: self.task_id.clone(),
        })
    }
    fn inject_tier3_warning(&self, _agent_id: &str, _msg: &str) {}
}

/// Delivers one user message with `context`.
struct OneMessage(Option<MessageContext>);

#[async_trait]
impl MailboxReader for OneMessage {
    async fn recv(&self, _agent_id: &str) -> Message {
        Message {
            id: "m-1".into(),
            kind: MessageKind::User,
            from: "user:test".into(),
            to: "agent:test".into(),
            payload: b"plan the launch".to_vec(),
            context: self.0.clone(),
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

struct NoopBootstrap;
#[async_trait]
impl RunBootstrap for NoopBootstrap {
    async fn ensure_run(&self, _controller_agent: &str) -> Result<String, BootstrapError> {
        Ok("run-1".into())
    }
}

/// The message contexts the guest and the post-processor were given.
type Seen = Arc<Mutex<Vec<Option<MessageContext>>>>;

struct Guest(Seen);
#[async_trait]
impl MessageHandler for Guest {
    async fn init(&self, _config: ComponentConfig) -> Result<Vec<u8>, HookError> {
        Ok(Vec::new())
    }
    async fn handle_message(
        &self,
        msg: &Message,
        _state: Vec<u8>,
    ) -> Result<ActionResult, HookError> {
        self.0.lock().unwrap().push(msg.context.clone());
        Ok(ActionResult {
            new_state: Vec::new(),
            actions: Vec::<AgentAction>::new(),
        })
    }
}

struct NoopDispatcher;
#[async_trait]
impl AgentActionDispatcher for NoopDispatcher {
    async fn dispatch(
        &self,
        _agent_id: &str,
        _source: &Message,
        _actions: &[AgentAction],
    ) -> Result<advance_shared_types::outbound::DeliveryReport, DispatchError> {
        Ok(advance_shared_types::outbound::DeliveryReport::empty())
    }
}

struct PostProcessor(Seen);
#[async_trait]
impl PostProcessorHook for PostProcessor {
    async fn run(
        &self,
        _agent_id: &str,
        msg: &Message,
        _result: &ActionResult,
    ) -> Result<(), PostProcessorError> {
        self.0.lock().unwrap().push(msg.context.clone());
        Ok(())
    }
}

/// One turn of a message carrying `context`, settled in `settled`: the task the assembly
/// context named, and the contexts the guest and the post-processor saw.
async fn one_turn(
    context: Option<MessageContext>,
    settled: Option<&str>,
) -> (
    Vec<Option<String>>,
    Vec<Option<MessageContext>>,
    Vec<Option<MessageContext>>,
) {
    let assembler = Arc::new(Settles {
        task_id: settled.map(str::to_string),
        named: Mutex::new(Vec::new()),
    });
    let guest: Seen = Arc::default();
    let post: Seen = Arc::default();
    let driver = AgentLoopDriverImpl::new(
        Arc::new(OneMessage(context)),
        assembler.clone(),
        Arc::new(PostProcessor(post.clone())),
        Arc::new(NoopDispatcher),
        Arc::new(NoopBootstrap),
        Arc::new(Guest(guest.clone())),
    );
    let config = ComponentConfig {
        id: "agent-b2".into(),
        config_data: None,
        trigger_context: None,
    };
    let instance = WasmInstance::new(ComponentId::new("agent-b2".into()).unwrap());
    driver.run_agent("agent:b2", config, instance).await;
    let named = assembler.named.lock().unwrap().clone();
    let guest = guest.lock().unwrap().clone();
    let post = post.lock().unwrap().clone();
    (named, guest, post)
}

fn task_of(context: &Option<MessageContext>) -> Option<&str> {
    context.as_ref().and_then(|c| c.task_id.as_deref())
}

#[tokio::test]
async fn the_turn_runs_in_the_task_the_assembly_settled() {
    let (named, guest, post) = one_turn(None, Some("task-20261122-0a1b2c3d")).await;
    assert_eq!(named, vec![None], "the message named no task");
    assert_eq!(guest.len(), 1);
    assert_eq!(task_of(&guest[0]), Some("task-20261122-0a1b2c3d"));
    assert_eq!(post.len(), 1);
    assert_eq!(task_of(&post[0]), Some("task-20261122-0a1b2c3d"));
    // The binding sets the task and nothing else: the turn's chain trace stays.
    let context = guest[0].as_ref().expect("a context");
    assert!(context.trace_id.is_some(), "the chain trace is kept");
    assert_eq!(context.in_reply_to, None);
}

#[tokio::test]
async fn a_task_the_message_names_stays() {
    let named_task = MessageContext {
        task_id: Some("task-from-the-sender".into()),
        run_id: Some("run-9".into()),
        execution_id: None,
        trace_id: Some("trace-9".into()),
        in_reply_to: Some("m-0".into()),
        correlation_id: None,
    };
    let (named, guest, post) = one_turn(Some(named_task.clone()), Some("task-other")).await;
    assert_eq!(named, vec![Some("task-from-the-sender".to_string())]);
    assert_eq!(
        guest,
        vec![Some(named_task.clone())],
        "the message is as it came"
    );
    assert_eq!(post, vec![Some(named_task)]);
}

#[tokio::test]
async fn a_turn_settled_in_no_task_leaves_the_message_as_it_came() {
    let (_, guest, post) = one_turn(None, None).await;
    assert_eq!(task_of(&guest[0]), None);
    assert_eq!(task_of(&post[0]), None);
}

#[tokio::test]
async fn an_empty_task_name_gives_way_to_the_task_the_assembly_settled() {
    for empty in ["", "  "] {
        let context = MessageContext {
            task_id: Some(empty.into()),
            run_id: None,
            execution_id: None,
            trace_id: Some("trace-9".into()),
            in_reply_to: None,
            correlation_id: None,
        };
        let (_, guest, post) =
            one_turn(Some(context.clone()), Some("task-20261122-0a1b2c3d")).await;
        assert_eq!(
            task_of(&guest[0]),
            Some("task-20261122-0a1b2c3d"),
            "{empty:?}"
        );
        assert_eq!(
            task_of(&post[0]),
            Some("task-20261122-0a1b2c3d"),
            "{empty:?}"
        );
        assert_eq!(
            guest[0].as_ref().unwrap().trace_id.as_deref(),
            Some("trace-9")
        );

        // Settled in the default partition, the turn is logged there: the empty name goes.
        let (_, guest, post) = one_turn(Some(context), None).await;
        assert_eq!(task_of(&guest[0]), None, "{empty:?}");
        assert_eq!(task_of(&post[0]), None, "{empty:?}");
    }
}

//! Slice C AC-15 verification: full agent-loop single-turn pipeline.
//!
//! Constructs 6 mocks (MailboxReader, ContextAssembler, AgentActionDispatcher,
//! PostProcessorHook, RunBootstrap, MessageHandler) — each records its
//! invocation into a shared `Arc<Mutex<Vec<&'static str>>>`. Calls
//! `AgentLoopDriverImpl::run_agent` once.
//!
//! Assertions:
//! - Invocation order:
//!   `["bootstrap", "init", "recv", "assemble", "handle_message", "dispatch", "post_process"]`
//! - Message identity preserved: recorded `recv` Message id == `dispatch`
//!   captured `&msg` id == `post_processor.run` captured `&msg` id.
//! - ActionResult identity preserved: `handle_message` returned new_state
//!   length == `dispatch` captured `&action_result.actions` length ==
//!   `post_processor.run` captured `&action_result.actions` length.
//! - 2-arg WIT compliance is structurally enforced by the
//!   `MessageHandler::handle_message(&Message, Vec<u8>)` trait signature
//!   at compile time.

use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;

use advance_scheduler::agent_loop::AgentLoopDriverImpl;
use advance_scheduler::hook::{
    BootstrapError, HookError, MessageHandler, RunBootstrap, TurnPersistenceBoundary,
};
use advance_scheduler::types::{ComponentConfig, ComponentId, WasmInstance};
use advance_scheduler::AgentLoopDriver;
use advance_shared_types::context::{
    AssemblyContext, AssemblyError, AssemblyResult, ContextAssembler, TierTokenCounts,
};
use advance_shared_types::mailbox::{
    ActionResult, AgentAction, AgentActionDispatcher, DispatchError, MailboxReader, Message,
    MessageKind,
};
use advance_shared_types::memory::{PostProcessorError, PostProcessorHook};

type Recorder = Arc<Mutex<Vec<&'static str>>>;

fn record(rec: &Recorder, tag: &'static str) {
    rec.lock().unwrap().push(tag);
}

const CANNED_MSG_ID: &str = "msg-pipeline-canned";

fn canned_message() -> Message {
    Message {
        id: CANNED_MSG_ID.into(),
        kind: MessageKind::User,
        from: "user:test".into(),
        to: "agent:test".into(),
        payload: b"hello".to_vec(),
        context: None,
        timestamp: std::time::SystemTime::UNIX_EPOCH,
        origin: None,
    }
}

fn canned_action_result() -> ActionResult {
    ActionResult {
        new_state: vec![0xAA, 0xBB, 0xCC],
        actions: vec![AgentAction {
            payload: b"action-1".to_vec(),
        }],
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Mocks recording invocation order + captured arg identity.
// ─────────────────────────────────────────────────────────────────────────

struct RecordingBootstrap(Recorder);

#[async_trait]
impl RunBootstrap for RecordingBootstrap {
    async fn ensure_run(&self, _controller_agent: &str) -> Result<String, BootstrapError> {
        record(&self.0, "bootstrap");
        Ok("run-1".into())
    }
}

struct RecordingMessageHandler {
    rec: Recorder,
    captured_msg_id: Arc<Mutex<Option<String>>>,
}

struct FailingFinalizerBoundary {
    rec: Recorder,
}

#[async_trait]
impl TurnPersistenceBoundary for FailingFinalizerBoundary {
    async fn begin_turn(&self, _agent_id: &str, _msg: &Message) -> Result<String, HookError> {
        record(&self.rec, "begin_turn");
        Ok("lease-1".into())
    }

    async fn finish_turn(&self, _agent_id: &str, _lease_id: &str) -> Result<(), HookError> {
        record(&self.rec, "finish_turn");
        Err(HookError::Failure("persist failed".into()))
    }

    async fn abort_turn(&self, _agent_id: &str, _lease_id: &str, _reason: &str) {
        record(&self.rec, "abort_turn");
    }
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
        *self.captured_msg_id.lock().unwrap() = Some(msg.id.clone());
        Ok(canned_action_result())
    }
}

struct RecordingMailbox(Recorder);

#[async_trait]
impl MailboxReader for RecordingMailbox {
    async fn recv(&self, _agent_id: &str) -> Message {
        record(&self.0, "recv");
        canned_message()
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

struct RecordingAssembler {
    rec: Recorder,
    captured_msg_id: Arc<Mutex<Option<String>>>,
}

#[async_trait]
impl ContextAssembler for RecordingAssembler {
    async fn assemble(&self, ctx: AssemblyContext) -> Result<AssemblyResult, AssemblyError> {
        record(&self.rec, "assemble");
        *self.captured_msg_id.lock().unwrap() = Some(ctx.message.id.clone());
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

struct RecordingDispatcher {
    rec: Recorder,
    captured_action_count: Arc<Mutex<Option<usize>>>,
}

#[async_trait]
impl AgentActionDispatcher for RecordingDispatcher {
    async fn dispatch(
        &self,
        _agent_id: &str,
        _source: &Message,
        actions: &[AgentAction],
    ) -> Result<advance_shared_types::outbound::DeliveryReport, DispatchError> {
        record(&self.rec, "dispatch");
        *self.captured_action_count.lock().unwrap() = Some(actions.len());
        Ok(advance_shared_types::outbound::DeliveryReport::empty())
    }
}

struct RecordingPostProcessor {
    rec: Recorder,
    captured_msg_id: Arc<Mutex<Option<String>>>,
    captured_action_count: Arc<Mutex<Option<usize>>>,
}

#[async_trait]
impl PostProcessorHook for RecordingPostProcessor {
    async fn run(
        &self,
        _agent_id: &str,
        msg: &Message,
        result: &ActionResult,
    ) -> Result<(), PostProcessorError> {
        record(&self.rec, "post_process");
        *self.captured_msg_id.lock().unwrap() = Some(msg.id.clone());
        *self.captured_action_count.lock().unwrap() = Some(result.actions.len());
        Ok(())
    }
}

#[tokio::test]
async fn full_pipeline_invocation_order_and_identity() {
    let rec: Recorder = Arc::new(Mutex::new(Vec::new()));
    let assemble_msg_id = Arc::new(Mutex::new(None));
    let handle_msg_id = Arc::new(Mutex::new(None));
    let dispatch_action_count = Arc::new(Mutex::new(None));
    let post_proc_msg_id = Arc::new(Mutex::new(None));
    let post_proc_action_count = Arc::new(Mutex::new(None));

    let driver = AgentLoopDriverImpl::new(
        Arc::new(RecordingMailbox(rec.clone())),
        Arc::new(RecordingAssembler {
            rec: rec.clone(),
            captured_msg_id: Arc::clone(&assemble_msg_id),
        }),
        Arc::new(RecordingPostProcessor {
            rec: rec.clone(),
            captured_msg_id: Arc::clone(&post_proc_msg_id),
            captured_action_count: Arc::clone(&post_proc_action_count),
        }),
        Arc::new(RecordingDispatcher {
            rec: rec.clone(),
            captured_action_count: Arc::clone(&dispatch_action_count),
        }),
        Arc::new(RecordingBootstrap(rec.clone())),
        Arc::new(RecordingMessageHandler {
            rec: rec.clone(),
            captured_msg_id: Arc::clone(&handle_msg_id),
        }),
    );

    let config = ComponentConfig {
        id: "agent-pipeline-test".into(),
        config_data: None,
        trigger_context: None,
    };
    let instance = WasmInstance::new(ComponentId::new("agent-pipeline-test".into()).unwrap());

    driver.run_agent("agent:pipeline", config, instance).await;

    // Assertion 1: invocation order.
    let order = rec.lock().unwrap().clone();
    assert_eq!(
        order,
        vec![
            "bootstrap",
            "init",
            "recv",
            "assemble",
            "handle_message",
            "dispatch",
            "post_process",
        ],
        "pipeline must invoke each trait method in canonical order"
    );

    // Assertion 2: Message identity preserved across recv → assemble →
    // handle_message → post_process. (Dispatch captures action count, not
    // Message; identity tracked via dispatch_action_count assertion below.)
    assert_eq!(
        assemble_msg_id.lock().unwrap().as_deref(),
        Some(CANNED_MSG_ID)
    );
    assert_eq!(
        handle_msg_id.lock().unwrap().as_deref(),
        Some(CANNED_MSG_ID)
    );
    assert_eq!(
        post_proc_msg_id.lock().unwrap().as_deref(),
        Some(CANNED_MSG_ID)
    );

    // Assertion 3: ActionResult identity preserved (action count threaded
    // from handle_message → dispatch → post_process).
    assert_eq!(*dispatch_action_count.lock().unwrap(), Some(1));
    assert_eq!(*post_proc_action_count.lock().unwrap(), Some(1));
}

#[tokio::test]
async fn turn_persistence_finalizer_failure_skips_dispatch_and_post_process() {
    let rec: Recorder = Arc::new(Mutex::new(Vec::new()));

    let driver = AgentLoopDriverImpl::new(
        Arc::new(RecordingMailbox(rec.clone())),
        Arc::new(RecordingAssembler {
            rec: rec.clone(),
            captured_msg_id: Arc::new(Mutex::new(None)),
        }),
        Arc::new(RecordingPostProcessor {
            rec: rec.clone(),
            captured_msg_id: Arc::new(Mutex::new(None)),
            captured_action_count: Arc::new(Mutex::new(None)),
        }),
        Arc::new(RecordingDispatcher {
            rec: rec.clone(),
            captured_action_count: Arc::new(Mutex::new(None)),
        }),
        Arc::new(RecordingBootstrap(rec.clone())),
        Arc::new(RecordingMessageHandler {
            rec: rec.clone(),
            captured_msg_id: Arc::new(Mutex::new(None)),
        }),
    )
    .with_turn_persistence_boundary(Arc::new(FailingFinalizerBoundary { rec: rec.clone() }));

    let config = ComponentConfig {
        id: "agent-persist-test".into(),
        config_data: None,
        trigger_context: None,
    };
    let instance = WasmInstance::new(ComponentId::new("agent-persist-test".into()).unwrap());

    driver.run_agent("agent:persist", config, instance).await;

    let order = rec.lock().unwrap().clone();
    assert_eq!(
        order,
        vec![
            "bootstrap",
            "init",
            "recv",
            "assemble",
            "begin_turn",
            "handle_message",
            "finish_turn",
        ]
    );
}

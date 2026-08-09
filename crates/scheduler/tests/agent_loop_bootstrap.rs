//! Slice B `AgentLoopDriverImpl::run_agent` RunBootstrap wire verification.
//!
//! Mocks the 5 inverted-trait fields + RunBootstrap + (Slice C addition)
//! the MessageHandler; verifies `run_agent` calls `ensure_run` exactly
//! once with the expected `controller_agent` argument as the first step
//! of the pipeline. Slice C: the pipeline continues through the rest of
//! the trait calls (init → recv → assemble → handle_message → dispatch
//! → post_process), so the stubs are cooperative (return canned Ok values).
//! The bootstrap counter + agent_id assertions are preserved.
//!
//! The full single-turn pipeline behavior (invocation order + record
//! equality) is verified separately in `agent_loop_message_pipeline.rs`
//! (Slice C T34 — AC-15).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;

use advance_scheduler::agent_loop::AgentLoopDriverImpl;
use advance_scheduler::hook::{BootstrapError, HookError, MessageHandler, RunBootstrap};
use advance_scheduler::types::{ComponentConfig, ComponentId, WasmInstance};
use advance_scheduler::AgentLoopDriver;
use advance_shared_types::agent_tree::AgentState;
use advance_shared_types::context::{
    AssemblyContext, AssemblyError, AssemblyResult, ContextAssembler, TierTokenCounts,
};
use advance_shared_types::mailbox::ActionResult;
use advance_shared_types::mailbox::{
    AgentAction, AgentActionDispatcher, DispatchError, MailboxReader, Message, MessageKind,
};
use advance_shared_types::memory::{PostProcessorError, PostProcessorHook};

// ─────────────────────────────────────────────────────────────────────────
// Mock RunBootstrap that records each call's controller_agent argument.
// ─────────────────────────────────────────────────────────────────────────

struct RecordingBootstrap {
    count: Arc<AtomicUsize>,
    last_agent: std::sync::Mutex<Option<String>>,
}

impl RecordingBootstrap {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            count: Arc::new(AtomicUsize::new(0)),
            last_agent: std::sync::Mutex::new(None),
        })
    }
}

#[async_trait]
impl RunBootstrap for RecordingBootstrap {
    async fn ensure_run(&self, controller_agent: &str) -> Result<String, BootstrapError> {
        self.count.fetch_add(1, Ordering::Relaxed);
        *self.last_agent.lock().unwrap() = Some(controller_agent.to_string());
        Ok(format!("run-for-{controller_agent}"))
    }
}

/// Failing bootstrap (verifies `run_agent` exits cleanly on bootstrap error).
struct FailingBootstrap;

#[async_trait]
impl RunBootstrap for FailingBootstrap {
    async fn ensure_run(&self, _controller_agent: &str) -> Result<String, BootstrapError> {
        Err(BootstrapError::EnsureRun("simulated failure".into()))
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Cooperative stubs for the pipeline. Slice C: agent-loop runs the full
// single-turn pipeline; stubs return canned Ok values so the post-
// bootstrap steps complete without unreachable!().
// ─────────────────────────────────────────────────────────────────────────

fn canned_message() -> Message {
    Message {
        id: "msg-canned".into(),
        kind: MessageKind::User,
        from: "user:test".into(),
        to: "agent:test".into(),
        payload: Vec::new(),
        context: None,
        timestamp: std::time::SystemTime::UNIX_EPOCH,
        origin: None,
    }
}

struct StubMailbox;

#[async_trait]
impl MailboxReader for StubMailbox {
    async fn recv(&self, _agent_id: &str) -> Message {
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

struct StubAssembler;

#[async_trait]
impl ContextAssembler for StubAssembler {
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

struct StubPostProcessor;

#[async_trait]
impl PostProcessorHook for StubPostProcessor {
    async fn run(
        &self,
        _agent_id: &str,
        _msg: &Message,
        _result: &ActionResult,
    ) -> Result<(), PostProcessorError> {
        Ok(())
    }
}

struct StubDispatcher;

#[async_trait]
impl AgentActionDispatcher for StubDispatcher {
    async fn dispatch(
        &self,
        _agent_id: &str,
        _source: &advance_shared_types::mailbox::Message,
        _actions: &[AgentAction],
    ) -> Result<advance_shared_types::outbound::DeliveryReport, DispatchError> {
        Ok(advance_shared_types::outbound::DeliveryReport::empty())
    }
}

/// Slice C cooperative MessageHandler stub. Returns canned init bytes +
/// canned ActionResult so the pipeline progresses through to dispatch +
/// post_process.
struct StubMessageHandler;

#[async_trait]
impl MessageHandler for StubMessageHandler {
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
            actions: Vec::new(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

fn make_driver(bootstrap: Arc<dyn RunBootstrap>) -> AgentLoopDriverImpl {
    AgentLoopDriverImpl::new(
        Arc::new(StubMailbox),
        Arc::new(StubAssembler),
        Arc::new(StubPostProcessor),
        Arc::new(StubDispatcher),
        bootstrap,
        Arc::new(StubMessageHandler), // Slice C: 6th arg
    )
}

fn dummy_config() -> ComponentConfig {
    ComponentConfig {
        id: "agent-a-component".into(),
        config_data: None,
        trigger_context: None,
    }
}

fn dummy_instance() -> WasmInstance {
    WasmInstance::new(ComponentId::new("agent-a".into()).unwrap())
}

#[tokio::test]
async fn run_agent_invokes_ensure_run_once() {
    let bootstrap = RecordingBootstrap::new();
    let driver = make_driver(bootstrap.clone());
    driver
        .run_agent("agent-a", dummy_config(), dummy_instance())
        .await;
    assert_eq!(bootstrap.count.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn run_agent_passes_agent_id_as_controller() {
    // Round-1 Warning-2 fix: bootstrap receives `agent_id`, NOT
    // `component_config.id`. The two are different identifiers.
    let bootstrap = RecordingBootstrap::new();
    let driver = make_driver(bootstrap.clone());
    driver
        .run_agent("agent-controller-x", dummy_config(), dummy_instance())
        .await;
    let last = bootstrap.last_agent.lock().unwrap();
    assert_eq!(last.as_deref(), Some("agent-controller-x"));
}

#[tokio::test]
async fn run_agent_exits_cleanly_on_bootstrap_failure() {
    // Round-3 Info-3: bootstrap failure path emits eprintln + returns.
    let driver = make_driver(Arc::new(FailingBootstrap));
    // Should not panic; should not hang.
    driver
        .run_agent("agent-fail", dummy_config(), dummy_instance())
        .await;
}

// Suppress the AgentState unused-import warning.
#[allow(dead_code)]
fn _unused_assemblycontext_compat(_: AgentState) {}

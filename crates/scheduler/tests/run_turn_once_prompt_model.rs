//! Stage-C SAT-A (AC-15) — `run_turn_once` now feeds the REAL prompt (UTF-8 of
//! `msg.payload`, 64 KiB-capped) + the driver's configured model into
//! `AssemblyContext`, instead of the empty placeholders. `turn_buffer` stays
//! empty (digest history arrives via MODULE-010's assemble() fold).

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
    MessageKind,
};
use advance_shared_types::memory::{PostProcessorError, PostProcessorHook};

/// Captures `(prompt, model, turn_buffer_len)` from the single assembled ctx.
type Captured = Arc<Mutex<Option<(String, String, usize)>>>;

struct SpyAssembler(Captured);
#[async_trait]
impl ContextAssembler for SpyAssembler {
    async fn assemble(&self, ctx: AssemblyContext) -> Result<AssemblyResult, AssemblyError> {
        *self.0.lock().unwrap() =
            Some((ctx.prompt.clone(), ctx.model.clone(), ctx.turn_buffer.len()));
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

struct PayloadMailbox(Vec<u8>);
#[async_trait]
impl MailboxReader for PayloadMailbox {
    async fn recv(&self, _agent_id: &str) -> Message {
        Message {
            id: "m".into(),
            kind: MessageKind::User,
            from: "user:test".into(),
            to: "agent:test".into(),
            payload: self.0.clone(),
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

struct NoopBootstrap;
#[async_trait]
impl RunBootstrap for NoopBootstrap {
    async fn ensure_run(&self, _controller_agent: &str) -> Result<String, BootstrapError> {
        Ok("run-1".into())
    }
}

struct NoopHandler;
#[async_trait]
impl MessageHandler for NoopHandler {
    async fn init(&self, _config: ComponentConfig) -> Result<Vec<u8>, HookError> {
        Ok(vec![0x42])
    }
    async fn handle_message(
        &self,
        _msg: &Message,
        _state: Vec<u8>,
    ) -> Result<ActionResult, HookError> {
        Ok(ActionResult {
            new_state: vec![0x01],
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

struct NoopPostProcessor;
#[async_trait]
impl PostProcessorHook for NoopPostProcessor {
    async fn run(
        &self,
        _agent_id: &str,
        _msg: &Message,
        _result: &ActionResult,
    ) -> Result<(), PostProcessorError> {
        Ok(())
    }
}

fn driver_with(payload: Vec<u8>, captured: Captured) -> AgentLoopDriverImpl {
    AgentLoopDriverImpl::new(
        Arc::new(PayloadMailbox(payload)),
        Arc::new(SpyAssembler(captured)),
        Arc::new(NoopPostProcessor),
        Arc::new(NoopDispatcher),
        Arc::new(NoopBootstrap),
        Arc::new(NoopHandler),
    )
}

fn component() -> (ComponentConfig, WasmInstance) {
    (
        ComponentConfig {
            id: "agent-t8".into(),
            config_data: None,
            trigger_context: None,
        },
        WasmInstance::new(ComponentId::new("agent-t8".into()).unwrap()),
    )
}

#[tokio::test]
async fn feeds_real_prompt_and_configured_model() {
    let captured: Captured = Arc::new(Mutex::new(None));
    let driver = driver_with(b"hello world".to_vec(), captured.clone())
        .with_model("claude-3-5-sonnet-20241022".to_string());
    let (cfg, inst) = component();
    driver.run_agent("agent:t8", cfg, inst).await;

    let (prompt, model, tb_len) = captured.lock().unwrap().clone().expect("assemble ran");
    assert_eq!(prompt, "hello world", "prompt = UTF-8 of msg.payload");
    assert_eq!(
        model, "claude-3-5-sonnet-20241022",
        "model = with_model value"
    );
    assert_eq!(
        tb_len, 0,
        "turn_buffer stays empty (no in-process history store)"
    );
}

#[tokio::test]
async fn default_model_is_empty_and_non_utf8_payload_is_lossy() {
    let captured: Captured = Arc::new(Mutex::new(None));
    // No with_model → empty model (harness-neutral). Invalid UTF-8 bytes →
    // lossy decode (no panic).
    let driver = driver_with(vec![0xff, 0xfe, b'h', b'i'], captured.clone());
    let (cfg, inst) = component();
    driver.run_agent("agent:t8", cfg, inst).await;

    let (prompt, model, _) = captured.lock().unwrap().clone().expect("assemble ran");
    assert_eq!(
        model, "",
        "no with_model → empty default model (harness-neutral)"
    );
    assert!(
        prompt.ends_with("hi"),
        "non-UTF8 payload lossy-decodes without panic: {prompt:?}"
    );
}

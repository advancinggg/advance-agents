//! MODULE-014-AC-25 (029) — agent-loop trap policy.
//!
//! On a guest trap (`HookError::Failure` from `handle_message`), `run_turn_once`
//! routes to `AgentLoopDriverImpl::handle_trap`, which (1) emits a `component.error`
//! EventBus event via the injected emitter and (2) applies the configured
//! `RestartPolicy` via `restart_decision(policy, false)`, surfacing the decision to
//! the serve loop through an interior stop cell. `serve` / `serve_n_turns` break on
//! `RestartDecision::Stop` (Never) and continue on `Restart` (OnFailure/Always);
//! the `None` default preserves the prior continue-on-trap behaviour.
//!
//! Gated `required-features = ["test-support"]` (drives the bounded `serve_n_turns`).
//! The full wired SYS-AC-029 e2e witness is the harvest's (this is the crate floor).

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use advance_scheduler::agent_loop::AgentLoopDriverImpl;
use advance_scheduler::hook::{
    BootstrapError, CrashCascadeSink, HookError, MessageHandler, RunBootstrap,
};
use advance_scheduler::types::{
    ComponentConfig, ComponentId, RestartPolicy, TrapError, WasmInstance,
};
use advance_shared_types::context::{
    AssemblyContext, AssemblyError, AssemblyResult, ContextAssembler, TierTokenCounts,
};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{
    ActionResult, AgentAction, AgentActionDispatcher, DispatchError, MailboxReader, Message,
    MessageKind,
};
use advance_shared_types::memory::{PostProcessorError, PostProcessorHook};
use advance_shared_types::outbound::DeliveryReport;
use advance_shared_types::traits::EventBusEmit;

/// Handler whose every `handle_message` traps (maps to `HookError::Failure`, the
/// trap-equivalent surface `run_turn_once` routes to `handle_trap`).
struct TrappingHandler {
    handle_calls: Arc<Mutex<usize>>,
}
#[async_trait]
impl MessageHandler for TrappingHandler {
    async fn init(&self, _config: ComponentConfig) -> Result<Vec<u8>, HookError> {
        Ok(vec![0])
    }
    async fn handle_message(
        &self,
        _msg: &Message,
        _state: Vec<u8>,
    ) -> Result<ActionResult, HookError> {
        *self.handle_calls.lock().unwrap() += 1;
        Err(HookError::Failure("boom-trap".into()))
    }
}

/// EventBus emitter that records every emitted event.
struct RecordingBus {
    events: Arc<Mutex<Vec<Event>>>,
}
impl EventBusEmit for RecordingBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

/// Wave-18 recording crash-cascade sink: records every `(agent_id, reason)` pair
/// `handle_trap` cascades. The production sink (cli `build_crash_cascade_sink`)
/// drives the real cap-lifecycle `handle_crash`; here we only assert the scheduler
/// seam fires on the right trap variant with the right args.
struct RecordingCrashSink {
    records: Arc<Mutex<Vec<(String, String)>>>,
}
impl CrashCascadeSink for RecordingCrashSink {
    fn handle_crash(&self, agent_id: &str, reason: &str) {
        self.records
            .lock()
            .unwrap()
            .push((agent_id.to_string(), reason.to_string()));
    }
}

/// Mailbox that always yields a canned message (so `serve_n_turns` is bounded only
/// by `n` / the stop cell, not by message availability).
struct YieldMailbox;
#[async_trait]
impl MailboxReader for YieldMailbox {
    async fn recv(&self, agent_id: &str) -> Message {
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

struct OkBootstrap;
#[async_trait]
impl RunBootstrap for OkBootstrap {
    async fn ensure_run(&self, _controller_agent: &str) -> Result<String, BootstrapError> {
        Ok("run-1".into())
    }
}

fn build(
    handle_calls: Arc<Mutex<usize>>,
    events: Arc<Mutex<Vec<Event>>>,
    wire_emitter: bool,
    policy: Option<RestartPolicy>,
) -> AgentLoopDriverImpl {
    let mut driver = AgentLoopDriverImpl::new(
        Arc::new(YieldMailbox),
        Arc::new(OkAssembler),
        Arc::new(OkPostProcessor),
        Arc::new(OkDispatcher),
        Arc::new(OkBootstrap),
        Arc::new(TrappingHandler { handle_calls }),
    );
    if wire_emitter {
        let bus: Arc<dyn EventBusEmit> = Arc::new(RecordingBus { events });
        driver = driver.with_component_error_emitter(bus);
    }
    if let Some(p) = policy {
        driver = driver.with_restart_policy(p);
    }
    driver
}

fn cfg() -> ComponentConfig {
    ComponentConfig {
        id: "agent:trap".into(),
        config_data: None,
        trigger_context: None,
    }
}
fn inst() -> WasmInstance {
    WasmInstance::new(ComponentId::new("trap-inst".into()).unwrap())
}

/// T-029a: a trapped turn emits exactly one `component.error` event carrying the
/// component id, the `hook-failure` error_type, and the echoed trap reason.
#[tokio::test]
async fn t029a_trap_emits_component_error() {
    let calls = Arc::new(Mutex::new(0usize));
    let events = Arc::new(Mutex::new(Vec::new()));
    let driver = build(calls, events.clone(), true, Some(RestartPolicy::OnFailure));
    driver.serve_n_turns("agent:trap", cfg(), inst(), 1).await;

    let ev = events.lock().unwrap();
    assert_eq!(ev.len(), 1, "exactly one component.error per trapped turn");
    assert_eq!(ev[0].event_type, "component.error");
    assert_eq!(ev[0].agent_id, "agent:trap");
    assert_eq!(ev[0].payload["error_type"], "hook-failure");
    assert!(
        ev[0].payload["message"]
            .as_str()
            .unwrap_or_default()
            .contains("boom-trap"),
        "the trap reason is echoed into the component.error payload"
    );
}

/// T-029b: `serve_n_turns` honors the trap RestartPolicy via the stop cell —
/// `Never` breaks after the first trap; `OnFailure`/`Always`/`None` run all n.
#[tokio::test]
async fn t029b_serve_n_turns_honors_restart_policy() {
    // Never → Stop → break after the FIRST trapped turn (1 of 5).
    let calls = Arc::new(Mutex::new(0usize));
    let events = Arc::new(Mutex::new(Vec::new()));
    let driver = build(
        calls.clone(),
        events.clone(),
        true,
        Some(RestartPolicy::Never),
    );
    driver.serve_n_turns("agent:trap", cfg(), inst(), 5).await;
    assert_eq!(
        *calls.lock().unwrap(),
        1,
        "Never → serve loop breaks after the first trap"
    );
    assert_eq!(
        events.lock().unwrap().len(),
        1,
        "one component.error before the break"
    );

    // OnFailure → Restart → all 5 turns run.
    let calls = Arc::new(Mutex::new(0usize));
    let events = Arc::new(Mutex::new(Vec::new()));
    let driver = build(
        calls.clone(),
        events.clone(),
        true,
        Some(RestartPolicy::OnFailure),
    );
    driver.serve_n_turns("agent:trap", cfg(), inst(), 5).await;
    assert_eq!(
        *calls.lock().unwrap(),
        5,
        "OnFailure → all 5 turns run (continue on trap)"
    );
    assert_eq!(
        events.lock().unwrap().len(),
        5,
        "one component.error per trapped turn"
    );

    // Always → Restart → all 5 turns run.
    let calls = Arc::new(Mutex::new(0usize));
    let driver = build(
        calls.clone(),
        Arc::new(Mutex::new(Vec::new())),
        true,
        Some(RestartPolicy::Always),
    );
    driver.serve_n_turns("agent:trap", cfg(), inst(), 5).await;
    assert_eq!(*calls.lock().unwrap(), 5, "Always → all 5 turns run");

    // None (default) + no emitter → prior behaviour: all 5 turns, no emit, no break.
    let calls = Arc::new(Mutex::new(0usize));
    let driver = build(calls.clone(), Arc::new(Mutex::new(Vec::new())), false, None);
    driver.serve_n_turns("agent:trap", cfg(), inst(), 5).await;
    assert_eq!(
        *calls.lock().unwrap(),
        5,
        "None policy (default) preserves the prior infinite-serve-on-trap behaviour"
    );
}

/// MODULE-014-T-029c (Wave-18): `handle_trap` invokes the injected `CrashCascadeSink`
/// on a trap (Crash) routed through the real `run_turn_once` exactly once with
/// `(agent_id, reason)`; a cooperative `Cancelled` does NOT; and the default-`None` (no
/// sink) path is byte-identical. (This scheduler-crate test uses the mock `TrappingHandler`
/// — the `Err(Failure)`→`Crash` surface `run_turn_once` routes to `handle_trap`; the REAL
/// WASM guest trap end-to-end is the system-acceptance `sys_ac_030_*` witness.)
#[tokio::test]
async fn t029c_crash_cascade_sink_on_crash_only() {
    // (a) REAL run_turn_once → handle_trap(Crash) → sink, via the public serve API.
    // `Never` breaks after the first trap, so the single trapped turn cascades once.
    let calls = Arc::new(Mutex::new(0usize));
    let records = Arc::new(Mutex::new(Vec::new()));
    let sink: Arc<dyn CrashCascadeSink> = Arc::new(RecordingCrashSink {
        records: records.clone(),
    });
    let driver = build(
        calls.clone(),
        Arc::new(Mutex::new(Vec::new())),
        false,
        Some(RestartPolicy::Never),
    )
    .with_crash_cascade(sink);
    driver.serve_n_turns("agent:trap", cfg(), inst(), 5).await;
    {
        let rec = records.lock().unwrap();
        assert_eq!(
            rec.len(),
            1,
            "exactly one crash cascade for the single trapped turn"
        );
        assert_eq!(
            rec[0].0, "agent:trap",
            "the served (colon) agent id is cascaded verbatim"
        );
        assert_eq!(
            rec[0].1, "boom-trap",
            "the real guest trap reason is cascaded verbatim"
        );
    }
    assert_eq!(
        *calls.lock().unwrap(),
        1,
        "Never policy still breaks after the first trap"
    );

    // (b) Cancelled discriminator — a cooperative cancel is NOT a crash, so no cascade.
    // `run_turn_once` only ever produces Crash, so drive the Cancelled arm directly via
    // the test-support accessor (proves the Crash-only filter is load-bearing).
    let records = Arc::new(Mutex::new(Vec::new()));
    let sink: Arc<dyn CrashCascadeSink> = Arc::new(RecordingCrashSink {
        records: records.clone(),
    });
    let driver = build(
        Arc::new(Mutex::new(0usize)),
        Arc::new(Mutex::new(Vec::new())),
        false,
        None,
    )
    .with_crash_cascade(sink);
    driver
        .handle_trap_for_test("agent:trap", TrapError::Cancelled)
        .await;
    assert!(
        records.lock().unwrap().is_empty(),
        "a cooperative Cancelled is NOT a crash → no parent crash-report cascade"
    );
    // Same driver DOES cascade on a direct Crash → the gate is on the variant, not the call site.
    driver
        .handle_trap_for_test("agent:trap", TrapError::Crash("direct".into()))
        .await;
    {
        let rec = records.lock().unwrap();
        assert_eq!(rec.len(), 1, "a Crash cascades once");
        assert_eq!(rec[0].1, "direct", "the Crash reason is cascaded verbatim");
    }

    // (c) default-None discriminator — no sink wired → serve completes, no panic,
    // trap policy unchanged (byte-identical to pre-Wave-18 handle_trap).
    let calls = Arc::new(Mutex::new(0usize));
    let driver = build(
        calls.clone(),
        Arc::new(Mutex::new(Vec::new())),
        false,
        Some(RestartPolicy::Never),
    );
    driver.serve_n_turns("agent:trap", cfg(), inst(), 3).await;
    assert_eq!(
        *calls.lock().unwrap(),
        1,
        "None crash_sink leaves the Never-policy trap path unchanged"
    );
}

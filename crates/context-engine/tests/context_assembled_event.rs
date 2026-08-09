//! AC-12 (MODULE-010-T16) — `context.assembled` event emission.
//!
//! 8 sub-cases: (1) emit exactly once per assemble(); (2) event_type ==
//! "context.assembled"; (3) payload tier_token_counts matches AssemblyResult;
//! (4) payload routing fields match; (5) Event.agent_id+task_id match ctx;
//! (6) task_id=None vs Some yields different is_new_task; (7) Event.id +
//! trace_id non-empty + differ across consecutive emits (uuid uniqueness);
//! (8) varying inputs → varying payload tier_token_counts.

use std::sync::{Arc, Mutex};

use advance_context_engine::ContextAssemblerImpl;
use advance_shared_types::context::{ContextAssembler, LlmMessage};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;

#[path = "common/mod.rs"]
mod common;
use common::*;

// ─── capturing spy EventBus ───

#[derive(Clone, Default)]
struct SpyEventBus {
    events: Arc<Mutex<Vec<Event>>>,
}
impl EventBusEmit for SpyEventBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

/// Build an assembler wired to `spy` (all other deps are common Null doubles).
fn build_with_spy(spy: SpyEventBus) -> ContextAssemblerImpl {
    ContextAssemblerImpl::new(
        Arc::new(MockCallableInventory::default()),
        Arc::new(MockHostFnInventory::default()),
        Arc::new(NullAgentIdentity),
        Arc::new(NullKnowledgeMap),
        Arc::new(NullAgentTreeSnapshot),
        Arc::new(NullEmbedding),
        Arc::new(NullTaskIndex),
        Arc::new(NullLightLlm),
        Arc::new(NullUnifiedSearch),
        Arc::new(spy),
        Arc::new(NullSkillSummary),
        Arc::new(NullVectorIndex),
        Arc::new(NullL2Digest),
        Arc::new(NullL3Epoch),
        Arc::new(NullL4TaskSummary),
        Arc::new(NullL5Synthesis),
        Arc::new(NullL6Consolidation),
        Arc::new(NullPromptInjectionHelpers),
        Arc::new(NullDecomposition),
    )
}

// ─── (1)+(2)+(3)+(4)+(5) one emit, schema + value pass-through ───

#[tokio::test]
async fn emits_one_context_assembled_event_matching_result() {
    let spy = SpyEventBus::default();
    let asm = build_with_spy(spy.clone());

    let result = asm.assemble(stub_ctx()).await.unwrap();

    let events = spy.events.lock().unwrap();
    // (1) exactly once.
    assert_eq!(events.len(), 1);
    let ev = &events[0];
    // (2) event_type.
    assert_eq!(ev.event_type, "context.assembled");
    // (3) payload tier_token_counts matches the returned AssemblyResult.
    let expected_ttc = serde_json::to_value(&result.tier_token_counts).unwrap();
    assert_eq!(ev.payload["tier_token_counts"], expected_ttc);
    // (4) routing fields match.
    assert_eq!(
        ev.payload["routing_method"],
        serde_json::json!(result.routing_method)
    );
    assert_eq!(
        ev.payload["routing_confidence"].as_f64().unwrap() as f32,
        result.routing_confidence
    );
    assert_eq!(
        ev.payload["is_new_task"],
        serde_json::json!(result.is_new_task)
    );
    // (5) agent_id + task_id match the context.
    assert_eq!(ev.agent_id, "agent-default");
    assert_eq!(ev.task_id, None);
}

// ─── (6) task_id=None vs Some yields different is_new_task ───

#[tokio::test]
async fn task_id_presence_changes_is_new_task_in_payload() {
    // task_id = None → router runs over the NullTaskIndex (no hits) → NewTask
    // → is_new_task = true.
    let spy_none = SpyEventBus::default();
    let asm_none = build_with_spy(spy_none.clone());
    asm_none.assemble(stub_ctx()).await.unwrap();
    let ev_none_is_new = spy_none.events.lock().unwrap()[0].payload["is_new_task"]
        .as_bool()
        .unwrap();

    // task_id = Some → assembler short-circuits is_new_task = false.
    let spy_some = SpyEventBus::default();
    let asm_some = build_with_spy(spy_some.clone());
    let mut ctx_some = stub_ctx();
    ctx_some.task_id = Some("task-existing".into());
    asm_some.assemble(ctx_some).await.unwrap();
    let events_some = spy_some.events.lock().unwrap();
    let ev_some_is_new = events_some[0].payload["is_new_task"].as_bool().unwrap();
    // task_id is threaded into the event.
    assert_eq!(events_some[0].task_id, Some("task-existing".into()));

    assert!(
        ev_none_is_new,
        "task_id=None should derive is_new_task=true"
    );
    assert!(
        !ev_some_is_new,
        "task_id=Some should yield is_new_task=false"
    );
    assert_ne!(ev_none_is_new, ev_some_is_new);
}

// ─── (7) Event.id + trace_id non-empty + differ across consecutive emits ───

#[tokio::test]
async fn event_id_and_trace_id_are_unique_per_emit() {
    let spy = SpyEventBus::default();
    let asm = build_with_spy(spy.clone());

    asm.assemble(stub_ctx()).await.unwrap();
    asm.assemble(stub_ctx()).await.unwrap();

    let events = spy.events.lock().unwrap();
    assert_eq!(events.len(), 2);
    assert!(!events[0].id.is_empty());
    assert!(!events[0].trace_id.is_empty());
    // uuid v4 → two consecutive emits differ.
    assert_ne!(events[0].id, events[1].id);
    assert_ne!(events[0].trace_id, events[1].trace_id);
    // id and trace_id are independent within one event.
    assert_ne!(events[0].id, events[0].trace_id);
}

// ─── T3 (Stage-F obs SLICE 1): context.assembled threads the handle-message chain ───

#[tokio::test]
async fn context_assembled_threads_chain_trace_and_root_span() {
    use advance_shared_types::event::chain_root_span_id;
    use advance_shared_types::mailbox::MessageContext;

    let spy = SpyEventBus::default();
    let asm = build_with_spy(spy.clone());

    // A turn whose inbound message already carries the chain trace (as minted at
    // run_turn_once) and a known message id.
    let mut ctx = stub_ctx();
    ctx.message.id = "msg-CHAIN".into();
    ctx.message.context = Some(MessageContext {
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: Some("chain-trace-T".into()),
        in_reply_to: None,
        correlation_id: None,
    });

    asm.assemble(ctx).await.unwrap();

    let events = spy.events.lock().unwrap();
    assert_eq!(events.len(), 1);
    let ev = &events[0];
    assert_eq!(ev.event_type, "context.assembled");
    // 137 — shares the chain trace from msg.context.
    assert_eq!(
        ev.trace_id, "chain-trace-T",
        "context.assembled must carry the chain trace_id"
    );
    // 138 root — span_id is the deterministic chain-root span (NOT the old literal).
    assert_eq!(
        ev.span_id,
        chain_root_span_id("msg-CHAIN"),
        "context.assembled.span_id must be the deterministic chain-root span"
    );
    assert_ne!(
        ev.span_id, "context-assembled",
        "the fixed literal must be gone"
    );
    // It is the chain ROOT → no parent.
    assert!(
        ev.parent_span_id.is_none(),
        "context.assembled is the chain root (no parent)"
    );
}

// ─── (8) varying inputs → varying payload tier_token_counts ───

#[tokio::test]
async fn varying_inputs_change_payload_tier_token_counts() {
    // Empty turn_buffer.
    let spy_empty = SpyEventBus::default();
    let asm_empty = build_with_spy(spy_empty.clone());
    asm_empty.assemble(stub_ctx()).await.unwrap();
    let ttc_empty = spy_empty.events.lock().unwrap()[0].payload["tier_token_counts"].clone();

    // turn_buffer with content → larger tier3.
    let spy_big = SpyEventBus::default();
    let asm_big = build_with_spy(spy_big.clone());
    let mut ctx_big = stub_ctx();
    ctx_big.turn_buffer = vec![LlmMessage {
        role: "user".into(),
        content: "a turn-buffer message long enough to move the tier3 token count".into(),
    }];
    asm_big.assemble(ctx_big).await.unwrap();
    let ttc_big = spy_big.events.lock().unwrap()[0].payload["tier_token_counts"].clone();

    // The schema is wired to real values, not hardcoded constants.
    assert_ne!(
        ttc_empty, ttc_big,
        "tier_token_counts in the emitted payload must reflect actual input size"
    );
    assert!(ttc_big["tier3"].as_u64().unwrap() > ttc_empty["tier3"].as_u64().unwrap());
}

// ─── invalid agent_id → no AssemblyResult → no event emitted ───

#[tokio::test]
async fn invalid_agent_id_emits_no_event() {
    let spy = SpyEventBus::default();
    let asm = build_with_spy(spy.clone());

    let mut ctx = stub_ctx();
    ctx.agent_id = "../etc/passwd".into(); // fails the CONTRACT-090 invariant-4 whitelist

    let result = asm.assemble(ctx).await;
    assert!(result.is_err(), "invalid agent_id must be rejected");
    // The event is emitted only AFTER a successful AssemblyResult is built; a
    // rejected agent_id short-circuits before that, so NO event fires.
    assert!(
        spy.events.lock().unwrap().is_empty(),
        "no context.assembled event may be emitted when assembly is rejected"
    );
}

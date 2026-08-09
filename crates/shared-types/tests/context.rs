//! Serde + wire-format tests for `advance_shared_types::context`.

use advance_shared_types::agent_tree::{AgentState, AgentStatus};
use advance_shared_types::context::{
    AssemblyContext, AssemblyError, AssemblyResult, LlmMessage, TierTokenCounts,
};
use advance_shared_types::mailbox::{Message, MessageKind};
use std::time::{Duration, UNIX_EPOCH};

fn sample_state() -> AgentState {
    AgentState {
        agent_id: "agent:root".to_string(),
        status: AgentStatus::Active,
        current_task_id: None,
        current_run_id: None,
        iteration: 0,
        turn_counter: 0,
        last_handle_message_at: None,
    }
}

fn sample_message() -> Message {
    Message {
        id: "m1".to_string(),
        kind: MessageKind::User,
        from: "user:alice".to_string(),
        to: "agent:root".to_string(),
        payload: b"hello".to_vec(),
        context: None,
        timestamp: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        origin: None,
    }
}

#[test]
fn llm_message_round_trip() {
    let m = LlmMessage {
        role: "user".to_string(),
        content: "hello".to_string(),
    };
    let json = serde_json::to_string(&m).unwrap();
    let back: LlmMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(back, m);
}

#[test]
fn llm_message_deny_unknown_fields() {
    let bad = r#"{"role":"x","content":"y","extra":true}"#;
    let err = serde_json::from_str::<LlmMessage>(bad).unwrap_err();
    assert_eq!(err.classify(), serde_json::error::Category::Data);
}

#[test]
fn tier_token_counts_round_trip() {
    let t = TierTokenCounts {
        tier1a: 5,
        tier1b: 10,
        tier2: 20,
        tier3: 30,
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: TierTokenCounts = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
}

#[test]
fn tier_token_counts_deny_unknown_fields() {
    let bad = r#"{"tier1a":0,"tier1b":0,"tier2":0,"tier3":0,"extra":true}"#;
    let err = serde_json::from_str::<TierTokenCounts>(bad).unwrap_err();
    assert_eq!(err.classify(), serde_json::error::Category::Data);
}

#[test]
fn assembly_error_round_trip() {
    for e in [
        AssemblyError::BudgetExhausted("x".to_string()),
        AssemblyError::EmbeddingFailed("e".to_string()),
        AssemblyError::MemoryStoreFailure("m".to_string()),
    ] {
        let json = serde_json::to_string(&e).unwrap();
        let back: AssemblyError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);
    }
}

#[test]
fn assembly_context_round_trip() {
    let ctx = AssemblyContext {
        agent_id: "agent:root".to_string(),
        task_id: Some("t1".to_string()),
        message: sample_message(),
        prompt: "summarize Q3".to_string(),
        model: "claude-opus-4-7".to_string(),
        turn_buffer: vec![],
        prior_state: sample_state(),
    };
    let json = serde_json::to_string(&ctx).unwrap();
    let back: AssemblyContext = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ctx);
}

#[test]
fn assembly_result_round_trip() {
    let r = AssemblyResult {
        messages: vec![LlmMessage {
            role: "system".to_string(),
            content: "be helpful".to_string(),
        }],
        routing_method: "search".to_string(),
        routing_confidence: 0.75,
        is_new_task: true,
        tier_token_counts: TierTokenCounts {
            tier1a: 5,
            tier1b: 3,
            tier2: 10,
            tier3: 2,
        },
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: AssemblyResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

//! Serde + wire-format tests for `advance_shared_types::await_session`.

use advance_shared_types::await_session::{
    AwaitTreeSummary, OrchestrationError, SessionId, SessionSummary,
};
use std::collections::HashMap;

#[test]
fn session_id_is_transparent_bare_string() {
    let id = SessionId("s1".to_string());
    let json = serde_json::to_string(&id).unwrap();
    assert_eq!(json, "\"s1\"");
    let back: SessionId = serde_json::from_str(&json).unwrap();
    assert_eq!(back, id);
}

#[test]
fn session_id_is_hashmap_key() {
    let mut m: HashMap<SessionId, u32> = HashMap::new();
    m.insert(SessionId("s1".to_string()), 1);
    assert_eq!(m.get(&SessionId("s1".to_string())), Some(&1));
}

#[test]
fn orchestration_error_round_trip() {
    for e in [
        OrchestrationError::CapabilityDenied("x".to_string()),
        OrchestrationError::InvalidTarget("x".to_string()),
        OrchestrationError::DeadlockDetected("x".to_string()),
        OrchestrationError::SessionLimitExceeded("x".to_string()),
        OrchestrationError::SessionClosed("x".to_string()),
        OrchestrationError::IdleTimeoutExceeded("x".to_string()),
        OrchestrationError::NotFound("x".to_string()),
        OrchestrationError::InvalidRequest("x".to_string()),
        OrchestrationError::Downstream("x".to_string()),
    ] {
        let json = serde_json::to_string(&e).unwrap();
        let back: OrchestrationError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);
    }
}

#[test]
fn session_summary_round_trip() {
    let s = SessionSummary {
        session_id: "s1".to_string(),
        parent_session_id: None,
        agent_id: "agent:root".to_string(),
        mode: "all_of".to_string(),
        expected: 3,
        received: 1,
        status: "pending".to_string(),
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: SessionSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
}

#[test]
fn session_summary_deny_unknown_fields() {
    let bad = r#"{"session_id":"x","parent_session_id":null,"agent_id":"a","mode":"m","expected":0,"received":0,"status":"p","extra":true}"#;
    let err = serde_json::from_str::<SessionSummary>(bad).unwrap_err();
    assert_eq!(err.classify(), serde_json::error::Category::Data);
}

#[test]
fn await_tree_summary_round_trip() {
    let t = AwaitTreeSummary {
        depth: 2,
        total_sessions: 3,
        pending_replies: 1,
        sessions: vec![],
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: AwaitTreeSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
}

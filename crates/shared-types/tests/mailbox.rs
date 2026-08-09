//! Serde + wire-format + deny_unknown_fields tests for `advance_shared_types::mailbox`.

use advance_shared_types::mailbox::{
    ActionResult, AgentAction, DispatchError, Message, MessageContext, MessageKind, MessageOrigin,
    MsgError,
};
use advance_shared_types::security_validator::SecurityError;
use chrono::{TimeZone, Utc};
use std::collections::HashMap;
use std::time::{Duration, UNIX_EPOCH};

#[test]
fn message_kind_round_trip() {
    for k in [
        MessageKind::User,
        MessageKind::Agent,
        MessageKind::Control,
        MessageKind::Auto,
        MessageKind::System,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let back: MessageKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, k);
    }
}

#[test]
fn message_kind_wire_format_lock() {
    assert_eq!(
        serde_json::to_string(&MessageKind::User).unwrap(),
        "\"User\""
    );
    assert_eq!(
        serde_json::to_string(&MessageKind::Agent).unwrap(),
        "\"Agent\""
    );
    assert_eq!(
        serde_json::to_string(&MessageKind::Control).unwrap(),
        "\"Control\""
    );
    assert_eq!(
        serde_json::to_string(&MessageKind::Auto).unwrap(),
        "\"Auto\""
    );
    assert_eq!(
        serde_json::to_string(&MessageKind::System).unwrap(),
        "\"System\""
    );
}

#[test]
fn message_context_round_trip() {
    let ctx = MessageContext {
        task_id: Some("t1".to_string()),
        run_id: None,
        execution_id: None,
        trace_id: Some("tr1".to_string()),
        in_reply_to: None,
        correlation_id: Some("c1".to_string()),
    };
    let json = serde_json::to_string(&ctx).unwrap();
    let back: MessageContext = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ctx);
}

#[test]
fn message_context_deny_unknown_fields() {
    let bad = r#"{"task_id":null,"run_id":null,"execution_id":null,"trace_id":null,"in_reply_to":null,"correlation_id":null,"extra":true}"#;
    let err = serde_json::from_str::<MessageContext>(bad).unwrap_err();
    assert_eq!(err.classify(), serde_json::error::Category::Data);
}

#[test]
fn message_origin_round_trip() {
    let o = MessageOrigin {
        message_id: "m1".to_string(),
        original_channel: "telegram".to_string(),
        original_sender: "telegram:1234567".to_string(),
        adapter_id: "tg-main".to_string(),
        channel_metadata: HashMap::new(),
        received_at: Utc.with_ymd_and_hms(2026, 4, 18, 17, 0, 0).unwrap(),
        context: None,
    };
    let json = serde_json::to_string(&o).unwrap();
    let back: MessageOrigin = serde_json::from_str(&json).unwrap();
    assert_eq!(back, o);
}

#[test]
fn message_round_trip_asymmetric_timestamps() {
    let msg = Message {
        id: "m1".to_string(),
        kind: MessageKind::Agent,
        from: "agent:parent".to_string(),
        to: "agent:child".to_string(),
        payload: b"hello".to_vec(),
        context: None,
        timestamp: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        origin: None,
    };
    let json = serde_json::to_string(&msg).unwrap();
    // timestamp (SystemTime) serializes as struct; received_at (DateTime<Utc>) serializes as ISO-8601.
    // Asymmetry is canonical-by-design per Slice AC v2 plan §3.11.
    assert!(json.contains("secs_since_epoch") || json.contains("secs"));
    let back: Message = serde_json::from_str(&json).unwrap();
    assert_eq!(back, msg);
}

#[test]
fn msg_error_round_trip() {
    for e in [
        MsgError::InvalidTarget("x".to_string()),
        MsgError::MailboxFull,
        MsgError::CircuitBreakerOpen("reason".to_string()),
        MsgError::CapabilityDenied("cap".to_string()),
        MsgError::InvalidPayload("size".to_string()),
    ] {
        let json = serde_json::to_string(&e).unwrap();
        let back: MsgError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);
    }
}

#[test]
fn agent_action_round_trip() {
    let a = AgentAction {
        payload: vec![1, 2, 3],
    };
    let json = serde_json::to_string(&a).unwrap();
    let back: AgentAction = serde_json::from_str(&json).unwrap();
    assert_eq!(back, a);
}

#[test]
fn agent_action_deny_unknown_fields() {
    let bad = r#"{"payload":[1,2],"extra":true}"#;
    let err = serde_json::from_str::<AgentAction>(bad).unwrap_err();
    assert_eq!(err.classify(), serde_json::error::Category::Data);
}

#[test]
fn action_result_round_trip() {
    let r = ActionResult {
        new_state: b"state".to_vec(),
        actions: vec![AgentAction {
            payload: b"a".to_vec(),
        }],
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: ActionResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

#[test]
fn dispatch_error_round_trip() {
    for e in [
        DispatchError::ValidationFailed(SecurityError::InvalidAction("x".to_string())),
        DispatchError::ValidationFailed(SecurityError::OversizedMessage),
        DispatchError::DeliveryFailed(MsgError::MailboxFull),
        DispatchError::TargetNotFound("t".to_string()),
        DispatchError::InvalidPayload("p".to_string()),
    ] {
        let json = serde_json::to_string(&e).unwrap();
        let back: DispatchError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);
    }
}

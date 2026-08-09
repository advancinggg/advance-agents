//! T_S A1 / A2 / A3 — Event struct schema tests (AC-02).

use advance_shared_types::event::Event;
use chrono::{DateTime, TimeZone, Utc};
use serde_json::json;

fn make_event(id: &str, ts: DateTime<Utc>) -> Event {
    Event {
        id: id.to_string(),
        timestamp: ts,
        agent_id: "agent-001".to_string(),
        task_id: Some("task-001".to_string()),
        run_id: Some("run-001".to_string()),
        execution_id: Some("exec-001".to_string()),
        trace_id: "trace-001".to_string(),
        span_id: "span-001".to_string(),
        parent_span_id: Some("parent-span-001".to_string()),
        event_type: "runtime.started".to_string(),
        payload: json!({"foo": "bar", "n": 42}),
        duration_ms: Some(123),
    }
}

#[test]
fn t_s_a1_round_trip_all_12_fields_populated() {
    let ts: DateTime<Utc> = Utc
        .with_ymd_and_hms(2026, 5, 3, 12, 0, 0)
        .single()
        .expect("valid timestamp");
    let event = make_event("evt-001", ts);
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: Event = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(restored, event);
}

#[test]
fn t_s_a2_round_trip_with_all_options_none() {
    let ts: DateTime<Utc> = Utc
        .with_ymd_and_hms(2026, 5, 3, 12, 0, 0)
        .single()
        .expect("valid timestamp");
    let event = Event {
        id: "evt-002".to_string(),
        timestamp: ts,
        agent_id: "agent-002".to_string(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: "trace-002".to_string(),
        span_id: "span-002".to_string(),
        parent_span_id: None,
        event_type: "task.created".to_string(),
        payload: serde_json::Value::Null,
        duration_ms: None,
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: Event = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(restored, event);
    assert!(restored.task_id.is_none());
    assert!(restored.run_id.is_none());
    assert!(restored.execution_id.is_none());
    assert!(restored.parent_span_id.is_none());
    assert!(restored.duration_ms.is_none());
}

#[test]
fn t_s_a3_unknown_field_is_rejected() {
    // Round-2 W2 fix: assert is_err() only — do not pattern-match the error string
    // (brittle to serde version bumps).
    let json = r#"{
        "id": "evt-003",
        "timestamp": "2026-05-03T12:00:00Z",
        "agent_id": "agent-003",
        "task_id": null,
        "run_id": null,
        "execution_id": null,
        "trace_id": "trace-003",
        "span_id": "span-003",
        "parent_span_id": null,
        "event_type": "task.created",
        "payload": null,
        "duration_ms": null,
        "foo": 42
    }"#;
    let result: Result<Event, _> = serde_json::from_str(json);
    assert!(
        result.is_err(),
        "Event must reject unknown fields per #[serde(deny_unknown_fields)]"
    );
}

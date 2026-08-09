//! serde round-trip, wire-format lock, and deny_unknown_fields tests for the
//! Slice B' `Event` struct.

use advance_shared_types::event::Event;
use chrono::{DateTime, TimeZone, Utc};

fn make_event_all_populated() -> Event {
    Event {
        id: "evt-001".into(),
        timestamp: Utc.timestamp_nanos(
            "2026-04-09T10:00:00.123456789Z"
                .parse::<DateTime<Utc>>()
                .unwrap()
                .timestamp_nanos_opt()
                .unwrap(),
        ),
        agent_id: "agent-root".into(),
        task_id: Some("task-001".into()),
        run_id: Some("run-001".into()),
        execution_id: Some("exec-001".into()),
        trace_id: "trace-aaa".into(),
        span_id: "span-001".into(),
        parent_span_id: Some("span-000".into()),
        event_type: "fs.write".into(),
        payload: serde_json::json!({"path": "/hello.txt"}),
        duration_ms: Some(42),
    }
}

fn rt<T>(v: T)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let encoded = serde_json::to_string(&v).expect("serialize");
    let decoded: T = serde_json::from_str(&encoded).expect("deserialize");
    assert_eq!(v, decoded);
}

// ---------- Round-trip symmetry ----------

#[test]
fn event_serde_round_trip_all_fields_populated() {
    rt(make_event_all_populated());
}

#[test]
fn event_serde_round_trip_optional_nulls() {
    let event = Event {
        id: "evt-002".into(),
        timestamp: "2026-04-09T10:00:00.123456789Z"
            .parse::<DateTime<Utc>>()
            .unwrap(),
        agent_id: "agent-root".into(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: "trace-bbb".into(),
        span_id: "span-002".into(),
        parent_span_id: None,
        event_type: "runtime.started".into(),
        payload: serde_json::json!({}),
        duration_ms: None,
    };
    rt(event);
}

// ---------- Wire-format lock ----------

#[test]
fn event_wire_format_lock() {
    let event = make_event_all_populated();
    let encoded = serde_json::to_string(&event).expect("serialize");
    assert_eq!(
        encoded,
        concat!(
            r#"{"id":"evt-001","#,
            r#""timestamp":"2026-04-09T10:00:00.123456789Z","#,
            r#""agent_id":"agent-root","#,
            r#""task_id":"task-001","#,
            r#""run_id":"run-001","#,
            r#""execution_id":"exec-001","#,
            r#""trace_id":"trace-aaa","#,
            r#""span_id":"span-001","#,
            r#""parent_span_id":"span-000","#,
            r#""event_type":"fs.write","#,
            r#""payload":{"path":"/hello.txt"},"#,
            r#""duration_ms":42}"#,
        )
    );
}

// ---------- Negative: deny_unknown_fields ----------

#[test]
fn event_deny_unknown_fields_rejects_smuggled_key() {
    let json = concat!(
        r#"{"id":"evt-001","#,
        r#""timestamp":"2026-04-09T10:00:00.123456789Z","#,
        r#""agent_id":"agent-root","#,
        r#""task_id":null,"#,
        r#""run_id":null,"#,
        r#""execution_id":null,"#,
        r#""trace_id":"trace-aaa","#,
        r#""span_id":"span-001","#,
        r#""parent_span_id":null,"#,
        r#""event_type":"fs.write","#,
        r#""payload":{},"#,
        r#""duration_ms":null,"#,
        r#""secret_field":"hostile"}"#,
    );
    let result: Result<Event, serde_json::Error> = serde_json::from_str(json);
    let err =
        result.expect_err("Event must reject unknown fields (deny_unknown_fields regression)");
    assert_eq!(
        err.classify(),
        serde_json::error::Category::Data,
        "expected Data category error (semantic rejection), got: {err}"
    );
}

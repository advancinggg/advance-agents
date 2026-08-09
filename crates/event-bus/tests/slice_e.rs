//! Slice m019-E integration tests.
//!
//! Covers:
//! - T08, T08-ng, T15 — AC-08 + AC-17 Trigger Bus dispatch wiring + mirror invariant
//! - T10, T10-no-qd, T10-no-payload — AC-10 mailbox SLO breach detection
//! - T14, T14-llm, T14-404 — AC-15 dashboard view route family
//! - T75 — AC-15 route enumeration regression-lock
//! - T76 — AC-01 framework path (entry/exit emit pattern)
//! - T77 — cap-llm payload-shape fix verification (closes §3.6 item 17)
//!
//! T74 (sweeper cancel-first sequencing) is in `tests/sweeper.rs` to share
//! the existing sweeper test scaffolding.
//! T78 (lint algorithm AST detection) lives in `observability-xtask/src/lint.rs`
//! `#[cfg(test)] mod tests`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use advance_event_bus::{Event, EventBus, EventBusConfig};
use advance_scheduler::contracts::TriggerBusDispatch;
use advance_scheduler::types::{SubscriptionId, TriggerSubscription};
use advance_shared_types::traits::EventBusEmit;
use chrono::Utc;
use rusqlite::{Connection, OpenFlags};
use serde_json::json;

// ─── Shared helpers ─────────────────────────────────────────────────────────

/// Mock TriggerBusDispatch that records all dispatch() calls into a shared
/// vector. subscribe/unsubscribe are no-ops since the tests only exercise
/// dispatch (the projection path EmitPipeline routes through).
///
/// **Synchrony invariant verification** (T15 / AC-17): because
/// `TriggerBusDispatch::dispatch` is a synchronous trait method (`fn`, no
/// `.await`), and because `EmitPipeline::emit` is non-async, the dispatch call
/// MUST complete before `EventBus::emit` returns. T15 asserts this indirectly:
/// after `bus.emit(whitelisted)` returns synchronously, `dispatch_calls.len() == 1`.
/// If dispatch were spawned on a separate task or deferred, the count would not
/// be incremented yet. The prior version of this mock held a `call_order` Vec
/// promising to record "fanout" + "dispatch" tokens; nothing wrote the "fanout"
/// token, so the field was dead code (Audit R1 W2 fix — removed).
#[derive(Default)]
struct MockTriggerBusDispatch {
    dispatch_calls: Mutex<Vec<Event>>,
}

impl TriggerBusDispatch for MockTriggerBusDispatch {
    fn subscribe(&self, _subscription: TriggerSubscription) -> SubscriptionId {
        SubscriptionId(0)
    }

    fn unsubscribe(&self, _id: SubscriptionId) {}

    fn dispatch(&self, event: Event) {
        self.dispatch_calls.lock().unwrap().push(event);
    }
}

fn cfg_async(
    jsonl_dir: &Path,
    db_path: &Path,
    trigger_bus_dispatch: Option<Arc<dyn TriggerBusDispatch>>,
    mailbox_threshold_ms: u64,
) -> EventBusConfig {
    let mut cfg = EventBusConfig::new(jsonl_dir.to_path_buf(), db_path.to_path_buf());
    cfg.websocket_addr = "127.0.0.1:0".parse().unwrap();
    cfg.trigger_bus_dispatch = trigger_bus_dispatch;
    cfg.mailbox_delivery_slow_threshold_ms = mailbox_threshold_ms;
    cfg
}

fn build_event(event_type: &str, agent_id: &str) -> Event {
    Event {
        id: ulid::Ulid::new().to_string(),
        timestamp: Utc::now(),
        agent_id: agent_id.to_string(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: ulid::Ulid::new().to_string(),
        span_id: ulid::Ulid::new().to_string(),
        parent_span_id: None,
        event_type: event_type.to_string(),
        payload: json!({}),
        duration_ms: None,
    }
}

fn count_events_by_type(db_path: &Path, event_type: &str) -> i64 {
    let conn =
        Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).expect("open db");
    conn.query_row(
        "SELECT COUNT(*) FROM events WHERE event_type = ?",
        [event_type],
        |r| r.get(0),
    )
    .unwrap_or(0)
}

fn select_one_event(db_path: &Path, event_type: &str) -> Option<(String, String)> {
    let conn =
        Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).expect("open db");
    conn.query_row(
        "SELECT agent_id, payload FROM events WHERE event_type = ? LIMIT 1",
        [event_type],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
    )
    .ok()
}

// ─── T08, T08-ng, T15 — AC-08 + AC-17 Trigger Bus dispatch ──────────────────

#[tokio::test(flavor = "multi_thread")]
async fn t08_whitelisted_emit_triggers_dispatch() {
    let temp = tempfile::TempDir::new().unwrap();
    let mock = Arc::new(MockTriggerBusDispatch::default());
    let cfg = cfg_async(
        &temp.path().join("events"),
        &temp.path().join("events.db"),
        Some(mock.clone() as Arc<dyn TriggerBusDispatch>),
        1000,
    );
    let bus = EventBus::new(cfg).await.expect("bus");
    bus.emit(build_event("component.finished", "agent-a"));
    bus.shutdown().await;
    let calls = mock.dispatch_calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "expected exactly 1 dispatch call");
    assert_eq!(calls[0].event_type, "component.finished");
    assert_eq!(calls[0].agent_id, "agent-a");
}

#[tokio::test(flavor = "multi_thread")]
async fn t08_ng_dispatch_none_skips_silently() {
    let temp = tempfile::TempDir::new().unwrap();
    let cfg = cfg_async(
        &temp.path().join("events"),
        &temp.path().join("events.db"),
        None,
        1000,
    );
    let db_path = cfg.db_path.clone();
    let bus = EventBus::new(cfg).await.expect("bus");
    bus.emit(build_event("component.spawned", "agent-b"));
    bus.shutdown().await;
    // Fan-out still wrote the row.
    assert_eq!(count_events_by_type(&db_path, "component.spawned"), 1);
    // No panic. No dispatch (no mock to verify since trigger_bus_dispatch was None).
}

#[tokio::test(flavor = "multi_thread")]
async fn t15_mirror_invariant_whitelisted_vs_non() {
    let temp = tempfile::TempDir::new().unwrap();
    let mock = Arc::new(MockTriggerBusDispatch::default());
    let cfg = cfg_async(
        &temp.path().join("events"),
        &temp.path().join("events.db"),
        Some(mock.clone() as Arc<dyn TriggerBusDispatch>),
        1000,
    );
    let db_path = cfg.db_path.clone();
    let bus = EventBus::new(cfg).await.expect("bus");
    // Case (a): whitelisted emit. Dispatch MUST fire BEFORE bus.emit returns —
    // the mirror invariant (AC-17) requires same-call-frame dispatch. We
    // assert by reading dispatch_calls synchronously immediately after emit()
    // returns: if dispatch were deferred/async, the count would still be 0.
    bus.emit(build_event("component.spawned", "agent-x"));
    {
        let calls = mock.dispatch_calls.lock().unwrap();
        assert_eq!(
            calls.len(),
            1,
            "dispatch MUST fire synchronously in the emit() call frame (AC-17 mirror invariant)"
        );
        assert_eq!(calls[0].event_type, "component.spawned");
    }
    // Case (b): non-whitelisted emit. Dispatch MUST NOT fire.
    bus.emit(build_event("fs.write", "agent-y"));
    {
        let calls = mock.dispatch_calls.lock().unwrap();
        assert_eq!(
            calls.len(),
            1,
            "non-whitelisted event must NOT dispatch (count still 1)"
        );
    }
    bus.shutdown().await;
    // Both events written to events.db (fan-out works regardless of whitelist).
    assert_eq!(count_events_by_type(&db_path, "component.spawned"), 1);
    assert_eq!(count_events_by_type(&db_path, "fs.write"), 1);
}

// ─── T10, T10-no-qd, T10-no-payload — AC-10 Mailbox SLO breach ──────────────

#[tokio::test(flavor = "multi_thread")]
async fn t10_breach_emits_mirror() {
    let temp = tempfile::TempDir::new().unwrap();
    let cfg = cfg_async(
        &temp.path().join("events"),
        &temp.path().join("events.db"),
        None,
        1000,
    );
    let db_path = cfg.db_path.clone();
    let bus = EventBus::new(cfg).await.expect("bus");
    for (lat, qd) in [(500u64, None), (1000u64, None), (1500u64, Some(7u64))] {
        let mut ev = build_event("msg.received", "agent-a");
        let mut payload = serde_json::Map::new();
        payload.insert("delivery_latency_ms".into(), json!(lat));
        if let Some(q) = qd {
            payload.insert("queue_depth".into(), json!(q));
        }
        ev.payload = serde_json::Value::Object(payload);
        bus.emit(ev);
    }
    bus.shutdown().await;
    // 3 input rows + 1 mirror (the breaching 1500ms event).
    assert_eq!(count_events_by_type(&db_path, "msg.received"), 3);
    assert_eq!(count_events_by_type(&db_path, "mailbox.delivery_slow"), 1);
    let (agent_id, payload_json) =
        select_one_event(&db_path, "mailbox.delivery_slow").expect("mirror row");
    assert_eq!(agent_id, "agent-a", "struct-level agent_id propagated");
    let payload: serde_json::Value = serde_json::from_str(&payload_json).unwrap();
    assert_eq!(payload["agent_id"], json!("agent-a"));
    assert_eq!(payload["latency_ms"], json!(1500));
    assert_eq!(payload["queue_depth"], json!(7));
}

#[tokio::test(flavor = "multi_thread")]
async fn t10_no_qd_mirror_omits_queue_depth_field() {
    let temp = tempfile::TempDir::new().unwrap();
    let cfg = cfg_async(
        &temp.path().join("events"),
        &temp.path().join("events.db"),
        None,
        1000,
    );
    let db_path = cfg.db_path.clone();
    let bus = EventBus::new(cfg).await.expect("bus");
    let mut ev = build_event("msg.received", "agent-a");
    ev.payload = json!({"delivery_latency_ms": 1500u64});
    bus.emit(ev);
    bus.shutdown().await;
    assert_eq!(count_events_by_type(&db_path, "mailbox.delivery_slow"), 1);
    let (_, payload_json) = select_one_event(&db_path, "mailbox.delivery_slow").unwrap();
    let payload: serde_json::Value = serde_json::from_str(&payload_json).unwrap();
    assert!(
        payload.get("queue_depth").is_none(),
        "queue_depth key MUST be absent (not null, not 0) when source event lacks it; got {payload:?}"
    );
    assert_eq!(payload["latency_ms"], json!(1500));
}

#[tokio::test(flavor = "multi_thread")]
async fn t10_no_payload_no_mirror() {
    let temp = tempfile::TempDir::new().unwrap();
    let cfg = cfg_async(
        &temp.path().join("events"),
        &temp.path().join("events.db"),
        None,
        1000,
    );
    let db_path = cfg.db_path.clone();
    let bus = EventBus::new(cfg).await.expect("bus");
    let mut ev = build_event("msg.received", "agent-a");
    ev.payload = json!({}); // no delivery_latency_ms field
    bus.emit(ev);
    bus.shutdown().await;
    assert_eq!(count_events_by_type(&db_path, "msg.received"), 1);
    assert_eq!(count_events_by_type(&db_path, "mailbox.delivery_slow"), 0);
}

// ─── T14, T14-llm, T14-404 — AC-15 Dashboard views ──────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn t14_dashboard_views_all_200() {
    let temp = tempfile::TempDir::new().unwrap();
    let cfg = cfg_async(
        &temp.path().join("events"),
        &temp.path().join("events.db"),
        None,
        1000,
    );
    let bus = EventBus::new(cfg).await.expect("bus");
    let addr = bus.server_addr().expect("server_addr");
    let client = reqwest_get();
    for view in [
        "message_flow",
        "task_timeline",
        "recall_quality",
        "topology",
        "security",
        "grant_panel",
        "run_panel",
        "agent_panel",
    ] {
        let url = format!("http://{}/query/dashboard/{}", addr, view);
        let resp = client.get(&url).await;
        assert_eq!(
            resp.0, 200,
            "view {view} status should be 200, got {}",
            resp.0
        );
        // Response body should be valid JSON.
        let _: serde_json::Value = serde_json::from_str(&resp.1)
            .unwrap_or_else(|e| panic!("view {view} body not JSON: {e}: body={}", resp.1));
    }
    // `trace` requires ?trace_id=.
    let resp = client
        .get(&format!(
            "http://{}/query/dashboard/trace?trace_id=tr-x",
            addr
        ))
        .await;
    assert_eq!(resp.0, 200);
    // `llm_analytics` returns valid JSON even with empty event store.
    let resp = client
        .get(&format!("http://{}/query/dashboard/llm_analytics", addr))
        .await;
    assert_eq!(resp.0, 200);
    bus.shutdown().await;
}

// T14-llm-overflow — Audit R1 Critical 1 regression: extreme window_secs
// values do NOT panic the handler or produce future-cutoff garbage. The
// `?window_secs=` parameter is clamped to MAX_WINDOW_SECS (100 years) BEFORE
// the `as i64` cast that would otherwise overflow to negative on inputs
// > i64::MAX (chrono::Duration::seconds then produces a future timestamp).
#[tokio::test(flavor = "multi_thread")]
async fn t14_llm_overflow_clamped() {
    let temp = tempfile::TempDir::new().unwrap();
    let cfg = cfg_async(
        &temp.path().join("events"),
        &temp.path().join("events.db"),
        None,
        1000,
    );
    let bus = EventBus::new(cfg).await.expect("bus");
    let addr = bus.server_addr().expect("server_addr");
    let client = reqwest_get();
    // Stress: window_secs = u64::MAX. Without the Audit R1 C1 clamp this
    // overflows on `as i64` (negative) and either silently selects zero rows
    // or panics in chrono.
    let resp = client
        .get(&format!(
            "http://{}/query/dashboard/llm_analytics?window_secs=18446744073709551615",
            addr
        ))
        .await;
    assert_eq!(
        resp.0, 200,
        "extreme window_secs must NOT panic the handler"
    );
    let body: serde_json::Value = serde_json::from_str(&resp.1).unwrap();
    // Should return an empty aggregate (no events seeded in this test).
    assert_eq!(body["request_count"].as_u64(), Some(0));
    bus.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn t14_404_unknown_view() {
    let temp = tempfile::TempDir::new().unwrap();
    let cfg = cfg_async(
        &temp.path().join("events"),
        &temp.path().join("events.db"),
        None,
        1000,
    );
    let bus = EventBus::new(cfg).await.expect("bus");
    let addr = bus.server_addr().expect("server_addr");
    let client = reqwest_get();
    let resp = client
        .get(&format!("http://{}/query/dashboard/foobar", addr))
        .await;
    assert_eq!(resp.0, 404, "unknown view must 404");
    bus.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn t14_llm_analytics_aggregates_top_level_payload() {
    let temp = tempfile::TempDir::new().unwrap();
    let cfg = cfg_async(
        &temp.path().join("events"),
        &temp.path().join("events.db"),
        None,
        1000,
    );
    let bus = EventBus::new(cfg).await.expect("bus");
    // Seed 6 llm.response events with TOP-LEVEL payload shape (post cap-llm fix).
    for _ in 0..6 {
        let mut ev = build_event("llm.response", "agent-llm");
        ev.payload = json!({
            "model": "test-model",
            "input_tokens": 100u64,
            "output_tokens": 50u64,
            "cost_usd": 0.01_f64,
        });
        bus.emit(ev);
    }
    // Give the db_indexer actor a moment to drain. The pipeline's try_send is
    // synchronous, but the writer task runs concurrently. shutdown() awaits
    // the drain. We perform the GET BEFORE shutdown so the server is still up,
    // but events should already be in the bounded channel.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let addr = bus.server_addr().expect("server_addr");
    let client = reqwest_get();
    let resp = client
        .get(&format!(
            "http://{}/query/dashboard/llm_analytics?window_secs=600",
            addr
        ))
        .await;
    assert_eq!(resp.0, 200);
    let body: serde_json::Value = serde_json::from_str(&resp.1).unwrap();
    let request_count = body["request_count"].as_u64().expect("request_count u64");
    let tokens_in = body["tokens_in_total"]
        .as_u64()
        .expect("tokens_in_total u64");
    let tokens_out = body["tokens_out_total"]
        .as_u64()
        .expect("tokens_out_total u64");
    // Bounded race: some events may still be in flight. Assert >= 1.
    assert!(
        request_count >= 1,
        "request_count should be >=1 after drain, got {request_count}"
    );
    assert!(
        tokens_in >= 100,
        "tokens_in_total should reflect top-level input_tokens read"
    );
    assert!(
        tokens_out >= 50,
        "tokens_out_total should reflect top-level output_tokens read"
    );
    bus.shutdown().await;
}

// ─── T75 — AC-15 route enumeration regression ───────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn t75_route_enumeration_10_valid_2_invalid_3_baseline() {
    let temp = tempfile::TempDir::new().unwrap();
    let cfg = cfg_async(
        &temp.path().join("events"),
        &temp.path().join("events.db"),
        None,
        1000,
    );
    let bus = EventBus::new(cfg).await.expect("bus");
    let addr = bus.server_addr().expect("server_addr");
    let client = reqwest_get();
    let valid_views = [
        "message_flow",
        "run_panel",
        "agent_panel",
        "task_timeline",
        "llm_analytics",
        "recall_quality",
        "topology",
        "security",
        "grant_panel",
    ];
    let mut ok_count = 0;
    for v in valid_views {
        let resp = client
            .get(&format!("http://{}/query/dashboard/{}", addr, v))
            .await;
        if resp.0 == 200 {
            ok_count += 1;
        }
    }
    // trace requires a trace_id query param
    let resp = client
        .get(&format!(
            "http://{}/query/dashboard/trace?trace_id=tr-x",
            addr
        ))
        .await;
    if resp.0 == 200 {
        ok_count += 1;
    }
    assert_eq!(ok_count, 10, "10 valid dashboard views must all 200");
    // 2 invalid views → 404.
    for bogus in ["foobar", "not_a_view"] {
        let resp = client
            .get(&format!("http://{}/query/dashboard/{}", addr, bogus))
            .await;
        assert_eq!(resp.0, 404);
    }
    // 3 baseline routes still work.
    let resp = client
        .get(&format!("http://{}/query/traces?trace_id=tr-x", addr))
        .await;
    assert_eq!(resp.0, 200);
    let resp = client
        .get(&format!("http://{}/query/events?event_type=fs.write", addr))
        .await;
    assert_eq!(resp.0, 200);
    let resp = client
        .get(&format!("http://{}/query/sweeper_state", addr))
        .await;
    assert_eq!(resp.0, 200);
    bus.shutdown().await;
}

// ─── T76 — AC-01 framework path: entry/exit emit pattern ────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn t76_entry_exit_pattern_roundtrips() {
    let temp = tempfile::TempDir::new().unwrap();
    let cfg = cfg_async(
        &temp.path().join("events"),
        &temp.path().join("events.db"),
        None,
        1000,
    );
    let db_path = cfg.db_path.clone();
    let bus = EventBus::new(cfg).await.expect("bus");
    // Simulate a host-function-style handler that emits entry + exit events
    // around its inner work. This is the canonical AC-01 framework pattern
    // — a real HostFunctionHandler::call body would invoke `bus.emit()` (or a
    // helper like `emit_fs_event(emitter, ...)`) at function entry and exit.
    let entry_span = ulid::Ulid::new().to_string();
    let entry = Event {
        id: ulid::Ulid::new().to_string(),
        timestamp: Utc::now(),
        agent_id: "test-agent".into(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: ulid::Ulid::new().to_string(),
        span_id: entry_span.clone(),
        parent_span_id: None,
        event_type: "fs.read.entry".into(),
        payload: json!({"path": "/tmp/foo"}),
        duration_ms: None,
    };
    bus.emit(entry);
    let exit = Event {
        id: ulid::Ulid::new().to_string(),
        timestamp: Utc::now(),
        agent_id: "test-agent".into(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: ulid::Ulid::new().to_string(),
        span_id: entry_span.clone(),
        parent_span_id: None,
        event_type: "fs.read".into(),
        payload: json!({"path": "/tmp/foo", "bytes_read": 100}),
        duration_ms: Some(5),
    };
    bus.emit(exit);
    bus.shutdown().await;
    assert_eq!(count_events_by_type(&db_path, "fs.read.entry"), 1);
    assert_eq!(count_events_by_type(&db_path, "fs.read"), 1);
}

// ─── T77 — cap-llm payload-shape fix (§3.6 item 17 closure) ─────────────────

#[test]
fn t77_cap_llm_emit_llm_response_uses_top_level_payload() {
    // Direct verification: read the cap-llm/src/events.rs source and confirm
    // the payload is built with TOP-LEVEL input_tokens / output_tokens keys
    // (NOT nested `tokens.{input,output}`). Source-level T77 keeps the test
    // self-contained in event-bus; the wire-level T83 in cap-llm/src/gateway.rs
    // is the integration-level verification (asserts on actual Event payload).
    let src = std::fs::read_to_string("../capabilities/cap-llm/src/events.rs")
        .expect("read cap-llm events.rs");
    assert!(
        src.contains("\"input_tokens\": response.input_tokens"),
        "emit_llm_response payload must use top-level input_tokens key (PRD §15.3.5)"
    );
    assert!(
        src.contains("\"output_tokens\": response.output_tokens"),
        "emit_llm_response payload must use top-level output_tokens key (PRD §15.3.5)"
    );
    assert!(
        !src.contains("\"tokens\": {\n            \"input\":"),
        "nested tokens.{{input,output}} shape must be removed (closes §3.6 item 17)"
    );
}

// ─── Minimal HTTP client (avoids reqwest dep) ──────────────────────────────

fn reqwest_get() -> TestClient {
    TestClient
}

struct TestClient;
impl TestClient {
    async fn get(&self, url: &str) -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let parsed_url = url::Url::parse(url).expect("valid url");
        let host = parsed_url.host_str().expect("host");
        let port = parsed_url.port().expect("port");
        let path_q = match parsed_url.query() {
            Some(q) => format!("{}?{}", parsed_url.path(), q),
            None => parsed_url.path().to_string(),
        };
        let addr = format!("{}:{}", host, port);
        let mut stream = tokio::net::TcpStream::connect(&addr)
            .await
            .expect("connect");
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            path_q, addr
        );
        stream.write_all(req.as_bytes()).await.expect("write");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read");
        let resp = String::from_utf8_lossy(&buf).to_string();
        let mut lines = resp.split("\r\n");
        let status_line = lines.next().unwrap_or("");
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let body = resp.splitn(2, "\r\n\r\n").nth(1).unwrap_or("").to_string();
        // Strip chunked encoding markers if present (simple approximation).
        let body = strip_chunked(&body);
        (status, body)
    }
}

fn strip_chunked(s: &str) -> String {
    // Best-effort: if body looks like chunked (hex-line + \r\n + content + \r\n
    // + hex-line + \r\n + ...), concatenate the content parts. Otherwise
    // return as-is.
    if !s
        .lines()
        .next()
        .map_or(false, |first| first.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return s.to_string();
    }
    let mut out = String::new();
    let mut lines = s.lines();
    while let Some(hex) = lines.next() {
        let n = match u64::from_str_radix(hex.trim(), 16) {
            Ok(n) => n as usize,
            Err(_) => return s.to_string(),
        };
        if n == 0 {
            break;
        }
        // Next line is the chunk content (may have CR/LF inside; assume
        // single-line chunks for simplicity).
        if let Some(content) = lines.next() {
            out.push_str(content);
        }
    }
    out
}

// Suppress unused-import warning on HashMap (used in commented-out section).
#[allow(dead_code)]
fn _unused_imports_marker(_: HashMap<String, String>) {}

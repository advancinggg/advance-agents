//! MODULE-012-AC-10 / MODULE-019-AC-18 deferred-half witness (Wave-20 security
//! lane): `sensitive_params` parameter-name redaction across the 3 EXISTING
//! EventBus observation sinks — debug-logs (JSONL file_writer), audit-records
//! (SQLite db_indexer), dashboard-events (WebSocket ws_broadcaster).
//!
//! Anti-fake-green: a `sensitive_params` source masks `api_key` to `[REDACTED]`
//! on ALL 3 sinks (present-but-masked, `note` untouched); the BASELINE (no
//! source) leaks the raw value on all 3. Observation-only (§1.7): the original
//! UNREDACTED event flows to the trigger-bus (execution) path.
//!
//! AC-10 stays HELD (only 3 of 5 surfaces exist; production population is dormant
//! — the WIT submit-component path does not carry sensitive_params, so this
//! drives a test-constructed source). See MODULE-012 §3.6.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use advance_event_bus::{EventBus, EventBusConfig, SensitiveParamsSource};
use advance_scheduler::contracts::TriggerBusDispatch;
use advance_scheduler::types::{SubscriptionId, TriggerSubscription};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use chrono::Utc;
use futures::StreamExt;
use serde_json::json;
use tokio_tungstenite::tungstenite::Message;

const SECRET: &str = "legacy3-raw-secret-7f3a";
const COMP: &str = "comp-A";

/// In-test source: returns the exact CONTRACT-217 v0.2 declaration for `comp-A`.
struct MapSource;
impl SensitiveParamsSource for MapSource {
    fn names_for(&self, agent_id: &str) -> Option<Arc<HashSet<String>>> {
        if agent_id == COMP {
            let mut s = HashSet::new();
            for name in ["api_key", "id", "event_type", "run_id"] {
                s.insert(name.to_owned());
            }
            Some(Arc::new(s))
        } else {
            None
        }
    }
}

/// Recording TriggerBusDispatch — captures the events it receives (to prove the
/// execution path sees the UNREDACTED original). subscribe/unsubscribe unused.
struct RecordingDispatch {
    seen: Mutex<Vec<Event>>,
}
impl TriggerBusDispatch for RecordingDispatch {
    fn subscribe(&self, _s: TriggerSubscription) -> SubscriptionId {
        unimplemented!("not exercised by this witness")
    }
    fn unsubscribe(&self, _id: SubscriptionId) {}
    fn dispatch(&self, event: Event) {
        self.seen.lock().unwrap().push(event);
    }
}

fn event(event_type: &str) -> Event {
    Event {
        id: "sp-redact-1".into(),
        timestamp: Utc::now(),
        agent_id: COMP.into(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: "tr-1".into(),
        span_id: "s-1".into(),
        parent_span_id: None,
        event_type: event_type.into(),
        payload: json!({
            "id": "structural-id-must-not-change",
            "event_type": "structural-event-type-must-not-change",
            "run_id": "structural-run-id-must-not-change",
            "named_params": {
                "api_key": SECRET,
                "id": SECRET,
                "event_type": SECRET,
                "run_id": SECRET
            },
            "nested": [{"named_params": {
                "api_key": SECRET,
                "id": SECRET,
                "event_type": SECRET,
                "run_id": SECRET
            }}],
            "cap_params": [
                {"key": "api_key", "value": SECRET},
                {"key": "id", "value": SECRET}
            ],
            "note": "ok"
        }),
        duration_ms: None,
    }
}

/// SELECT the most-recent event payload text from the SQLite audit sink.
fn db_payloads(db_path: &std::path::Path) -> String {
    let conn = rusqlite::Connection::open(db_path).expect("open db");
    let mut stmt = conn.prepare("SELECT payload FROM events").expect("prepare");
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .expect("query")
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    rows.join("\n")
}

fn jsonl_today(dir: &std::path::Path) -> String {
    let f = dir.join(format!("{}.jsonl", Utc::now().date_naive()));
    std::fs::read_to_string(&f).unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sensitive_params_redacted_on_all_three_sinks() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let mut cfg = EventBusConfig::new(jsonl_dir.clone(), db_path.clone());
    cfg.websocket_addr = "127.0.0.1:0".parse().unwrap();
    cfg.sensitive_params_source = Some(Arc::new(MapSource));
    let bus = EventBus::new(cfg).await.expect("bus");

    // Dashboard sink: subscribe a WS client before emitting.
    let addr = bus.server_addr().unwrap();
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/events"))
        .await
        .expect("ws");
    tokio::time::sleep(Duration::from_millis(100)).await;

    bus.emit(event("runtime.started"));

    // Collect the WS frame for our event.
    let ws_frame = tokio::time::timeout(Duration::from_millis(800), async {
        loop {
            if let Some(Ok(Message::Text(t))) = ws.next().await {
                let s = t.to_string();
                if s.contains("sp-redact-1") {
                    return s;
                }
            }
        }
    })
    .await
    .expect("WS frame for emitted event");

    tokio::time::sleep(Duration::from_millis(300)).await;
    let jsonl = jsonl_today(&jsonl_dir);
    let db = db_payloads(&db_path);
    bus.shutdown().await;

    for (sink, content) in [("JSONL", &jsonl), ("SQLite", &db), ("WS", &ws_frame)] {
        assert!(
            content.contains("[REDACTED]"),
            "{sink}: api_key must be masked; got {content}"
        );
        assert!(
            !content.contains(SECRET),
            "{sink}: raw secret must NOT appear; got {content}"
        );
        // present-but-masked + non-sensitive key untouched.
        assert!(content.contains("api_key"), "{sink}: key still present");
        assert!(
            content.contains("structural-id-must-not-change"),
            "{sink}: structural id must remain byte-identical"
        );
        assert!(
            content.contains("structural-event-type-must-not-change")
                && content.contains("structural-run-id-must-not-change"),
            "{sink}: structural routing fields must remain byte-identical"
        );
        assert!(
            content.contains("\"note\":\"ok\""),
            "{sink}: note untouched"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn baseline_no_source_leaks_on_all_three_sinks() {
    // Anti-fake-green discriminator: with NO source, the raw secret appears on
    // all 3 sinks (byte-identical to the pre-Wave-20 behaviour).
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let mut cfg = EventBusConfig::new(jsonl_dir.clone(), db_path.clone());
    cfg.websocket_addr = "127.0.0.1:0".parse().unwrap();
    // sensitive_params_source = None (default)
    let bus = EventBus::new(cfg).await.expect("bus");

    let addr = bus.server_addr().unwrap();
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/events"))
        .await
        .expect("ws");
    tokio::time::sleep(Duration::from_millis(100)).await;

    bus.emit(event("runtime.started"));

    let ws_frame = tokio::time::timeout(Duration::from_millis(800), async {
        loop {
            if let Some(Ok(Message::Text(t))) = ws.next().await {
                let s = t.to_string();
                if s.contains("sp-redact-1") {
                    return s;
                }
            }
        }
    })
    .await
    .expect("WS frame");

    tokio::time::sleep(Duration::from_millis(300)).await;
    let jsonl = jsonl_today(&jsonl_dir);
    let db = db_payloads(&db_path);
    bus.shutdown().await;

    for (sink, content) in [("JSONL", &jsonl), ("SQLite", &db), ("WS", &ws_frame)] {
        assert!(
            content.contains(SECRET),
            "{sink}: baseline (no source) leaks raw secret; got {content}"
        );
        assert!(
            !content.contains("[REDACTED]"),
            "{sink}: no redaction without a source"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn observation_only_execution_path_sees_unredacted() {
    // §1.7 observation-only: the redacted event goes ONLY to the obs sinks; the
    // execution path (trigger_bus_dispatch, whitelisted events) receives the
    // ORIGINAL unredacted event so downstream triggering is unaltered. This is the
    // LOAD-BEARING half — trigger_bus can spawn work, so it must see the real
    // payload. The other original-routed sinks (cost_tracker / stats_aggregator)
    // are intentionally NOT asserted here: they persist only counters / token
    // aggregates, never the event payload, so original-vs-redacted is unobservable
    // through them (no payload-bearing leak surface to witness).
    let temp = tempfile::TempDir::new().unwrap();
    let mut cfg = EventBusConfig::new(temp.path().join("events"), temp.path().join("events.db"));
    cfg.websocket_addr = "127.0.0.1:0".parse().unwrap();
    cfg.sensitive_params_source = Some(Arc::new(MapSource));
    let dispatch = Arc::new(RecordingDispatch {
        seen: Mutex::new(Vec::new()),
    });
    cfg.trigger_bus_dispatch = Some(dispatch.clone());
    let bus = EventBus::new(cfg).await.expect("bus");

    // `grant.issued` is in TRIGGER_BUS_WHITELIST → trigger dispatch fires.
    bus.emit(event("grant.issued"));
    tokio::time::sleep(Duration::from_millis(200)).await;
    bus.shutdown().await;

    let seen = dispatch.seen.lock().unwrap();
    assert_eq!(
        seen.len(),
        1,
        "trigger dispatch fired once for the whitelisted event"
    );
    let payload = serde_json::to_string(&seen[0].payload).unwrap();
    assert!(
        payload.contains(SECRET),
        "execution path must see the UNREDACTED original; got {payload}"
    );
    assert!(
        !payload.contains("[REDACTED]"),
        "execution path must NOT be redacted (observation-only invariant)"
    );
}

/// Sync-mode parity (audit-r1 Codex finding): `new_synchronous_for_tests` ALSO
/// applies the source — the 2 sync sinks (file_writer JSONL + db_indexer SQLite)
/// redact, matching the Async EmitPipeline. No WS/stats/trigger in sync mode.
/// `#[test]` (NOT tokio) — the sync constructor must not run inside an executor.
#[test]
fn sync_mode_redacts_the_two_sync_sinks() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let mut cfg = EventBusConfig::new(jsonl_dir.clone(), db_path.clone());
    cfg.sensitive_params_source = Some(Arc::new(MapSource));
    let bus = EventBus::new_synchronous_for_tests(cfg).unwrap();
    bus.emit(event("runtime.started")); // sync → immediate writes

    let jsonl = jsonl_today(&jsonl_dir);
    let db = db_payloads(&db_path);
    for (sink, content) in [("JSONL", &jsonl), ("SQLite", &db)] {
        assert!(
            content.contains("[REDACTED]"),
            "{sink}: masked; got {content}"
        );
        assert!(
            !content.contains(SECRET),
            "{sink}: raw secret absent; got {content}"
        );
        assert!(
            content.contains("\"note\":\"ok\""),
            "{sink}: note untouched"
        );
    }
}

#[test]
fn malformed_canonical_container_is_suppressed_without_raw_fallback() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let mut cfg = EventBusConfig::new(jsonl_dir.clone(), db_path.clone());
    cfg.sensitive_params_source = Some(Arc::new(MapSource));
    let bus = EventBus::new_synchronous_for_tests(cfg).unwrap();
    let mut malformed = event("runtime.started");
    malformed.payload = json!({
        "cap_params": [{"key": "api_key", "value": SECRET, "extra": true}]
    });
    bus.emit(malformed);

    let jsonl = jsonl_today(&jsonl_dir);
    let db = db_payloads(&db_path);
    assert!(
        jsonl.is_empty(),
        "blocked payload must not reach JSONL: {jsonl}"
    );
    assert!(db.is_empty(), "blocked payload must not reach SQLite: {db}");
    assert_eq!(bus.dropped_count(), 1, "suppression is observable");
}

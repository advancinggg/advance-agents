//! SYS-J-41 — every host-function event is appended to JSONL and SQLite and
//! broadcast over the WebSocket to the dashboard.
//! Chain: MODULE-001 → MODULE-019 → MODULE-004.
//!
//! Small-witness slice (2026-06-11), two legs:
//!  - **SYS-AC-132** — a WebSocket client connected to `/events` receives the same
//!    event in real time (REAL async `EventBus` over a real TCP socket + a real
//!    `tokio-tungstenite` client — the missing WS-client seam).
//!  - **SYS-AC-231** — when the SQLite events-table insert fails, the event line is
//!    still present in the JSONL file (JSONL is the durable source of truth; SQLite
//!    is a rebuildable index). Fault injection WITHOUT product edits: an EXTERNAL
//!    rusqlite connection issues `DROP TABLE events`; the bus's pooled connection
//!    re-compiles its cached INSERT on the schema-cookie change inside
//!    `sqlite3_step` (prepare_v2 semantics) and fails deterministically with
//!    "no such table" — while the JSONL append (which runs FIRST in the sync emit
//!    path) succeeds independently.

use std::time::Duration;

use advance_event_bus::{EventBus, EventBusConfig};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use chrono::Utc;
use futures::StreamExt;
use tokio_tungstenite::tungstenite::Message as WsMessage;

fn event(id: &str, event_type: &str) -> Event {
    Event {
        id: id.to_string(),
        timestamp: Utc::now(),
        agent_id: "agent:harness".to_string(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: "tr-j41".to_string(),
        span_id: "sp-j41".to_string(),
        parent_span_id: None,
        event_type: event_type.to_string(),
        payload: serde_json::json!({"leg": "j41"}),
        duration_ms: None,
    }
}

/// SYS-AC-132 — a WebSocket client connected to /events receives the same event
/// in real time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sys_ac_132_ws_client_receives_event_in_real_time() {
    let temp = tempfile::TempDir::new().unwrap();
    let mut cfg = EventBusConfig::new(temp.path().join("events"), temp.path().join("events.db"));
    cfg.websocket_addr = "127.0.0.1:0".parse().unwrap();
    let bus = EventBus::new(cfg).await.expect("real async bus");

    let addr = bus.server_addr().expect("ws server bound");
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/events"))
        .await
        .expect("ws connect");
    tokio::time::sleep(Duration::from_millis(100)).await;

    bus.emit(event("evt-132", "fs.write"));

    // The SAME event arrives at the client in bounded real time, as JSON
    // carrying the emitted id + type. CAPTURE the outcome, shut the bus down,
    // THEN assert — so a failed assertion cannot leak the axum server task +
    // bound listener for the rest of the test binary (adversarial r11; the bus
    // has no Drop impl, only shutdown() stops its server task).
    let frame: Result<Option<String>, tokio::time::error::Elapsed> =
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match ws.next().await {
                    Some(Ok(WsMessage::Text(t))) if t.contains("evt-132") => {
                        return Some(t.to_string())
                    }
                    Some(_) => {}
                    None => return None,
                }
            }
        })
        .await;
    bus.shutdown().await;

    let frame = frame
        .expect("event reaches the WS client in real time")
        .expect("ws stayed open until the frame arrived");
    let parsed: serde_json::Value = serde_json::from_str(&frame).expect("frame is the event JSON");
    assert_eq!(parsed.get("id").and_then(|v| v.as_str()), Some("evt-132"));
    assert_eq!(
        parsed.get("event_type").and_then(|v| v.as_str()),
        Some("fs.write")
    );
}

/// SYS-AC-231 — when the SQLite events-table insert fails, the event line is still
/// present in the JSONL file (no event loss; JSONL durable source of truth, SQLite
/// a rebuildable index).
///
/// Topology scope (adversarial r11): this witnesses the criterion's failure mode —
/// SQLite-insert failure does not lose the JSONL line — on the synchronous bus
/// (the harness's established RealBus mode), where the JSONL append precedes the
/// index write inline. In the production ASYNC pipeline the same property holds
/// structurally (independent file_writer/db_indexer actors: an indexer failure
/// cannot touch the file actor); what the async topology adds is a DIFFERENT,
/// out-of-criterion failure mode (bounded-channel backpressure dropping an event
/// from BOTH sinks under saturation) — a pre-existing event-bus product property,
/// not the SQLite-failure clause this SYS-AC certifies.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_231_jsonl_line_survives_sqlite_insert_failure() {
    let temp = tempfile::TempDir::new().unwrap();
    let jsonl_dir = temp.path().join("events");
    let db_path = temp.path().join("events.db");
    let cfg = EventBusConfig::new(jsonl_dir.clone(), db_path.clone());
    // Synchronous bus (inline dual write) — run in spawn_blocking per its
    // "must not be called from inside the async executor" contract.
    let bus = tokio::task::spawn_blocking(move || {
        EventBus::new_synchronous_for_tests(cfg).expect("sync bus")
    })
    .await
    .unwrap();

    // Event #1: both sinks healthy — JSONL line + SQLite row land.
    bus.emit(event("evt-231-pre", "fs.write"));
    assert_eq!(bus.dropped_count(), 0, "healthy emit drops nothing");

    // Fault injection: an EXTERNAL connection drops the events table. The bus's
    // pooled connections hold no transaction between emits (locks are
    // per-transaction), so the external writer takes the WAL write lock freely.
    {
        let external = rusqlite::Connection::open(&db_path).expect("external conn");
        external
            .execute_batch("DROP TABLE events;")
            .expect("drop the events table out from under the bus");
    }

    // Event #2: the JSONL append runs FIRST and succeeds; the SQLite index
    // fails (cached INSERT auto-reprepares against the changed schema cookie
    // → "no such table: events").
    bus.emit(event("evt-231-post", "fs.write"));

    // The JSONL file contains BOTH lines — no event loss.
    let today = jsonl_dir.join(format!("{}.jsonl", Utc::now().date_naive()));
    let content = std::fs::read_to_string(&today).expect("jsonl file present");
    assert!(
        content.contains("evt-231-pre"),
        "healthy event line present"
    );
    assert!(
        content.contains("evt-231-post"),
        "the event line written while SQLite was failing is STILL in the JSONL: {content:?}"
    );

    // The SQLite row for event #2 is absent (the table is gone) — the index
    // lost it, the log did not.
    {
        let check = rusqlite::Connection::open(&db_path).expect("check conn");
        let table_count: i64 = check
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='events'",
                [],
                |r| r.get(0),
            )
            .expect("schema query");
        assert_eq!(table_count, 0, "events table really is gone");
    }

    // Secondary assertion (pre-committed as droppable if non-deterministic;
    // see plan): the failed index increments dropped_count exactly once.
    assert_eq!(
        bus.dropped_count(),
        1,
        "the SQLite-failed emit counts one dropped sink-write"
    );
}

//! SYS-J-41 — every host-function event is appended to JSONL and SQLite and
//! queryable via the HTTP history API. Chain: MODULE-001 → MODULE-019 → MODULE-004.
//!
//! Witnesses **SYS-AC-133**: "GET /query/events?event_type=<type> returns the
//! persisted event, confirming the HTTP history API is queryable."
//!
//! Witness design (harvest-obs slice, 2026-06-10): a REAL guest turn through the
//! production composition root performs an `agent-fs::write` → the real cap-fs
//! provider emits `fs.write` via the real `EventBusEmit` → the harness RealBus
//! (sync `EventBus`) indexes it into the production-schema `events` table
//! (sys_j47 precedent). The HTTP-API leg is then witnessed twice:
//!
//! - **Leg B (the witnessing leg)**: a REAL TCP socket GET against a production
//!   `EventBus::new` axum server (the same `.nest("/query", query_router(..))`
//!   mount the daemon runs, event-bus/src/lib.rs:431-434) opened over the SAME
//!   events.db (WAL + NO_MUTEX + busy_timeout — dual-open safe; schema apply
//!   idempotent). This is a genuine network round-trip through the production
//!   listener, router, governor, and handler.
//! - **Leg A (supporting)**: `tower::ServiceExt::oneshot` against the production
//!   `query_router` over an r2d2 pool on the same db (the event-bus crate's own
//!   tests/query_api.rs precedent; `ConnectInfo` inserted defensively for the
//!   GovernorLayer).
//!
//! No module of the M001→M019→M004 chain is mocked.

use std::net::SocketAddr;

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::OpenFlags;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

use advance_event_bus::query_api::{query_router, QueryState};
use advance_event_bus::{EventBus, EventBusConfig};
use system_acceptance::{Cap, EventSink, SystemUnderTest};

const J01_SKELETON: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

/// Minimal HTTP/1.1 GET over a raw TCP socket (no client dependency); returns
/// (status_line, body). `Connection: close` so read_to_end terminates.
async fn raw_http_get(addr: SocketAddr, path_and_query: &str) -> (String, String) {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let req = format!("GET {path_and_query} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .expect("write request");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read response");
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .expect("response has header/body separator");
    let status_line = head.lines().next().unwrap_or_default().to_string();
    (status_line, body.to_string())
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_133_query_events_returns_persisted_host_fn_event_over_http() {
    // 1. REAL guest turn → real fs.write event persisted by the real bus.
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .events(EventSink::RealBus)
        .build(J01_SKELETON)
        .await;
    sut.inject_message("alice", b"sys-j41-query-api").await;
    sut.run_turn().await;
    sut.assert_db_event("fs.write", |r| {
        r.agent_id.as_deref() == Some(sut.agent_id())
    });
    sut.assert_no_dropped_events();
    let db_path = sut
        .event_db_path()
        .expect("RealBus exposes the events.db path")
        .to_path_buf();

    // 2. Leg B (witnessing leg): production EventBus::new serves /query over a
    //    REAL TCP socket; same events.db (fresh jsonl dir for the overlay bus).
    let overlay_jsonl = tempfile::TempDir::new().unwrap();
    let mut cfg = EventBusConfig::new(overlay_jsonl.path().to_path_buf(), db_path.clone());
    cfg.websocket_addr = "127.0.0.1:0".parse().unwrap();
    let server_bus = EventBus::new(cfg).await.expect("async EventBus::new");
    let addr = server_bus.server_addr().expect("bound server addr");

    let (status_line, body) = raw_http_get(addr, "/query/events?event_type=fs.write").await;
    assert!(
        status_line.contains("200"),
        "GET /query/events over a real socket returns 200, got: {status_line}"
    );
    let v: serde_json::Value = serde_json::from_str(&body).expect("JSON array body");
    let arr = v.as_array().expect("top-level array of EventRow");
    assert!(
        !arr.is_empty(),
        "the persisted fs.write event comes back through the HTTP history API"
    );
    let row = &arr[0];
    assert_eq!(row["event_type"], "fs.write");
    assert_eq!(
        row["agent_id"].as_str(),
        Some(sut.agent_id()),
        "the returned row is the real guest turn's event"
    );
    assert!(
        row["payload"].as_str().is_some(),
        "EventRow.payload carries the raw payload column"
    );

    // 3. Leg A (supporting): oneshot against the production router over the
    //    same store — the event-bus crate's own precedent pattern.
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let mgr = SqliteConnectionManager::file(&db_path).with_flags(flags);
    let pool = std::sync::Arc::new(r2d2::Pool::builder().max_size(2).build(mgr).unwrap());
    let router = query_router(QueryState { pool });
    let mut request = Request::builder()
        .uri("/events?event_type=fs.write")
        .body(Body::empty())
        .unwrap();
    request.extensions_mut().insert(ConnectInfo::<SocketAddr>(
        "127.0.0.1:65001".parse().unwrap(),
    ));
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = v.as_array().expect("array");
    assert!(
        !arr.is_empty(),
        "oneshot router leg agrees with the socket leg"
    );
    assert_eq!(arr[0]["event_type"], "fs.write");
}

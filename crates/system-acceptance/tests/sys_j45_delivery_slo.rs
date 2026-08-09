//! SYS-J-45 — when mailbox delivery latency exceeds the SLO, a
//! mailbox.delivery_slow event is emitted and visible in observability.
//! Chain: MODULE-006 → MODULE-019 → MODULE-004.
//!
//! Witnesses (harvest-obs slice, 2026-06-10): **SYS-AC-143, SYS-AC-144,
//! SYS-AC-145** — test-local real wiring, ZERO product changes:
//! - the REAL `MailboxDispatcherImpl` (M006) measures `delivery_latency_ms`
//!   from function entry and emits `msg.received` on every successful delivery;
//! - the REAL async `EventBus::new` (M019 — the production constructor, the
//!   only mode containing the `EmitPipeline` breach mirror) compares against
//!   the pub config threshold (`mailbox_delivery_slow_threshold_ms`, strict
//!   `>`) and synthesizes `mailbox.delivery_slow`;
//! - the REAL production-schema SQLite + the REAL axum `/query` server (M004 +
//!   the query surface) make it queryable over a real TCP socket.
//!
//! Latency induction (143/145) is ENVIRONMENTAL: the dispatcher's
//! `Arc<dyn AgentTreeReader>` dependency is a test double whose sync
//! `agent_exists` sleeps via `std::thread::sleep` (the trait is sync — a tokio
//! sleep cannot run there; multi_thread flavor keeps the worker pool live)
//! before answering truthfully. The dispatcher's pipeline, clock, threshold
//! compare, mirror synthesis, and query path are all production code; no module
//! of the chain is mocked and no outcome is hardcoded. A hard self-checking
//! gate asserts the measured latency exceeds the injected sleep BEFORE any
//! mirror assertion (plan-eval r7), so a mis-built double fails loudly with the
//! correct attribution.
//!
//! 144 runs against the DEFAULT 1000ms threshold on a separate bus so cold-box
//! latency spikes cannot leak mirror events into its exactly-N assertion.

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use advance_event_bus::{EventBus, EventBusConfig};
use advance_messaging::{MailboxDispatcher, MailboxDispatcherImpl, MailboxStore};
use advance_shared_types::agent_tree::{AgentKind, AgentTreeReader, Capability};
use advance_shared_types::mailbox::{Message, MessageKind};
use advance_shared_types::traits::EventBusEmit;
use rusqlite::OpenFlags;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Messaging-layer ids carry the `agent:`/`user:` prefix (is_safe_id,
// messaging/src/id_validation.rs) — unlike cap-lifecycle's bare-id convention.
const TARGET: &str = "agent:obs-slo";

/// Truthful tree double with injectable lookup latency. `validate_routing`
/// calls `agent_exists(to)` (and the USER_PREFIX rule short-circuits the
/// adjacency legs for `user:`-from sends) — sleeping here inflates the REAL
/// latency the production dispatcher measures from function entry.
struct SleepyTree {
    delay: Duration,
}
impl AgentTreeReader for SleepyTree {
    fn parent_of(&self, _: &str) -> Option<String> {
        None
    }
    fn children_of(&self, _: &str) -> Vec<String> {
        Vec::new()
    }
    fn siblings_of(&self, _: &str) -> Vec<String> {
        Vec::new()
    }
    fn agent_exists(&self, agent_id: &str) -> bool {
        if !self.delay.is_zero() {
            std::thread::sleep(self.delay); // sync trait — std sleep, NOT tokio
        }
        agent_id == TARGET
    }
    fn agent_kind(&self, _: &str) -> Option<AgentKind> {
        Some(AgentKind::Child)
    }
    fn capabilities(&self, _: &str) -> Vec<Capability> {
        Vec::new()
    }
}

fn msg(n: u32) -> Message {
    Message {
        id: format!("slo-msg-{n}"),
        kind: MessageKind::User,
        from: "user:slo".into(),
        to: TARGET.into(),
        payload: format!("slo-{n}").into_bytes(),
        context: None,
        timestamp: SystemTime::now(),
        origin: None,
    }
}

/// Production async EventBus over a unique temp base with the given SLO
/// threshold; returns (bus, events.db path).
async fn async_bus(tag: &str, threshold_ms: u64) -> (Arc<EventBus>, std::path::PathBuf) {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!("adv-obs-slo-{tag}-{nanos}"));
    std::fs::create_dir_all(&base).unwrap();
    let db = base.join("events.db");
    let mut cfg = EventBusConfig::new(base.join("jsonl"), db.clone());
    cfg.websocket_addr = "127.0.0.1:0".parse().unwrap();
    cfg.mailbox_delivery_slow_threshold_ms = threshold_ms;
    let bus = EventBus::new(cfg).await.expect("async EventBus::new");
    (Arc::new(bus), db)
}

/// Bounded poll of the events table (the async db actor writes per-event but
/// asynchronously): returns the payloads of rows matching `event_type` once
/// `min` rows are visible, panicking after ~5s.
fn poll_events(db: &std::path::Path, event_type: &str, min: usize) -> Vec<serde_json::Value> {
    for _ in 0..1000 {
        if let Ok(conn) = rusqlite::Connection::open_with_flags(
            db,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ) {
            let rows: Vec<(String, Option<String>, String)> = conn
                .prepare(
                    "SELECT payload, parent_span_id, agent_id FROM events \
                     WHERE event_type = ?1 ORDER BY timestamp",
                )
                .ok()
                .map(|mut stmt| {
                    stmt.query_map([event_type], |r| {
                        Ok((
                            r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                            r.get::<_, Option<String>>(1)?,
                            r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                        ))
                    })
                    .map(|it| it.filter_map(Result::ok).collect())
                    .unwrap_or_default()
                })
                .unwrap_or_default();
            if rows.len() >= min {
                return rows
                    .into_iter()
                    .map(|(p, parent_span, agent)| {
                        let mut v: serde_json::Value =
                            serde_json::from_str(&p).unwrap_or(serde_json::json!({}));
                        v["__parent_span_id"] = serde_json::json!(parent_span);
                        v["__agent_id"] = serde_json::json!(agent);
                        v
                    })
                    .collect();
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("events table never reached {min} row(s) of {event_type} within ~5s");
}

/// Count rows of an event type (no minimum wait — for exactly-N assertions
/// after the expected rows are already visible).
fn count_events(db: &std::path::Path, event_type: &str) -> usize {
    let conn = rusqlite::Connection::open_with_flags(
        db,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    conn.query_row(
        "SELECT COUNT(*) FROM events WHERE event_type = ?1",
        [event_type],
        |r| r.get::<_, i64>(0),
    )
    .unwrap() as usize
}

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
    let (head, body) = text.split_once("\r\n\r\n").expect("header/body separator");
    (
        head.lines().next().unwrap_or_default().to_string(),
        body.to_string(),
    )
}

/// SYS-AC-144 — every successful mailbox delivery emits exactly one
/// msg.received carrying payload.delivery_latency_ms (default threshold, fast
/// tree — no mirrors in play).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_144_every_delivery_emits_one_msg_received_with_latency() {
    let (bus, db) = async_bus("144", 1000).await;
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    let store = Arc::new(MailboxStore::new(NonZeroUsize::new(64).unwrap()));
    let dispatcher = MailboxDispatcherImpl::new(
        store,
        Arc::new(SleepyTree {
            delay: Duration::ZERO,
        }),
    )
    .with_event_bus(bus_dyn);

    for n in 0..3 {
        dispatcher
            .deliver(TARGET, msg(n))
            .await
            .expect("successful delivery");
    }

    let received = poll_events(&db, "msg.received", 3);
    assert_eq!(
        received.len(),
        3,
        "exactly one msg.received per successful delivery"
    );
    assert_eq!(
        count_events(&db, "msg.received"),
        3,
        "no extra msg.received rows"
    );
    for (i, p) in received.iter().enumerate() {
        assert!(
            p.get("delivery_latency_ms")
                .and_then(|v| v.as_u64())
                .is_some(),
            "msg.received #{i} payload carries delivery_latency_ms, got {p}"
        );
        assert_eq!(p["to"], TARGET, "delivery target recorded");
    }
}

/// SYS-AC-143 + SYS-AC-145 — a delivery whose REAL measured latency exceeds
/// the (lowered) threshold causes exactly one mailbox.delivery_slow with
/// payload {agent_id, latency_ms}, queryable via GET /query/events over a real
/// socket.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_143_145_slow_delivery_emits_queryable_breach_mirror() {
    const THRESHOLD_MS: u64 = 5;
    const INJECTED_SLEEP_MS: u64 = 25;
    let (bus, db) = async_bus("143", THRESHOLD_MS).await;
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    let store = Arc::new(MailboxStore::new(NonZeroUsize::new(64).unwrap()));
    let dispatcher = MailboxDispatcherImpl::new(
        store,
        Arc::new(SleepyTree {
            delay: Duration::from_millis(INJECTED_SLEEP_MS),
        }),
    )
    .with_event_bus(bus_dyn);

    dispatcher
        .deliver(TARGET, msg(0))
        .await
        .expect("slow but successful delivery");

    // Hard self-checking gate (plan-eval r7): the REAL measured latency must
    // reflect the injected environmental delay BEFORE any mirror assertion.
    let received = poll_events(&db, "msg.received", 1);
    let measured = received[0]["delivery_latency_ms"]
        .as_u64()
        .expect("msg.received carries delivery_latency_ms");
    assert!(
        measured >= INJECTED_SLEEP_MS,
        "measured delivery_latency_ms ({measured}) >= injected sleep \
         ({INJECTED_SLEEP_MS}ms) — if this fails the latency injection is \
         mis-built (wrong sleep API / test flavor), NOT a product gap"
    );

    // SYS-AC-143: the breach mirror fired with the spec'd payload.
    let mirrors = poll_events(&db, "mailbox.delivery_slow", 1);
    assert_eq!(
        mirrors.len(),
        1,
        "exactly one mirror for the one slow delivery"
    );
    let m = &mirrors[0];
    assert_eq!(
        m["agent_id"], TARGET,
        "payload.agent_id is the delivery target"
    );
    let latency = m["latency_ms"]
        .as_u64()
        .expect("payload.latency_ms present");
    assert!(
        latency > THRESHOLD_MS,
        "payload.latency_ms ({latency}) > threshold ({THRESHOLD_MS})"
    );
    assert_eq!(
        m["__agent_id"], TARGET,
        "struct agent_id propagated from source"
    );
    assert!(
        m["__parent_span_id"].as_str().is_some(),
        "mirror links its source via parent_span_id (breach-mirror linkage; \
         noted as supporting evidence only — SYS-AC-138 chain-span intent stays \
         deferred per the plan gate)"
    );

    // SYS-AC-145: visible via the production /query surface over a real socket.
    let addr = bus.server_addr().expect("query server bound");
    let (status_line, body) =
        raw_http_get(addr, "/query/events?event_type=mailbox.delivery_slow").await;
    assert!(
        status_line.contains("200"),
        "200 from /query/events, got {status_line}"
    );
    let v: serde_json::Value = serde_json::from_str(&body).expect("JSON array");
    let arr = v.as_array().expect("array of EventRow");
    assert_eq!(arr.len(), 1, "the mirror is queryable");
    let row = &arr[0];
    assert_eq!(row["event_type"], "mailbox.delivery_slow");
    assert_eq!(row["agent_id"], TARGET);
    let payload: serde_json::Value =
        serde_json::from_str(row["payload"].as_str().expect("payload string")).unwrap();
    assert_eq!(
        payload["agent_id"], TARGET,
        "queryable payload carries agent_id"
    );
    assert!(
        payload["latency_ms"].as_u64().is_some(),
        "queryable payload carries latency_ms"
    );
}

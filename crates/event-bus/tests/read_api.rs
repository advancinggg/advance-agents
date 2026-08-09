//! MODULE-019-AC-23 / CONTRACT-185 `ObservabilityReadApi` witnesses (T82–T88).
//!
//! Every test drives the REAL async `EventBus::new` (witness-floor real
//! substrate) and reads through `EventBus::read_api()`. The stress witnesses
//! (T84 concurrent-emit vs the DB truth-set, T86 >1000 overflow) exercise the
//! exact interleavings the plan's adversarial review used to refute a
//! broadcast-splice design — for a correct DB-tail impl they are deterministic.

use std::sync::Arc;
use std::time::Duration;

use advance_event_bus::{
    Clock, EventBus, EventBusConfig, EventFilter, ObservabilityReadApi, ReadApiError, ReadCursor,
    ReadNext,
};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use chrono::{DateTime, TimeZone, Timelike, Utc};
use serde_json::json;

// ─── helpers ─────────────────────────────────────────────────────────────────

fn cfg(jsonl: &std::path::Path, db: &std::path::Path) -> EventBusConfig {
    let mut c = EventBusConfig::new(jsonl.to_path_buf(), db.to_path_buf());
    c.websocket_addr = "127.0.0.1:0".parse().unwrap(); // OS-assigned port (parallel-safe)
    c
}

/// A fixed wall-clock for deterministic retention-boundary tests.
struct FixedClock(DateTime<Utc>);
impl Clock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

fn ev(id: &str, event_type: &str) -> Event {
    Event {
        id: id.into(),
        timestamp: Utc::now(),
        agent_id: "agent-a".into(),
        task_id: None,
        run_id: None,
        execution_id: None,
        trace_id: "tr-1".into(),
        span_id: "s-1".into(),
        parent_span_id: None,
        event_type: event_type.into(),
        payload: json!({}),
        duration_ms: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn ev_full(
    id: &str,
    event_type: &str,
    agent_id: &str,
    run_id: Option<&str>,
    trace_id: &str,
    ts: DateTime<Utc>,
) -> Event {
    Event {
        id: id.into(),
        timestamp: ts,
        agent_id: agent_id.into(),
        task_id: None,
        run_id: run_id.map(|s| s.into()),
        execution_id: None,
        trace_id: trace_id.into(),
        span_id: "s-1".into(),
        parent_span_id: None,
        event_type: event_type.into(),
        payload: json!({}),
        duration_ms: None,
    }
}

/// Drain a `resume` stream to exhaustion: collect delivered ids until `recv()`
/// blocks past `idle` (caught up — no more events for now).
async fn drain_resume(stream: &mut advance_event_bus::ResumeStream, idle: Duration) -> Vec<String> {
    let mut out = Vec::new();
    loop {
        match tokio::time::timeout(idle, stream.recv()).await {
            Ok(Ok(Some(re))) => out.push(re.event.id.clone()),
            Ok(Ok(None)) => break,
            Ok(Err(e)) => panic!("resume recv error: {e}"),
            Err(_) => break, // idle timeout — caught up
        }
    }
    out
}

/// Truth-set: ids in the persisted store with `rowid > rowid(after_id)`, in
/// rowid order (the exact sequence a correct `resume(after_id)` must deliver
/// with no filter/retention exclusion).
fn db_ids_after(db: &std::path::Path, after_id: &str) -> Vec<String> {
    let conn = rusqlite::Connection::open(db).unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id FROM events \
             WHERE rowid > (SELECT rowid FROM events WHERE id = ?1) \
             ORDER BY rowid",
        )
        .unwrap();
    let ids = stmt
        .query_map([after_id], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    ids
}

fn db_count(db: &std::path::Path) -> u64 {
    let conn = rusqlite::Connection::open(db).unwrap();
    conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
        .unwrap()
}

// ─── T82 — filtered live subscribe + emit order (AC-23 a) ────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t82_filtered_live_subscribe_in_emit_order() {
    let temp = tempfile::TempDir::new().unwrap();
    let bus = EventBus::new(cfg(&temp.path().join("j"), &temp.path().join("events.db")))
        .await
        .expect("bus");
    let read = bus.read_api().expect("async bus → read_api Some");

    // Subscribe BEFORE emitting (broadcast delivers only post-subscribe events).
    let mut sub = read.subscribe(EventFilter {
        event_type_prefix: Some("llm.".into()),
        ..Default::default()
    });

    // Interleave 3 matching (llm.*) + 2 non-matching (fs.*).
    bus.emit(ev("l1", "llm.request"));
    bus.emit(ev("f1", "fs.read"));
    bus.emit(ev("l2", "llm.response"));
    bus.emit(ev("f2", "fs.write"));
    bus.emit(ev("l3", "llm.retry"));

    let mut got = Vec::new();
    for _ in 0..3 {
        match tokio::time::timeout(Duration::from_secs(2), sub.recv()).await {
            Ok(ReadNext::Event(e)) => got.push(e.id.clone()),
            other => panic!("expected Event, got {other:?}"),
        }
    }
    assert_eq!(
        got,
        vec!["l1", "l2", "l3"],
        "3 llm.* in emit order, fs.* filtered"
    );

    // No further matching event: recv() blocks → timeout.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), sub.recv())
            .await
            .is_err(),
        "no 4th llm.* — the 2 fs.* must NOT be delivered"
    );

    bus.shutdown().await;
}

// ─── T83 — match-all live subscribe preserves emit order ─────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t83_live_subscribe_preserves_emit_order() {
    let temp = tempfile::TempDir::new().unwrap();
    let bus = EventBus::new(cfg(&temp.path().join("j"), &temp.path().join("events.db")))
        .await
        .expect("bus");
    let read = bus.read_api().unwrap();
    let mut sub = read.subscribe(EventFilter::default());

    let expected: Vec<String> = (0..25).map(|i| format!("e{i}")).collect();
    for id in &expected {
        bus.emit(ev(id, "task.created"));
    }

    let mut got = Vec::new();
    for _ in 0..expected.len() {
        match tokio::time::timeout(Duration::from_secs(2), sub.recv()).await {
            Ok(ReadNext::Event(e)) => got.push(e.id.clone()),
            other => panic!("expected Event, got {other:?}"),
        }
    }
    assert_eq!(got, expected, "delivered order == emit order");
    bus.shutdown().await;
}

// ─── T84 — durable resume is gap-free vs the DB truth-set (AC-23 b, STRESS) ──

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t84_resume_gap_free_vs_db_truth_set_under_concurrency() {
    let temp = tempfile::TempDir::new().unwrap();
    let db = temp.path().join("events.db");
    let bus = Arc::new(
        EventBus::new(cfg(&temp.path().join("j"), &db))
            .await
            .expect("bus"),
    );
    let read = bus.read_api().unwrap();

    // Anchor first, persisted → becomes the durable cursor.
    bus.emit(ev("anchor", "run.created"));
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Burst 240 events from 8 concurrent tasks (persist/broadcast skew would
    // manifest here under the refuted broadcast-splice design).
    let mut tasks = Vec::new();
    for t in 0..8u32 {
        let b = bus.clone();
        tasks.push(tokio::spawn(async move {
            for i in 0..30u32 {
                b.emit(ev(&format!("b-{t}-{i}"), "msg.received"));
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(500)).await; // let all 240 persist

    let mut stream = read
        .resume(Some(ReadCursor("anchor".into())), EventFilter::default())
        .await
        .expect("resume");
    let delivered = drain_resume(&mut stream, Duration::from_millis(600)).await;

    let truth = db_ids_after(&db, "anchor");
    assert_eq!(
        truth.len(),
        240,
        "sanity: 240 events after the anchor persisted"
    );
    assert_eq!(
        delivered, truth,
        "resume delivered EXACTLY the committed rowid-ordered tail — zero gap, zero dup"
    );
    // no dup
    let mut uniq = delivered.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(uniq.len(), delivered.len(), "no duplicate delivery");

    Arc::try_unwrap(bus)
        .map_err(|_| ())
        .unwrap()
        .shutdown()
        .await;
}

// ─── T84b — resume LIVE SPLICE after catch-up (AC-23 b) ───────────────────────
// The criterion's "replay + LIVE SPLICE": after a resume stream has caught up to
// the current end, a NEW event emitted AFTERWARD must be delivered via the
// continued tail. This drives the live-splice half as a closed loop (all other
// resume tests emit BEFORE resume = replay only).

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t84b_resume_live_splice_after_catchup() {
    let temp = tempfile::TempDir::new().unwrap();
    let db = temp.path().join("events.db");
    let bus = EventBus::new(cfg(&temp.path().join("j"), &db))
        .await
        .expect("bus");
    let read = bus.read_api().unwrap();

    // Backlog: A (emitted + persisted BEFORE resume).
    bus.emit(ev("A", "run.created"));
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut stream = read.resume(None, EventFilter::default()).await.unwrap();

    // Replay the backlog → A, then the stream is caught up.
    match tokio::time::timeout(Duration::from_secs(1), stream.recv()).await {
        Ok(Ok(Some(re))) => assert_eq!(re.event.id, "A", "replay delivers the backlog first"),
        other => panic!("expected replayed A, got {other:?}"),
    }

    // LIVE SPLICE: emit B AFTER the stream has caught up (no pre-persist sleep) —
    // the continued DB-tail must pick it up.
    bus.emit(ev("B", "run.round_completed"));
    match tokio::time::timeout(Duration::from_secs(3), stream.recv()).await {
        Ok(Ok(Some(re))) => assert_eq!(
            re.event.id, "B",
            "live-splice delivers the post-catch-up event"
        ),
        other => panic!("expected live-spliced B (post-catch-up), got {other:?}"),
    }

    // And a second post-catch-up event, to prove the splice is a continuing tail.
    bus.emit(ev("C", "run.round_completed"));
    match tokio::time::timeout(Duration::from_secs(3), stream.recv()).await {
        Ok(Ok(Some(re))) => assert_eq!(re.event.id, "C", "the live splice keeps tailing"),
        other => panic!("expected live-spliced C, got {other:?}"),
    }

    bus.shutdown().await;
}

// ─── T85 — cursor discriminators + CursorNotFound (AC-23 b) ──────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t85_cursor_discriminators() {
    let temp = tempfile::TempDir::new().unwrap();
    let db = temp.path().join("events.db");
    let bus = EventBus::new(cfg(&temp.path().join("j"), &db))
        .await
        .expect("bus");
    let read = bus.read_api().unwrap();

    for i in 1..=5 {
        bus.emit(ev(&format!("e{i}"), "task.created"));
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    // latest cursor → empty backlog.
    let mut s_latest = read
        .resume(Some(ReadCursor("e5".into())), EventFilter::default())
        .await
        .unwrap();
    assert!(
        drain_resume(&mut s_latest, Duration::from_millis(300))
            .await
            .is_empty(),
        "resume from latest ⇒ no backlog"
    );

    // earliest cursor → all-after.
    let mut s_early = read
        .resume(Some(ReadCursor("e1".into())), EventFilter::default())
        .await
        .unwrap();
    assert_eq!(
        drain_resume(&mut s_early, Duration::from_millis(400)).await,
        vec!["e2", "e3", "e4", "e5"],
        "resume from earliest ⇒ everything after it"
    );

    // None cursor → whole retained window.
    let mut s_all = read.resume(None, EventFilter::default()).await.unwrap();
    assert_eq!(
        drain_resume(&mut s_all, Duration::from_millis(400)).await,
        vec!["e1", "e2", "e3", "e4", "e5"],
        "resume(None) ⇒ full retained window"
    );

    // nonexistent cursor → defensive CursorNotFound (NOT a silent full re-replay).
    match read
        .resume(
            Some(ReadCursor("does-not-exist".into())),
            EventFilter::default(),
        )
        .await
    {
        Err(ReadApiError::CursorNotFound(id)) => assert_eq!(id, "does-not-exist"),
        Err(e) => panic!("expected CursorNotFound, got a different error: {e}"),
        Ok(_) => panic!("expected CursorNotFound, got Ok(stream) — silent re-replay!"),
    }

    bus.shutdown().await;
}

// ─── T86 — overflow (no ring drop) + Lagged surfaced + retention boundary ────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t86a_resume_survives_overflow_but_subscribe_surfaces_lagged() {
    let temp = tempfile::TempDir::new().unwrap();
    let db = temp.path().join("events.db");
    let bus = EventBus::new(cfg(&temp.path().join("j"), &db))
        .await
        .expect("bus");
    let read = bus.read_api().unwrap();

    // A live subscriber that we deliberately do NOT drain.
    let mut lagging = read.subscribe(EventFilter::default());

    // Emit > the 1000-slot broadcast ring.
    for i in 0..1500u32 {
        bus.emit(ev(&format!("o{i}"), "task.created"));
    }
    tokio::time::sleep(Duration::from_millis(800)).await; // persist all 1500

    // (i) DB-tail resume has NO ring — delivers every committed row.
    let mut stream = read.resume(None, EventFilter::default()).await.unwrap();
    let delivered = drain_resume(&mut stream, Duration::from_millis(700)).await;
    assert_eq!(
        delivered.len() as u64,
        db_count(&db),
        "resume delivered every committed row — pull-based, no overflow drop"
    );
    assert_eq!(delivered.len(), 1500, "all 1500 committed + delivered");

    // (ii) the un-drained live subscriber surfaces Lagged (not a silent gap).
    let mut saw_lag = false;
    for _ in 0..1500 {
        match tokio::time::timeout(Duration::from_millis(300), lagging.recv()).await {
            Ok(ReadNext::Lagged { skipped }) => {
                assert!(skipped > 0);
                saw_lag = true;
                break;
            }
            Ok(ReadNext::Event(_)) => continue,
            Ok(ReadNext::Closed) => break,
            Err(_) => break,
        }
    }
    assert!(
        saw_lag,
        "un-drained subscribe past the 1000 ring MUST surface Lagged"
    );

    bus.shutdown().await;
}

// ─── T85b — resume cross-batch forward-progress over a sparse filter (AC-23 b) ─
// Witnesses the round-6 no-rescan property DISCRIMINATINGLY: the sole match sits
// BEYOND the first RESUME_BATCH (>512 non-matching rows before it), so it is only
// reachable if the rowid-contiguous tail advances `last_rowid` over an entirely
// non-matching batch and fetches the next one. A non-advancing / rescanning tail
// would never reach it (the drain would time out with nothing delivered).

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t85b_resume_sparse_filter_cross_batch_forward_progress() {
    let temp = tempfile::TempDir::new().unwrap();
    let db = temp.path().join("events.db");
    let bus = EventBus::new(cfg(&temp.path().join("j"), &db))
        .await
        .expect("bus");
    let read = bus.read_api().unwrap();

    // 600 non-matching rows (> RESUME_BATCH=512) BEFORE the match ⇒ the entire
    // first batch is non-matching; the match (rowid ~601) is in a later batch.
    for i in 0..600u32 {
        bus.emit(ev_full(
            &format!("noise-a{i}"),
            "task.created",
            "noise",
            None,
            "tr-n",
            Utc::now(),
        ));
    }
    bus.emit(ev_full(
        "the-match",
        "task.created",
        "target-agent",
        None,
        "tr-t",
        Utc::now(),
    ));
    for i in 0..100u32 {
        bus.emit(ev_full(
            &format!("noise-b{i}"),
            "task.created",
            "noise",
            None,
            "tr-n",
            Utc::now(),
        ));
    }
    tokio::time::sleep(Duration::from_millis(800)).await;

    let mut stream = read
        .resume(
            None,
            EventFilter {
                agent_id: Some("target-agent".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let delivered = drain_resume(&mut stream, Duration::from_millis(700)).await;
    assert_eq!(
        delivered,
        vec!["the-match"],
        "resume reaches the match BEYOND the first 512-row batch (cross-batch forward progress; a non-advancing/rescanning tail would never deliver it)"
    );

    bus.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t86b_retention_boundary_day_kept() {
    let temp = tempfile::TempDir::new().unwrap();
    let db = temp.path().join("events.db");

    // Fixed "today" = 2026-07-05; default retention_days = 30 ⇒ cutoff 2026-06-05.
    let today = Utc.with_ymd_and_hms(2026, 7, 5, 12, 0, 0).unwrap();
    let mut c = cfg(&temp.path().join("j"), &db);
    c.clock = Arc::new(FixedClock(today));
    c.jsonl_retention_days = 30;
    let bus = EventBus::new(c).await.expect("bus");
    let read = bus.read_api().unwrap();

    let before = Utc.with_ymd_and_hms(2026, 6, 4, 23, 59, 59).unwrap(); // day BEFORE window → excluded
    let boundary =
        Utc.with_ymd_and_hms(2026, 6, 5, 0, 0, 0).unwrap() + chrono::Duration::nanoseconds(1); // boundary day earliest instant → KEPT
    let now_ev = Utc.with_ymd_and_hms(2026, 7, 5, 8, 0, 0).unwrap();

    bus.emit(ev_full(
        "before",
        "task.created",
        "agent-a",
        None,
        "tr-1",
        before,
    ));
    bus.emit(ev_full(
        "boundary",
        "task.created",
        "agent-a",
        None,
        "tr-1",
        boundary,
    ));
    bus.emit(ev_full(
        "today",
        "task.created",
        "agent-a",
        None,
        "tr-1",
        now_ev,
    ));
    tokio::time::sleep(Duration::from_millis(300)).await;

    // query honors retention: excludes `before`, INCLUDES `boundary` + `today`.
    let rows = read.query(&EventFilter::default(), 100).await.unwrap();
    let ids: std::collections::HashSet<String> = rows.iter().map(|r| r.event.id.clone()).collect();
    assert!(
        !ids.contains("before"),
        "day-before-window event excluded by retention"
    );
    assert!(
        ids.contains("boundary"),
        "boundary-day event KEPT (a datetime/midnight cutoff would wrongly drop it)"
    );
    assert!(ids.contains("today"), "today event kept");

    // resume(None) honors the same retention window.
    let mut stream = read.resume(None, EventFilter::default()).await.unwrap();
    let delivered = drain_resume(&mut stream, Duration::from_millis(400)).await;
    let dset: std::collections::HashSet<String> = delivered.into_iter().collect();
    assert!(!dset.contains("before"));
    assert!(dset.contains("boundary") && dset.contains("today"));

    bus.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t86c_retention_zero_is_unbounded() {
    let temp = tempfile::TempDir::new().unwrap();
    let db = temp.path().join("events.db");
    let today = Utc.with_ymd_and_hms(2026, 7, 5, 12, 0, 0).unwrap();
    let mut c = cfg(&temp.path().join("j"), &db);
    c.clock = Arc::new(FixedClock(today));
    c.jsonl_retention_days = 0; // keep everything (matches the sweeper)
    let bus = EventBus::new(c).await.expect("bus");
    let read = bus.read_api().unwrap();

    let ancient = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
    bus.emit(ev_full(
        "ancient",
        "task.created",
        "agent-a",
        None,
        "tr-1",
        ancient,
    ));
    tokio::time::sleep(Duration::from_millis(200)).await;

    let rows = read.query(&EventFilter::default(), 100).await.unwrap();
    assert!(
        rows.iter().any(|r| r.event.id == "ancient"),
        "retention_days=0 ⇒ no cutoff, ancient event returned"
    );
    bus.shutdown().await;
}

// ─── T87 — query filters + limit cap + cursor identity (AC-23 c) ─────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t87_query_filters_limit_and_cursor() {
    let temp = tempfile::TempDir::new().unwrap();
    let db = temp.path().join("events.db");
    let bus = EventBus::new(cfg(&temp.path().join("j"), &db))
        .await
        .expect("bus");
    let read = bus.read_api().unwrap();

    let now = Utc::now();
    bus.emit(ev_full(
        "q1",
        "llm.request",
        "agent-x",
        Some("run-1"),
        "trace-A",
        now,
    ));
    bus.emit(ev_full(
        "q2",
        "llm.response",
        "agent-y",
        Some("run-2"),
        "trace-B",
        now,
    ));
    bus.emit(ev_full(
        "q3",
        "fs.read",
        "agent-x",
        Some("run-1"),
        "trace-A",
        now,
    ));
    tokio::time::sleep(Duration::from_millis(300)).await;

    // event_type_prefix "llm." → {q1, q2}
    let r = read
        .query(
            &EventFilter {
                event_type_prefix: Some("llm.".into()),
                ..Default::default()
            },
            100,
        )
        .await
        .unwrap();
    let ids: std::collections::HashSet<_> = r.iter().map(|e| e.event.id.clone()).collect();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains("q1") && ids.contains("q2"));

    // agent_id = agent-x → {q1, q3}
    let r = read
        .query(
            &EventFilter {
                agent_id: Some("agent-x".into()),
                ..Default::default()
            },
            100,
        )
        .await
        .unwrap();
    let ids: std::collections::HashSet<_> = r.iter().map(|e| e.event.id.clone()).collect();
    assert_eq!(ids, ["q1", "q3"].into_iter().map(String::from).collect());

    // run_id + trace_id exact
    let r = read
        .query(
            &EventFilter {
                run_id: Some("run-2".into()),
                trace_id: Some("trace-B".into()),
                ..Default::default()
            },
            100,
        )
        .await
        .unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].event.id, "q2");
    // cursor identity: each ReadEvent.cursor == its own id.
    assert_eq!(r[0].cursor, ReadCursor("q2".into()));

    // limit is honored (cap ≤ MAX_LIMIT=1000; here we just check the bound works).
    let r = read.query(&EventFilter::default(), 2).await.unwrap();
    assert!(r.len() <= 2, "explicit limit honored");

    bus.shutdown().await;
}

// ─── T87b — since filter survives rowid/timestamp inversion (AC-23 c) ────────
// Anti-fake-green for the round-6 query fix: a backdated event holds the NEWEST
// rowid, so a naive "LIMIT by rowid, then drop by since" would silently return
// empty. `since` in SQL makes LIMIT operate on the since-matching set.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t87b_since_filter_survives_rowid_timestamp_inversion() {
    let temp = tempfile::TempDir::new().unwrap();
    let db = temp.path().join("events.db");
    let bus = EventBus::new(cfg(&temp.path().join("j"), &db))
        .await
        .expect("bus");
    let read = bus.read_api().unwrap();

    let recent = Utc::now();
    let backdated = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
    // e_recent gets the LOWER rowid; e_backdated (older timestamp) gets the HIGHER
    // rowid — the exact inversion that trips a post-LIMIT since drop.
    bus.emit(ev_full(
        "e_recent",
        "task.created",
        "agent-a",
        None,
        "tr-1",
        recent,
    ));
    bus.emit(ev_full(
        "e_backdated",
        "task.created",
        "agent-a",
        None,
        "tr-1",
        backdated,
    ));
    tokio::time::sleep(Duration::from_millis(300)).await;

    let since = "2021-01-01T00:00:00Z".to_string();

    // query(since, limit=1): with the fix, LIMIT operates on the since-matching
    // set {e_recent}, so it returns e_recent — NOT empty (the old bug).
    let rows = read
        .query(
            &EventFilter {
                since: Some(since.clone()),
                ..Default::default()
            },
            1,
        )
        .await
        .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "since must not be starved by the newest backdated rowid"
    );
    assert_eq!(rows[0].event.id, "e_recent");

    // resume honors since too (precise instant): only e_recent, not e_backdated.
    let mut stream = read
        .resume(
            None,
            EventFilter {
                since: Some(since),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let delivered = drain_resume(&mut stream, Duration::from_millis(400)).await;
    assert_eq!(
        delivered,
        vec!["e_recent"],
        "resume since excludes the backdated event"
    );

    // bad since string ⇒ BadFilter (validated before touching SQL).
    match read
        .query(
            &EventFilter {
                since: Some("not-a-date".into()),
                ..Default::default()
            },
            10,
        )
        .await
    {
        Err(ReadApiError::BadFilter(_)) => {}
        Err(e) => panic!("expected BadFilter, got {e}"),
        Ok(_) => panic!("expected BadFilter for a non-RFC-3339 since"),
    }

    // Sub-second boundary (round-7): with a whole-second `since`, a row 1 ns AFTER
    // it MUST be included — a raw lexicographic bind would drop it (`'.' < 'Z'`).
    // trace-filtered for determinism vs the wall-clock events above.
    //
    // FIXED 2026-08-06 (found by the m021-s7-capstone gate, which this crate serves as
    // a regression oracle for): this section used the FIXED date 2026-07-05, so when the
    // shared bus's 30-day retention window rolled past that date on 2026-08-04 all three
    // rows silently left the query window and the assert failed on `{}` — a date
    // time-bomb (t86b pins a fixed TODAY for exactly this reason). The boundary
    // semantics are date-independent, so the fixture second now derives from the real
    // clock, safely inside any retention window.
    let sec = (Utc::now() - chrono::Duration::minutes(10))
        .with_nanosecond(0)
        .unwrap();
    bus.emit(ev_full(
        "b_at",
        "task.created",
        "agent-a",
        None,
        "tr-boundary",
        sec,
    ));
    bus.emit(ev_full(
        "b_after_ns",
        "task.created",
        "agent-a",
        None,
        "tr-boundary",
        sec + chrono::Duration::nanoseconds(1),
    ));
    bus.emit(ev_full(
        "b_before",
        "task.created",
        "agent-a",
        None,
        "tr-boundary",
        sec - chrono::Duration::nanoseconds(1),
    ));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let brows = read
        .query(
            &EventFilter {
                since: Some(sec.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
                trace_id: Some("tr-boundary".into()),
                ..Default::default()
            },
            100,
        )
        .await
        .unwrap();
    let bids: std::collections::HashSet<String> =
        brows.iter().map(|r| r.event.id.clone()).collect();
    assert!(
        bids.contains("b_at") && bids.contains("b_after_ns"),
        "since must include the boundary second + the 1ns-after row (offset/fraction-safe); got {bids:?}"
    );
    assert!(
        !bids.contains("b_before"),
        "the 1ns-before-second row is excluded"
    );

    // Offset normalization (round-8): the SAME second rendered as +08:00 must equal
    // its Z form. A raw-string bind would compare "…+08:00" garbage; the
    // UTC-normalized bound treats it as the same second → b_at is included.
    // (FIXED 2026-08-06 with the boundary section above: was the fixed string
    // "2026-07-05T20:00:00+08:00", the same retention time-bomb.)
    let sec_off = sec
        .with_timezone(&chrono::FixedOffset::east_opt(8 * 3600).unwrap())
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, false);
    let offrows = read
        .query(
            &EventFilter {
                since: Some(sec_off),
                trace_id: Some("tr-boundary".into()),
                ..Default::default()
            },
            100,
        )
        .await
        .unwrap();
    let offids: std::collections::HashSet<String> =
        offrows.iter().map(|r| r.event.id.clone()).collect();
    assert!(
        offids.contains("b_at") && offids.contains("b_after_ns"),
        "an offset-form since must normalize to UTC (+08:00 form == Z form); got {offids:?}"
    );
    assert!(
        !offids.contains("b_before"),
        "offset since still excludes the earlier row"
    );

    bus.shutdown().await;
}

// ─── T88 — dyn object-safety + Sync→None + emit path untouched ───────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t88_object_safety_sync_none_and_emit_untouched() {
    let temp = tempfile::TempDir::new().unwrap();
    let db = temp.path().join("events.db");
    let bus = EventBus::new(cfg(&temp.path().join("j"), &db))
        .await
        .expect("bus");

    // dyn object-safety: read_api() already yields Arc<dyn ObservabilityReadApi>.
    let read: Arc<dyn ObservabilityReadApi> = bus.read_api().expect("Some");

    // Emit-path untouched: events still fan out to the db_indexer sink with the
    // read API present.
    for i in 0..12u32 {
        bus.emit(ev(&format!("u{i}"), "task.created"));
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        db_count(&db),
        12,
        "all 12 emits persisted — emit path intact"
    );
    let rows = read.query(&EventFilter::default(), 100).await.unwrap();
    assert_eq!(rows.len(), 12, "read api sees all 12");
    bus.shutdown().await;

    // Sync (test) bus has no broadcaster / server → read_api() is None.
    let temp2 = tempfile::TempDir::new().unwrap();
    let sync_bus = EventBus::new_synchronous_for_tests(EventBusConfig::new(
        temp2.path().join("j2"),
        temp2.path().join("events2.db"),
    ))
    .expect("sync bus");
    assert!(sync_bus.read_api().is_none(), "sync bus ⇒ read_api None");
}

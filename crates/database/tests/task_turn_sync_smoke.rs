//! MODULE-004 Slice H (m004-slice-h, 2026-05-24) — task_index + turn_index
//! incremental write surface integration tests. Closes AC-10 (task_index
//! sync per turn) + AC-11 (turn_index per-turn writes + reference_count
//! preservation per M011 §3.6 hard requirement). Verifies the 3 new
//! methods on `SqliteIndexHandle`:
//!   - `upsert_task_index`
//!   - `upsert_turn_index`
//!   - `bump_turn_reference`
//!
//! Test inventory (matches MODULE-004 §3.3 T-task-sync-* / T-turn-sync-*):
//!   T-task-sync-01      insert all fields
//!   T-task-sync-02      brief-change update with embedding refresh
//!   T-task-sync-03      sync-only-counter update (COALESCE preserves brief/status)
//!   T-task-sync-04      embedding-only refresh
//!   T-task-sync-04b     all-None COALESCE preserve + updated_at refreshes
//!   T-task-sync-04c     updated_at refreshes on UPDATE
//!   T-task-sync-05      pre-flight dim mismatch
//!   T-task-sync-06      pre-flight NaN / ±Inf embedding rejection
//!   T-task-sync-07      pre-flight separator-byte rejection
//!   T-task-sync-08      pre-flight empty/whitespace agent_id rejection
//!   T-task-sync-09      pre-flight invalid RFC 3339 last_turn_at
//!   T-task-sync-CROSS-AGENT          cross-agent task_id overwrite (PRD §11.3.3)
//!   T-task-sync-CROSS-AGENT-EMB-NONE cross-agent overwrite with embedding=None preserves prior embedding
//!   T-turn-sync-01      insert with 3-component id
//!   T-turn-sync-02      update digest + embedding (rowid stable; reference_count preserved)
//!   T-turn-sync-03      reference_count preserve-on-conflict (M011 §3.6)
//!   T-turn-sync-04      bump_turn_reference atomic increment
//!   T-turn-sync-04b     bump does NOT touch turn_vec (AC-31 invariant)
//!   T-turn-sync-05      bump_turn_reference idempotent on absent row
//!   T-turn-sync-06      embedding-optional insert
//!   T-turn-sync-07      embedding-add-later
//!   T-turn-sync-08      pre-flight invalid RFC 3339 timestamp
//!   T-turn-sync-09a..e  pre-flight validation split (dim / NaN / Inf / empty agent_id / separator)
//!   T-turn-sync-10      concurrent upsert different ids
//!   T-turn-sync-11      concurrent bump same id (pool_size=8)
//!   T-turn-sync-CROSS-AGENT    3-component id structurally isolates agents
//!   T-turn-sync-ID-CONSISTENCY id-PK vs row-column consistency on INSERT

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use advance_database::{DbError, R2d2SqliteIndexHandle, SqliteIndexHandle};

mod common;

#[allow(unused_imports)]
use common::*;

const ID_SEP: char = '\u{1F}';
const A_AGENT: &str = "A";
const B_AGENT: &str = "B";

fn turn_id(agent: &str, task: &str, turn: u32) -> String {
    format!("{agent}{ID_SEP}{task}{ID_SEP}turn-{turn}")
}

fn make_one_hot(idx: usize) -> Vec<f32> {
    let mut v = vec![0.0_f32; 768];
    v[idx] = 1.0;
    v
}

// ──────────────────────────────────────────────────────────────────────
// Helpers — direct-SQL row inspection (lighter than full snapshot structs)
// ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
struct TaskRow {
    task_id: String,
    agent_id: String,
    title: String,
    brief: Option<String>,
    status: Option<String>,
    last_turn_at: Option<String>,
    turns_total: Option<i64>,
    updated_at: Option<String>,
}

fn read_task_row(h: &R2d2SqliteIndexHandle, task_id: &str) -> Option<TaskRow> {
    let conn = h.get_conn().unwrap();
    conn.query_row(
        "SELECT task_id, agent_id, title, brief, status, last_turn_at, turns_total, updated_at \
         FROM task_index WHERE task_id = ?1",
        rusqlite::params![task_id],
        |r| {
            Ok(TaskRow {
                task_id: r.get(0)?,
                agent_id: r.get(1)?,
                title: r.get(2)?,
                brief: r.get(3)?,
                status: r.get(4)?,
                last_turn_at: r.get(5)?,
                turns_total: r.get(6)?,
                updated_at: r.get(7)?,
            })
        },
    )
    .ok()
}

#[derive(Debug, Clone, PartialEq)]
struct TurnRowFull {
    id: String,
    agent_id: String,
    task_id: String,
    turn: i64,
    timestamp: String,
    digest: String,
    importance: Option<String>,
    reference_count: i64,
    has_user_instruction: Option<i64>,
    has_user_correction: Option<i64>,
    has_tool_use: Option<i64>,
    has_decision: Option<i64>,
    tokens_digest: Option<i64>,
    tokens_l0_processed: Option<i64>,
    access_count: i64,
    last_accessed: Option<String>,
}

fn read_turn_row_full(h: &R2d2SqliteIndexHandle, id: &str) -> Option<TurnRowFull> {
    let conn = h.get_conn().unwrap();
    conn.query_row(
        "SELECT id, agent_id, task_id, turn, timestamp, digest, importance, reference_count, \
                has_user_instruction, has_user_correction, has_tool_use, has_decision, \
                tokens_digest, tokens_l0_processed, access_count, last_accessed \
         FROM turn_index WHERE id = ?1",
        rusqlite::params![id],
        |r| {
            Ok(TurnRowFull {
                id: r.get(0)?,
                agent_id: r.get(1)?,
                task_id: r.get(2)?,
                turn: r.get(3)?,
                timestamp: r.get(4)?,
                digest: r.get(5)?,
                importance: r.get(6)?,
                reference_count: r.get(7)?,
                has_user_instruction: r.get(8)?,
                has_user_correction: r.get(9)?,
                has_tool_use: r.get(10)?,
                has_decision: r.get(11)?,
                tokens_digest: r.get(12)?,
                tokens_l0_processed: r.get(13)?,
                access_count: r.get(14)?,
                last_accessed: r.get(15)?,
            })
        },
    )
    .ok()
}

fn turn_vec_count_by_rowid(h: &R2d2SqliteIndexHandle, rowid: i64) -> i64 {
    let conn = h.get_conn().unwrap();
    conn.query_row(
        "SELECT count(*) FROM turn_vec WHERE rowid = ?1",
        rusqlite::params![rowid],
        |r| r.get(0),
    )
    .unwrap()
}

fn task_vec_blob_by_rowid(h: &R2d2SqliteIndexHandle, rowid: i64) -> Option<Vec<u8>> {
    let conn = h.get_conn().unwrap();
    conn.query_row(
        "SELECT embedding FROM task_vec WHERE rowid = ?1",
        rusqlite::params![rowid],
        |r| r.get(0),
    )
    .ok()
}

fn turn_vec_blob_by_rowid(h: &R2d2SqliteIndexHandle, rowid: i64) -> Option<Vec<u8>> {
    let conn = h.get_conn().unwrap();
    conn.query_row(
        "SELECT embedding FROM turn_vec WHERE rowid = ?1",
        rusqlite::params![rowid],
        |r| r.get(0),
    )
    .ok()
}

fn turn_rowid(h: &R2d2SqliteIndexHandle, id: &str) -> i64 {
    let conn = h.get_conn().unwrap();
    conn.query_row(
        "SELECT rowid FROM turn_index WHERE id = ?1",
        rusqlite::params![id],
        |r| r.get(0),
    )
    .unwrap()
}

fn task_rowid(h: &R2d2SqliteIndexHandle, task_id: &str) -> i64 {
    let conn = h.get_conn().unwrap();
    conn.query_row(
        "SELECT rowid FROM task_index WHERE task_id = ?1",
        rusqlite::params![task_id],
        |r| r.get(0),
    )
    .unwrap()
}

// ──────────────────────────────────────────────────────────────────────
// task_index path
// ──────────────────────────────────────────────────────────────────────

#[test]
fn t_task_sync_01_insert_all_fields() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let t0 = "2026-05-24T10:00:00.000Z";
    let emb = make_one_hot(0);

    h.upsert_task_index(
        A_AGENT,
        "t-001",
        "Title One",
        Some("first brief"),
        Some("active"),
        Some(t0),
        Some(5),
        Some(&emb),
    )
    .unwrap();

    let row = read_task_row(&h, "t-001").expect("task row inserted");
    assert_eq!(row.task_id, "t-001");
    assert_eq!(row.agent_id, A_AGENT);
    assert_eq!(row.title, "Title One");
    assert_eq!(row.brief.as_deref(), Some("first brief"));
    assert_eq!(row.status.as_deref(), Some("active"));
    assert_eq!(row.last_turn_at.as_deref(), Some(t0));
    assert_eq!(row.turns_total, Some(5));
    assert!(row.updated_at.is_some());

    let rowid = task_rowid(&h, "t-001");
    assert_eq!(count_rows(&h, "task_vec"), 1);
    let blob = task_vec_blob_by_rowid(&h, rowid).expect("task_vec row");
    assert_eq!(blob, embedding_to_blob(&emb));

    // Primary table's embedding BLOB stays NULL (Slice E convention).
    let conn = h.get_conn().unwrap();
    let primary_emb: Option<Vec<u8>> = conn
        .query_row(
            "SELECT embedding FROM task_index WHERE task_id = ?1",
            rusqlite::params!["t-001"],
            |r| r.get(0),
        )
        .unwrap();
    assert!(primary_emb.is_none());
}

#[test]
fn t_task_sync_02_brief_change_update_with_embedding_refresh() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let t0 = "2026-05-24T10:00:00.000Z";
    let t1 = "2026-05-24T11:00:00.000Z";

    h.upsert_task_index(
        A_AGENT,
        "t-001",
        "T",
        Some("first"),
        Some("active"),
        Some(t0),
        Some(5),
        Some(&make_one_hot(0)),
    )
    .unwrap();
    let rowid_before = task_rowid(&h, "t-001");

    h.upsert_task_index(
        A_AGENT,
        "t-001",
        "T",
        Some("revised"),
        Some("active"),
        Some(t1),
        Some(6),
        Some(&make_one_hot(1)),
    )
    .unwrap();
    let rowid_after = task_rowid(&h, "t-001");

    assert_eq!(rowid_before, rowid_after, "rowid stable across update");
    let row = read_task_row(&h, "t-001").unwrap();
    assert_eq!(row.brief.as_deref(), Some("revised"));
    assert_eq!(row.last_turn_at.as_deref(), Some(t1));
    assert_eq!(row.turns_total, Some(6));
    let blob = task_vec_blob_by_rowid(&h, rowid_after).unwrap();
    assert_eq!(blob, embedding_to_blob(&make_one_hot(1)));
}

#[test]
fn t_task_sync_03_sync_only_counter_update_preserves_brief_status_via_coalesce() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let t0 = "2026-05-24T10:00:00.000Z";
    let t2 = "2026-05-24T12:00:00.000Z";

    h.upsert_task_index(
        A_AGENT,
        "t-001",
        "T",
        Some("first"),
        Some("active"),
        Some(t0),
        Some(5),
        Some(&make_one_hot(0)),
    )
    .unwrap();
    let rowid_before = task_rowid(&h, "t-001");

    h.upsert_task_index(A_AGENT, "t-001", "T", None, None, Some(t2), Some(7), None)
        .unwrap();

    let row = read_task_row(&h, "t-001").unwrap();
    assert_eq!(
        row.brief.as_deref(),
        Some("first"),
        "brief preserved via COALESCE"
    );
    assert_eq!(
        row.status.as_deref(),
        Some("active"),
        "status preserved via COALESCE"
    );
    assert_eq!(row.last_turn_at.as_deref(), Some(t2));
    assert_eq!(row.turns_total, Some(7));

    // task_vec row untouched — embedding=None skips DELETE+INSERT.
    let rowid_after = task_rowid(&h, "t-001");
    assert_eq!(rowid_before, rowid_after);
    let blob = task_vec_blob_by_rowid(&h, rowid_after).unwrap();
    assert_eq!(
        blob,
        embedding_to_blob(&make_one_hot(0)),
        "embedding preserved"
    );
}

#[test]
fn t_task_sync_04_embedding_only_refresh() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let t0 = "2026-05-24T10:00:00.000Z";

    h.upsert_task_index(
        A_AGENT,
        "t-001",
        "T",
        Some("first"),
        Some("active"),
        Some(t0),
        Some(5),
        Some(&make_one_hot(0)),
    )
    .unwrap();
    h.upsert_task_index(
        A_AGENT,
        "t-001",
        "T",
        None,
        None,
        None,
        None,
        Some(&make_one_hot(1)),
    )
    .unwrap();

    let row = read_task_row(&h, "t-001").unwrap();
    assert_eq!(row.brief.as_deref(), Some("first"));
    assert_eq!(row.status.as_deref(), Some("active"));
    assert_eq!(row.last_turn_at.as_deref(), Some(t0));
    assert_eq!(row.turns_total, Some(5));

    let rowid = task_rowid(&h, "t-001");
    let blob = task_vec_blob_by_rowid(&h, rowid).unwrap();
    assert_eq!(blob, embedding_to_blob(&make_one_hot(1)));
}

#[test]
fn t_task_sync_04b_all_none_coalesce_preserves_and_updated_at_refreshes() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let t0 = "2026-05-24T10:00:00.000Z";

    h.upsert_task_index(
        A_AGENT,
        "t-001",
        "T",
        Some("first"),
        Some("active"),
        Some(t0),
        Some(5),
        Some(&make_one_hot(0)),
    )
    .unwrap();
    let row_before = read_task_row(&h, "t-001").unwrap();
    let ts0 = row_before.updated_at.clone();

    thread::sleep(Duration::from_millis(50));

    // All optional fields None except required ones (agent_id / task_id / title).
    h.upsert_task_index(A_AGENT, "t-001", "T", None, None, None, None, None)
        .unwrap();

    let row_after = read_task_row(&h, "t-001").unwrap();
    // COALESCE preserves all optional fields:
    assert_eq!(row_after.brief, row_before.brief);
    assert_eq!(row_after.status, row_before.status);
    assert_eq!(row_after.last_turn_at, row_before.last_turn_at);
    assert_eq!(row_after.turns_total, row_before.turns_total);
    // updated_at is always-overwrite (>= tolerates same-millisecond on slow clocks).
    assert!(
        row_after.updated_at >= ts0,
        "updated_at refreshes (>= tolerates same-ms)"
    );
}

#[test]
fn t_task_sync_04c_updated_at_refreshes_on_update() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let t0 = "2026-05-24T10:00:00.000Z";

    h.upsert_task_index(
        A_AGENT,
        "t-001",
        "T",
        Some("first"),
        None,
        Some(t0),
        Some(5),
        None,
    )
    .unwrap();
    let ts0 = read_task_row(&h, "t-001").unwrap().updated_at.unwrap();

    thread::sleep(Duration::from_millis(50));

    h.upsert_task_index(
        A_AGENT,
        "t-001",
        "T",
        Some("revised"),
        None,
        Some(t0),
        Some(5),
        None,
    )
    .unwrap();
    let row_after = read_task_row(&h, "t-001").unwrap();

    // >= tolerates millisecond-collision on slow clocks; the second
    // assertion proves the UPDATE actually executed.
    assert!(row_after.updated_at.as_deref().unwrap() >= ts0.as_str());
    assert_eq!(row_after.brief.as_deref(), Some("revised"));
}

#[test]
fn t_task_sync_05_preflight_dim_mismatch() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let bad = vec![0.0_f32; 100];
    let err = h
        .upsert_task_index(A_AGENT, "t-001", "T", None, None, None, None, Some(&bad))
        .unwrap_err();
    match err {
        DbError::InvalidConfig(msg) => assert!(msg.contains("embedding dim"), "got: {msg}"),
        other => panic!("expected InvalidConfig, got {other:?}"),
    }
    assert_eq!(count_rows(&h, "task_index"), 0);
    assert_eq!(count_rows(&h, "task_vec"), 0);
}

#[test]
fn t_task_sync_06_preflight_nan_or_inf_rejected() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let mut nan_emb = make_one_hot(0);
    nan_emb[10] = f32::NAN;
    let mut inf_emb = make_one_hot(0);
    inf_emb[20] = f32::INFINITY;
    let mut neg_inf_emb = make_one_hot(0);
    neg_inf_emb[30] = f32::NEG_INFINITY;

    for emb in [&nan_emb, &inf_emb, &neg_inf_emb] {
        let err = h
            .upsert_task_index(A_AGENT, "t-001", "T", None, None, None, None, Some(emb))
            .unwrap_err();
        match err {
            DbError::InvalidConfig(msg) => assert!(msg.contains("finite"), "got: {msg}"),
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }
    assert_eq!(count_rows(&h, "task_index"), 0);
}

#[test]
fn t_task_sync_07_preflight_separator_byte_rejected() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let sep = "bad\u{1F}agent";
    let err = h
        .upsert_task_index(sep, "t-001", "T", None, None, None, None, None)
        .unwrap_err();
    assert!(matches!(err, DbError::InvalidConfig(_)));

    let bad_task = "bad\u{1F}task";
    let err = h
        .upsert_task_index(A_AGENT, bad_task, "T", None, None, None, None, None)
        .unwrap_err();
    assert!(matches!(err, DbError::InvalidConfig(_)));

    assert_eq!(count_rows(&h, "task_index"), 0);
}

#[test]
fn t_task_sync_08_preflight_empty_agent_id_rejected() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    for empty in &["", "   ", "\t", "\n"] {
        let err = h
            .upsert_task_index(empty, "t-001", "T", None, None, None, None, None)
            .unwrap_err();
        assert!(matches!(err, DbError::InvalidConfig(_)));
    }
    assert_eq!(count_rows(&h, "task_index"), 0);
}

#[test]
fn t_task_sync_09_preflight_invalid_rfc3339_last_turn_at() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let err = h
        .upsert_task_index(
            A_AGENT,
            "t-001",
            "T",
            None,
            None,
            Some("garbage"),
            None,
            None,
        )
        .unwrap_err();
    match err {
        DbError::InvalidConfig(msg) => assert!(msg.contains("RFC 3339"), "got: {msg}"),
        other => panic!("expected InvalidConfig, got {other:?}"),
    }
    assert_eq!(count_rows(&h, "task_index"), 0);
}

#[test]
fn t_task_sync_cross_agent_intentional_overwrite() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();

    h.upsert_task_index(
        A_AGENT,
        "t-shared",
        "A's view",
        Some("a-brief"),
        None,
        None,
        None,
        Some(&make_one_hot(0)),
    )
    .unwrap();
    h.upsert_task_index(
        B_AGENT,
        "t-shared",
        "B's view",
        Some("b-brief"),
        None,
        None,
        None,
        Some(&make_one_hot(1)),
    )
    .unwrap();

    assert_eq!(count_rows(&h, "task_index"), 1);
    let row = read_task_row(&h, "t-shared").unwrap();
    assert_eq!(
        row.agent_id, B_AGENT,
        "cross-agent agent_id overwrite by design (PRD §11.3.3)"
    );
    assert_eq!(row.title, "B's view", "title always-overwrites");
    assert_eq!(row.brief.as_deref(), Some("b-brief"));
    let rowid = task_rowid(&h, "t-shared");
    let blob = task_vec_blob_by_rowid(&h, rowid).unwrap();
    assert_eq!(blob, embedding_to_blob(&make_one_hot(1)));
}

#[test]
fn t_task_sync_cross_agent_emb_none_preserves_prior_embedding() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();

    h.upsert_task_index(
        A_AGENT,
        "t-shared",
        "A's view",
        None,
        None,
        None,
        None,
        Some(&make_one_hot(0)),
    )
    .unwrap();
    h.upsert_task_index(
        B_AGENT, "t-shared", "B's view", None, None, None, None, None,
    )
    .unwrap();

    let row = read_task_row(&h, "t-shared").unwrap();
    assert_eq!(row.agent_id, B_AGENT);
    assert_eq!(row.title, "B's view");
    // task_vec row UNCHANGED — embedding stays as agent-A's.
    let rowid = task_rowid(&h, "t-shared");
    let blob = task_vec_blob_by_rowid(&h, rowid).unwrap();
    assert_eq!(
        blob,
        embedding_to_blob(&make_one_hot(0)),
        "stale embedding under cross-agent rotation — documented Slice E None-preserves convention"
    );
}

// ──────────────────────────────────────────────────────────────────────
// turn_index path
// ──────────────────────────────────────────────────────────────────────

#[test]
fn t_turn_sync_01_insert_3component_id_all_fields() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let ts = "2026-05-24T10:00:00.000Z";

    h.upsert_turn_index(
        A_AGENT,
        "t-001",
        1,
        ts,
        "d0",
        Some("notable"),
        Some(true),
        Some(false),
        Some(true),
        Some(false),
        Some(&make_one_hot(0)),
        Some(100),
        Some(200),
    )
    .unwrap();

    let id = turn_id(A_AGENT, "t-001", 1);
    let row = read_turn_row_full(&h, &id).expect("row inserted");
    assert_eq!(row.id, id);
    assert_eq!(row.agent_id, A_AGENT);
    assert_eq!(row.task_id, "t-001");
    assert_eq!(row.turn, 1);
    assert_eq!(row.timestamp, ts);
    assert_eq!(row.digest, "d0");
    assert_eq!(row.importance.as_deref(), Some("notable"));
    assert_eq!(row.reference_count, 0);
    assert_eq!(row.has_user_instruction, Some(1));
    assert_eq!(row.has_user_correction, Some(0));
    assert_eq!(row.has_tool_use, Some(1));
    assert_eq!(row.has_decision, Some(0));
    assert_eq!(row.tokens_digest, Some(100));
    assert_eq!(row.tokens_l0_processed, Some(200));
    assert_eq!(row.access_count, 0);
    assert!(row.last_accessed.is_none());

    let rowid = turn_rowid(&h, &id);
    assert_eq!(count_rows(&h, "turn_vec"), 1);
    let blob = turn_vec_blob_by_rowid(&h, rowid).unwrap();
    assert_eq!(blob, embedding_to_blob(&make_one_hot(0)));
}

#[test]
fn t_turn_sync_02_update_digest_and_embedding_rowid_stable() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let ts = "2026-05-24T10:00:00.000Z";

    h.upsert_turn_index(
        A_AGENT,
        "t-001",
        1,
        ts,
        "d0",
        None,
        None,
        None,
        None,
        None,
        Some(&make_one_hot(0)),
        None,
        None,
    )
    .unwrap();
    let id = turn_id(A_AGENT, "t-001", 1);
    let rowid_before = turn_rowid(&h, &id);

    h.upsert_turn_index(
        A_AGENT,
        "t-001",
        1,
        ts,
        "d0-revised",
        None,
        None,
        None,
        None,
        None,
        Some(&make_one_hot(1)),
        None,
        None,
    )
    .unwrap();
    let rowid_after = turn_rowid(&h, &id);

    assert_eq!(rowid_before, rowid_after);
    let row = read_turn_row_full(&h, &id).unwrap();
    assert_eq!(row.digest, "d0-revised");
    assert_eq!(row.reference_count, 0, "caller did not bump — preserved");
    let blob = turn_vec_blob_by_rowid(&h, rowid_after).unwrap();
    assert_eq!(blob, embedding_to_blob(&make_one_hot(1)));
}

#[test]
fn t_turn_sync_03_reference_count_preserve_on_conflict() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let ts = "2026-05-24T10:00:00.000Z";

    h.upsert_turn_index(
        A_AGENT, "t-001", 1, ts, "d0", None, None, None, None, None, None, None, None,
    )
    .unwrap();
    assert!(h.bump_turn_reference(A_AGENT, "t-001", 1).unwrap());
    assert!(h.bump_turn_reference(A_AGENT, "t-001", 1).unwrap());
    assert!(h.bump_turn_reference(A_AGENT, "t-001", 1).unwrap());

    // Stale caller upserts again — caller cannot pass reference_count via the
    // API; the impl binds 0 on INSERT and OMITs the column on UPDATE.
    h.upsert_turn_index(
        A_AGENT, "t-001", 1, ts, "d0-stale", None, None, None, None, None, None, None, None,
    )
    .unwrap();

    let id = turn_id(A_AGENT, "t-001", 1);
    let row = read_turn_row_full(&h, &id).unwrap();
    assert_eq!(
        row.reference_count, 3,
        "M011 §3.6: reference_count PRESERVED on conflict"
    );
    assert_eq!(row.digest, "d0-stale", "other fields update normally");
}

#[test]
fn t_turn_sync_04_bump_atomic_increment() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let ts = "2026-05-24T10:00:00.000Z";
    h.upsert_turn_index(
        A_AGENT, "t-001", 1, ts, "d0", None, None, None, None, None, None, None, None,
    )
    .unwrap();

    for _ in 0..5 {
        assert!(h.bump_turn_reference(A_AGENT, "t-001", 1).unwrap());
    }
    let id = turn_id(A_AGENT, "t-001", 1);
    let row = read_turn_row_full(&h, &id).unwrap();
    assert_eq!(row.reference_count, 5);
}

#[test]
fn t_turn_sync_04b_bump_does_not_touch_turn_vec() {
    // AC-31 M004-side invariant: bump_turn_reference does NOT re-embed.
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let ts = "2026-05-24T10:00:00.000Z";
    h.upsert_turn_index(
        A_AGENT,
        "t-001",
        1,
        ts,
        "d0",
        None,
        None,
        None,
        None,
        None,
        Some(&make_one_hot(0)),
        None,
        None,
    )
    .unwrap();
    let id = turn_id(A_AGENT, "t-001", 1);
    let rowid = turn_rowid(&h, &id);
    let blob_before = turn_vec_blob_by_rowid(&h, rowid).unwrap();
    let vec_count_before = turn_vec_count_by_rowid(&h, rowid);
    assert_eq!(vec_count_before, 1);

    for _ in 0..3 {
        assert!(h.bump_turn_reference(A_AGENT, "t-001", 1).unwrap());
    }

    let blob_after = turn_vec_blob_by_rowid(&h, rowid).unwrap();
    let vec_count_after = turn_vec_count_by_rowid(&h, rowid);
    assert_eq!(blob_before, blob_after, "byte-for-byte invariance (AC-31)");
    assert_eq!(vec_count_after, 1, "turn_vec row count unchanged");
}

#[test]
fn t_turn_sync_05_bump_idempotent_on_absent_row() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let res = h.bump_turn_reference(A_AGENT, "missing", 1).unwrap();
    assert!(!res, "Ok(false) on missing row");
    assert_eq!(count_rows(&h, "turn_index"), 0);
}

#[test]
fn t_turn_sync_06_embedding_optional_insert() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let ts = "2026-05-24T10:00:00.000Z";
    h.upsert_turn_index(
        A_AGENT, "t-001", 1, ts, "d0", None, None, None, None, None, None, None, None,
    )
    .unwrap();
    assert_eq!(count_rows(&h, "turn_index"), 1);
    assert_eq!(count_rows(&h, "turn_vec"), 0);
}

#[test]
fn t_turn_sync_07_embedding_add_later() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let ts = "2026-05-24T10:00:00.000Z";
    h.upsert_turn_index(
        A_AGENT, "t-001", 1, ts, "d0", None, None, None, None, None, None, None, None,
    )
    .unwrap();
    assert_eq!(count_rows(&h, "turn_vec"), 0);

    h.upsert_turn_index(
        A_AGENT,
        "t-001",
        1,
        ts,
        "d0",
        None,
        None,
        None,
        None,
        None,
        Some(&make_one_hot(0)),
        None,
        None,
    )
    .unwrap();
    assert_eq!(count_rows(&h, "turn_index"), 1);
    assert_eq!(count_rows(&h, "turn_vec"), 1);
}

#[test]
fn t_turn_sync_08_preflight_invalid_rfc3339_timestamp() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let err = h
        .upsert_turn_index(
            A_AGENT, "t-001", 1, "garbage", "d0", None, None, None, None, None, None, None, None,
        )
        .unwrap_err();
    match err {
        DbError::InvalidConfig(msg) => assert!(msg.contains("RFC 3339"), "got: {msg}"),
        other => panic!("expected InvalidConfig, got {other:?}"),
    }
}

#[test]
fn t_turn_sync_09a_preflight_dim_mismatch() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let bad = vec![0.0_f32; 100];
    let err = h
        .upsert_turn_index(
            A_AGENT,
            "t-001",
            1,
            "2026-05-24T10:00:00.000Z",
            "d0",
            None,
            None,
            None,
            None,
            None,
            Some(&bad),
            None,
            None,
        )
        .unwrap_err();
    match err {
        DbError::InvalidConfig(msg) => assert!(msg.contains("embedding dim"), "got: {msg}"),
        other => panic!("expected InvalidConfig, got {other:?}"),
    }
    assert_eq!(count_rows(&h, "turn_index"), 0);
}

#[test]
fn t_turn_sync_09b_preflight_nan_rejected() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let mut emb = make_one_hot(0);
    emb[42] = f32::NAN;
    let err = h
        .upsert_turn_index(
            A_AGENT,
            "t-001",
            1,
            "2026-05-24T10:00:00.000Z",
            "d0",
            None,
            None,
            None,
            None,
            None,
            Some(&emb),
            None,
            None,
        )
        .unwrap_err();
    match err {
        DbError::InvalidConfig(msg) => assert!(msg.contains("finite"), "got: {msg}"),
        other => panic!("expected InvalidConfig, got {other:?}"),
    }
}

#[test]
fn t_turn_sync_09c_preflight_inf_rejected() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let mut pos_inf = make_one_hot(0);
    pos_inf[7] = f32::INFINITY;
    let mut neg_inf = make_one_hot(0);
    neg_inf[8] = f32::NEG_INFINITY;
    for emb in [&pos_inf, &neg_inf] {
        let err = h
            .upsert_turn_index(
                A_AGENT,
                "t-001",
                1,
                "2026-05-24T10:00:00.000Z",
                "d0",
                None,
                None,
                None,
                None,
                None,
                Some(emb),
                None,
                None,
            )
            .unwrap_err();
        match err {
            DbError::InvalidConfig(msg) => assert!(msg.contains("finite"), "got: {msg}"),
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }
}

#[test]
fn t_turn_sync_09d_preflight_empty_agent_id_rejected() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    for empty in &["", "   ", "\t"] {
        let err = h
            .upsert_turn_index(
                empty,
                "t-001",
                1,
                "2026-05-24T10:00:00.000Z",
                "d0",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, DbError::InvalidConfig(_)));
    }
    assert_eq!(count_rows(&h, "turn_index"), 0);
}

#[test]
fn t_turn_sync_09e_preflight_separator_byte_rejected() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let bad_agent = "bad\u{1F}agent";
    let bad_task = "bad\u{1F}task";
    let err1 = h
        .upsert_turn_index(
            bad_agent,
            "t-001",
            1,
            "2026-05-24T10:00:00.000Z",
            "d0",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
    let err2 = h
        .upsert_turn_index(
            A_AGENT,
            bad_task,
            1,
            "2026-05-24T10:00:00.000Z",
            "d0",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
    assert!(matches!(err1, DbError::InvalidConfig(_)));
    assert!(matches!(err2, DbError::InvalidConfig(_)));
    assert_eq!(count_rows(&h, "turn_index"), 0);
}

#[test]
fn t_turn_sync_10_concurrent_upsert_different_ids() {
    let dir = tempdir();
    let h = Arc::new(R2d2SqliteIndexHandle::new(&dir.path().join("triple.db"), 4).unwrap());
    let ts = "2026-05-24T10:00:00.000Z";

    let h1 = Arc::clone(&h);
    let h2 = Arc::clone(&h);
    let j1 = thread::spawn(move || {
        h1.upsert_turn_index(
            "A", "t-1", 1, ts, "d-a", None, None, None, None, None, None, None, None,
        )
    });
    let j2 = thread::spawn(move || {
        h2.upsert_turn_index(
            "B", "t-2", 1, ts, "d-b", None, None, None, None, None, None, None, None,
        )
    });
    j1.join().unwrap().unwrap();
    j2.join().unwrap().unwrap();
    assert_eq!(count_rows(&h, "turn_index"), 2);
}

#[test]
fn t_turn_sync_11_concurrent_bump_same_id_soak() {
    let dir = tempdir();
    let h = Arc::new(R2d2SqliteIndexHandle::new(&dir.path().join("triple.db"), 8).unwrap());
    let ts = "2026-05-24T10:00:00.000Z";
    h.upsert_turn_index(
        A_AGENT, "t-001", 1, ts, "d0", None, None, None, None, None, None, None, None,
    )
    .unwrap();

    let threads: Vec<_> = (0..8)
        .map(|_| {
            let hh = Arc::clone(&h);
            thread::spawn(move || {
                for _ in 0..100 {
                    hh.bump_turn_reference(A_AGENT, "t-001", 1).unwrap();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let id = turn_id(A_AGENT, "t-001", 1);
    let row = read_turn_row_full(&h, &id).unwrap();
    assert_eq!(
        row.reference_count, 800,
        "no lost increments under contention"
    );
}

#[test]
fn t_turn_sync_cross_agent_isolation() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let ts = "2026-05-24T10:00:00.000Z";

    h.upsert_turn_index(
        A_AGENT, "t-001", 1, ts, "d-A", None, None, None, None, None, None, None, None,
    )
    .unwrap();
    h.upsert_turn_index(
        B_AGENT, "t-001", 1, ts, "d-B", None, None, None, None, None, None, None, None,
    )
    .unwrap();
    assert!(h.bump_turn_reference(A_AGENT, "t-001", 1).unwrap());
    assert!(h.bump_turn_reference(A_AGENT, "t-001", 1).unwrap());
    assert!(h.bump_turn_reference(B_AGENT, "t-001", 1).unwrap());
    assert!(h.bump_turn_reference(B_AGENT, "t-001", 1).unwrap());
    assert!(h.bump_turn_reference(B_AGENT, "t-001", 1).unwrap());
    assert!(h.bump_turn_reference(B_AGENT, "t-001", 1).unwrap());
    assert!(h.bump_turn_reference(B_AGENT, "t-001", 1).unwrap());

    assert_eq!(
        count_rows(&h, "turn_index"),
        2,
        "3-component id structurally distinct"
    );
    let row_a = read_turn_row_full(&h, &turn_id(A_AGENT, "t-001", 1)).unwrap();
    let row_b = read_turn_row_full(&h, &turn_id(B_AGENT, "t-001", 1)).unwrap();
    assert_eq!(row_a.reference_count, 2);
    assert_eq!(row_b.reference_count, 5);
    assert_eq!(row_a.digest, "d-A");
    assert_eq!(row_b.digest, "d-B");
}

// ──────────────────────────────────────────────────────────────────────
// Slice H adversarial R1 closures — hardening to align the incremental
// write surface with the rebuild scanner's stricter validation.
// ──────────────────────────────────────────────────────────────────────

#[test]
fn t_turn_sync_adv_w2_turn_zero_rejected() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let err = h
        .upsert_turn_index(
            A_AGENT,
            "t-001",
            0,
            "2026-05-24T10:00:00.000Z",
            "d0",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
    match err {
        DbError::InvalidConfig(msg) => assert!(msg.contains("turn must be non-zero"), "got: {msg}"),
        other => panic!("expected InvalidConfig, got {other:?}"),
    }
    assert_eq!(count_rows(&h, "turn_index"), 0);
}

#[test]
fn t_turn_sync_adv_w3_empty_digest_rejected() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let err = h
        .upsert_turn_index(
            A_AGENT,
            "t-001",
            1,
            "2026-05-24T10:00:00.000Z",
            "",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_err();
    match err {
        DbError::InvalidConfig(msg) => {
            assert!(msg.contains("digest must be non-empty"), "got: {msg}")
        }
        other => panic!("expected InvalidConfig, got {other:?}"),
    }
    assert_eq!(count_rows(&h, "turn_index"), 0);
}

#[test]
fn t_task_sync_adv_w4_empty_task_id_rejected() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    for empty in &["", "   ", "\t"] {
        let err = h
            .upsert_task_index(A_AGENT, empty, "T", None, None, None, None, None)
            .unwrap_err();
        match err {
            DbError::InvalidConfig(msg) => assert!(msg.contains("task_id"), "got: {msg}"),
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }
    assert_eq!(count_rows(&h, "task_index"), 0);
}

#[test]
fn t_turn_sync_adv_w4_empty_task_id_rejected_on_upsert_and_bump() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    for empty in &["", "   "] {
        let err = h
            .upsert_turn_index(
                A_AGENT,
                empty,
                1,
                "2026-05-24T10:00:00.000Z",
                "d0",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, DbError::InvalidConfig(_)));
        let err2 = h.bump_turn_reference(A_AGENT, empty, 1).unwrap_err();
        assert!(matches!(err2, DbError::InvalidConfig(_)));
    }
    assert_eq!(count_rows(&h, "turn_index"), 0);
}

#[test]
fn t_task_sync_adv_w5_c0_control_chars_rejected() {
    // Newline, tab, NUL, DEL — all C0/DEL range.
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let bad_chars = ["\n", "\t", "\0", "\u{7F}", "\u{01}", "\u{1E}"];
    for bad in &bad_chars {
        let bad_agent = format!("agent{bad}suffix");
        let bad_task = format!("task{bad}suffix");

        let err1 = h
            .upsert_task_index(&bad_agent, "t-001", "T", None, None, None, None, None)
            .unwrap_err();
        assert!(
            matches!(err1, DbError::InvalidConfig(_)),
            "agent_id with {:?} should be rejected",
            bad
        );
        let err2 = h
            .upsert_task_index(A_AGENT, &bad_task, "T", None, None, None, None, None)
            .unwrap_err();
        assert!(
            matches!(err2, DbError::InvalidConfig(_)),
            "task_id with {:?} should be rejected",
            bad
        );
    }
    assert_eq!(count_rows(&h, "task_index"), 0);
}

#[test]
fn t_turn_sync_adv_w5_c0_control_chars_rejected_on_upsert_and_bump() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let bad_chars = ["\n", "\t", "\0", "\u{7F}", "\u{01}", "\u{1E}"];
    for bad in &bad_chars {
        let bad_agent = format!("agent{bad}suffix");
        let bad_task = format!("task{bad}suffix");

        let err_upsert_a = h
            .upsert_turn_index(
                &bad_agent,
                "t-001",
                1,
                "2026-05-24T10:00:00.000Z",
                "d0",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap_err();
        assert!(
            matches!(err_upsert_a, DbError::InvalidConfig(_)),
            "upsert agent_id with {:?} should be rejected",
            bad
        );

        let err_upsert_t = h
            .upsert_turn_index(
                A_AGENT,
                &bad_task,
                1,
                "2026-05-24T10:00:00.000Z",
                "d0",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap_err();
        assert!(
            matches!(err_upsert_t, DbError::InvalidConfig(_)),
            "upsert task_id with {:?} should be rejected",
            bad
        );

        let err_bump_a = h.bump_turn_reference(&bad_agent, "t-001", 1).unwrap_err();
        assert!(
            matches!(err_bump_a, DbError::InvalidConfig(_)),
            "bump agent_id with {:?} should be rejected",
            bad
        );

        let err_bump_t = h.bump_turn_reference(A_AGENT, &bad_task, 1).unwrap_err();
        assert!(
            matches!(err_bump_t, DbError::InvalidConfig(_)),
            "bump task_id with {:?} should be rejected",
            bad
        );
    }
    assert_eq!(count_rows(&h, "turn_index"), 0);
}

#[test]
fn t_turn_sync_id_consistency_on_insert() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let ts = "2026-05-24T10:00:00.000Z";

    h.upsert_turn_index(
        A_AGENT, "t-001", 1, ts, "d0", None, None, None, None, None, None, None, None,
    )
    .unwrap();
    let id = turn_id(A_AGENT, "t-001", 1);
    let row = read_turn_row_full(&h, &id).unwrap();
    // INSERT path guarantees id-PK / row-column consistency.
    assert_eq!(row.agent_id, A_AGENT);
    assert_eq!(row.task_id, "t-001");
    assert_eq!(row.turn, 1);

    // Direct SQL forgery of agent_id column. The trait API does not bypass
    // this — but bump_turn_reference still finds the row via the id PK
    // (which encodes agent "A") regardless of the column value.
    {
        let conn = h.get_conn().unwrap();
        conn.execute(
            "UPDATE turn_index SET agent_id = 'FORGED' WHERE id = ?1",
            rusqlite::params![id],
        )
        .unwrap();
    }
    assert!(
        h.bump_turn_reference(A_AGENT, "t-001", 1).unwrap(),
        "bump finds row by id-PK regardless of forged agent_id column"
    );
    let row_after = read_turn_row_full(&h, &id).unwrap();
    assert_eq!(row_after.reference_count, 1);
    assert_eq!(
        row_after.agent_id, "FORGED",
        "out-of-band column forgery is out of scope of the trait API"
    );
}

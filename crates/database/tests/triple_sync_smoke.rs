//! MODULE-004 Slice E (m004-slice-e) — incremental write surface integration
//! tests. Closes AC-13 (triple-consistency sync). Verifies the 4 new methods
//! on `SqliteIndexHandle`:
//!   - `upsert_content_index`
//!   - `upsert_meta_index`
//!   - `delete_content_index_row`
//!   - `delete_meta_index_row`
//!
//! Test inventory (matches MODULE-004 §3.3 T-tsync-* family):
//!   T-tsync-01  insert path
//!   T-tsync-02a update preview + embedding (rowid stable)
//!   T-tsync-02b multi-update rowid stability
//!   T-tsync-03  embedding-optional insert
//!   T-tsync-04  embedding-add-later
//!   T-tsync-04b last_modified=None preserves existing
//!   T-tsync-05  pre-flight dim mismatch
//!   T-tsync-06  meta insert
//!   T-tsync-07  meta update keeps existing meta_vec rowid when embedding=None
//!   T-tsync-08  delete content (atomic across content_index/fts/vec)
//!   T-tsync-09  delete meta (atomic across meta_index/vec)
//!   T-tsync-10  end-to-end recall integration
//!   T-tsync-11  concurrent upsert (file-backed pool_size=4)
//!   T-tsync-12  idempotent delete on absent row
//!   T-tsync-13  separator-byte rejection in id components (round-6 audit fix)
//!   T-tsync-14  empty/whitespace agent_id rejection — write/read parity (round-7 audit fix)
//!   T-tsync-15  embedding finite-ness rejection (NaN / ±Inf) — round-13 adversarial fix
//!   T-tsync-16  last_modified RFC 3339 syntactic check — round-13 adversarial fix

use advance_database::{DbError, R2d2RecallImpl, R2d2SqliteIndexHandle, Recall, SqliteIndexHandle};

mod common;

use common::*;

fn one_hot(idx: usize) -> Vec<f32> {
    let mut v = vec![0.0_f32; 768];
    v[idx] = 1.0;
    v
}

const A_AGENT: &str = "/";

// ──────────────────────────────────────────────────────────────────────
// content_index upsert path
// ──────────────────────────────────────────────────────────────────────

#[test]
fn t_tsync_01_insert_path_writes_index_fts_and_vec() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let t0_str = "2026-05-04T10:00:00.000Z";

    h.upsert_content_index(A_AGENT, "/notes.md", "abc", Some(&one_hot(0)), Some(t0_str))
        .unwrap();

    // content_index row matches inputs.
    let row = read_content_row(&h, "/notes.md").expect("row inserted");
    assert_eq!(row.id, format!("{}\u{1F}{}", A_AGENT, "/notes.md"));
    assert_eq!(row.agent_id, A_AGENT);
    assert_eq!(row.file_path, "/notes.md");
    assert_eq!(row.content_preview.as_deref(), Some("abc"));
    assert_eq!(row.last_modified.as_deref(), Some(t0_str));

    // content_fts row is populated with matching rowid + searchable preview.
    let fts_count = count_rows_where(&h, "content_fts", "content_preview MATCH 'abc'", &[]);
    assert_eq!(fts_count, 1);

    // content_vec has matching row.
    assert_eq!(count_rows(&h, "content_vec"), 1);
}

#[test]
fn t_tsync_02a_update_replaces_preview_and_embedding_keeping_rowid() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let t0_str = "2026-05-04T10:00:00.000Z";

    // Helper: read rowid + content_vec embedding in a single short-lived
    // borrow of the pool's only connection (`new_in_memory()` has
    // pool_size=1; holding the conn across other helper calls deadlocks).
    fn read_rowid_and_vec_blob(h: &R2d2SqliteIndexHandle, file_path: &str) -> (i64, Vec<u8>) {
        let conn = h.get_conn().unwrap();
        let rowid: i64 = conn
            .query_row(
                "SELECT rowid FROM content_index WHERE file_path = ?1",
                [file_path],
                |r| r.get(0),
            )
            .unwrap();
        let blob: Vec<u8> = conn
            .query_row(
                "SELECT embedding FROM content_vec WHERE rowid = ?1",
                [rowid],
                |r| r.get(0),
            )
            .unwrap();
        (rowid, blob)
    }

    h.upsert_content_index(A_AGENT, "/notes.md", "abc", Some(&one_hot(0)), Some(t0_str))
        .unwrap();
    let (rowid_initial, _) = read_rowid_and_vec_blob(&h, "/notes.md");

    h.upsert_content_index(A_AGENT, "/notes.md", "def", Some(&one_hot(1)), Some(t0_str))
        .unwrap();

    // Single content_index row, rowid stable.
    assert_eq!(count_rows(&h, "content_index"), 1);
    let (rowid_after, blob_after) = read_rowid_and_vec_blob(&h, "/notes.md");
    assert_eq!(
        rowid_initial, rowid_after,
        "rowid stable across UPSERT update"
    );

    // FTS5 reflects the new preview.
    let fts_def = count_rows_where(&h, "content_fts", "content_preview MATCH 'def'", &[]);
    assert_eq!(fts_def, 1);
    let fts_abc = count_rows_where(&h, "content_fts", "content_preview MATCH 'abc'", &[]);
    assert_eq!(fts_abc, 0);

    // content_vec has the second-update embedding.
    let mut expected_blob = Vec::with_capacity(768 * 4);
    for f in one_hot(1) {
        expected_blob.extend_from_slice(&f.to_le_bytes());
    }
    assert_eq!(blob_after, expected_blob);
}

#[test]
fn t_tsync_02b_multi_update_rowid_stability() {
    fn read_rowid(h: &R2d2SqliteIndexHandle, file_path: &str) -> i64 {
        let conn = h.get_conn().unwrap();
        conn.query_row(
            "SELECT rowid FROM content_index WHERE file_path = ?1",
            [file_path],
            |r| r.get(0),
        )
        .unwrap()
    }

    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    h.upsert_content_index(A_AGENT, "/x.md", "abc", Some(&one_hot(0)), None)
        .unwrap();
    let initial_rowid = read_rowid(&h, "/x.md");

    h.upsert_content_index(A_AGENT, "/x.md", "def", Some(&one_hot(1)), None)
        .unwrap();
    h.upsert_content_index(A_AGENT, "/x.md", "ghi", Some(&one_hot(2)), None)
        .unwrap();

    let final_rowid = read_rowid(&h, "/x.md");

    assert_eq!(
        initial_rowid, final_rowid,
        "UPSERT preserves rowid across multiple updates"
    );
    assert_eq!(count_rows(&h, "content_index"), 1);
    assert_eq!(count_rows(&h, "content_fts"), 1);
    assert_eq!(count_rows(&h, "content_vec"), 1);
}

#[test]
fn t_tsync_03_embedding_none_skips_content_vec() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();

    h.upsert_content_index(A_AGENT, "/notes.md", "preview", None, None)
        .unwrap();

    assert_eq!(count_rows(&h, "content_index"), 1);
    assert_eq!(count_rows(&h, "content_fts"), 1);
    assert_eq!(count_rows(&h, "content_vec"), 0);
}

#[test]
fn t_tsync_04_embedding_added_later() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    h.upsert_content_index(A_AGENT, "/notes.md", "preview", None, None)
        .unwrap();
    assert_eq!(count_rows(&h, "content_vec"), 0);

    h.upsert_content_index(A_AGENT, "/notes.md", "preview", Some(&one_hot(0)), None)
        .unwrap();

    assert_eq!(count_rows(&h, "content_index"), 1);
    assert_eq!(count_rows(&h, "content_fts"), 1);
    assert_eq!(count_rows(&h, "content_vec"), 1);
}

#[test]
fn t_tsync_04b_last_modified_none_preserves_existing_on_update() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    let t0_str = "2026-05-04T10:00:00.000Z";

    h.upsert_content_index(A_AGENT, "/x.md", "abc", None, Some(t0_str))
        .unwrap();
    let row1 = read_content_row(&h, "/x.md").unwrap();
    assert_eq!(row1.last_modified.as_deref(), Some(t0_str));

    // UPDATE with last_modified=None must preserve the existing t0_str.
    h.upsert_content_index(A_AGENT, "/x.md", "def", None, None)
        .unwrap();
    let row2 = read_content_row(&h, "/x.md").unwrap();
    assert_eq!(row2.content_preview.as_deref(), Some("def"));
    assert_eq!(
        row2.last_modified.as_deref(),
        Some(t0_str),
        "COALESCE-on-UPDATE preserves existing last_modified when caller passes None"
    );
}

#[test]
fn t_tsync_05_pre_flight_dim_mismatch_rejects_before_sql() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();

    let bad = vec![0.0_f32; 100];
    let r = h.upsert_content_index(A_AGENT, "/notes.md", "abc", Some(&bad), None);

    match r {
        Err(DbError::InvalidConfig(msg)) => {
            assert!(msg.contains("embedding dim"), "msg: {msg}")
        }
        other => panic!("expected InvalidConfig, got {other:?}"),
    }

    // Pre-flight rejection — no SQL ran, no rows anywhere.
    assert_eq!(count_rows(&h, "content_index"), 0);
    assert_eq!(count_rows(&h, "content_fts"), 0);
    assert_eq!(count_rows(&h, "content_vec"), 0);
}

// ──────────────────────────────────────────────────────────────────────
// meta_index upsert path
// ──────────────────────────────────────────────────────────────────────

#[test]
fn t_tsync_06_meta_insert_writes_meta_index_and_meta_vec() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();

    h.upsert_meta_index(
        A_AGENT,
        "/research",
        "paper.md",
        Some("a research paper"),
        Some(r#"["a","b"]"#),
        Some(&one_hot(0)),
    )
    .unwrap();

    let row = read_meta_row(&h, "/research", "paper.md").expect("row inserted");
    assert_eq!(
        row.id,
        format!("{}\u{1F}{}\u{1F}{}", A_AGENT, "/research", "paper.md")
    );
    assert_eq!(row.agent_id, A_AGENT);
    assert_eq!(row.directory, "/research");
    assert_eq!(row.entry_name, "paper.md");
    assert_eq!(row.description.as_deref(), Some("a research paper"));
    // tags is JSON-encoded per the doc-comment contract.
    assert_eq!(row.tags.as_deref(), Some(r#"["a","b"]"#));

    assert_eq!(count_rows(&h, "meta_vec"), 1);
}

#[test]
fn t_tsync_07_meta_update_without_embedding_preserves_meta_vec_row() {
    fn read_meta_rowid(h: &R2d2SqliteIndexHandle, dir: &str, entry: &str) -> i64 {
        let conn = h.get_conn().unwrap();
        conn.query_row(
            "SELECT rowid FROM meta_index WHERE directory = ?1 AND entry_name = ?2",
            [dir, entry],
            |r| r.get(0),
        )
        .unwrap()
    }

    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    h.upsert_meta_index(
        A_AGENT,
        "/research",
        "paper.md",
        Some("first"),
        None,
        Some(&one_hot(0)),
    )
    .unwrap();
    let rowid_initial = read_meta_rowid(&h, "/research", "paper.md");

    h.upsert_meta_index(
        A_AGENT,
        "/research",
        "paper.md",
        Some("second"),
        None,
        None, // no embedding → meta_vec row from initial insert preserved.
    )
    .unwrap();

    let row = read_meta_row(&h, "/research", "paper.md").unwrap();
    assert_eq!(row.description.as_deref(), Some("second"));
    assert_eq!(count_rows(&h, "meta_index"), 1);
    assert_eq!(count_rows(&h, "meta_vec"), 1);

    let rowid_after = read_meta_rowid(&h, "/research", "paper.md");
    assert_eq!(
        rowid_initial, rowid_after,
        "UPSERT preserves meta_index rowid; meta_vec row stays aligned"
    );
}

#[test]
fn t_tsync_15_embedding_nan_inf_rejected() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();

    // NaN component
    let mut emb_nan = one_hot(0);
    emb_nan[10] = f32::NAN;
    let r = h.upsert_content_index(A_AGENT, "/x.md", "abc", Some(&emb_nan), None);
    assert!(matches!(r, Err(DbError::InvalidConfig(ref m)) if m.contains("finite")));

    // +Inf component
    let mut emb_pos_inf = one_hot(0);
    emb_pos_inf[20] = f32::INFINITY;
    let r = h.upsert_content_index(A_AGENT, "/x.md", "abc", Some(&emb_pos_inf), None);
    assert!(matches!(r, Err(DbError::InvalidConfig(_))));

    // -Inf component on meta upsert
    let mut emb_neg_inf = one_hot(0);
    emb_neg_inf[30] = f32::NEG_INFINITY;
    let r = h.upsert_meta_index(A_AGENT, "/d", "x.md", None, None, Some(&emb_neg_inf));
    assert!(matches!(r, Err(DbError::InvalidConfig(_))));

    // No rows leaked.
    assert_eq!(count_rows(&h, "content_index"), 0);
    assert_eq!(count_rows(&h, "meta_index"), 0);
    assert_eq!(count_rows(&h, "content_vec"), 0);
    assert_eq!(count_rows(&h, "meta_vec"), 0);
}

#[test]
fn t_tsync_16_last_modified_must_parse_as_rfc3339() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();

    // Garbage string rejected.
    let r = h.upsert_content_index(A_AGENT, "/x.md", "abc", None, Some("garbage"));
    assert!(matches!(r, Err(DbError::InvalidConfig(ref m)) if m.contains("RFC 3339")));

    // Empty string rejected.
    let r = h.upsert_content_index(A_AGENT, "/x.md", "abc", None, Some(""));
    assert!(matches!(r, Err(DbError::InvalidConfig(_))));

    // Valid RFC 3339 accepted (sanity check that we didn't break the happy path).
    let r = h.upsert_content_index(
        A_AGENT,
        "/x.md",
        "abc",
        None,
        Some("2026-05-04T10:00:00.000Z"),
    );
    assert!(r.is_ok());
    assert_eq!(count_rows(&h, "content_index"), 1);

    // None still works (writes NULL on INSERT, preserves on UPDATE).
    let r = h.upsert_content_index(A_AGENT, "/y.md", "def", None, None);
    assert!(r.is_ok());
}

#[test]
fn t_tsync_14_empty_agent_id_rejected() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();

    // Empty agent_id rejected on all 4 methods.
    let r = h.upsert_content_index("", "/x.md", "abc", None, None);
    assert!(matches!(r, Err(DbError::InvalidConfig(ref m)) if m.contains("agent_id")));

    let r = h.upsert_meta_index("", "/dir", "name.md", None, None, None);
    assert!(matches!(r, Err(DbError::InvalidConfig(ref m)) if m.contains("agent_id")));

    let r = h.delete_content_index_row("", "/x.md");
    assert!(matches!(r, Err(DbError::InvalidConfig(ref m)) if m.contains("agent_id")));

    let r = h.delete_meta_index_row("", "/dir", "name.md");
    assert!(matches!(r, Err(DbError::InvalidConfig(ref m)) if m.contains("agent_id")));

    // Whitespace-only agent_id rejected.
    let r = h.upsert_content_index("   ", "/x.md", "abc", None, None);
    assert!(matches!(r, Err(DbError::InvalidConfig(_))));

    // No rows leaked.
    assert_eq!(count_rows(&h, "content_index"), 0);
    assert_eq!(count_rows(&h, "meta_index"), 0);
}

#[test]
fn t_tsync_13_separator_byte_rejected_in_id_components() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();

    // \u{1F} in agent_id (content upsert)
    let r = h.upsert_content_index("agent\u{1F}injected", "/x.md", "abc", None, None);
    assert!(matches!(r, Err(DbError::InvalidConfig(ref m)) if m.contains("agent_id")));

    // \u{1F} in file_path (content upsert)
    let r = h.upsert_content_index(A_AGENT, "/path\u{1F}injected.md", "abc", None, None);
    assert!(matches!(r, Err(DbError::InvalidConfig(ref m)) if m.contains("file_path")));

    // \u{1F} in directory (meta upsert)
    let r = h.upsert_meta_index(A_AGENT, "/dir\u{1F}injected", "x.md", None, None, None);
    assert!(matches!(r, Err(DbError::InvalidConfig(ref m)) if m.contains("directory")));

    // \u{1F} in entry_name (meta upsert)
    let r = h.upsert_meta_index(A_AGENT, "/dir", "name\u{1F}injected.md", None, None, None);
    assert!(matches!(r, Err(DbError::InvalidConfig(ref m)) if m.contains("entry_name")));

    // delete paths reject too
    let r = h.delete_content_index_row("a\u{1F}b", "/x.md");
    assert!(matches!(r, Err(DbError::InvalidConfig(_))));
    let r = h.delete_meta_index_row(A_AGENT, "/d\u{1F}", "x.md");
    assert!(matches!(r, Err(DbError::InvalidConfig(_))));

    // No rows leaked through.
    assert_eq!(count_rows(&h, "content_index"), 0);
    assert_eq!(count_rows(&h, "meta_index"), 0);
}

// ──────────────────────────────────────────────────────────────────────
// deletes (idempotent)
// ──────────────────────────────────────────────────────────────────────

#[test]
fn t_tsync_08_delete_content_clears_all_three_tables() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    h.upsert_content_index(A_AGENT, "/notes.md", "abc", Some(&one_hot(0)), None)
        .unwrap();
    assert_eq!(count_rows(&h, "content_index"), 1);

    h.delete_content_index_row(A_AGENT, "/notes.md").unwrap();

    assert_eq!(count_rows(&h, "content_index"), 0);
    assert_eq!(count_rows(&h, "content_fts"), 0);
    assert_eq!(count_rows(&h, "content_vec"), 0);
}

#[test]
fn t_tsync_09_delete_meta_clears_meta_index_and_meta_vec() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    h.upsert_meta_index(
        A_AGENT,
        "/research",
        "paper.md",
        Some("desc"),
        None,
        Some(&one_hot(0)),
    )
    .unwrap();
    assert_eq!(count_rows(&h, "meta_index"), 1);

    h.delete_meta_index_row(A_AGENT, "/research", "paper.md")
        .unwrap();

    assert_eq!(count_rows(&h, "meta_index"), 0);
    assert_eq!(count_rows(&h, "meta_vec"), 0);
}

// ──────────────────────────────────────────────────────────────────────
// end-to-end recall integration
// ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn t_tsync_10_e2e_recall_finds_upserted_content() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();

    // Asserts dense_max(=1.0) > fts5_score(<1.0); merge() takes max so dense
    // wins for /a.md. Future merge-policy changes (e.g. averaging) would
    // invalidate this assertion.
    h.upsert_content_index(A_AGENT, "/a.md", "alpha", Some(&one_hot(0)), None)
        .unwrap();
    h.upsert_content_index(A_AGENT, "/b.md", "beta", Some(&one_hot(1)), None)
        .unwrap();

    let recall = R2d2RecallImpl::new(h.clone());
    let results = recall
        .recall(A_AGENT, "alpha", &one_hot(0), 10)
        .await
        .unwrap();

    // Both rows pass the dense threshold (orthogonal one_hots → similarity
    // 0.5 ≥ DENSE_THRESHOLD=0.3).
    assert_eq!(results.len(), 2, "results: {:?}", results);

    // Find /a.md and /b.md by file_path.
    let a = results
        .iter()
        .find(|r| r.file_path.as_deref() == Some("/a.md"))
        .expect("/a.md missing");
    let b = results
        .iter()
        .find(|r| r.file_path.as_deref() == Some("/b.md"))
        .expect("/b.md missing");

    // /a.md: cos=1, sparse FTS5 also matches "alpha"; max(dense=1.0, sparse<1.0) = 1.0.
    assert!(
        (a.similarity - 1.0).abs() < 1e-5,
        "a.similarity = {}",
        a.similarity
    );

    // /b.md: cos=0, dense path only — "alpha" not in /b.md preview → similarity 0.5.
    assert!(
        (b.similarity - 0.5).abs() < 1e-5,
        "b.similarity = {}",
        b.similarity
    );
}

// ──────────────────────────────────────────────────────────────────────
// concurrent upsert (file-backed pool_size=4)
// ──────────────────────────────────────────────────────────────────────

#[test]
fn t_tsync_11_concurrent_upsert_serializes_via_begin_immediate() {
    use std::sync::Arc;
    use std::thread;

    let dir = tempdir();
    let path = dir.path().join("triple.db");
    let h = Arc::new(R2d2SqliteIndexHandle::new(&path, 4).expect("file-backed handle"));

    let h1 = Arc::clone(&h);
    let h2 = Arc::clone(&h);

    let t1 = thread::spawn(move || {
        h1.upsert_content_index(A_AGENT, "/thread-a.md", "alpha", Some(&one_hot(0)), None)
            .unwrap();
    });
    let t2 = thread::spawn(move || {
        h2.upsert_content_index(A_AGENT, "/thread-b.md", "beta", Some(&one_hot(1)), None)
            .unwrap();
    });

    t1.join().unwrap();
    t2.join().unwrap();

    assert_eq!(count_rows(&h, "content_index"), 2);
    assert_eq!(count_rows(&h, "content_fts"), 2);
    assert_eq!(count_rows(&h, "content_vec"), 2);
}

// ──────────────────────────────────────────────────────────────────────
// idempotent delete on absent row
// ──────────────────────────────────────────────────────────────────────

#[test]
fn t_tsync_12_delete_on_absent_row_is_noop() {
    let h = R2d2SqliteIndexHandle::new_in_memory().unwrap();

    let r = h.delete_content_index_row(A_AGENT, "/never-existed.md");
    assert!(r.is_ok(), "delete on absent row must return Ok; got {r:?}");

    assert_eq!(count_rows(&h, "content_index"), 0);
    assert_eq!(count_rows(&h, "content_fts"), 0);
    assert_eq!(count_rows(&h, "content_vec"), 0);

    // Same for meta side.
    let r = h.delete_meta_index_row(A_AGENT, "/never", "thing.md");
    assert!(
        r.is_ok(),
        "delete meta on absent row must return Ok; got {r:?}"
    );
    assert_eq!(count_rows(&h, "meta_index"), 0);
    assert_eq!(count_rows(&h, "meta_vec"), 0);
}

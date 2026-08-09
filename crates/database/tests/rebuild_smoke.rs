//! MODULE-004 Slice D — IndexRebuild integration tests (28 tests).
//!
//! Coverage: AC-08 (per-source-table population + cross-agent isolation +
//! idempotence + hidden-path exclusion + malformed-input handling +
//! embedder-failure surface + multi-agent collision detection +
//! cross-territory poisoning prevention) and AC-09 (access-stat reset
//! across content_index, memory_index, turn_index).

mod common;

use std::path::PathBuf;

use advance_database::{
    DbError, IndexRebuild, R2d2IndexRebuildImpl, R2d2RecallImpl, R2d2SqliteIndexHandle, Recall,
    Source, SqliteIndexHandle,
};
use chrono::{DateTime, Utc};
use common::{
    count_rows, count_rows_where, db_at, emb_with_sim, make_agent_root, read_content_row,
    read_turn_row, seed_content, seed_memory, seed_turn_with_access, tempdir, ts_text,
    write_knowledge_jsonl, write_meta_yaml, write_summary_yaml, write_text_file,
    write_turn_index_yaml, ConstEmbedder, CountingEmbedder, FailingEmbedder, IdentityEmbedder,
};

fn build_impl(
    handle: R2d2SqliteIndexHandle,
    embedder: impl advance_database::Embedder + Clone + 'static,
    workspace_root: PathBuf,
) -> R2d2IndexRebuildImpl<R2d2SqliteIndexHandle, impl advance_database::Embedder + Clone + 'static>
{
    R2d2IndexRebuildImpl::new(handle, embedder, workspace_root)
}

// ──────────────────────────────────────────────────────────────────────
// AC-08: per-source-table population (T-rebuild-01..06 + sub-tests)
// ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_01_empty_workspace() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "");
    write_meta_yaml(
        &root,
        "",
        "_scope:\n  slug: ws\n  description: \"root workspace\"\n",
    );
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let counter = CountingEmbedder::new(ConstEmbedder::new());
    let rebuilder = build_impl(handle.clone(), counter.clone(), root);
    let report = rebuilder.rebuild_full().await.unwrap();
    assert_eq!(report.meta_rows, 1, "meta_rows should be 1 for root _scope");
    assert_eq!(report.content_rows, 0);
    assert_eq!(report.memory_rows, 0);
    assert_eq!(report.task_rows, 0);
    assert_eq!(report.turn_rows, 0);
    assert_eq!(report.embed_calls, 1, "root description embedded");
    assert_eq!(count_rows(&handle, "meta_vec"), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_02_nested_meta_yaml() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "");
    write_meta_yaml(
        &root,
        "",
        "_scope:\n  slug: ws\n  description: root\nresearch:\n  description: research entry\n",
    );
    write_meta_yaml(
        &root,
        "research",
        "_scope:\n  slug: research\n  description: research scope\nnotes.md:\n  description: notes file\n",
    );
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let counter = CountingEmbedder::new(ConstEmbedder::new());
    let rebuilder = build_impl(handle.clone(), counter.clone(), root);
    let report = rebuilder.rebuild_full().await.unwrap();
    assert_eq!(
        report.meta_rows, 4,
        "root _scope + root research entry + research _scope + research notes entry"
    );
    assert_eq!(count_rows(&handle, "meta_vec"), 4);
    assert_eq!(report.embed_calls, 4);
    // Verify directory normalization
    let conn = handle.get_conn().unwrap();
    let mut stmt = conn
        .prepare("SELECT directory FROM meta_index WHERE entry_name = '_scope' AND agent_id = ?1")
        .unwrap();
    let root_dir: String = stmt.query_row(["/"], |r| r.get(0)).unwrap();
    assert_eq!(root_dir, "", "root _scope directory should be empty string");
}

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_02b_parent_child_meta_double_write() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "");
    make_agent_root(&root, "research");
    write_meta_yaml(
        &root,
        "",
        "_scope:\n  slug: ws\n  description: root\nresearch:\n  description: parent's view of research\n",
    );
    write_meta_yaml(
        &root,
        "research",
        "_scope:\n  slug: research\n  description: research's own scope\n",
    );
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let rebuilder = build_impl(handle.clone(), ConstEmbedder::new(), root);
    let report = rebuilder.rebuild_full().await.unwrap();
    assert!(report.meta_rows >= 3);
    // Two rows describe `/research` directory: one under root agent_id, one under research agent_id.
    let n = count_rows_where(&handle, "meta_index", "directory = ?1", &[&"/research"]);
    assert!(n >= 2, "expected >=2 rows describing /research, got {n}");
}

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_03_content_file() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "");
    write_text_file(&root, "notes.md", "abc");
    write_meta_yaml(
        &root,
        "",
        "_scope:\n  slug: ws\n  description: \"\"\nnotes.md:\n  description: \"\"\n",
    );
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let counter = CountingEmbedder::new(ConstEmbedder::new());
    let rebuilder = build_impl(handle.clone(), counter.clone(), root);
    let report = rebuilder.rebuild_full().await.unwrap();
    assert_eq!(report.content_rows, 1);
    assert_eq!(
        report.embed_calls, 1,
        "only content preview embedded; meta descriptions empty"
    );
    let row = read_content_row(&handle, "/notes.md").expect("content row missing");
    assert_eq!(row.content_preview.as_deref(), Some("abc"));
    assert_eq!(row.access_count, 0);
    assert!(row.last_accessed.is_none());
    assert!(
        row.last_modified.is_some(),
        "last_modified should be populated from FS mtime"
    );
    assert_eq!(count_rows(&handle, "content_fts"), 1);
    assert_eq!(count_rows(&handle, "content_vec"), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_04_knowledge_jsonl_all_statuses() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "");
    let entries = [
        serde_json::json!({"id":"m1","agent_id":"/","type":"fact","content":"a","created_at":"2026-01-01T00:00:00.000Z","is_active":true,"status":"active"}),
        serde_json::json!({"id":"m2","agent_id":"/","type":"fact","content":"b","created_at":"2026-01-01T00:00:00.000Z","is_active":true,"status":"contested"}),
        serde_json::json!({"id":"m3","agent_id":"/","type":"fact","content":"c","created_at":"2026-01-01T00:00:00.000Z","is_active":true,"status":"orphaned"}),
        serde_json::json!({"id":"m4","agent_id":"/","type":"fact","content":"d","created_at":"2026-01-01T00:00:00.000Z","is_active":false,"status":"superseded","superseded_by":"m1"}),
        serde_json::json!({"id":"m5","agent_id":"/","type":"fact","content":"e","created_at":"2026-01-01T00:00:00.000Z","is_active":false,"status":"forgotten"}),
    ];
    write_knowledge_jsonl(&root, "", &entries);
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let counter = CountingEmbedder::new(ConstEmbedder::new());
    let rebuilder = build_impl(handle.clone(), counter.clone(), root);
    let report = rebuilder.rebuild_full().await.unwrap();
    assert_eq!(report.memory_rows, 5);
    assert_eq!(count_rows(&handle, "memory_vec"), 5);
    assert_eq!(report.embed_calls, 5);
    let conn = handle.get_conn().unwrap();
    let statuses: Vec<String> = conn
        .prepare("SELECT status FROM memory_index ORDER BY id")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert_eq!(
        statuses,
        vec!["active", "contested", "orphaned", "superseded", "forgotten"]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_04b_status_invariant_violation_active_to_superseded() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "");
    let entries = [
        serde_json::json!({"id":"bad","agent_id":"/","type":"fact","content":"x","created_at":"2026-01-01T00:00:00.000Z","is_active":true,"status":"superseded"}),
    ];
    write_knowledge_jsonl(&root, "", &entries);
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let rebuilder = build_impl(handle.clone(), ConstEmbedder::new(), root);
    let report = rebuilder.rebuild_full().await.unwrap();
    assert_eq!(report.memory_rows, 0);
    assert!(!report.errors.is_empty());
    assert!(report
        .errors
        .iter()
        .any(|e| e.contains("status invariant") && e.contains("bad")));
}

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_04c_summary_yaml_cross_territory_mismatch() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "research");
    write_summary_yaml(
        &root,
        "research",
        "task-001",
        "_meta:\n  task_id: task-001\n  agent_id: writer\n  title: A task\nbrief: hello\n",
    );
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let rebuilder = build_impl(handle.clone(), ConstEmbedder::new(), root);
    let report = rebuilder.rebuild_full().await.unwrap();
    assert_eq!(report.task_rows, 0);
    assert!(report
        .errors
        .iter()
        .any(|e| e.contains("agent_id mismatch")));
}

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_04d_cluster_id_silently_dropped() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "");
    let entries = [
        serde_json::json!({"id":"m1","agent_id":"/","type":"fact","content":"x","created_at":"2026-01-01T00:00:00.000Z","is_active":true,"status":"active","cluster_id":"cl-pricing-2026q1"}),
    ];
    write_knowledge_jsonl(&root, "", &entries);
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let rebuilder = build_impl(handle.clone(), ConstEmbedder::new(), root);
    let report = rebuilder.rebuild_full().await.unwrap();
    assert_eq!(report.memory_rows, 1);
    let conn = handle.get_conn().unwrap();
    let mut stmt = conn.prepare("PRAGMA table_info(memory_index)").unwrap();
    let cols: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert!(
        !cols.iter().any(|c| c == "cluster_id"),
        "memory_index has no cluster_id column"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_04e_status_invariant_violation_inactive_to_active() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "");
    let entries = [
        serde_json::json!({"id":"bad","agent_id":"/","type":"fact","content":"x","created_at":"2026-01-01T00:00:00.000Z","is_active":false,"status":"active"}),
    ];
    write_knowledge_jsonl(&root, "", &entries);
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let rebuilder = build_impl(handle.clone(), ConstEmbedder::new(), root);
    let report = rebuilder.rebuild_full().await.unwrap();
    assert_eq!(report.memory_rows, 0);
    assert!(report
        .errors
        .iter()
        .any(|e| e.contains("status invariant") && e.contains("bad")));
}

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_04f_memory_id_collision() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "agent-a");
    make_agent_root(&root, "agent-b");
    let e1 = [
        serde_json::json!({"id":"mem-collision-001","agent_id":"agent-a","type":"fact","content":"agent-a content","created_at":"2026-01-01T00:00:00.000Z","is_active":true,"status":"active"}),
    ];
    let e2 = [
        serde_json::json!({"id":"mem-collision-001","agent_id":"agent-b","type":"fact","content":"agent-b content","created_at":"2026-01-01T00:00:00.000Z","is_active":true,"status":"active"}),
    ];
    write_knowledge_jsonl(&root, "agent-a", &e1);
    write_knowledge_jsonl(&root, "agent-b", &e2);
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let rebuilder = build_impl(handle.clone(), ConstEmbedder::new(), root);
    let report = rebuilder.rebuild_full().await.unwrap();
    assert_eq!(
        report.memory_rows, 1,
        "agent-a wins due to sort_by_file_name"
    );
    let conn = handle.get_conn().unwrap();
    let agent_id: String = conn
        .query_row(
            "SELECT agent_id FROM memory_index WHERE id = 'mem-collision-001'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(agent_id, "agent-a");
    assert!(report.errors.iter().any(|e| {
        e.contains("memory_index id collision")
            && e.contains("mem-collision-001")
            && e.contains("agent-b")
    }));
}

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_04g_knowledge_cross_territory_mismatch() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "research");
    let entries = [
        serde_json::json!({"id":"poison","agent_id":"writer","type":"fact","content":"x","created_at":"2026-01-01T00:00:00.000Z","is_active":true,"status":"active"}),
    ];
    write_knowledge_jsonl(&root, "research", &entries);
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let rebuilder = build_impl(handle.clone(), ConstEmbedder::new(), root);
    let report = rebuilder.rebuild_full().await.unwrap();
    assert_eq!(report.memory_rows, 0);
    assert!(report
        .errors
        .iter()
        .any(|e| e.contains("agent_id mismatch") && e.contains("writer")));
}

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_05_summary_yaml_basic() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "");
    write_summary_yaml(
        &root,
        "",
        "task-001",
        "_meta:\n  task_id: task-001\n  agent_id: \"/\"\n  title: Q3 analysis\n  turns_total: 62\n  last_turn_at: \"2026-03-23T10:00:00.000Z\"\nbrief: Brief content here\n",
    );
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let counter = CountingEmbedder::new(ConstEmbedder::new());
    let rebuilder = build_impl(handle.clone(), counter.clone(), root);
    let report = rebuilder.rebuild_full().await.unwrap();
    assert_eq!(report.task_rows, 1);
    assert_eq!(count_rows(&handle, "task_vec"), 1);
    assert_eq!(report.embed_calls, 1);
    let conn = handle.get_conn().unwrap();
    let (task_id, title, brief, status, lta, tt): (String, String, Option<String>, String, Option<String>, Option<i64>) = conn
        .query_row(
            "SELECT task_id, title, brief, status, last_turn_at, turns_total FROM task_index WHERE task_id = 'task-001'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .unwrap();
    assert_eq!(task_id, "task-001");
    assert_eq!(title, "Q3 analysis");
    assert_eq!(brief.as_deref(), Some("Brief content here"));
    assert_eq!(status, "active");
    assert_eq!(lta.as_deref(), Some("2026-03-23T10:00:00.000Z"));
    assert_eq!(tt, Some(62));
}

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_06_turn_index_yaml() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "");
    write_turn_index_yaml(
        &root,
        "",
        "task-001",
        "turns:\n- turn: 1\n  timestamp: \"2026-03-23T10:00:00.000Z\"\n  digest: \"first turn digest\"\n  collapsed_view: \"first turn body\"\n  importance: notable\n  reference_count: 0\n  has_user_instruction: true\n  has_user_correction: false\n  has_tool_use: true\n  has_decision: true\n  tokens_digest: 25\n  tokens_l0_processed: 100\n- turn: 2\n  timestamp: \"2026-03-23T11:00:00.000Z\"\n  digest: \"second\"\n  collapsed_view: \"second body\"\n  importance: normal\n",
    );
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let counter = CountingEmbedder::new(ConstEmbedder::new());
    let rebuilder = build_impl(handle.clone(), counter.clone(), root);
    let report = rebuilder.rebuild_full().await.unwrap();
    assert_eq!(report.turn_rows, 2);
    assert_eq!(count_rows(&handle, "turn_vec"), 2);
    assert_eq!(report.embed_calls, 2);
    let conn = handle.get_conn().unwrap();
    let id1: String = conn
        .query_row(
            "SELECT id FROM turn_index WHERE task_id = 'task-001' AND turn = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    // Slice H (2026-05-24): id format is 3-component agent-prefixed
    // `"{agent_id}\u{1F}{task_id}\u{1F}turn-{N}"`. Root agent encoded as
    // "/" per §1.4.4 agent_id encoding rule.
    assert_eq!(id1, format!("/{0}task-001{0}turn-1", '\u{1F}'));
}

// ──────────────────────────────────────────────────────────────────────
// AC-09: access-stat reset (T-rebuild-07/08/08b)
// ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_07_access_count_reset_content() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "");
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let lm: DateTime<Utc> = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    seed_content(
        &handle,
        "preseed",
        "/",
        "/notes.md",
        "abc",
        &emb_with_sim(0.7),
        50,
        lm,
    )
    .unwrap();
    write_text_file(&root, "notes.md", "abc");
    write_meta_yaml(
        &root,
        "",
        "_scope:\n  slug: ws\n  description: \"\"\nnotes.md:\n  description: \"\"\n",
    );
    let rebuilder = build_impl(handle.clone(), ConstEmbedder::new(), root);
    rebuilder.rebuild_full().await.unwrap();
    let row = read_content_row(&handle, "/notes.md").expect("row exists");
    assert_eq!(row.access_count, 0, "access_count must be reset to 0");
    assert!(row.last_accessed.is_none(), "last_accessed must be NULL");
}

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_08_access_count_reset_memory() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "");
    let handle = db_at(&root.join(".runtime").join("index.db"));
    seed_memory(
        &handle,
        "mem-001",
        "/",
        "preseed content",
        &emb_with_sim(0.5),
        Some("active"),
        99,
    )
    .unwrap();
    let entries = [
        serde_json::json!({"id":"mem-001","agent_id":"/","type":"fact","content":"new content","created_at":"2026-01-01T00:00:00.000Z","is_active":true,"status":"active"}),
    ];
    write_knowledge_jsonl(&root, "", &entries);
    let rebuilder = build_impl(handle.clone(), ConstEmbedder::new(), root);
    rebuilder.rebuild_full().await.unwrap();
    let conn = handle.get_conn().unwrap();
    let (ac, la): (i64, Option<String>) = conn
        .query_row(
            "SELECT access_count, last_accessed FROM memory_index WHERE id = 'mem-001'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(ac, 0);
    assert!(la.is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_08b_access_count_reset_turn() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "");
    let handle = db_at(&root.join(".runtime").join("index.db"));
    // Slice H (2026-05-24): 3-component agent-prefixed id. Pre-seeded id
    // must match what rebuild_full emits so read_turn_row(&handle, &id)
    // finds the freshly-written row.
    let id = format!("/{0}task-001{0}turn-1", '\u{1F}');
    let ts: DateTime<Utc> = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    seed_turn_with_access(
        &handle,
        &id,
        "/",
        "task-001",
        1,
        "preseed digest",
        ts,
        77,
        ts,
    )
    .unwrap();
    write_turn_index_yaml(
        &root,
        "",
        "task-001",
        "turns:\n- turn: 1\n  timestamp: \"2026-03-23T10:00:00.000Z\"\n  digest: \"new digest\"\n  collapsed_view: \"new body\"\n",
    );
    let rebuilder = build_impl(handle.clone(), ConstEmbedder::new(), root);
    rebuilder.rebuild_full().await.unwrap();
    let row = read_turn_row(&handle, &id).expect("turn row exists");
    assert_eq!(row.access_count, 0);
    assert!(row.last_accessed.is_none());
}

// ──────────────────────────────────────────────────────────────────────
// E2E recall (T-rebuild-09)
// ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_09_e2e_deterministic_ranking() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "");
    write_meta_yaml(&root, "", "_scope:\n  slug: ws\n  description: \"\"\n");
    write_text_file(&root, "notes.md", "target-text");
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let embedder = IdentityEmbedder::new("target-text");
    let rebuilder = build_impl(handle.clone(), embedder.clone(), root);
    rebuilder.rebuild_full().await.unwrap();

    // Now query via recall
    let recall = R2d2RecallImpl::new(handle.clone());
    let query_emb = emb_with_sim(1.0); // matches IdentityEmbedder("target-text").embed("target-text")
    let results = recall
        .recall("/", "target-text", &query_emb, 5)
        .await
        .unwrap();
    assert_eq!(results.len(), 1, "exactly 1 above-threshold result");
    assert!(matches!(results[0].source, Source::Content));
    assert_eq!(results[0].file_path.as_deref(), Some("/notes.md"));
    assert!((results[0].similarity - 1.0).abs() < 1e-5);
    assert!(results[0].adjusted_score > 0.0);
}

// ──────────────────────────────────────────────────────────────────────
// rebuild_agent (T-rebuild-10/10b)
// ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_10_rebuild_agent_isolation() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "");
    make_agent_root(&root, "research");
    let root_entries = [
        serde_json::json!({"id":"root-mem","agent_id":"/","type":"fact","content":"r","created_at":"2026-01-01T00:00:00.000Z","is_active":true,"status":"active"}),
    ];
    let res_entries = [
        serde_json::json!({"id":"res-mem","agent_id":"research","type":"fact","content":"x","created_at":"2026-01-01T00:00:00.000Z","is_active":true,"status":"active"}),
    ];
    write_knowledge_jsonl(&root, "", &root_entries);
    write_knowledge_jsonl(&root, "research", &res_entries);
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let rebuilder = build_impl(handle.clone(), ConstEmbedder::new(), root);
    rebuilder.rebuild_full().await.unwrap();
    assert_eq!(count_rows(&handle, "memory_index"), 2);

    rebuilder.rebuild_agent("research").await.unwrap();
    assert_eq!(
        count_rows(&handle, "memory_index"),
        2,
        "still 2 — root unchanged, research re-indexed"
    );
    assert_eq!(
        count_rows_where(&handle, "memory_index", "agent_id = ?1", &[&"/"]),
        1
    );
    assert_eq!(
        count_rows_where(&handle, "memory_index", "agent_id = ?1", &[&"research"]),
        1
    );
}

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_10b_rebuild_agent_root_path() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "");
    make_agent_root(&root, "research");
    let root_entries = [
        serde_json::json!({"id":"root-mem","agent_id":"/","type":"fact","content":"r","created_at":"2026-01-01T00:00:00.000Z","is_active":true,"status":"active"}),
    ];
    let res_entries = [
        serde_json::json!({"id":"res-mem","agent_id":"research","type":"fact","content":"x","created_at":"2026-01-01T00:00:00.000Z","is_active":true,"status":"active"}),
    ];
    write_knowledge_jsonl(&root, "", &root_entries);
    write_knowledge_jsonl(&root, "research", &res_entries);
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let rebuilder = build_impl(handle.clone(), ConstEmbedder::new(), root);
    rebuilder.rebuild_full().await.unwrap();

    rebuilder.rebuild_agent("/").await.unwrap();
    assert_eq!(
        count_rows_where(&handle, "memory_index", "agent_id = ?1", &[&"/"]),
        1
    );
    assert_eq!(
        count_rows_where(&handle, "memory_index", "agent_id = ?1", &[&"research"]),
        1
    );
}

// ──────────────────────────────────────────────────────────────────────
// Malformed input + errors cap (T-rebuild-11/11b)
// ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_11_malformed_meta_yaml_skipped() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "");
    make_agent_root(&root, "research");
    write_meta_yaml(&root, "", "_scope:\n  slug: ws\n  description: \"valid\"\n");
    write_meta_yaml(
        &root,
        "research",
        "_scope: {\n  slug: bad,\n  description: \"unclosed\n", // unmatched
    );
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let rebuilder = build_impl(handle.clone(), ConstEmbedder::new(), root);
    let report = rebuilder.rebuild_full().await.unwrap();
    assert!(report.meta_rows >= 1);
    assert!(!report.errors.is_empty());
    assert!(report
        .errors
        .iter()
        .any(|e| e.contains("research") && e.contains(".meta.yaml")));
}

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_11b_errors_cap_truncation() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "");
    // Generate 2000 broken .meta.yaml files
    for i in 0..2000 {
        write_meta_yaml(
            &root,
            &format!("dir-{i:04}"),
            "_scope: {\n  description: \"unclosed\n",
        );
    }
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let rebuilder = build_impl(handle.clone(), ConstEmbedder::new(), root);
    let report = rebuilder.rebuild_full().await.unwrap();
    assert_eq!(report.errors.len(), 1024);
    assert!(report.errors[1023].starts_with("… "));
    assert!(report.errors[1023].ends_with(" more errors truncated"));
}

// ──────────────────────────────────────────────────────────────────────
// Hidden-path exclusion (T-rebuild-12)
// ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_12_hidden_paths_excluded() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "");
    write_text_file(&root, ".git/HEAD", "ref: refs/heads/main");
    std::fs::create_dir_all(root.join(".runtime")).unwrap();
    write_text_file(&root, ".advance/packs/foo.txt", "pack data");
    write_text_file(&root, ".sub/sub-uuid-001/data.txt", "sub data");
    write_text_file(&root, "visible.md", "visible content");
    write_meta_yaml(
        &root,
        "",
        "_scope:\n  slug: ws\n  description: \"\"\nvisible.md:\n  description: \"\"\n",
    );
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let rebuilder = build_impl(handle.clone(), ConstEmbedder::new(), root);
    rebuilder.rebuild_full().await.unwrap();
    assert_eq!(count_rows(&handle, "content_index"), 1);
    let row = read_content_row(&handle, "/visible.md").unwrap();
    assert_eq!(row.file_path, "/visible.md");
    let banned = count_rows_where(
        &handle,
        "content_index",
        "file_path LIKE '%/.runtime/%' OR file_path LIKE '%/.git/%' OR file_path LIKE '%/.advance/%' OR file_path LIKE '%/.sub/%'",
        &[],
    );
    assert_eq!(banned, 0, "no rows for hidden trees");
}

// ──────────────────────────────────────────────────────────────────────
// Idempotence (T-rebuild-13/13b)
// ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_13_idempotent() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "");
    write_meta_yaml(&root, "", "_scope:\n  slug: ws\n  description: \"\"\n");
    write_text_file(&root, "notes.md", "abc");
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let rebuilder = build_impl(handle.clone(), ConstEmbedder::new(), root.clone());
    let r1 = rebuilder.rebuild_full().await.unwrap();
    let r2 = rebuilder.rebuild_full().await.unwrap();
    assert_eq!(r1.meta_rows, r2.meta_rows);
    assert_eq!(r1.content_rows, r2.content_rows);
    assert_eq!(r1.memory_rows, r2.memory_rows);
    assert_eq!(r1.task_rows, r2.task_rows);
    assert_eq!(r1.turn_rows, r2.turn_rows);
    assert_eq!(count_rows(&handle, "content_index"), r1.content_rows as i64);
    assert!(r1.errors.is_empty());
    assert!(r2.errors.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_13b_id_stability() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "");
    write_meta_yaml(&root, "", "_scope:\n  slug: ws\n  description: \"root\"\n");
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let rebuilder = build_impl(handle.clone(), ConstEmbedder::new(), root);
    rebuilder.rebuild_full().await.unwrap();
    let conn = handle.get_conn().unwrap();
    let ids1: Vec<String> = conn
        .prepare("SELECT id FROM meta_index ORDER BY id")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    drop(conn);
    rebuilder.rebuild_full().await.unwrap();
    let conn = handle.get_conn().unwrap();
    let ids2: Vec<String> = conn
        .prepare("SELECT id FROM meta_index ORDER BY id")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert_eq!(ids1, ids2);
    let expected_root_id = format!("/{0}{0}_scope", '\u{1F}');
    assert!(ids1.contains(&expected_root_id), "root id shape pinned");
}

// ──────────────────────────────────────────────────────────────────────
// Missing source files (T-rebuild-14)
// ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_14_missing_optional_sources() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "");
    write_meta_yaml(
        &root,
        "",
        "_scope:\n  slug: ws\n  description: \"\"\nnotes.md:\n  description: \"\"\n",
    );
    write_text_file(&root, "notes.md", "abc");
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let rebuilder = build_impl(handle.clone(), ConstEmbedder::new(), root);
    let report = rebuilder.rebuild_full().await.unwrap();
    assert_eq!(report.memory_rows, 0);
    assert_eq!(report.task_rows, 0);
    assert_eq!(report.turn_rows, 0);
    assert_eq!(report.content_rows, 1);
    assert_eq!(report.meta_rows, 2);
    assert!(report.errors.is_empty());
}

// ──────────────────────────────────────────────────────────────────────
// Embedder failure (T-rebuild-15) + collisions (T-rebuild-15b/15c)
// ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_15_embedder_failure_propagates() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "");
    write_text_file(&root, "notes.md", "abc");
    write_meta_yaml(
        &root,
        "",
        "_scope:\n  slug: ws\n  description: \"d\"\nnotes.md:\n  description: \"\"\n",
    );
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let rebuilder = build_impl(handle.clone(), FailingEmbedder, root);
    let err = rebuilder.rebuild_full().await.unwrap_err();
    match err {
        DbError::Internal(msg) => assert!(msg.contains("embed:"), "got: {msg}"),
        other => panic!("expected DbError::Internal, got {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_15b_task_id_collision() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "agent-a");
    make_agent_root(&root, "agent-b");
    write_summary_yaml(
        &root,
        "agent-a",
        "task-001",
        "_meta:\n  task_id: task-001\n  agent_id: agent-a\n  title: A\nbrief: a\n",
    );
    write_summary_yaml(
        &root,
        "agent-b",
        "task-001",
        "_meta:\n  task_id: task-001\n  agent_id: agent-b\n  title: B\nbrief: b\n",
    );
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let rebuilder = build_impl(handle.clone(), ConstEmbedder::new(), root);
    let report = rebuilder.rebuild_full().await.unwrap();
    assert_eq!(report.task_rows, 1);
    let conn = handle.get_conn().unwrap();
    let agent: String = conn
        .query_row(
            "SELECT agent_id FROM task_index WHERE task_id = 'task-001'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(agent, "agent-a");
    assert!(report.errors.iter().any(|e| {
        e.contains("task_id collision") && e.contains("task-001") && e.contains("agent-b")
    }));
}

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_15c_turn_distinct_ids() {
    // Slice H (2026-05-24) semantic update: 3-component agent-prefixed
    // turn_index id format makes cross-agent PK collisions structurally
    // impossible. Pre-Slice-H this test verified "first-agent wins via
    // SQLITE_CONSTRAINT_PRIMARYKEY catch"; after the id-format change both
    // agents' rows survive with distinct ids.
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "agent-a");
    make_agent_root(&root, "agent-b");
    let yaml = "turns:\n- turn: 1\n  timestamp: \"2026-03-23T10:00:00.000Z\"\n  digest: \"d1\"\n  collapsed_view: \"\"\n";
    write_turn_index_yaml(&root, "agent-a", "task-001", yaml);
    write_turn_index_yaml(&root, "agent-b", "task-001", yaml);
    let handle = db_at(&root.join(".runtime").join("index.db"));
    let rebuilder = build_impl(handle.clone(), ConstEmbedder::new(), root);
    let report = rebuilder.rebuild_full().await.unwrap();
    // Both agents' turn rows survive.
    assert_eq!(report.turn_rows, 2);
    let conn = handle.get_conn().unwrap();
    let mut stmt = conn
        .prepare("SELECT agent_id FROM turn_index WHERE task_id = 'task-001' AND turn = 1")
        .unwrap();
    let mut agents: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    agents.sort();
    assert_eq!(agents, vec!["agent-a".to_string(), "agent-b".to_string()]);
    // The formerly-expected "turn_index id collision" error must NOT appear
    // (any other pre-existing rebuild errors are tolerated).
    assert!(
        !report.errors.iter().any(|e| e.contains("turn_index id collision")),
        "turn_index id collision error should be absent — 3-component id structurally prevents PK collision; got errors: {:?}",
        report.errors
    );
    let _ = ts_text; // keep import used
}

// ──────────────────────────────────────────────────────────────────────
// MODULE-002-T64 (AC-19): `index.md` non-dependency at the SQLite rebuild leg.
// SQLite rebuild neither requires nor special-cases `index.md` — a present
// `index.md` is indexed as ordinary content, and rebuild succeeds even when the
// `.meta.yaml` does not list it. ADR 2026-06-29 Decision 2.
// ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn t_rebuild_module002_t64_index_md_is_ordinary_content() {
    let ws = tempdir();
    let root = ws.path().to_path_buf();
    make_agent_root(&root, "");
    write_text_file(&root, "index.md", "# Index\nnav");
    // The `.meta.yaml` deliberately does NOT list `index.md` — rebuild must not
    // depend on it being present in the directory index.
    write_meta_yaml(&root, "", "_scope:\n  slug: ws\n  description: \"\"\n");

    let handle = db_at(&root.join(".runtime").join("index.db"));
    let rebuilder = build_impl(handle.clone(), ConstEmbedder::new(), root);
    let report = rebuilder.rebuild_full().await.unwrap(); // succeeds

    // `index.md` is indexed exactly like any other content file.
    let row = read_content_row(&handle, "/index.md").expect("index.md content row missing");
    assert_eq!(row.content_preview.as_deref(), Some("# Index\nnav"));
    assert!(report.content_rows >= 1);
}

//! AC-17 — self-stats / child-stats (REQ-318).

use std::sync::Arc;

use advance_database::{R2d2SqliteIndexHandle, SqliteIndexHandle};
use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus};
use cap_lifecycle::{
    AgentStats, AgentStatsReader, AgentTreeStore, DefaultStatsController, LifecycleError,
    SqliteAgentStatsReader, StatsController,
};
use tempfile::TempDir;

struct RecReader(AgentStats);
impl AgentStatsReader for RecReader {
    fn read_stats(&self, _a: &str) -> Result<AgentStats, LifecycleError> {
        Ok(self.0.clone())
    }
}

struct FailReader;
impl AgentStatsReader for FailReader {
    fn read_stats(&self, _a: &str) -> Result<AgentStats, LifecycleError> {
        Err(LifecycleError::IoFailure("boom".into()))
    }
}

fn sample() -> AgentStats {
    AgentStats {
        active_tasks: 1,
        completed_tasks: 2,
        avg_turns_per_task: 3.0,
        avg_completion_time_hours: 4.0,
        memory_entries: 5,
        llm_tokens_24h: 6,
        error_count_24h: 7,
        last_active: "2026-05-17T00:00:00Z".into(),
    }
}

fn tree_with_parent_child() -> (TempDir, AgentTreeStore) {
    let tmp = TempDir::new().unwrap();
    let tree = AgentTreeStore::new(tmp.path().to_path_buf()).unwrap();
    let rws = tree.workspace_root().join("root");
    std::fs::create_dir_all(&rws).unwrap();
    tree.insert_root(AgentNode {
        id: AgentId("root".into()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: rws,
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    })
    .unwrap();
    let cws = tree.workspace_root().join("root/c");
    std::fs::create_dir_all(&cws).unwrap();
    tree.insert_child(
        &AgentId("root".into()),
        AgentNode {
            id: AgentId("c".into()),
            kind: AgentKind::Child,
            parent: Some(AgentId("root".into())),
            workspace_path: cws,
            capabilities: Vec::new(),
            template_ref: None,
            status: AgentStatus::Active,
        },
    )
    .unwrap();
    (tmp, tree)
}

#[test]
fn ac17_self_stats_round_trips() {
    let (_t, tree) = tree_with_parent_child();
    let c = DefaultStatsController::new(tree, Arc::new(RecReader(sample())));
    assert_eq!(c.self_stats("root").unwrap(), sample());
}

#[test]
fn ac17_child_stats_parent_ok() {
    let (_t, tree) = tree_with_parent_child();
    let c = DefaultStatsController::new(tree, Arc::new(RecReader(sample())));
    assert_eq!(c.child_stats("root", "c").unwrap(), sample());
}

#[test]
fn ac17_child_stats_non_parent_permission_denied() {
    let (_t, tree) = tree_with_parent_child();
    let c = DefaultStatsController::new(tree, Arc::new(RecReader(sample())));
    let e = c.child_stats("c", "root").unwrap_err();
    assert!(matches!(e, LifecycleError::PermissionDenied(_)));
}

#[test]
fn ac17_child_stats_missing_child_not_found() {
    let (_t, tree) = tree_with_parent_child();
    let c = DefaultStatsController::new(tree, Arc::new(RecReader(sample())));
    let e = c.child_stats("root", "ghost").unwrap_err();
    assert!(matches!(e, LifecycleError::NotFound(_)));
}

#[test]
fn ac17_reader_io_failure_surfaces() {
    let (_t, tree) = tree_with_parent_child();
    let c = DefaultStatsController::new(tree, Arc::new(FailReader));
    let e = c.self_stats("root").unwrap_err();
    assert!(matches!(e, LifecycleError::IoFailure(_)));
}

#[test]
fn ac17_sqlite_reader_seeded_row() {
    let handle = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    {
        let conn = handle.get_conn().unwrap();
        conn.execute_batch(
            "CREATE TABLE agent_stats (
               agent_id TEXT PRIMARY KEY,
               active_tasks INTEGER NOT NULL,
               completed_tasks INTEGER NOT NULL,
               avg_turns_per_task REAL NOT NULL,
               avg_completion_time_hours REAL NOT NULL,
               memory_entries INTEGER NOT NULL,
               llm_tokens_24h INTEGER NOT NULL,
               error_count_24h INTEGER NOT NULL,
               last_active TEXT NOT NULL
             );
             INSERT INTO agent_stats VALUES
               ('root',1,2,3.0,4.0,5,6,7,'2026-05-17T00:00:00Z');",
        )
        .unwrap();
    }
    let reader = SqliteAgentStatsReader::new(Arc::new(handle));
    assert_eq!(reader.read_stats("root").unwrap(), sample());
}

/// harvest-obs regression (2026-06-10): the REAL M019 `agent_stats` schema
/// (event-bus/src/schema.rs) declares every value column NULLABLE, and the
/// live stats_aggregator UPSERT writes `avg_turns_per_task` /
/// `avg_completion_time_hours` / `memory_entries` as literal NULL. The
/// pre-fix reader read these as non-Option `f64`/`i64` and failed every
/// real-writer row with `IoFailure(InvalidColumnType)` (masked by the
/// hand-seeded NOT-NULL table in `ac17_sqlite_reader_seeded_row`). This test
/// seeds the verbatim production schema + a row shaped exactly like the
/// aggregator UPSERT and asserts Ok with semantic-zero defaults.
#[test]
fn ac17_sqlite_reader_real_writer_null_row() {
    let handle = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    {
        let conn = handle.get_conn().unwrap();
        // Verbatim CREATE_AGENT_STATS_SQL from event-bus/src/schema.rs.
        conn.execute_batch(
            "CREATE TABLE agent_stats (
               agent_id TEXT PRIMARY KEY,
               active_tasks INTEGER,
               completed_tasks INTEGER,
               avg_turns_per_task REAL,
               avg_completion_time_hours REAL,
               memory_entries INTEGER,
               llm_tokens_24h INTEGER,
               error_count_24h INTEGER,
               last_active TEXT
             );
             -- Row shape = UPSERT_AGENT_STATS_SQL (stats_aggregator.rs):
             -- VALUES (?1, ?2, ?3, NULL, NULL, NULL, ?4, ?5, ?6)
             INSERT INTO agent_stats VALUES
               ('obs-a', 2, 1, NULL, NULL, NULL, 850, 0, '2026-06-10T00:00:00Z');",
        )
        .unwrap();
    }
    let reader = SqliteAgentStatsReader::new(Arc::new(handle));
    let got = reader.read_stats("obs-a").unwrap();
    assert_eq!(
        got,
        AgentStats {
            active_tasks: 2,
            completed_tasks: 1,
            avg_turns_per_task: 0.0,
            avg_completion_time_hours: 0.0,
            memory_entries: 0,
            llm_tokens_24h: 850,
            error_count_24h: 0,
            last_active: "2026-06-10T00:00:00Z".into(),
        },
        "NULL avg_*/memory_entries must project to semantic zeros, not IoFailure"
    );
}

/// adversarial r12: a NULL in an ALWAYS-WRITTEN counter column (here
/// llm_tokens_24h) is an anomaly — surfaced as IoFailure, never normalized to
/// a plausible 0 (corruption-masking refusal).
#[test]
fn ac17_sqlite_reader_null_counter_is_surfaced_not_masked() {
    let handle = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    {
        let conn = handle.get_conn().unwrap();
        conn.execute_batch(
            "CREATE TABLE agent_stats (
               agent_id TEXT PRIMARY KEY, active_tasks INTEGER,
               completed_tasks INTEGER, avg_turns_per_task REAL,
               avg_completion_time_hours REAL, memory_entries INTEGER,
               llm_tokens_24h INTEGER, error_count_24h INTEGER, last_active TEXT );
             INSERT INTO agent_stats VALUES
               ('obs-a', 2, 1, NULL, NULL, NULL, NULL, 0, '2026-06-10T00:00:00Z');",
        )
        .unwrap();
    }
    let reader = SqliteAgentStatsReader::new(Arc::new(handle));
    let e = reader.read_stats("obs-a").unwrap_err();
    assert!(
        matches!(&e, LifecycleError::IoFailure(m) if m.contains("llm_tokens_24h")),
        "NULL llm_tokens_24h must surface as IoFailure naming the column, got {e:?}"
    );
}

/// adversarial r12: the foreign-owned last_active TEXT column is egress-capped
/// at 64 bytes — an oversized value is rejected, never reflected unbounded
/// across the WIT boundary.
#[test]
fn ac17_sqlite_reader_oversized_last_active_rejected() {
    let handle = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    {
        let conn = handle.get_conn().unwrap();
        conn.execute(
            "CREATE TABLE agent_stats (
               agent_id TEXT PRIMARY KEY, active_tasks INTEGER,
               completed_tasks INTEGER, avg_turns_per_task REAL,
               avg_completion_time_hours REAL, memory_entries INTEGER,
               llm_tokens_24h INTEGER, error_count_24h INTEGER, last_active TEXT )",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO agent_stats VALUES ('obs-a', 2, 1, NULL, NULL, NULL, 850, 0, ?1)",
            [&"x".repeat(100_000)],
        )
        .unwrap();
    }
    let reader = SqliteAgentStatsReader::new(Arc::new(handle));
    let e = reader.read_stats("obs-a").unwrap_err();
    assert!(
        matches!(&e, LifecycleError::IoFailure(m) if m.contains("last_active")),
        "100KB last_active must be rejected with IoFailure naming the column, got {e:?}"
    );
}

#[test]
fn ac17_sqlite_reader_missing_row_not_found() {
    let handle = R2d2SqliteIndexHandle::new_in_memory().unwrap();
    {
        let conn = handle.get_conn().unwrap();
        conn.execute_batch(
            "CREATE TABLE agent_stats (
               agent_id TEXT PRIMARY KEY, active_tasks INTEGER NOT NULL,
               completed_tasks INTEGER NOT NULL, avg_turns_per_task REAL NOT NULL,
               avg_completion_time_hours REAL NOT NULL, memory_entries INTEGER NOT NULL,
               llm_tokens_24h INTEGER NOT NULL, error_count_24h INTEGER NOT NULL,
               last_active TEXT NOT NULL );",
        )
        .unwrap();
    }
    let reader = SqliteAgentStatsReader::new(Arc::new(handle));
    let e = reader.read_stats("absent").unwrap_err();
    assert!(matches!(e, LifecycleError::NotFound(_)));
}

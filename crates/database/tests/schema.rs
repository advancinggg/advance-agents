use std::path::Path;

use advance_database::{DbError, R2d2SqliteIndexHandle, SqliteIndexHandle};
use rusqlite::{params, OptionalExtension};

#[test]
fn t01_migrations_idempotent() {
    let handle = R2d2SqliteIndexHandle::new_in_memory().expect("first setup");
    handle
        .run_migrations()
        .expect("second migration must be a no-op");
    handle
        .run_migrations()
        .expect("third migration must be a no-op");
    assert_eq!(handle.schema_version(), 1);
}

#[test]
fn t01b_schema_audit_after_migration() {
    let handle = R2d2SqliteIndexHandle::new_in_memory().expect("setup");
    let conn = handle.get_conn().expect("get conn");

    let expected_tables = [
        "meta_index",
        "content_index",
        "content_fts",
        "memory_index",
        "task_index",
        "turn_index",
        "meta_vec",
        "content_vec",
        "memory_vec",
        "task_vec",
        "turn_vec",
    ];
    for name in expected_tables {
        let row: Option<String> = conn
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
                params![name],
                |r| r.get(0),
            )
            .optional()
            .expect("query");
        assert!(row.is_some(), "expected table {name} to exist");
    }

    let expected_indexes = [
        "idx_meta_agent_dir",
        "idx_content_agent_path",
        "idx_memory_agent_active",
        "idx_task_agent_status",
        "idx_turn_task",
    ];
    for name in expected_indexes {
        let row: Option<String> = conn
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?",
                params![name],
                |r| r.get(0),
            )
            .optional()
            .expect("query");
        assert!(row.is_some(), "expected index {name} to exist");
    }
}

#[test]
fn pool_size_zero_returns_invalid_config_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("idx.db");
    let result = R2d2SqliteIndexHandle::new(&path, 0);
    match result {
        Err(DbError::InvalidConfig(msg)) => {
            assert!(msg.contains("pool_size"), "msg = {msg}");
        }
        Err(other) => panic!("expected InvalidConfig, got {other:?}"),
        Ok(_) => panic!("expected error for pool_size = 0"),
    }
}

#[test]
fn memory_path_routes_to_explicit_helper() {
    let result = R2d2SqliteIndexHandle::new(Path::new(":memory:"), 1);
    match result {
        Err(DbError::InvalidConfig(msg)) => {
            assert!(msg.contains("new_in_memory"), "msg = {msg}");
        }
        Err(other) => panic!("expected InvalidConfig, got {other:?}"),
        Ok(_) => panic!("expected error for db_path == :memory:"),
    }
}

#[test]
fn sqlite_uri_path_does_not_redirect_to_memory() {
    // R2d2SqliteIndexHandle::new strips SQLITE_OPEN_URI from its OpenFlags, so a
    // caller passing a URI-shaped path opens a literal file with that name (or
    // fails with an OS error if the path is invalid) instead of being silently
    // reinterpreted as a memory database. Adversarial defense (round-12 W2 fix).
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("file::memory:?cache=shared");
    let result = R2d2SqliteIndexHandle::new(&path, 1);
    // Either the path is created literally (success) or rejected by the OS, but
    // it must NOT silently return a memory database. Verify by writing a row
    // and checking the file exists on disk.
    match result {
        Ok(handle) => {
            let conn = handle.get_conn().expect("conn");
            conn.execute(
                "INSERT INTO meta_index (id, agent_id, directory, entry_name, updated_at) \
                 VALUES ('t-uri', 'a-1', '/tmp', 'probe', '2026-05-01')",
                [],
            )
            .expect("insert");
            drop(conn);
            drop(handle);
            assert!(path.exists(), "expected literal file at {path:?}");
        }
        Err(DbError::Sqlite(_)) | Err(DbError::Pool(_)) => {
            // Acceptable — the colon-laden filename may be rejected on some
            // filesystems. Failing is fine; silent URI redirect is what we
            // explicitly defend against.
        }
        Err(other) => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn schema_version_persisted_via_pragma_user_version() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("v.db");
    let handle = R2d2SqliteIndexHandle::new(&path, 1).expect("setup");
    let conn = handle.get_conn().expect("get conn");
    let v: u32 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .expect("user_version");
    assert_eq!(v, 1, "PRAGMA user_version must be persisted to 1");
}

#[test]
fn migrations_committed_in_single_transaction_with_user_version() {
    // After a successful run_migrations(), PRAGMA user_version and the table
    // set must agree (no half-state). This is a positive test for the
    // transactional wrapping; the rollback path (mid-apply failure) is hard
    // to exercise deterministically without injecting a fault, but the
    // transaction's commit-or-rollback contract guarantees atomicity.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("tx.db");
    let handle = R2d2SqliteIndexHandle::new(&path, 1).expect("setup");
    let conn = handle.get_conn().expect("get conn");
    let v: u32 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .expect("user_version");
    let table_count: u32 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE '%_index'",
            [],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(v, 1);
    assert_eq!(
        table_count, 5,
        "expected 5 *_index primary tables to coexist with user_version=1"
    );
}

#[test]
fn fresh_db_with_preexisting_tables_rejected() {
    // user_version=0 + pre-created primary tables = adversarial bypass attempt.
    // schema::apply must refuse rather than silently CREATE-IF-NOT-EXISTS over
    // attacker-shaped state and then bless it as version-1.
    use rusqlite::Connection;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("preplanted.db");
    {
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch(
            "CREATE TABLE meta_index (id TEXT, attacker_field TEXT);
             -- user_version stays at default 0",
        )
        .expect("plant table");
    }
    let result = R2d2SqliteIndexHandle::new(&path, 1);
    match result {
        Err(DbError::InvalidConfig(msg)) => {
            assert!(
                msg.contains("fresh database") && msg.contains("must be empty"),
                "msg = {msg}"
            );
        }
        Err(other) => panic!("expected InvalidConfig (fresh-db-must-be-empty), got {other:?}"),
        Ok(_) => panic!("expected rejection of pre-planted fresh DB"),
    }
}

#[test]
fn forged_v1_with_ordinary_tables_impersonating_virtuals_rejected() {
    // Adversarial round 10 closure: an attacker plants 11 ordinary tables
    // using the expected names (including the 6 names we expect to be
    // virtual: content_fts as fts5, meta_vec/content_vec/memory_vec/task_vec/
    // turn_vec as vec0). Both ordinary and virtual tables show type='table'
    // in sqlite_master, so a count-only check passes. The new defense reads
    // sqlite_master.sql and verifies each of the 6 virtual-table names has
    // its expected module token (fts5 or vec0).
    use rusqlite::Connection;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("forged_v1_ordinary_tables.db");
    {
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch(
            "CREATE TABLE meta_index (id TEXT);
             CREATE TABLE content_index (id TEXT);
             CREATE TABLE content_fts (id TEXT);          -- ORDINARY, not fts5
             CREATE TABLE memory_index (id TEXT);
             CREATE TABLE task_index (task_id TEXT);
             CREATE TABLE turn_index (id TEXT);
             CREATE TABLE meta_vec (id TEXT);             -- ORDINARY, not vec0
             CREATE TABLE content_vec (id TEXT);          -- ORDINARY
             CREATE TABLE memory_vec (id TEXT);           -- ORDINARY
             CREATE TABLE task_vec (id TEXT);             -- ORDINARY
             CREATE TABLE turn_vec (id TEXT);             -- ORDINARY
             PRAGMA user_version = 1;",
        )
        .expect("plant 11 ordinary tables + version");
    }
    let result = R2d2SqliteIndexHandle::new(&path, 1);
    match result {
        Err(DbError::InvalidConfig(msg)) => {
            assert!(
                msg.contains("user_version=1") && msg.contains("virtual-table"),
                "msg = {msg}"
            );
        }
        Err(other) => panic!("expected InvalidConfig, got {other:?}"),
        Ok(_) => panic!("expected rejection of forged-v1 ordinary-table impersonation"),
    }
}

#[test]
fn forged_v1_with_views_instead_of_tables_rejected() {
    // Adversarial round 9 closure: an attacker plants user_version=1 plus
    // 11 forged VIEWs (or indexes/triggers) using the expected names. A
    // name-only count would return 11 and accept the file; the type='table'
    // filter on the SCHEMA_VERSION branch correctly rejects this.
    use rusqlite::Connection;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("forged_v1_views.db");
    {
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch(
            "CREATE VIEW meta_index AS SELECT 1 AS id;
             CREATE VIEW content_index AS SELECT 1 AS id;
             CREATE VIEW content_fts AS SELECT 1 AS id;
             CREATE VIEW memory_index AS SELECT 1 AS id;
             CREATE VIEW task_index AS SELECT 1 AS task_id;
             CREATE VIEW turn_index AS SELECT 1 AS id;
             CREATE VIEW meta_vec AS SELECT 1 AS embedding;
             CREATE VIEW content_vec AS SELECT 1 AS embedding;
             CREATE VIEW memory_vec AS SELECT 1 AS embedding;
             CREATE VIEW task_vec AS SELECT 1 AS embedding;
             CREATE VIEW turn_vec AS SELECT 1 AS embedding;
             PRAGMA user_version = 1;",
        )
        .expect("plant 11 views + version");
    }
    let result = R2d2SqliteIndexHandle::new(&path, 1);
    // Two valid outcomes:
    //   (a) The user_version=0 emptiness check fires first (it counts ANY
    //       object kind including views), rejecting with the fresh-DB-empty
    //       message. NOTE: this branch only runs when stored==0, but our
    //       file has stored=1 — so this won't fire here.
    //   (b) The user_version=SCHEMA_VERSION branch fires with type='table'
    //       filter → existing=0 != 11 → rejection.
    match result {
        Err(DbError::InvalidConfig(msg)) => {
            assert!(
                msg.contains("user_version=1") && msg.contains("expected tables"),
                "msg = {msg}"
            );
        }
        Err(other) => panic!("expected InvalidConfig, got {other:?}"),
        Ok(_) => panic!("expected rejection of forged-v1-with-views"),
    }
}

#[test]
fn empty_db_with_forged_user_version_rejected() {
    // Adversarial round 8 closure: an attacker who plants ONLY
    // `PRAGMA user_version = 1` on an empty DB (no expected tables) bypasses
    // the fresh-DB emptiness check (stored != 0) AND the migration body
    // (stored == SCHEMA_VERSION skips). The new defense rejects when
    // user_version matches but the 11 expected tables are not all present.
    use rusqlite::Connection;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("forged_version_empty.db");
    {
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch("PRAGMA user_version = 1;")
            .expect("plant version marker");
    }
    let result = R2d2SqliteIndexHandle::new(&path, 1);
    match result {
        Err(DbError::InvalidConfig(msg)) => {
            assert!(
                msg.contains("user_version=1") && msg.contains("expected tables"),
                "msg = {msg}"
            );
        }
        Err(other) => panic!("expected InvalidConfig, got {other:?}"),
        Ok(_) => panic!("expected rejection of empty DB with forged user_version"),
    }
}

#[test]
fn fresh_db_with_mixed_case_preexisting_object_rejected() {
    // Adversarial round 7 closure: SQLite preserves CREATE-time casing in
    // sqlite_master.name, so `CREATE TABLE "Meta_Index"` stores literal
    // `Meta_Index`. A case-sensitive IN-list would miss it, but the runtime's
    // own `CREATE TABLE IF NOT EXISTS meta_index` resolution is case-
    // insensitive, opening a forgery path. The fresh-DB check now uses
    // LOWER(name) to foreclose every case variant.
    use rusqlite::Connection;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("preplanted_mixedcase.db");
    {
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch("CREATE TABLE \"Meta_Index\" (id TEXT, attacker_field TEXT);")
            .expect("plant mixed-case table");
    }
    let result = R2d2SqliteIndexHandle::new(&path, 1);
    match result {
        Err(DbError::InvalidConfig(msg)) => {
            assert!(
                msg.contains("fresh database") && msg.contains("must be empty"),
                "msg = {msg}"
            );
        }
        Err(other) => panic!("expected InvalidConfig, got {other:?}"),
        Ok(_) => panic!("expected rejection of mixed-case pre-planted object"),
    }
}

#[test]
fn fresh_db_with_preexisting_view_rejected() {
    // Adversarial round 6 closure: `CREATE VIEW <expected_name>` bypasses a
    // `type='table'` filter. The fresh-DB check now uses no type filter, so
    // any object kind (table/view/index/trigger) at one of the 11 expected
    // names triggers rejection. Empirical bypass confirmed by Codex evaluator.
    use rusqlite::Connection;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("preplanted_view.db");
    {
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch(
            "CREATE VIEW content_fts AS \
                 SELECT 'p' AS file_path, 'c' AS content_preview, 't' AS tags;",
        )
        .expect("plant view");
    }
    let result = R2d2SqliteIndexHandle::new(&path, 1);
    match result {
        Err(DbError::InvalidConfig(msg)) => {
            assert!(
                msg.contains("fresh database") && msg.contains("must be empty"),
                "msg = {msg}"
            );
        }
        Err(other) => panic!("expected InvalidConfig (fresh-db-must-be-empty), got {other:?}"),
        Ok(_) => panic!("expected rejection of pre-planted view"),
    }
}

#[test]
fn fresh_db_with_preexisting_virtual_tables_rejected() {
    // Adversarial round 5 closure: planting only virtual tables (e.g. content_fts
    // with attacker-chosen columns, or meta_vec with attacker-chosen vec0
    // dimension) must also be rejected — the auxiliary-table prepopulation
    // path was the residual gap after R4's primary-only check.
    use rusqlite::Connection;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("preplanted_virtual.db");
    {
        // We bootstrap sqlite-vec for this Connection via the production handle
        // path's auto_extension registration: opening any handle once registers
        // it process-globally. Use a separate :memory: handle just to register.
        let _bootstrap = R2d2SqliteIndexHandle::new_in_memory().expect("bootstrap");
        let conn = Connection::open(&path).expect("open");
        // Plant only a forged vec0 table with mismatched dimension (1 vs 768).
        conn.execute_batch("CREATE VIRTUAL TABLE meta_vec USING vec0(embedding float[1]);")
            .expect("plant virtual");
    }
    let result = R2d2SqliteIndexHandle::new(&path, 1);
    match result {
        Err(DbError::InvalidConfig(msg)) => {
            assert!(
                msg.contains("fresh database") && msg.contains("must be empty"),
                "msg = {msg}"
            );
        }
        Err(other) => panic!("expected InvalidConfig (fresh-db-must-be-empty), got {other:?}"),
        Ok(_) => panic!("expected rejection of pre-planted virtual table"),
    }
}

#[test]
fn schema_mismatch_rejects_unknown_version() {
    use rusqlite::Connection;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("tampered.db");
    {
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch("PRAGMA user_version = 99")
            .expect("set tampered version");
    }
    let result = R2d2SqliteIndexHandle::new(&path, 1);
    match result {
        Err(DbError::SchemaMismatch { stored, expected }) => {
            assert_eq!(stored, 99);
            assert_eq!(expected, 1);
        }
        Err(other) => panic!("expected SchemaMismatch, got {other:?}"),
        Ok(_) => panic!("expected SchemaMismatch error"),
    }
}

#[test]
fn t14_two_layer_separation() {
    fn assert_dyn_safe<T: ?Sized>(_: &T) {}
    let handle = R2d2SqliteIndexHandle::new_in_memory().expect("setup");
    let dyn_handle: &dyn SqliteIndexHandle = &handle;
    assert_dyn_safe(dyn_handle);

    let _: u32 = handle.schema_version();
}

#[test]
fn t20_database_capabilities() {
    let handle = R2d2SqliteIndexHandle::new_in_memory().expect("setup");
    let conn = handle.get_conn().expect("get conn");

    let v: String = conn
        .query_row("SELECT sqlite_version()", [], |r| r.get(0))
        .expect("sqlite_version");
    let parts: Vec<u32> = v
        .split('.')
        .take(2)
        .map(|x| x.parse().unwrap_or(0))
        .collect();
    let major = parts[0];
    let minor = parts.get(1).copied().unwrap_or(0);
    assert!(
        major > 3 || (major == 3 && minor >= 45),
        "expected SQLite >= 3.45, got {v}"
    );

    let vec_v: String = conn
        .query_row("SELECT vec_version()", [], |r| r.get(0))
        .expect("sqlite-vec must be loaded");
    assert!(!vec_v.is_empty());

    conn.execute_batch(
        "CREATE VIRTUAL TABLE temp.x_fts5_probe USING fts5(content); DROP TABLE temp.x_fts5_probe;",
    )
    .expect("FTS5 must be available — CREATE VIRTUAL TABLE ... USING fts5 failed");
}

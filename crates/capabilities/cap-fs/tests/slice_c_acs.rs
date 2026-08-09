//! Slice C AC verification tests — covers the 4 in-scope ACs:
//! AC-03 (.meta.yaml mandatory at directory creation, M005 spawn-child path)
//! AC-12 (triple consistency: fs.write → .meta.yaml → SQLite + events)
//! AC-13 (startup reconciliation: drift detection + auto-fill + SQL rebuild)
//! AC-17 (workspace root .meta.yaml as single metadata index tree root)
//!
//! Tests T24-T39. Each test builds its own ephemeral fixture (no shared state).

mod common;

use std::path::Path;
use std::sync::Arc;

use advance_runtime::host_registry::{HostCallContext, HostFunctionHandler};
use advance_shared_types::traits::{AgentTreeSnapshot, EventBusEmit};
use cap_fs::{
    is_reconciler_skipped_name, normalize_ws_path, DefaultAtomicWriter, DefaultVirtualPathResolver,
    FsDeleteHandler, FsWriteHandler, MetaMaintainer, MetaSchemaLoader, ReconcileReport, SqliteSync,
    VirtualPathResolver, WorkspaceReconciler,
};
use wasmtime::component::Val;

use common::{
    build_real_db_sync, single_agent_tree, MockIndexRebuild, MockSqliteSync, SqlSyncCall,
    TestEmitter,
};

const TRACE_ID: &str = "tr-sc";

fn ctx_for(agent_id: &str) -> HostCallContext {
    HostCallContext {
        agent_id: agent_id.into(),
        trace_id: TRACE_ID.into(),
        turn_id: None,
        capability: "fs".into(),
        function: "advance:runtime/agent-fs::test".into(),
        run_id: None,
        iteration: None,
    }
}

fn unwrap_ok_none(out: Vec<Val>) {
    assert_eq!(out.len(), 1);
    match out.into_iter().next().unwrap() {
        Val::Result(Ok(None)) => {}
        other => panic!("expected Ok(None), got {other:?}"),
    }
}

fn schema_loader_for(tempdir_path: &Path) -> Arc<MetaSchemaLoader> {
    Arc::new(MetaSchemaLoader::new_with_default(
        tempdir_path.join("schema.yaml"),
    ))
}

fn maintainer_for(tempdir_path: &Path) -> Arc<MetaMaintainer> {
    Arc::new(MetaMaintainer::new(
        schema_loader_for(tempdir_path),
        Arc::new(DefaultAtomicWriter),
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// AC-03: ensure_dir_meta primitive used by M005 spawn-child path.
// ─────────────────────────────────────────────────────────────────────────────

// SC-T24: ensure_dir_meta creates a fresh .meta.yaml with `_scope` block.
#[tokio::test]
async fn sc_t24_ensure_dir_meta_creates_fresh_yaml() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let dir = tempdir.path().join("sub-a");
    std::fs::create_dir_all(&dir).unwrap();

    let maintainer = maintainer_for(tempdir.path());
    let created = maintainer
        .ensure_dir_meta(&dir, None)
        .await
        .expect("ensure_dir_meta");
    assert!(created, "first call should create .meta.yaml");

    let meta_path = dir.join(".meta.yaml");
    assert!(meta_path.exists(), ".meta.yaml must exist");
    let body = std::fs::read_to_string(&meta_path).unwrap();
    assert!(body.contains("_scope"), "scope block must be present");
    assert!(
        body.contains("description"),
        "scope must include description"
    );
}

// SC-T25: ensure_dir_meta is idempotent — second call returns false, no overwrite.
#[tokio::test]
async fn sc_t25_ensure_dir_meta_idempotent() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let dir = tempdir.path().join("sub-b");
    std::fs::create_dir_all(&dir).unwrap();

    let maintainer = maintainer_for(tempdir.path());
    let first = maintainer.ensure_dir_meta(&dir, None).await.unwrap();
    assert!(first, "first call creates");
    let body_first = std::fs::read_to_string(dir.join(".meta.yaml")).unwrap();

    let second = maintainer.ensure_dir_meta(&dir, None).await.unwrap();
    assert!(!second, "second call must be a no-op");
    let body_second = std::fs::read_to_string(dir.join(".meta.yaml")).unwrap();
    assert_eq!(
        body_first, body_second,
        "idempotent — bytes must match across calls"
    );
}

// SC-T25b: ensure_dir_meta with Some(parent) writes child + parent meta.
#[tokio::test]
async fn sc_t25b_ensure_dir_meta_with_parent_writes_both() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let parent = tempdir.path().join("research");
    let child = parent.join("topic-a");
    std::fs::create_dir_all(&child).unwrap();

    let maintainer = maintainer_for(tempdir.path());
    let created = maintainer
        .ensure_dir_meta(&child, Some(&parent))
        .await
        .unwrap();
    assert!(created, "child .meta.yaml created on first call");

    // Both child and parent .meta.yaml should exist.
    assert!(
        child.join(".meta.yaml").exists(),
        "child .meta.yaml present"
    );
    assert!(
        parent.join(".meta.yaml").exists(),
        "parent .meta.yaml present"
    );

    // Parent's .meta.yaml lists topic-a as an entry with is_dir = true.
    let parent_body = std::fs::read_to_string(parent.join(".meta.yaml")).unwrap();
    assert!(
        parent_body.contains("topic-a"),
        "parent must list topic-a entry"
    );
    assert!(
        parent_body.contains("is_dir"),
        "parent's topic-a entry must include is_dir flag"
    );
}

// SC-T25c: ensure_dir_meta retry-after-partial-failure repairs missing parent
// entry without rewriting the child. Exercises the AC-03 idempotency contract
// for the M005 spawn-child path (Codex audit Round 1 C1 closure).
#[tokio::test]
async fn sc_t25c_ensure_dir_meta_repairs_partial_failure() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let parent = tempdir.path().join("research");
    let child = parent.join("topic-a");
    std::fs::create_dir_all(&child).unwrap();

    let maintainer = maintainer_for(tempdir.path());

    // Simulate partial failure: write the child .meta.yaml only — leaving the
    // parent's .meta.yaml absent (the partial-failure state where step 1
    // succeeded but step 2 crashed).
    let first_called = maintainer.ensure_dir_meta(&child, None).await.unwrap();
    assert!(first_called, "child meta initially created");
    assert!(
        !parent.join(".meta.yaml").exists(),
        "parent meta absent (simulated partial failure)"
    );

    let child_body_pre = std::fs::read_to_string(child.join(".meta.yaml")).unwrap();

    // Second call WITH parent — should NOT overwrite child but SHOULD now
    // bootstrap parent meta + add the topic-a entry.
    let returned = maintainer
        .ensure_dir_meta(&child, Some(&parent))
        .await
        .unwrap();
    assert!(
        !returned,
        "second call returns false (child already existed)"
    );

    // Child preserved byte-for-byte.
    let child_body_post = std::fs::read_to_string(child.join(".meta.yaml")).unwrap();
    assert_eq!(
        child_body_pre, child_body_post,
        "child .meta.yaml unchanged on retry"
    );

    // Parent meta now exists and lists topic-a.
    assert!(
        parent.join(".meta.yaml").exists(),
        "parent .meta.yaml created on retry"
    );
    let parent_body = std::fs::read_to_string(parent.join(".meta.yaml")).unwrap();
    assert!(
        parent_body.contains("topic-a"),
        "parent .meta.yaml lists child entry after retry"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// AC-12: triple consistency on fs.write / fs.delete.
// ─────────────────────────────────────────────────────────────────────────────

struct WriteFixture {
    _tempdir: tempfile::TempDir,
    agent_workspace: std::path::PathBuf,
    handler: FsWriteHandler,
    emitter: Arc<TestEmitter>,
    db_mock: Arc<MockSqliteSync>,
}

fn write_fixture(agent_id: &str, fail_on: Option<usize>) -> WriteFixture {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join(agent_id);
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let tree = Arc::new(single_agent_tree(agent_id, agent_workspace.clone()))
        as Arc<dyn AgentTreeSnapshot>;
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::clone(&tree),
    ));
    let emitter = Arc::new(TestEmitter::new());
    let mock = Arc::new(match fail_on {
        Some(n) => MockSqliteSync::fail_on(n),
        None => MockSqliteSync::new(),
    });
    let handler = FsWriteHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: maintainer_for(tempdir.path()),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: Some(Arc::clone(&mock) as Arc<dyn SqliteSync>),
        workspace_root: Some(workspace_root),
        agent_tree: Some(Arc::clone(&tree)),
        git_sync: None,
    };
    WriteFixture {
        _tempdir: tempdir,
        agent_workspace,
        handler,
        emitter,
        db_mock: mock,
    }
}

// SC-T26: text fs.write upserts content_index + meta_index in real DB handle.
#[tokio::test]
async fn sc_t26_write_text_upserts_content_and_meta_real_db() {
    let agent_id = "agent-1";
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join(agent_id);
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let tree = Arc::new(single_agent_tree(agent_id, agent_workspace.clone()))
        as Arc<dyn AgentTreeSnapshot>;
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::clone(&tree),
    ));
    let emitter = Arc::new(TestEmitter::new());

    let (sync, handle) = build_real_db_sync();
    let handler = FsWriteHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: maintainer_for(tempdir.path()),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: Some(Arc::clone(&sync)),
        workspace_root: Some(workspace_root.clone()),
        agent_tree: Some(Arc::clone(&tree)),
        git_sync: None,
    };

    let body: Vec<Val> = b"hello slice c".iter().copied().map(Val::U8).collect();
    let out = handler
        .call(
            ctx_for(agent_id),
            vec![Val::String("notes.md".into()), Val::List(body)],
            1,
        )
        .await
        .unwrap();
    unwrap_ok_none(out);

    // Inspect rows directly via the handle.
    let conn = handle.get_conn().unwrap();
    let agent_m004 = "agent-1"; // single-level relative path under root
    let preview: String = conn
        .query_row(
            "SELECT content_preview FROM content_index WHERE agent_id = ?1 AND file_path = ?2",
            rusqlite::params![agent_m004, "/agent-1/notes.md"],
            |r| r.get(0),
        )
        .expect("content row present");
    assert_eq!(preview, "hello slice c");

    let entry: String = conn
        .query_row(
            "SELECT entry_name FROM meta_index WHERE agent_id = ?1 AND directory = ?2",
            rusqlite::params![agent_m004, "/agent-1"],
            |r| r.get(0),
        )
        .expect("meta row present");
    assert_eq!(entry, "notes.md");
}

// SC-T26b: binary fs.write skips content_index but still writes meta_index.
#[tokio::test]
async fn sc_t26b_write_binary_skips_content_index() {
    let agent_id = "agent-1";
    let f = write_fixture(agent_id, None);

    // 0xFF is invalid as a leading UTF-8 byte → is_text_for_sql_index = false.
    let body: Vec<Val> = [0xFFu8, 0xD8, 0xFF, 0xE0]
        .iter()
        .copied()
        .map(Val::U8)
        .collect();
    let out = f
        .handler
        .call(
            ctx_for(agent_id),
            vec![Val::String("image.bin".into()), Val::List(body)],
            1,
        )
        .await
        .unwrap();
    unwrap_ok_none(out);

    // Only upsert_meta should have been called (no upsert_content for binary).
    let calls = f.db_mock.snapshot();
    assert_eq!(calls.len(), 1, "expected exactly 1 SQL call (meta only)");
    assert!(
        matches!(&calls[0], SqlSyncCall::UpsertMeta { .. }),
        "expected UpsertMeta, got {:?}",
        calls[0]
    );

    // Triple-consistency invariant still holds: file + .meta.yaml exist.
    assert!(f.agent_workspace.join("image.bin").exists());
    assert!(f.agent_workspace.join(".meta.yaml").exists());
}

// SC-T27: fs.delete propagates to delete_content + delete_meta.
#[tokio::test]
async fn sc_t27_delete_propagates_to_sqlite_legs() {
    let agent_id = "agent-1";
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join(agent_id);
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let tree = Arc::new(single_agent_tree(agent_id, agent_workspace.clone()))
        as Arc<dyn AgentTreeSnapshot>;
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::clone(&tree),
    ));
    let emitter = Arc::new(TestEmitter::new());
    let mock = Arc::new(MockSqliteSync::new());
    let maintainer = maintainer_for(tempdir.path());

    // Pre-populate: write the file via the write handler so .meta.yaml is set up.
    let write_handler = FsWriteHandler {
        resolver: Arc::clone(&resolver) as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: Arc::clone(&maintainer),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: Some(Arc::clone(&mock) as Arc<dyn SqliteSync>),
        workspace_root: Some(workspace_root.clone()),
        agent_tree: Some(Arc::clone(&tree)),
        git_sync: None,
    };
    let body: Vec<Val> = b"x".iter().copied().map(Val::U8).collect();
    let _ = write_handler
        .call(
            ctx_for(agent_id),
            vec![Val::String("a.txt".into()), Val::List(body)],
            1,
        )
        .await
        .unwrap();

    let pre_calls = mock.snapshot();
    assert!(pre_calls
        .iter()
        .any(|c| matches!(c, SqlSyncCall::UpsertContent { .. })));

    // Delete via the delete handler.
    let delete_handler = FsDeleteHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer,
        db_sync: Some(Arc::clone(&mock) as Arc<dyn SqliteSync>),
        workspace_root: Some(workspace_root.clone()),
        agent_tree: Some(Arc::clone(&tree)),
        git_sync: None,
    };
    let out = delete_handler
        .call(ctx_for(agent_id), vec![Val::String("a.txt".into())], 1)
        .await
        .unwrap();
    unwrap_ok_none(out);

    let calls = mock.snapshot();
    let has_delete_content = calls
        .iter()
        .any(|c| matches!(c, SqlSyncCall::DeleteContent { .. }));
    let has_delete_meta = calls
        .iter()
        .any(|c| matches!(c, SqlSyncCall::DeleteMeta { .. }));
    assert!(has_delete_content, "delete_content was not called");
    assert!(has_delete_meta, "delete_meta was not called");
}

// SC-T28: SQL leg failure emits runtime.degraded.sqlite_sync_failed but write returns Ok.
#[tokio::test]
async fn sc_t28_sql_failure_emits_runtime_degraded_event() {
    let agent_id = "agent-1";
    // Fail on the first SQL call (upsert_content for text).
    let f = write_fixture(agent_id, Some(1));

    let body: Vec<Val> = b"hello".iter().copied().map(Val::U8).collect();
    let out = f
        .handler
        .call(
            ctx_for(agent_id),
            vec![Val::String("notes.md".into()), Val::List(body)],
            1,
        )
        .await
        .unwrap();
    // fs.write returns Ok even when SQL leg fails — the FS source-of-truth
    // is committed first, the SQL leg is best-effort.
    unwrap_ok_none(out);

    // file + .meta.yaml are committed regardless.
    assert!(f.agent_workspace.join("notes.md").exists());
    assert!(f.agent_workspace.join(".meta.yaml").exists());

    let evs = f.emitter.snapshot();
    assert!(
        evs.iter()
            .any(|e| e.event_type == "runtime.degraded.sqlite_sync_failed"),
        "expected runtime.degraded.sqlite_sync_failed event, got {:?}",
        evs.iter().map(|e| &e.event_type).collect::<Vec<_>>()
    );
    // fs.write event is still emitted since FS commit succeeded.
    assert!(evs.iter().any(|e| e.event_type == "fs.write"));
}

// SC-T29: db_sync=None preserves slice A/B compat — no SQL leg, no panic.
#[tokio::test]
async fn sc_t29_db_sync_none_skips_sql_leg() {
    let agent_id = "agent-1";
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join(agent_id);
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let tree = Arc::new(single_agent_tree(agent_id, agent_workspace.clone()))
        as Arc<dyn AgentTreeSnapshot>;
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::clone(&tree),
    ));
    let emitter = Arc::new(TestEmitter::new());

    let handler = FsWriteHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: maintainer_for(tempdir.path()),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: None,
    };

    let body: Vec<Val> = b"hi".iter().copied().map(Val::U8).collect();
    let out = handler
        .call(
            ctx_for(agent_id),
            vec![Val::String("a.txt".into()), Val::List(body)],
            1,
        )
        .await
        .unwrap();
    unwrap_ok_none(out);

    let evs = emitter.snapshot();
    // No runtime.degraded events — SQL leg silently skipped.
    assert!(
        !evs.iter()
            .any(|e| e.event_type.starts_with("runtime.degraded.")),
        "no runtime.degraded events expected, got {:?}",
        evs.iter().map(|e| &e.event_type).collect::<Vec<_>>()
    );
}

// SC-T30: event ordering — SQL leg runs before fs.write event emission.
#[tokio::test]
async fn sc_t30_sql_runs_before_event_emission() {
    let agent_id = "agent-1";
    // Force SQL failure so we observe the runtime.degraded event, then verify
    // that fs.write event comes AFTER it (SQL leg runs strictly before event emission).
    let f = write_fixture(agent_id, Some(1));

    let body: Vec<Val> = b"abc".iter().copied().map(Val::U8).collect();
    let _ = f
        .handler
        .call(
            ctx_for(agent_id),
            vec![Val::String("notes.md".into()), Val::List(body)],
            1,
        )
        .await
        .unwrap();

    let evs = f.emitter.snapshot();
    let degraded_idx = evs
        .iter()
        .position(|e| e.event_type == "runtime.degraded.sqlite_sync_failed")
        .expect("degraded event present");
    let write_idx = evs
        .iter()
        .position(|e| e.event_type == "fs.write")
        .expect("fs.write event present");
    assert!(
        degraded_idx < write_idx,
        "expected runtime.degraded BEFORE fs.write (degraded={degraded_idx}, write={write_idx})"
    );
}

// SC-T30b: agent_id normalization for nested workspace paths.
#[tokio::test]
async fn sc_t30b_agent_id_normalization_for_nested_workspace() {
    // Place agent at workspace_root/team-a/researcher → expect agent_id "team-a/researcher".
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_id = "researcher";
    let agent_workspace = workspace_root.join("team-a/researcher");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let tree = Arc::new(single_agent_tree(agent_id, agent_workspace.clone()))
        as Arc<dyn AgentTreeSnapshot>;
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::clone(&tree),
    ));
    let emitter = Arc::new(TestEmitter::new());
    let mock = Arc::new(MockSqliteSync::new());

    let handler = FsWriteHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: maintainer_for(tempdir.path()),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: Some(Arc::clone(&mock) as Arc<dyn SqliteSync>),
        workspace_root: Some(workspace_root.clone()),
        agent_tree: Some(Arc::clone(&tree)),
        git_sync: None,
    };

    let body: Vec<Val> = b"x".iter().copied().map(Val::U8).collect();
    let _ = handler
        .call(
            ctx_for(agent_id),
            vec![Val::String("notes.md".into()), Val::List(body)],
            1,
        )
        .await
        .unwrap();

    let calls = mock.snapshot();
    let upsert_content = calls.iter().find_map(|c| match c {
        SqlSyncCall::UpsertContent { agent_id, .. } => Some(agent_id.clone()),
        _ => None,
    });
    assert_eq!(upsert_content.as_deref(), Some("team-a/researcher"));
}

// ─────────────────────────────────────────────────────────────────────────────
// AC-13: workspace reconciliation.
// ─────────────────────────────────────────────────────────────────────────────

fn make_reconciler(
    workspace_root: std::path::PathBuf,
    tempdir_path: &Path,
    rebuild: Option<Arc<dyn advance_database::IndexRebuild>>,
    emitter: Arc<dyn EventBusEmit>,
) -> WorkspaceReconciler {
    let schema = schema_loader_for(tempdir_path);
    let maintainer = Arc::new(MetaMaintainer::new(
        Arc::clone(&schema),
        Arc::new(DefaultAtomicWriter),
    ));
    WorkspaceReconciler::new(workspace_root, schema, maintainer, rebuild, emitter)
}

// SC-T31: reconciler creates missing .meta.yaml in workspace dirs.
#[tokio::test]
async fn sc_t31_reconciler_creates_missing_meta_yaml() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let ws = tempdir.path().to_path_buf();
    std::fs::create_dir_all(ws.join("research")).unwrap();
    std::fs::create_dir_all(ws.join("notes")).unwrap();

    let emitter = Arc::new(TestEmitter::new());
    let reconciler = make_reconciler(
        ws.clone(),
        tempdir.path(),
        None,
        emitter.clone() as Arc<dyn EventBusEmit>,
    );

    let report = reconciler.reconcile("/", "trace-1").await.unwrap();
    assert!(
        report.meta_yaml_created >= 3,
        "expected 3 dirs (root + research + notes) had meta created, got {}",
        report.meta_yaml_created
    );
    assert!(ws.join(".meta.yaml").exists());
    assert!(ws.join("research/.meta.yaml").exists());
    assert!(ws.join("notes/.meta.yaml").exists());
}

// SC-T32: reconciler adds disk-only entries into existing .meta.yaml.
#[tokio::test]
async fn sc_t32_reconciler_adds_disk_only_entries() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let ws = tempdir.path().to_path_buf();
    let dir = ws.join("research");
    std::fs::create_dir_all(&dir).unwrap();
    // Pre-create the directory's .meta.yaml without listing the on-disk file.
    let maintainer = maintainer_for(tempdir.path());
    maintainer.ensure_dir_meta(&dir, None).await.unwrap();
    // Add a file on disk that's not in the meta yet.
    std::fs::write(dir.join("findings.md"), b"hello").unwrap();

    let emitter = Arc::new(TestEmitter::new());
    let reconciler = make_reconciler(
        ws.clone(),
        tempdir.path(),
        None,
        emitter.clone() as Arc<dyn EventBusEmit>,
    );
    let report = reconciler.reconcile("/", "trace-2").await.unwrap();
    assert!(report.entries_added >= 1, "expected ≥1 entry added");

    let meta = std::fs::read_to_string(dir.join(".meta.yaml")).unwrap();
    assert!(
        meta.contains("findings.md"),
        ".meta.yaml must list findings.md"
    );
}

// SC-T33: reconciler removes meta entries for files no longer on disk.
#[tokio::test]
async fn sc_t33_reconciler_removes_meta_only_entries() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let ws = tempdir.path().to_path_buf();
    let dir = ws.join("research");
    std::fs::create_dir_all(&dir).unwrap();

    let maintainer = maintainer_for(tempdir.path());
    // Stage: write a file → meta now lists it. Then delete the file on disk
    // (without going through fs.delete) to simulate drift.
    std::fs::write(dir.join("ghost.md"), b"x").unwrap();
    let load = maintainer.load(&dir).await.unwrap().unwrap_or_default();
    let (next, _) = maintainer
        .add_entry_for_write(Some(load), "ghost.md", b"x")
        .unwrap();
    maintainer.write(&dir, &next).await.unwrap();
    std::fs::remove_file(dir.join("ghost.md")).unwrap();
    assert!(!dir.join("ghost.md").exists());

    let emitter = Arc::new(TestEmitter::new());
    let reconciler = make_reconciler(
        ws.clone(),
        tempdir.path(),
        None,
        emitter.clone() as Arc<dyn EventBusEmit>,
    );
    let report = reconciler.reconcile("/", "trace-3").await.unwrap();
    assert!(report.entries_removed >= 1, "expected ≥1 entry removed");

    let meta = std::fs::read_to_string(dir.join(".meta.yaml")).unwrap();
    assert!(
        !meta.contains("ghost.md"),
        ".meta.yaml must no longer list ghost.md"
    );
}

// SC-T34: reconciler repairs empty required fields on existing entries.
#[tokio::test]
async fn sc_t34_reconciler_repairs_empty_required_fields() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let ws = tempdir.path().to_path_buf();
    let dir = ws.join("research");
    std::fs::create_dir_all(&dir).unwrap();

    // Write a .meta.yaml with an empty description on the entry — directly,
    // bypassing the maintainer's validation, simulating drift from an earlier
    // schema or a hand-edit.
    std::fs::write(dir.join("notes.md"), b"hello").unwrap();
    let yaml = "_scope:\n  description: \"[pending] research\"\nnotes.md:\n  name: notes.md\n  slug: notes\n  description: \"\"\n";
    std::fs::write(dir.join(".meta.yaml"), yaml).unwrap();

    let emitter = Arc::new(TestEmitter::new());
    let reconciler = make_reconciler(
        ws.clone(),
        tempdir.path(),
        None,
        emitter.clone() as Arc<dyn EventBusEmit>,
    );
    let report = reconciler.reconcile("/", "trace-4").await.unwrap();
    assert!(
        report.fields_repaired >= 1,
        "expected ≥1 field repaired, got {}",
        report.fields_repaired
    );

    let meta = std::fs::read_to_string(dir.join(".meta.yaml")).unwrap();
    assert!(
        meta.contains("[pending]"),
        "description should be repaired with [pending] fallback"
    );
}

// SC-T35: reconciler invokes IndexRebuild::rebuild_full when configured.
#[tokio::test]
async fn sc_t35_reconciler_invokes_index_rebuild() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let ws = tempdir.path().to_path_buf();
    std::fs::create_dir_all(ws.join("research")).unwrap();

    let canned = advance_database::RebuildReport {
        meta_rows: 5,
        content_rows: 3,
        embed_calls: 2,
        elapsed_ms: 42,
        ..Default::default()
    };
    let rebuild = Arc::new(MockIndexRebuild::new(canned));
    let emitter = Arc::new(TestEmitter::new());
    let reconciler = make_reconciler(
        ws.clone(),
        tempdir.path(),
        Some(Arc::clone(&rebuild) as Arc<dyn advance_database::IndexRebuild>),
        emitter.clone() as Arc<dyn EventBusEmit>,
    );
    let report = reconciler.reconcile("/", "trace-5").await.unwrap();

    let calls = rebuild.calls.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(calls, 1, "rebuild_full must be called exactly once");
    let rb = report
        .rebuild_report
        .as_ref()
        .expect("rebuild_report must be Some");
    assert_eq!(rb.meta_rows, 5);
    assert_eq!(rb.content_rows, 3);
}

// SC-T36: reconciler skips hidden dirs (.git/.runtime/.advance/.sub/.agent + sqlite).
#[tokio::test]
async fn sc_t36_reconciler_skips_hidden_dirs_and_sqlite() {
    // Direct unit-level coverage of the unified predicate.
    for name in [".git", ".runtime", ".advance", ".sub", ".agent"] {
        assert!(
            is_reconciler_skipped_name(name),
            "{name} must be in the skip-set"
        );
    }
    for name in [
        "index.sqlite",
        "x.sqlite-wal",
        "x.sqlite-shm",
        "x.sqlite-journal",
    ] {
        assert!(is_reconciler_skipped_name(name));
    }
    for name in ["notes.md", "research", ".gitignore", ".agent-templates"] {
        assert!(
            !is_reconciler_skipped_name(name),
            "{name} must NOT be skipped"
        );
    }

    // Integration: hidden dir contents must not produce .meta.yaml.
    let tempdir = tempfile::TempDir::new().unwrap();
    let ws = tempdir.path().to_path_buf();
    std::fs::create_dir_all(ws.join(".git/objects")).unwrap();
    std::fs::create_dir_all(ws.join(".runtime/cache")).unwrap();
    std::fs::create_dir_all(ws.join("notes")).unwrap();

    let emitter = Arc::new(TestEmitter::new());
    let reconciler = make_reconciler(
        ws.clone(),
        tempdir.path(),
        None,
        emitter.clone() as Arc<dyn EventBusEmit>,
    );
    let _ = reconciler.reconcile("/", "trace-6").await.unwrap();

    assert!(
        !ws.join(".git/.meta.yaml").exists(),
        ".git/.meta.yaml must NOT be created"
    );
    assert!(
        !ws.join(".git/objects/.meta.yaml").exists(),
        ".git/objects/.meta.yaml must NOT be created"
    );
    assert!(
        !ws.join(".runtime/.meta.yaml").exists(),
        ".runtime/.meta.yaml must NOT be created"
    );
    assert!(
        ws.join("notes/.meta.yaml").exists(),
        "regular dirs still get .meta.yaml"
    );
}

// SC-T37: reconciler emits FsEvent::ReconcileCompleted with full payload.
#[tokio::test]
async fn sc_t37_reconciler_emits_reconcile_completed_event() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let ws = tempdir.path().to_path_buf();
    std::fs::create_dir_all(ws.join("research")).unwrap();

    let canned = advance_database::RebuildReport {
        meta_rows: 7,
        content_rows: 11,
        embed_calls: 0,
        elapsed_ms: 5,
        ..Default::default()
    };
    let rebuild = Arc::new(MockIndexRebuild::new(canned));
    let emitter = Arc::new(TestEmitter::new());
    let reconciler = make_reconciler(
        ws.clone(),
        tempdir.path(),
        Some(Arc::clone(&rebuild) as Arc<dyn advance_database::IndexRebuild>),
        emitter.clone() as Arc<dyn EventBusEmit>,
    );
    let _: ReconcileReport = reconciler.reconcile("agent-7", "trace-7").await.unwrap();

    let evs = emitter.snapshot();
    let ev = evs
        .iter()
        .find(|e| e.event_type == "fs.reconcile_completed")
        .expect("ReconcileCompleted event must be emitted");
    assert_eq!(ev.agent_id, "agent-7");
    assert_eq!(ev.trace_id, "trace-7");

    let payload = &ev.payload["ReconcileCompleted"];
    assert!(payload["dirs_scanned"].as_u64().unwrap() >= 2);
    assert!(payload["meta_yaml_created"].as_u64().unwrap() >= 2);
    let summary = &payload["rebuild_report_summary"];
    assert_eq!(summary["meta_rows"].as_u64().unwrap(), 7);
    assert_eq!(summary["content_rows"].as_u64().unwrap(), 11);
}

// SC-T37b (MODULE-002-T51, stage-B 2026-06-15): reconciler emits
// `runtime.index_rebuild { total_files, total_dirs }` on the successful-rebuild
// branch — total_files == M004 rebuild `content_rows`, total_dirs == the reconcile
// pass's `dirs_scanned` — and does NOT emit it when no IndexRebuild is configured
// (the signal is gated on the rebuild branch). Corroborates SYS-AC-147 at module level.
#[tokio::test]
async fn sc_t37b_reconciler_emits_runtime_index_rebuild_event() {
    // Positive: rebuild configured → runtime.index_rebuild carries the rebuild volume.
    let tempdir = tempfile::TempDir::new().unwrap();
    let ws = tempdir.path().to_path_buf();
    std::fs::create_dir_all(ws.join("research")).unwrap();

    let canned = advance_database::RebuildReport {
        meta_rows: 7,
        content_rows: 11,
        embed_calls: 0,
        elapsed_ms: 5,
        ..Default::default()
    };
    let rebuild = Arc::new(MockIndexRebuild::new(canned));
    let emitter = Arc::new(TestEmitter::new());
    let reconciler = make_reconciler(
        ws.clone(),
        tempdir.path(),
        Some(Arc::clone(&rebuild) as Arc<dyn advance_database::IndexRebuild>),
        emitter.clone() as Arc<dyn EventBusEmit>,
    );
    let report: ReconcileReport = reconciler.reconcile("agent-51", "trace-51").await.unwrap();

    let evs = emitter.snapshot();
    let ev = evs
        .iter()
        .find(|e| e.event_type == "runtime.index_rebuild")
        .expect("runtime.index_rebuild event must be emitted on the rebuild branch");
    assert_eq!(ev.agent_id, "agent-51");
    assert_eq!(ev.trace_id, "trace-51");
    assert_eq!(
        ev.payload["total_files"].as_u64().unwrap(),
        11,
        "total_files == M004 rebuild content_rows"
    );
    assert_eq!(
        ev.payload["total_dirs"].as_u64().unwrap(),
        report.dirs_scanned,
        "total_dirs == reconcile pass dirs_scanned"
    );
    assert!(
        report.dirs_scanned >= 2,
        "workspace_root + research/ scanned"
    );

    // Negative: no IndexRebuild configured → NO runtime.index_rebuild event.
    let tempdir2 = tempfile::TempDir::new().unwrap();
    let ws2 = tempdir2.path().to_path_buf();
    std::fs::create_dir_all(ws2.join("notes")).unwrap();
    let emitter2 = Arc::new(TestEmitter::new());
    let reconciler2 = make_reconciler(
        ws2.clone(),
        tempdir2.path(),
        None,
        emitter2.clone() as Arc<dyn EventBusEmit>,
    );
    let _ = reconciler2
        .reconcile("agent-51b", "trace-51b")
        .await
        .unwrap();
    assert!(
        !emitter2
            .snapshot()
            .iter()
            .any(|e| e.event_type == "runtime.index_rebuild"),
        "no runtime.index_rebuild without a configured IndexRebuild"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// AC-17: workspace root .meta.yaml as the single metadata index tree root.
// ─────────────────────────────────────────────────────────────────────────────

// SC-T38: reconciler always populates workspace_root/.meta.yaml.
#[tokio::test]
async fn sc_t38_reconciler_creates_workspace_root_meta_yaml() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let ws = tempdir.path().to_path_buf();
    // Empty workspace — only the root dir.
    let emitter = Arc::new(TestEmitter::new());
    let reconciler = make_reconciler(
        ws.clone(),
        tempdir.path(),
        None,
        emitter.clone() as Arc<dyn EventBusEmit>,
    );
    let report = reconciler.reconcile("/", "trace-8").await.unwrap();

    assert!(
        ws.join(".meta.yaml").exists(),
        "workspace root .meta.yaml MUST be present after reconcile"
    );
    assert!(
        report.meta_yaml_created >= 1,
        "expected ≥1 .meta.yaml created"
    );
}

// SC-T38b: post-reconcile workspace-wide invariant — every non-skipped
// directory has EXACTLY ONE .meta.yaml, and the workspace root is the tree
// root (verified via ascending-path traversal). Strengthens AC-17 coverage
// per Test Round 1 evaluator finding.
#[tokio::test]
async fn sc_t38b_reconciler_enforces_exactly_one_meta_per_dir() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let ws = tempdir.path().to_path_buf();

    // Build a non-trivial tree: root + research/{topic-a, topic-b/subtopic} + notes
    // and one hidden subtree (.git/objects) which must NOT receive .meta.yaml.
    std::fs::create_dir_all(ws.join("research/topic-a")).unwrap();
    std::fs::create_dir_all(ws.join("research/topic-b/subtopic")).unwrap();
    std::fs::create_dir_all(ws.join("notes")).unwrap();
    std::fs::create_dir_all(ws.join(".git/objects")).unwrap();
    std::fs::write(ws.join("notes/findings.md"), b"hello").unwrap();
    std::fs::write(ws.join("research/topic-a/idea.md"), b"abc").unwrap();

    let emitter = Arc::new(TestEmitter::new());
    let reconciler = make_reconciler(
        ws.clone(),
        tempdir.path(),
        None,
        emitter.clone() as Arc<dyn EventBusEmit>,
    );
    let _ = reconciler.reconcile("/", "trace-8b").await.unwrap();

    // Expected non-skipped dirs that should each have exactly one .meta.yaml:
    let expected_dirs: Vec<std::path::PathBuf> = vec![
        ws.clone(),
        ws.join("research"),
        ws.join("research/topic-a"),
        ws.join("research/topic-b"),
        ws.join("research/topic-b/subtopic"),
        ws.join("notes"),
    ];
    for dir in &expected_dirs {
        assert!(
            dir.is_dir(),
            "test setup: {} should be a directory",
            dir.display()
        );
        let meta_path = dir.join(".meta.yaml");
        assert!(
            meta_path.is_file(),
            "AC-17 invariant: every non-skipped dir must have a .meta.yaml; missing at {}",
            dir.display()
        );
    }

    // Hidden subtree must remain untouched.
    assert!(
        !ws.join(".git/.meta.yaml").exists(),
        ".git must remain untouched"
    );
    assert!(
        !ws.join(".git/objects/.meta.yaml").exists(),
        ".git/objects must remain untouched"
    );

    // Workspace-root .meta.yaml is the single tree root: every non-skipped
    // dir is reachable by ascending parents from workspace_root, and
    // workspace_root has no parent within the test tempdir scope.
    for dir in &expected_dirs {
        let mut current: Option<&std::path::Path> = Some(dir.as_path());
        let mut found_root = false;
        while let Some(c) = current {
            if c == ws.as_path() {
                found_root = true;
                break;
            }
            current = c.parent();
        }
        assert!(
            found_root,
            "AC-17 invariant: {} must trace back to workspace root",
            dir.display()
        );
    }
}

// SC-T39: fs.delete updates parent .meta.yaml + propagates to SQL delete_meta.
#[tokio::test]
async fn sc_t39_fs_delete_updates_parent_meta_and_sql() {
    let agent_id = "agent-1";
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join(agent_id);
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let tree = Arc::new(single_agent_tree(agent_id, agent_workspace.clone()))
        as Arc<dyn AgentTreeSnapshot>;
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::clone(&tree),
    ));
    let emitter = Arc::new(TestEmitter::new());
    let mock = Arc::new(MockSqliteSync::new());
    let maintainer = maintainer_for(tempdir.path());

    // Create a file via fs.write (sets up .meta.yaml).
    let write_handler = FsWriteHandler {
        resolver: Arc::clone(&resolver) as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: Arc::clone(&maintainer),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: Some(Arc::clone(&mock) as Arc<dyn SqliteSync>),
        workspace_root: Some(workspace_root.clone()),
        agent_tree: Some(Arc::clone(&tree)),
        git_sync: None,
    };
    let body: Vec<Val> = b"abc".iter().copied().map(Val::U8).collect();
    let _ = write_handler
        .call(
            ctx_for(agent_id),
            vec![Val::String("notes.md".into()), Val::List(body)],
            1,
        )
        .await
        .unwrap();
    assert!(agent_workspace.join("notes.md").exists());
    let pre_meta = std::fs::read_to_string(agent_workspace.join(".meta.yaml")).unwrap();
    assert!(pre_meta.contains("notes.md"));

    // Now delete the file via fs.delete.
    let delete_handler = FsDeleteHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer,
        db_sync: Some(Arc::clone(&mock) as Arc<dyn SqliteSync>),
        workspace_root: Some(workspace_root.clone()),
        agent_tree: Some(Arc::clone(&tree)),
        git_sync: None,
    };
    let out = delete_handler
        .call(ctx_for(agent_id), vec![Val::String("notes.md".into())], 1)
        .await
        .unwrap();
    unwrap_ok_none(out);

    // Parent .meta.yaml is updated — entry removed.
    assert!(!agent_workspace.join("notes.md").exists());
    let post_meta = std::fs::read_to_string(agent_workspace.join(".meta.yaml")).unwrap();
    assert!(
        !post_meta.contains("notes.md"),
        ".meta.yaml must no longer list the deleted file"
    );

    // SQL delete_meta was called with the parent dir + entry name.
    let calls = mock.snapshot();
    let delete_meta_call = calls.iter().find_map(|c| match c {
        SqlSyncCall::DeleteMeta {
            agent_id,
            directory,
            entry_name,
        } => Some((agent_id.clone(), directory.clone(), entry_name.clone())),
        _ => None,
    });
    let (agent, directory, entry) = delete_meta_call.expect("DeleteMeta must be called");
    assert_eq!(agent, "agent-1");
    assert_eq!(
        directory,
        normalize_ws_path(&workspace_root, &agent_workspace)
    );
    assert_eq!(entry, "notes.md");
}

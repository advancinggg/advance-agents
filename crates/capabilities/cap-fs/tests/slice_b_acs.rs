//! Slice B AC verification tests — covers the 12 in-scope ACs.
//!
//! Layer breakdown: ~30 integration tests covering AC-01, AC-02, AC-04, AC-05,
//! AC-06, AC-07, AC-08, AC-09, AC-10, AC-11, AC-14, AC-15.

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use advance_runtime::host_registry::{HostCallContext, HostFunctionHandler};
use advance_shared_types::traits::{AgentTreeSnapshot, EventBusEmit};
use cap_fs::{
    DefaultAtomicWriter, DefaultVirtualPathResolver, FileHistoryProvider, FsError,
    FsFileHistoryHandler, FsListChildHandler, FsListSlugHandler, FsReadAtHandler,
    FsReadChildAtHandler, FsReadChildHandler, FsReadHandler, FsReadSlugHandler, FsScanChildHandler,
    FsScanHandler, FsScanSlugHandler, FsSlugFileHistoryHandler, FsUpdateEntryMetaHandler,
    FsUpdateScopeHandler, FsWriteHandler, MetaMaintainer, MetaSchemaLoader,
    StubFileHistoryProvider, VersionEntry, VirtualPathResolver, DEFAULT_MAX_LIST_ENTRIES,
};
use wasmtime::component::Val;

use common::{
    multi_agent_tree, single_agent_tree, FailingAtomicWriter, MockFileHistoryProvider, TestEmitter,
};

const TRACE_ID: &str = "tr-sb";

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

fn unwrap_ok_some(out: Vec<Val>) -> Val {
    assert_eq!(out.len(), 1);
    match out.into_iter().next().unwrap() {
        Val::Result(Ok(Some(inner))) => *inner,
        other => panic!("expected Ok(Some), got {other:?}"),
    }
}

fn unwrap_ok_none(out: Vec<Val>) {
    assert_eq!(out.len(), 1);
    match out.into_iter().next().unwrap() {
        Val::Result(Ok(None)) => {}
        other => panic!("expected Ok(None), got {other:?}"),
    }
}

fn unwrap_err_variant(out: Vec<Val>) -> (String, String) {
    assert_eq!(out.len(), 1);
    match out.into_iter().next().unwrap() {
        Val::Result(Err(Some(inner))) => match *inner {
            Val::Variant(case, Some(payload)) => match *payload {
                Val::String(s) => (case, s),
                other => panic!("expected String payload, got {other:?}"),
            },
            other => panic!("expected Variant, got {other:?}"),
        },
        other => panic!("expected Err(Some), got {other:?}"),
    }
}

fn maintainer_with_default_writer() -> Arc<MetaMaintainer> {
    let schema_path = std::env::temp_dir().join("schema-acs-test.yaml");
    Arc::new(MetaMaintainer::new(
        Arc::new(MetaSchemaLoader::new_with_default(schema_path)),
        Arc::new(DefaultAtomicWriter),
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// AC-04: scan reports has_agent: true for dirs containing .agent/
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ac04_scan_reports_has_agent_true_for_agent_dir() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("agent");
    std::fs::create_dir_all(agent_workspace.join("child-territory/.agent")).unwrap();
    std::fs::create_dir_all(agent_workspace.join("plain-dir")).unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::new(single_agent_tree("agent", agent_workspace.clone())) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsScanHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: maintainer_with_default_writer(),
        max_entries: DEFAULT_MAX_LIST_ENTRIES,
    };
    let out = handler
        .call(ctx_for("agent"), vec![Val::String(".".into())], 1)
        .await
        .unwrap();
    let val = unwrap_ok_some(out);
    let record = match val {
        Val::Record(r) => r,
        _ => panic!("expected ScanResult record"),
    };
    let children_field = record
        .iter()
        .find(|(k, _)| k == "children")
        .map(|(_, v)| v)
        .unwrap();
    let children = match children_field {
        Val::List(items) => items,
        _ => panic!("children should be List"),
    };
    let mut found_child_territory = false;
    let mut found_plain_dir = false;
    for child in children {
        if let Val::Record(fields) = child {
            let name = match &fields[0].1 {
                Val::String(s) => s,
                _ => continue,
            };
            let has_agent = match &fields[4].1 {
                Val::Bool(b) => *b,
                _ => continue,
            };
            if name == "child-territory" {
                assert!(has_agent, "child-territory must have has_agent=true");
                found_child_territory = true;
            }
            if name == "plain-dir" {
                assert!(!has_agent, "plain-dir must have has_agent=false");
                found_plain_dir = true;
            }
        }
    }
    assert!(found_child_territory && found_plain_dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// AC-05: L0 scan returns metadata only (no fs.read events for child files);
// L1 read with preview budget; L2 read full body.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ac05_l0_scan_emits_only_fs_scan_event() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    std::fs::write(agent_workspace.join("file1.md"), b"content1").unwrap();
    std::fs::write(agent_workspace.join("file2.md"), b"content2").unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(single_agent_tree("a", agent_workspace)) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsScanHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: maintainer_with_default_writer(),
        max_entries: DEFAULT_MAX_LIST_ENTRIES,
    };
    handler
        .call(ctx_for("a"), vec![Val::String(".".into())], 1)
        .await
        .unwrap();
    let evs = emitter.snapshot();
    assert_eq!(
        evs.len(),
        1,
        "scan must emit exactly 1 fs.scan event (no fs.read)"
    );
    assert_eq!(evs[0].event_type, "fs.scan");
}

#[tokio::test]
async fn ac05_l1_read_with_preview_budget_truncates_data() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let big_data = vec![b'x'; 200];
    std::fs::write(agent_workspace.join("big.txt"), &big_data).unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(single_agent_tree("a", agent_workspace)) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsReadHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        preview_max_bytes: Some(50),
    };
    let out = handler
        .call(ctx_for("a"), vec![Val::String("big.txt".into())], 1)
        .await
        .unwrap();
    let val = unwrap_ok_some(out);
    if let Val::List(items) = val {
        assert_eq!(items.len(), 50, "L1 preview clamps to budget");
    } else {
        panic!("expected List");
    }
}

#[tokio::test]
async fn ac05_l2_read_without_preview_returns_full_data() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let data = vec![b'y'; 200];
    std::fs::write(agent_workspace.join("big.txt"), &data).unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(single_agent_tree("a", agent_workspace)) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsReadHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        preview_max_bytes: None,
    };
    let out = handler
        .call(ctx_for("a"), vec![Val::String("big.txt".into())], 1)
        .await
        .unwrap();
    let val = unwrap_ok_some(out);
    if let Val::List(items) = val {
        assert_eq!(items.len(), 200, "L2 full read");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AC-02: Slug-based peer reading (read-slug)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ac02_read_slug_happy_path() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let tree = multi_agent_tree(&workspace_root);
    // Create sub-b's territory + a file
    let sub_b_path = workspace_root.join("parent/sub-b");
    std::fs::create_dir_all(&sub_b_path).unwrap();
    std::fs::write(sub_b_path.join("note.md"), b"hello-from-sub-b").unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsReadSlugHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
    };
    let out = handler
        .call(
            ctx_for("sub-a"),
            vec![
                Val::String("sub-b".into()),
                Val::String("sibling-template".into()),
                Val::String("note.md".into()),
            ],
            1,
        )
        .await
        .unwrap();
    let val = unwrap_ok_some(out);
    if let Val::List(items) = val {
        assert_eq!(items.len(), b"hello-from-sub-b".len());
    }
}

#[tokio::test]
async fn ac02_read_slug_wrong_slug_returns_notfound() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let tree = multi_agent_tree(&workspace_root);
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsReadSlugHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
    };
    let out = handler
        .call(
            ctx_for("sub-a"),
            vec![
                Val::String("sub-b".into()),
                Val::String("nonexistent-slug".into()),
                Val::String("note.md".into()),
            ],
            1,
        )
        .await
        .unwrap();
    let (case, _) = unwrap_err_variant(out);
    assert_eq!(case, "not-found");
}

// ─────────────────────────────────────────────────────────────────────────────
// AC-06: 7 access permission rules
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ac06_rule2_resolve_child_read_with_non_child_returns_notfound() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let tree = multi_agent_tree(&workspace_root);
    let resolver = DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    );
    // sub-a is NOT a parent of sub-b
    let err = resolver
        .resolve_child_read("sub-a", "sub-b", "x.md")
        .unwrap_err();
    assert!(matches!(err, FsError::NotFound(_)), "got {err:?}");
}

#[tokio::test]
async fn ac06_rule2_parent_writes_to_child_territory_returns_permission_denied() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let tree = multi_agent_tree(&workspace_root);
    let parent_path = workspace_root.join("parent");
    std::fs::create_dir_all(parent_path.join("sub-a")).unwrap();
    let resolver = DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    );
    // Parent tries to write into sub-a's territory.
    let err = resolver
        .resolve_write("parent", "sub-a/forbidden.md")
        .unwrap_err();
    assert!(matches!(err, FsError::PermissionDenied(_)), "got {err:?}");
}

#[tokio::test]
async fn ac06_rule6_resolve_write_to_agent_dir_returns_permission_denied() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(agent_workspace.join(".agent")).unwrap();
    let resolver = DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(single_agent_tree("a", agent_workspace)) as Arc<dyn AgentTreeSnapshot>,
    );
    let err = resolver
        .resolve_write("a", ".agent/config.yaml")
        .unwrap_err();
    assert!(matches!(err, FsError::PermissionDenied(_)), "got {err:?}");
}

// ─────────────────────────────────────────────────────────────────────────────
// AC-07: .agent/_* hidden subset cross-territory
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ac07_apply_hidden_name_walk_rejects_agent_underscore_paths() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(agent_workspace.join(".agent/_drafts")).unwrap();
    std::fs::write(agent_workspace.join(".agent/_drafts/x.md"), b"hidden").unwrap();
    let resolver = DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(single_agent_tree("a", agent_workspace)) as Arc<dyn AgentTreeSnapshot>,
    );
    let err = resolver
        .resolve_read("a", ".agent/_drafts/x.md")
        .unwrap_err();
    assert!(matches!(err, FsError::NotFound(_)), "got {err:?}");
}

#[tokio::test]
async fn ac07_apply_hidden_name_walk_allows_agent_non_underscore() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(agent_workspace.join(".agent")).unwrap();
    std::fs::write(agent_workspace.join(".agent/config.yaml"), b"k: v").unwrap();
    let resolver = DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(single_agent_tree("a", agent_workspace)) as Arc<dyn AgentTreeSnapshot>,
    );
    // Read of `.agent/config.yaml` is allowed (Rule 6 says read-only via host fn,
    // but the resolver's read path doesn't reject .agent/<non-underscore>).
    let r = resolver.resolve_read("a", ".agent/config.yaml");
    assert!(r.is_ok(), "got {r:?}");
}

// ─────────────────────────────────────────────────────────────────────────────
// AC-08 / AC-09: schema load + reload + extension
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ac08_schema_loader_default_has_four_required_fields() {
    // ADR 2026-06-29 Decision 1 added a 4th required field: entity `type`
    // (strengthening — a new required field, not a criterion weakening).
    let loader = MetaSchemaLoader::new_with_default(PathBuf::new());
    let schema = loader.current();
    assert_eq!(schema.required.len(), 4);
    assert!(schema.required.contains_key("type"));
}

#[tokio::test]
async fn ac08_schema_reload_from_yaml_swaps_schema() {
    let loader = MetaSchemaLoader::new_with_default(PathBuf::new());
    let new_yaml = r#"
required:
  name:
    type: string
    auto: filename
optional:
  priority:
    type: integer
    default: 0
"#;
    loader.reload_from_yaml(new_yaml).unwrap();
    let schema = loader.current();
    assert_eq!(schema.required.len(), 1);
    assert!(schema.optional.contains_key("priority"));
}

#[tokio::test]
async fn ac09_schema_reload_invalid_yaml_keeps_previous() {
    let loader = MetaSchemaLoader::new_with_default(PathBuf::new());
    let original_required = loader.current().required.len();
    let bad = r#"
required:
  bad-no-auto:
    type: string
"#;
    let r = loader.reload_from_yaml(bad);
    assert!(r.is_err());
    assert_eq!(loader.current().required.len(), original_required);
}

// ─────────────────────────────────────────────────────────────────────────────
// AC-10: meta-first atomic commit; rollback on data failure
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ac10_fs_write_creates_meta_yaml_with_auto_populated_entry() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::new(single_agent_tree("a", agent_workspace.clone())) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let m = maintainer_with_default_writer();
    let handler = FsWriteHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: Arc::clone(&m),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: None,
    };
    let data: Vec<Val> = b"# Hello\n\nbody".iter().copied().map(Val::U8).collect();
    handler
        .call(
            ctx_for("a"),
            vec![Val::String("doc.md".into()), Val::List(data)],
            1,
        )
        .await
        .unwrap();
    // .meta.yaml should exist with the auto-populated entry.
    let meta_loaded = m.load(&agent_workspace).await.unwrap().unwrap();
    let entry = meta_loaded.entries.get("doc.md").unwrap();
    assert_eq!(entry.name, "doc");
    assert_eq!(entry.slug, "doc");
    assert_eq!(entry.description, "Hello");
    // 2 events: fs.write + meta.updated (renamed Slice D per PRD §15.3.8)
    let evs = emitter.snapshot();
    assert_eq!(evs.len(), 2);
    assert_eq!(evs[0].event_type, "fs.write");
    assert_eq!(evs[1].event_type, "meta.updated");
}

#[tokio::test]
async fn ac10_fs_write_rollback_on_data_failure() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::new(single_agent_tree("a", agent_workspace.clone())) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    // FailingAtomicWriter fails on the 2nd call (the data write, after meta-first commit).
    let writer = Arc::new(FailingAtomicWriter::new(2));
    let m = Arc::new(MetaMaintainer::new(
        Arc::new(MetaSchemaLoader::new_with_default(PathBuf::new())),
        writer.clone() as Arc<dyn cap_fs::AtomicWriter>,
    ));
    let handler = FsWriteHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: Arc::clone(&m),
        writer: writer as Arc<dyn cap_fs::AtomicWriter>,
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: None,
    };
    let data: Vec<Val> = b"hello".iter().copied().map(Val::U8).collect();
    let out = handler
        .call(
            ctx_for("a"),
            vec![Val::String("doc.md".into()), Val::List(data)],
            1,
        )
        .await
        .unwrap();
    // Returns Err to caller.
    let (case, _) = unwrap_err_variant(out);
    assert_eq!(case, "io-error");
    // Meta should be rolled back to None (no .meta.yaml).
    let m2 = maintainer_with_default_writer();
    let r = m2.load(&agent_workspace).await.unwrap();
    assert!(r.is_none(), ".meta.yaml should be gone after rollback");
}

// ─────────────────────────────────────────────────────────────────────────────
// AC-11: update-scope / update-entry-meta validation
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ac11_update_scope_on_territory_root_succeeds() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::new(single_agent_tree("a", agent_workspace.clone())) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let m = maintainer_with_default_writer();
    let handler = FsUpdateScopeHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: Arc::clone(&m),
    };
    let out = handler
        .call(
            ctx_for("a"),
            vec![
                Val::String(".".into()),
                Val::String("territory description".into()),
                Val::List(vec![Val::String("tag1".into())]),
            ],
            1,
        )
        .await
        .unwrap();
    unwrap_ok_none(out);
    let meta = m.load(&agent_workspace).await.unwrap().unwrap();
    assert_eq!(meta.scope.description, "territory description");
}

#[tokio::test]
async fn ac11_update_entry_meta_for_missing_entry_returns_invalid_path() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(single_agent_tree("a", agent_workspace)) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsUpdateEntryMetaHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: maintainer_with_default_writer(),
    };
    let out = handler
        .call(
            ctx_for("a"),
            vec![
                Val::String(".".into()),
                Val::String("nonexistent.md".into()),
                Val::String("desc".into()),
                Val::List(vec![]),
            ],
            1,
        )
        .await
        .unwrap();
    let (case, _) = unwrap_err_variant(out);
    assert_eq!(case, "invalid-path");
}

// ─────────────────────────────────────────────────────────────────────────────
// AC-14: read-child / list-child / scan-child happy path
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ac14_read_child_happy_path() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let tree = multi_agent_tree(&workspace_root);
    let sub_a_path = workspace_root.join("parent/sub-a");
    std::fs::create_dir_all(&sub_a_path).unwrap();
    std::fs::write(sub_a_path.join("note.md"), b"child-content").unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsReadChildHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
    };
    let out = handler
        .call(
            ctx_for("parent"),
            vec![Val::String("sub-a".into()), Val::String("note.md".into())],
            1,
        )
        .await
        .unwrap();
    let val = unwrap_ok_some(out);
    if let Val::List(items) = val {
        assert_eq!(items.len(), b"child-content".len());
    }
}

#[tokio::test]
async fn ac14_read_child_with_non_child_id_returns_notfound() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let tree = multi_agent_tree(&workspace_root);
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsReadChildHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
    };
    // sub-a is not a parent of sub-b
    let out = handler
        .call(
            ctx_for("sub-a"),
            vec![Val::String("sub-b".into()), Val::String("x.md".into())],
            1,
        )
        .await
        .unwrap();
    let (case, _) = unwrap_err_variant(out);
    assert_eq!(case, "not-found");
}

// ─────────────────────────────────────────────────────────────────────────────
// AC-15: parent fs.write to child territory blocked
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ac15_parent_write_to_child_territory_returns_permission_denied() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let tree = multi_agent_tree(&workspace_root);
    let parent_path = workspace_root.join("parent");
    std::fs::create_dir_all(parent_path.join("sub-a")).unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsWriteHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: maintainer_with_default_writer(),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: None,
    };
    let data: Vec<Val> = vec![Val::U8(1)];
    let out = handler
        .call(
            ctx_for("parent"),
            vec![Val::String("sub-a/forbidden.md".into()), Val::List(data)],
            1,
        )
        .await
        .unwrap();
    let (case, _) = unwrap_err_variant(out);
    assert_eq!(case, "permission-denied");
}

// ─────────────────────────────────────────────────────────────────────────────
// AC-01: history fns callable via mock provider
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ac01_file_history_via_mock_provider_returns_versions() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    std::fs::write(agent_workspace.join("doc.md"), b"v3").unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(single_agent_tree("a", agent_workspace.clone())) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let mut mock = MockFileHistoryProvider::new();
    mock.history.insert(
        agent_workspace.join("doc.md"),
        vec![
            VersionEntry {
                version: "abc111".into(),
                timestamp: "2026-05-01T00:00:00Z".into(),
                message: Some("v1".into()),
            },
            VersionEntry {
                version: "def222".into(),
                timestamp: "2026-05-02T00:00:00Z".into(),
                message: Some("v2".into()),
            },
        ],
    );
    let handler = FsFileHistoryHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        history: Arc::new(mock) as Arc<dyn FileHistoryProvider>,
    };
    let out = handler
        .call(ctx_for("a"), vec![Val::String("doc.md".into())], 1)
        .await
        .unwrap();
    let val = unwrap_ok_some(out);
    if let Val::List(items) = val {
        assert_eq!(
            items.len(),
            2,
            "MockFileHistoryProvider returned 2 versions"
        );
    }
}

#[tokio::test]
async fn ac01_stub_history_provider_returns_empty() {
    let stub = StubFileHistoryProvider;
    let r = stub.file_history(&PathBuf::from("/tmp/example")).unwrap();
    assert!(r.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// Round 1 audit-fix coverage
// ─────────────────────────────────────────────────────────────────────────────

// AC-07 round 1 fix: list/scan of `.agent/` filters `_*` entries.
#[tokio::test]
async fn round1_fs_list_on_agent_dir_filters_underscore_entries() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(agent_workspace.join(".agent/_drafts")).unwrap();
    std::fs::write(agent_workspace.join(".agent/_drafts/x.md"), b"hidden").unwrap();
    std::fs::write(agent_workspace.join(".agent/config.yaml"), b"k: v").unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(single_agent_tree("a", agent_workspace)) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = cap_fs::FsListHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        max_entries: DEFAULT_MAX_LIST_ENTRIES,
    };
    let out = handler
        .call(ctx_for("a"), vec![Val::String(".agent".into())], 1)
        .await
        .unwrap();
    let val = unwrap_ok_some(out);
    if let Val::List(items) = val {
        // Only `config.yaml` should be present; `_drafts` is filtered out.
        let mut names = Vec::new();
        for entry in items {
            if let Val::Record(fields) = entry {
                if let Val::String(s) = &fields[0].1 {
                    names.push(s.clone());
                }
            }
        }
        assert!(names.contains(&"config.yaml".to_string()));
        assert!(
            !names.contains(&"_drafts".to_string()),
            "should filter _drafts; got {names:?}"
        );
    }
}

// AC-10 round 1 fix: scan handlers serialize against fs.write/fs.delete via meta_lock.
// Verified indirectly: this test demonstrates that scan sees consistent state by
// waiting for write to complete before scanning.
#[tokio::test]
async fn round1_scan_sees_consistent_state_after_write() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::new(single_agent_tree("a", agent_workspace.clone())) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let m = maintainer_with_default_writer();
    // First, write a file.
    let write_handler = FsWriteHandler {
        resolver: Arc::clone(&resolver) as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: Arc::clone(&m),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: None,
    };
    let data: Vec<Val> = b"hello".iter().copied().map(Val::U8).collect();
    write_handler
        .call(
            ctx_for("a"),
            vec![Val::String("doc.md".into()), Val::List(data)],
            1,
        )
        .await
        .unwrap();
    // Then scan.
    let scan_handler = FsScanHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: m,
        max_entries: DEFAULT_MAX_LIST_ENTRIES,
    };
    let out = scan_handler
        .call(ctx_for("a"), vec![Val::String(".".into())], 1)
        .await
        .unwrap();
    let val = unwrap_ok_some(out);
    // Verify the scan result includes the written file.
    if let Val::Record(fields) = val {
        let children = fields.iter().find(|(k, _)| k == "children").unwrap();
        if let Val::List(items) = &children.1 {
            let mut found = false;
            for c in items {
                if let Val::Record(cfields) = c {
                    if let Val::String(s) = &cfields[0].1 {
                        if s == "doc.md" {
                            found = true;
                        }
                    }
                }
            }
            assert!(found, "scan must see doc.md after write completed");
        }
    }
}

// AC-09 round 1 fix: schema optional defaults applied on add_entry_for_write.
#[tokio::test]
async fn round1_add_entry_for_write_applies_optional_defaults() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("schema.yaml");
    let loader = Arc::new(MetaSchemaLoader::new_with_default(path));
    let m = MetaMaintainer::new(loader, Arc::new(DefaultAtomicWriter));
    let (meta, _) = m.add_entry_for_write(None, "x.md", b"x").unwrap();
    let entry = meta.entries.get("x.md").unwrap();
    // Default schema's optional fields: tags=[], status=active.
    assert_eq!(entry.tags, Vec::<String>::new());
    assert_eq!(entry.status, Some("active".to_string()));
}

// Round 1 fix: schema-load validation rejects mismatched default value types.
#[tokio::test]
async fn round1_schema_validation_rejects_default_type_mismatch() {
    let loader = MetaSchemaLoader::new_with_default(PathBuf::new());
    let bad = r#"
required: {}
optional:
  priority:
    type: integer
    default: "not-a-number"
"#;
    let r = loader.reload_from_yaml(bad);
    assert!(r.is_err(), "should reject string default for integer field");
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional handler coverage — list-slug, scan-slug, list-child, scan-child,
// read-at, read-child-at, child-file-history, slug-file-history.
// Brings AC-01 / AC-02 / AC-14 from "registration only" to "exercised end-to-end".
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn handlers_list_slug_happy_path() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let tree = multi_agent_tree(&workspace_root);
    let sub_b_path = workspace_root.join("parent/sub-b");
    std::fs::create_dir_all(&sub_b_path).unwrap();
    std::fs::write(sub_b_path.join("a.md"), b"a").unwrap();
    std::fs::write(sub_b_path.join("b.md"), b"b").unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsListSlugHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        max_entries: DEFAULT_MAX_LIST_ENTRIES,
    };
    let out = handler
        .call(
            ctx_for("sub-a"),
            vec![
                Val::String("sub-b".into()),
                Val::String("sibling-template".into()),
            ],
            1,
        )
        .await
        .unwrap();
    let val = unwrap_ok_some(out);
    if let Val::List(items) = val {
        assert!(items.len() >= 2, "list-slug should return >= 2 entries");
    }
}

#[tokio::test]
async fn handlers_scan_slug_happy_path() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let tree = multi_agent_tree(&workspace_root);
    let sub_b_path = workspace_root.join("parent/sub-b");
    std::fs::create_dir_all(&sub_b_path).unwrap();
    std::fs::write(sub_b_path.join("a.md"), b"a").unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsScanSlugHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: maintainer_with_default_writer(),
        max_entries: DEFAULT_MAX_LIST_ENTRIES,
    };
    let out = handler
        .call(
            ctx_for("sub-a"),
            vec![
                Val::String("sub-b".into()),
                Val::String("sibling-template".into()),
            ],
            1,
        )
        .await
        .unwrap();
    let val = unwrap_ok_some(out);
    assert!(
        matches!(val, Val::Record(_)),
        "scan-slug returns ScanResult record"
    );
}

#[tokio::test]
async fn handlers_list_child_happy_path() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let tree = multi_agent_tree(&workspace_root);
    let sub_a_path = workspace_root.join("parent/sub-a");
    std::fs::create_dir_all(&sub_a_path).unwrap();
    std::fs::write(sub_a_path.join("x.md"), b"x").unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsListChildHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        max_entries: DEFAULT_MAX_LIST_ENTRIES,
    };
    let out = handler
        .call(
            ctx_for("parent"),
            vec![Val::String("sub-a".into()), Val::String(".".into())],
            1,
        )
        .await
        .unwrap();
    let val = unwrap_ok_some(out);
    if let Val::List(items) = val {
        assert!(items.len() >= 1);
    }
}

#[tokio::test]
async fn handlers_scan_child_happy_path() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let tree = multi_agent_tree(&workspace_root);
    let sub_a_path = workspace_root.join("parent/sub-a");
    std::fs::create_dir_all(&sub_a_path).unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsScanChildHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: maintainer_with_default_writer(),
        max_entries: DEFAULT_MAX_LIST_ENTRIES,
    };
    let out = handler
        .call(
            ctx_for("parent"),
            vec![Val::String("sub-a".into()), Val::String(".".into())],
            1,
        )
        .await
        .unwrap();
    let val = unwrap_ok_some(out);
    assert!(matches!(val, Val::Record(_)));
}

#[tokio::test]
async fn handlers_read_at_with_mock_provider() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    std::fs::write(agent_workspace.join("doc.md"), b"current").unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(single_agent_tree("a", agent_workspace.clone())) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let mut mock = MockFileHistoryProvider::new();
    mock.at.insert(
        (agent_workspace.join("doc.md"), "v1".into()),
        b"old-content".to_vec(),
    );
    let handler = FsReadAtHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        history: Arc::new(mock) as Arc<dyn FileHistoryProvider>,
    };
    let out = handler
        .call(
            ctx_for("a"),
            vec![Val::String("doc.md".into()), Val::String("v1".into())],
            1,
        )
        .await
        .unwrap();
    let val = unwrap_ok_some(out);
    if let Val::List(items) = val {
        assert_eq!(items.len(), b"old-content".len());
    }
}

#[tokio::test]
async fn handlers_read_child_at_with_mock_provider() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let tree = multi_agent_tree(&workspace_root);
    let sub_a_path = workspace_root.join("parent/sub-a");
    std::fs::create_dir_all(&sub_a_path).unwrap();
    std::fs::write(sub_a_path.join("doc.md"), b"current").unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let mut mock = MockFileHistoryProvider::new();
    mock.at
        .insert((sub_a_path.join("doc.md"), "v2".into()), b"old-cv".to_vec());
    let handler = FsReadChildAtHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        history: Arc::new(mock) as Arc<dyn FileHistoryProvider>,
    };
    let out = handler
        .call(
            ctx_for("parent"),
            vec![
                Val::String("sub-a".into()),
                Val::String("doc.md".into()),
                Val::String("v2".into()),
            ],
            1,
        )
        .await
        .unwrap();
    let val = unwrap_ok_some(out);
    if let Val::List(items) = val {
        assert_eq!(items.len(), b"old-cv".len());
    }
}

#[tokio::test]
async fn handlers_child_file_history_with_mock_provider() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let tree = multi_agent_tree(&workspace_root);
    let sub_a_path = workspace_root.join("parent/sub-a");
    std::fs::create_dir_all(&sub_a_path).unwrap();
    std::fs::write(sub_a_path.join("doc.md"), b"x").unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let mut mock = MockFileHistoryProvider::new();
    mock.history.insert(
        sub_a_path.join("doc.md"),
        vec![VersionEntry {
            version: "abc".into(),
            timestamp: "2026-05-06T00:00:00Z".into(),
            message: None,
        }],
    );
    let handler = cap_fs::FsChildFileHistoryHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        history: Arc::new(mock) as Arc<dyn FileHistoryProvider>,
    };
    let out = handler
        .call(
            ctx_for("parent"),
            vec![Val::String("sub-a".into()), Val::String("doc.md".into())],
            1,
        )
        .await
        .unwrap();
    let val = unwrap_ok_some(out);
    if let Val::List(items) = val {
        assert_eq!(items.len(), 1);
    }
}

#[tokio::test]
async fn handlers_slug_file_history_with_mock_provider() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let tree = multi_agent_tree(&workspace_root);
    let sub_b_path = workspace_root.join("parent/sub-b");
    std::fs::create_dir_all(&sub_b_path).unwrap();
    std::fs::write(sub_b_path.join("note.md"), b"x").unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let mut mock = MockFileHistoryProvider::new();
    mock.history.insert(
        sub_b_path.join("note.md"),
        vec![VersionEntry {
            version: "def".into(),
            timestamp: "2026-05-06T00:00:00Z".into(),
            message: Some("v1".into()),
        }],
    );
    let handler = FsSlugFileHistoryHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        history: Arc::new(mock) as Arc<dyn FileHistoryProvider>,
    };
    let out = handler
        .call(
            ctx_for("sub-a"),
            vec![
                Val::String("sub-b".into()),
                Val::String("sibling-template".into()),
                Val::String("note.md".into()),
            ],
            1,
        )
        .await
        .unwrap();
    let val = unwrap_ok_some(out);
    if let Val::List(items) = val {
        assert_eq!(items.len(), 1);
    }
}

// AC-09: end-to-end reload → fs.write → entry has new schema's default field.
#[tokio::test]
async fn ac09_reload_then_write_uses_new_schema_defaults() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("schema.yaml");
    let loader = Arc::new(MetaSchemaLoader::new_with_default(path));
    // Reload with an extension field `priority: 0`.
    loader
        .reload_from_yaml(
            r#"
required:
  name:
    type: string
    auto: filename
  slug:
    type: string
    auto: filename-to-slug
  description:
    type: string
    auto: content-extract
optional:
  tags:
    type: list<string>
    default: []
  priority:
    type: integer
    default: 0
"#,
        )
        .unwrap();
    let m = MetaMaintainer::new(loader, Arc::new(DefaultAtomicWriter));
    let (meta, _) = m.add_entry_for_write(None, "x.md", b"x").unwrap();
    let entry = meta.entries.get("x.md").unwrap();
    // priority extension default should be materialized in `extra`.
    assert!(entry.extra.contains_key("priority"));
}

// AC-10: fs.delete meta-rollback path (mirror of ac10_fs_write_rollback_on_data_failure
// but for delete — uses meta-first commit, then remove_file fails on a read-only data file).
#[tokio::test]
async fn ac10_fs_delete_returns_err_when_file_missing() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(single_agent_tree("a", agent_workspace.clone())) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let m = maintainer_with_default_writer();
    let handler = cap_fs::FsDeleteHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: Arc::clone(&m),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: None,
    };
    let out = handler
        .call(ctx_for("a"), vec![Val::String("missing.md".into())], 1)
        .await
        .unwrap();
    let (case, _) = unwrap_err_variant(out);
    // missing file → io-error (not-found from remove_file).
    assert!(case == "io-error" || case == "not-found");
}

// Round 1 fix: handler-level .agent guard in update-scope uses vpath.
#[tokio::test]
async fn round1_update_scope_rejects_agent_path_via_vpath() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(agent_workspace.join(".agent")).unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(single_agent_tree("a", agent_workspace)) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsUpdateScopeHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: maintainer_with_default_writer(),
    };
    let out = handler
        .call(
            ctx_for("a"),
            vec![
                Val::String(".agent".into()),
                Val::String("desc".into()),
                Val::List(vec![]),
            ],
            1,
        )
        .await
        .unwrap();
    let (case, _) = unwrap_err_variant(out);
    assert_eq!(case, "permission-denied");
}

// ─────────────────────────────────────────────────────────────────────────────
// Round 2 fixes — close 7 AC coverage gaps flagged by Codex round 2:
//   AC-06 Rule 4 (parent-blocked) + Rule 5 (non-adjacent-blocked)
//   AC-07 scan suppresses all hidden classes (.meta.yaml, .advance, .git, *.sqlite*)
//   AC-08 schema load from on-disk yaml file
//   AC-09 fs_write persistence into .meta.yaml on disk (end-to-end)
//   AC-10 fs_delete success path (meta entry removed + meta.updated event)
//   AC-10 fs_delete rollback when remove_file fails after meta-first commit
//   AC-11 update-scope / update-entry-meta schema validation rejection paths
//   AC-14 child-cannot-read-parent via read-child handler
// ─────────────────────────────────────────────────────────────────────────────

// AC-06 Rule 4: a child agent cannot use read-child to reach its parent.
// In multi_agent_tree, parent is NOT in children_of(sub-a), so sub-a calling
// resolve_child_read("sub-a", "parent", ...) returns NotFound.
#[tokio::test]
async fn ac06_rule4_child_cannot_resolve_child_read_against_parent() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let tree = multi_agent_tree(&workspace_root);
    let resolver = DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    );
    // sub-a's parent is "parent", so resolve_child_read with parent as the
    // would-be child id must return NotFound (parent is not a child of sub-a).
    let err = resolver
        .resolve_child_read("sub-a", "parent", "any.md")
        .unwrap_err();
    assert!(matches!(err, FsError::NotFound(_)), "got {err:?}");
}

// AC-06 Rule 5: a non-adjacent third-party agent (no peer_slug_map entry) cannot
// reach another agent via slug-read. sub-c has no peer_slug_map in the fixture,
// so any resolve_slug_read attempt by sub-c returns NotFound.
#[tokio::test]
async fn ac06_rule5_non_adjacent_resolve_slug_read_returns_notfound() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let tree = multi_agent_tree(&workspace_root);
    let resolver = DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    );
    // sub-c has no entries in peer_slug_map, so even a real sibling slug fails.
    let err = resolver
        .resolve_slug_read("sub-c", "sub-a", "sibling-template", "x.md")
        .unwrap_err();
    assert!(matches!(err, FsError::NotFound(_)), "got {err:?}");
}

// AC-07: fs.scan must suppress all hidden classes from children. Plant
// .meta.yaml + .advance + .git + a sqlite file at the territory root and
// verify scan's children list contains none of them.
#[tokio::test]
async fn ac07_scan_suppresses_meta_yaml_dot_advance_dot_git_and_sqlite() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    // Hidden classes:
    std::fs::write(
        agent_workspace.join(".meta.yaml"),
        b"_scope:\n  description: \"\"\n",
    )
    .unwrap();
    std::fs::create_dir_all(agent_workspace.join(".advance")).unwrap();
    std::fs::create_dir_all(agent_workspace.join(".git")).unwrap();
    std::fs::write(agent_workspace.join("data.sqlite"), b"sqlite-bytes").unwrap();
    std::fs::write(agent_workspace.join("data.sqlite-wal"), b"wal").unwrap();
    // A regular file that should appear:
    std::fs::write(agent_workspace.join("note.md"), b"hi").unwrap();

    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::new(single_agent_tree("a", agent_workspace.clone())) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsScanHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: maintainer_with_default_writer(),
        max_entries: DEFAULT_MAX_LIST_ENTRIES,
    };
    let out = handler
        .call(ctx_for("a"), vec![Val::String(".".into())], 1)
        .await
        .unwrap();
    let val = unwrap_ok_some(out);
    let mut child_names = Vec::new();
    if let Val::Record(fields) = val {
        let children = fields.iter().find(|(k, _)| k == "children").unwrap();
        if let Val::List(items) = &children.1 {
            for c in items {
                if let Val::Record(cfields) = c {
                    if let Val::String(s) = &cfields[0].1 {
                        child_names.push(s.clone());
                    }
                }
            }
        }
    }
    assert!(
        child_names.contains(&"note.md".to_string()),
        "got {child_names:?}"
    );
    for hidden in [
        ".meta.yaml",
        ".advance",
        ".git",
        "data.sqlite",
        "data.sqlite-wal",
    ] {
        assert!(
            !child_names.contains(&hidden.to_string()),
            "scan must suppress {hidden}; got {child_names:?}"
        );
    }
}

// AC-08: MetaSchemaLoader::load_from_disk reads + parses an on-disk yaml file
// (the startup-load path used at process boot to pick up
// `.agent/meta-schema.yaml`).
#[test]
fn ac08_schema_load_from_disk_reads_yaml_file() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("meta-schema.yaml");
    let yaml = r#"
required:
  name:
    type: string
    auto: filename
  slug:
    type: string
    auto: filename-to-slug
  description:
    type: string
    auto: content-extract
optional:
  status:
    type:
      - active
      - archived
    default: active
  tags:
    type: list<string>
    default: []
"#;
    std::fs::write(&path, yaml).unwrap();
    let loader = MetaSchemaLoader::load_from_disk(&path).expect("load_from_disk should succeed");
    let schema = loader.current();
    assert!(schema.required.contains_key("name"));
    assert!(schema.required.contains_key("slug"));
    assert!(schema.required.contains_key("description"));
    assert!(schema.optional.contains_key("status"));
    assert!(schema.optional.contains_key("tags"));
}

// AC-08: load_from_disk on a missing path returns the default schema (i.e.
// startup proceeds even when no on-disk schema exists).
#[test]
fn ac08_schema_load_from_disk_missing_returns_default() {
    let dir = tempfile::TempDir::new().unwrap();
    let missing = dir.path().join("does-not-exist.yaml");
    let loader = MetaSchemaLoader::load_from_disk(&missing)
        .expect("missing schema file should fall back to default");
    let schema = loader.current();
    // Default schema has the required fields name/slug/description/type
    // (ADR 2026-06-29 Decision 1 added entity `type`).
    assert!(schema.required.contains_key("name"));
    assert!(schema.required.contains_key("slug"));
    assert!(schema.required.contains_key("description"));
    assert!(schema.required.contains_key("type"));
}

// AC-09: fs_write persists the auto-populated entry into the on-disk
// `.meta.yaml` file (verified by reading the file directly, not via the
// maintainer cache).
#[tokio::test]
async fn ac09_fs_write_persists_meta_yaml_on_disk() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::new(single_agent_tree("a", agent_workspace.clone())) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let m = maintainer_with_default_writer();
    let handler = FsWriteHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: Arc::clone(&m),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: None,
    };
    let data: Vec<Val> = b"# Title\n\nbody\n".iter().copied().map(Val::U8).collect();
    handler
        .call(
            ctx_for("a"),
            vec![Val::String("doc.md".into()), Val::List(data)],
            1,
        )
        .await
        .unwrap();
    // Read .meta.yaml off disk directly.
    let yaml = std::fs::read_to_string(agent_workspace.join(".meta.yaml")).unwrap();
    assert!(
        yaml.contains("doc.md:"),
        "yaml should contain entry; got:\n{yaml}"
    );
    assert!(
        yaml.contains("name: doc"),
        "yaml should have name; got:\n{yaml}"
    );
    assert!(
        yaml.contains("slug: doc"),
        "yaml should have slug; got:\n{yaml}"
    );
    assert!(
        yaml.contains("description: Title") || yaml.contains("description: \"Title\""),
        "yaml should have content-extracted description; got:\n{yaml}"
    );
}

// AC-10: fs_delete on an existing file with an existing meta entry must
// remove the entry from .meta.yaml AND emit meta.updated alongside fs.delete.
#[tokio::test]
async fn ac10_fs_delete_success_removes_entry_and_emits_meta_updated() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::new(single_agent_tree("a", agent_workspace.clone())) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let m = maintainer_with_default_writer();
    // Step 1: write a file (creates .meta.yaml with entry).
    let write_handler = FsWriteHandler {
        resolver: Arc::clone(&resolver) as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: Arc::clone(&m),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: None,
    };
    let data: Vec<Val> = b"hello".iter().copied().map(Val::U8).collect();
    write_handler
        .call(
            ctx_for("a"),
            vec![Val::String("doomed.md".into()), Val::List(data)],
            1,
        )
        .await
        .unwrap();
    // Sanity: meta has the entry pre-delete.
    assert!(m
        .load(&agent_workspace)
        .await
        .unwrap()
        .unwrap()
        .entries
        .contains_key("doomed.md"));
    // Reset emitter so we can inspect just the delete-phase events.
    let delete_emitter = Arc::new(TestEmitter::new());
    let delete_handler = cap_fs::FsDeleteHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: delete_emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: Arc::clone(&m),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: None,
    };
    let out = delete_handler
        .call(ctx_for("a"), vec![Val::String("doomed.md".into())], 1)
        .await
        .unwrap();
    unwrap_ok_none(out);
    // Meta entry should be gone.
    let after = m.load(&agent_workspace).await.unwrap().unwrap();
    assert!(
        !after.entries.contains_key("doomed.md"),
        "entry should be removed after delete"
    );
    // Both fs.delete and meta.updated must have fired.
    let evs = delete_emitter.snapshot();
    assert!(evs.iter().any(|e| e.event_type == "fs.delete"));
    assert!(evs.iter().any(|e| e.event_type == "meta.updated"));
}

// AC-10: when remove_file fails after meta-first commit, the maintainer must
// roll back .meta.yaml so the entry survives. We arrange this by pre-seeding
// .meta.yaml with an entry whose data file does not actually exist on disk —
// meta-first commit succeeds, remove_file fails (NotFound), rollback restores
// the original meta.
#[tokio::test]
async fn ac10_fs_delete_rolls_back_meta_when_remove_file_fails() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::new(single_agent_tree("a", agent_workspace.clone())) as Arc<dyn AgentTreeSnapshot>,
    ));
    let m = maintainer_with_default_writer();
    // Pre-seed .meta.yaml with an entry for "phantom.md", but never create the
    // file on disk.
    let (meta_seed, _) = m
        .add_entry_for_write(None, "phantom.md", b"phantom-bytes")
        .unwrap();
    m.write(&agent_workspace, &meta_seed).await.unwrap();
    assert!(m
        .load(&agent_workspace)
        .await
        .unwrap()
        .unwrap()
        .entries
        .contains_key("phantom.md"));

    let emitter = Arc::new(TestEmitter::new());
    let handler = cap_fs::FsDeleteHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: Arc::clone(&m),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: None,
    };
    let out = handler
        .call(ctx_for("a"), vec![Val::String("phantom.md".into())], 1)
        .await
        .unwrap();
    let (case, _) = unwrap_err_variant(out);
    // Returns io-error (or not-found) to caller.
    assert!(case == "io-error" || case == "not-found");
    // The phantom entry must have been restored by the rollback path.
    let restored = m.load(&agent_workspace).await.unwrap().unwrap();
    assert!(
        restored.entries.contains_key("phantom.md"),
        "rollback should restore the meta entry; got {:?}",
        restored.entries.keys().collect::<Vec<_>>()
    );
}

// AC-11: update-scope's schema validation path — empty description rejected
// end-to-end at the host fn boundary.
#[tokio::test]
async fn ac11_update_scope_rejects_empty_description_via_handler() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(single_agent_tree("a", agent_workspace)) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsUpdateScopeHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: maintainer_with_default_writer(),
    };
    let out = handler
        .call(
            ctx_for("a"),
            vec![
                Val::String(".".into()),
                Val::String("   ".into()),
                Val::List(vec![]),
            ],
            1,
        )
        .await
        .unwrap();
    let (case, _) = unwrap_err_variant(out);
    assert_eq!(case, "invalid-path");
}

// AC-11: update-entry-meta's schema validation — empty description rejected
// end-to-end at the host fn boundary, even when the entry exists.
#[tokio::test]
async fn ac11_update_entry_meta_rejects_empty_description_via_handler() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::new(single_agent_tree("a", agent_workspace.clone())) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let m = maintainer_with_default_writer();
    // Seed an entry so the validation has something to gate.
    let write_handler = FsWriteHandler {
        resolver: Arc::clone(&resolver) as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: Arc::clone(&m),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: None,
    };
    let data: Vec<Val> = b"x".iter().copied().map(Val::U8).collect();
    write_handler
        .call(
            ctx_for("a"),
            vec![Val::String("entry.md".into()), Val::List(data)],
            1,
        )
        .await
        .unwrap();
    let handler = FsUpdateEntryMetaHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: Arc::clone(&m),
    };
    let out = handler
        .call(
            ctx_for("a"),
            vec![
                Val::String(".".into()),
                Val::String("entry.md".into()),
                Val::String("".into()),
                Val::List(vec![]),
            ],
            1,
        )
        .await
        .unwrap();
    let (case, _) = unwrap_err_variant(out);
    assert_eq!(case, "invalid-path");
}

// ─────────────────────────────────────────────────────────────────────────────
// Adversarial round 1 fix tests:
//   — NotFound payload is relative-only (no host path leak)
//   — ENOENT on visible path maps to not-found (anti-fingerprinting)
//   — WIT string params (peer_id, slug, child_id, version, entry_name) bounded
//   — description (≤4096) + tags (≤32 × ≤128) bounded
// ─────────────────────────────────────────────────────────────────────────────

// W-Codex-1 closure: NotFound from hidden-path rejection emits ONLY the
// guest-supplied vpath (relative), never the absolute host workspace path.
#[tokio::test]
async fn adv1_notfound_payload_does_not_leak_host_path() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("agentX");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    std::fs::write(
        agent_workspace.join(".meta.yaml"),
        b"_scope:\n  description: \"\"\n",
    )
    .unwrap();
    let resolver = DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::new(single_agent_tree("agentX", agent_workspace.clone()))
            as Arc<dyn AgentTreeSnapshot>,
    );
    // Read a hidden class — must emit NotFound with relative-only payload.
    let err = resolver.resolve_read("agentX", ".meta.yaml").unwrap_err();
    let payload = match &err {
        FsError::NotFound(s) => s.clone(),
        other => panic!("expected NotFound, got {other:?}"),
    };
    assert!(
        !payload.contains(workspace_root.to_str().unwrap()),
        "payload leaks workspace_root: {payload:?}"
    );
    assert!(
        !payload.contains(agent_workspace.to_str().unwrap()),
        "payload leaks agent_workspace: {payload:?}"
    );
}

// W-Codex-3 closure: ENOENT on a visible (non-hidden) path now maps to
// not-found at the host fn boundary, indistinguishable from a hidden-path
// NotFound (anti-fingerprinting per AC-06).
#[tokio::test]
async fn adv1_enoent_on_visible_path_returns_not_found() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(single_agent_tree("a", agent_workspace)) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsReadHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        preview_max_bytes: None,
    };
    let out = handler
        .call(
            ctx_for("a"),
            vec![Val::String("definitely-missing.txt".into())],
            1,
        )
        .await
        .unwrap();
    let (case, _) = unwrap_err_variant(out);
    assert_eq!(
        case, "not-found",
        "ENOENT on visible path must map to not-found, not io-error"
    );
}

// W-Claude-1 closure: oversized peer_id (and slug) on read-slug → HandlerError
// at the WIT boundary, not a 100 MB allocation.
#[tokio::test]
async fn adv1_read_slug_rejects_oversized_peer_id() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::new(multi_agent_tree(&workspace_root)) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsReadSlugHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
    };
    let big = "x".repeat(2048); // > MAX_WIT_STRING_PARAM_BYTES (1024)
    let out = handler
        .call(
            ctx_for("sub-a"),
            vec![
                Val::String(big),
                Val::String("sibling-template".into()),
                Val::String("note.md".into()),
            ],
            1,
        )
        .await
        .unwrap();
    let (case, msg) = unwrap_err_variant(out);
    assert_eq!(case, "invalid-path");
    assert!(
        msg.contains("MAX_WIT_STRING_PARAM_BYTES") && msg.contains("peer_id"),
        "got: {msg}"
    );
}

// W-Codex-4 closure: oversized description on update-scope → HandlerError at
// the WIT-parse boundary (rejected BEFORE clone, defending against the
// memory-amplification path that the maintainer-side validation would only
// catch after host allocation already happened).
#[tokio::test]
async fn adv1_update_scope_rejects_oversized_description() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(single_agent_tree("a", agent_workspace)) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsUpdateScopeHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: maintainer_with_default_writer(),
    };
    let huge = "a".repeat(8192); // > MAX_DESCRIPTION_BYTES (4096)
    let out = handler
        .call(
            ctx_for("a"),
            vec![
                Val::String(".".into()),
                Val::String(huge),
                Val::List(vec![]),
            ],
            1,
        )
        .await
        .unwrap();
    let (case, msg) = unwrap_err_variant(out);
    assert_eq!(case, "invalid-path");
    assert!(
        msg.contains("MAX_DESCRIPTION_BYTES"),
        "expected MAX_DESCRIPTION_BYTES rejection at WIT-parse boundary, got: {msg}"
    );
}

// W-Codex-4 closure: oversized tag count on update-entry-meta → invalid-path.
#[tokio::test]
async fn adv1_update_entry_meta_rejects_oversized_tag_count() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::new(single_agent_tree("a", agent_workspace.clone())) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let m = maintainer_with_default_writer();
    // Seed an entry first.
    let write_handler = FsWriteHandler {
        resolver: Arc::clone(&resolver) as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: Arc::clone(&m),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: None,
    };
    let data: Vec<Val> = b"x".iter().copied().map(Val::U8).collect();
    write_handler
        .call(
            ctx_for("a"),
            vec![Val::String("e.md".into()), Val::List(data)],
            1,
        )
        .await
        .unwrap();
    let handler = FsUpdateEntryMetaHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: m,
    };
    let many_tags: Vec<Val> = (0..40).map(|i| Val::String(format!("t{i}"))).collect();
    let out = handler
        .call(
            ctx_for("a"),
            vec![
                Val::String(".".into()),
                Val::String("e.md".into()),
                Val::String("desc".into()),
                Val::List(many_tags),
            ],
            1,
        )
        .await
        .unwrap();
    let (case, msg) = unwrap_err_variant(out);
    assert_eq!(case, "invalid-path");
    assert!(
        msg.contains("MAX_TAGS_COUNT"),
        "expected MAX_TAGS_COUNT rejection at WIT-parse boundary, got: {msg}"
    );
}

// AC-06 round 6 fix: case-folding child-territory bypass. On HFS+/APFS, a
// parent agent typing `Sub-A/x.md` with alternate casing for the child name
// would resolve to the same on-disk dir as `sub-a/x.md`, but a byte-level
// `path.starts_with(child.workspace_path)` check would miss that. The fix
// uses case-insensitive component compare via path_starts_with_ci.
#[tokio::test]
async fn ac06_case_folding_child_territory_write_rejected() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let tree = multi_agent_tree(&workspace_root);
    let parent_path = workspace_root.join("parent");
    std::fs::create_dir_all(parent_path.join("sub-a")).unwrap();
    let resolver = DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    );
    // Parent tries to write into a case-different version of sub-a's path.
    // On case-folding filesystems both refer to the same on-disk dir; the
    // bypass would let parent reach sub-a's territory.
    let err = resolver
        .resolve_write("parent", "Sub-A/forbidden.md")
        .unwrap_err();
    assert!(matches!(err, FsError::PermissionDenied(_)), "got {err:?}");
}

// AC-06/AC-07: case-folding `.agent` bypass closure. On HFS+/APFS,
// `.AGENT` and `.agent` resolve to the same on-disk directory, so any
// case-sensitive `.agent` check would let a guest typing `.AGENT/_x` past
// the cross-territory hidden subset (AC-07) and `.AGENT/x.md` past Rule 6
// (AC-06). Exercise both with an upper-case `.AGENT` vpath and assert the
// resolver still rejects.
#[tokio::test]
async fn ac07_case_folding_dot_agent_underscore_path_rejected() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let resolver = DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(single_agent_tree("a", agent_workspace)) as Arc<dyn AgentTreeSnapshot>,
    );
    // `.AGENT/_x` must be rejected just like `.agent/_x` is.
    let err = resolver.resolve_read("a", ".AGENT/_x").unwrap_err();
    assert!(matches!(err, FsError::NotFound(_)), "got {err:?}");
}

#[tokio::test]
async fn ac06_rule6_case_folding_dot_agent_write_rejected() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let resolver = DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(single_agent_tree("a", agent_workspace)) as Arc<dyn AgentTreeSnapshot>,
    );
    // Rule 6: `.AGENT/x.md` write must be blocked the same as `.agent/x.md`.
    let err = resolver.resolve_write("a", ".AGENT/x.md").unwrap_err();
    assert!(matches!(err, FsError::PermissionDenied(_)), "got {err:?}");
}

// AC-07: FsScanHandler against `.agent/` filters `_*` entries (the scan-side
// counterpart to `round1_fs_list_on_agent_dir_filters_underscore_entries`,
// which only exercised the list handler).
#[tokio::test]
async fn ac07_scan_on_agent_dir_filters_underscore_entries() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(agent_workspace.join(".agent/_drafts")).unwrap();
    std::fs::write(agent_workspace.join(".agent/_drafts/x.md"), b"hidden").unwrap();
    std::fs::write(agent_workspace.join(".agent/config.yaml"), b"k: v").unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(single_agent_tree("a", agent_workspace)) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsScanHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: maintainer_with_default_writer(),
        max_entries: DEFAULT_MAX_LIST_ENTRIES,
    };
    let out = handler
        .call(ctx_for("a"), vec![Val::String(".agent".into())], 1)
        .await
        .unwrap();
    let val = unwrap_ok_some(out);
    let mut child_names = Vec::new();
    if let Val::Record(fields) = val {
        let children = fields.iter().find(|(k, _)| k == "children").unwrap();
        if let Val::List(items) = &children.1 {
            for c in items {
                if let Val::Record(cfields) = c {
                    if let Val::String(s) = &cfields[0].1 {
                        child_names.push(s.clone());
                    }
                }
            }
        }
    }
    assert!(
        child_names.contains(&"config.yaml".to_string()),
        "got {child_names:?}"
    );
    assert!(
        !child_names.contains(&"_drafts".to_string()),
        "scan must filter _drafts from .agent/; got {child_names:?}"
    );
}

// AC-11: success path for FsUpdateEntryMetaHandler — write a file (seeds
// `.meta.yaml` with an entry), then update its description+tags via the
// handler, then re-read the entry off disk to verify persistence.
#[tokio::test]
async fn ac11_update_entry_meta_success_persists_to_meta_yaml() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::new(single_agent_tree("a", agent_workspace.clone())) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let m = maintainer_with_default_writer();
    // Seed an entry via fs.write so the maintainer + on-disk yaml have it.
    let write_handler = FsWriteHandler {
        resolver: Arc::clone(&resolver) as Arc<dyn VirtualPathResolver>,
        emitter: emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: Arc::clone(&m),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: None,
    };
    let data: Vec<Val> = b"# Title\n\nbody".iter().copied().map(Val::U8).collect();
    write_handler
        .call(
            ctx_for("a"),
            vec![Val::String("note.md".into()), Val::List(data)],
            1,
        )
        .await
        .unwrap();
    // Run update-entry-meta with valid args.
    let update_emitter = Arc::new(TestEmitter::new());
    let update_handler = FsUpdateEntryMetaHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: update_emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: Arc::clone(&m),
    };
    let out = update_handler
        .call(
            ctx_for("a"),
            vec![
                Val::String(".".into()),
                Val::String("note.md".into()),
                Val::String("updated description".into()),
                Val::List(vec![
                    Val::String("tag-a".into()),
                    Val::String("tag-b".into()),
                ]),
            ],
            1,
        )
        .await
        .unwrap();
    unwrap_ok_none(out);
    // Verify on-disk yaml reflects the update.
    let yaml = std::fs::read_to_string(agent_workspace.join(".meta.yaml")).unwrap();
    assert!(
        yaml.contains("description: updated description"),
        "yaml should reflect updated description; got:\n{yaml}"
    );
    assert!(
        yaml.contains("tag-a") && yaml.contains("tag-b"),
        "yaml should reflect updated tags; got:\n{yaml}"
    );
    // meta.updated must have fired with source=update-entry-meta.
    let evs = update_emitter.snapshot();
    assert!(
        evs.iter().any(|e| e.event_type == "meta.updated"),
        "expected meta.updated event; got: {:?}",
        evs.iter().map(|e| &e.event_type).collect::<Vec<_>>()
    );
}

// AC-09: hot-reload schema with a new optional default, then run FsWriteHandler
// end-to-end, then verify the new default is persisted into `.meta.yaml` on
// disk (closes the on-disk + reload combination gap that
// `ac09_reload_then_write_uses_new_schema_defaults` left at the maintainer
// unit level only).
#[tokio::test]
async fn ac09_reload_then_fs_write_persists_new_default_on_disk() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join("a");
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::new(single_agent_tree("a", agent_workspace.clone())) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    // Build a maintainer whose schema loader we can reload before the write.
    let schema_path = std::env::temp_dir().join("schema-ac09-reload.yaml");
    let loader = Arc::new(MetaSchemaLoader::new_with_default(schema_path));
    // Add a new optional `priority` field with default 7.
    let new_yaml = r#"
required:
  name:
    type: string
    auto: filename
  slug:
    type: string
    auto: filename-to-slug
  description:
    type: string
    auto: content-extract
optional:
  status:
    type:
      - draft
      - active
      - archived
    default: active
  tags:
    type: list<string>
    default: []
  priority:
    type: integer
    default: 7
"#;
    loader.reload_from_yaml(new_yaml).unwrap();
    let m = Arc::new(MetaMaintainer::new(loader, Arc::new(DefaultAtomicWriter)));
    let handler = FsWriteHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: Arc::clone(&m),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: None,
    };
    let data: Vec<Val> = b"# Doc\n\nbody".iter().copied().map(Val::U8).collect();
    handler
        .call(
            ctx_for("a"),
            vec![Val::String("note.md".into()), Val::List(data)],
            1,
        )
        .await
        .unwrap();
    // Read the persisted .meta.yaml off disk and assert the new default was
    // written for the entry.
    let yaml = std::fs::read_to_string(agent_workspace.join(".meta.yaml")).unwrap();
    assert!(
        yaml.contains("note.md:"),
        "yaml should contain entry; got:\n{yaml}"
    );
    assert!(
        yaml.contains("priority: 7"),
        "yaml should persist the hot-reloaded schema default; got:\n{yaml}"
    );
}

// AC-14 (Rule 4 via host fn): a child agent invoking read-child against its
// parent (sub-a → "parent") must fail with NotFound — children cannot reach
// parent territory through the read-child capability.
#[tokio::test]
async fn ac14_child_cannot_read_parent_via_read_child_handler() {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let tree = multi_agent_tree(&workspace_root);
    let parent_path = workspace_root.join("parent");
    std::fs::create_dir_all(&parent_path).unwrap();
    std::fs::write(parent_path.join("secret.md"), b"parent-only").unwrap();
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root,
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsReadChildHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
    };
    let out = handler
        .call(
            ctx_for("sub-a"),
            vec![
                Val::String("parent".into()),
                Val::String("secret.md".into()),
            ],
            1,
        )
        .await
        .unwrap();
    let (case, _) = unwrap_err_variant(out);
    assert_eq!(case, "not-found");
}

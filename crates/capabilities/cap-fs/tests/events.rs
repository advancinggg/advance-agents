//! Event payload + emission tests.
//!
//! Locks the FsEvent shape that downstream M004 indexer + M011 post-processor will
//! subscribe to via the `fs.*` event_type strings.

mod common;

use std::sync::Arc;

use advance_runtime::host_registry::{HostCallContext, HostFunctionHandler};
use advance_shared_types::traits::{AgentTreeSnapshot, EventBusEmit};
use cap_fs::{
    DefaultAtomicWriter, DefaultVirtualPathResolver, FsDeleteHandler, FsListHandler, FsReadHandler,
    FsWriteHandler, MetaMaintainer, MetaSchemaLoader, DEFAULT_MAX_LIST_ENTRIES,
};

fn test_maintainer() -> Arc<MetaMaintainer> {
    let schema_path = std::env::temp_dir().join("schema-events-test.yaml");
    Arc::new(MetaMaintainer::new(
        Arc::new(MetaSchemaLoader::new_with_default(schema_path)),
        Arc::new(DefaultAtomicWriter),
    ))
}
use wasmtime::component::Val;

use common::{single_agent_tree, TestEmitter};

const AGENT_ID: &str = "agent-evt";
const TRACE_ID: &str = "trace-evt-1";

fn ctx() -> HostCallContext {
    HostCallContext {
        agent_id: AGENT_ID.into(),
        trace_id: TRACE_ID.into(),
        turn_id: None,
        capability: "fs".into(),
        function: "advance:runtime/agent-fs::read".into(),
        run_id: None,
        iteration: None,
    }
}

struct Setup {
    _tempdir: tempfile::TempDir,
    workspace_root: std::path::PathBuf,
    agent_workspace: std::path::PathBuf,
    emitter: Arc<TestEmitter>,
    resolver: Arc<DefaultVirtualPathResolver>,
}

fn setup() -> Setup {
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join(AGENT_ID);
    std::fs::create_dir_all(&agent_workspace).unwrap();
    let tree = single_agent_tree(AGENT_ID, agent_workspace.clone());
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        Arc::new(tree) as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter = Arc::new(TestEmitter::new());
    Setup {
        _tempdir: tempdir,
        workspace_root,
        agent_workspace,
        emitter,
        resolver,
    }
}

// SA-T29: fs.write payload roundtrip.
#[tokio::test]
async fn write_event_payload_shape() {
    let s = setup();
    let handler = FsWriteHandler {
        resolver: s.resolver.clone(),
        emitter: s.emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: test_maintainer(),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: None,
    };
    let data: Vec<Val> = b"hello".iter().copied().map(Val::U8).collect();
    handler
        .call(ctx(), vec![Val::String("a.txt".into()), Val::List(data)], 1)
        .await
        .unwrap();
    let evs = s.emitter.snapshot();
    // Slice B emits both fs.write and meta.updated (renamed Slice D per PRD §15.3.8).
    assert_eq!(evs.len(), 2);
    let p = &evs[0].payload;
    assert_eq!(p["Write"]["agent_id"], AGENT_ID);
    assert_eq!(p["Write"]["path"], "a.txt");
    assert_eq!(p["Write"]["size"], 5);
    assert_eq!(p["Write"]["is_new_file"], true);
    assert_eq!(evs[1].event_type, "meta.updated");
}

// SA-T29b: fs.read payload roundtrip.
#[tokio::test]
async fn read_event_payload_shape() {
    let s = setup();
    std::fs::write(s.agent_workspace.join("r.md"), b"abc").unwrap();
    let handler = FsReadHandler {
        resolver: s.resolver.clone(),
        emitter: s.emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        preview_max_bytes: None,
    };
    handler
        .call(ctx(), vec![Val::String("r.md".into())], 1)
        .await
        .unwrap();
    let evs = s.emitter.snapshot();
    let p = &evs[0].payload;
    assert_eq!(p["Read"]["agent_id"], AGENT_ID);
    assert_eq!(p["Read"]["path"], "r.md");
    assert_eq!(p["Read"]["source"], "Private");
    assert_eq!(p["Read"]["size"], 3);
}

// SA-T29c: fs.delete and fs.list payload shapes.
#[tokio::test]
async fn delete_and_list_event_payload_shape() {
    let s = setup();
    std::fs::write(s.agent_workspace.join("z.md"), b"z").unwrap();
    std::fs::write(s.agent_workspace.join("a.md"), b"a").unwrap();

    let list_handler = FsListHandler {
        resolver: s.resolver.clone(),
        emitter: s.emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        max_entries: DEFAULT_MAX_LIST_ENTRIES,
    };
    list_handler
        .call(ctx(), vec![Val::String(".".into())], 1)
        .await
        .unwrap();

    let delete_handler = FsDeleteHandler {
        resolver: s.resolver.clone(),
        emitter: s.emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        maintainer: test_maintainer(),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: None,
    };
    delete_handler
        .call(ctx(), vec![Val::String("a.md".into())], 1)
        .await
        .unwrap();

    let evs = s.emitter.snapshot();
    assert_eq!(evs.len(), 2);
    assert_eq!(evs[0].event_type, "fs.list");
    assert_eq!(evs[0].payload["List"]["count"], 2);
    assert_eq!(evs[0].payload["List"]["source"], "Private");
    assert_eq!(evs[0].payload["List"]["agent_id"], AGENT_ID);

    assert_eq!(evs[1].event_type, "fs.delete");
    assert_eq!(evs[1].payload["Delete"]["path"], "a.md");
    assert_eq!(evs[1].payload["Delete"]["agent_id"], AGENT_ID);
}

// SA-T29e: max_entries=8 over-limit emits no event.
#[tokio::test]
async fn list_handler_over_limit_uses_canonical_msg_no_emit() {
    let s = setup();
    // Create 9 files in agent workspace.
    for i in 0..9 {
        std::fs::write(s.agent_workspace.join(format!("f{i:02}.txt")), b"x").unwrap();
    }
    let handler = FsListHandler {
        resolver: s.resolver.clone(),
        emitter: s.emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        max_entries: 8,
    };
    let out = handler
        .call(ctx(), vec![Val::String(".".into())], 1)
        .await
        .unwrap();
    assert_eq!(out.len(), 1);
    match out.into_iter().next().unwrap() {
        Val::Result(Err(Some(inner))) => match *inner {
            Val::Variant(case, Some(payload)) => {
                assert_eq!(case, "io-error");
                match *payload {
                    Val::String(msg) => {
                        assert_eq!(
                            msg,
                            cap_fs::list_over_limit_msg(8),
                            "handler must use list_over_limit_msg(8) verbatim"
                        );
                    }
                    _ => panic!("expected String payload"),
                }
            }
            other => panic!("expected Variant, got {other:?}"),
        },
        other => panic!("expected Err(Some), got {other:?}"),
    }
    assert_eq!(s.emitter.snapshot().len(), 0);
    let _ = s.workspace_root; // silence unused field warning
}

// SA-T30: Event struct fields populated from HostCallContext (ctx.agent_id, ctx.trace_id).
#[tokio::test]
async fn event_struct_fields_from_host_call_context() {
    let s = setup();
    std::fs::write(s.agent_workspace.join("h.md"), b"h").unwrap();
    let handler = FsReadHandler {
        resolver: s.resolver.clone(),
        emitter: s.emitter.clone() as Arc<dyn EventBusEmit>,
        concurrency: common::test_concurrency(),
        preview_max_bytes: None,
    };
    handler
        .call(ctx(), vec![Val::String("h.md".into())], 1)
        .await
        .unwrap();
    let evs = s.emitter.snapshot();
    assert_eq!(evs[0].agent_id, AGENT_ID);
    assert_eq!(evs[0].trace_id, TRACE_ID);
    assert_eq!(evs[0].event_type, "fs.read");
    // span_id is a fresh UUID v4 — at least non-empty.
    assert!(!evs[0].span_id.is_empty());
    // id is a fresh UUID v4 — at least non-empty.
    assert!(!evs[0].id.is_empty());
    // task_id / run_id / execution_id / parent_span_id all None.
    assert!(evs[0].task_id.is_none());
    assert!(evs[0].run_id.is_none());
    assert!(evs[0].execution_id.is_none());
    assert!(evs[0].parent_span_id.is_none());
    assert!(evs[0].duration_ms.is_none());
}

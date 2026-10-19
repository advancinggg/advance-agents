//! Agent-path R-c / C7 pins (OSS-5.md `operator_rc.rs`).

mod common;

use std::sync::{Arc, Mutex};

use advance_runtime::host_registry::{HostCallContext, HostFunctionHandler};
use advance_shared_types::traits::AgentTreeSnapshot;
use cap_fs::{
    DefaultAtomicWriter, DefaultVirtualPathResolver, FsDeleteHandler, FsListHandler,
    FsWriteHandler, GitSync, GitSyncError, GitSyncOp, MetaMaintainer, MetaSchemaLoader,
    PendingFsCommit, VirtualPathResolver, DEFAULT_MAX_LIST_ENTRIES,
};
use wasmtime::component::Val;

use common::{single_agent_tree, test_concurrency, MockGitSync, TestEmitter};

const AGENT: &str = "agent-1";

fn ctx() -> HostCallContext {
    HostCallContext {
        agent_id: AGENT.into(),
        trace_id: "trace-rc".into(),
        turn_id: None,
        capability: "fs".into(),
        function: "advance:runtime/agent-fs::write".into(),
        run_id: None,
        iteration: None,
    }
}

fn unwrap_ok_none(out: Vec<Val>) {
    match out.into_iter().next() {
        Some(Val::Result(Ok(None))) => {}
        other => panic!("expected Ok(None), got {other:?}"),
    }
}

fn unwrap_err_case(out: Vec<Val>) -> String {
    match out.into_iter().next() {
        Some(Val::Result(Err(Some(inner)))) => match *inner {
            Val::Variant(case, _) => case,
            other => panic!("expected variant, {other:?}"),
        },
        other => panic!("expected Err, {other:?}"),
    }
}

fn unwrap_ok_list(out: Vec<Val>) -> Vec<String> {
    match out.into_iter().next() {
        Some(Val::Result(Ok(Some(inner)))) => match *inner {
            Val::List(items) => items
                .into_iter()
                .filter_map(|item| match item {
                    Val::Record(fields) => fields.into_iter().find_map(|(k, v)| {
                        if k == "name" {
                            match v {
                                Val::String(s) => Some(s),
                                _ => None,
                            }
                        } else {
                            None
                        }
                    }),
                    _ => None,
                })
                .collect(),
            other => panic!("expected list, {other:?}"),
        },
        other => panic!("expected Ok list, {other:?}"),
    }
}

struct ProbeSync {
    maintainer: Arc<MetaMaintainer>,
    held_at_enqueue: Mutex<Vec<bool>>,
    inner: Arc<MockGitSync>,
}

#[async_trait::async_trait]
impl GitSync for ProbeSync {
    async fn submit_fs_commit(
        &self,
        agent_id: &str,
        op: GitSyncOp,
        vpath: &str,
        physical_path: std::path::PathBuf,
        meta_yaml_path: std::path::PathBuf,
    ) -> Result<(), GitSyncError> {
        self.enqueue_fs_commit(agent_id, op, vpath, physical_path, meta_yaml_path)
            .await?
            .wait()
            .await
    }

    async fn enqueue_fs_commit(
        &self,
        agent_id: &str,
        op: GitSyncOp,
        vpath: &str,
        physical_path: std::path::PathBuf,
        meta_yaml_path: std::path::PathBuf,
    ) -> Result<PendingFsCommit, GitSyncError> {
        let held = self.maintainer.try_acquire().is_none();
        self.held_at_enqueue.lock().unwrap().push(held);
        self.inner
            .enqueue_fs_commit(agent_id, op, vpath, physical_path, meta_yaml_path)
            .await
    }
}

fn maintainer_at(root: &std::path::Path) -> Arc<MetaMaintainer> {
    let schema = root.join("schema-rc.yaml");
    Arc::new(MetaMaintainer::new(
        Arc::new(MetaSchemaLoader::new_with_default(schema)),
        Arc::new(DefaultAtomicWriter),
    ))
}

#[tokio::test]
async fn fs_write_enqueues_commit_before_releasing_meta_lock() {
    let td = tempfile::TempDir::new().unwrap();
    let root = td.path().to_path_buf();
    let workspace = root.join(AGENT);
    std::fs::create_dir_all(&workspace).unwrap();
    let tree = Arc::new(single_agent_tree(AGENT, workspace.clone())) as Arc<dyn AgentTreeSnapshot>;
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        root.clone(),
        Arc::clone(&tree),
    ));
    let emitter = Arc::new(TestEmitter::new());
    let maintainer = maintainer_at(&root);
    let mock = Arc::new(MockGitSync::new());
    let probe = Arc::new(ProbeSync {
        maintainer: Arc::clone(&maintainer),
        held_at_enqueue: Mutex::new(Vec::new()),
        inner: mock,
    });
    let handler = FsWriteHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as _,
        concurrency: test_concurrency(),
        maintainer: Arc::clone(&maintainer),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: Some(probe.clone() as Arc<dyn GitSync>),
    };
    let body: Vec<Val> = b"rc".iter().copied().map(Val::U8).collect();
    unwrap_ok_none(
        handler
            .call(ctx(), vec![Val::String("rc.md".into()), Val::List(body)], 1)
            .await
            .unwrap(),
    );
    let held = probe.held_at_enqueue.lock().unwrap().clone();
    assert_eq!(held, vec![true], "enqueue must run while L1 is held");
    assert!(
        maintainer.try_acquire().is_some(),
        "L1 must be free after fs.write returns"
    );
}

#[tokio::test]
async fn fs_delete_enqueues_commit_before_releasing_meta_lock() {
    let td = tempfile::TempDir::new().unwrap();
    let root = td.path().to_path_buf();
    let workspace = root.join(AGENT);
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(workspace.join("bye.md"), b"x").unwrap();
    let tree = Arc::new(single_agent_tree(AGENT, workspace.clone())) as Arc<dyn AgentTreeSnapshot>;
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        root.clone(),
        Arc::clone(&tree),
    ));
    let emitter = Arc::new(TestEmitter::new());
    let maintainer = maintainer_at(&root);
    let mock = Arc::new(MockGitSync::new());
    let probe = Arc::new(ProbeSync {
        maintainer: Arc::clone(&maintainer),
        held_at_enqueue: Mutex::new(Vec::new()),
        inner: mock,
    });
    let handler = FsDeleteHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as _,
        concurrency: test_concurrency(),
        maintainer: Arc::clone(&maintainer),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: Some(probe.clone() as Arc<dyn GitSync>),
    };
    unwrap_ok_none(
        handler
            .call(ctx(), vec![Val::String("bye.md".into())], 1)
            .await
            .unwrap(),
    );
    let held = probe.held_at_enqueue.lock().unwrap().clone();
    assert_eq!(held, vec![true], "delete enqueue must run while L1 is held");
    assert!(maintainer.try_acquire().is_some());
}

#[tokio::test]
async fn agent_fs_write_into_runtime_refused() {
    let td = tempfile::TempDir::new().unwrap();
    let root = td.path().to_path_buf();
    let workspace = root.join(AGENT);
    std::fs::create_dir_all(workspace.join(".runtime")).unwrap();
    let tree = Arc::new(single_agent_tree(AGENT, workspace.clone())) as Arc<dyn AgentTreeSnapshot>;
    let resolver = Arc::new(DefaultVirtualPathResolver::new(root, tree));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsWriteHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as _,
        concurrency: test_concurrency(),
        maintainer: maintainer_at(td.path()),
        writer: Arc::new(DefaultAtomicWriter),
        db_sync: None,
        workspace_root: None,
        agent_tree: None,
        git_sync: None,
    };
    let body: Vec<Val> = b"no".iter().copied().map(Val::U8).collect();
    let case = unwrap_err_case(
        handler
            .call(
                ctx(),
                vec![Val::String(".runtime/secret.md".into()), Val::List(body)],
                1,
            )
            .await
            .unwrap(),
    );
    assert_eq!(case, "not-found");
}

#[tokio::test]
async fn agent_list_root_hides_runtime() {
    let td = tempfile::TempDir::new().unwrap();
    let root = td.path().to_path_buf();
    let workspace = root.join(AGENT);
    std::fs::create_dir_all(workspace.join(".runtime")).unwrap();
    std::fs::write(workspace.join("ok.md"), b"1").unwrap();
    let tree = Arc::new(single_agent_tree(AGENT, workspace.clone())) as Arc<dyn AgentTreeSnapshot>;
    let resolver = Arc::new(DefaultVirtualPathResolver::new(root, tree));
    let emitter = Arc::new(TestEmitter::new());
    let handler = FsListHandler {
        resolver: resolver as Arc<dyn VirtualPathResolver>,
        emitter: emitter as _,
        concurrency: test_concurrency(),
        max_entries: DEFAULT_MAX_LIST_ENTRIES,
    };
    let names = unwrap_ok_list(
        handler
            .call(ctx(), vec![Val::String(".".into())], 1)
            .await
            .unwrap(),
    );
    assert!(names.contains(&"ok.md".into()), "{names:?}");
    assert!(
        !names.iter().any(|n| n.eq_ignore_ascii_case(".runtime")),
        "{names:?}"
    );
}

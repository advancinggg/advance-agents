//! Part A — production terminate-cascade adapters (dev-task-cascade-subset).
//! Real-backend witnesses for `cascade_adapters.rs`: GrantRevokeCascade,
//! MailboxFlushCascade, RunManagerCascade, FsWorkspaceCleanup, plus a full
//! 3-node tree terminate driven through `DefaultTerminateController` with all 4
//! real adapters injected.

use std::sync::Arc;

use advance_database::{R2d2SqliteIndexHandle, SqliteIndexHandle};
use advance_messaging::{MailboxStore, DEFAULT_CAPACITY};
use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{Message, MessageKind};
use advance_shared_types::run::TaskRunStatus;
use advance_shared_types::traits::EventBusEmit;
use cap_grant::data::{
    CapParam, Grant, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl,
};
use cap_grant::{GrantSqliteIndex, GrantStore};
use cap_lifecycle::terminate::{GrantCascadeRevoke, RunCascade};
use cap_lifecycle::{
    AgentTreeStore, DefaultTerminateController, FsWorkspaceCleanup, GrantRevokeCascade,
    MailboxCascade, MailboxFlushCascade, RunManagerCascade, TerminateController, WorkspaceCleanup,
};
use std::time::SystemTime;
use tempfile::TempDir;

/// No-op EventBus for store/run-manager construction in tests.
struct NoopBus;
impl EventBusEmit for NoopBus {
    fn emit(&self, _event: Event) {}
}

fn make_grant_store() -> Arc<GrantStore> {
    let handle: Arc<dyn SqliteIndexHandle> =
        Arc::new(R2d2SqliteIndexHandle::new_in_memory().expect("in-memory sqlite"));
    let index = GrantSqliteIndex::new(handle);
    index.ensure_schema().expect("ensure_schema");
    Arc::new(GrantStore::new(index, Arc::new(NoopBus)))
}

fn active_grant(id: &str, agent: &str, cap: &str, params: Vec<CapParam>) -> Grant {
    Grant {
        id: GrantId::new(id),
        grantee: agent.to_string(),
        capability: cap.to_string(),
        params,
        ttl: GrantTtl::Persistent,
        issuer: GrantIssuer::Config,
        provenance: GrantProvenance::StaticConfig,
        status: GrantStatus::Active,
        created_at: chrono::Utc::now(),
        expires_at: None,
    }
}

fn msg(to: &str) -> Message {
    Message {
        id: format!("m-{to}"),
        kind: MessageKind::Agent,
        from: "peer".to_string(),
        to: to.to_string(),
        payload: b"hi".to_vec(),
        context: None,
        timestamp: SystemTime::now(),
        origin: None,
    }
}

// Test 11 — GrantRevokeCascade against a REAL GrantStore.
#[test]
fn grant_revoke_cascade_revokes_active_grants() {
    let store = make_grant_store();
    store.insert(active_grant("g1", "X", "fs", vec![])).unwrap();
    store
        .insert(active_grant("g2", "X", "http", vec![]))
        .unwrap();
    // Sanity: 2 active before.
    assert_eq!(
        store
            .list_by_grantee("X")
            .iter()
            .filter(|g| g.status == GrantStatus::Active)
            .count(),
        2
    );
    let cascade = GrantRevokeCascade::new(store.clone());
    cascade.revoke_for_agent("X").unwrap();
    // No active grants remain for X.
    assert_eq!(
        store
            .list_by_grantee("X")
            .iter()
            .filter(|g| g.status == GrantStatus::Active)
            .count(),
        0
    );
}

// Test 12 — FsWorkspaceCleanup against the real filesystem.
#[test]
fn fs_workspace_cleanup_removes_and_guards() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let sub = root.join("agents/x/.sub/uuid");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(sub.join("f.txt"), b"x").unwrap();
    let cleanup = FsWorkspaceCleanup::new(root.clone());

    // Real removal.
    assert!(sub.exists());
    cleanup.remove_sub_workspace(&sub).unwrap();
    assert!(!sub.exists());

    // Idempotent: removing an absent path is Ok.
    cleanup.remove_sub_workspace(&sub).unwrap();

    // Containment guard: a path outside the workspace_root is rejected.
    let outside = TempDir::new().unwrap();
    let outside_path = outside.path().canonicalize().unwrap().join("evil");
    std::fs::create_dir_all(&outside_path).unwrap();
    let err = cleanup.remove_sub_workspace(&outside_path).unwrap_err();
    assert!(matches!(
        err,
        cap_lifecycle::LifecycleError::InvalidTarget(_)
    ));
    // The out-of-root dir was NOT deleted.
    assert!(outside_path.exists());

    // `..`-traversal guard: a non-canonical path that lexically starts with the
    // root but escapes via `..` is rejected (Path::starts_with does not resolve
    // `..`). Build a sibling dir of root, then a `<root>/../sibling` path.
    let sibling = root.parent().unwrap().join("sibling-victim");
    std::fs::create_dir_all(&sibling).unwrap();
    let traversal = root.join("..").join("sibling-victim");
    let err = cleanup.remove_sub_workspace(&traversal).unwrap_err();
    assert!(matches!(
        err,
        cap_lifecycle::LifecycleError::InvalidTarget(_)
    ));
    // The escape target was NOT deleted.
    assert!(sibling.exists());
}

// Test 13 — MailboxFlushCascade against a REAL MailboxStore.
#[test]
fn mailbox_cascade_flush_and_notify() {
    let store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    let mb = store.get_or_create("victim").unwrap();
    mb.deliver(msg("victim")).unwrap();
    mb.deliver(msg("victim")).unwrap();
    mb.deliver(msg("victim")).unwrap();
    assert_eq!(mb.depth(), 3);

    let cascade = MailboxFlushCascade::new(store.clone());
    cascade.flush_mailbox("victim").unwrap();
    assert_eq!(store.get("victim").unwrap().depth(), 0);

    // notify_parent_crash delivers a System message into the parent's mailbox.
    cascade
        .notify_parent_crash("parent", "child-7", "panic")
        .unwrap();
    let pmb = store.get("parent").expect("parent mailbox created");
    assert_eq!(pmb.depth(), 1);
    let m = pmb.poll().expect("crash notice present");
    assert_eq!(m.kind, MessageKind::System);
    assert_eq!(m.from, "system");
    assert_eq!(m.to, "parent");
    let body = String::from_utf8(m.payload).unwrap();
    assert!(body.contains("child-7"));
    assert!(body.contains("panic"));

    // Flushing a never-registered mailbox is a no-op (does not panic / create).
    cascade.flush_mailbox("ghost").unwrap();
}

// Test 14 — RunManagerCascade against a REAL RunManager. Split into a
// deterministic real-effect leg + a non-racy adapter-dispatch leg.
#[tokio::test]
async fn run_manager_cascade_real_backend() {
    use advance_run_manager::{RunConfig, RunManager};

    let rm: Arc<RunManager> = RunManager::new_arc(Arc::new(NoopBus));

    // --- Real-effect leg (deterministic): drive the real async cancel directly
    // and observe cancel_pending via the __test-util accessor.
    let id = rm.ensure_run("r1", "r1", RunConfig::default()).unwrap();
    rm.cancel_run(&id, "x".to_string()).await.unwrap();
    assert_eq!(
        rm.snapshot_cancel_pending_for_test(&id),
        Some(Some("x".to_string())),
        "Active run should carry cancel_pending after the real cancel"
    );

    // --- Adapter-dispatch leg: the adapter creates a run via ensure_run, then the
    // rewired cancel_run does a SYNC agent-keyed forced cancel-all
    // (RunManager::cancel_all_runs_for_agent) — no spawn, applied immediately.
    let cascade = RunManagerCascade::new(rm.clone());
    cascade.ensure_run("a1").unwrap(); // creates a1's run (RunId discarded)
    cascade.cancel_run("a1").unwrap(); // sync forced cancel of a1's single live run (Ok)
    cascade.cancel_run("never-registered").unwrap(); // 0 live runs → clean Ok no-op

    let id_a = rm
        .ensure_run("multi-a", "multi", RunConfig::default())
        .unwrap();
    let id_b = rm
        .ensure_run("multi-b", "multi", RunConfig::default())
        .unwrap();
    cascade.cancel_run("multi").unwrap();
    assert!(matches!(
        rm.snapshot_status_for_test(&id_a),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "terminate-cascade"
    ));
    assert!(matches!(
        rm.snapshot_status_for_test(&id_b),
        Some(TaskRunStatus::Cancelled(reason)) if reason == "terminate-cascade"
    ));
    let err = rm
        .ensure_run("multi-c", "multi", RunConfig::default())
        .unwrap_err();
    assert!(
        format!("{err:?}").contains("run-creation-blocked-for-terminating-agent"),
        "terminate cancel-all blocks new runs for the terminated agent"
    );
}

// Test 15 — full 3-node tree terminate through DefaultTerminateController with
// all 4 REAL adapters: real grant revoke + real workspace removal + real mailbox.
#[tokio::test]
async fn full_tree_terminate_with_real_adapters() {
    use advance_run_manager::RunManager;

    let tmp = TempDir::new().unwrap();
    let tree = AgentTreeStore::new(tmp.path().to_path_buf()).unwrap();
    let root_ws = tree.workspace_root().join("root");
    std::fs::create_dir_all(&root_ws).unwrap();
    tree.insert_root(node("root", AgentKind::Root, None, root_ws))
        .unwrap();
    let child_ws = tree.workspace_root().join("root/child");
    std::fs::create_dir_all(&child_ws).unwrap();
    tree.insert_child(
        &AgentId("root".into()),
        node("child", AgentKind::Child, Some("root"), child_ws),
    )
    .unwrap();
    // gc is a Sub with a real workspace dir (so WorkspaceCleanup removes it).
    let gc_ws = tree.workspace_root().join("root/child/.sub/gc");
    std::fs::create_dir_all(&gc_ws).unwrap();
    tree.insert_child(
        &AgentId("child".into()),
        node("gc", AgentKind::Sub, Some("child"), gc_ws.clone()),
    )
    .unwrap();

    // Real backends.
    let grant_store = make_grant_store();
    grant_store
        .insert(active_grant(
            "g-gc",
            "gc",
            "fs",
            vec![CapParam {
                key: "read-paths".into(),
                value: "/tmp".into(),
            }],
        ))
        .unwrap();
    let mailbox_store = Arc::new(MailboxStore::new(DEFAULT_CAPACITY));
    mailbox_store
        .get_or_create("gc")
        .unwrap()
        .deliver(msg("gc"))
        .unwrap();
    let rm = RunManager::new_arc(Arc::new(NoopBus));

    let ctrl = DefaultTerminateController::new(
        tree.clone(),
        Arc::new(GrantRevokeCascade::new(grant_store.clone())),
        Arc::new(MailboxFlushCascade::new(mailbox_store.clone())),
        Arc::new(RunManagerCascade::new(rm)),
        Arc::new(FsWorkspaceCleanup::new(tree.workspace_root().to_path_buf())),
    );

    ctrl.terminate_child("child", "gc").unwrap();

    // Tree node gone.
    assert!(!tree.contains(&AgentId("gc".into())));
    // Real grant revoked.
    assert_eq!(
        grant_store
            .list_by_grantee("gc")
            .iter()
            .filter(|g| g.status == GrantStatus::Active)
            .count(),
        0
    );
    // Real Sub workspace removed from disk.
    assert!(!gc_ws.exists());
    // Real mailbox drained.
    assert_eq!(mailbox_store.get("gc").unwrap().depth(), 0);
}

fn node(id: &str, kind: AgentKind, parent: Option<&str>, ws: std::path::PathBuf) -> AgentNode {
    AgentNode {
        id: AgentId(id.into()),
        kind,
        parent: parent.map(|p| AgentId(p.into())),
        workspace_path: ws,
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    }
}

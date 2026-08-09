//! MODULE-011-AC-29 — hierarchy memory effect (REQ-245, joint M005/M011).
//!
//! Witnessed over REAL components, covering the AC's three clauses:
//!   1. (live) parent `scan-child`/`read-child` can access sub-agent memory —
//!      via the real cap-fs `DefaultVirtualPathResolver::resolve_child_read`
//!      (the same primitive M005-AC-05 already witnesses);
//!   2. (archive) a Sub's memory is archived to the parent's
//!      `.agent/memory/archive/<sub_id>/` on cleanup (NOT deleted) — via the real
//!      `DefaultTerminateController` cascade + the injected `FsMemoryArchiver`;
//!   3. (recall) the parent's memory store surfaces the archived sub entry — via
//!      a real `cap_memory::MemoryStore::open` over the new level-2
//!      `archive/<sub_id>/` scan in `KnowledgeJsonlStore::open`.
//!
//! The grant/mailbox/run cascade seams are no-ops here (irrelevant to the memory
//! effect); the workspace-removal + archive + persistence legs are REAL.

use std::path::Path;
use std::sync::Arc;

use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentStatus, AgentTreeSnapshot, Capability,
};
use cap_fs::resolver::{DefaultVirtualPathResolver, VirtualPathResolver};
use cap_lifecycle::{
    AgentTreeStore, DefaultSpawner, DefaultTerminateController, FsMemoryArchiver,
    FsWorkspaceCleanup, GrantCascadeRevoke, LifecycleError, MailboxCascade, MemoryArchiver,
    RunCascade, SpawnError, SpawnSubConfig, Spawner, SpawnerSubsetGate, TerminateController,
};
use cap_memory::{
    MemoryEntry, MemoryStatus, MemoryStore, MemoryType, DEFAULT_MAX_ACTIVE_PER_AGENT,
};
use tempfile::TempDir;

// --- permissive / no-op cascade seams (the archive + workspace-removal legs are REAL) ---

struct AllowAll;
impl SpawnerSubsetGate for AllowAll {
    fn check(&self, _p: &[Capability], _c: &[Capability]) -> Result<(), SpawnError> {
        Ok(())
    }
}

struct NoopGrant;
impl GrantCascadeRevoke for NoopGrant {
    fn revoke_for_agent(&self, _a: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
}

struct NoopMailbox;
impl MailboxCascade for NoopMailbox {
    fn flush_mailbox(&self, _a: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn notify_parent_crash(&self, _p: &str, _c: &str, _r: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
}

struct NoopRun;
impl RunCascade for NoopRun {
    fn ensure_run(&self, _a: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn cancel_run(&self, _a: &str) -> Result<(), LifecycleError> {
        Ok(())
    }
}

fn fact(id: &str, agent: &str, content: &str) -> MemoryEntry {
    MemoryEntry {
        id: id.into(),
        agent_id: agent.into(),
        entry_type: MemoryType::Fact,
        content: content.into(),
        tags: vec![],
        created_at: "2026-06-25T00:00:00Z".into(),
        task_origin: None,
        is_active: true,
        superseded_by: None,
        status: MemoryStatus::Active,
        supersession_reason: None,
        cluster_id: None,
        sources: vec![],
    }
}

fn root_tree() -> (TempDir, AgentTreeStore, std::path::PathBuf) {
    let tmp = TempDir::new().unwrap();
    let tree = AgentTreeStore::new(tmp.path().to_path_buf()).unwrap();
    let root_ws = tree.workspace_root().join("root");
    std::fs::create_dir_all(&root_ws).unwrap();
    tree.insert_root(AgentNode {
        id: AgentId("root".into()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: root_ws.clone(),
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    })
    .unwrap();
    (tmp, tree, root_ws)
}

#[test]
fn ac29_sub_memory_archived_on_cleanup_and_parent_recall_sees_it() {
    let (_tmp, tree, root_ws) = root_tree();

    // REAL spawn_sub → AgentKind::Sub under root (so the terminate cascade's
    // Sub-only remove_sub_workspace + the archiver actually fire).
    let spawner = DefaultSpawner::new(tree.clone(), Arc::new(AllowAll));
    let sub_id = spawner
        .spawn_sub(SpawnSubConfig {
            parent_id: AgentId("root".into()),
            capabilities: vec![],
            template_ref: None,
        })
        .unwrap();
    let sub_node = tree.get_node(&sub_id).expect("sub in tree");
    assert_eq!(sub_node.kind, AgentKind::Sub);
    let sub_ws = sub_node.workspace_path.clone();

    // Write a memory entry into the SUB's own memory store (creates
    // `<sub_ws>/.agent/memory/<slug>/knowledge.jsonl`).
    let sub_mem_dir = sub_ws.join(".agent/memory");
    {
        let store = MemoryStore::open(sub_mem_dir.clone(), DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap();
        store
            .insert(&sub_id.0, fact("m1", &sub_id.0, "sub-secret"))
            .unwrap();
    }

    // --- Clause 1 (live): parent reads the sub's memory file cross-tree while
    // the sub is alive. Discover the on-disk slug dir (slug() is pub(crate)).
    let slug_dir = std::fs::read_dir(&sub_mem_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .expect("sub memory slug dir");
    let resolver = DefaultVirtualPathResolver::new(
        tree.workspace_root().to_path_buf(),
        Arc::new(tree.clone()) as Arc<dyn AgentTreeSnapshot>,
    );
    let vpath = format!(".agent/memory/{slug_dir}/knowledge.jsonl");
    assert!(
        resolver
            .resolve_child_read("root", &sub_id.0, &vpath)
            .is_ok(),
        "clause 1: parent must read the live sub's memory cross-tree (vpath={vpath})"
    );

    // --- Clause 2 (archive on cleanup): terminate the sub with the archiver wired.
    let controller = DefaultTerminateController::new(
        tree.clone(),
        Arc::new(NoopGrant),
        Arc::new(NoopMailbox),
        Arc::new(NoopRun),
        Arc::new(FsWorkspaceCleanup::new(tree.workspace_root().to_path_buf())),
    )
    .with_memory_archiver(Arc::new(FsMemoryArchiver));
    controller.terminate_child("root", &sub_id.0).unwrap();

    // Sub workspace removed (cleanup ran)...
    assert!(!sub_ws.exists(), "sub workspace must be removed on cleanup");
    // ...sub node gone from the tree...
    assert!(tree.get_node(&sub_id).is_none(), "sub node removed");
    // ...but its memory SURVIVES in the parent's archive/<sub_id>/ (archived ≠ deleted).
    let archived = root_ws
        .join(".agent/memory/archive")
        .join(&sub_id.0)
        .join("knowledge.jsonl");
    assert!(
        archived.exists(),
        "archived sub memory must exist at {}",
        archived.display()
    );

    // --- Clause 3 (parent recall): the parent's memory store hydrates the
    // archived sub entries via the new level-2 archive scan, and recall by the
    // sub's id surfaces them.
    let parent_store =
        MemoryStore::open(root_ws.join(".agent/memory"), DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap();
    let hits = parent_store.recall(&sub_id.0, "", 10);
    assert!(
        hits.iter()
            .any(|e| e.id == "m1" && e.content == "sub-secret"),
        "clause 3: parent recall must see the archived nested sub memory; got {hits:?}"
    );
}

/// Anti-fake-green guard: with NO archiver injected, terminate deletes the sub
/// workspace exactly as before and creates NO archive (the additive default is
/// byte-identical to the pre-existing teardown).
#[test]
fn ac29_default_none_archiver_does_not_archive() {
    let (_tmp, tree, root_ws) = root_tree();
    let spawner = DefaultSpawner::new(tree.clone(), Arc::new(AllowAll));
    let sub_id = spawner
        .spawn_sub(SpawnSubConfig {
            parent_id: AgentId("root".into()),
            capabilities: vec![],
            template_ref: None,
        })
        .unwrap();
    let sub_ws = tree.get_node(&sub_id).unwrap().workspace_path.clone();
    {
        let store =
            MemoryStore::open(sub_ws.join(".agent/memory"), DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap();
        store.insert(&sub_id.0, fact("m1", &sub_id.0, "x")).unwrap();
    }
    // NO .with_memory_archiver(...)
    let controller = DefaultTerminateController::new(
        tree.clone(),
        Arc::new(NoopGrant),
        Arc::new(NoopMailbox),
        Arc::new(NoopRun),
        Arc::new(FsWorkspaceCleanup::new(tree.workspace_root().to_path_buf())),
    );
    controller.terminate_child("root", &sub_id.0).unwrap();
    assert!(!sub_ws.exists());
    assert!(
        !root_ws.join(".agent/memory/archive").exists(),
        "no archive must be created when no archiver is injected"
    );
}

/// An archiver that always fails — models a mid-cleanup IO fault (e.g. ENOSPC on
/// the parent's archive partition).
struct FailingArchiver;
impl MemoryArchiver for FailingArchiver {
    fn archive_sub_memory(
        &self,
        _sub_id: &str,
        _sub_workspace: &Path,
        _parent_workspace: &Path,
    ) -> Result<(), LifecycleError> {
        Err(LifecycleError::IoFailure(
            "simulated archive fault (ENOSPC)".into(),
        ))
    }
}

/// ADVERSARIAL-fix witness (preserve-on-failure): when the archiver FAILS, the sub
/// workspace + its memory are PRESERVED (NOT deleted) so the un-archived entries are
/// not lost — the AC's "archived, NOT deleted" promise holds on the error path. The
/// tree node is still removed (logical termination) and the cascade is not aborted.
#[test]
fn ac29_archive_failure_preserves_sub_workspace() {
    let (_tmp, tree, root_ws) = root_tree();
    let spawner = DefaultSpawner::new(tree.clone(), Arc::new(AllowAll));
    let sub_id = spawner
        .spawn_sub(SpawnSubConfig {
            parent_id: AgentId("root".into()),
            capabilities: vec![],
            template_ref: None,
        })
        .unwrap();
    let sub_ws = tree.get_node(&sub_id).unwrap().workspace_path.clone();
    {
        let store =
            MemoryStore::open(sub_ws.join(".agent/memory"), DEFAULT_MAX_ACTIVE_PER_AGENT).unwrap();
        store
            .insert(&sub_id.0, fact("m1", &sub_id.0, "must-not-be-lost"))
            .unwrap();
    }
    let controller = DefaultTerminateController::new(
        tree.clone(),
        Arc::new(NoopGrant),
        Arc::new(NoopMailbox),
        Arc::new(NoopRun),
        Arc::new(FsWorkspaceCleanup::new(tree.workspace_root().to_path_buf())),
    )
    .with_memory_archiver(Arc::new(FailingArchiver));
    // terminate succeeds (cascade not aborted by the archive fault)...
    controller.terminate_child("root", &sub_id.0).unwrap();
    // ...but the sub workspace + its memory are PRESERVED (archive failed → not deleted).
    assert!(
        sub_ws.exists(),
        "archive failure must PRESERVE the sub workspace (memory not lost)"
    );
    assert!(
        sub_ws.join(".agent/memory").exists(),
        "the sub's un-archived memory must survive on disk for recovery"
    );
    // No partial/garbage archive was left under the parent for this sub.
    assert!(
        !root_ws
            .join(".agent/memory/archive")
            .join(&sub_id.0)
            .exists(),
        "a failed archive leaves no parent archive dir for this sub"
    );
    // The tree node is still removed — logical termination completed.
    assert!(
        tree.get_node(&sub_id).is_none(),
        "sub node still removed (logical termination); only the on-disk workspace is preserved"
    );
}

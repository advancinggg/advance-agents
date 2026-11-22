//! MODULE-010 D4 (owner decision 2026-11-17) — a terminated Sub or Child hands its task
//! history to its parent: its `.agent/tasks/` moves to the parent's
//! `.agent/tasks/archived-agents/<agent-id>/`, before a Sub's workspace is removed.
//!
//! Over REAL components: the `DefaultTerminateController` cascade with the injected
//! `FsMemoryArchiver` and `FsWorkspaceCleanup`; the grant, mailbox and run seams are no-ops.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus, Capability};
use cap_lifecycle::task_history_left;
use cap_lifecycle::{
    AgentTreeStore, DefaultSpawner, DefaultTerminateController, FsMemoryArchiver,
    FsWorkspaceCleanup, GrantCascadeRevoke, LifecycleError, MailboxCascade, MemoryArchiver,
    RunCascade, SpawnChildConfig, SpawnError, SpawnSubConfig, Spawner, SpawnerSubsetGate,
    TerminateController,
};
use tempfile::TempDir;

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

fn root_tree() -> (TempDir, AgentTreeStore, PathBuf) {
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

fn controller(
    tree: &AgentTreeStore,
    archiver: Arc<dyn MemoryArchiver>,
) -> DefaultTerminateController {
    DefaultTerminateController::new(
        tree.clone(),
        Arc::new(NoopGrant),
        Arc::new(NoopMailbox),
        Arc::new(NoopRun),
        Arc::new(FsWorkspaceCleanup::new(tree.workspace_root().to_path_buf())),
    )
    .with_memory_archiver(archiver)
}

fn terminate(tree: &AgentTreeStore, parent: &str, agent: &str) {
    controller(tree, Arc::new(FsMemoryArchiver::new()))
        .terminate_child(parent, agent)
        .unwrap();
}

const LOG_LINE: &str =
    "{\"turn\":1,\"seq\":0,\"role\":\"user\",\"content\":\"sort the seed packets\"}\n";

/// Give `workspace` one task with a turn log and a summary.
fn write_task(workspace: &Path, task: &str) {
    let dir = workspace.join(".agent/tasks/active").join(task);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("llm-turns.jsonl"), LOG_LINE).unwrap();
    std::fs::write(dir.join("summary.yaml"), "brief: sort the seed packets\n").unwrap();
}

fn spawn_sub(tree: &AgentTreeStore, parent: &str) -> (AgentId, PathBuf) {
    let id = DefaultSpawner::new(tree.clone(), Arc::new(AllowAll))
        .spawn_sub(SpawnSubConfig {
            parent_id: AgentId(parent.into()),
            capabilities: vec![],
            template_ref: None,
        })
        .unwrap();
    let ws = tree.get_node(&id).unwrap().workspace_path.clone();
    (id, ws)
}

fn spawn_child(tree: &AgentTreeStore, parent: &str, id: &str, dir: &str) -> PathBuf {
    let id = DefaultSpawner::new(tree.clone(), Arc::new(AllowAll))
        .spawn_child(SpawnChildConfig {
            handle: None,
            parent_id: AgentId(parent.into()),
            child_id: AgentId(id.into()),
            child_workspace_path: PathBuf::from(dir),
            capabilities: vec![],
            template_ref: None,
            binary: None,
        })
        .unwrap();
    tree.get_node(&id).unwrap().workspace_path.clone()
}

fn archived(root_ws: &Path) -> PathBuf {
    root_ws.join(".agent/tasks/archived-agents")
}

#[test]
fn a_terminated_sub_hands_its_task_history_to_its_parent() {
    let (_tmp, tree, root_ws) = root_tree();
    let (sub, sub_ws) = spawn_sub(&tree, "root");
    write_task(&sub_ws, "task-sort");
    terminate(&tree, "root", &sub.0);
    assert!(!sub_ws.exists(), "the Sub's workspace is removed");
    let task = archived(&root_ws).join(&sub.0).join("active/task-sort");
    assert_eq!(
        std::fs::read_to_string(task.join("llm-turns.jsonl")).unwrap(),
        LOG_LINE
    );
    assert!(task.join("summary.yaml").is_file());
}

#[test]
fn a_terminated_child_hands_its_history_over_and_keeps_its_directory() {
    let (_tmp, tree, root_ws) = root_tree();
    let child_ws = spawn_child(&tree, "root", "child-a", "agents/a");
    write_task(&child_ws, "task-sort");
    std::fs::write(child_ws.join("notes.md"), "the user's own file\n").unwrap();
    terminate(&tree, "root", "child-a");
    assert!(
        child_ws.join("notes.md").is_file(),
        "a Child's directory is the user's"
    );
    assert!(
        !child_ws.join(".agent/tasks").exists(),
        "its history moved out"
    );
    assert_eq!(
        std::fs::read_to_string(
            archived(&root_ws).join("child-a/active/task-sort/llm-turns.jsonl")
        )
        .unwrap(),
        LOG_LINE
    );
}

#[test]
fn what_a_descendant_handed_over_moves_on_with_its_parents_history() {
    let (_tmp, tree, root_ws) = root_tree();
    let child_ws = spawn_child(&tree, "root", "child-a", "agents/a");
    let grandchild_ws = spawn_child(&tree, "child-a", "child-b", "b");
    write_task(&child_ws, "task-plan");
    write_task(&grandchild_ws, "task-sort");
    terminate(&tree, "root", "child-a");
    let child = archived(&root_ws).join("child-a");
    assert!(child.join("active/task-plan/llm-turns.jsonl").is_file());
    assert!(
        child
            .join("archived-agents/child-b/active/task-sort/llm-turns.jsonl")
            .is_file(),
        "the grandchild's history is in its parent's"
    );
    assert!(!grandchild_ws.join(".agent/tasks").exists());
}

#[test]
fn a_reused_id_never_overwrites_an_earlier_archive() {
    let (_tmp, tree, root_ws) = root_tree();
    let first = spawn_child(&tree, "root", "child-a", "agents/a");
    write_task(&first, "task-one");
    terminate(&tree, "root", "child-a");
    let second = spawn_child(&tree, "root", "child-a", "agents/a-again");
    write_task(&second, "task-two");
    terminate(&tree, "root", "child-a");
    assert!(archived(&root_ws).join("child-a/active/task-one").is_dir());
    assert!(archived(&root_ws)
        .join("child-a.2/active/task-two")
        .is_dir());
    assert!(!archived(&root_ws).join("child-a/active/task-two").exists());
}

#[test]
fn an_agent_without_task_history_leaves_no_archive() {
    let (_tmp, tree, root_ws) = root_tree();
    let (sub, _) = spawn_sub(&tree, "root");
    terminate(&tree, "root", &sub.0);
    let child_ws = spawn_child(&tree, "root", "child-a", "agents/a");
    std::fs::create_dir_all(child_ws.join(".agent/tasks/active/empty")).unwrap();
    terminate(&tree, "root", "child-a");
    assert!(
        !archived(&root_ws).exists(),
        "an empty history is not archived"
    );
}

#[cfg(unix)]
#[test]
fn a_linked_task_directory_is_neither_followed_nor_archived() {
    let (tmp, tree, root_ws) = root_tree();
    let child_ws = spawn_child(&tree, "root", "child-a", "agents/a");
    let elsewhere = tmp.path().join("elsewhere");
    write_task(&elsewhere, "task-out");
    std::os::unix::fs::symlink(
        elsewhere.join(".agent/tasks"),
        child_ws.join(".agent/tasks"),
    )
    .unwrap();
    terminate(&tree, "root", "child-a");
    assert!(!archived(&root_ws).exists());
    assert!(
        elsewhere
            .join(".agent/tasks/active/task-out/llm-turns.jsonl")
            .is_file(),
        "the link's target is left alone"
    );
}

/// Memory archives; task history fails.
struct HistoryFails;
impl MemoryArchiver for HistoryFails {
    fn archive_sub_memory(&self, _: &str, _: &Path, _: &Path) -> Result<(), LifecycleError> {
        Ok(())
    }
    fn archive_agent_tasks(&self, _: &str, _: &Path, _: &Path) -> Result<(), LifecycleError> {
        Err(LifecycleError::IoFailure("simulated archive fault".into()))
    }
}

#[test]
fn a_sub_whose_history_cannot_be_archived_keeps_its_workspace() {
    let (_tmp, tree, _root_ws) = root_tree();
    let (sub, sub_ws) = spawn_sub(&tree, "root");
    write_task(&sub_ws, "task-sort");
    controller(&tree, Arc::new(HistoryFails))
        .terminate_child("root", &sub.0)
        .unwrap();
    assert!(
        sub_ws
            .join(".agent/tasks/active/task-sort/llm-turns.jsonl")
            .is_file(),
        "the history is not lost"
    );
    assert!(
        tree.get_node(&sub).is_none(),
        "the node is removed all the same"
    );
}

#[test]
fn a_history_still_in_place_is_seen() {
    let tmp = TempDir::new().unwrap();
    let ws = tmp.path().join("agent");
    std::fs::create_dir_all(&ws).unwrap();
    assert!(!task_history_left(&ws), "no history");
    std::fs::create_dir_all(ws.join(".agent/tasks/active/empty")).unwrap();
    assert!(!task_history_left(&ws), "a history that holds no file");
    write_task(&ws, "task-sort");
    assert!(task_history_left(&ws));
    #[cfg(unix)]
    {
        let linked = tmp.path().join("linked");
        std::fs::create_dir_all(linked.join(".agent")).unwrap();
        std::os::unix::fs::symlink(ws.join(".agent/tasks"), linked.join(".agent/tasks")).unwrap();
        assert!(
            !task_history_left(&linked),
            "a linked history is not the workspace's own"
        );
    }
}

/// A history an older release kept in `.agent/memory/tasks/` counts as one, and a Sub that
/// still holds it keeps its workspace.
#[test]
fn a_history_where_an_older_release_kept_it_is_not_lost() {
    let (_tmp, tree, _root_ws) = root_tree();
    let (sub, sub_ws) = spawn_sub(&tree, "root");
    let legacy = sub_ws.join(".agent/memory/tasks/task-sort");
    std::fs::create_dir_all(&legacy).unwrap();
    std::fs::write(legacy.join("llm-turns.jsonl"), LOG_LINE).unwrap();
    assert!(task_history_left(&sub_ws));
    terminate(&tree, "root", &sub.0);
    assert!(
        legacy.join("llm-turns.jsonl").is_file(),
        "the history is not lost"
    );
    assert!(
        tree.get_node(&sub).is_none(),
        "the node is removed all the same"
    );
}

/// A parent whose `.agent/tasks` is a link gets nothing: the archive fails before it makes a
/// directory, so nothing is made where the link points, and the history stays.
#[cfg(unix)]
#[test]
fn no_directory_is_made_through_a_linked_parent_history() {
    let (tmp, tree, root_ws) = root_tree();
    let child_ws = spawn_child(&tree, "root", "child-a", "agents/a");
    write_task(&child_ws, "task-plan");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::create_dir_all(root_ws.join(".agent")).unwrap();
    std::os::unix::fs::symlink(&outside, root_ws.join(".agent/tasks")).unwrap();
    terminate(&tree, "root", "child-a");
    assert!(
        !outside.join("archived-agents").exists(),
        "nothing is made through the link"
    );
    assert!(
        child_ws
            .join(".agent/tasks/active/task-plan/llm-turns.jsonl")
            .is_file(),
        "the history stays"
    );
}

#[test]
fn an_unsafe_id_or_a_parent_component_is_refused() {
    let tmp = TempDir::new().unwrap();
    let archiver = FsMemoryArchiver::new();
    for id in ["..", ".", "a/b", ""] {
        assert!(
            archiver
                .archive_agent_tasks(id, tmp.path(), tmp.path())
                .is_err(),
            "{id:?}"
        );
    }
    assert!(archiver
        .archive_agent_tasks("ok", &tmp.path().join("a/../b"), tmp.path())
        .is_err());
    assert!(archiver
        .archive_agent_tasks("ok", tmp.path(), &tmp.path().join("a/../b"))
        .is_err());
}

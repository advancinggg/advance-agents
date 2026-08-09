//! Shared test fakes used by all integration tests.
//!
//! `TestAgentTree` implements both `AgentTreeReader` (6 methods) and
//! `AgentTreeSnapshot` (1 method) — `AgentTreeSnapshot: AgentTreeReader` is a
//! supertrait bound (`crates/shared-types/src/agent_tree.rs:212`), so a fake that
//! only impls `AgentTreeSnapshot` is a compile error.
//!
//! `TestEmitter` collects emitted `Event` values into a `std::sync::Mutex<Vec<_>>`.
//! We use `std::sync::Mutex` (not `tokio::sync::Mutex`) because the trait method
//! `EventBusEmit::emit(&self, event: Event)` is sync, and tests can call
//! `events.lock().unwrap().clone()` without `.await`.

#![allow(dead_code)] // some helpers are used by only a subset of test files

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentTreeReader, AgentTreeSnapshot, AgentTreeSnapshotData,
    Capability,
};
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use tokio::sync::Semaphore;

/// Build a per-test concurrency semaphore. Tests share the same default permit
/// count as production (`DEFAULT_FS_CONCURRENCY` — currently 16; tightened
/// from 256 in adversarial round 4 to bound peak host memory amplification
/// across concurrent reads). 16 permits is far more than any test sequence
/// runs in parallel, so the semaphore behaves transparently in tests.
pub fn test_concurrency() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(cap_fs::DEFAULT_FS_CONCURRENCY))
}

pub struct TestAgentTree {
    pub nodes: Vec<AgentNode>,
}

impl AgentTreeReader for TestAgentTree {
    fn parent_of(&self, _agent_id: &str) -> Option<String> {
        None
    }
    fn children_of(&self, _agent_id: &str) -> Vec<String> {
        Vec::new()
    }
    fn siblings_of(&self, _agent_id: &str) -> Vec<String> {
        Vec::new()
    }
    fn agent_exists(&self, agent_id: &str) -> bool {
        self.nodes.iter().any(|n| n.id.0 == agent_id)
    }
    fn agent_kind(&self, agent_id: &str) -> Option<AgentKind> {
        self.nodes
            .iter()
            .find(|n| n.id.0 == agent_id)
            .map(|n| n.kind.clone())
    }
    fn capabilities(&self, _agent_id: &str) -> Vec<Capability> {
        Vec::new()
    }
}

impl AgentTreeSnapshot for TestAgentTree {
    fn snapshot(&self) -> AgentTreeSnapshotData {
        AgentTreeSnapshotData {
            nodes: self.nodes.clone(),
            parent_of: HashMap::new(),
            children_of: HashMap::new(),
            peer_slug_map: HashMap::new(),
            revision: 0,
        }
    }
}

pub struct TestEmitter {
    pub events: Mutex<Vec<Event>>,
}

impl TestEmitter {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    pub fn snapshot(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }
}

impl EventBusEmit for TestEmitter {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

/// Build a single-agent `TestAgentTree` whose only agent has `id == agent_id` and
/// `workspace_path == workspace`. Used by most tests.
pub fn single_agent_tree(agent_id: &str, workspace: std::path::PathBuf) -> TestAgentTree {
    TestAgentTree {
        nodes: vec![AgentNode {
            id: AgentId(agent_id.to_string()),
            kind: AgentKind::Root,
            parent: None,
            workspace_path: workspace,
            capabilities: Vec::new(),
            template_ref: None,
            status: advance_shared_types::agent_tree::AgentStatus::Active,
        }],
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Slice B test fixtures.
// ─────────────────────────────────────────────────────────────────────────────

/// Multi-agent topology with parent + 3 children (sub-a, sub-b, sub-c). The
/// parent tree populates parent_of, children_of, and peer_slug_map for testing
/// Rules 2/3/4/5/6.
pub struct MultiAgentTree {
    pub nodes: Vec<AgentNode>,
    pub parent_of_map: HashMap<AgentId, Option<AgentId>>,
    pub children_of_map: HashMap<AgentId, Vec<AgentId>>,
    pub peer_slug_map: HashMap<AgentId, HashMap<String, AgentId>>,
}

impl AgentTreeReader for MultiAgentTree {
    fn parent_of(&self, agent_id: &str) -> Option<String> {
        self.parent_of_map
            .get(&AgentId(agent_id.to_string()))
            .and_then(|opt| opt.as_ref().map(|p| p.0.clone()))
    }
    fn children_of(&self, agent_id: &str) -> Vec<String> {
        self.children_of_map
            .get(&AgentId(agent_id.to_string()))
            .map(|cs| cs.iter().map(|c| c.0.clone()).collect())
            .unwrap_or_default()
    }
    fn siblings_of(&self, _agent_id: &str) -> Vec<String> {
        Vec::new()
    }
    fn agent_exists(&self, agent_id: &str) -> bool {
        self.nodes.iter().any(|n| n.id.0 == agent_id)
    }
    fn agent_kind(&self, agent_id: &str) -> Option<AgentKind> {
        self.nodes
            .iter()
            .find(|n| n.id.0 == agent_id)
            .map(|n| n.kind.clone())
    }
    fn capabilities(&self, _agent_id: &str) -> Vec<Capability> {
        Vec::new()
    }
}

impl AgentTreeSnapshot for MultiAgentTree {
    fn snapshot(&self) -> AgentTreeSnapshotData {
        AgentTreeSnapshotData {
            nodes: self.nodes.clone(),
            parent_of: self.parent_of_map.clone(),
            children_of: self.children_of_map.clone(),
            peer_slug_map: self.peer_slug_map.clone(),
            revision: 0,
        }
    }
}

/// Build a fixture with parent + 3 children. parent's workspace = `workspace_root/parent`,
/// children = parent/sub-a, parent/sub-b, parent/sub-c.
/// peer_slug_map: sub-a knows sub-b via slug "sibling-template", and vice versa.
pub fn multi_agent_tree(workspace_root: &std::path::Path) -> MultiAgentTree {
    let parent_id = AgentId("parent".to_string());
    let sub_a_id = AgentId("sub-a".to_string());
    let sub_b_id = AgentId("sub-b".to_string());
    let sub_c_id = AgentId("sub-c".to_string());

    let nodes = vec![
        AgentNode {
            id: parent_id.clone(),
            kind: AgentKind::Root,
            parent: None,
            workspace_path: workspace_root.join("parent"),
            capabilities: Vec::new(),
            template_ref: None,
            status: advance_shared_types::agent_tree::AgentStatus::Active,
        },
        AgentNode {
            id: sub_a_id.clone(),
            kind: AgentKind::Child,
            parent: Some(parent_id.clone()),
            workspace_path: workspace_root.join("parent/sub-a"),
            capabilities: Vec::new(),
            template_ref: Some("sibling-template".to_string()),
            status: advance_shared_types::agent_tree::AgentStatus::Active,
        },
        AgentNode {
            id: sub_b_id.clone(),
            kind: AgentKind::Child,
            parent: Some(parent_id.clone()),
            workspace_path: workspace_root.join("parent/sub-b"),
            capabilities: Vec::new(),
            template_ref: Some("sibling-template".to_string()),
            status: advance_shared_types::agent_tree::AgentStatus::Active,
        },
        AgentNode {
            id: sub_c_id.clone(),
            kind: AgentKind::Child,
            parent: Some(parent_id.clone()),
            workspace_path: workspace_root.join("parent/sub-c"),
            capabilities: Vec::new(),
            template_ref: Some("other-template".to_string()),
            status: advance_shared_types::agent_tree::AgentStatus::Active,
        },
    ];

    let mut parent_of = HashMap::new();
    parent_of.insert(parent_id.clone(), None);
    parent_of.insert(sub_a_id.clone(), Some(parent_id.clone()));
    parent_of.insert(sub_b_id.clone(), Some(parent_id.clone()));
    parent_of.insert(sub_c_id.clone(), Some(parent_id.clone()));

    let mut children_of = HashMap::new();
    children_of.insert(
        parent_id,
        vec![sub_a_id.clone(), sub_b_id.clone(), sub_c_id.clone()],
    );

    // peer_slug_map: sub-a sees sub-b under slug "sibling-template" (same template), and vice versa.
    // sub-c has a different template, so it doesn't appear in either's slug map.
    let mut peer_slug_map = HashMap::new();
    let mut sub_a_peers = HashMap::new();
    sub_a_peers.insert("sibling-template".to_string(), sub_b_id.clone());
    peer_slug_map.insert(sub_a_id.clone(), sub_a_peers);

    let mut sub_b_peers = HashMap::new();
    sub_b_peers.insert("sibling-template".to_string(), sub_a_id);
    peer_slug_map.insert(sub_b_id, sub_b_peers);

    MultiAgentTree {
        nodes,
        parent_of_map: parent_of,
        children_of_map: children_of,
        peer_slug_map,
    }
}

/// Mock `FileHistoryProvider` for tests.
pub struct MockFileHistoryProvider {
    pub history: HashMap<std::path::PathBuf, Vec<cap_fs::VersionEntry>>,
    pub at: HashMap<(std::path::PathBuf, String), Vec<u8>>,
}

impl MockFileHistoryProvider {
    pub fn new() -> Self {
        Self {
            history: HashMap::new(),
            at: HashMap::new(),
        }
    }
}

impl cap_fs::FileHistoryProvider for MockFileHistoryProvider {
    fn file_history(
        &self,
        physical_path: &std::path::Path,
    ) -> Result<Vec<cap_fs::VersionEntry>, cap_fs::FsError> {
        Ok(self.history.get(physical_path).cloned().unwrap_or_default())
    }
    fn read_at(
        &self,
        physical_path: &std::path::Path,
        version: &str,
    ) -> Result<Vec<u8>, cap_fs::FsError> {
        self.at
            .get(&(physical_path.to_path_buf(), version.to_string()))
            .cloned()
            .ok_or_else(|| {
                cap_fs::FsError::NotFound(format!("{}@{}", physical_path.display(), version))
            })
    }
}

/// Failing `AtomicWriter` for tests — fails on the Nth call.
pub struct FailingAtomicWriter {
    pub fail_on_call: usize,
    pub counter: std::sync::atomic::AtomicUsize,
}

impl FailingAtomicWriter {
    pub fn new(fail_on_call: usize) -> Self {
        Self {
            fail_on_call,
            counter: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

#[async_trait::async_trait]
impl cap_fs::AtomicWriter for FailingAtomicWriter {
    async fn write(&self, path: &std::path::Path, data: &[u8]) -> Result<(), cap_fs::FsError> {
        let n = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        if n == self.fail_on_call {
            return Err(cap_fs::FsError::IoError(format!(
                "injected failure at call {n}"
            )));
        }
        cap_fs::atomic_write(path, data).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Slice C test fixtures.
// ─────────────────────────────────────────────────────────────────────────────

/// Recorded SQL call from `MockSqliteSync`. Used by slice C AC-12 tests to
/// assert call ordering, agent_id encoding, payload contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqlSyncCall {
    UpsertContent {
        agent_id: String,
        file_path: String,
        preview: String,
        last_modified: Option<String>,
    },
    UpsertMeta {
        agent_id: String,
        directory: String,
        entry_name: String,
        description: Option<String>,
        tags_json: Option<String>,
    },
    DeleteContent {
        agent_id: String,
        file_path: String,
    },
    DeleteMeta {
        agent_id: String,
        directory: String,
        entry_name: String,
    },
}

/// Recording mock for `cap_fs::SqliteSync`. Counter increments on EVERY method
/// invocation across all 4 methods. `fail_on_call: Some(N)` triggers a failure
/// when the counter (1-indexed) reaches N. Per-test fresh fixture invariant
/// (each `#[tokio::test]` builds its own `MockSqliteSync` — no shared state).
pub struct MockSqliteSync {
    pub calls: std::sync::Mutex<Vec<SqlSyncCall>>,
    pub fail_on_call: Option<usize>,
    pub counter: std::sync::atomic::AtomicUsize,
}

impl MockSqliteSync {
    pub fn new() -> Self {
        Self {
            calls: std::sync::Mutex::new(Vec::new()),
            fail_on_call: None,
            counter: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn fail_on(n: usize) -> Self {
        Self {
            calls: std::sync::Mutex::new(Vec::new()),
            fail_on_call: Some(n),
            counter: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn snapshot(&self) -> Vec<SqlSyncCall> {
        self.calls.lock().unwrap().clone()
    }

    fn maybe_fail(&self, op: &str) -> Result<(), cap_fs::FsSyncError> {
        let n = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        if Some(n) == self.fail_on_call {
            Err(cap_fs::FsSyncError(format!(
                "injected sql {op} failure at call {n}"
            )))
        } else {
            Ok(())
        }
    }
}

#[async_trait::async_trait]
impl cap_fs::SqliteSync for MockSqliteSync {
    async fn upsert_content(
        &self,
        agent_id: &str,
        file_path: &str,
        preview: &str,
        last_modified: Option<&str>,
    ) -> Result<(), cap_fs::FsSyncError> {
        self.maybe_fail("upsert_content")?;
        self.calls.lock().unwrap().push(SqlSyncCall::UpsertContent {
            agent_id: agent_id.to_string(),
            file_path: file_path.to_string(),
            preview: preview.to_string(),
            last_modified: last_modified.map(|s| s.to_string()),
        });
        Ok(())
    }

    async fn upsert_meta(
        &self,
        agent_id: &str,
        directory: &str,
        entry_name: &str,
        description: Option<&str>,
        tags_json: Option<&str>,
    ) -> Result<(), cap_fs::FsSyncError> {
        self.maybe_fail("upsert_meta")?;
        self.calls.lock().unwrap().push(SqlSyncCall::UpsertMeta {
            agent_id: agent_id.to_string(),
            directory: directory.to_string(),
            entry_name: entry_name.to_string(),
            description: description.map(|s| s.to_string()),
            tags_json: tags_json.map(|s| s.to_string()),
        });
        Ok(())
    }

    async fn delete_content(
        &self,
        agent_id: &str,
        file_path: &str,
    ) -> Result<(), cap_fs::FsSyncError> {
        self.maybe_fail("delete_content")?;
        self.calls.lock().unwrap().push(SqlSyncCall::DeleteContent {
            agent_id: agent_id.to_string(),
            file_path: file_path.to_string(),
        });
        Ok(())
    }

    async fn delete_meta(
        &self,
        agent_id: &str,
        directory: &str,
        entry_name: &str,
    ) -> Result<(), cap_fs::FsSyncError> {
        self.maybe_fail("delete_meta")?;
        self.calls.lock().unwrap().push(SqlSyncCall::DeleteMeta {
            agent_id: agent_id.to_string(),
            directory: directory.to_string(),
            entry_name: entry_name.to_string(),
        });
        Ok(())
    }
}

/// Mock for `advance_database::IndexRebuild`. Returns the canned `RebuildReport`
/// in `report` on every `rebuild_full` / `rebuild_agent` call. `calls` records
/// the count of invocations.
pub struct MockIndexRebuild {
    pub report: advance_database::RebuildReport,
    pub calls: std::sync::atomic::AtomicUsize,
}

impl MockIndexRebuild {
    pub fn new(report: advance_database::RebuildReport) -> Self {
        Self {
            report,
            calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

#[async_trait::async_trait]
impl advance_database::IndexRebuild for MockIndexRebuild {
    async fn rebuild_full(
        &self,
    ) -> Result<advance_database::RebuildReport, advance_database::DbError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(self.report.clone())
    }

    async fn rebuild_agent(
        &self,
        _agent_id: &str,
    ) -> Result<advance_database::RebuildReport, advance_database::DbError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(self.report.clone())
    }
}

/// Build a real CONTRACT-030 SqliteIndexHandle backed by an in-memory SQLite
/// database, wrapped in `Db030SqliteSync`. Returns both so tests can inspect
/// rows directly via the handle. Used by AC-12 integration tests T26/T26b/T27.
pub fn build_real_db_sync() -> (
    std::sync::Arc<dyn cap_fs::SqliteSync>,
    std::sync::Arc<dyn advance_database::SqliteIndexHandle>,
) {
    let handle = std::sync::Arc::new(
        advance_database::R2d2SqliteIndexHandle::new_in_memory().expect("in-memory handle"),
    );
    let trait_handle: std::sync::Arc<dyn advance_database::SqliteIndexHandle> = handle.clone();
    let sync: std::sync::Arc<dyn cap_fs::SqliteSync> =
        std::sync::Arc::new(cap_fs::Db030SqliteSync::new(trait_handle.clone()));
    (sync, trait_handle)
}

// ─────────────────────────────────────────────────────────────────────────────
// Slice D test fixtures.
// ─────────────────────────────────────────────────────────────────────────────

/// Recorded git-sync call from `MockGitSync`. Used by slice D AC-16 tests to
/// assert call ordering, agent_id, vpath, op, and the affected_paths shape.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct GitSyncCall {
    pub agent_id: String,
    pub op: cap_fs::GitSyncOp,
    pub vpath: String,
    pub physical_path: std::path::PathBuf,
    pub meta_yaml_path: std::path::PathBuf,
}

/// Recording mock for `cap_fs::GitSync`. Counter increments on every
/// `submit_fs_commit` invocation. `fail_on_call: Some(N)` triggers a failure
/// when the counter (1-indexed) reaches N.
#[allow(dead_code)]
pub struct MockGitSync {
    pub calls: std::sync::Mutex<Vec<GitSyncCall>>,
    pub fail_on_call: Option<usize>,
    pub counter: std::sync::atomic::AtomicUsize,
}

#[allow(dead_code)]
impl MockGitSync {
    pub fn new() -> Self {
        Self {
            calls: std::sync::Mutex::new(Vec::new()),
            fail_on_call: None,
            counter: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn fail_on(n: usize) -> Self {
        Self {
            calls: std::sync::Mutex::new(Vec::new()),
            fail_on_call: Some(n),
            counter: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn snapshot(&self) -> Vec<GitSyncCall> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl cap_fs::GitSync for MockGitSync {
    async fn submit_fs_commit(
        &self,
        agent_id: &str,
        op: cap_fs::GitSyncOp,
        vpath: &str,
        physical_path: std::path::PathBuf,
        meta_yaml_path: std::path::PathBuf,
    ) -> Result<(), cap_fs::GitSyncError> {
        let n = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        if Some(n) == self.fail_on_call {
            return Err(cap_fs::GitSyncError(format!(
                "injected git submit failure at call {n}"
            )));
        }
        self.calls.lock().unwrap().push(GitSyncCall {
            agent_id: agent_id.to_string(),
            op,
            vpath: vpath.to_string(),
            physical_path,
            meta_yaml_path,
        });
        Ok(())
    }
}

/// Build a real `Adv003GitSync` adapter backed by a freshly bootstrapped repo
/// at `repo_dir` (the workspace_root). Returns the `Arc<dyn GitSync>` wrapping
/// a real `DefaultGitCommitQueue`. The queue is owned by the returned
/// `_queue_holder` JoinHandle proxy — keep the `_holder` value alive for the
/// duration of the test (drop closes the queue). Used by SD-T44/T45/T46/T47/
/// T48/T49 real-git tests.
#[allow(dead_code)]
pub struct RealGitFixture {
    pub git_sync: std::sync::Arc<dyn cap_fs::GitSync>,
    pub queue: std::sync::Arc<advance_git::DefaultGitCommitQueue>,
    pub repo_path: std::path::PathBuf,
}

#[allow(dead_code)]
pub async fn bootstrap_real_git_sync(repo_dir: &std::path::Path) -> RealGitFixture {
    advance_git::bootstrap_repo_at(repo_dir).expect("bootstrap_repo_at");
    let queue = std::sync::Arc::new(
        advance_git::DefaultGitCommitQueue::spawn(repo_dir.to_path_buf())
            .expect("DefaultGitCommitQueue::spawn"),
    );
    let queue_trait: std::sync::Arc<dyn advance_git::GitCommitQueue> = queue.clone();
    let git_sync: std::sync::Arc<dyn cap_fs::GitSync> =
        std::sync::Arc::new(cap_fs::Adv003GitSync::new(queue_trait));
    RealGitFixture {
        git_sync,
        queue,
        repo_path: repo_dir.to_path_buf(),
    }
}

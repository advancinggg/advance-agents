//! OSS-6 — files-family wiring: provider install, queue split, hoist, teardown.
#![cfg(unix)]

use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Weak};

use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, mint_session, CapDecl, FixtureDriver, FixtureHome, FixtureHomeSpec, Http,
    HttpResponse,
};
use advance_runtime_compose::test_support::{ComposeProbe, MemoryComposeLog};
use advance_runtime_compose::{compose, ClientApiOptions, ComposedRuntime};
use serde_json::{json, Value};

fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

fn home(caps: &'static [&'static str], git: bool) -> FixtureHome {
    FixtureHome::new(FixtureHomeSpec {
        capabilities: caps.iter().copied().map(CapDecl::Granted).collect(),
        driver: FixtureDriver::None,
        git,
        providers_yaml: None,
    })
    .expect("home")
}

fn error_code(body: &Value) -> &str {
    body.pointer("/error/code")
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn error_details(body: &Value) -> Vec<&str> {
    body.pointer("/error/details")
        .and_then(Value::as_array)
        .map(|entries| entries.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

async fn list_root(rt: &ComposedRuntime, token: &str) -> HttpResponse {
    let ep = rt.client_api().expect("client api");
    Http::get(ep.socket_addr, "/client/files/entries?path=")
        .session(token)
        .send()
        .await
}

async fn mkdir(rt: &ComposedRuntime, token: &str, path: &str, key: &str) -> HttpResponse {
    let ep = rt.client_api().expect("client api");
    Http::post(ep.socket_addr, "/client/files:mkdir")
        .session(token)
        .idempotency_key(key)
        .json(json!({ "path": path }))
        .await
}

fn git_checkout_branch(home: &Path, name: &str) {
    let status = Command::new("git")
        .args(["checkout", "-b", name])
        .current_dir(home)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("git checkout");
    assert!(status.success(), "git checkout -b {name} failed: {status}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn files_provider_installed_on_fs_home() {
    let home = home(&["fs"], true);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(home.options(Arc::new(log), Arc::clone(&probe)), Vec::new())
        .await
        .expect("compose");
    let rec = probe.record();
    assert!(
        rec.files_core
            .as_ref()
            .is_some_and(|weak| weak.strong_count() > 0),
        "files_core on an fs home"
    );
    assert!(
        rec.git_queue
            .as_ref()
            .is_some_and(|weak| weak.strong_count() > 0),
        "agent git_queue stays on for fs"
    );
    assert_eq!(rec.pack_schema_attached, Some(true));
    let ep = rt.client_api().expect("client api");
    let tok = mint_session(&ep);
    let listed = list_root(&rt, &tok).await;
    assert_eq!(listed.status, 200, "{:?}", listed.body);
    assert_eq!(
        listed.body["data"]["vcs"],
        json!("ready"),
        "{:?}",
        listed.body
    );
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn files_provider_installed_without_fs_capability() {
    let home = home(&[], true);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(home.options(Arc::new(log), Arc::clone(&probe)), Vec::new())
        .await
        .expect("compose");
    let rec = probe.record();
    assert!(
        rec.files_core
            .as_ref()
            .is_some_and(|weak| weak.strong_count() > 0),
        "files_core without an fs capability"
    );
    assert!(
        rec.git_queue.is_none()
            || rec
                .git_queue
                .as_ref()
                .is_some_and(|weak| weak.strong_count() == 0),
        "agent git_queue stays off without fs/skills"
    );
    let ep = rt.client_api().expect("client api");
    let tok = mint_session(&ep);
    let listed = list_root(&rt, &tok).await;
    assert_eq!(listed.status, 200, "{:?}", listed.body);
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn files_hoist_keeps_l6_off_on_memory_llm_home_without_fs() {
    let home = home(&["memory", "llm"], true);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(home.options(Arc::new(log), Arc::clone(&probe)), Vec::new())
        .await
        .expect("compose");
    let rec = probe.record();
    assert!(
        rec.files_core
            .as_ref()
            .is_some_and(|weak| weak.strong_count() > 0),
        "files_core on a memory+llm home"
    );
    assert!(
        rec.git_queue.is_none()
            || rec
                .git_queue
                .as_ref()
                .is_some_and(|weak| weak.strong_count() == 0),
        "L6 stays off: agent git_queue is the fs∨skills gate"
    );
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_fs_home_pack_runtime_unchanged() {
    let home = home(&["memory", "llm"], true);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(home.options(Arc::new(log), Arc::clone(&probe)), Vec::new())
        .await
        .expect("compose");
    assert_eq!(
        probe.record().pack_schema_attached,
        None,
        "non-fs homes do not attach the workspace schema to pack_runtime"
    );
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn files_core_absent_when_api_not_bound() {
    let home = home(&["fs"], true);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe))
            .with_client_api(ClientApiOptions::Off),
        Vec::new(),
    )
    .await
    .expect("compose");
    let rec = probe.record();
    assert!(
        rec.files_core.is_none()
            || rec
                .files_core
                .as_ref()
                .is_some_and(|weak| weak.strong_count() == 0),
        "Off composes no files core"
    );
    assert!(
        rec.git_queue
            .as_ref()
            .is_some_and(|weak| weak.strong_count() > 0),
        "fs still owns the agent git_queue"
    );
    assert!(
        rec.meta_maintainer
            .as_ref()
            .is_some_and(|weak| weak.strong_count() > 0),
        "fs still owns the maintainer"
    );
    assert!(rt.client_api().is_none());
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn files_writes_refuse_when_repo_not_main() {
    let home = home(&["fs"], true);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(home.options(Arc::new(log), Arc::clone(&probe)), Vec::new())
        .await
        .expect("compose");
    git_checkout_branch(home.home(), "other");
    let ep = rt.client_api().expect("client api");
    let tok = mint_session(&ep);
    let resp = mkdir(&rt, &tok, "notes", "k-not-main").await;
    assert_eq!(resp.status, 409, "{:?}", resp.body);
    assert_eq!(error_code(&resp.body), "invalid_state", "{:?}", resp.body);
    let details = error_details(&resp.body);
    assert!(
        details.iter().any(|d| *d == "vcs_unavailable"),
        "{details:?}"
    );
    assert!(
        details.iter().any(|d| *d == "reason:not_main"),
        "{details:?}"
    );
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn files_core_shares_maintainer_and_queue() {
    let home = home(&["fs"], true);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(home.options(Arc::new(log), Arc::clone(&probe)), Vec::new())
        .await
        .expect("compose");
    let rec = probe.record();
    let core = rec
        .files_core
        .as_ref()
        .and_then(Weak::upgrade)
        .expect("files_core");
    let maintainer = rec
        .meta_maintainer
        .as_ref()
        .and_then(Weak::upgrade)
        .expect("meta_maintainer");
    let queue = rec
        .git_queue
        .as_ref()
        .and_then(Weak::upgrade)
        .expect("git_queue");
    assert!(
        Arc::ptr_eq(core.maintainer().expect("maintainer"), &maintainer),
        "files core shares the fs MetaMaintainer"
    );
    let lane = core.lane().expect("lane");
    assert_eq!(
        Arc::as_ptr(lane) as *const (),
        Arc::as_ptr(&queue) as *const (),
        "files core shares the per-repo git queue"
    );
    drop((core, maintainer, queue));
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn files_in_flight_write_survives_teardown() {
    let home = home(&["fs"], true);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(home.options(Arc::new(log), Arc::clone(&probe)), Vec::new())
        .await
        .expect("compose");
    let ep = rt.client_api().expect("client api");
    let tok = mint_session(&ep);
    let resp = mkdir(&rt, &tok, "notes", "k-teardown").await;
    assert_eq!(resp.status, 200, "{:?}", resp.body);
    let notes = home.home().join("notes");
    assert!(notes.is_dir(), "mkdir landed on disk before teardown");
    rt.shutdown().await.expect("shutdown");
    assert!(
        notes.is_dir(),
        "the in-flight mkdir remains after the queue drains"
    );
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn files_state_under_state_root_when_set() {
    let home = home(&["fs"], true);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(home.options(Arc::new(log), Arc::clone(&probe)), Vec::new())
        .await
        .expect("compose");
    assert!(
        !home.home().join(".runtime/files").exists(),
        "open does not mkdir .runtime/files at boot"
    );
    let ep = rt.client_api().expect("client api");
    let tok = mint_session(&ep);
    let resp = mkdir(&rt, &tok, "notes", "k-state").await;
    assert_eq!(resp.status, 200, "{:?}", resp.body);
    let rec = probe.record();
    let core = rec
        .files_core
        .as_ref()
        .and_then(Weak::upgrade)
        .expect("files_core");
    let files_state = core.files_state().clone();
    drop(core);
    assert!(
        files_state.starts_with(home.state_root().join("files")),
        "files_state {} is under the state root",
        files_state.display()
    );
    assert!(
        files_state.exists(),
        "a mutation creates files-state under the state root"
    );
    assert!(
        !home.home().join(".runtime/files").exists(),
        "files-state stays out of the home .runtime/files path"
    );
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

struct OneAgentTree {
    nodes: Vec<advance_shared_types::agent_tree::AgentNode>,
}

impl advance_shared_types::agent_tree::AgentTreeReader for OneAgentTree {
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
    fn agent_kind(&self, agent_id: &str) -> Option<advance_shared_types::agent_tree::AgentKind> {
        self.nodes
            .iter()
            .find(|n| n.id.0 == agent_id)
            .map(|n| n.kind.clone())
    }
    fn capabilities(&self, _agent_id: &str) -> Vec<advance_shared_types::agent_tree::Capability> {
        Vec::new()
    }
}

impl advance_shared_types::agent_tree::AgentTreeSnapshot for OneAgentTree {
    fn snapshot(&self) -> advance_shared_types::agent_tree::AgentTreeSnapshotData {
        advance_shared_types::agent_tree::AgentTreeSnapshotData {
            nodes: self.nodes.clone(),
            parent_of: Default::default(),
            children_of: Default::default(),
            peer_slug_map: Default::default(),
            handles: Default::default(),
            revision: 0,
        }
    }
}

struct ProbeSync {
    maintainer: Arc<cap_fs::MetaMaintainer>,
    held_at_enqueue: std::sync::Mutex<Vec<bool>>,
}

#[async_trait::async_trait]
impl cap_fs::GitSync for ProbeSync {
    async fn submit_fs_commit(
        &self,
        agent_id: &str,
        op: cap_fs::GitSyncOp,
        vpath: &str,
        physical_path: std::path::PathBuf,
        meta_yaml_path: std::path::PathBuf,
    ) -> Result<(), cap_fs::GitSyncError> {
        self.enqueue_fs_commit(agent_id, op, vpath, physical_path, meta_yaml_path)
            .await?
            .wait()
            .await
    }

    async fn enqueue_commit_with_message(
        &self,
        _agent_id: &str,
        _op: cap_fs::GitSyncOp,
        _vpath: &str,
        _paths: Vec<std::path::PathBuf>,
        _message: &str,
    ) -> Result<cap_fs::PendingFsCommit, cap_fs::GitSyncError> {
        let held = self.maintainer.try_acquire().is_none();
        self.held_at_enqueue.lock().expect("probe").push(held);
        Ok(cap_fs::PendingFsCommit::ready(Ok(())))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chained_workspace_fs_enqueues_under_lock() {
    use advance_runtime_compose::data_wiring::{ChainedWorkspaceFs, DataFsParts};
    use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus};
    use cap_data::WorkspaceFs;
    use cap_fs::{
        DefaultAtomicWriter, DefaultVirtualPathResolver, MetaMaintainer, MetaSchemaLoader,
        StubFileHistoryProvider, VirtualPathResolver,
    };

    let td = tempfile::TempDir::new().expect("tempdir");
    let root = td.path().to_path_buf();
    let agent = "root";
    let workspace = root.join(agent);
    std::fs::create_dir_all(&workspace).expect("workspace");
    let tree = Arc::new(OneAgentTree {
        nodes: vec![AgentNode {
            id: AgentId(agent.into()),
            kind: AgentKind::Root,
            parent: None,
            workspace_path: workspace.clone(),
            capabilities: Vec::new(),
            template_ref: None,
            status: AgentStatus::Active,
        }],
    });
    let resolver: Arc<dyn VirtualPathResolver> =
        Arc::new(DefaultVirtualPathResolver::new(root.clone(), tree));
    let schema = Arc::new(MetaSchemaLoader::new_with_default(
        root.join("meta-schema.yaml"),
    ));
    let maintainer = Arc::new(MetaMaintainer::new(
        Arc::clone(&schema),
        Arc::new(DefaultAtomicWriter),
    ));
    let probe = Arc::new(ProbeSync {
        maintainer: Arc::clone(&maintainer),
        held_at_enqueue: std::sync::Mutex::new(Vec::new()),
    });
    let fs = ChainedWorkspaceFs::new(DataFsParts {
        workspace_root: workspace,
        resolver,
        schema,
        writer: Arc::new(DefaultAtomicWriter),
        maintainer,
        git_sync: Some(probe.clone() as Arc<dyn cap_fs::GitSync>),
        history: Arc::new(StubFileHistoryProvider),
    });
    fs.write(agent, "note.md", b"hello", "data.create")
        .await
        .expect("write");
    let held = probe.held_at_enqueue.lock().expect("probe").clone();
    assert_eq!(held, vec![true], "write enqueue must run while L1 is held");
    fs.remove(agent, "note.md", "data.delete")
        .await
        .expect("remove");
    let held = probe.held_at_enqueue.lock().expect("probe").clone();
    assert_eq!(
        held,
        vec![true, true],
        "delete enqueue must run while L1 is held"
    );
}

struct OverBudgetPlanner;

impl advance_runtime_compose::client_api_git::RestorePlanner for OverBudgetPlanner {
    fn plan(
        &self,
        _req: &advance_git::RestoreTreeRequest,
    ) -> Result<advance_git::RestorePlanSummary, advance_git::GitError> {
        Ok(advance_git::RestorePlanSummary {
            path_count: advance_git::MAX_USER_CHANGES.saturating_add(1),
            blob_bytes: 0,
        })
    }
}

struct SmallPlanner;

impl advance_runtime_compose::client_api_git::RestorePlanner for SmallPlanner {
    fn plan(
        &self,
        _req: &advance_git::RestoreTreeRequest,
    ) -> Result<advance_git::RestorePlanSummary, advance_git::GitError> {
        Ok(advance_git::RestorePlanSummary {
            path_count: 1,
            blob_bytes: 1,
        })
    }
}

struct ProbeLane {
    maintainer: Arc<cap_fs::MetaMaintainer>,
    held_at_restore: std::sync::Mutex<Vec<bool>>,
    restore_calls: std::sync::atomic::AtomicUsize,
}

fn ready_lane_rx<T: Send>(
    value: Result<T, advance_git::GitError>,
) -> tokio::sync::oneshot::Receiver<Result<T, advance_git::GitError>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let _ = tx.send(value);
    rx
}

fn dummy_restore_outcome() -> advance_git::RestoreOutcome {
    advance_git::RestoreOutcome {
        status: advance_git::UserCommitStatus::Committed,
        sha: Some("0".repeat(40)),
        head_sha: Some("0".repeat(40)),
        adopted_sha: None,
        subject: "[user] restore".into(),
        label: advance_git::CommitLabel {
            op: "restore".into(),
            paths: vec!["note.md".into()],
            to: None,
            count: 1,
            lines_added: None,
            lines_removed: None,
            size_bytes: None,
            versioned: None,
            from_sha: None,
            checkpoint: None,
            title: None,
            change: None,
        },
        restored: vec!["note.md".into()],
        restored_count: 1,
        removed_count: 0,
        unversioned_overwritten: Vec::new(),
        unversioned_overwritten_count: 0,
    }
}

impl advance_git::UserCommitLane for ProbeLane {
    fn prepare(
        &self,
        _req: advance_git::PrepareRequest,
    ) -> tokio::sync::oneshot::Receiver<Result<advance_git::PrepareOutcome, advance_git::GitError>>
    {
        ready_lane_rx(Err(advance_git::GitError::WorkerClosed))
    }

    fn commit_user(
        &self,
        _req: advance_git::UserCommitRequest,
    ) -> tokio::sync::oneshot::Receiver<Result<advance_git::UserCommitOutcome, advance_git::GitError>>
    {
        ready_lane_rx(Err(advance_git::GitError::WorkerClosed))
    }

    fn save_version(
        &self,
        _req: advance_git::SaveVersionRequest,
    ) -> tokio::sync::oneshot::Receiver<
        Result<advance_git::SaveVersionOutcome, advance_git::GitError>,
    > {
        ready_lane_rx(Err(advance_git::GitError::WorkerClosed))
    }

    fn restore_tree(
        &self,
        _req: advance_git::RestoreTreeRequest,
    ) -> tokio::sync::oneshot::Receiver<Result<advance_git::RestoreOutcome, advance_git::GitError>>
    {
        self.restore_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let held = self.maintainer.try_acquire().is_none();
        self.held_at_restore.lock().expect("probe").push(held);
        ready_lane_rx(Ok(dummy_restore_outcome()))
    }
}

fn test_maintainer(root: &Path) -> Arc<cap_fs::MetaMaintainer> {
    let schema = Arc::new(cap_fs::MetaSchemaLoader::new_with_default(
        root.join("meta-schema.yaml"),
    ));
    Arc::new(cap_fs::MetaMaintainer::new(
        schema,
        Arc::new(cap_fs::DefaultAtomicWriter),
    ))
}

#[test]
fn gated_rollback_holds_meta_lock() {
    use advance_client_api::{GitHistoryProvider, Principal};
    use advance_runtime_compose::client_api_git::WiredGitHistoryProvider;

    let td = tempfile::TempDir::new().expect("tempdir");
    let maintainer = test_maintainer(td.path());
    let lane = Arc::new(ProbeLane {
        maintainer: Arc::clone(&maintainer),
        held_at_restore: std::sync::Mutex::new(Vec::new()),
        restore_calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let provider = WiredGitHistoryProvider::new(
        td.path().to_path_buf(),
        Some(Arc::clone(&maintainer)),
        Some(lane.clone() as Arc<dyn advance_git::UserCommitLane>),
    )
    .with_planner(Arc::new(SmallPlanner));
    let result = provider
        .rollback_to_checkpoint("root", "cp1", &Principal::operator("tester"))
        .expect("rollback");
    assert_eq!(result.restored_path_count, 1);
    let held = lane.held_at_restore.lock().expect("probe").clone();
    assert_eq!(held, vec![true], "restore_tree must run while L1 is held");
}

#[test]
fn operator_rollback_plan_capped_outside_l1() {
    use advance_client_api::{
        GitHistoryProvider, Principal, ProviderError, TOO_MANY_ENTRIES_DETAIL,
    };
    use advance_git::{RestorePlanSummary, MAX_ADOPT_BYTES, MAX_USER_CHANGES};
    use advance_runtime_compose::client_api_git::{
        operator_rollback_over_cap, WiredGitHistoryProvider,
    };

    assert!(operator_rollback_over_cap(&RestorePlanSummary {
        path_count: MAX_USER_CHANGES.saturating_add(1),
        blob_bytes: 0,
    }));
    assert!(operator_rollback_over_cap(&RestorePlanSummary {
        path_count: 1,
        blob_bytes: MAX_ADOPT_BYTES.saturating_add(1),
    }));
    assert!(!operator_rollback_over_cap(&RestorePlanSummary {
        path_count: MAX_USER_CHANGES,
        blob_bytes: MAX_ADOPT_BYTES,
    }));

    let td = tempfile::TempDir::new().expect("tempdir");
    let maintainer = test_maintainer(td.path());
    let lane = Arc::new(ProbeLane {
        maintainer: Arc::clone(&maintainer),
        held_at_restore: std::sync::Mutex::new(Vec::new()),
        restore_calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let provider = WiredGitHistoryProvider::new(
        td.path().to_path_buf(),
        Some(Arc::clone(&maintainer)),
        Some(lane.clone() as Arc<dyn advance_git::UserCommitLane>),
    )
    .with_planner(Arc::new(OverBudgetPlanner));
    let err = provider
        .rollback_to_checkpoint("root", "cp1", &Principal::operator("tester"))
        .expect_err("over-budget plan is refused");
    assert_eq!(
        err,
        ProviderError::InvalidState(TOO_MANY_ENTRIES_DETAIL.into())
    );
    let client = err.into_client_error();
    assert_eq!(client.details, [TOO_MANY_ENTRIES_DETAIL]);
    assert!(
        lane.held_at_restore.lock().expect("probe").is_empty(),
        "L1 must not be acquired for an over-budget plan"
    );
    assert_eq!(
        lane.restore_calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "restore_tree must not run for an over-budget plan"
    );
}

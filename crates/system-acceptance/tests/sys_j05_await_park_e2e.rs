//! Wave-11 Lane A — SYS-AC-014 / 018 / 251 e2e witnesses on the REAL wired
//! agent-loop await park/resume path.
//!
//! Drives the PRODUCTION `WasmMessageHandler::handle_message` with a `RunSession`
//! (the path `start.rs` wires) over the `guest-rust-await-write` fixture, which
//! PARKS at `await-replies` and (for 014) performs ONE `agent-fs::write` after
//! resume. The chain is the `awaitleg_b4a_park.rs` build-lane proof EXTENDED with
//! a real git workspace + the cap-fs `agent-fs` host-fn (Adv003GitSync over a
//! DefaultGitCommitQueue) so the post-resume write yields a `CommitType::Turn`
//! commit, plus a real `AwaitSessionManagerRef` so a pause closes the session
//! (the sys_j06 recipe).
//!
//!   - 014: parent parks → a CHILD agent's PRODUCT `send` resolves the await →
//!     the fiber resumes, writes one file, and the turn completes as exactly ONE
//!     `run.round_completed` + ONE `[turn]` commit carrying the file. NO harness
//!     on_reply/close/resume_run.
//!   - 018: parent parks → a PRODUCT `pause_run` closes the session → the await
//!     returns `session-closed` → the guest aborts WITHOUT writing → NO `[turn]`
//!     commit, filesystem unchanged. (014, same guest, is the non-vacuous baseline.)
//!   - 251: parent parks (ReturnPartial, short idle) → the REAL idle monitor
//!     resolves PartialTimeout past the idle timeout → the run resumes (the
//!     handler's RunSuspendSink fires on the Ok resolution). NO self-call.

#![allow(clippy::type_complexity)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use advance_cli::agent_loop::{RunSession, SessionRunCell, WasmMessageHandler};
use advance_cli::await_wiring::RunManagerSuspendSink;
use advance_git::{bootstrap_repo_at, DefaultGitCommitQueue, GitCommitQueue};
use advance_messaging::MailboxDispatcher;
use advance_reply_tracker::{
    register_reply_tracker_host_fns_with_suspend_sink, register_send_host_fn,
    AwaitSessionManagerImpl, AwaitSessionManagerRef, ManagerOptions, RunSuspendSink,
};
use advance_run_manager::{RunConfig, RunId, RunManager};
use advance_runtime::capability_injector::{CapabilityInjector, ComponentCtx};
use advance_runtime::circuit_breaker::{CircuitBreakerBus, DefaultCircuitBreakerBus};
use advance_runtime::config::WasmConfig;
use advance_runtime::host_registry::{HostRegistry, InMemoryHostRegistry};
use advance_runtime::wit_bindings::with_caps::advance::runtime::types as wit_types;
use advance_runtime::ComponentRuntime;
use advance_scheduler::hook::MessageHandler;
use advance_scheduler::types::ComponentConfig;
use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentStatus, AgentTreeReader, AgentTreeSnapshot,
    AgentTreeSnapshotData, Capability,
};
use advance_shared_types::await_session::AwaitSessionRef;
use advance_shared_types::capability::{CapParams, CapRequest, CapabilityId, GrantDecision};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{Message, MessageContext, MessageKind, MsgError, NotifyError};
use advance_shared_types::run::TaskRunStatus;
use advance_shared_types::traits::{EventBusEmit, GrantCheck};
use cap_fs::{
    register_agent_fs, Adv003GitSync, DefaultAtomicWriter, DefaultVirtualPathResolver, GitSync,
    MetaSchemaLoader, StubFileHistoryProvider, VirtualPathResolver,
};
use tempfile::TempDir;
use wit_component::ComponentEncoder;

const PARENT_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-await-write.core.wasm");
const CHILD_CORE: &[u8] = include_bytes!("../../runtime/tests/fixtures/guest-rust-send.core.wasm");

// Must match the fixtures.
const STATE_AWAIT_WRITE_OK: [u8; 4] = [0xAC, 0x08, 0x14, 0x77];
const STATE_AWAIT_INTERRUPTED: [u8; 4] = [0xAC, 0x01, 0x18, 0x00];
const STATE_AWAIT_PARTIAL_OK: [u8; 4] = [0xAC, 0x02, 0x51, 0x01];
const STATE_SEND_OK: [u8; 4] = [0x5E, 0x4D, 0x0C, 0x01]; // guest-rust-send send branch

// ── stubs ────────────────────────────────────────────────────────────

struct AllowAll;
impl GrantCheck for AllowAll {
    fn check(&self, _: &str, _: &str, _: &str, _: &CapParams) -> GrantDecision {
        GrantDecision::Allow
    }
}

/// MockDispatcher (deliver → Ok) so the parent's await-request keeps the session
/// Open (parks) — the same witness floor as `awaitleg_b4a_park.rs` / `fiber_suspend_resume`.
/// NOT part of the park/resume mechanism: the resume is driven by the child's
/// PRODUCT `send` (014) / a PRODUCT `pause_run` (018) / the REAL idle monitor (251).
struct MockDispatcher;
#[async_trait::async_trait]
impl MailboxDispatcher for MockDispatcher {
    async fn deliver(&self, _t: &str, _m: Message) -> Result<(), MsgError> {
        Ok(())
    }
    async fn reply(&self, _f: &str, _i: &str, _p: Vec<u8>) -> Result<(), MsgError> {
        Ok(())
    }
    async fn notify_agent(
        &self,
        _f: &str,
        _t: &str,
        _p: Vec<u8>,
        _c: Option<MessageContext>,
    ) -> Result<(), NotifyError> {
        Ok(())
    }
}

struct CapturingBus {
    events: Mutex<Vec<Event>>,
}
impl CapturingBus {
    fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }
    fn snapshot(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }
}
impl EventBusEmit for CapturingBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

/// Minimal single-agent tree rooting "parent" at its territory (the OneAgentTree
/// shape at lib.rs:692, id = "parent" so the fs resolver roots its writes there).
struct ParentTree {
    nodes: Vec<AgentNode>,
}
impl ParentTree {
    fn new(territory: PathBuf) -> Self {
        Self {
            nodes: vec![AgentNode {
                id: AgentId("parent".to_string()),
                kind: AgentKind::Root,
                parent: None,
                workspace_path: territory,
                capabilities: Vec::new(),
                template_ref: None,
                status: AgentStatus::Active,
            }],
        }
    }
}
impl AgentTreeReader for ParentTree {
    fn parent_of(&self, _: &str) -> Option<String> {
        None
    }
    fn children_of(&self, _: &str) -> Vec<String> {
        Vec::new()
    }
    fn siblings_of(&self, _: &str) -> Vec<String> {
        Vec::new()
    }
    fn agent_exists(&self, id: &str) -> bool {
        self.nodes.iter().any(|n| n.id.0 == id)
    }
    fn agent_kind(&self, id: &str) -> Option<AgentKind> {
        self.nodes
            .iter()
            .find(|n| n.id.0 == id)
            .map(|n| n.kind.clone())
    }
    fn capabilities(&self, _: &str) -> Vec<Capability> {
        Vec::new()
    }
}
impl AgentTreeSnapshot for ParentTree {
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

fn wasm_cfg() -> WasmConfig {
    WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    }
}

fn component_bytes(core: &[u8]) -> Vec<u8> {
    ComponentEncoder::default()
        .validate(true)
        .module(core)
        .expect("core wraps")
        .encode()
        .expect("component encoded")
}

fn count(events: &[Event], ty: &str) -> usize {
    events.iter().filter(|e| e.event_type == ty).count()
}

/// Walk HEAD (most-recent first) → (message, blob-paths) per commit.
fn commits(ws: &Path) -> Vec<(String, Vec<String>)> {
    let repo = match git2::Repository::open(ws) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let head = match repo.head().and_then(|h| h.peel_to_commit()) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut cur = Some(head);
    while let Some(c) = cur {
        let msg = c.message().unwrap_or("").to_string();
        let mut paths = Vec::new();
        if let Ok(tree) = c.tree() {
            let _ = tree.walk(git2::TreeWalkMode::PreOrder, |dir, entry| {
                if entry.kind() == Some(git2::ObjectType::Blob) {
                    paths.push(format!("{dir}{}", entry.name().unwrap_or("")));
                }
                git2::TreeWalkResult::Ok
            });
        }
        out.push((msg, paths));
        cur = c.parent(0).ok();
    }
    out
}

/// HEAD-committed blob whose path ends with `suffix` → its committed bytes.
fn head_blob_ending(ws: &Path, suffix: &str) -> Option<Vec<u8>> {
    let repo = git2::Repository::open(ws).ok()?;
    let tree = repo.head().ok()?.peel_to_commit().ok()?.tree().ok()?;
    let mut found = None;
    let _ = tree.walk(git2::TreeWalkMode::PreOrder, |dir, entry| {
        if entry.kind() == Some(git2::ObjectType::Blob) {
            let full = format!("{dir}{}", entry.name().unwrap_or(""));
            if full.ends_with(suffix) {
                found = Some(entry.id());
                return git2::TreeWalkResult::Abort;
            }
        }
        git2::TreeWalkResult::Ok
    });
    let blob = repo.find_blob(found?).ok()?;
    Some(blob.content().to_vec())
}

/// The fully-wired real chain: messaging (send + suspend-sink await) + agent-fs
/// (git-attributed) over a real git workspace, with the parent `WasmMessageHandler`
/// carrying a `RunSession` + the run already minted/parked-ready.
struct Rig {
    _ws: TempDir,
    ws_path: PathBuf,
    territory: PathBuf,
    bus: Arc<CapturingBus>,
    rm: Arc<RunManager>,
    rid: RunId,
    handler: Arc<dyn MessageHandler>,
    init_state: Vec<u8>,
    runtime: Arc<ComponentRuntime>,
    injector: Arc<CapabilityInjector>,
}

async fn build_rig(parent_config: &[u8]) -> Rig {
    let ws = TempDir::new().expect("await-park tempdir");
    let ws_path = ws.path().to_path_buf();
    bootstrap_repo_at(&ws_path).expect("bootstrap_repo_at");
    let territory = ws_path.join("parent");
    std::fs::create_dir_all(&territory).expect("territory dir");

    let bus = Arc::new(CapturingBus::new());
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();

    // Git commit queue (emits git.commit) + Adv003GitSync → CommitType::Turn on fs.write.
    let queue = Arc::new(
        DefaultGitCommitQueue::spawn_with_event_bus(ws_path.clone(), bus_dyn.clone())
            .expect("git queue spawn"),
    );
    let queue_trait: Arc<dyn GitCommitQueue> = queue.clone();
    let git_sync: Arc<dyn GitSync> = Arc::new(Adv003GitSync::new(queue_trait));

    // Messaging chain: manager → AwaitSessionManagerRef → RunManager(with ref) →
    // RunManagerSuspendSink → sink-equipped await + send host-fns.
    let dispatcher: Arc<dyn MailboxDispatcher> = Arc::new(MockDispatcher);
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions::default(),
    ));
    let aref: Arc<dyn AwaitSessionRef> =
        Arc::new(AwaitSessionManagerRef::new(Arc::clone(&manager)));
    let rm = Arc::new(RunManager::new(bus_dyn.clone()).with_await_session_ref(aref));
    let rid = rm
        .ensure_run("parent", "parent", RunConfig::default())
        .expect("ensure_run");

    let cell: SessionRunCell = Arc::new(OnceLock::new());
    cell.set(rid.clone()).expect("cell empty");

    let sink: Arc<dyn RunSuspendSink> = Arc::new(RunManagerSuspendSink::new(rm.clone()));

    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    register_send_host_fn(&*registry, Arc::clone(&manager));
    register_reply_tracker_host_fns_with_suspend_sink(
        &*registry,
        Arc::clone(&manager),
        bus_dyn.clone(),
        Some(sink),
    );

    // agent-fs (slice A/B mode: trio None; git_sync Some → fs.write commits [turn]).
    let resolver: Arc<dyn VirtualPathResolver> = Arc::new(DefaultVirtualPathResolver::new(
        ws_path.clone(),
        Arc::new(ParentTree::new(territory.clone())) as Arc<dyn AgentTreeSnapshot>,
    ));
    register_agent_fs(
        &*registry,
        resolver,
        bus_dyn.clone(),
        Arc::new(MetaSchemaLoader::new_with_default(PathBuf::new())),
        Arc::new(StubFileHistoryProvider),
        Arc::new(DefaultAtomicWriter),
        None,
        None,
        None,
        None,
        Some(git_sync),
    );

    // Injector + runtime + parent component.
    let grant: Arc<dyn GrantCheck> = Arc::new(AllowAll);
    let breaker: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let injector = Arc::new(CapabilityInjector::new(registry, grant, breaker));
    let runtime = Arc::new(ComponentRuntime::new(&wasm_cfg()).expect("runtime"));
    let parent_loaded = runtime
        .load_component(&component_bytes(PARENT_CORE))
        .expect("parent component loads");
    let parent_caps = vec![
        CapRequest {
            capability: CapabilityId::from("messaging"),
        },
        CapRequest {
            capability: CapabilityId::from("fs"),
        },
    ];

    let handler: Arc<dyn MessageHandler> = Arc::new(
        WasmMessageHandler::new(
            runtime.clone(),
            parent_loaded,
            injector.clone(),
            parent_caps,
            "parent".to_string(),
            "trace-await-park".to_string(),
        )
        .with_run_session(RunSession {
            run_manager: rm.clone(),
            cell: cell.clone(),
        }),
    );
    let init_state = handler
        .init(ComponentConfig {
            id: "test-parent".to_string(),
            config_data: Some(parent_config.to_vec()),
            trigger_context: None,
        })
        .await
        .expect("parent init (cell set → ctx.run_id populated)");
    assert_eq!(
        init_state, parent_config,
        "init returns the routing-intent state"
    );

    Rig {
        _ws: ws,
        ws_path,
        territory,
        bus,
        rm,
        rid,
        handler,
        init_state,
        runtime,
        injector,
    }
}

fn parent_msg(id: &str) -> Message {
    Message {
        id: id.to_string(),
        kind: MessageKind::User,
        from: "user:harness".to_string(),
        to: "parent".to_string(),
        payload: vec![],
        context: None,
        timestamp: std::time::SystemTime::now(),
        origin: None,
    }
}

async fn wait_parked(rm: &RunManager, rid: &RunId) -> bool {
    for _ in 0..400 {
        if let Ok(st) = rm.run_status(rid) {
            if matches!(st.status, TaskRunStatus::Suspended) && st.root_await.is_some() {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

/// Drive the CHILD product `send` (guest-rust-send as "test-target" → send("agent:parent")).
async fn drive_child_send(rig: &Rig) {
    let child_loaded = rig
        .runtime
        .load_component(&component_bytes(CHILD_CORE))
        .expect("child component loads");
    let child_caps = vec![CapRequest {
        capability: CapabilityId::from("messaging"),
    }];
    let child_ctx = ComponentCtx::new("test-target".into(), "trace-child".into(), Vec::new());
    let (child_bindings, mut child_store) = rig
        .runtime
        .instantiate_advance_host_with_capabilities_async(
            &child_loaded,
            child_ctx,
            &child_caps,
            &*rig.injector,
        )
        .await
        .expect("child instantiate");
    let child_state = child_bindings
        .advance_runtime_message_driven()
        .call_init(
            &mut child_store,
            &wit_types::ComponentConfig {
                id: "test-child".into(),
                config_data: Some(b"send".to_vec()),
                trigger_context: None,
            },
        )
        .await
        .expect("child init call")
        .expect("child init Ok");
    let child_action = child_bindings
        .advance_runtime_message_driven()
        .call_handle_message(
            &mut child_store,
            &wit_types::Message { payload: vec![] },
            &child_state,
        )
        .await
        .expect("child handle-message call")
        .expect("child handle-message Ok");
    assert_eq!(
        child_action.new_state, STATE_SEND_OK,
        "child returned the send witness state → the product send ran + routed"
    );
}

// ── SYS-AC-014 ───────────────────────────────────────────────────────

/// Children replies aggregate into a SINGLE completed parent turn — one
/// `run.round_completed` AND one `[turn]` commit (the post-resume write), not
/// multiple turns. Product-`send`-driven resume; NO harness on_reply.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_014_single_completed_parent_turn_via_product_send() {
    let rig = build_rig(b"await-write").await;
    let rid = rig.rid.clone();

    let handler = rig.handler.clone();
    let init_state = rig.init_state.clone();
    let parent_task = tokio::spawn(async move {
        handler
            .handle_message(&parent_msg("msg-014"), init_state)
            .await
    });

    // Assert PARKED before resolving (else the single-turn claim is vacuous).
    assert!(
        wait_parked(&rig.rm, &rid).await,
        "parent run must enter Suspended (parked at await)"
    );

    // Product send resolves the await (NO harness on_reply/close/resume_run).
    drive_child_send(&rig).await;

    // Parent fiber resumes, writes, turn completes.
    let result = tokio::time::timeout(Duration::from_secs(30), parent_task)
        .await
        .expect("parent handle-message must complete within 30s after the child send")
        .expect("parent task panicked")
        .expect("parent handle-message Ok");
    assert_eq!(
        result.new_state, STATE_AWAIT_WRITE_OK,
        "parent resumed: await returned Ok and the guest wrote the witness file"
    );

    // Run back Active, root_await cleared.
    let st = rig.rm.run_status(&rid).expect("run_status after resume");
    assert!(
        matches!(st.status, TaskRunStatus::Active),
        "run resumed to Active (got {:?})",
        st.status
    );
    assert!(st.root_await.is_none(), "root_await cleared on resume");

    // One each of the run-lifecycle triple; suspended precedes resumed; one turn.
    let events = rig.bus.snapshot();
    assert_eq!(
        count(&events, "run.suspended"),
        1,
        "one run.suspended (the park)"
    );
    assert_eq!(
        count(&events, "run.resumed"),
        1,
        "one run.resumed (the product-send resume)"
    );
    assert_eq!(
        count(&events, "run.round_completed"),
        1,
        "exactly one run.round_completed across the fan-out (one turn boundary)"
    );
    let idx_susp = events
        .iter()
        .position(|e| e.event_type == "run.suspended")
        .unwrap();
    let idx_res = events
        .iter()
        .position(|e| e.event_type == "run.resumed")
        .unwrap();
    assert!(idx_susp < idx_res, "run.suspended precedes run.resumed");
    assert!(
        format!("{:?}", events[idx_res]).contains("await_complete"),
        "run.resumed reason is await_complete: {:?}",
        events[idx_res]
    );

    // The "one turn commit" conjunct: exactly one [turn] commit, whose tree carries
    // the post-resume write bytes (committed-tree anti-fake-green).
    let cs = commits(&rig.ws_path);
    let turn_commits: Vec<&(String, Vec<String>)> =
        cs.iter().filter(|(m, _)| m.starts_with("[turn]")).collect();
    assert_eq!(
        turn_commits.len(),
        1,
        "exactly one [turn] commit across the resumed turn"
    );
    let blob = head_blob_ending(&rig.ws_path, "await-out.txt")
        .expect("HEAD turn-commit tree contains the written file");
    assert_eq!(
        blob, b"await-resumed-write",
        "committed blob is the post-resume write bytes"
    );
}

// ── SYS-AC-018 ───────────────────────────────────────────────────────

/// An interrupted (pause-mid-await) turn unwinds with NO turn commit for the
/// aborted round (filesystem unchanged). The 014 path (same guest) DOES write +
/// commit on the Ok branch — so this absence is non-vacuous.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_018_interrupted_turn_no_commit_fs_unchanged() {
    let rig = build_rig(b"await-write").await;
    let rid = rig.rid.clone();

    let handler = rig.handler.clone();
    let init_state = rig.init_state.clone();
    let parent_task = tokio::spawn(async move {
        handler
            .handle_message(&parent_msg("msg-018"), init_state)
            .await
    });

    assert!(
        wait_parked(&rig.rm, &rid).await,
        "parent run must enter Suspended (parked at await)"
    );

    // Product pause_run while Suspended → closes the live await session.
    rig.rm
        .pause_run(&rid, "operator-pause".to_string())
        .await
        .expect("pause_run");

    // The await returns session-closed → the guest aborts WITHOUT writing.
    let result = tokio::time::timeout(Duration::from_secs(30), parent_task)
        .await
        .expect("parent handle-message must complete after pause")
        .expect("parent task panicked")
        .expect("parent handle-message Ok");
    assert_eq!(
        result.new_state, STATE_AWAIT_INTERRUPTED,
        "the await returned Err(session-closed) → the guest took the no-write branch"
    );

    // Run is Paused; no resume fired (resume is gated on Ok, never Err(SessionClosed)).
    assert!(
        matches!(
            rig.rm.run_status(&rid).expect("status").status,
            TaskRunStatus::Paused
        ),
        "run is Paused after pause_run"
    );
    let events = rig.bus.snapshot();
    assert_eq!(
        count(&events, "run.suspended"),
        1,
        "the turn DID park (non-vacuous)"
    );
    assert_eq!(
        count(&events, "run.resumed"),
        0,
        "NO resume on the interrupted round"
    );

    // No [turn] commit for the aborted round + the file never existed (fs unchanged).
    let cs = commits(&rig.ws_path);
    assert!(
        cs.iter().all(|(m, _)| !m.starts_with("[turn]")),
        "no [turn] commit was written for the aborted round (got: {:?})",
        cs.iter().map(|(m, _)| m).collect::<Vec<_>>()
    );
    assert!(
        cs.iter()
            .all(|(_, paths)| paths.iter().all(|p| !p.ends_with("await-out.txt"))),
        "no commit tree contains the await-out.txt write"
    );
    assert!(
        head_blob_ending(&rig.ws_path, "await-out.txt").is_none(),
        "no committed await-out.txt blob"
    );
    assert!(
        !rig.territory.join("await-out.txt").exists()
            && !rig.ws_path.join("await-out.txt").exists(),
        "the file was never written to the working tree (filesystem unchanged)"
    );
}

// ── SYS-AC-251 ───────────────────────────────────────────────────────

/// After a ReturnPartial idle timeout the parent turn is resumed — the REAL
/// per-session idle monitor resolves PartialTimeout and the handler's
/// RunSuspendSink resumes the run (run.suspended → run.resumed → round_completed).
/// NO self-call; driven solely by the real idle monitor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sys_ac_251_parent_turn_resumed_after_idle_timeout() {
    let rig = build_rig(b"await-partial").await;
    let rid = rig.rid.clone();

    let handler = rig.handler.clone();
    let init_state = rig.init_state.clone();
    let parent_task = tokio::spawn(async move {
        handler
            .handle_message(&parent_msg("msg-251"), init_state)
            .await
    });

    assert!(
        wait_parked(&rig.rm, &rid).await,
        "parent run must enter Suspended (parked at await)"
    );

    // Send NO reply. Let the REAL idle monitor (tick 5s, idle_timeout 1s) fire and
    // resolve PartialTimeout → resume. Real-time wait (the monitor uses tokio sleeps).
    let result = tokio::time::timeout(Duration::from_secs(40), parent_task)
        .await
        .expect("parent handle-message must resume + complete after the idle timeout")
        .expect("parent task panicked")
        .expect("parent handle-message Ok");
    assert_eq!(
        result.new_state, STATE_AWAIT_PARTIAL_OK,
        "parent resumed: await returned Ok(PartialTimeout) and the guest produced the witness state"
    );

    let st = rig
        .rm
        .run_status(&rid)
        .expect("run_status after idle resume");
    assert!(
        matches!(st.status, TaskRunStatus::Active),
        "run resumed to Active (got {:?})",
        st.status
    );
    assert!(
        st.root_await.is_none(),
        "root_await cleared on the idle resume"
    );

    let events = rig.bus.snapshot();
    assert_eq!(
        count(&events, "run.suspended"),
        1,
        "one run.suspended (the park)"
    );
    assert_eq!(
        count(&events, "run.resumed"),
        1,
        "one run.resumed (the idle-timeout resume)"
    );
    assert_eq!(
        count(&events, "run.round_completed"),
        1,
        "exactly one run.round_completed"
    );
    let idx_susp = events
        .iter()
        .position(|e| e.event_type == "run.suspended")
        .unwrap();
    let idx_res = events
        .iter()
        .position(|e| e.event_type == "run.resumed")
        .unwrap();
    assert!(idx_susp < idx_res, "run.suspended precedes run.resumed");
}

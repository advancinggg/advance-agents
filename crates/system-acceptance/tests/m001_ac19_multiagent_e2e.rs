//! Wave-20 lane m001loop — MODULE-001-AC-19 witness: the first true cross-module
//! multi-agent e2e, over a REAL runtime-spawned child, with all production components.
//!
//! Three legs, one hand-wired rig of REAL production components (the SUT `.agents()`
//! path bakes COLON `ComponentCtx` ids that break `await-replies` admission, so this
//! test hand-wires — the established drive-prod-fn precedent):
//!
//!   leg-a (core e2e): the parent's `await-replies` request IS the cross-agent message —
//!     the manager's admission dispatches it via the REAL `MailboxDispatcherImpl` into the
//!     runtime-spawned child's mailbox; the child's OWN real `AgentLoopDriverImpl` serve
//!     loop wakes on that delivery, runs `handle-message`, and issues a real `send`
//!     (`SendHandler`→`try_route_reply`→`on_reply`) → the parent's `await-replies` fiber
//!     (suspended via `call_async`) resumes. Oracle: event-grounded (`run.suspended`==1 +
//!     `run.resumed` reason=await_complete) + a recording send-spy capturing the child's
//!     `(target, payload)`. The parent-guest fixed-string write is NOT the oracle
//!     (`FailedDispatch` is also `Ok`, so the write does not discriminate bridge-off).
//!   leg-b: single-session pause (via pause_run) of a suspended parent → `session-closed`
//!     (cancel_run is the symmetric single-run session-close path, not separately driven).
//!   leg-c: deadlock via the `forms_cycle` ancestry walk over the runtime-spawned tree.
//!
//! Discriminators: bridge-off (no colon routing entry → `FailedDispatch` → 0 suspended);
//! child-loop-off (parked, request queued, 0 resumed); runtime-spawn (child absent from
//! the bare `AgentTreeStore` before `spawn_child`, authored by it after).
//!
//! Two trees, by design (the production colon/bare split): a COLON routing tree for the
//! dispatcher, a BARE `AgentTreeStore` for `spawn_child` + the leg-c deadlock gate. The
//! spawned child's COLON routing entry is harness-supplied — the disclosed mirror of the
//! UNBUILT production per-child daemon routing registration (why REQ-030 stays Partial).
//! The deadlock gate is prod-dormant (`agent_tree=None` in the shipped daemon); this
//! arms it test-side over the REAL `forms_cycle` production walk.

#![allow(clippy::type_complexity)]

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use advance_cli::agent_loop::{build_agent_loop, RunSession, SessionRunCell, WasmMessageHandler};
use advance_cli::await_wiring::RunManagerSuspendSink;
use advance_git::{bootstrap_repo_at, DefaultGitCommitQueue, GitCommitQueue};
use advance_messaging::{MailboxDispatcher, MailboxDispatcherImpl, MailboxStore};
use advance_reply_tracker::{
    register_reply_tracker_host_fns_with_suspend_sink, AwaitSessionManagerImpl,
    AwaitSessionManagerRef, ManagerOptions, RunSuspendSink, SendHandler,
};
use advance_run_manager::{RunConfig, RunId, RunManager};
use advance_runtime::capability_injector::CapabilityInjector;
use advance_runtime::circuit_breaker::{CircuitBreakerBus, DefaultCircuitBreakerBus};
use advance_runtime::config::WasmConfig;
use advance_runtime::host_registry::{
    HostCallContext, HostCallError, HostFunctionHandler, HostFunctionSpec, HostRegistry,
    InMemoryHostRegistry,
};
use advance_runtime::ComponentRuntime;
use advance_scheduler::hook::MessageHandler;
use advance_scheduler::types::{ComponentConfig, ComponentId, WasmInstance};
use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentStatus, AgentTreeReader, AgentTreeSnapshot,
    AgentTreeSnapshotData, Capability,
};
use advance_shared_types::await_session::{
    AgentAwaitRequest, AwaitMode, AwaitOptions, AwaitRequest, AwaitSessionRef, OrchestrationError,
    TimeoutPolicy,
};
use advance_shared_types::capability::{CapParams, CapRequest, CapabilityId, GrantDecision};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::Message;
use advance_shared_types::run::TaskRunStatus;
use advance_shared_types::traits::{EventBusEmit, GrantCheck};
use cap_fs::{
    register_agent_fs, Adv003GitSync, DefaultAtomicWriter, DefaultVirtualPathResolver, GitSync,
    MetaSchemaLoader, StubFileHistoryProvider, VirtualPathResolver,
};
use cap_lifecycle::{
    AgentTreeStore, DefaultSpawner, SpawnChildConfig, SpawnError, Spawner, SpawnerSubsetGate,
};
use tempfile::TempDir;
use wasmtime::component::Val;
use wit_component::ComponentEncoder;

const PARENT_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-await-write.core.wasm");
const CHILD_CORE: &[u8] = include_bytes!("../../runtime/tests/fixtures/guest-rust-send.core.wasm");

// Must match the fixtures.
const STATE_AWAIT_WRITE_OK: [u8; 4] = [0xAC, 0x08, 0x14, 0x77];
/// guest-rust-await-write returns this on the Err(session-closed) no-write branch.
const STATE_AWAIT_INTERRUPTED: [u8; 4] = [0xAC, 0x01, 0x18, 0x00];
/// guest-rust-send sends to "agent:parent" with this payload.
const SEND_PAYLOAD: [u8; 4] = [0x5E, 0x4D, 0xB3, 0x01];
const PARENT_ID_BARE: &str = "parent";
const PARENT_ID_COLON: &str = "agent:parent";
const CHILD_ID_BARE: &str = "test-target"; // guest-rust-await-write awaits "agent:test-target"
const CHILD_ID_COLON: &str = "agent:test-target";

// ── stubs ────────────────────────────────────────────────────────────

struct AllowAll;
impl GrantCheck for AllowAll {
    fn check(&self, _: &str, _: &str, _: &str, _: &CapParams) -> GrantDecision {
        GrantDecision::Allow
    }
}

/// AllowAll subset gate (the CONTRACT-122 seam — tests provide their own impl).
struct AllowAllSubset;
impl SpawnerSubsetGate for AllowAllSubset {
    fn check(&self, _parent: &[Capability], _child: &[Capability]) -> Result<(), SpawnError> {
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

/// Test-local interior-mutable COLON-keyed routing tree (the `ParentTree` precedent,
/// made mutable so the spawned child's colon id can be bridged in AFTER `spawn_child`).
/// The real `MailboxDispatcherImpl` holds this as `Arc<dyn AgentTreeReader>` and reads it
/// on every `deliver` via `validate_routing` (parent/child adjacency + `agent_exists`).
#[derive(Clone)]
struct RoutingTree {
    parents: Arc<Mutex<HashMap<String, Option<String>>>>,
}
impl RoutingTree {
    fn new() -> Self {
        Self {
            parents: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    fn add_root(&self, id: &str) {
        self.parents.lock().unwrap().insert(id.to_string(), None);
    }
    fn add_child(&self, id: &str, parent: &str) {
        self.parents
            .lock()
            .unwrap()
            .insert(id.to_string(), Some(parent.to_string()));
    }
}
impl AgentTreeReader for RoutingTree {
    fn parent_of(&self, id: &str) -> Option<String> {
        self.parents.lock().unwrap().get(id).cloned().flatten()
    }
    fn children_of(&self, id: &str) -> Vec<String> {
        self.parents
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, p)| p.as_deref() == Some(id))
            .map(|(k, _)| k.clone())
            .collect()
    }
    fn siblings_of(&self, id: &str) -> Vec<String> {
        let parents = self.parents.lock().unwrap();
        let me = parents.get(id).cloned().flatten();
        match me {
            Some(p) => parents
                .iter()
                .filter(|(k, pp)| k.as_str() != id && pp.as_deref() == Some(p.as_str()))
                .map(|(k, _)| k.clone())
                .collect(),
            None => Vec::new(),
        }
    }
    fn agent_exists(&self, id: &str) -> bool {
        self.parents.lock().unwrap().contains_key(id)
    }
    fn agent_kind(&self, id: &str) -> Option<AgentKind> {
        self.parents.lock().unwrap().get(id).map(|p| {
            if p.is_none() {
                AgentKind::Root
            } else {
                AgentKind::Child
            }
        })
    }
    fn capabilities(&self, _: &str) -> Vec<Capability> {
        Vec::new()
    }
}

/// Recording send-spy: a custom `send` `HostFunctionHandler` registered as the SINGLE
/// `send` spec (the registry is append-only — duplicate `(namespace,name)` fails at
/// linker wiring), recording the child's `(target, payload)` Vals then delegating to the
/// REAL `SendHandler` (records-then-delegates; NOT a mock — the real reply routing runs).
struct RecordingSendSpy {
    inner: SendHandler,
    recorded: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
}
fn decode_payload_val(v: Option<&Val>) -> Option<Vec<u8>> {
    match v {
        Some(Val::List(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                match it {
                    Val::U8(b) => out.push(*b),
                    _ => return None,
                }
            }
            Some(out)
        }
        _ => None,
    }
}
impl HostFunctionHandler for RecordingSendSpy {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        // Record (target, payload) BEFORE delegating (params are moved into inner.call).
        if let Some(Val::String(t)) = params.first() {
            if let Some(payload) = decode_payload_val(params.get(1)) {
                self.recorded.lock().unwrap().push((t.clone(), payload));
            }
        }
        self.inner.call(ctx, params, results_len)
    }
}

fn register_recording_send_spy(
    registry: &dyn HostRegistry,
    manager: Arc<AwaitSessionManagerImpl>,
    recorded: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
) {
    registry.register(HostFunctionSpec {
        capability: "messaging".to_string(),
        namespace: "advance:runtime/agent-messaging@0.1.0".to_string(),
        name: "send".to_string(),
        handler: Arc::new(RecordingSendSpy {
            inner: SendHandler::new(manager),
            recorded,
        }),
        idempotent: false,
    });
}

/// Minimal single-agent tree rooting "parent" at its territory (for the cap-fs resolver
/// only — the parent's post-resume write resolves under this; the child guest does no fs).
struct ParentTree {
    territory: PathBuf,
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
        id == PARENT_ID_BARE
    }
    fn agent_kind(&self, id: &str) -> Option<AgentKind> {
        (id == PARENT_ID_BARE).then_some(AgentKind::Root)
    }
    fn capabilities(&self, _: &str) -> Vec<Capability> {
        Vec::new()
    }
}
impl AgentTreeSnapshot for ParentTree {
    fn snapshot(&self) -> AgentTreeSnapshotData {
        AgentTreeSnapshotData {
            nodes: vec![AgentNode {
                id: AgentId(PARENT_ID_BARE.to_string()),
                kind: AgentKind::Root,
                parent: None,
                workspace_path: self.territory.clone(),
                capabilities: Vec::new(),
                template_ref: None,
                status: AgentStatus::Active,
            }],
            parent_of: HashMap::new(),
            children_of: HashMap::new(),
            peer_slug_map: HashMap::new(),
            revision: 0,
        }
    }
}

fn cap(name: &str) -> Capability {
    Capability {
        id: CapabilityId::from(name),
        params: CapParams::empty(),
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

/// The fully-wired real chain: a REAL `MailboxDispatcherImpl` over a colon routing tree,
/// a REAL bare `AgentTreeStore` + `DefaultSpawner`, the messaging chain (recording send-spy
/// + suspend-sink await), agent-fs over a real git workspace, and the parent
/// `WasmMessageHandler` carrying a `RunSession`. The child is ALWAYS spawned at runtime;
/// `bridge`/`child_loop` toggle the controls.
struct Rig {
    _ws: TempDir,
    bus: Arc<CapturingBus>,
    rm: Arc<RunManager>,
    rid: RunId,
    manager: Arc<AwaitSessionManagerImpl>,
    handler: Arc<WasmMessageHandler>,
    init_state: Vec<u8>,
    recorded_sends: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
    mailbox_store: Arc<MailboxStore>,
    child_task: Option<tokio::task::JoinHandle<()>>,
    child_absent_pre_spawn: bool,
    child_present_post_spawn: bool,
}
impl Drop for Rig {
    fn drop(&mut self) {
        if let Some(t) = self.child_task.take() {
            t.abort();
        }
    }
}

async fn build_rig(parent_config: &[u8], bridge: bool, child_loop: bool) -> Rig {
    let ws = TempDir::new().expect("tempdir");
    let ws_path = ws.path().to_path_buf();
    bootstrap_repo_at(&ws_path).expect("bootstrap_repo_at");
    let territory = ws_path.join(PARENT_ID_BARE);
    std::fs::create_dir_all(&territory).expect("territory dir");

    let bus = Arc::new(CapturingBus::new());
    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();

    // Git commit queue + Adv003GitSync → CommitType::Turn on the parent's post-resume write.
    let queue = Arc::new(
        DefaultGitCommitQueue::spawn_with_event_bus(ws_path.clone(), bus_dyn.clone())
            .expect("git queue"),
    );
    let queue_trait: Arc<dyn GitCommitQueue> = queue.clone();
    let git_sync: Arc<dyn GitSync> = Arc::new(Adv003GitSync::new(queue_trait));

    // ── Bare AgentTreeStore + DefaultSpawner (runtime spawn + leg-c deadlock ancestry). ──
    let bare_store = AgentTreeStore::new(ws_path.clone()).expect("bare AgentTreeStore");
    bare_store
        .insert_root(AgentNode {
            id: AgentId(PARENT_ID_BARE.to_string()),
            kind: AgentKind::Root,
            parent: None,
            workspace_path: territory.clone(),
            capabilities: vec![cap("messaging"), cap("fs")],
            template_ref: None,
            status: AgentStatus::Active,
        })
        .expect("insert parent root");
    let spawner = DefaultSpawner::new(bare_store.clone(), Arc::new(AllowAllSubset));

    // Runtime-spawn discriminator: child absent BEFORE spawn_child.
    let child_absent_pre_spawn = !bare_store
        .snapshot()
        .nodes
        .iter()
        .any(|n| n.id.0 == CHILD_ID_BARE);

    // REAL runtime spawn_child (the cross-module growth path).
    let spawned = spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId(PARENT_ID_BARE.to_string()),
            child_id: AgentId(CHILD_ID_BARE.to_string()),
            child_workspace_path: PathBuf::from("children").join(CHILD_ID_BARE),
            capabilities: vec![cap("messaging")],
            template_ref: None,
            binary: None,
        })
        .expect("spawn_child");
    assert_eq!(
        spawned.0, CHILD_ID_BARE,
        "spawn_child returns the bare child id"
    );
    let child_present_post_spawn = bare_store
        .snapshot()
        .nodes
        .iter()
        .any(|n| n.id.0 == CHILD_ID_BARE);

    // ── COLON routing tree for the real dispatcher; bridge the spawned child's colon id. ──
    let routing_tree = RoutingTree::new();
    routing_tree.add_root(PARENT_ID_COLON);
    if bridge {
        // The colon routing id is DERIVED from the spawn result (harness-supplied mirror
        // of the unbuilt production per-child daemon routing registration).
        routing_tree.add_child(&format!("agent:{}", spawned.0), PARENT_ID_COLON);
    }

    // ── Real MailboxStore + MailboxDispatcherImpl over the colon routing tree. ──
    let mailbox_store = Arc::new(MailboxStore::new(std::num::NonZeroUsize::new(64).unwrap()));
    let dispatcher: Arc<dyn MailboxDispatcher> = Arc::new(MailboxDispatcherImpl::new(
        mailbox_store.clone(),
        Arc::new(routing_tree.clone()) as Arc<dyn AgentTreeReader>,
    ));

    // ── Messaging chain: manager (deadlock gate armed) → RunManager → suspend sink. ──
    let manager = Arc::new(AwaitSessionManagerImpl::new(
        dispatcher,
        ManagerOptions {
            agent_tree: Some(Arc::new(bare_store.clone()) as Arc<dyn AgentTreeSnapshot>),
            ..ManagerOptions::default()
        },
    ));
    let aref: Arc<dyn AwaitSessionRef> =
        Arc::new(AwaitSessionManagerRef::new(Arc::clone(&manager)));
    let rm = Arc::new(RunManager::new(bus_dyn.clone()).with_await_session_ref(aref));
    let rid = rm
        .ensure_run(PARENT_ID_BARE, PARENT_ID_BARE, RunConfig::default())
        .expect("ensure_run");
    let cell: SessionRunCell = Arc::new(OnceLock::new());
    cell.set(rid.clone()).expect("cell");
    let sink: Arc<dyn RunSuspendSink> = Arc::new(RunManagerSuspendSink::new(rm.clone()));

    // ── Shared host registry: the recording send-spy + suspend-sink await + agent-fs. ──
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    let recorded_sends = Arc::new(Mutex::new(Vec::new()));
    register_recording_send_spy(&*registry, Arc::clone(&manager), recorded_sends.clone());
    register_reply_tracker_host_fns_with_suspend_sink(
        &*registry,
        Arc::clone(&manager),
        bus_dyn.clone(),
        Some(sink),
    );
    let resolver: Arc<dyn VirtualPathResolver> = Arc::new(DefaultVirtualPathResolver::new(
        ws_path.clone(),
        Arc::new(ParentTree {
            territory: territory.clone(),
        }) as Arc<dyn AgentTreeSnapshot>,
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

    // ── Injector + runtime. ──
    let grant: Arc<dyn GrantCheck> = Arc::new(AllowAll);
    let breaker: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let injector = Arc::new(CapabilityInjector::new(registry, grant, breaker));
    let runtime = Arc::new(ComponentRuntime::new(&wasm_cfg()).expect("runtime"));

    // ── Parent handler (bare ctx "parent"), with a RunSession (park/resume). ──
    let parent_loaded = runtime
        .load_component(&component_bytes(PARENT_CORE))
        .expect("parent component");
    let parent_caps = vec![
        CapRequest {
            capability: CapabilityId::from("messaging"),
        },
        CapRequest {
            capability: CapabilityId::from("fs"),
        },
    ];
    let handler = Arc::new(
        WasmMessageHandler::new(
            runtime.clone(),
            parent_loaded,
            injector.clone(),
            parent_caps,
            PARENT_ID_BARE.to_string(),
            "trace-ac19".to_string(),
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
        .expect("parent init");

    // ── The per-child serve loop: a REAL AgentLoopDriverImpl for the runtime-spawned
    //    child, serving the COLON recv-key (= the dispatcher delivery key), bare ctx. ──
    let child_task = if child_loop {
        let child_loaded = runtime
            .load_component(&component_bytes(CHILD_CORE))
            .expect("child component");
        let child_handler: Arc<dyn advance_scheduler::hook::MessageHandler> =
            Arc::new(WasmMessageHandler::new(
                runtime.clone(),
                child_loaded,
                injector.clone(),
                vec![CapRequest {
                    capability: CapabilityId::from("messaging"),
                }],
                CHILD_ID_BARE.to_string(), // bare ctx → send source bare-normalizes to "test-target"
                "trace-ac19-child".to_string(),
            ));
        let child_driver =
            build_agent_loop(mailbox_store.clone(), child_handler, bus_dyn.clone(), None);
        let recv_key = CHILD_ID_COLON.to_string(); // serve recv-key == dispatcher delivery key
        Some(tokio::spawn(async move {
            child_driver
                .serve(
                    &recv_key,
                    ComponentConfig {
                        id: CHILD_ID_BARE.to_string(),
                        config_data: Some(b"send".to_vec()),
                        trigger_context: None,
                    },
                    WasmInstance::new(ComponentId::new("ac19-child-inst".to_string()).expect("id")),
                )
                .await;
        }))
    } else {
        None
    };

    Rig {
        _ws: ws,
        bus,
        rm,
        rid,
        manager,
        handler,
        init_state,
        recorded_sends,
        mailbox_store,
        child_task,
        child_absent_pre_spawn,
        child_present_post_spawn,
    }
}

fn parent_msg(id: &str) -> Message {
    Message {
        id: id.to_string(),
        kind: advance_shared_types::mailbox::MessageKind::User,
        from: "user:harness".to_string(),
        to: PARENT_ID_COLON.to_string(),
        payload: vec![],
        context: None,
        timestamp: std::time::SystemTime::now(),
        origin: None,
    }
}

// ── leg-a: core e2e ──────────────────────────────────────────────────

/// MODULE-001-AC-19 leg-a: a REAL runtime-spawned child, woken by the real dispatcher
/// (the parent's await-request IS the cross-agent message), replies via the real send
/// path, and the parent's await-replies fiber resumes. Event-grounded oracle + the
/// recording send-spy captures the child's payload.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn module_001_ac19_leg_a_core_spawn_dispatch_reply_await_unblock() {
    let rig = build_rig(b"await-write", true, true).await;
    let rid = rig.rid.clone();

    // Runtime-spawn discriminator.
    assert!(
        rig.child_absent_pre_spawn,
        "child absent from the bare tree BEFORE spawn_child"
    );
    assert!(
        rig.child_present_post_spawn,
        "child authored by spawn_child (runtime spawn)"
    );

    let handler = rig.handler.clone();
    let init_state = rig.init_state.clone();
    let parent_task = tokio::spawn(async move {
        handler
            .handle_message(&parent_msg("msg-ac19-a"), init_state)
            .await
    });

    // The child's serve loop (autonomous) wakes on the dispatched await-request and replies,
    // so the parent parks-then-resumes; we do NOT poll for the transient Suspended state (it
    // races with the auto-reply) — the run.suspended/run.resumed EVENTS below are the oracle.
    let result = tokio::time::timeout(Duration::from_secs(30), parent_task)
        .await
        .expect("parent must resume within 30s after the child's send")
        .expect("parent task panicked")
        .expect("parent handle_message Ok");
    assert_eq!(
        result.new_state, STATE_AWAIT_WRITE_OK,
        "parent resumed: the await returned Ok (a real reply resolved it)"
    );

    let st = rig.rm.run_status(&rid).expect("status");
    assert!(
        matches!(st.status, TaskRunStatus::Active),
        "run resumed to Active (got {:?})",
        st.status
    );
    assert!(st.root_await.is_none(), "root_await cleared on resume");

    // Event oracle: exactly one suspend + one resume(await_complete); suspend precedes resume.
    let events = rig.bus.snapshot();
    assert_eq!(
        count(&events, "run.suspended"),
        1,
        "one run.suspended (the park)"
    );
    assert_eq!(
        count(&events, "run.resumed"),
        1,
        "one run.resumed (the real reply resume)"
    );
    let idx_s = events
        .iter()
        .position(|e| e.event_type == "run.suspended")
        .unwrap();
    let idx_r = events
        .iter()
        .position(|e| e.event_type == "run.resumed")
        .unwrap();
    assert!(idx_s < idx_r, "suspend precedes resume");
    assert!(
        format!("{:?}", events[idx_r]).contains("await_complete"),
        "run.resumed reason is await_complete: {:?}",
        events[idx_r]
    );

    // Payload oracle: the recording send-spy captured the child's send (the specific
    // payload round-tripped through the real send host-fn).
    let sends = rig.recorded_sends.lock().unwrap().clone();
    assert!(
        sends
            .iter()
            .any(|(t, p)| t == PARENT_ID_COLON && p.as_slice() == SEND_PAYLOAD),
        "the child's serve loop issued a real send(agent:parent, SEND_PAYLOAD); recorded={sends:?}"
    );
}

/// leg-a bridge-off control: WITHOUT the colon routing-tree entry, the parent's
/// await-request dispatch fails validate_routing → all-slots-fail → FailedDispatch →
/// the parent NEVER parks (0 run.suspended). Proves the real dispatch is load-bearing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn module_001_ac19_leg_a_bridge_off_no_park() {
    let rig = build_rig(b"await-write", false, true).await;
    let handler = rig.handler.clone();
    let init_state = rig.init_state.clone();
    // No park is expected → the handle_message returns quickly (FailedDispatch is Ok).
    let _ = tokio::time::timeout(
        Duration::from_secs(30),
        handler.handle_message(&parent_msg("msg-ac19-a-bridgeoff"), init_state),
    )
    .await
    .expect("handle_message completes (FailedDispatch returns Ok, no park)");
    let events = rig.bus.snapshot();
    assert_eq!(
        count(&events, "run.suspended"),
        0,
        "bridge-off → FailedDispatch (no routable child) → the parent never parked"
    );
    assert!(
        rig.recorded_sends.lock().unwrap().is_empty(),
        "bridge-off → no dispatch reached the child → no send recorded"
    );
}

/// leg-a child-loop-off control: bridge ON but NO child serve loop → the await-request is
/// dispatched + the parent parks (1 run.suspended), but nothing handles it → 0 run.resumed
/// within a bounded grace, and the request sits queued in the child mailbox. Proves the
/// child serve loop is load-bearing (NOT a 3600s idle-timeout wait).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn module_001_ac19_leg_a_child_loop_off_parks_no_resume() {
    let rig = build_rig(b"await-write", true, false).await;
    let rid = rig.rid.clone();
    let handler = rig.handler.clone();
    let init_state = rig.init_state.clone();
    let parent = tokio::spawn(async move {
        handler
            .handle_message(&parent_msg("msg-ac19-a-noloop"), init_state)
            .await
    });
    assert!(
        wait_parked(&rig.rm, &rid).await,
        "parent parks (dispatch succeeded to the child mailbox)"
    );
    // Bounded grace: no reply ever arrives (no child loop) → no resume.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let events = rig.bus.snapshot();
    assert_eq!(count(&events, "run.suspended"), 1, "the parent parked");
    assert_eq!(
        count(&events, "run.resumed"),
        0,
        "no resume (no child loop handled the request)"
    );
    // The dispatched await-request is queued in the child's colon mailbox, unhandled.
    let depth = rig
        .mailbox_store
        .get(CHILD_ID_COLON)
        .map(|mb| mb.depth())
        .unwrap_or(0);
    assert!(
        depth >= 1,
        "the await-request is queued in the child mailbox (dispatch succeeded); depth={depth}"
    );
    // The parent stays parked forever (no reply); abort it so the test doesn't leak a task.
    parent.abort();
}

// ── leg-b: single-session pause (pause_run) → session-closed ──────────────

/// MODULE-001-AC-19 leg-b: a suspended parent (parked awaiting the spawned child, child
/// loop OFF so it stays parked) is pause_run'd → the live await session closes →
/// session-closed → run Paused, 0 resume. (BUILT single-session; NOT the multi-level tree
/// cascade — that is the untested AC-21.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn module_001_ac19_leg_b_single_session_pause_closes_session() {
    let rig = build_rig(b"await-write", true, false).await;
    let rid = rig.rid.clone();
    let handler = rig.handler.clone();
    let init_state = rig.init_state.clone();
    let parent_task = tokio::spawn(async move {
        handler
            .handle_message(&parent_msg("msg-ac19-b"), init_state)
            .await
    });
    assert!(wait_parked(&rig.rm, &rid).await, "parent parks at await");

    rig.rm
        .pause_run(&rid, "operator-pause".to_string())
        .await
        .expect("pause_run");

    let result = tokio::time::timeout(Duration::from_secs(30), parent_task)
        .await
        .expect("parent completes after pause")
        .expect("parent task panicked")
        .expect("parent handle_message Ok");
    // The await returned Err(session-closed) → the guest took the no-write/interrupted branch.
    assert_eq!(
        result.new_state, STATE_AWAIT_INTERRUPTED,
        "the await returned session-closed → the guest took the interrupted (no-write) branch"
    );
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
        "NO resume on the pause-closed session"
    );
}

// ── leg-c: deadlock via the ancestry walk over the runtime-spawned tree ──

/// MODULE-001-AC-19 leg-c: with the deadlock gate armed over the runtime-spawned bare
/// ancestry (parent → test-target), an UPWARD await (child awaits its ancestor parent) is
/// rejected whole-call at admission with DeadlockDetected (the forms_cycle parent_of walk).
/// Control: the DOWNWARD await (parent → child, leg-a) admits — the gate is directional.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn module_001_ac19_leg_c_deadlock_over_runtime_spawned_ancestry() {
    let rig = build_rig(b"await-write", true, false).await;

    // Upward await: caller "test-target" awaits its ancestor "agent:parent" → cycle.
    let res = rig
        .manager
        .start_with_run(
            CHILD_ID_BARE,
            None,
            vec![AwaitRequest::AgentRequest(AgentAwaitRequest {
                target: PARENT_ID_COLON.to_string(),
                payload: vec![],
                correlation_id: "ac19-c-deadlock".to_string(),
                context: None,
            })],
            AwaitOptions {
                mode: AwaitMode::AllOf,
                idle_timeout_secs: Some(5),
                on_idle_timeout: TimeoutPolicy::Fail,
                keep_losers: false,
            },
        )
        .await;
    assert!(
        matches!(res, Err(OrchestrationError::DeadlockDetected(_))),
        "upward await (child→ancestor) over the runtime-spawned ancestry is whole-call DeadlockDetected; got {res:?}"
    );
    // No message enqueued to the parent (whole-call reject before dispatch).
    let depth = rig
        .mailbox_store
        .get(PARENT_ID_COLON)
        .map(|mb| mb.depth())
        .unwrap_or(0);
    assert_eq!(
        depth, 0,
        "deadlock-rejected await dispatches nothing to the parent"
    );

    // Control: the DOWNWARD await (parent → child) admits (it parks; not deadlock). Drive a
    // bounded start that we then drop — admission must NOT be DeadlockDetected.
    let down = tokio::time::timeout(
        Duration::from_millis(300),
        rig.manager.start_with_run(
            PARENT_ID_BARE,
            None,
            vec![AwaitRequest::AgentRequest(AgentAwaitRequest {
                target: CHILD_ID_COLON.to_string(),
                payload: vec![],
                correlation_id: "ac19-c-control".to_string(),
                context: None,
            })],
            AwaitOptions {
                mode: AwaitMode::AllOf,
                idle_timeout_secs: Some(1),
                on_idle_timeout: TimeoutPolicy::ReturnPartial,
                keep_losers: false,
            },
        ),
    )
    .await;
    // It either timed out (still parked — admitted) or returned a non-deadlock result.
    match down {
        Err(_elapsed) => { /* still parked → admitted (directional gate); fine */ }
        Ok(r) => assert!(
            !matches!(r, Err(OrchestrationError::DeadlockDetected(_))),
            "downward parent→child await must NOT be deadlock-rejected (directional gate); got {r:?}"
        ),
    }
}

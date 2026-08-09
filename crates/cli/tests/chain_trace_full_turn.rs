//! Stage-F obs SLICE 1 — T9 (MANDATORY, no fallback): one REAL turn through the
//! production agent loop proves the handle-message chain is LIVE end-to-end.
//!
//! Wiring: the REAL `MailboxDispatcherImpl` delivers a `context:None` message; the
//! `AgentLoopDriverImpl` mints the chain `trace_id` at `run_turn_once`, the emitting
//! `ContextAssemblerImpl` fires `context.assembled`, the j01 skeleton guest's
//! `agent_fs::write` fires `fs.write` under the per-turn re-stamped `ComponentCtx`,
//! and the wired `RunSession` fires `run.round_completed`.
//!
//! Asserts (all three mandatory):
//!  (i)  run.round_completed.trace_id == context.assembled.trace_id  (137: one chain)
//!  (ii) run.round_completed.parent_span_id == context.assembled.span_id
//!         == chain_root_span_id(msg.id)                              (138 pair)
//!  (iii) fs.write.trace_id == context.assembled.trace_id            (re-stamp LIVE —
//!         the guest's wit msg carries NO context, so the cap event can ONLY get the
//!         chain trace from the re-stamped ComponentCtx; (i)/(ii) alone don't prove it)

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

use advance_cli::agent_loop::{
    build_agent_loop, RunManagerBootstrap, RunSession, SessionRunCell, WasmMessageHandler,
};
use advance_cli::context_wiring::{
    build_context_assembler, EmptyCallableInventory, FixedHostFnInventory,
};
use advance_messaging::{MailboxDispatcher, MailboxDispatcherImpl, MailboxStore};
use advance_run_manager::{RunConfig, RunManager};
use advance_runtime::capability_injector::CapabilityInjector;
use advance_runtime::circuit_breaker::{CircuitBreakerBus, DefaultCircuitBreakerBus};
use advance_runtime::config::WasmConfig;
use advance_runtime::host_registry::{HostRegistry, InMemoryHostRegistry};
use advance_runtime::ComponentRuntime;
use advance_scheduler::hook::MessageHandler;
use advance_scheduler::types::{ComponentConfig, ComponentId, WasmInstance};
use advance_scheduler::AgentLoopDriver;
use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentStatus, AgentTreeReader, AgentTreeSnapshot,
    AgentTreeSnapshotData, Capability,
};
use advance_shared_types::capability::{CapParams, CapRequest, CapabilityId, GrantDecision};
use advance_shared_types::context::ContextAssembler;
use advance_shared_types::event::{chain_root_span_id, Event};
use advance_shared_types::mailbox::{Message, MessageKind};
use advance_shared_types::traits::{EventBusEmit, GrantCheck};
use cap_fs::{
    register_agent_fs, Adv003GitSync, DefaultAtomicWriter, DefaultVirtualPathResolver, GitSync,
    MetaSchemaLoader, StubFileHistoryProvider, VirtualPathResolver,
};
use wit_component::ComponentEncoder;

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");
const AGENT_ID: &str = "agent:a";
const AGENT_DIR: &str = "a";
const MSG_ID: &str = "msg-t9-chain";

struct AllowAll;
impl GrantCheck for AllowAll {
    fn check(&self, _: &str, _: &str, _: &str, _: &CapParams) -> GrantDecision {
        GrantDecision::Allow
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

struct OneAgentTree {
    nodes: Vec<AgentNode>,
}
impl OneAgentTree {
    fn new(workspace: PathBuf) -> Self {
        Self {
            nodes: vec![AgentNode {
                id: AgentId(AGENT_ID.to_string()),
                kind: AgentKind::Root,
                parent: None,
                workspace_path: workspace,
                capabilities: Vec::new(),
                template_ref: None,
                status: AgentStatus::Active,
            }],
        }
    }
}
impl AgentTreeReader for OneAgentTree {
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
impl AgentTreeSnapshot for OneAgentTree {
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

fn find<'a>(events: &'a [Event], ty: &str) -> &'a Event {
    events
        .iter()
        .find(|e| e.event_type == ty)
        .unwrap_or_else(|| {
            panic!(
                "expected a {ty} event; got {:?}",
                events.iter().map(|e| &e.event_type).collect::<Vec<_>>()
            )
        })
}

#[tokio::test]
async fn t9_one_real_turn_threads_the_handle_message_chain() {
    // --- workspace + real git repo ---
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join(AGENT_DIR);
    std::fs::create_dir_all(&agent_workspace).unwrap();
    advance_git::bootstrap_repo_at(&workspace_root).expect("bootstrap_repo_at");
    let queue = Arc::new(
        advance_git::DefaultGitCommitQueue::spawn(workspace_root.clone()).expect("git queue spawn"),
    );
    let queue_trait: Arc<dyn advance_git::GitCommitQueue> = queue.clone();
    let git_sync: Arc<dyn GitSync> = Arc::new(Adv003GitSync::new(queue_trait));

    // --- shared capturing bus + agent tree ---
    let bus = Arc::new(CapturingBus::new());
    let tree = Arc::new(OneAgentTree::new(agent_workspace.clone()));

    // --- cap-fs (emits fs.write from ctx.trace_id) ---
    let resolver: Arc<dyn VirtualPathResolver> = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        tree.clone() as Arc<dyn AgentTreeSnapshot>,
    ));
    let schema = Arc::new(MetaSchemaLoader::new_with_default(PathBuf::new()));
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    register_agent_fs(
        &*registry,
        resolver,
        bus.clone() as Arc<dyn EventBusEmit>,
        schema,
        Arc::new(StubFileHistoryProvider),
        Arc::new(DefaultAtomicWriter),
        None,
        None,
        None,
        None,
        Some(git_sync),
    );
    let grant: Arc<dyn GrantCheck> = Arc::new(AllowAll);
    let breaker: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let injector = Arc::new(CapabilityInjector::new(registry.clone(), grant, breaker));

    // --- runtime + guest ---
    let runtime = Arc::new(ComponentRuntime::new(&wasm_cfg()).expect("runtime"));
    let component = ComponentEncoder::default()
        .validate(true)
        .module(CORE_BYTES)
        .expect("wrap")
        .encode()
        .expect("encode");
    let loaded = runtime.load_component(&component).expect("component loads");

    // --- run-manager session wiring (shared cell + RunManager on the SAME bus so
    //     run.round_completed is captured) ---
    let run_manager = Arc::new(RunManager::new(bus.clone() as Arc<dyn EventBusEmit>));
    let cell: SessionRunCell = Arc::new(OnceLock::new());

    // --- production MessageHandler WITH run_session (so complete_round_with_trace fires) ---
    let message_handler: Arc<dyn MessageHandler> = Arc::new(
        WasmMessageHandler::new(
            runtime,
            loaded,
            injector,
            vec![CapRequest {
                capability: CapabilityId::from("fs"),
            }],
            AGENT_ID.to_string(),
            "trace-boot".to_string(), // overridden per-turn by the re-stamp
        )
        .with_run_session(RunSession {
            run_manager: run_manager.clone(),
            cell: cell.clone(),
        }),
    );

    // --- shared mailbox + real dispatcher (emits msg.received) ---
    let store = Arc::new(MailboxStore::new(NonZeroUsize::new(64).unwrap()));
    let dispatcher =
        MailboxDispatcherImpl::new(store.clone(), tree.clone() as Arc<dyn AgentTreeReader>)
            .with_event_bus(bus.clone() as Arc<dyn EventBusEmit>);

    // --- driver: emitting assembler (context.assembled) + run bootstrap (publishes cell) ---
    let assembler: Arc<dyn ContextAssembler> = build_context_assembler(
        bus.clone() as Arc<dyn EventBusEmit>,
        Arc::new(EmptyCallableInventory),
        Arc::new(FixedHostFnInventory::from_names(&[])),
        tree.clone() as Arc<dyn AgentTreeSnapshot>,
    );
    let driver = build_agent_loop(
        store.clone(),
        message_handler,
        bus.clone() as Arc<dyn EventBusEmit>,
        None,
    )
    .with_context_assembler(assembler)
    .with_run_bootstrap(Arc::new(RunManagerBootstrap {
        run_manager: run_manager.clone(),
        run_config: RunConfig::default(),
        session_agent: AGENT_ID.to_string(),
        cell: cell.clone(),
    }));

    // --- inject ONE inbound message (context:None) through the real dispatcher ---
    let payload = b"hello-chain".to_vec();
    let msg = Message {
        id: MSG_ID.to_string(),
        kind: MessageKind::User,
        from: "user:harness".to_string(),
        to: AGENT_ID.to_string(),
        payload: payload.clone(),
        context: None,
        timestamp: SystemTime::now(),
        origin: None,
    };
    dispatcher.deliver(AGENT_ID, msg).await.expect("deliver");

    // --- drive ONE real turn ---
    let cfg = ComponentConfig {
        id: AGENT_ID.to_string(),
        config_data: None,
        trigger_context: None,
    };
    let instance =
        WasmInstance::new(ComponentId::new("agent-a-inst".to_string()).expect("component id"));
    driver.run_agent(AGENT_ID, cfg, instance).await;

    // --- gather the chain events ---
    let events = bus.snapshot();
    let assembled = find(&events, "context.assembled");
    let round_completed = find(&events, "run.round_completed");
    let fs_write = find(&events, "fs.write");

    let expected_root = chain_root_span_id(MSG_ID);

    // (i) 137 — context.assembled + run.round_completed share ONE chain trace.
    assert_eq!(
        round_completed.trace_id, assembled.trace_id,
        "137: run.round_completed and context.assembled must share the chain trace_id"
    );
    assert!(
        !assembled.trace_id.is_empty(),
        "chain trace_id is non-empty"
    );
    assert_ne!(
        assembled.trace_id, "trace-boot",
        "the boot constant must be overridden per-turn"
    );

    // (ii) 138 — run.round_completed is a child of the context.assembled chain root.
    assert_eq!(
        assembled.span_id, expected_root,
        "context.assembled.span_id == chain_root_span_id(msg.id) (the chain root)"
    );
    assert_eq!(
        round_completed.parent_span_id.as_deref(),
        Some(expected_root.as_str()),
        "138: run.round_completed.parent_span_id == context.assembled.span_id (chain root)"
    );

    // (iii) re-stamp LIVE — fs.write (a cap event from the guest) carries the chain
    // trace. The guest's wit msg has NO context, so the ONLY way fs.write gets the
    // chain trace is the per-turn ComponentCtx.trace_id re-stamp. This is the
    // load-bearing proof that (i)/(ii) cannot give.
    assert_eq!(
        fs_write.trace_id, assembled.trace_id,
        "iii: fs.write.trace_id == chain trace — the ComponentCtx re-stamp is LIVE"
    );

    drop(queue);
}

//! /dev Slice BS-3 (2026-06-03) — full-turn witness through the REAL agent loop.
//!
//! Extends the T-SAH-00 spike from "drive the guest directly" to "drive the
//! production `AgentLoopDriverImpl::run_agent` via `build_agent_loop`", exercising
//! the wired whole: an inbound message delivered through the REAL
//! `MailboxDispatcherImpl` (emitting `msg.received`) is `recv`'d by `run_agent`,
//! which drives the skeleton guest's `fs.write` → cap-fs → a git Turn commit.
//!
//! Witnesses (the slice's gated SYS-AC):
//!  - **SYS-AC-002** — the turn emits a `msg.received` event (at delivery, which
//!    triggers the turn).
//!  - **SYS-AC-190** — that event carries `delivery_latency_ms` < 1000 ms.
//!  - plus the SYS-AC-003 turn-commit **capability** (asserted, not flipped — the
//!    "after the reply" precondition is deferred with SYS-AC-001).

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use advance_cli::agent_loop::{build_agent_loop, WasmMessageHandler};
use advance_messaging::{MailboxDispatcher, MailboxDispatcherImpl, MailboxStore};
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
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{Message, MessageKind};
use advance_shared_types::traits::{EventBusEmit, GrantCheck};
use cap_fs::{
    register_agent_fs, Adv003GitSync, DefaultAtomicWriter, DefaultVirtualPathResolver, GitSync,
    MetaSchemaLoader, StubFileHistoryProvider, VirtualPathResolver,
};
use wit_component::ComponentEncoder;

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");
// Routing id — MUST be `agent:`-prefixed to pass the messaging layer's `is_safe_id`
// (cap-fs accepts any string; the dispatcher's `validate_routing` does not). The agent's
// workspace DIRECTORY is a separate clean name ("a") — no colon in the path.
const AGENT_ID: &str = "agent:a";
const AGENT_DIR: &str = "a";

struct AllowAll;
impl GrantCheck for AllowAll {
    fn check(&self, _: &str, _: &str, _: &str, _: &CapParams) -> GrantDecision {
        GrantDecision::Allow
    }
}

/// Captures emitted events so the test can witness `msg.received`.
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

#[tokio::test]
async fn full_turn_witnesses_msg_received_and_turn_commit() {
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

    // --- shared capturing event bus + agent tree (used by dispatcher AND cap-fs) ---
    let bus = Arc::new(CapturingBus::new());
    let tree = Arc::new(OneAgentTree::new(agent_workspace.clone()));

    // --- cap-fs registration WITH git_sync (versioned namespace; the spike proved reachability) ---
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

    // --- runtime + production MessageHandler loading the skeleton guest ---
    let runtime = Arc::new(ComponentRuntime::new(&wasm_cfg()).expect("runtime"));
    let component = ComponentEncoder::default()
        .validate(true)
        .module(CORE_BYTES)
        .expect("wrap")
        .encode()
        .expect("encode");
    let loaded = runtime.load_component(&component).expect("component loads");
    let message_handler: Arc<dyn MessageHandler> = Arc::new(WasmMessageHandler::new(
        runtime,
        loaded,
        injector,
        vec![CapRequest {
            capability: CapabilityId::from("fs"),
        }],
        AGENT_ID.to_string(),
        "trace-full-turn".to_string(),
    ));

    // --- shared mailbox + real dispatcher (emits msg.received) + the agent loop ---
    let store = Arc::new(MailboxStore::new(NonZeroUsize::new(64).unwrap()));
    let dispatcher =
        MailboxDispatcherImpl::new(store.clone(), tree.clone() as Arc<dyn AgentTreeReader>)
            .with_event_bus(bus.clone() as Arc<dyn EventBusEmit>);
    // Phase-2 reply-delivery slice: build_agent_loop now takes the event bus
    // (for the real EventBusRejectionSink) + an optional outbound sink. This
    // fs-only full-turn witness has no reply action → None outbound (gate-only,
    // behavior unchanged).
    let driver = build_agent_loop(
        store.clone(),
        message_handler,
        bus.clone() as Arc<dyn EventBusEmit>,
        None,
    );

    // --- inject one inbound message through the REAL dispatcher (user: sender bypasses adjacency) ---
    let payload = b"hello-full-turn".to_vec();
    let msg = Message {
        id: "msg-1".to_string(),
        kind: MessageKind::User,
        from: "user:harness".to_string(),
        to: AGENT_ID.to_string(),
        payload: payload.clone(),
        context: None,
        timestamp: SystemTime::now(),
        origin: None,
    };
    dispatcher
        .deliver(AGENT_ID, msg)
        .await
        .expect("deliver (validate_routing passes)");

    // --- drive the real turn: run_agent recvs the queued message + runs the guest ---
    let cfg = ComponentConfig {
        id: AGENT_ID.to_string(),
        config_data: None,
        trigger_context: None,
    };
    // `run_agent` ignores the WasmInstance (the WASM lives behind the MessageHandler);
    // ComponentId only needs to be a syntactically-valid id (no colon).
    let instance =
        WasmInstance::new(ComponentId::new("agent-a-inst".to_string()).expect("component id"));
    driver.run_agent(AGENT_ID, cfg, instance).await;

    // --- SYS-AC-002 + SYS-AC-190: msg.received emitted with delivery_latency_ms < 1000 ---
    let events = bus.snapshot();
    let msg_received = events
        .iter()
        .find(|e| e.event_type == "msg.received")
        .expect("SYS-AC-002: a msg.received event was emitted");
    assert_eq!(
        msg_received.agent_id, AGENT_ID,
        "msg.received agent_id == receiver"
    );
    assert_eq!(
        msg_received.payload.get("to").and_then(|v| v.as_str()),
        Some(AGENT_ID),
        "msg.received payload.to == receiver"
    );
    let latency = msg_received
        .payload
        .get("delivery_latency_ms")
        .and_then(|v| v.as_u64())
        .expect("SYS-AC-190: msg.received carries delivery_latency_ms");
    assert!(
        latency < 1000,
        "SYS-AC-190: delivery_latency_ms {latency} < 1000ms SLO"
    );

    // --- turn-commit capability (SYS-AC-003 substance; not flipped, D4a) ---
    let written = agent_workspace.join("j01.txt");
    assert!(written.is_file(), "the turn's fs.write landed: {written:?}");
    assert_eq!(
        std::fs::read(&written).unwrap(),
        payload,
        "file content == injected payload"
    );
    let repo = git2::Repository::open(&workspace_root).expect("open repo");
    let head = repo.head().expect("HEAD").peel_to_commit().expect("commit");
    assert_eq!(
        head.parent_count(),
        0,
        "exactly one new turn commit (root) since bootstrap"
    );
    assert!(
        head.message().unwrap_or("").starts_with("[turn]"),
        "the commit is a CommitType::Turn commit"
    );

    drop(queue); // keep the git queue alive through the synchronous commit + asserts
}

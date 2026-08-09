//! /dev Slice BS-3 (2026-06-03) — T-SAH-00 system-acceptance spike.
//!
//! De-risks the two central feasibility questions for the whole slice in one shot:
//!  1. **R1 (host-bindings foreign-world import):** a guest whose world imports
//!     `agent-fs@0.1.0` (NOT `agent-messaging`) instantiates through the existing
//!     `advance-host-with-capabilities` bindgen — only the EXPORTS
//!     (message-driven/runnable) must match; the `agent-fs` import is satisfied by
//!     the linker (CapabilityInjector), not the bindgen world.
//!  2. **D10 + D11 (versioned reachability + git turn-commit):** the guest's
//!     `fs.write` reaches real cap-fs (registered under the *versioned* namespace
//!     `advance:runtime/agent-fs@0.1.0`) and produces exactly one `CommitType::Turn`
//!     git commit over a `bootstrap_repo_at` repo whose tree contains the write.
//!
//! This is the same load→instantiate→call→assert-commit pattern the production
//! `MessageHandler` (cli/src/agent_loop.rs) will use.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use advance_runtime::capability_injector::{CapabilityInjector, ComponentCtx};
use advance_runtime::circuit_breaker::{CircuitBreakerBus, DefaultCircuitBreakerBus};
use advance_runtime::config::WasmConfig;
use advance_runtime::host_registry::{HostRegistry, InMemoryHostRegistry};
use advance_runtime::wit_bindings::with_caps::advance::runtime::types as wit_types;
use advance_runtime::ComponentRuntime;
use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentStatus, AgentTreeReader, AgentTreeSnapshot,
    AgentTreeSnapshotData, Capability,
};
use advance_shared_types::capability::{CapParams, CapRequest, CapabilityId, GrantDecision};
use advance_shared_types::event::Event;
use advance_shared_types::traits::{EventBusEmit, GrantCheck};
use cap_fs::{
    register_agent_fs, Adv003GitSync, DefaultAtomicWriter, DefaultVirtualPathResolver, GitSync,
    MetaSchemaLoader, StubFileHistoryProvider, VirtualPathResolver,
};
use wit_component::ComponentEncoder;

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");
/// Witness state the skeleton guest returns after a successful fs.write.
const STATE_WROTE: [u8; 4] = [0xAC, 0x17, 0xF5, 0x01];
const AGENT_ID: &str = "a";

// ---------- minimal inline test fakes (cap-fs tests/common is not reachable here) ----------

struct AllowAll;
impl GrantCheck for AllowAll {
    fn check(&self, _: &str, _: &str, _: &str, _: &CapParams) -> GrantDecision {
        GrantDecision::Allow
    }
}

struct NoopEventBus;
impl EventBusEmit for NoopEventBus {
    fn emit(&self, _event: Event) {}
}

/// Single-agent tree: one root agent `AGENT_ID` whose workspace is `workspace`.
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

fn component_bytes() -> Vec<u8> {
    ComponentEncoder::default()
        .validate(true)
        .module(CORE_BYTES)
        .expect("core module wraps")
        .encode()
        .expect("component encoded")
}

#[tokio::test]
async fn t_sah_00_skeleton_guest_fs_write_produces_one_turn_commit() {
    // --- workspace + real git repo (bootstrap_repo_at → main HEAD; do_commit requires it) ---
    let tempdir = tempfile::TempDir::new().unwrap();
    let workspace_root = tempdir.path().to_path_buf();
    let agent_workspace = workspace_root.join(AGENT_ID);
    std::fs::create_dir_all(&agent_workspace).unwrap();

    advance_git::bootstrap_repo_at(&workspace_root).expect("bootstrap_repo_at");
    let queue = Arc::new(
        advance_git::DefaultGitCommitQueue::spawn(workspace_root.clone()).expect("git queue spawn"),
    );
    let queue_trait: Arc<dyn advance_git::GitCommitQueue> = queue.clone();
    let git_sync: Arc<dyn GitSync> = Arc::new(Adv003GitSync::new(queue_trait));

    // --- cap-fs registration WITH git_sync (the full register_agent_fs, not _default) ---
    let tree = Arc::new(OneAgentTree::new(agent_workspace.clone()));
    let resolver: Arc<dyn VirtualPathResolver> = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        tree as Arc<dyn AgentTreeSnapshot>,
    ));
    let emitter: Arc<dyn EventBusEmit> = Arc::new(NoopEventBus);
    let schema = Arc::new(MetaSchemaLoader::new_with_default(PathBuf::new()));
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    register_agent_fs(
        &*registry,
        resolver,
        emitter,
        schema,
        Arc::new(StubFileHistoryProvider),
        Arc::new(DefaultAtomicWriter),
        None,           // preview_max_bytes
        None,           // db_sync
        None,           // workspace_root (slice-C trio all-None)
        None,           // agent_tree
        Some(git_sync), // slice-D git attribution → CommitType::Turn per write
    );

    let grant: Arc<dyn GrantCheck> = Arc::new(AllowAll);
    let breaker: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    let injector = CapabilityInjector::new(registry.clone(), grant, breaker);

    // --- load + instantiate the skeleton guest through the existing host bindgen ---
    let runtime = ComponentRuntime::new(&wasm_cfg()).expect("runtime");
    let loaded = runtime
        .load_component(&component_bytes())
        .expect("component loads");
    let caps_fs = vec![CapRequest {
        capability: CapabilityId::from("fs"),
    }];
    let ctx = ComponentCtx::new(AGENT_ID.into(), "trace-spike".into(), Vec::new());
    let (bindings, mut store) = runtime
        .instantiate_advance_host_with_capabilities_async(&loaded, ctx, &caps_fs, &injector)
        .await
        .expect("R1: guest importing agent-fs@0.1.0 instantiates against advance-host-with-capabilities");

    // --- drive one turn: init then handle-message (guest calls fs.write) ---
    let cfg = wit_types::ComponentConfig {
        id: "spike".into(),
        config_data: None,
        trigger_context: None,
    };
    let init_state = bindings
        .advance_runtime_message_driven()
        .call_init(&mut store, &cfg)
        .await
        .expect("init call")
        .expect("init Ok");

    let payload = b"hello-spike".to_vec();
    let msg = wit_types::Message {
        payload: payload.clone(),
    };
    let result = bindings
        .advance_runtime_message_driven()
        .call_handle_message(&mut store, &msg, &init_state)
        .await
        .expect("handle-message call")
        .expect("handle-message Ok: D10 — fs.write host fn reachable under versioned namespace");

    // (1) the guest's fs.write succeeded -> witness state.
    assert_eq!(
        result.new_state, STATE_WROTE,
        "guest returned the post-write witness state"
    );

    // (2) the file landed in the agent's territory with the injected payload.
    let written = agent_workspace.join("j01.txt");
    assert!(written.is_file(), "fs.write produced the file: {written:?}");
    assert_eq!(
        std::fs::read(&written).unwrap(),
        payload,
        "file content matches the injected payload"
    );

    // (3) D11 — exactly one new turn commit whose tree contains the write.
    let repo = git2::Repository::open(&workspace_root).expect("open repo");
    let head = repo
        .head()
        .expect("HEAD")
        .peel_to_commit()
        .expect("HEAD commit");
    assert_eq!(
        head.parent_count(),
        0,
        "exactly one commit since bootstrap (root commit, no parents)"
    );
    let cmsg = head.message().unwrap_or("");
    assert!(
        cmsg.starts_with("[turn]"),
        "commit is a CommitType::Turn commit; message = {cmsg:?}"
    );
    let tree = head.tree().expect("commit tree");
    assert!(
        tree.get_path(std::path::Path::new("a/j01.txt")).is_ok(),
        "the turn commit's tree contains the agent's write (a/j01.txt)"
    );

    // keep the git queue alive until after the (synchronous, await-not-spawn) commit + asserts.
    drop(queue);
}

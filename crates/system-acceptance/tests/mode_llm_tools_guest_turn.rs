//! Guest-driven LLM tool loop: `guest-rust-llm-tools` calls `generate` with
//! `params.tools`, reads native `tool_calls` from `parsed-output`, dispatches
//! `agent-fs::write`, then generates again until the model returns text.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use advance_runtime::capability_injector::CapabilityInjector;
use advance_runtime::circuit_breaker::DefaultCircuitBreakerBus;
use advance_runtime::config::WasmConfig;
use advance_runtime::host_registry::{HostRegistry, InMemoryHostRegistry};
use advance_runtime::wit_bindings::with_caps::advance::runtime::types as wit_types;
use advance_runtime::{ComponentCtx, ComponentRuntime};

use advance_shared_types::agent_tree::{
    AgentId, AgentKind, AgentNode, AgentStatus, AgentTreeReader, AgentTreeSnapshot,
    AgentTreeSnapshotData,
};
use advance_shared_types::capability::{CapParams, CapRequest, CapabilityId, GrantDecision};
use advance_shared_types::context::LlmMessage;
use advance_shared_types::event::Event;
use advance_shared_types::traits::{EventBusEmit, GrantCheck};

use cap_fs::{
    register_agent_fs, DefaultAtomicWriter, DefaultVirtualPathResolver, MetaSchemaLoader,
    StubFileHistoryProvider,
};
use cap_llm::register_agent_llm;
use system_acceptance::llm_loopback::{LoopbackLlm, ScriptedResponse};

struct NullBus;
impl EventBusEmit for NullBus {
    fn emit(&self, _event: Event) {}
}

struct AllowAllGrant;
impl GrantCheck for AllowAllGrant {
    fn check(
        &self,
        _agent_id: &str,
        _capability: &str,
        _function: &str,
        _params: &CapParams,
    ) -> GrantDecision {
        GrantDecision::Allow
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
    fn capabilities(&self, _: &str) -> Vec<advance_shared_types::agent_tree::Capability> {
        Vec::new()
    }
}
impl AgentTreeSnapshot for OneAgentTree {
    fn snapshot(&self) -> AgentTreeSnapshotData {
        AgentTreeSnapshotData {
            handles: Default::default(),
            nodes: self.nodes.clone(),
            parent_of: HashMap::new(),
            children_of: HashMap::new(),
            peer_slug_map: HashMap::new(),
            revision: 0,
        }
    }
}

const LLM_TOOLS_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-llm-tools.core.wasm");

const AGENT_ID: &str = "agent:tools";
const FINAL_REPLY: &str = "created-roadmap";
const WRITE_ARGS: &str = r##"{"path":"roadmap.md","content":"# Roadmap\n"}"##;
const IDENTITY: &str = "IDENTITY-PREFIX-TOOLS";

#[tokio::test(flavor = "multi_thread")]
async fn llm_tools_guest_loops_generate_write_generate() {
    let tmp = tempfile::TempDir::new().unwrap();
    let workspace_root = tmp.path().to_path_buf();
    let agent_workspace = workspace_root.join("tools");
    std::fs::create_dir_all(&agent_workspace).unwrap();

    let loopback = LoopbackLlm::start(
        vec![
            ScriptedResponse::ok_tool_calls("call_1", "write", WRITE_ARGS, 11, 6),
            ScriptedResponse::ok_chat(FINAL_REPLY, 18, 4),
        ],
        None,
        None,
        Arc::new(NullBus),
        AGENT_ID.to_string(),
    )
    .await;

    let bus: Arc<dyn EventBusEmit> = Arc::new(NullBus);
    let tree = Arc::new(OneAgentTree::new(agent_workspace.clone()));
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        tree.clone() as Arc<dyn AgentTreeSnapshot>,
    ));
    let schema = Arc::new(MetaSchemaLoader::new_with_default(PathBuf::new()));
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    loopback.gateway.publish_assembled(
        AGENT_ID,
        Arc::from(vec![LlmMessage {
            role: "system".into(),
            content: IDENTITY.into(),
        }]),
    );
    register_agent_llm(&*registry, loopback.gateway.clone());
    register_agent_fs(
        &*registry,
        resolver,
        bus,
        schema,
        Arc::new(StubFileHistoryProvider),
        Arc::new(DefaultAtomicWriter),
        None,
        None,
        None,
        None,
        None,
    );

    let injector = CapabilityInjector::new(
        registry,
        Arc::new(AllowAllGrant),
        Arc::new(DefaultCircuitBreakerBus::new()),
    );

    let component = build_agent::encode_core_to_component(LLM_TOOLS_CORE)
        .expect("encode llm-tools core into a component");
    let runtime = ComponentRuntime::new(&WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    })
    .expect("construct runtime");
    let loaded = runtime
        .load_component(&component)
        .expect("load_component accepts the llm-tools component");

    let caps = vec![
        CapRequest {
            capability: CapabilityId::from("llm"),
        },
        CapRequest {
            capability: CapabilityId::from("fs"),
        },
    ];
    let mut ctx = ComponentCtx::new(
        AGENT_ID.to_string(),
        "trace-llm-tools".to_string(),
        Vec::new(),
    );
    ctx.stamp_trusted_turn("turn-tools-1".to_string());
    let (bindings, mut store) = runtime
        .instantiate_advance_host_with_capabilities_async(&loaded, ctx, &caps, &injector)
        .await
        .expect("instantiate the llm+fs guest");

    let state = bindings
        .advance_runtime_message_driven()
        .call_init(
            &mut store,
            &wit_types::ComponentConfig {
                id: AGENT_ID.to_string(),
                config_data: None,
                trigger_context: None,
            },
        )
        .await
        .expect("call_init does not trap")
        .expect("init returns Ok");

    let msg = wit_types::Message {
        payload: b"create a roadmap file".to_vec(),
    };
    let action_result = bindings
        .advance_runtime_message_driven()
        .call_handle_message(&mut store, &msg, &state)
        .await
        .expect("call_handle_message does not trap")
        .expect("handle_message returns Ok");

    assert_eq!(action_result.actions.len(), 1);
    assert_eq!(
        action_result.actions[0].payload,
        FINAL_REPLY.as_bytes(),
        "final generate text is the action payload"
    );
    assert_eq!(
        loopback.chat_request_count(),
        2,
        "guest generate loop: tool_calls then text"
    );
    let bodies = loopback.all_chat_request_bodies();
    assert_eq!(bodies.len(), 2);
    for (i, body) in bodies.iter().enumerate() {
        assert!(
            body.contains(IDENTITY),
            "generate {} must keep the identity seed (F3 peek): {body}",
            i + 1
        );
    }

    let wrote = agent_workspace.join("roadmap.md");
    let body = std::fs::read_to_string(&wrote)
        .unwrap_or_else(|_| panic!("guest tool loop must write {}", wrote.display()));
    assert!(
        body.contains("Roadmap"),
        "written file carries tool content: {body:?}"
    );
}

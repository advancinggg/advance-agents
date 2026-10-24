//! V11 — guest-rust-callables loopback: remember → write → text.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use advance_cli::callables::{
    register_agent_callables, register_fs_callables, register_memory_callables, CallableDispatcher,
    StaticCaps,
};
use advance_runtime::callable_registry::InMemoryCallableRegistry;
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
use advance_shared_types::repetition::{OutputHash, RepetitionDecision, ToolCallSignature};
use advance_shared_types::traits::{EventBusEmit, GrantCheck, RepetitionGuardCheck};

use cap_fs::{
    register_agent_fs, DefaultAtomicWriter, DefaultVirtualPathResolver, MetaSchemaLoader,
    StubFileHistoryProvider,
};
use cap_llm::register_agent_llm;
use cap_memory::{register_agent_memory, L6CursorStore, MemoryStore};
use system_acceptance::llm_loopback::{LoopbackLlm, ScriptedResponse};

struct CaptureBus {
    events: Mutex<Vec<Event>>,
}
impl EventBusEmit for CaptureBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
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

struct PassRep;
impl RepetitionGuardCheck for PassRep {
    fn record_tool_call(&self, _: &str, _: ToolCallSignature) -> RepetitionDecision {
        RepetitionDecision::Pass
    }
    fn record_output(&self, _: &str, _: OutputHash) -> RepetitionDecision {
        RepetitionDecision::Pass
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

const CALLABLES_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-callables.core.wasm");

const AGENT_ID: &str = "agent:callables";
const FINAL_REPLY: &str = "remembered-and-wrote";
const REMEMBER_ARGS: &str = r##"{"content":"remember-this","tags":["insight"]}"##;
const WRITE_ARGS: &str = r##"{"path":"roadmap.md","content":"# Roadmap\n"}"##;
const IDENTITY: &str = "IDENTITY-PREFIX-CALLABLES";

#[tokio::test(flavor = "multi_thread")]
async fn v11_callables_guest_remember_then_write_then_text() {
    let tmp = tempfile::TempDir::new().unwrap();
    let workspace_root = tmp.path().to_path_buf();
    let agent_workspace = workspace_root.join("callables");
    std::fs::create_dir_all(&agent_workspace).unwrap();

    let loopback = LoopbackLlm::start(
        vec![
            ScriptedResponse::ok_tool_calls("call_1", "remember", REMEMBER_ARGS, 11, 6),
            ScriptedResponse::ok_tool_calls("call_2", "write", WRITE_ARGS, 14, 6),
            ScriptedResponse::ok_chat(FINAL_REPLY, 18, 4),
        ],
        None,
        None,
        Arc::new(CaptureBus {
            events: Mutex::new(Vec::new()),
        }),
        AGENT_ID.to_string(),
    )
    .await;

    let captured = Arc::new(CaptureBus {
        events: Mutex::new(Vec::new()),
    });
    let bus: Arc<dyn EventBusEmit> = captured.clone();
    let tree = Arc::new(OneAgentTree::new(agent_workspace.clone()));
    let resolver = Arc::new(DefaultVirtualPathResolver::new(
        workspace_root.clone(),
        tree.clone() as Arc<dyn AgentTreeSnapshot>,
    ));
    let schema = Arc::new(MetaSchemaLoader::new_with_default(PathBuf::new()));
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    let callable_reg = Arc::new(InMemoryCallableRegistry::new());
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
        bus.clone(),
        schema,
        Arc::new(StubFileHistoryProvider),
        Arc::new(DefaultAtomicWriter),
        None,
        None,
        None,
        None,
        None,
    );
    register_agent_memory(
        &*registry,
        Arc::new(MemoryStore::new()),
        bus.clone(),
        Arc::new(L6CursorStore::new()),
    );
    register_fs_callables(&*callable_reg, &*registry);
    register_memory_callables(&*callable_reg, &*registry);

    let dispatcher = Arc::new(CallableDispatcher::new(
        callable_reg,
        Arc::new(StaticCaps(vec!["llm".into(), "fs".into(), "memory".into()])),
        Arc::new(AllowAllGrant),
        Arc::new(DefaultCircuitBreakerBus::new()),
        Arc::new(PassRep),
        bus,
    ));
    register_agent_callables(&*registry, Arc::clone(&dispatcher));
    loopback
        .gateway
        .set_callable_catalog(Arc::clone(&dispatcher) as Arc<dyn cap_llm::CallableCatalogPort>);
    dispatcher.bind_gateway(loopback.gateway.clone());

    let injector = CapabilityInjector::new(
        registry,
        Arc::new(AllowAllGrant),
        Arc::new(DefaultCircuitBreakerBus::new()),
    );

    let component = build_agent::encode_core_to_component(CALLABLES_CORE)
        .expect("encode callables core into a component");
    let runtime = ComponentRuntime::new(&WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    })
    .expect("construct runtime");
    let loaded = runtime
        .load_component(&component)
        .expect("load_component accepts the callables component");

    let caps = vec![
        CapRequest {
            capability: CapabilityId::from("llm"),
        },
        CapRequest {
            capability: CapabilityId::from("fs"),
        },
        CapRequest {
            capability: CapabilityId::from("memory"),
        },
    ];
    let mut ctx = ComponentCtx::new(
        AGENT_ID.to_string(),
        "trace-callables".to_string(),
        Vec::new(),
    );
    ctx.stamp_trusted_turn("turn-callables-1".to_string());
    let (bindings, mut store) = runtime
        .instantiate_advance_host_with_capabilities_async(&loaded, ctx, &caps, &injector)
        .await
        .expect("instantiate the callables guest");

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
        payload: b"remember then write a roadmap".to_vec(),
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
        3,
        "guest generate loop: remember, write, then text"
    );
    let bodies = loopback.all_chat_request_bodies();
    assert_eq!(bodies.len(), 3);
    for (i, body) in bodies.iter().enumerate() {
        assert!(
            body.contains(IDENTITY),
            "generate {} must keep the identity seed (F3 peek): {body}",
            i + 1
        );
    }

    let invoked: Vec<Event> = captured
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.event_type == "callable.invoked")
        .cloned()
        .collect();
    assert_eq!(
        invoked.len(),
        2,
        "callable.invoked ×2, got {:?}",
        invoked.iter().map(|e| &e.payload).collect::<Vec<_>>()
    );
    assert_eq!(invoked[0].payload["name"], "remember");
    assert_eq!(invoked[0].payload["source"], "host-fn");
    assert_eq!(invoked[1].payload["name"], "write");
    assert_eq!(invoked[1].payload["source"], "host-fn");

    let wrote = agent_workspace.join("roadmap.md");
    let body = std::fs::read_to_string(&wrote)
        .unwrap_or_else(|_| panic!("guest callable loop must write {}", wrote.display()));
    assert!(
        body.contains("Roadmap"),
        "written file carries tool content: {body:?}"
    );
}

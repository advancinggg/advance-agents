//! ADR 2026-10-28 S1 V5 — guest-rust-callables loopback over the browser family:
//! navigate → snapshot → click(ref) → text, with the Fake browser driver. The
//! observation reaches the model between the fixed delimiters; `ui.action` ×2 and
//! `ui.observation` ×1 are on the bus beside the dispatcher's `callable.invoked` ×3.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use advance_cli::callables::{register_agent_callables, CallableDispatcher, StaticCaps};
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
use cap_ui::conformance::{browser_policy, fake_browser, FIXTURE_HOME_URL, FIXTURE_NEXT_URL};
use cap_ui::testing::{AllowlistGrant, NoScan, StaticUiPolicy};
use cap_ui::{register_ui_callables, UiDeps, UiDrivers, UiSurfaces, OBSERVATION_BEGIN};
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
    fn check(&self, _: &str, _: &str, _: &str, _: &CapParams) -> GrantDecision {
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

const AGENT_ID: &str = "agent:ui-browser";
const FINAL_REPLY: &str = "clicked-next-page";
const IDENTITY: &str = "IDENTITY-PREFIX-UI";

struct Outcome {
    payload: Vec<u8>,
    bodies: Vec<String>,
    events: Vec<Event>,
    current_url: Option<String>,
}

async fn run_ui_guest(scripts: Vec<ScriptedResponse>, prompt: &str) -> Outcome {
    let tmp = tempfile::TempDir::new().unwrap();
    let workspace_root = tmp.path().to_path_buf();
    let agent_workspace = workspace_root.join("ui-browser");
    std::fs::create_dir_all(&agent_workspace).unwrap();

    let loopback = LoopbackLlm::start(
        scripts,
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
    // The guest links fs / memory; their callables are deliberately not
    // registered so the catalog is the browser family alone.
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

    let driver = Arc::new(fake_browser());
    let policy = StaticUiPolicy {
        browser: Some(browser_policy()),
        screen: None,
    };
    let ui_grant = Arc::new(AllowlistGrant::from_policy(&policy));
    let deps = UiDeps {
        grant: ui_grant,
        policy: Arc::new(policy),
        leak: Arc::new(NoScan),
        events: bus.clone(),
        ssrf: None,
        injection: None,
    };
    register_ui_callables(
        &*callable_reg,
        deps,
        UiDrivers::browser(driver.clone()),
        UiSurfaces::BROWSER,
    );

    let dispatcher = Arc::new(CallableDispatcher::new(
        callable_reg,
        Arc::new(StaticCaps(vec!["llm".into(), "browser".into()])),
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

    let caps: Vec<CapRequest> = ["llm", "fs", "memory"]
        .into_iter()
        .map(|c| CapRequest {
            capability: CapabilityId::from(c),
        })
        .collect();
    let mut ctx = ComponentCtx::new(AGENT_ID.to_string(), "trace-ui".to_string(), Vec::new());
    ctx.stamp_trusted_turn("turn-ui-1".to_string());
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
        payload: prompt.as_bytes().to_vec(),
    };
    let action_result = bindings
        .advance_runtime_message_driven()
        .call_handle_message(&mut store, &msg, &state)
        .await
        .expect("call_handle_message does not trap")
        .expect("handle_message returns Ok");

    let events = captured.events.lock().unwrap().clone();
    Outcome {
        payload: action_result
            .actions
            .first()
            .map(|a| a.payload.clone())
            .unwrap_or_default(),
        bodies: loopback.all_chat_request_bodies(),
        events,
        current_url: driver.current_url(),
    }
}

fn tool_message<'a>(body: &'a serde_json::Value, call_id: &str) -> &'a str {
    body["messages"]
        .as_array()
        .expect("messages")
        .iter()
        .find(|m| m["role"] == "tool" && m["tool_call_id"] == call_id)
        .and_then(|m| m["content"].as_str())
        .unwrap_or_else(|| panic!("no tool message for {call_id} in {body}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn v5_browser_navigate_snapshot_click_then_text() {
    let out = run_ui_guest(
        vec![
            ScriptedResponse::ok_tool_calls(
                "call_1",
                "browser__navigate",
                &format!(r#"{{"url":"{FIXTURE_HOME_URL}"}}"#),
                11,
                6,
            ),
            ScriptedResponse::ok_tool_calls("call_2", "browser__snapshot", "{}", 12, 6),
            ScriptedResponse::ok_tool_calls("call_3", "browser__click", r#"{"ref":"e3"}"#, 13, 6),
            ScriptedResponse::ok_chat(FINAL_REPLY, 18, 4),
        ],
        "open the fixture and follow the next-page link",
    )
    .await;

    assert_eq!(
        out.payload,
        FINAL_REPLY.as_bytes(),
        "final text is the action payload"
    );
    assert_eq!(out.bodies.len(), 4, "navigate, snapshot, click, then text");

    let bodies: Vec<serde_json::Value> = out
        .bodies
        .iter()
        .map(|b| serde_json::from_str(b).expect("request body is JSON"))
        .collect();
    for (i, body) in bodies.iter().enumerate().take(3) {
        let names: Vec<&str> = body["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("request {} advertises tools", i + 1))
            .iter()
            .filter_map(|t| t["function"]["name"].as_str())
            .collect();
        assert!(
            names.contains(&"browser__navigate"),
            "request {}: {names:?}",
            i + 1
        );
        assert!(
            names.contains(&"browser__snapshot"),
            "request {}: {names:?}",
            i + 1
        );
        assert!(!names.contains(&"remember"), "request {}: {names:?}", i + 1);
        assert!(
            body.to_string().contains(IDENTITY),
            "request {} keeps the identity seed",
            i + 1
        );
    }

    let navigated = tool_message(&bodies[1], "call_1");
    assert!(navigated.starts_with("ok navigate: changed"), "{navigated}");
    assert!(
        navigated.ends_with("origin=https://fixture.test"),
        "{navigated}"
    );

    let observed = tool_message(&bodies[2], "call_2");
    assert!(observed.starts_with(OBSERVATION_BEGIN), "{observed}");
    assert!(
        observed.contains("surface=browser kind=snapshot"),
        "{observed}"
    );
    assert!(observed.contains("untrusted-content"), "{observed}");
    assert!(observed.contains("e3 link \"Next page\""), "{observed}");
    assert!(observed.contains("[secure]"), "{observed}");
    assert!(!observed.contains("hunter2"), "{observed}");

    let clicked = tool_message(&bodies[3], "call_3");
    assert!(clicked.starts_with("ok click: changed"), "{clicked}");
    assert!(
        clicked.ends_with("origin=https://fixture.test"),
        "{clicked}"
    );
    assert!(!clicked.contains("title="), "{clicked}");
    assert_eq!(out.current_url.as_deref(), Some(FIXTURE_NEXT_URL));

    let invoked: Vec<&Event> = out
        .events
        .iter()
        .filter(|e| e.event_type == "callable.invoked")
        .collect();
    assert_eq!(invoked.len(), 3, "{invoked:?}");
    assert_eq!(invoked[0].payload["name"], "browser__navigate");
    assert_eq!(invoked[1].payload["name"], "browser__snapshot");
    assert_eq!(invoked[2].payload["name"], "browser__click");
    assert!(invoked.iter().all(|e| e.payload["source"] == "host-fn"));
    assert!(invoked.iter().all(|e| e.payload["is_error"] == false));

    let ui: Vec<&Event> = out
        .events
        .iter()
        .filter(|e| e.event_type.starts_with("ui."))
        .collect();
    let types: Vec<&str> = ui.iter().map(|e| e.event_type.as_str()).collect();
    assert_eq!(
        types,
        ["ui.action", "ui.observation", "ui.action"],
        "{types:?}"
    );
    assert_eq!(ui[0].payload["verb"], "navigate");
    assert_eq!(ui[1].payload["kind"], "snapshot");
    assert_eq!(ui[2].payload["verb"], "click");
    assert!(ui.iter().all(|e| e.agent_id == AGENT_ID));
}

/// A refused navigation (origin outside the grant) is recorded as a tool-role
/// refusal; the turn still closes with the scripted text.
#[tokio::test(flavor = "multi_thread")]
async fn v5b_denied_origin_is_recorded_as_a_refusal() {
    let out = run_ui_guest(
        vec![
            ScriptedResponse::ok_tool_calls(
                "bad_1",
                "browser__navigate",
                r#"{"url":"https://denied.test/"}"#,
                11,
                6,
            ),
            ScriptedResponse::ok_chat(FINAL_REPLY, 18, 4),
        ],
        "open a page outside the grant",
    )
    .await;
    assert_eq!(out.payload, FINAL_REPLY.as_bytes());
    assert_eq!(out.bodies.len(), 2);
    let body: serde_json::Value = serde_json::from_str(&out.bodies[1]).unwrap();
    let refusal = tool_message(&body, "bad_1");
    assert!(refusal.contains("permission-denied"), "{refusal}");
    assert!(refusal.contains("denied.test"), "{refusal}");
    assert!(out
        .events
        .iter()
        .any(|e| e.event_type == "ui.refused" && e.payload["verb"] == "navigate"));
    assert!(out
        .events
        .iter()
        .any(|e| e.event_type == "callable.invoked" && e.payload["is_error"] == true));
    assert_eq!(out.current_url, None, "the driver never navigated");
}

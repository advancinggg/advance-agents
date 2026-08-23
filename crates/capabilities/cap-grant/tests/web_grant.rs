//! MODULE-013-T48 — `web.*` Layer-1 grant dimension (MODULE-013-AC-25).
//!
//! Grant + revoke + un-granted across host-fn **and** MCP-HTTP. Refusal
//! originates at GrantCheck. Offline withholds injection. `decoy.ping`
//! keeps withheld lists as `Ok(List)` so empty-on-Err cannot pass.

mod common;

use std::sync::{Arc, Mutex};

use advance_runtime::host_registry::{
    HostCallContext, HostFunctionHandler, HostRegistry, InMemoryHostRegistry,
};
use advance_shared_types::agent_tree::Capability;
use advance_shared_types::capability::{CapParams, CapabilityId, GrantDecision};
use advance_shared_types::event::Event;
use advance_shared_types::repetition::{OutputHash, RepetitionDecision, ToolCallSignature};
use advance_shared_types::security_validator::{
    Allowlist, HttpCapability, HttpRequest, HttpResponse, HttpSecurityChain, LeakDetector,
    ScanContext, ScanResult,
};
use advance_shared_types::traits::{EventBusEmit, GrantCheck, RepetitionGuardCheck};
use advance_shared_types::web_search::{
    WEB_EXTRACT_TOOL_ID, WEB_GRANT_CAPABILITY, WEB_SEARCH_TOOL_ID,
};
use async_trait::async_trait;
use cap_grant::data::{
    CapParam, Grant, GrantDraft, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl,
};
use cap_grant::{
    validate_capability_subset, AuthzLevel, GrantCheckImpl, StaticConfigCompiler, SubsetValidator,
    SubsetValidatorImpl,
};
use cap_mcp::{
    register_mcp_client, register_mcp_client_with_web_grant, McpClient, McpServerEntry,
    McpServersConfig, McpTransportSpec, ToolPattern,
};
use cap_tools::host_fn::{WebAwareInvokeHandler, WebAwareListHandler};
use cap_tools::lazy_registry::{LazyRegistryConfig, LazyToolRegistry};
use cap_tools::web::{
    agent_tool_infos, CompositeToolRegistry, FixtureProvider, HostToolRegistry,
    OfflineDenyingGrantCheck, WebFamilyConfig, WebFamilyDispatcher, WebFamilyParts,
};
use cap_tools::{MethodInfo, ToolInfo, ToolRegistry};
use chrono::Utc;
use wasmtime::component::Val;

use crate::common::make_store;

const AGENT: &str = "agent-1";
const MCP_SERVER: &str = "web-http";
const DECOY: &str = "decoy.ping";

struct NoopBus;
impl EventBusEmit for NoopBus {
    fn emit(&self, _: Event) {}
}

struct NoopGuard;
impl RepetitionGuardCheck for NoopGuard {
    fn record_tool_call(&self, _: &str, _: ToolCallSignature) -> RepetitionDecision {
        RepetitionDecision::Pass
    }
    fn record_output(&self, _: &str, _: OutputHash) -> RepetitionDecision {
        RepetitionDecision::Pass
    }
}

struct NoOpDetector;
impl LeakDetector for NoOpDetector {
    fn scan(&self, _: &str, _: ScanContext) -> ScanResult {
        ScanResult::Clean
    }
    fn scan_headers(&self, _: &[(String, String)]) -> ScanResult {
        ScanResult::Clean
    }
}

struct WebHttpMock {
    captured: Mutex<Vec<serde_json::Value>>,
}

impl WebHttpMock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            captured: Mutex::new(Vec::new()),
        })
    }
    fn captured(&self) -> Vec<serde_json::Value> {
        self.captured.lock().unwrap().clone()
    }
    fn tools_call_names(&self) -> Vec<String> {
        self.captured()
            .iter()
            .filter(|j| j["method"] == "tools/call")
            .filter_map(|j| j["params"]["name"].as_str().map(str::to_string))
            .collect()
    }
}

#[async_trait]
impl HttpSecurityChain for WebHttpMock {
    async fn execute(
        &self,
        _agent_id: &str,
        req: HttpRequest,
        _cap: &HttpCapability,
    ) -> Result<HttpResponse, advance_shared_types::security_validator::HttpError> {
        let parsed: serde_json::Value = serde_json::from_slice(&req.body).expect("jsonrpc body");
        self.captured.lock().unwrap().push(parsed.clone());
        let id = parsed["id"].clone();
        let method = parsed["method"].as_str().unwrap_or("");
        let result = match method {
            "tools/list" => serde_json::json!({
                "tools": [
                    {"name": WEB_SEARCH_TOOL_ID, "description": "search"},
                    {"name": WEB_EXTRACT_TOOL_ID, "description": "extract"},
                    {"name": DECOY, "description": "decoy"}
                ]
            }),
            "tools/call" => match parsed["params"]["name"].as_str() {
                Some(WEB_SEARCH_TOOL_ID) => serde_json::json!({
                    "hits": [{
                        "title": "t",
                        "url": "https://example.com",
                        "snippet": "s",
                        "rank": 1,
                        "result_ref": "wr_mcp"
                    }]
                }),
                Some(WEB_EXTRACT_TOOL_ID) => serde_json::json!({
                    "evidence_id": "ev_mcp",
                    "url": "https://example.com",
                    "text": "hello"
                }),
                other => panic!("unexpected tools/call name: {other:?}"),
            },
            other => panic!("unexpected jsonrpc method: {other}"),
        };
        let envelope = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
        });
        Ok(HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: serde_json::to_vec(&envelope).unwrap(),
        })
    }
}

fn web_grant(id: &str) -> Grant {
    Grant {
        id: GrantId::new(id),
        grantee: AGENT.to_string(),
        capability: WEB_GRANT_CAPABILITY.to_string(),
        params: vec![],
        ttl: GrantTtl::Persistent,
        issuer: GrantIssuer::Resolver("test".to_string()),
        provenance: GrantProvenance::Requested,
        status: GrantStatus::Active,
        created_at: Utc::now(),
        expires_at: None,
    }
}

fn cap_grant(id: &str, capability: &str) -> Grant {
    Grant {
        id: GrantId::new(id),
        grantee: AGENT.to_string(),
        capability: capability.to_string(),
        params: vec![],
        ttl: GrantTtl::Persistent,
        issuer: GrantIssuer::Resolver("test".to_string()),
        provenance: GrantProvenance::Requested,
        status: GrantStatus::Active,
        created_at: Utc::now(),
        expires_at: None,
    }
}

fn decoy_info() -> ToolInfo {
    ToolInfo {
        id: DECOY.into(),
        description: "non-web decoy".into(),
        methods: vec![MethodInfo {
            name: "ping".into(),
            description: None,
            input_schema: None,
            output_schema: None,
            idempotent: Some(true),
        }],
    }
}

fn host_ctx() -> HostCallContext {
    HostCallContext {
        agent_id: AGENT.into(),
        trace_id: "t48".into(),
        turn_id: None,
        capability: "tools".into(),
        function: "advance:runtime/agent-tools@0.1.0::tool-invoke".into(),
        run_id: None,
        iteration: None,
    }
}

fn mcp_ctx() -> HostCallContext {
    HostCallContext {
        agent_id: AGENT.into(),
        trace_id: "t48".into(),
        turn_id: None,
        capability: "mcp.tool-patterns".into(),
        function: "advance:runtime/mcp-client@0.1.0::invoke-mcp-tool".into(),
        run_id: None,
        iteration: None,
    }
}

fn invoke_vals(tool_id: &str, method: &str, body: &[u8]) -> Vec<Val> {
    vec![
        Val::String(tool_id.into()),
        Val::String(method.into()),
        Val::List(body.iter().copied().map(Val::U8).collect()),
    ]
}

fn mcp_invoke_vals(tool: &str, body: &[u8]) -> Vec<Val> {
    vec![
        Val::String(MCP_SERVER.into()),
        Val::String(tool.into()),
        Val::List(body.iter().copied().map(Val::U8).collect()),
    ]
}

fn err_class(v: &Val) -> Option<String> {
    match v {
        Val::Result(Err(Some(inner))) => match inner.as_ref() {
            Val::Variant(case, _) => Some(case.clone()),
            _ => None,
        },
        _ => None,
    }
}

fn ok_list_field(v: &Val, field: &str) -> Vec<String> {
    let Val::Result(Ok(Some(inner))) = v else {
        panic!("expected Ok(List), got {v:?}");
    };
    let Val::List(items) = inner.as_ref() else {
        panic!("expected List, got {inner:?}");
    };
    items
        .iter()
        .filter_map(|item| {
            let Val::Record(fields) = item else {
                return None;
            };
            fields.iter().find_map(|(k, val)| {
                if k == field {
                    if let Val::String(s) = val {
                        return Some(s.clone());
                    }
                }
                None
            })
        })
        .collect()
}

fn assert_permission_denied(v: &Val) {
    assert_eq!(err_class(v).as_deref(), Some("permission-denied"), "{v:?}");
}

fn ok_bytes(v: &Val) -> Vec<u8> {
    match v {
        Val::Result(Ok(Some(inner))) => match inner.as_ref() {
            Val::List(items) => items
                .iter()
                .map(|x| match x {
                    Val::U8(b) => *b,
                    other => panic!("non-u8 in result list: {other:?}"),
                })
                .collect(),
            other => panic!("Ok arm is not a list: {other:?}"),
        },
        other => panic!("expected Ok bytes, got {other:?}"),
    }
}

async fn host_handlers(grant: Arc<dyn GrantCheck>) -> (WebAwareInvokeHandler, WebAwareListHandler) {
    let host = HostToolRegistry::new();
    for info in agent_tool_infos() {
        host.register(info).await;
    }
    host.register(decoy_info()).await;
    let wasm = Arc::new(LazyToolRegistry::new(LazyRegistryConfig::default()));
    let tools: Arc<dyn ToolRegistry> = Arc::new(CompositeToolRegistry {
        host: Arc::new(host),
        wasm,
    });
    let dispatcher = Arc::new(WebFamilyDispatcher::from_parts(WebFamilyParts {
        chain: None,
        helpers: None,
        web: WebFamilyConfig::default(),
        tools: Default::default(),
        evidence_ids: Arc::new(cap_tools::web::EvidenceIdStore::new()),
        provider: Arc::new(FixtureProvider::default()),
    }));
    (
        WebAwareInvokeHandler {
            tools: Arc::clone(&tools),
            emitter: Arc::new(NoopBus),
            repetition_guard: Arc::new(NoopGuard),
            web_grant: Arc::clone(&grant),
            dispatcher: Some(Arc::clone(&dispatcher)),
        },
        WebAwareListHandler {
            tools,
            emitter: Arc::new(NoopBus),
            web_grant: grant,
            dispatcher: Some(dispatcher),
        },
    )
}

fn dummy_http_cap() -> HttpCapability {
    HttpCapability {
        allowlist: Allowlist {
            patterns: vec!["https://mcp.example.com/*".into()],
        },
        credentials: vec![],
        component_id: MCP_SERVER.into(),
    }
}

fn mcp_client(chain: Arc<dyn HttpSecurityChain>) -> Arc<McpClient> {
    let patterns = vec![
        ToolPattern::compile(WEB_SEARCH_TOOL_ID).unwrap(),
        ToolPattern::compile(WEB_EXTRACT_TOOL_ID).unwrap(),
        ToolPattern::compile(DECOY).unwrap(),
    ];
    let entry = McpServerEntry {
        server_id: MCP_SERVER.into(),
        description: "t48 web http".into(),
        transport: McpTransportSpec::Http {
            endpoint_url: "https://mcp.example.com/v1".into(),
            capability: dummy_http_cap(),
        },
        tool_patterns: Some(patterns),
        tool_schemas: Default::default(),
    };
    let cfg = Arc::new(
        McpServersConfig::builder()
            .add_server(entry)
            .unwrap()
            .build(),
    );
    Arc::new(McpClient::new(cfg, Arc::new(NoOpDetector), Some(chain)))
}

fn mcp_spec(
    registry: &InMemoryHostRegistry,
    name: &str,
) -> advance_runtime::host_registry::HostFunctionSpec {
    registry
        .lookup("mcp.tool-patterns")
        .into_iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("missing {name}"))
}

fn authz_web(bus: &common::RecordingBus, decision: &str, function: &str) -> bool {
    bus.all_of("authz.checked").iter().any(|e| {
        e.payload.get("capability").and_then(|v| v.as_str()) == Some(WEB_GRANT_CAPABILITY)
            && e.payload.get("decision").and_then(|v| v.as_str()) == Some(decision)
            && e.payload.get("function").and_then(|v| v.as_str()) == Some(function)
    })
}

fn web_denied_any(bus: &common::RecordingBus) -> bool {
    bus.all_of("authz.checked").iter().any(|e| {
        e.payload.get("capability").and_then(|v| v.as_str()) == Some(WEB_GRANT_CAPABILITY)
            && e.payload.get("decision").and_then(|v| v.as_str()) == Some("denied")
    })
}

#[tokio::test]
async fn t48_grant_revoke_both_realizations() {
    // MODULE-013-T48-a..d
    let (store, bus, _h) = make_store();
    let gid = store.insert_dynamic(web_grant("g-web")).unwrap();
    let check: Arc<dyn GrantCheck> = Arc::new(GrantCheckImpl::with_authz_level(
        store.clone(),
        AuthzLevel::All,
    ));

    let (host_invoke, host_list) = host_handlers(Arc::clone(&check)).await;
    let listed = host_list.call(host_ctx(), vec![], 1).await.unwrap();
    let ids = ok_list_field(&listed[0], "id");
    assert!(ids.contains(&WEB_SEARCH_TOOL_ID.to_string()));
    assert!(ids.contains(&WEB_EXTRACT_TOOL_ID.to_string()));
    assert!(ids.contains(&DECOY.to_string()));

    let search = host_invoke
        .call(
            host_ctx(),
            invoke_vals(WEB_SEARCH_TOOL_ID, "search", br#"{"query":"rust"}"#),
            1,
        )
        .await
        .unwrap();
    let body = ok_bytes(&search[0]);
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let result_ref = parsed["hits"][0]["result_ref"]
        .as_str()
        .expect("result_ref")
        .to_string();
    assert!(parsed["hits"]
        .as_array()
        .map(|h| !h.is_empty())
        .unwrap_or(false));
    let extract_args = serde_json::json!({"result_ref": result_ref});
    let extracted = host_invoke
        .call(
            host_ctx(),
            invoke_vals(
                WEB_EXTRACT_TOOL_ID,
                "extract",
                extract_args.to_string().as_bytes(),
            ),
            1,
        )
        .await
        .unwrap();
    let extract_js: serde_json::Value =
        serde_json::from_slice(&ok_bytes(&extracted[0])).expect("host extract json");
    assert!(
        extract_js["evidence_id"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "host extract evidence: {extract_js}"
    );
    assert!(authz_web(&bus, "allowed", "tool-invoke"));

    let mock = WebHttpMock::new();
    let client = mcp_client(mock.clone());
    let registry = InMemoryHostRegistry::new();
    register_mcp_client_with_web_grant(&registry, client, Arc::clone(&check));
    let list_h = mcp_spec(&registry, "list-mcp-tools");
    let inv_h = mcp_spec(&registry, "invoke-mcp-tool");
    let mcp_listed = list_h
        .handler
        .call(mcp_ctx(), vec![Val::String(MCP_SERVER.into())], 1)
        .await
        .unwrap();
    let names = ok_list_field(&mcp_listed[0], "name");
    assert!(names.contains(&WEB_SEARCH_TOOL_ID.to_string()));
    assert!(names.contains(&WEB_EXTRACT_TOOL_ID.to_string()));
    assert!(names.contains(&DECOY.to_string()));
    let mcp_search = inv_h
        .handler
        .call(
            mcp_ctx(),
            mcp_invoke_vals(WEB_SEARCH_TOOL_ID, br#"{"query":"q"}"#),
            1,
        )
        .await
        .unwrap();
    let mcp_search_js: serde_json::Value =
        serde_json::from_slice(&ok_bytes(&mcp_search[0])).expect("mcp search json");
    assert!(
        mcp_search_js["hits"]
            .as_array()
            .is_some_and(|h| !h.is_empty()),
        "mcp search hits: {mcp_search_js}"
    );
    let mcp_extract = inv_h
        .handler
        .call(
            mcp_ctx(),
            mcp_invoke_vals(WEB_EXTRACT_TOOL_ID, br#"{"result_ref":"wr_mcp"}"#),
            1,
        )
        .await
        .unwrap();
    let mcp_extract_js: serde_json::Value =
        serde_json::from_slice(&ok_bytes(&mcp_extract[0])).expect("mcp extract json");
    assert!(
        mcp_extract_js["evidence_id"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "mcp extract evidence: {mcp_extract_js}"
    );
    let calls = mock.tools_call_names();
    assert!(calls.contains(&WEB_SEARCH_TOOL_ID.to_string()));
    assert!(calls.contains(&WEB_EXTRACT_TOOL_ID.to_string()));
    assert!(authz_web(&bus, "allowed", "invoke-mcp-tool"));
    let calls_after_allow = mock.tools_call_names().len();

    store.cascade_revoke(gid.as_str()).unwrap();

    let listed = host_list.call(host_ctx(), vec![], 1).await.unwrap();
    let ids = ok_list_field(&listed[0], "id");
    assert!(ids.contains(&DECOY.to_string()));
    assert!(!ids.contains(&WEB_SEARCH_TOOL_ID.to_string()));
    assert!(!ids.contains(&WEB_EXTRACT_TOOL_ID.to_string()));
    for tool in [WEB_SEARCH_TOOL_ID, WEB_EXTRACT_TOOL_ID] {
        let method = if tool == WEB_SEARCH_TOOL_ID {
            "search"
        } else {
            "extract"
        };
        let body: &[u8] = if tool == WEB_SEARCH_TOOL_ID {
            br#"{"query":"x"}"#
        } else {
            br#"{"result_ref":"wr_x"}"#
        };
        let out = host_invoke
            .call(host_ctx(), invoke_vals(tool, method, body), 1)
            .await
            .unwrap();
        assert_permission_denied(&out[0]);
    }
    assert!(authz_web(&bus, "denied", "tool-invoke"));

    let mcp_listed = list_h
        .handler
        .call(mcp_ctx(), vec![Val::String(MCP_SERVER.into())], 1)
        .await
        .unwrap();
    let names = ok_list_field(&mcp_listed[0], "name");
    assert!(names.contains(&DECOY.to_string()));
    assert!(!names.contains(&WEB_SEARCH_TOOL_ID.to_string()));
    assert!(!names.contains(&WEB_EXTRACT_TOOL_ID.to_string()));
    for tool in [WEB_SEARCH_TOOL_ID, WEB_EXTRACT_TOOL_ID] {
        let body: &[u8] = if tool == WEB_SEARCH_TOOL_ID {
            br#"{"query":"x"}"#
        } else {
            br#"{"result_ref":"wr_x"}"#
        };
        let out = inv_h
            .handler
            .call(mcp_ctx(), mcp_invoke_vals(tool, body), 1)
            .await
            .unwrap();
        assert_permission_denied(&out[0]);
    }
    assert!(authz_web(&bus, "denied", "invoke-mcp-tool"));
    assert_eq!(mock.tools_call_names().len(), calls_after_allow);
}

#[tokio::test]
async fn t48_e_ungranted_both_realizations() {
    let (store, bus, _h) = make_store();
    let check: Arc<dyn GrantCheck> =
        Arc::new(GrantCheckImpl::with_authz_level(store, AuthzLevel::All));
    let (host_invoke, host_list) = host_handlers(Arc::clone(&check)).await;
    let listed = host_list.call(host_ctx(), vec![], 1).await.unwrap();
    let ids = ok_list_field(&listed[0], "id");
    assert!(ids.contains(&DECOY.to_string()));
    assert!(!ids.contains(&WEB_SEARCH_TOOL_ID.to_string()));
    assert!(!ids.contains(&WEB_EXTRACT_TOOL_ID.to_string()));
    for tool in [WEB_SEARCH_TOOL_ID, WEB_EXTRACT_TOOL_ID] {
        let method = if tool == WEB_SEARCH_TOOL_ID {
            "search"
        } else {
            "extract"
        };
        let body: &[u8] = if tool == WEB_SEARCH_TOOL_ID {
            br#"{"query":"x"}"#
        } else {
            br#"{"result_ref":"wr_x"}"#
        };
        let out = host_invoke
            .call(host_ctx(), invoke_vals(tool, method, body), 1)
            .await
            .unwrap();
        assert_permission_denied(&out[0]);
    }

    let mock = WebHttpMock::new();
    let client = mcp_client(mock.clone());
    let registry = InMemoryHostRegistry::new();
    register_mcp_client_with_web_grant(&registry, client, check);
    let list_h = mcp_spec(&registry, "list-mcp-tools");
    let inv_h = mcp_spec(&registry, "invoke-mcp-tool");
    let mcp_listed = list_h
        .handler
        .call(mcp_ctx(), vec![Val::String(MCP_SERVER.into())], 1)
        .await
        .unwrap();
    let names = ok_list_field(&mcp_listed[0], "name");
    assert!(names.contains(&DECOY.to_string()));
    assert!(!names.contains(&WEB_SEARCH_TOOL_ID.to_string()));
    assert!(!names.contains(&WEB_EXTRACT_TOOL_ID.to_string()));
    for tool in [WEB_SEARCH_TOOL_ID, WEB_EXTRACT_TOOL_ID] {
        let body: &[u8] = if tool == WEB_SEARCH_TOOL_ID {
            br#"{"query":"x"}"#
        } else {
            br#"{"result_ref":"wr_x"}"#
        };
        let out = inv_h
            .handler
            .call(mcp_ctx(), mcp_invoke_vals(tool, body), 1)
            .await
            .unwrap();
        assert_permission_denied(&out[0]);
    }
    assert!(authz_web(&bus, "denied", "tool-invoke"));
    assert!(authz_web(&bus, "denied", "invoke-mcp-tool"));
    assert!(mock.tools_call_names().is_empty());
}

#[tokio::test]
async fn t48_f_offline_withholds_injection() {
    let (store, bus, _h) = make_store();
    store.insert_dynamic(web_grant("g-web")).unwrap();
    let inner: Arc<dyn GrantCheck> =
        Arc::new(GrantCheckImpl::with_authz_level(store, AuthzLevel::All));
    let off: Arc<dyn GrantCheck> = Arc::new(OfflineDenyingGrantCheck {
        inner,
        offline: true,
    });
    let (host_invoke, host_list) = host_handlers(Arc::clone(&off)).await;
    let listed = host_list.call(host_ctx(), vec![], 1).await.unwrap();
    let ids = ok_list_field(&listed[0], "id");
    assert!(ids.contains(&DECOY.to_string()));
    assert!(!ids.contains(&WEB_SEARCH_TOOL_ID.to_string()));
    assert!(!ids.contains(&WEB_EXTRACT_TOOL_ID.to_string()));
    for tool in [WEB_SEARCH_TOOL_ID, WEB_EXTRACT_TOOL_ID] {
        let method = if tool == WEB_SEARCH_TOOL_ID {
            "search"
        } else {
            "extract"
        };
        let body: &[u8] = if tool == WEB_SEARCH_TOOL_ID {
            br#"{"query":"x"}"#
        } else {
            br#"{"result_ref":"wr_x"}"#
        };
        let out = host_invoke
            .call(host_ctx(), invoke_vals(tool, method, body), 1)
            .await
            .unwrap();
        assert_permission_denied(&out[0]);
    }

    let mock = WebHttpMock::new();
    let client = mcp_client(mock.clone());
    let registry = InMemoryHostRegistry::new();
    register_mcp_client_with_web_grant(&registry, client, off);
    let list_h = mcp_spec(&registry, "list-mcp-tools");
    let inv_h = mcp_spec(&registry, "invoke-mcp-tool");
    let mcp_listed = list_h
        .handler
        .call(mcp_ctx(), vec![Val::String(MCP_SERVER.into())], 1)
        .await
        .unwrap();
    let names = ok_list_field(&mcp_listed[0], "name");
    assert!(names.contains(&DECOY.to_string()));
    assert!(!names.contains(&WEB_SEARCH_TOOL_ID.to_string()));
    assert!(!names.contains(&WEB_EXTRACT_TOOL_ID.to_string()));
    for tool in [WEB_SEARCH_TOOL_ID, WEB_EXTRACT_TOOL_ID] {
        let body: &[u8] = if tool == WEB_SEARCH_TOOL_ID {
            br#"{"query":"x"}"#
        } else {
            br#"{"result_ref":"wr_x"}"#
        };
        let out = inv_h
            .handler
            .call(mcp_ctx(), mcp_invoke_vals(tool, body), 1)
            .await
            .unwrap();
        assert_permission_denied(&out[0]);
    }
    assert!(!web_denied_any(&bus));
    assert!(mock.tools_call_names().is_empty());
}

#[test]
fn t48_g_dimension_independence() {
    let (store, _bus, _h) = make_store();
    store.insert_dynamic(web_grant("g-web")).unwrap();
    let check = GrantCheckImpl::with_authz_level(store.clone(), AuthzLevel::All);
    for cap in ["tools", "mcp.servers", "mcp.tool-patterns", "http", "fs"] {
        assert!(
            matches!(
                check.check(AGENT, cap, "fn", &CapParams::empty()),
                GrantDecision::Deny(_)
            ),
            "{cap} must Deny under a web-only grant"
        );
    }
    let (store2, _b2, _h2) = make_store();
    store2
        .insert_dynamic(cap_grant("g-tools", "tools"))
        .unwrap();
    let check2 = GrantCheckImpl::with_authz_level(store2, AuthzLevel::All);
    assert!(matches!(
        check2.check(
            AGENT,
            WEB_GRANT_CAPABILITY,
            "tool-invoke",
            &CapParams::empty()
        ),
        GrantDecision::Deny(_)
    ));
}

#[test]
fn t48_h_yaml_web_true_compiles() {
    let v: serde_yml::Value = serde_yml::from_str("capabilities:\n  web: true\n").unwrap();
    let grants = StaticConfigCompiler::compile_from_value(&v, "root").unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].capability, WEB_GRANT_CAPABILITY);
    assert!(grants[0].params.is_empty());
    assert_eq!(grants[0].id.as_str(), "static:root:web");
}

#[test]
fn t48_i_subset_whitelist_and_web_arm() {
    let parent = vec![Capability {
        id: CapabilityId::new(WEB_GRANT_CAPABILITY),
        params: CapParams::empty(),
    }];
    let child = vec![Capability {
        id: CapabilityId::new(WEB_GRANT_CAPABILITY),
        params: CapParams::empty(),
    }];
    validate_capability_subset(&parent, &child).expect("Null/Null web subset Ok");
    let bogus = vec![Capability {
        id: CapabilityId::new(WEB_GRANT_CAPABILITY),
        params: CapParams::new(serde_json::json!({"bogus": 1})),
    }];
    assert!(validate_capability_subset(&parent, &bogus).is_err());

    let parent_g = Grant {
        id: GrantId::new("p"),
        grantee: AGENT.to_string(),
        capability: WEB_GRANT_CAPABILITY.to_string(),
        params: vec![CapParam {
            key: "foo".into(),
            value: "bar".into(),
        }],
        ttl: GrantTtl::Persistent,
        issuer: GrantIssuer::Config,
        provenance: GrantProvenance::Requested,
        status: GrantStatus::Active,
        created_at: Utc::now(),
        expires_at: None,
    };
    let child_d = GrantDraft {
        capability: WEB_GRANT_CAPABILITY.to_string(),
        params: vec![CapParam {
            key: "foo".into(),
            value: "bar".into(),
        }],
        ttl: GrantTtl::Persistent,
    };
    let err = SubsetValidatorImpl::new()
        .validate(&parent_g, &child_d)
        .expect_err("non-empty web params fail-closed");
    let msg = err.to_string();
    assert!(
        msg.contains("whole-capability-only"),
        "expected web arm, got {msg}"
    );
    assert!(!msg.contains("unknown capability"));
}

#[tokio::test]
async fn t48_j_two_arg_registrar_fail_closed() {
    let mock = WebHttpMock::new();
    let client = mcp_client(mock.clone());
    let registry = InMemoryHostRegistry::new();
    register_mcp_client(&registry, client);
    let list_h = mcp_spec(&registry, "list-mcp-tools");
    let inv_h = mcp_spec(&registry, "invoke-mcp-tool");
    let mcp_listed = list_h
        .handler
        .call(mcp_ctx(), vec![Val::String(MCP_SERVER.into())], 1)
        .await
        .unwrap();
    let names = ok_list_field(&mcp_listed[0], "name");
    assert!(names.contains(&DECOY.to_string()));
    assert!(!names.contains(&WEB_SEARCH_TOOL_ID.to_string()));
    assert!(!names.contains(&WEB_EXTRACT_TOOL_ID.to_string()));
    for tool in [WEB_SEARCH_TOOL_ID, WEB_EXTRACT_TOOL_ID] {
        let body: &[u8] = if tool == WEB_SEARCH_TOOL_ID {
            br#"{"query":"x"}"#
        } else {
            br#"{"result_ref":"wr_x"}"#
        };
        let out = inv_h
            .handler
            .call(mcp_ctx(), mcp_invoke_vals(tool, body), 1)
            .await
            .unwrap();
        assert_permission_denied(&out[0]);
    }
    assert!(mock.tools_call_names().is_empty());
}

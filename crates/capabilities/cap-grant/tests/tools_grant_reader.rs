//! CONTRACT-183 `ToolsGrantReader` unit coverage (Wave-15 Lane E), and its `mcp`
//! and `web` counterparts `McpGrantReader` and `WebGrantReader`.
//!
//! Verifies the `tools.ids` allowlist projection: ids→narrow, no-ids→wildcard(None),
//! no-grant→deny(Some([])), expired/revoked/non-tools excluded, CSV de-dup union,
//! and the colon→bare grantee bridge. For `mcp`: one scope per active grant, never
//! merged, agreeing with the call-time check, and silent (no `authz.checked`); the
//! mcp-client host functions over the real grant check and readers. For `web`:
//! held by an active, unexpired grant, agreeing with the check, and silent.

mod common;

use advance_shared_types::capability::{CapParams, GrantDecision};
use advance_shared_types::mcp::{McpGrantScope, MAX_REQUEST_TOKEN_BYTES};
use advance_shared_types::traits::{GrantCheck, McpGrantReader, ToolsGrantReader, WebGrantReader};
use cap_grant::data::{
    CapParam, Grant, GrantId, GrantIssuer, GrantProvenance, GrantStatus, GrantTtl,
};
use cap_grant::{
    AuthzLevel, GrantCheckImpl, McpGrantReaderImpl, ToolsGrantReaderImpl, WebGrantReaderImpl,
};
use chrono::Utc;

use common::make_store;

fn tools_grant(id: &str, grantee: &str, ids_csv: Option<&str>, status: GrantStatus) -> Grant {
    Grant {
        id: GrantId::new(id),
        grantee: grantee.to_string(),
        capability: "tools".to_string(),
        params: match ids_csv {
            Some(v) => vec![CapParam {
                key: "ids".to_string(),
                value: v.to_string(),
            }],
            None => vec![],
        },
        ttl: GrantTtl::Persistent,
        issuer: GrantIssuer::Config,
        provenance: GrantProvenance::StaticConfig,
        status,
        created_at: Utc::now(),
        expires_at: None,
    }
}

#[test]
fn tgr_01_ids_grant_narrows_to_allowlist() {
    let (store, _bus, _h) = make_store();
    store
        .insert(tools_grant(
            "g1",
            "alice",
            Some("toola,toolb"),
            GrantStatus::Active,
        ))
        .unwrap();
    let reader = ToolsGrantReaderImpl::new(store);
    assert_eq!(
        reader.tool_allowlist("alice"),
        Some(vec!["toola".to_string(), "toolb".to_string()])
    );
}

#[test]
fn tgr_02_no_ids_grant_is_wildcard_none() {
    let (store, _bus, _h) = make_store();
    store
        .insert(tools_grant("g1", "alice", None, GrantStatus::Active))
        .unwrap();
    let reader = ToolsGrantReaderImpl::new(store);
    assert_eq!(reader.tool_allowlist("alice"), None);
}

#[test]
fn tgr_03_no_tools_grant_denies_all() {
    let (store, _bus, _h) = make_store();
    // A non-"tools" grant must NOT grant tools.
    let mut g = tools_grant("g1", "alice", Some("toola"), GrantStatus::Active);
    g.capability = "fs".to_string();
    store.insert(g).unwrap();
    let reader = ToolsGrantReaderImpl::new(store);
    assert_eq!(reader.tool_allowlist("alice"), Some(Vec::new()));
}

#[test]
fn tgr_04_revoked_grant_excluded() {
    let (store, _bus, _h) = make_store();
    store
        .insert(tools_grant(
            "g1",
            "alice",
            Some("toola"),
            GrantStatus::Revoked,
        ))
        .unwrap();
    let reader = ToolsGrantReaderImpl::new(store);
    // Revoked → not counted → deny all.
    assert_eq!(reader.tool_allowlist("alice"), Some(Vec::new()));
}

#[test]
fn tgr_05_expired_grant_excluded() {
    let (store, _bus, _h) = make_store();
    let mut g = tools_grant("g1", "alice", Some("toola"), GrantStatus::Active);
    g.expires_at = Some(Utc::now() - chrono::Duration::hours(1));
    store.insert(g).unwrap();
    let reader = ToolsGrantReaderImpl::new(store);
    // Active-but-expired → excluded → deny all.
    assert_eq!(reader.tool_allowlist("alice"), Some(Vec::new()));
}

#[test]
fn tgr_06_colon_to_bare_bridge() {
    let (store, _bus, _h) = make_store();
    // Seed under the BARE id (`insert` rejects colon grantees); query with the COLON id.
    store
        .insert(tools_grant(
            "g1",
            "harness",
            Some("toola"),
            GrantStatus::Active,
        ))
        .unwrap();
    let reader = ToolsGrantReaderImpl::new(store);
    assert_eq!(
        reader.tool_allowlist("agent:harness"),
        Some(vec!["toola".to_string()])
    );
}

#[test]
fn tgr_07_union_de_duped_across_grants() {
    let (store, _bus, _h) = make_store();
    store
        .insert(tools_grant(
            "g1",
            "alice",
            Some("toola"),
            GrantStatus::Active,
        ))
        .unwrap();
    store
        .insert(tools_grant(
            "g2",
            "alice",
            Some("toolb, toola"),
            GrantStatus::Active,
        ))
        .unwrap();
    let reader = ToolsGrantReaderImpl::new(store);
    let allow = reader.tool_allowlist("alice").unwrap();
    assert!(allow.contains(&"toola".to_string()));
    assert!(allow.contains(&"toolb".to_string()));
    assert_eq!(
        allow.len(),
        2,
        "ids are de-duped across grants; got {allow:?}"
    );
}

// ===== McpGrantReader =====

fn mcp_grant(id: &str, grantee: &str, params: &[(&str, &str)]) -> Grant {
    let mut g = tools_grant(id, grantee, None, GrantStatus::Active);
    g.capability = "mcp".to_string();
    g.params = params
        .iter()
        .map(|(key, value)| CapParam {
            key: key.to_string(),
            value: value.to_string(),
        })
        .collect();
    g
}

fn scope(servers: Option<&[&str]>, patterns: Option<&[&str]>) -> McpGrantScope {
    let owned = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    McpGrantScope {
        servers: servers.map(owned),
        tool_patterns: patterns.map(owned),
    }
}

#[test]
fn mgr_01_one_scope_per_active_mcp_grant() {
    let (store, _bus, _h) = make_store();
    store
        .insert(mcp_grant(
            "g-a",
            "alice",
            &[("servers", "a"), ("tool-patterns", "x*, y_tool")],
        ))
        .unwrap();
    store
        .insert(mcp_grant("g-b", "alice", &[("servers", "a,b")]))
        .unwrap();
    store
        .insert(mcp_grant("g-c", "alice", &[("tool-patterns", "z*")]))
        .unwrap();
    let mut revoked = mcp_grant("g-d", "alice", &[]);
    revoked.status = GrantStatus::Revoked;
    store.insert(revoked).unwrap();
    let mut expired = mcp_grant("g-e", "alice", &[]);
    expired.expires_at = Some(Utc::now() - chrono::Duration::hours(1));
    store.insert(expired).unwrap();
    // A misspelled key covers nothing, so the grant lists nothing.
    store
        .insert(mcp_grant(
            "g-f",
            "alice",
            &[("servers", "a"), ("tool_patterns", "x*")],
        ))
        .unwrap();
    store
        .insert(tools_grant("g-g", "alice", None, GrantStatus::Active))
        .unwrap();
    store
        .insert(mcp_grant("g-h", "bob", &[("servers", "a")]))
        .unwrap();

    let reader = McpGrantReaderImpl::new(store);
    assert_eq!(
        reader.mcp_grant_scopes("alice"),
        vec![
            scope(Some(&["a"]), Some(&["x*", "y_tool"])),
            scope(Some(&["a", "b"]), None),
            // No `servers`: the grant reaches no server.
            scope(Some(&[]), Some(&["z*"])),
        ]
    );
}

#[test]
fn mgr_02_whole_capability_grant_and_no_grant() {
    let (store, _bus, _h) = make_store();
    store.insert(mcp_grant("g1", "alice", &[])).unwrap();
    let reader = McpGrantReaderImpl::new(store);
    assert_eq!(
        reader.mcp_grant_scopes("alice"),
        vec![McpGrantScope::unrestricted()]
    );
    assert_eq!(reader.mcp_grant_scopes("bob"), Vec::new());
}

#[test]
fn mgr_03_colon_to_bare_bridge() {
    let (store, _bus, _h) = make_store();
    store
        .insert(mcp_grant("g1", "harness", &[("servers", "a")]))
        .unwrap();
    let reader = McpGrantReaderImpl::new(store);
    assert_eq!(
        reader.mcp_grant_scopes("agent:harness"),
        vec![scope(Some(&["a"]), None)]
    );
}

// A listing filtered through the scopes shows exactly what the call-time check allows,
// keeps grants apart, and writes no `authz.checked` event, while the same filter run
// through `GrantCheck` writes one deny event per hidden entry. Names the call cannot carry
// (they would split, trim or vanish as request tokens, or run past the request string limit)
// stay hidden, even where a pattern or an open tool axis would match them.
#[test]
fn mgr_04_filtered_listing_matches_the_check_and_emits_nothing() {
    let (store, bus, _h) = make_store();
    store
        .insert(mcp_grant(
            "g-a",
            "alice",
            &[("servers", "github"), ("tool-patterns", "get_*")],
        ))
        .unwrap();
    store
        .insert(mcp_grant("g-b", "alice", &[("servers", "notes")]))
        .unwrap();
    let longest = "x".repeat(MAX_REQUEST_TOKEN_BYTES);
    let too_long = "x".repeat(MAX_REQUEST_TOKEN_BYTES + 1);
    let listed = [
        ("github", "get_issue"),
        ("github", "get_pr"),
        ("github", "delete_repo"),
        ("github", "get_x "),
        ("github", "get_a,get_b"),
        ("notes", "delete_note"),
        ("notes", ""),
        ("notes", " note"),
        ("notes", "note\u{00A0}"),
        ("notes", "a,b"),
        ("notes", longest.as_str()),
        ("notes", too_long.as_str()),
        ("slack", "get_channel"),
        ("slack", "post"),
    ];

    let reader = McpGrantReaderImpl::new(store.clone());
    let scopes = reader.mcp_grant_scopes("alice");
    let visible: Vec<(&str, &str)> = listed
        .iter()
        .copied()
        .filter(|(server, tool)| scopes.iter().any(|s| s.covers_tool(server, tool)))
        .collect();
    assert_eq!(
        visible,
        vec![
            ("github", "get_issue"),
            ("github", "get_pr"),
            ("notes", "delete_note"),
            ("notes", longest.as_str()),
        ]
    );
    assert_eq!(bus.count_of("authz.checked"), 0);

    let check = GrantCheckImpl::new(store);
    let allowed: Vec<(&str, &str)> = listed
        .iter()
        .copied()
        .filter(|(server, tool)| {
            let request = CapParams::from(serde_json::json!({
                "servers": server,
                "tool-patterns": tool,
            }));
            matches!(
                check.check("alice", "mcp", "list-mcp-tools", &request),
                GrantDecision::Allow
            )
        })
        .collect();
    assert_eq!(allowed, visible);
    assert_eq!(bus.count_of("authz.checked"), listed.len() - visible.len());
}

// ===== WebGrantReader =====

fn web_grant(id: &str, grantee: &str) -> Grant {
    let mut g = tools_grant(id, grantee, None, GrantStatus::Active);
    g.capability = "web".to_string();
    g
}

// The `web` grant is held through an active, unexpired `web` grant (the answer the call-time
// check gives a whole-capability `web` request), also across the colon→bare bridge. Reading it
// writes no `authz.checked` event.
#[test]
fn wgr_01_web_grant_held_by_an_active_unexpired_grant() {
    let (store, bus, _h) = make_store();
    store.insert(web_grant("g-1", "alice")).unwrap();
    let mut revoked = web_grant("g-2", "bob");
    revoked.status = GrantStatus::Revoked;
    store.insert(revoked).unwrap();
    let mut expired = web_grant("g-3", "carol");
    expired.expires_at = Some(Utc::now() - chrono::Duration::hours(1));
    store.insert(expired).unwrap();
    store
        .insert(tools_grant("g-4", "dave", None, GrantStatus::Active))
        .unwrap();
    store.insert(mcp_grant("g-5", "dave", &[])).unwrap();

    let reader = WebGrantReaderImpl::new(store.clone());
    assert!(reader.web_grant_held("alice"));
    assert!(reader.web_grant_held("agent:alice"));
    let agents = ["alice", "bob", "carol", "dave", "erin"];
    for agent in &agents[1..] {
        assert!(!reader.web_grant_held(agent), "{agent}");
    }
    assert_eq!(bus.count_of("authz.checked"), 0);

    let check = GrantCheckImpl::new(store);
    for agent in agents {
        let allowed = matches!(
            check.check(agent, "web", "f", &CapParams::empty()),
            GrantDecision::Allow
        );
        assert_eq!(allowed, reader.web_grant_held(agent), "{agent}");
    }
}

// ===== The mcp-client host functions over the real grant check and reader =====

/// An MCP server double answering each method with a fixed result, recording
/// the methods it was sent.
struct ScriptedServer {
    id: String,
    tools: Vec<String>,
    sent: std::sync::Mutex<Vec<String>>,
}

impl ScriptedServer {
    fn new(id: &str, tools: &[&str]) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            id: id.to_string(),
            tools: tools.iter().map(|t| t.to_string()).collect(),
            sent: std::sync::Mutex::new(Vec::new()),
        })
    }

    fn sent(&self) -> Vec<String> {
        self.sent.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl cap_mcp::McpTransport for ScriptedServer {
    async fn invoke(
        &self,
        _caller: Option<&str>,
        method: &str,
        _params: serde_json::Value,
    ) -> Result<Vec<u8>, cap_mcp::McpError> {
        self.sent.lock().unwrap().push(method.to_string());
        let result = match method {
            "tools/list" => serde_json::json!({
                "tools": self.tools.iter().map(|n| serde_json::json!({"name": n})).collect::<Vec<_>>()
            }),
            "prompts/list" => serde_json::json!({"prompts": [{"name": "daily"}]}),
            "resources/list" => serde_json::json!({"resources": [{"uri": "note://1"}]}),
            "prompts/get" => serde_json::json!({"messages": []}),
            "resources/read" => serde_json::json!({"contents": []}),
            "tools/call" => serde_json::json!({"content": []}),
            other => panic!("unexpected method {other}"),
        };
        Ok(serde_json::to_vec(&result).unwrap())
    }

    async fn notify(
        &self,
        _method: &str,
        _params: Option<serde_json::Value>,
    ) -> Result<(), cap_mcp::McpError> {
        Ok(())
    }

    fn server_id(&self) -> &str {
        &self.id
    }
}

struct NoLeaks;
impl advance_shared_types::security_validator::LeakDetector for NoLeaks {
    fn scan(
        &self,
        _text: &str,
        _context: advance_shared_types::security_validator::ScanContext,
    ) -> advance_shared_types::security_validator::ScanResult {
        advance_shared_types::security_validator::ScanResult::Clean
    }
    fn scan_headers(
        &self,
        _headers: &[(String, String)],
    ) -> advance_shared_types::security_validator::ScanResult {
        advance_shared_types::security_validator::ScanResult::Clean
    }
}

struct NoEvents;
impl advance_shared_types::traits::EventBusEmit for NoEvents {
    fn emit(&self, _event: advance_shared_types::event::Event) {}
}

/// The mcp-client host functions over `servers`, each answered by its double,
/// behind a gate that reads `store`'s grants (no web grant).
fn mcp_host_functions(
    store: &std::sync::Arc<cap_grant::GrantStore>,
    servers: &[&std::sync::Arc<ScriptedServer>],
) -> advance_runtime::host_registry::InMemoryHostRegistry {
    use std::sync::Arc;
    let gate = cap_mcp::McpGate::new(
        Arc::new(GrantCheckImpl::new(Arc::clone(store))),
        Arc::new(McpGrantReaderImpl::new(Arc::clone(store))),
        None,
    );
    mcp_host_functions_behind(gate, servers)
}

/// The mcp-client host functions over `servers` (http servers, each answered by
/// its double), behind `gate`.
fn mcp_host_functions_behind(
    gate: cap_mcp::McpGate,
    servers: &[&std::sync::Arc<ScriptedServer>],
) -> advance_runtime::host_registry::InMemoryHostRegistry {
    use std::sync::Arc;
    let mut builder = cap_mcp::McpServersConfig::builder();
    let mut injected: std::collections::HashMap<String, Arc<dyn cap_mcp::McpTransport>> =
        std::collections::HashMap::new();
    for server in servers {
        builder = builder
            .add_server(cap_mcp::McpServerEntry {
                server_id: server.id.clone(),
                description: String::new(),
                transport: cap_mcp::McpTransportSpec::Http {
                    endpoint_url: format!("https://{}.example.com/mcp", server.id),
                    capability: advance_shared_types::security_validator::HttpCapability {
                        allowlist: advance_shared_types::security_validator::Allowlist {
                            patterns: vec![format!("{}.example.com", server.id)],
                        },
                        credentials: vec![],
                        component_id: server.id.clone(),
                    },
                },
                tool_patterns: None,
                tool_schemas: Default::default(),
            })
            .unwrap();
        injected.insert(
            server.id.clone(),
            Arc::clone(*server) as Arc<dyn cap_mcp::McpTransport>,
        );
    }
    let client = Arc::new(cap_mcp::McpClient::new_with_transports(
        Arc::new(builder.build()),
        Arc::new(NoLeaks),
        injected,
    ));
    let registry = advance_runtime::host_registry::InMemoryHostRegistry::new();
    cap_mcp::register_mcp_client(&registry, client, gate, Arc::new(NoEvents));
    registry
}

/// Call the mcp-client function `name` as `agent`; its result, `Ok` with the
/// `field` of each listed record (empty for a non-list result) or `Err` with
/// the `mcp-error` arm.
async fn call_mcp(
    registry: &advance_runtime::host_registry::InMemoryHostRegistry,
    agent: &str,
    name: &str,
    params: &[&str],
    field: &str,
) -> Result<Vec<String>, String> {
    use advance_runtime::host_registry::HostRegistry;
    use wasmtime::component::Val;
    let spec = registry
        .lookup("mcp")
        .into_iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("{name} is not registered under `mcp`"));
    let mut vals: Vec<Val> = params.iter().map(|p| Val::String(p.to_string())).collect();
    match name {
        "invoke-mcp-tool" => vals.push(Val::List(vec![])),
        "get-mcp-prompt" => vals.push(Val::List(vec![])),
        _ => {}
    }
    let ctx = advance_runtime::host_registry::HostCallContext {
        agent_id: agent.to_string(),
        trace_id: "t".into(),
        turn_id: None,
        capability: "mcp".into(),
        function: format!("advance:runtime/mcp-client@0.1.0::{name}"),
        run_id: None,
        iteration: None,
    };
    let out = spec.handler.call(ctx, vals, 1).await.expect("handled");
    match &out[0] {
        Val::Result(Ok(Some(inner))) => match inner.as_ref() {
            Val::List(items) => Ok(items
                .iter()
                .filter_map(|item| match item {
                    Val::Record(fields) => fields.iter().find_map(|(k, v)| match v {
                        Val::String(s) if k == field => Some(s.clone()),
                        _ => None,
                    }),
                    _ => None,
                })
                .collect()),
            _ => Ok(Vec::new()),
        },
        Val::Result(Err(Some(inner))) => match inner.as_ref() {
            Val::Variant(case, _) => Err(case.clone()),
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    }
}

// Under the real grant check and reader, the mcp-client listings show what the
// grants reach and write no `authz.checked` event, however many entries they
// hide; a refused call writes one. A grant restricting tools reaches none of
// the server's prompts and resources. Refusals send nothing to the server.
#[tokio::test]
async fn mgr_05_mcp_client_host_functions_decide_by_the_grants() {
    let (store, bus, _h) = make_store();
    store
        .insert(mcp_grant(
            "g-a",
            "alice",
            &[("servers", "github"), ("tool-patterns", "get_*")],
        ))
        .unwrap();
    store
        .insert(mcp_grant("g-b", "alice", &[("servers", "notes")]))
        .unwrap();
    let mut github_tools = vec!["get_issue", "get_pr"];
    let hidden: Vec<String> = (0..40).map(|i| format!("admin_{i}")).collect();
    github_tools.extend(hidden.iter().map(String::as_str));
    let github = ScriptedServer::new("github", &github_tools);
    let notes = ScriptedServer::new("notes", &[]);
    let slack = ScriptedServer::new("slack", &["post"]);
    let registry = mcp_host_functions(&store, &[&github, &notes, &slack]);
    let call = |name: &'static str, params: &'static [&'static str], field: &'static str| {
        call_mcp(&registry, "alice", name, params, field)
    };

    assert_eq!(
        call("list-mcp-servers", &[], "id").await,
        Ok(vec!["github".to_string(), "notes".to_string()])
    );
    assert_eq!(
        call("list-mcp-tools", &["github"], "name").await,
        Ok(vec!["get_issue".to_string(), "get_pr".to_string()])
    );
    assert_eq!(
        call("list-mcp-tools", &["slack"], "name").await,
        Err("permission-denied".to_string())
    );
    for name in ["list-mcp-prompts", "list-mcp-resources"] {
        assert_eq!(
            call(name, &["github"], "name").await,
            Err("permission-denied".to_string()),
            "{name}"
        );
    }
    assert_eq!(
        call("list-mcp-prompts", &["notes"], "name").await,
        Ok(vec!["daily".to_string()])
    );
    assert_eq!(
        call("list-mcp-resources", &["notes"], "uri").await,
        Ok(vec!["note://1".to_string()])
    );
    assert_eq!(
        bus.count_of("authz.checked"),
        0,
        "the listings hid 41 entries without one deny event"
    );

    assert_eq!(
        call("invoke-mcp-tool", &["github", "admin_3"], "").await,
        Err("permission-denied".to_string())
    );
    assert_eq!(
        call("get-mcp-prompt", &["github", "daily"], "").await,
        Err("permission-denied".to_string())
    );
    assert_eq!(
        call("read-mcp-resource", &["github", "repo://x"], "").await,
        Err("permission-denied".to_string())
    );
    let denied = bus.all_of("authz.checked");
    assert_eq!(denied.len(), 3, "one deny event per refused call");
    assert!(denied
        .iter()
        .all(|e| e.payload["capability"] == "mcp" && e.payload["decision"] == "denied"));

    assert_eq!(
        call("invoke-mcp-tool", &["github", "get_issue"], "").await,
        Ok(vec![])
    );
    assert_eq!(
        call("get-mcp-prompt", &["notes", "daily"], "").await,
        Ok(vec![])
    );
    assert_eq!(
        call("read-mcp-resource", &["notes", "note://1"], "").await,
        Ok(vec![])
    );
    assert_eq!(github.sent(), ["tools/list", "tools/call"]);
    assert_eq!(
        notes.sent(),
        [
            "prompts/list",
            "resources/list",
            "prompts/get",
            "resources/read"
        ]
    );
    assert!(slack.sent().is_empty());
}

// Under the real grant check writing every decision (`AuthzLevel::All`) and the real readers, a
// tool listing that hides `web.search` from an agent without the `web` grant, or shows it to one
// holding it, writes no `authz.checked` event: the web family is listed through the silent web
// grant reader. A call of `web.search` is decided by the check, which writes the `web` decision.
#[tokio::test]
async fn mgr_06_web_family_listings_read_the_web_grant_without_an_event() {
    use std::sync::Arc;
    let (store, bus, _h) = make_store();
    store
        .insert(mcp_grant("g-mcp", "alice", &[("servers", "search")]))
        .unwrap();
    let search = ScriptedServer::new("search", &["web.search", "lookup"]);
    let check: Arc<dyn GrantCheck> = Arc::new(GrantCheckImpl::with_authz_level(
        Arc::clone(&store),
        AuthzLevel::All,
    ));
    let gate = cap_mcp::McpGate::new(
        Arc::clone(&check),
        Arc::new(McpGrantReaderImpl::new(Arc::clone(&store))),
        Some(cap_mcp::McpWebGrant::new(
            Arc::clone(&check),
            Arc::new(WebGrantReaderImpl::new(Arc::clone(&store))),
        )),
    );
    let registry = mcp_host_functions_behind(gate, &[&search]);
    let call = |name: &'static str, params: &'static [&'static str], field: &'static str| {
        call_mcp(&registry, "alice", name, params, field)
    };

    assert_eq!(
        call("list-mcp-tools", &["search"], "name").await,
        Ok(vec!["lookup".to_string()])
    );
    assert_eq!(
        bus.count_of("authz.checked"),
        0,
        "the listing hid web.search without an event"
    );
    assert_eq!(
        call("invoke-mcp-tool", &["search", "web.search"], "").await,
        Err("permission-denied".to_string())
    );
    let web: Vec<_> = bus
        .all_of("authz.checked")
        .into_iter()
        .filter(|e| e.payload["capability"] == "web")
        .collect();
    assert_eq!(web.len(), 1, "the refused call wrote the web decision");
    assert_eq!(web[0].payload["decision"], "denied");

    store.insert(web_grant("g-web", "alice")).unwrap();
    let written = bus.count_of("authz.checked");
    assert_eq!(
        call("list-mcp-tools", &["search"], "name").await,
        Ok(vec!["web.search".to_string(), "lookup".to_string()])
    );
    assert_eq!(
        bus.count_of("authz.checked"),
        written,
        "the listing showed web.search without an event"
    );
    assert_eq!(
        call("invoke-mcp-tool", &["search", "web.search"], "").await,
        Ok(vec![])
    );
    assert_eq!(search.sent(), ["tools/list", "tools/list", "tools/call"]);
}

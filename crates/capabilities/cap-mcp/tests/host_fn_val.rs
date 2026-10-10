//! Slice D AC-15 — host_fn `Val` encode/decode + registration (SD-40..SD-47),
//! plus the `mcp` grant gate of the host functions and the `mcp.*` events
//! they emit.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use advance_runtime::host_registry::{HostRegistry, InMemoryHostRegistry};
use advance_shared_types::security_validator::{
    Allowlist, HttpCapability, LeakDetector, ScanContext, ScanResult,
};
use cap_mcp::{
    register_mcp_client, McpClient, McpError, McpErrorKind, McpGate, McpServerEntry,
    McpServersConfig, McpTransport, McpTransportSpec, McpWebGrant, SchemaValidator, MCP_CAPABILITY,
};
use serde_json::json;
use wasmtime::component::Val;

mod support;
use support::gate::{
    ctx, open_gate, scope, spec, CapturingBus, FixedScopes, FixedWebReader, RecordingCheck,
};
use support::mock_transport::CountingMockTransport;

struct NoOpDetector;
impl LeakDetector for NoOpDetector {
    fn scan(&self, _t: &str, _c: ScanContext) -> ScanResult {
        ScanResult::Clean
    }
    fn scan_headers(&self, _h: &[(String, String)]) -> ScanResult {
        ScanResult::Clean
    }
}

fn dummy_client() -> Arc<McpClient> {
    let entry = McpServerEntry {
        server_id: "srv".to_string(),
        description: "".to_string(),
        transport: McpTransportSpec::Stdio {
            command: "true".to_string(),
            args: vec![],
            env: BTreeMap::new(),
            cwd: None,
        },
        tool_patterns: None,
        tool_schemas: BTreeMap::new(),
    };
    let cfg = Arc::new(
        McpServersConfig::builder()
            .add_server(entry)
            .unwrap()
            .build(),
    );
    Arc::new(McpClient::new(cfg, Arc::new(NoOpDetector), None))
}

// ─────────────────────────────────────────────────────────────────────────
// SD-40 — mcp-error encoding: all 6 kebab arms
// ─────────────────────────────────────────────────────────────────────────
#[test]
fn sd_40_all_mcp_error_kinds_kebab() {
    assert_eq!(McpErrorKind::NotFound.as_kebab(), "not-found");
    assert_eq!(McpErrorKind::ToolNotFound.as_kebab(), "tool-not-found");
    assert_eq!(McpErrorKind::TransportError.as_kebab(), "transport-error");
    assert_eq!(
        McpErrorKind::PermissionDenied.as_kebab(),
        "permission-denied"
    );
    assert_eq!(McpErrorKind::InvalidResponse.as_kebab(), "invalid-response");
    assert_eq!(McpErrorKind::ServerError.as_kebab(), "server-error");
}

// ─────────────────────────────────────────────────────────────────────────
// SD-46 — register_mcp_client puts all 7 functions under the one capability
// `mcp`; nothing is left under the former `mcp.servers` / `mcp.tool-patterns`
// ─────────────────────────────────────────────────────────────────────────
#[test]
fn sd_46_register_under_one_capability() {
    let registry = InMemoryHostRegistry::new();
    register_mcp_client(&registry, dummy_client(), open_gate(), CapturingBus::new());

    assert_eq!(MCP_CAPABILITY, "mcp");
    let specs = registry.lookup("mcp");
    let names: std::collections::BTreeSet<_> = specs.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "list-mcp-servers",
            "list-mcp-tools",
            "list-mcp-prompts",
            "get-mcp-prompt",
            "list-mcp-resources",
            "read-mcp-resource",
            "invoke-mcp-tool",
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(specs.len(), 7);
    assert!(registry.lookup("mcp.servers").is_empty());
    assert!(registry.lookup("mcp.tool-patterns").is_empty());

    for spec in &specs {
        assert_eq!(spec.capability, "mcp");
        assert_eq!(spec.namespace, "advance:runtime/mcp-client@0.1.0");
        assert_eq!(
            spec.idempotent,
            spec.name != "invoke-mcp-tool",
            "{} idempotent flag",
            spec.name
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────
// SD-47 — SchemaValidator is Send + Sync (compile-time)
// ─────────────────────────────────────────────────────────────────────────
fn _assert_send_sync()
where
    SchemaValidator: Send + Sync,
    McpClient: Send + Sync,
{
}

fn _unused(_: &McpError) {}

// ─────────────────────────────────────────────────────────────────────────
// The `mcp` grant gate and the `mcp.*` events
// ─────────────────────────────────────────────────────────────────────────

/// A client whose servers are `(id, stdio, transport)`; each server is answered
/// by its mock transport. A stdio server's command never runs: its transport is
/// injected.
fn client_with(servers: &[(&str, bool, &Arc<CountingMockTransport>)]) -> Arc<McpClient> {
    let mut builder = McpServersConfig::builder();
    let mut injected: HashMap<String, Arc<dyn McpTransport>> = HashMap::new();
    for (id, stdio, mock) in servers {
        let transport = if *stdio {
            McpTransportSpec::Stdio {
                command: "true".into(),
                args: vec![],
                env: BTreeMap::new(),
                cwd: None,
            }
        } else {
            McpTransportSpec::Http {
                endpoint_url: format!("https://{id}.example.com/mcp"),
                capability: HttpCapability {
                    allowlist: Allowlist {
                        patterns: vec![format!("{id}.example.com")],
                    },
                    credentials: vec![],
                    component_id: (*id).into(),
                },
            }
        };
        builder = builder
            .add_server(McpServerEntry {
                server_id: (*id).into(),
                description: format!("{id} server"),
                transport,
                tool_patterns: None,
                tool_schemas: BTreeMap::new(),
            })
            .unwrap();
        injected.insert(
            (*id).to_string(),
            Arc::clone(*mock) as Arc<dyn McpTransport>,
        );
    }
    Arc::new(McpClient::new_with_transports(
        Arc::new(builder.build()),
        Arc::new(NoOpDetector),
        injected,
    ))
}

fn registered(
    client: Arc<McpClient>,
    gate: McpGate,
    bus: &Arc<CapturingBus>,
) -> InMemoryHostRegistry {
    let registry = InMemoryHostRegistry::new();
    register_mcp_client(&registry, client, gate, Arc::clone(bus) as _);
    registry
}

/// Call the mcp-client function `name` as `agent` and return its one result.
async fn call(registry: &InMemoryHostRegistry, agent: &str, name: &str, params: Vec<Val>) -> Val {
    let spec = spec(registry, name);
    let mut out = spec
        .handler
        .call(ctx(agent, name), params, 1)
        .await
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    out.remove(0)
}

fn s(text: &str) -> Val {
    Val::String(text.into())
}

fn invoke_params(server: &str, tool: &str) -> Vec<Val> {
    vec![
        s(server),
        s(tool),
        Val::List(b"{}".iter().map(|b| Val::U8(*b)).collect()),
    ]
}

/// The `mcp-error` arm of a failed result; `None` for a success.
fn err_class(v: &Val) -> Option<String> {
    match v {
        Val::Result(Err(Some(inner))) => match inner.as_ref() {
            Val::Variant(case, _) => Some(case.clone()),
            other => panic!("error payload is not a variant: {other:?}"),
        },
        Val::Result(Ok(_)) => None,
        other => panic!("not a result: {other:?}"),
    }
}

/// The `field` of each record in a successful list result.
fn listed(v: &Val, field: &str) -> Vec<String> {
    let Val::Result(Ok(Some(inner))) = v else {
        panic!("expected a list, got {v:?}");
    };
    let Val::List(items) = inner.as_ref() else {
        panic!("expected a list, got {inner:?}");
    };
    items
        .iter()
        .map(|item| {
            let Val::Record(fields) = item else {
                panic!("expected a record, got {item:?}");
            };
            fields
                .iter()
                .find_map(|(k, v)| match v {
                    Val::String(text) if k == field => Some(text.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("no {field} in {item:?}"))
        })
        .collect()
}

fn tools(names: &[&str]) -> serde_json::Value {
    json!({ "tools": names.iter().map(|n| json!({"name": n})).collect::<Vec<_>>() })
}

// invoke-mcp-tool asks the caller's `mcp` grant about the server and the tool
// it names, and refuses before any request when no grant covers them. Every
// call emits one event: `mcp.tool_invoked` with a result, `mcp.tool_error`
// with the error class otherwise, refusals included.
#[tokio::test]
async fn invoke_asks_the_mcp_grant_for_the_server_and_the_tool() {
    let mock = Arc::new(CountingMockTransport::new("srv"));
    mock.push_ok(json!({"content": [{"type": "text", "text": "hi"}]}));
    let check = RecordingCheck::new(|(_, _, _, params)| params["tool-patterns"] != "rm");
    let reader = FixedScopes::unrestricted();
    let bus = CapturingBus::new();
    let registry = registered(
        client_with(&[("srv", false, &mock)]),
        McpGate::new(check.clone(), reader.clone(), None),
        &bus,
    );

    let ok = call(
        &registry,
        "agent-x",
        "invoke-mcp-tool",
        invoke_params("srv", "echo"),
    )
    .await;
    assert_eq!(err_class(&ok), None, "{ok:?}");
    let denied = call(
        &registry,
        "agent-x",
        "invoke-mcp-tool",
        invoke_params("srv", "rm"),
    )
    .await;
    assert_eq!(err_class(&denied).as_deref(), Some("permission-denied"));
    // Allowed, but the server's transport has no answer left.
    let failed = call(
        &registry,
        "agent-x",
        "invoke-mcp-tool",
        invoke_params("srv", "echo"),
    )
    .await;
    assert_eq!(err_class(&failed).as_deref(), Some("transport-error"));

    let function = "advance:runtime/mcp-client@0.1.0::invoke-mcp-tool";
    let asked = |tool: &str| {
        (
            "agent-x".to_string(),
            "mcp".to_string(),
            function.to_string(),
            json!({"servers": "srv", "tool-patterns": tool}),
        )
    };
    assert_eq!(
        check.asked(),
        vec![asked("echo"), asked("rm"), asked("echo")]
    );
    let sent: Vec<String> = mock
        .captured()
        .into_iter()
        .map(|(m, p)| format!("{m} {}", p["name"]))
        .collect();
    assert_eq!(
        sent,
        ["tools/call \"echo\"", "tools/call \"echo\""],
        "the refused call sent nothing"
    );
    assert_eq!(reader.reads(), 0, "a call never reads the listing scopes");

    let events = bus.events();
    assert_eq!(
        bus.types(),
        ["mcp.tool_invoked", "mcp.tool_error", "mcp.tool_error"]
    );
    let invoked = &events[0];
    assert_eq!(invoked.agent_id, "agent-x");
    assert_eq!(invoked.trace_id, "trace-invoke-mcp-tool");
    assert_eq!(invoked.run_id.as_deref(), Some("run-1"));
    assert_eq!(invoked.payload["server_id"], "srv");
    assert_eq!(invoked.payload["tool_name"], "echo");
    assert_eq!(invoked.payload["agent_id"], "agent-x");
    assert!(
        invoked.payload["duration_ms"].is_u64(),
        "{}",
        invoked.payload
    );
    assert_eq!(
        events[1].payload,
        json!({"server_id": "srv", "tool_name": "rm", "error_type": "permission-denied"})
    );
    assert_eq!(events[2].payload["error_type"], "transport-error");
}

// get-mcp-prompt and read-mcp-resource ask for the server as a whole: the
// request carries the server-wide token `*`, which only a grant leaving the
// tool axis unrestricted covers. A refusal sends nothing and emits nothing; a
// result emits `mcp.prompt_fetched` / `mcp.resource_read`, the URI reduced to
// its scheme and host.
#[tokio::test]
async fn prompts_and_resources_ask_for_the_whole_server() {
    let mock = Arc::new(CountingMockTransport::new("srv"));
    let check = RecordingCheck::new(|(_, _, _, params)| params["tool-patterns"] != "*");
    let bus = CapturingBus::new();
    let registry = registered(
        client_with(&[("srv", false, &mock)]),
        McpGate::new(check.clone(), FixedScopes::unrestricted(), None),
        &bus,
    );
    let uri = "https://reader:secret@files.example.com/notes/q3.md?token=abc";
    let prompt = vec![s("srv"), s("summary"), Val::List(vec![])];

    let denied = call(&registry, "agent-x", "get-mcp-prompt", prompt.clone()).await;
    assert_eq!(err_class(&denied).as_deref(), Some("permission-denied"));
    let denied = call(
        &registry,
        "agent-x",
        "read-mcp-resource",
        vec![s("srv"), s(uri)],
    )
    .await;
    assert_eq!(err_class(&denied).as_deref(), Some("permission-denied"));
    let ns = "advance:runtime/mcp-client@0.1.0";
    assert_eq!(
        check.asked(),
        vec![
            (
                "agent-x".to_string(),
                "mcp".to_string(),
                format!("{ns}::get-mcp-prompt"),
                json!({"servers": "srv", "tool-patterns": "*"}),
            ),
            (
                "agent-x".to_string(),
                "mcp".to_string(),
                format!("{ns}::read-mcp-resource"),
                json!({"servers": "srv", "tool-patterns": "*"}),
            ),
        ]
    );
    assert_eq!(mock.call_count(), 0);
    assert!(bus.events().is_empty());

    let mock = Arc::new(CountingMockTransport::new("srv"));
    mock.push_ok(json!({"messages": []}));
    let resource = json!({"contents": [{"uri": uri, "text": "q3"}]});
    mock.push_ok(resource.clone());
    let registry = registered(client_with(&[("srv", false, &mock)]), open_gate(), &bus);
    let fetched = call(&registry, "agent-x", "get-mcp-prompt", prompt).await;
    assert_eq!(err_class(&fetched), None, "{fetched:?}");
    let read = call(
        &registry,
        "agent-x",
        "read-mcp-resource",
        vec![s("srv"), s(uri)],
    )
    .await;
    assert_eq!(err_class(&read), None, "{read:?}");

    assert_eq!(bus.types(), ["mcp.prompt_fetched", "mcp.resource_read"]);
    let events = bus.events();
    assert_eq!(
        events[0].payload,
        json!({"server_id": "srv", "prompt_name": "summary"})
    );
    assert_eq!(
        events[1].payload,
        json!({
            "server_id": "srv",
            "uri": "https://files.example.com",
            "size_bytes": serde_json::to_vec(&resource).unwrap().len(),
        })
    );
    assert_eq!(events[1].agent_id, "agent-x");
    assert!(!events[1].payload.to_string().contains("secret"));
}

// The listings read the caller's grant scopes and never ask the grant check,
// so they write no `authz.checked` event: list-mcp-servers shows the servers a
// grant reaches and list-mcp-tools the tools a grant covers; the prompts and
// resources of a server need a grant leaving its tool axis unrestricted. A
// refused listing sends nothing. No listing emits an `mcp.*` event.
#[tokio::test]
async fn listings_follow_the_grant_scopes_without_asking_the_grant_check() {
    let github = Arc::new(CountingMockTransport::new("github"));
    github.push_ok(tools(&["get_issue", "delete_repo", "get_pr"]));
    let notes = Arc::new(CountingMockTransport::new("notes"));
    notes.push_ok(json!({"prompts": [{"name": "daily"}]}));
    notes.push_ok(json!({"resources": [{"uri": "note://1"}]}));
    let slack = Arc::new(CountingMockTransport::new("slack"));
    let check = RecordingCheck::allowing_all();
    let reader = FixedScopes::new(vec![
        scope(Some(&["github"]), Some(&["get_*"])),
        scope(Some(&["notes"]), None),
    ]);
    let bus = CapturingBus::new();
    let registry = registered(
        client_with(&[
            ("github", false, &github),
            ("notes", false, &notes),
            ("slack", false, &slack),
        ]),
        McpGate::new(check.clone(), reader.clone(), None),
        &bus,
    );

    let servers = call(&registry, "agent-x", "list-mcp-servers", vec![]).await;
    assert_eq!(listed(&servers, "id"), ["github", "notes"]);
    let github_tools = call(&registry, "agent-x", "list-mcp-tools", vec![s("github")]).await;
    assert_eq!(listed(&github_tools, "name"), ["get_issue", "get_pr"]);
    let slack_tools = call(&registry, "agent-x", "list-mcp-tools", vec![s("slack")]).await;
    assert_eq!(
        err_class(&slack_tools).as_deref(),
        Some("permission-denied")
    );
    for name in ["list-mcp-prompts", "list-mcp-resources"] {
        let out = call(&registry, "agent-x", name, vec![s("github")]).await;
        assert_eq!(
            err_class(&out).as_deref(),
            Some("permission-denied"),
            "{name}"
        );
    }
    let prompts = call(&registry, "agent-x", "list-mcp-prompts", vec![s("notes")]).await;
    assert_eq!(listed(&prompts, "name"), ["daily"]);
    let resources = call(&registry, "agent-x", "list-mcp-resources", vec![s("notes")]).await;
    assert_eq!(listed(&resources, "uri"), ["note://1"]);

    assert!(check.asked().is_empty(), "{:?}", check.asked());
    assert_eq!(reader.reads(), 7);
    assert_eq!(
        github.call_count(),
        1,
        "only the tool listing reached github"
    );
    assert_eq!(slack.call_count(), 0);
    assert!(bus.events().is_empty());
}

// The web family tools need the caller's web grant: a call asks the web
// grant's check, a listing its silent reader, so a listing writes no
// `authz.checked` event. A stdio server's are hidden and refused whatever the
// grants say, without asking either. Without a web grant they are withheld on
// every server.
#[tokio::test]
async fn web_family_tools_need_the_web_grant_and_an_http_server() {
    let listing = || tools(&["web.search", "web.extract", "decoy"]);
    let local = Arc::new(CountingMockTransport::new("local"));
    local.push_ok(listing());
    let remote = Arc::new(CountingMockTransport::new("remote"));
    remote.push_ok(listing());
    remote.push_ok(json!({"hits": []}));
    let web = RecordingCheck::allowing_all();
    let web_reader = FixedWebReader::new(true);
    let bus = CapturingBus::new();
    let registry = registered(
        client_with(&[("local", true, &local), ("remote", false, &remote)]),
        McpGate::new(
            RecordingCheck::allowing_all(),
            FixedScopes::unrestricted(),
            Some(McpWebGrant::new(web.clone(), web_reader.clone())),
        ),
        &bus,
    );

    let out = call(&registry, "agent-x", "list-mcp-tools", vec![s("local")]).await;
    assert_eq!(listed(&out, "name"), ["decoy"]);
    let out = call(
        &registry,
        "agent-x",
        "invoke-mcp-tool",
        invoke_params("local", "web.search"),
    )
    .await;
    assert_eq!(err_class(&out).as_deref(), Some("permission-denied"));
    assert_eq!(
        local.call_count(),
        1,
        "only the listing reached the stdio server"
    );
    assert!(
        web.asked().is_empty(),
        "a stdio server's web tools ask no web check"
    );
    assert_eq!(web_reader.reads(), 0, "nor read the web grant");

    let out = call(&registry, "agent-x", "list-mcp-tools", vec![s("remote")]).await;
    assert_eq!(listed(&out, "name"), ["web.search", "web.extract", "decoy"]);
    assert_eq!(web_reader.reads(), 1, "the listing read the web grant once");
    assert!(web.asked().is_empty(), "the listing asked no web check");
    let out = call(
        &registry,
        "agent-x",
        "invoke-mcp-tool",
        invoke_params("remote", "web.search"),
    )
    .await;
    assert_eq!(err_class(&out), None, "{out:?}");
    let web_asked: Vec<(String, String)> = web
        .asked()
        .into_iter()
        .map(|(_, cap, f, _)| (cap, f))
        .collect();
    assert_eq!(
        web_asked,
        [("web".to_string(), "invoke-mcp-tool".to_string())]
    );
    assert_eq!(web_reader.reads(), 1, "a call reads no listing answer");

    // A web grant the agent does not hold: the listing hides the web family
    // tools without asking the check; a call is refused by the check.
    let remote = Arc::new(CountingMockTransport::new("remote"));
    remote.push_ok(listing());
    let refusing = RecordingCheck::new(|_| false);
    let registry = registered(
        client_with(&[("remote", false, &remote)]),
        McpGate::new(
            RecordingCheck::allowing_all(),
            FixedScopes::unrestricted(),
            Some(McpWebGrant::new(
                refusing.clone(),
                FixedWebReader::new(false),
            )),
        ),
        &bus,
    );
    let out = call(&registry, "agent-x", "list-mcp-tools", vec![s("remote")]).await;
    assert_eq!(listed(&out, "name"), ["decoy"]);
    assert!(
        refusing.asked().is_empty(),
        "the listing asked no web check"
    );
    let out = call(
        &registry,
        "agent-x",
        "invoke-mcp-tool",
        invoke_params("remote", "web.search"),
    )
    .await;
    assert_eq!(err_class(&out).as_deref(), Some("permission-denied"));
    assert_eq!(refusing.asked().len(), 1);
    assert_eq!(remote.call_count(), 1, "the refused call sent nothing");

    let remote = Arc::new(CountingMockTransport::new("remote"));
    remote.push_ok(listing());
    let registry = registered(
        client_with(&[("remote", false, &remote)]),
        open_gate(),
        &bus,
    );
    let out = call(&registry, "agent-x", "list-mcp-tools", vec![s("remote")]).await;
    assert_eq!(listed(&out, "name"), ["decoy"]);
    let out = call(
        &registry,
        "agent-x",
        "invoke-mcp-tool",
        invoke_params("remote", "web.search"),
    )
    .await;
    assert_eq!(err_class(&out).as_deref(), Some("permission-denied"));
    assert_eq!(remote.call_count(), 1, "the withheld call sent nothing");
}

// A tool that fails while running answers with a result marked `isError`: the
// guest receives that result, and the call emits `mcp.tool_error` with the
// error type `tool-error` and none of the server's text, not
// `mcp.tool_invoked`. A result marked `isError: false` is a success.
#[tokio::test]
async fn a_result_marked_is_error_is_a_tool_error() {
    let mock = Arc::new(CountingMockTransport::new("srv"));
    let failed = json!({
        "content": [{"type": "text", "text": "quota exceeded for account 42"}],
        "isError": true,
    });
    mock.push_ok(failed.clone());
    mock.push_ok(json!({"content": [{"type": "text", "text": "done"}], "isError": false}));
    let bus = CapturingBus::new();
    let registry = registered(client_with(&[("srv", false, &mock)]), open_gate(), &bus);

    let out = call(
        &registry,
        "agent-x",
        "invoke-mcp-tool",
        invoke_params("srv", "charge"),
    )
    .await;
    let Val::Result(Ok(Some(inner))) = &out else {
        panic!("expected the result bytes, got {out:?}");
    };
    let Val::List(items) = inner.as_ref() else {
        panic!("expected list<u8>, got {inner:?}");
    };
    let received: Vec<u8> = items
        .iter()
        .map(|v| match v {
            Val::U8(b) => *b,
            other => panic!("expected u8, got {other:?}"),
        })
        .collect();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&received).unwrap(),
        failed,
        "the guest receives the failed result"
    );
    let out = call(
        &registry,
        "agent-x",
        "invoke-mcp-tool",
        invoke_params("srv", "charge"),
    )
    .await;
    assert_eq!(err_class(&out), None, "{out:?}");

    assert_eq!(bus.types(), ["mcp.tool_error", "mcp.tool_invoked"]);
    let events = bus.events();
    assert_eq!(
        events[0].payload,
        json!({"server_id": "srv", "tool_name": "charge", "error_type": "tool-error"})
    );
    assert_eq!(events[0].agent_id, "agent-x");
    assert_eq!(events[0].trace_id, "trace-invoke-mcp-tool");
    assert!(!events[0].payload.to_string().contains("quota"));
}

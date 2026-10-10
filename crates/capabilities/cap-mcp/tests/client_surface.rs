//! Slice D AC-15 — full 7-method client surface coverage (SD-30..SD-36), plus
//! tool listings (pages, entry limits, the tool cache) and the caller each
//! request is made for.
//!
//! Uses `CountingMockTransport` as the per-server backend so the test asserts
//! the McpClient's dispatch path (method names, JSON-RPC param shapes,
//! response parsing + tool-pattern filtering) without requiring real network
//! or subprocess.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use advance_runtime::host_registry::{HostCallContext, HostRegistry, InMemoryHostRegistry};
use advance_shared_types::security_validator::{LeakDetector, ScanContext, ScanResult};
use cap_mcp::{
    register_mcp_client, McpClient, McpClientLimits, McpErrorKind, McpReconfig, McpServerEntry,
    McpServersConfig, McpTransport, McpTransportSpec, ToolPattern, MAX_CACHED_TOOLS,
    MAX_TOOLS_PER_SERVER, MAX_TOOL_DESCRIPTION_BYTES, MAX_TOOL_LIST_CURSOR_BYTES,
    MAX_TOOL_LIST_PAGES, MAX_TOOL_NAME_BYTES, MAX_TOOL_SCHEMA_BYTES,
};
use serde_json::{json, Value};
use wasmtime::component::Val;

mod support;
use support::gate::{open_gate, CapturingBus};
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

fn entry_with_patterns(server_id: &str, patterns: Option<Vec<&str>>) -> McpServerEntry {
    let tool_patterns = patterns.map(|raws| {
        raws.into_iter()
            .map(|r| ToolPattern::compile(r).unwrap())
            .collect::<Vec<_>>()
    });
    McpServerEntry {
        server_id: server_id.to_string(),
        description: format!("{server_id} test desc"),
        transport: McpTransportSpec::Stdio {
            command: "true".to_string(),
            args: vec![],
            env: BTreeMap::new(),
            cwd: None,
        },
        tool_patterns,
        tool_schemas: BTreeMap::new(),
    }
}

fn build_client_with_mock(
    server_id: &str,
    mock: Arc<CountingMockTransport>,
    patterns: Option<Vec<&str>>,
) -> McpClient {
    let cfg = Arc::new(
        McpServersConfig::builder()
            .add_server(entry_with_patterns(server_id, patterns))
            .unwrap()
            .build(),
    );
    let mock_dyn: Arc<dyn McpTransport> = mock;
    let mut injected = HashMap::new();
    injected.insert(server_id.to_string(), mock_dyn);
    McpClient::new_with_transports(cfg, Arc::new(NoOpDetector), injected)
}

// SD-30 — list_servers
#[tokio::test]
async fn sd_30_list_servers() {
    let mock = Arc::new(CountingMockTransport::new("srv"));
    let client = build_client_with_mock("srv", mock, None);
    let servers = client.list_servers().await;
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].id, "srv");
    assert_eq!(servers[0].description, "srv test desc");
}

// SD-31 — list_tools dispatches tools/list and parses array
#[tokio::test]
async fn sd_31_list_tools_parses_array() {
    let mock = Arc::new(CountingMockTransport::new("srv"));
    mock.push_ok(serde_json::json!({
        "tools": [
            {"name": "a", "description": "tool a"},
            {"name": "b", "description": "tool b"},
        ]
    }));
    let client = build_client_with_mock("srv", mock.clone(), None);
    let tools = client.list_tools(None, "srv").await.expect("ok");
    let names: Vec<_> = tools.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, vec!["a", "b"]);
    assert_eq!(tools[0].server_id, "srv");
    let captured = mock.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].0, "tools/list");
}

// SD-13 (covered here) — list_tools applies tool-patterns filter
#[tokio::test]
async fn sd_13_list_tools_filters_by_pattern() {
    let mock = Arc::new(CountingMockTransport::new("srv"));
    mock.push_ok(serde_json::json!({
        "tools": [
            {"name": "search.web", "description": ""},
            {"name": "search.code", "description": ""},
            {"name": "delete-all", "description": ""},
        ]
    }));
    let client = build_client_with_mock("srv", mock, Some(vec!["search.*"]));
    let tools = client.list_tools(None, "srv").await.expect("ok");
    let names: Vec<_> = tools.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, vec!["search.web", "search.code"]);
}

// SD-32 — invoke_tool dispatches tools/call with name+arguments payload
#[tokio::test]
async fn sd_32_invoke_tool_payload_shape() {
    let mock = Arc::new(CountingMockTransport::new("srv"));
    mock.push_ok(serde_json::json!({"ok": true}));
    let client = build_client_with_mock("srv", mock.clone(), None);
    let params = serde_json::to_vec(&serde_json::json!({"q": "weather"})).unwrap();
    let bytes = client
        .invoke_tool(None, "srv", "search", &params)
        .await
        .expect("ok");
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed["ok"], serde_json::json!(true));
    let captured = mock.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].0, "tools/call");
    assert_eq!(captured[0].1["name"], serde_json::json!("search"));
    assert_eq!(
        captured[0].1["arguments"]["q"],
        serde_json::json!("weather")
    );
}

// SD-33 — list_prompts
#[tokio::test]
async fn sd_33_list_prompts() {
    let mock = Arc::new(CountingMockTransport::new("srv"));
    mock.push_ok(serde_json::json!({
        "prompts": [
            {"name": "greet", "description": "hello"},
        ]
    }));
    let client = build_client_with_mock("srv", mock.clone(), None);
    let prompts = client.list_prompts(None, "srv").await.expect("ok");
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].name, "greet");
    assert_eq!(prompts[0].server_id, "srv");
    assert_eq!(mock.captured()[0].0, "prompts/list");
}

// SD-34 — get_prompt
#[tokio::test]
async fn sd_34_get_prompt() {
    let mock = Arc::new(CountingMockTransport::new("srv"));
    mock.push_ok(serde_json::json!({"text": "hello, alice!"}));
    let client = build_client_with_mock("srv", mock.clone(), None);
    let bytes = client
        .get_prompt(
            None,
            "srv",
            "greet",
            vec![("name".to_string(), "alice".to_string())],
        )
        .await
        .expect("ok");
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed["text"], serde_json::json!("hello, alice!"));
    let captured = mock.captured();
    assert_eq!(captured[0].0, "prompts/get");
    assert_eq!(captured[0].1["name"], serde_json::json!("greet"));
    assert_eq!(
        captured[0].1["arguments"]["name"],
        serde_json::json!("alice")
    );
}

// SD-35 — list_resources
#[tokio::test]
async fn sd_35_list_resources() {
    let mock = Arc::new(CountingMockTransport::new("srv"));
    mock.push_ok(serde_json::json!({
        "resources": [
            {"uri": "file:///x.txt", "description": "x"},
        ]
    }));
    let client = build_client_with_mock("srv", mock.clone(), None);
    let res = client.list_resources(None, "srv").await.expect("ok");
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].uri, "file:///x.txt");
    assert_eq!(mock.captured()[0].0, "resources/list");
}

// SD-36 — read_resource
#[tokio::test]
async fn sd_36_read_resource() {
    let mock = Arc::new(CountingMockTransport::new("srv"));
    mock.push_ok(serde_json::json!({"contents": "the answer is 42"}));
    let client = build_client_with_mock("srv", mock.clone(), None);
    let bytes = client
        .read_resource(None, "srv", "file:///x.txt")
        .await
        .expect("ok");
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed["contents"], serde_json::json!("the answer is 42"));
    let captured = mock.captured();
    assert_eq!(captured[0].0, "resources/read");
    assert_eq!(captured[0].1["uri"], serde_json::json!("file:///x.txt"));
}

// A result larger than `max_result_bytes` fails the call; one within it passes.
#[tokio::test]
async fn a_result_over_the_cap_fails_the_call() {
    let mock = Arc::new(CountingMockTransport::new("srv"));
    mock.push_ok(serde_json::json!({"text": "x".repeat(64)}));
    mock.push_ok(serde_json::json!({"ok": true}));
    let client = build_client_with_mock("srv", mock, None).with_limits(McpClientLimits {
        max_result_bytes: 32,
        ..McpClientLimits::default()
    });
    let err = client
        .invoke_tool(None, "srv", "search", b"{}")
        .await
        .expect_err("the result is over the cap");
    assert_eq!(err.kind, McpErrorKind::TransportError);
    assert!(
        err.message.contains("exceeds 32 bytes"),
        "msg={}",
        err.message
    );
    client
        .invoke_tool(None, "srv", "search", b"{}")
        .await
        .expect("a small result passes");
}

// ─────────────────────────────────────────────────────────────────────────
// Tool listings
// ─────────────────────────────────────────────────────────────────────────

fn names(tools: &[cap_mcp::McpToolInfo]) -> Vec<String> {
    tools.iter().map(|t| t.name.clone()).collect()
}

// A listing follows `nextCursor`, sending each cursor back, and reads at most
// MAX_TOOL_LIST_PAGES pages.
#[tokio::test]
async fn a_listing_follows_next_cursor_up_to_the_page_cap() {
    let mock = Arc::new(CountingMockTransport::new("srv"));
    for page in 0..=MAX_TOOL_LIST_PAGES {
        mock.push_ok(json!({
            "tools": [{"name": format!("t{page}")}],
            "nextCursor": format!("c{}", page + 1),
        }));
    }
    let client = build_client_with_mock("srv", mock.clone(), None);
    let tools = client.list_tools(None, "srv").await.expect("listed");
    assert_eq!(tools.len(), MAX_TOOL_LIST_PAGES);
    let captured = mock.captured();
    assert_eq!(captured.len(), MAX_TOOL_LIST_PAGES);
    assert_eq!(captured[0], ("tools/list".to_string(), json!({})));
    for (page, call) in captured.iter().enumerate().skip(1) {
        assert_eq!(
            call,
            &(
                "tools/list".to_string(),
                json!({"cursor": format!("c{page}")})
            )
        );
    }
}

// A listing ends at a page whose cursor is missing, not a string, empty,
// too long or the same as the one that asked for the page.
#[tokio::test]
async fn a_listing_ends_at_a_page_without_a_usable_cursor() {
    let too_long = "x".repeat(MAX_TOOL_LIST_CURSOR_BYTES + 1);
    for last in [
        json!(null),
        json!(42),
        json!(""),
        json!(too_long),
        json!("c1"),
    ] {
        let mock = Arc::new(CountingMockTransport::new("srv"));
        mock.push_ok(json!({"tools": [{"name": "a"}], "nextCursor": "c1"}));
        mock.push_ok(json!({"tools": [{"name": "b"}], "nextCursor": last}));
        mock.push_ok(json!({"tools": [{"name": "c"}]}));
        let client = build_client_with_mock("srv", mock.clone(), None);
        let tools = client.list_tools(None, "srv").await.expect("listed");
        assert_eq!(names(&tools), ["a", "b"], "{last}");
        assert_eq!(mock.call_count(), 2, "{last}");
    }
    let mock = Arc::new(CountingMockTransport::new("srv"));
    let longest = "x".repeat(MAX_TOOL_LIST_CURSOR_BYTES);
    mock.push_ok(json!({"tools": [{"name": "a"}], "nextCursor": longest}));
    mock.push_ok(json!({"tools": [{"name": "b"}]}));
    let client = build_client_with_mock("srv", mock.clone(), None);
    let tools = client.list_tools(None, "srv").await.expect("listed");
    assert_eq!(names(&tools), ["a", "b"]);
}

// A listed tool keeps its inputSchema when it is an object within the size
// limit whose references stay inside it; otherwise the tool is listed
// without one.
#[tokio::test]
async fn listed_tools_keep_an_input_schema_within_the_limits() {
    let small = json!({"type": "object", "properties": {"q": {"type": "string"}}});
    let external = json!({
        "type": "object",
        "properties": {"q": {"$ref": "https://schemas.example.com/q.json"}},
    });
    let big = json!({"type": "object", "description": "x".repeat(MAX_TOOL_SCHEMA_BYTES)});
    let mock = Arc::new(CountingMockTransport::new("srv"));
    mock.push_ok(json!({"tools": [
        {"name": "small", "inputSchema": small},
        {"name": "external", "inputSchema": external},
        {"name": "big", "inputSchema": big},
        {"name": "not-an-object", "inputSchema": "string"},
        {"name": "none"},
    ]}));
    let client = build_client_with_mock("srv", mock, None);
    let tools = client.list_tools(None, "srv").await.expect("listed");
    assert_eq!(
        names(&tools),
        ["small", "external", "big", "not-an-object", "none"]
    );
    assert_eq!(tools[0].input_schema, Some(small));
    for tool in &tools[1..] {
        assert_eq!(tool.input_schema, None, "{}", tool.name);
    }
}

// A listed name must fit a literal tool pattern and be a name a call can
// carry, and is listed once; a long description is cut.
#[tokio::test]
async fn listed_names_and_descriptions_meet_the_entry_limits() {
    let longest = "n".repeat(MAX_TOOL_NAME_BYTES);
    let too_long = "n".repeat(MAX_TOOL_NAME_BYTES + 1);
    let mock = Arc::new(CountingMockTransport::new("srv"));
    mock.push_ok(json!({"tools": [
        {"name": longest, "description": "d".repeat(MAX_TOOL_DESCRIPTION_BYTES + 100)},
        {"name": too_long},
        {"name": "has,comma"},
        {"name": " padded"},
        {"name": "ok", "description": "first"},
        {"name": "ok", "description": "again"},
    ]}));
    let client = build_client_with_mock("srv", mock, None);
    let tools = client.list_tools(None, "srv").await.expect("listed");
    assert_eq!(names(&tools), [longest, "ok".to_string()]);
    assert!(tools[0].description.len() <= MAX_TOOL_DESCRIPTION_BYTES);
    assert!(tools[0].description.ends_with('…'));
    assert_eq!(tools[1].description, "first");
}

// A listing keeps at most MAX_TOOLS_PER_SERVER tools and reads no page past
// them.
#[tokio::test]
async fn a_listing_keeps_at_most_max_tools_per_server() {
    let page: Vec<Value> = (0..MAX_TOOLS_PER_SERVER + 10)
        .map(|i| json!({"name": format!("t{i}")}))
        .collect();
    let mock = Arc::new(CountingMockTransport::new("srv"));
    mock.push_ok(json!({"tools": page, "nextCursor": "more"}));
    mock.push_ok(json!({"tools": [{"name": "late"}]}));
    let client = build_client_with_mock("srv", mock.clone(), None);
    let tools = client.list_tools(None, "srv").await.expect("listed");
    assert_eq!(tools.len(), MAX_TOOLS_PER_SERVER);
    assert_eq!(mock.call_count(), 1);
}

fn full_page(count: usize) -> Value {
    let tools: Vec<Value> = (0..count)
        .map(|i| json!({"name": format!("t{i}")}))
        .collect();
    json!({ "tools": tools })
}

// The cache keeps each server's latest listing, within MAX_CACHED_TOOLS tools
// across servers, shared fairly: once the listings do not all fit, each is
// cut to its server's share (its first tools) and says so, while its caller
// gets all of it. A server that lists no tools has an empty entry, and the
// room it leaves goes to the others' next listings. A failed listing changes
// nothing.
#[tokio::test]
async fn the_tool_cache_shares_the_total_cap_fairly_and_marks_cut_listings() {
    let fitting = MAX_CACHED_TOOLS / MAX_TOOLS_PER_SERVER;
    let ids: Vec<String> = (0..=fitting).map(|i| format!("srv{i}")).collect();
    let mocks: Vec<Arc<CountingMockTransport>> = ids
        .iter()
        .map(|id| Arc::new(CountingMockTransport::new(id.as_str())))
        .collect();
    let mut builder = McpServersConfig::builder();
    let mut injected: HashMap<String, Arc<dyn McpTransport>> = HashMap::new();
    for (id, mock) in ids.iter().zip(&mocks) {
        builder = builder.add_server(entry_with_patterns(id, None)).unwrap();
        injected.insert(id.clone(), mock.clone());
    }
    let client =
        McpClient::new_with_transports(Arc::new(builder.build()), Arc::new(NoOpDetector), injected);
    let cached_of = |client: &McpClient, id: &str| {
        client
            .cached_tools()
            .into_iter()
            .find(|listing| listing.server_id == id)
            .unwrap_or_else(|| panic!("no entry for {id}"))
    };
    let first_names =
        |count: usize| -> Vec<String> { (0..count).map(|i| format!("t{i}")).collect() };
    assert!(client.cached_tools().is_empty());
    assert_eq!(client.servers_to_list(), ids, "none is listed yet");

    // As many full listings as fit are cached whole.
    for (id, mock) in ids.iter().zip(&mocks).take(fitting) {
        mock.push_ok(full_page(MAX_TOOLS_PER_SERVER));
        client.list_tools(None, id).await.expect("listed");
    }
    assert!(client.cached_tools().iter().all(|l| !l.is_truncated()));
    assert_eq!(client.servers_to_list(), [ids[fitting].clone()]);

    // One more: every listing is cut to its share and marked.
    mocks[fitting].push_ok(full_page(MAX_TOOLS_PER_SERVER));
    let tools = client
        .list_tools(None, &ids[fitting])
        .await
        .expect("listed");
    assert_eq!(tools.len(), MAX_TOOLS_PER_SERVER, "the caller gets it all");
    let cached = client.cached_tools();
    let in_order: Vec<&str> = cached.iter().map(|l| l.server_id.as_str()).collect();
    let mut sorted: Vec<&str> = ids.iter().map(String::as_str).collect();
    sorted.sort();
    assert_eq!(in_order, sorted, "one entry per server, in server-id order");
    assert_eq!(
        cached.iter().map(|l| l.tools.len()).sum::<usize>(),
        MAX_CACHED_TOOLS
    );
    let share = MAX_CACHED_TOOLS / ids.len();
    for listing in &cached {
        assert!(listing.is_truncated(), "{}", listing.server_id);
        assert_eq!(listing.listed, MAX_TOOLS_PER_SERVER);
        assert!((share..=share + 1).contains(&listing.tools.len()));
        assert_eq!(names(&listing.tools), first_names(listing.tools.len()));
    }
    assert!(
        client.servers_to_list().is_empty(),
        "each listing holds its share of the full cache: listing it again changes nothing"
    );

    // A server listing no tools keeps an empty entry, and the room it left is there for
    // each cut listing's next listing.
    mocks[0].push_ok(full_page(0));
    client.list_tools(None, &ids[0]).await.expect("listed");
    let empty = cached_of(&client, &ids[0]);
    assert_eq!((empty.tools.len(), empty.listed), (0, 0));
    assert!(!empty.is_truncated());
    assert_eq!(client.servers_to_list(), ids[1..]);
    mocks[fitting].push_ok(full_page(MAX_TOOLS_PER_SERVER));
    client
        .list_tools(None, &ids[fitting])
        .await
        .expect("listed");
    let last = cached_of(&client, &ids[fitting]);
    assert_eq!(last.tools.len(), MAX_TOOLS_PER_SERVER);
    assert!(!last.is_truncated());
    assert_eq!(client.servers_to_list(), ids[1..fitting]);
    assert!(
        client
            .cached_tools()
            .iter()
            .map(|l| l.tools.len())
            .sum::<usize>()
            <= MAX_CACHED_TOOLS
    );

    // A failed listing (nothing scripted) leaves the cache as it was.
    let before = client.cached_tools();
    assert!(client.list_tools(None, &ids[1]).await.is_err());
    assert_eq!(client.cached_tools(), before);
}

// ─────────────────────────────────────────────────────────────────────────
// Callers
// ─────────────────────────────────────────────────────────────────────────

/// An answer every list method can read.
fn any_listing() -> Value {
    json!({"tools": [], "prompts": [], "resources": []})
}

// Every request reaches the transport with the caller it was made for.
#[tokio::test]
async fn requests_reach_the_transport_with_their_caller() {
    let mock = Arc::new(CountingMockTransport::new("srv"));
    for _ in 0..6 {
        mock.push_ok(any_listing());
    }
    let client = build_client_with_mock("srv", mock.clone(), None);
    client.list_tools(Some("agent-a"), "srv").await.unwrap();
    client.list_prompts(Some("agent-b"), "srv").await.unwrap();
    client
        .get_prompt(Some("agent-c"), "srv", "p", vec![])
        .await
        .unwrap();
    client.list_resources(None, "srv").await.unwrap();
    client
        .read_resource(Some("agent-d"), "srv", "file:///x")
        .await
        .unwrap();
    client
        .invoke_tool(Some("agent-e"), "srv", "t", b"{}")
        .await
        .unwrap();
    let expected: Vec<Option<String>> = [
        Some("agent-a"),
        Some("agent-b"),
        Some("agent-c"),
        None,
        Some("agent-d"),
        Some("agent-e"),
    ]
    .iter()
    .map(|c| c.map(str::to_string))
    .collect();
    assert_eq!(mock.callers(), expected);
}

// The mcp-client host functions make their requests for the calling agent.
#[tokio::test]
async fn the_host_functions_call_for_the_calling_agent() {
    let mock = Arc::new(CountingMockTransport::new("srv"));
    for _ in 0..6 {
        mock.push_ok(any_listing());
    }
    let client = Arc::new(build_client_with_mock("srv", mock.clone(), None));
    let registry = InMemoryHostRegistry::new();
    register_mcp_client(&registry, client, open_gate(), CapturingBus::new());
    let specs = registry.lookup("mcp");
    let server = || Val::String("srv".into());
    let calls: Vec<(&str, Vec<Val>)> = vec![
        ("list-mcp-tools", vec![server()]),
        ("list-mcp-prompts", vec![server()]),
        (
            "get-mcp-prompt",
            vec![server(), Val::String("p".into()), Val::List(vec![])],
        ),
        ("list-mcp-resources", vec![server()]),
        (
            "read-mcp-resource",
            vec![server(), Val::String("file:///x".into())],
        ),
        (
            "invoke-mcp-tool",
            vec![server(), Val::String("t".into()), Val::List(vec![])],
        ),
    ];
    for (name, params) in calls {
        let spec = specs
            .iter()
            .find(|spec| spec.name == name)
            .unwrap_or_else(|| panic!("missing {name}"));
        let ctx = HostCallContext {
            agent_id: "agent-x".into(),
            trace_id: "trace".into(),
            turn_id: None,
            capability: spec.capability.clone(),
            function: format!("{}::{name}", spec.namespace),
            run_id: None,
            iteration: None,
        };
        let out = spec.handler.call(ctx, params, 1).await.expect("handled");
        assert!(
            matches!(&out[0], Val::Result(Ok(_))),
            "{name}: {:?}",
            out[0]
        );
    }
    assert_eq!(mock.callers(), vec![Some("agent-x".to_string()); 6]);
}

#[tokio::test]
async fn replace_config_drops_removed_and_changed_servers_and_their_cache() {
    let mock = Arc::new(CountingMockTransport::new("old"));
    mock.push_ok(json!({"tools": [{"name": "echo"}]}));
    let client = build_client_with_mock("old", mock, None);
    client.list_tools(None, "old").await.unwrap();
    assert_eq!(client.cached_tools().len(), 1);

    let unchanged = McpServersConfig::builder()
        .add_server(entry_with_patterns("old", None))
        .unwrap()
        .build();
    assert_eq!(client.replace_config(unchanged), McpReconfig::default());
    assert_eq!(client.cached_tools().len(), 1);

    let empty = McpServersConfig::builder().build();
    let reconfig = client.replace_config(empty);
    assert_eq!(reconfig.removed, ["old"]);
    assert!(client.cached_tools().is_empty());
    assert!(client.list_servers().await.is_empty());
}

// A server whose entry changes (here its tool patterns, so its fingerprint) is
// reported as changed, beside a server added: its connection is closed and its
// cached tools are dropped, and the next call connects the new entry instead of
// reusing the old connection.
#[tokio::test]
async fn replace_config_closes_the_connection_of_a_changed_server() {
    let mock = Arc::new(CountingMockTransport::new("srv"));
    mock.push_ok(json!({"tools": [{"name": "echo"}]}));
    let client = build_client_with_mock("srv", Arc::clone(&mock), None);
    client.list_tools(None, "srv").await.unwrap();
    assert_eq!(client.cached_tools().len(), 1);

    let next = McpServersConfig::builder()
        .add_server(entry_with_patterns("srv", Some(vec!["echo"])))
        .unwrap()
        .add_server(entry_with_patterns("fresh", None))
        .unwrap()
        .build();
    let reconfig = client.replace_config(next);
    assert_eq!(
        reconfig,
        McpReconfig {
            added: vec!["fresh".to_string()],
            removed: vec![],
            changed: vec!["srv".to_string()],
        }
    );
    assert!(
        client.cached_tools().is_empty(),
        "the changed server's tools are dropped"
    );
    assert_eq!(
        Arc::strong_count(&mock),
        1,
        "the client let go of the old connection"
    );

    // Connecting the new entry needs a runtime for stdio servers, which this
    // client lacks: the call fails instead of reaching the old connection.
    let err = client
        .invoke_tool(None, "srv", "echo", b"{}")
        .await
        .expect_err("the new entry is not connected");
    assert_eq!(err.kind, McpErrorKind::TransportError);
    assert!(err.message.contains("with_runtime"), "msg={}", err.message);
    assert_eq!(
        mock.call_count(),
        1,
        "only the listing reached the old connection"
    );
    let ids: Vec<String> = client
        .list_servers()
        .await
        .into_iter()
        .map(|server| server.id)
        .collect();
    assert_eq!(ids, ["fresh", "srv"]);
}

//! Slice D AC-15 — full 7-method client surface coverage (SD-30..SD-36).
//!
//! Uses `CountingMockTransport` as the per-server backend so the test asserts
//! the McpClient's dispatch path (method names, JSON-RPC param shapes,
//! response parsing + tool-pattern filtering) without requiring real network
//! or subprocess.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use advance_shared_types::security_validator::{LeakDetector, ScanContext, ScanResult};
use cap_mcp::{
    McpClient, McpServerEntry, McpServersConfig, McpTransport, McpTransportSpec, ToolPattern,
};

mod support;
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
    let tools = client.list_tools("srv").await.expect("ok");
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
    let tools = client.list_tools("srv").await.expect("ok");
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
        .invoke_tool("srv", "search", &params)
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
    let prompts = client.list_prompts("srv").await.expect("ok");
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
    let res = client.list_resources("srv").await.expect("ok");
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
        .read_resource("srv", "file:///x.txt")
        .await
        .expect("ok");
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed["contents"], serde_json::json!("the answer is 42"));
    let captured = mock.captured();
    assert_eq!(captured[0].0, "resources/read");
    assert_eq!(captured[0].1["uri"], serde_json::json!("file:///x.txt"));
}

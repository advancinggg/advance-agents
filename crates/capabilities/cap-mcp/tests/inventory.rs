//! Slice J (V1-b) — cap-mcp half of the CONTRACT-165 inventory feed:
//! `mcp_tool_entries` gather over a mock transport (T32 sub-(2) MCP side, incl.
//! the `mcp.tool-patterns` filter + skip-on-error) and the `invoke_tool`
//! cross-name rejection (T32 sub-(3)). The pure `mcp_tool_entries_from_infos`
//! mapping is unit-tested inline in `src/inventory.rs`.

// The shared `support` scaffolding exposes more of CountingMockTransport than
// this binary uses (push_err / call_count / captured); silence dead_code for the
// shared module rather than emit a per-binary warning.
#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use advance_shared_types::security_validator::{LeakDetector, ScanContext, ScanResult};
use cap_mcp::{
    mcp_tool_entries, McpClient, McpErrorKind, McpServerEntry, McpServersConfig, McpTransport,
    McpTransportSpec, ToolPattern,
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

fn entry(server_id: &str, patterns: Option<Vec<&str>>) -> McpServerEntry {
    let tool_patterns = patterns.map(|raws| {
        raws.into_iter()
            .map(|r| ToolPattern::compile(r).unwrap())
            .collect::<Vec<_>>()
    });
    McpServerEntry {
        server_id: server_id.to_string(),
        description: format!("{server_id} desc"),
        transport: McpTransportSpec::Stdio {
            command: "true".to_string(),
            args: vec![],
            env: BTreeMap::new(),
        },
        tool_patterns,
        tool_schemas: BTreeMap::new(),
    }
}

fn client_with(
    server_id: &str,
    mock: Arc<CountingMockTransport>,
    patterns: Option<Vec<&str>>,
) -> McpClient {
    let cfg = Arc::new(
        McpServersConfig::builder()
            .add_server(entry(server_id, patterns))
            .unwrap()
            .build(),
    );
    let mut injected: HashMap<String, Arc<dyn McpTransport>> = HashMap::new();
    injected.insert(server_id.to_string(), mock);
    McpClient::new_with_transports(cfg, Arc::new(NoOpDetector), injected)
}

// MJ-GATHER-01 — `mcp_tool_entries` gathers across the server, preserving name +
// server_id, mapping each to `McpToolEntry` with an empty-object params_schema.
#[tokio::test]
async fn mj_gather_01_collects_entries_with_server_id() {
    let mock = Arc::new(CountingMockTransport::new("srv"));
    mock.push_ok(serde_json::json!({
        "tools": [
            {"name": "web-search", "description": "Search the web"},
            {"name": "fetch-url", "description": "Fetch a URL"},
        ]
    }));
    let client = client_with("srv", mock, None);

    let entries = mcp_tool_entries(&client).await;
    let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["web-search", "fetch-url"]);
    assert!(entries.iter().all(|e| e.server_id == "srv"));
    assert!(entries
        .iter()
        .all(|e| e.params_schema == serde_json::json!({})));
}

// MJ-GATHER-02 — the `mcp.tool-patterns` filter is respected end-to-end through
// `mcp_tool_entries`: a clean-ASCII non-matching name (`delete-all`) is dropped
// while `search.*` matches pass (T32 sub-(2) MCP side; mirrors SD-13).
#[tokio::test]
async fn mj_gather_02_respects_tool_patterns_filter() {
    let mock = Arc::new(CountingMockTransport::new("srv"));
    mock.push_ok(serde_json::json!({
        "tools": [
            {"name": "search.web", "description": ""},
            {"name": "search.code", "description": ""},
            {"name": "delete-all", "description": ""},
        ]
    }));
    let client = client_with("srv", mock, Some(vec!["search.*"]));

    let entries = mcp_tool_entries(&client).await;
    let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["search.web", "search.code"]);
    assert!(
        !names.contains(&"delete-all"),
        "mcp.tool-patterns filter not applied during gather"
    );
}

// MJ-GATHER-03 — skip-on-error: a server whose `list_tools` errors (no scripted
// response → transport error) contributes nothing rather than aborting the
// whole gather.
#[tokio::test]
async fn mj_gather_03_skips_erroring_server() {
    let mock = Arc::new(CountingMockTransport::new("srv")); // no push_ok → errors
    let client = client_with("srv", mock, None);
    let entries = mcp_tool_entries(&client).await;
    assert!(entries.is_empty());
}

// T32 sub-(3) — `invoke_tool` with a name that FAILS the server's tool-patterns
// → `ToolNotFound` (the `!entry.tool_allowed(name)` arm, client.rs:293-297).
// Co-located inventory-suite witness; whitelist.rs also covers this.
#[tokio::test]
async fn mj_t32_sub3_invoke_cross_name_tool_not_found() {
    let mock = Arc::new(CountingMockTransport::new("srv"));
    let client = client_with("srv", mock, Some(vec!["search.*"]));
    let err = client
        .invoke_tool("srv", "delete-all", b"{}")
        .await
        .expect_err("a tool outside tool-patterns must be rejected");
    assert_eq!(err.kind, McpErrorKind::ToolNotFound);
}

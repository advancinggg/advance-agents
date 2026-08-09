//! Slice D AC-15 — host_fn `Val` encode/decode + registration (SD-40..SD-47).

use std::collections::BTreeMap;
use std::sync::Arc;

use advance_runtime::host_registry::{HostRegistry, InMemoryHostRegistry};
use advance_shared_types::security_validator::{LeakDetector, ScanContext, ScanResult};
use cap_mcp::{
    register_mcp_client, McpClient, McpError, McpErrorKind, McpServerEntry, McpServersConfig,
    McpTransportSpec, SchemaValidator,
};

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
// SD-46 — register_mcp_client wires the SPLIT capability dimensions
// (5 server-level + 2 tool-level = 7 total, each under the right dimension)
// ─────────────────────────────────────────────────────────────────────────
#[test]
fn sd_46_register_split_capability() {
    let client = dummy_client();
    let registry = InMemoryHostRegistry::new();
    register_mcp_client(&registry, client);

    let servers_specs = registry.lookup("mcp.servers");
    let tool_specs = registry.lookup("mcp.tool-patterns");
    assert_eq!(servers_specs.len(), 5);
    assert_eq!(tool_specs.len(), 2);

    let server_names: std::collections::BTreeSet<_> =
        servers_specs.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        server_names,
        [
            "list-mcp-servers",
            "list-mcp-prompts",
            "get-mcp-prompt",
            "list-mcp-resources",
            "read-mcp-resource",
        ]
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
    );
    let tool_names: std::collections::BTreeSet<_> =
        tool_specs.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        tool_names,
        ["list-mcp-tools", "invoke-mcp-tool"]
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
    );

    // Per-method idempotent flag check.
    for spec in servers_specs.iter() {
        assert!(spec.idempotent, "{} should be idempotent", spec.name);
        assert_eq!(spec.namespace, "advance:runtime/mcp-client@0.1.0");
    }
    for spec in tool_specs.iter() {
        match spec.name.as_str() {
            "list-mcp-tools" => assert!(spec.idempotent),
            "invoke-mcp-tool" => assert!(!spec.idempotent),
            _ => unreachable!(),
        }
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

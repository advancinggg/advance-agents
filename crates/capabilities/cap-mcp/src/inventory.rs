//! Slice J (V1-b) — MCP half of the CONTRACT-165 inventory feed.
//!
//! Maps the MCP client's per-server tool listing into the shared-types
//! [`McpToolEntry`] projection consumed (alongside the cap-tools WASM half) by
//! MODULE-010's Layer-3 `# Available Tools` assembly. This module produces a
//! `Vec<McpToolEntry>`; the combined `CallableInventoryReader` impl lives in
//! cap-tools (`cap_tools::CallableInventory`), which holds the two halves as
//! separate vectors — so cap-mcp does NOT depend on cap-tools (no cap-* cycle).
//!
//! `params_schema` is the tool's `inputSchema` as [`McpClient::list_tools`]
//! kept it (an object within the listing limits), or an empty JSON object when
//! the server gave none it kept.

use advance_shared_types::capability::McpToolEntry;

use crate::client::{McpClient, McpToolInfo};

/// Map per-server [`McpToolInfo`] records into CONTRACT-165 [`McpToolEntry`].
///
/// `server_id` is preserved; `params_schema` is the captured input schema, or
/// an empty object (see the module rustdoc).
pub fn mcp_tool_entries_from_infos(infos: Vec<McpToolInfo>) -> Vec<McpToolEntry> {
    infos
        .into_iter()
        .map(|info| McpToolEntry {
            name: info.name,
            description: info.description,
            params_schema: info.input_schema.unwrap_or_else(|| serde_json::json!({})),
            server_id: info.server_id,
        })
        .collect()
}

/// Gather a snapshot of MCP tool entries across all whitelisted servers.
///
/// Enumerates [`McpClient::list_servers`] and, for each, [`McpClient::list_tools`]
/// (which already applies each server's configured tool patterns and the
/// listing limits), on no agent's behalf. A server
/// whose `list_tools` errors is **skipped** (defensive — one unreachable or
/// misbehaving server must not blank the whole inventory). Order is
/// server-list order, then per-server tool order.
pub async fn mcp_tool_entries(client: &McpClient) -> Vec<McpToolEntry> {
    let mut out = Vec::new();
    for server in client.list_servers().await {
        match client.list_tools(None, &server.id).await {
            Ok(infos) => out.extend(mcp_tool_entries_from_infos(infos)),
            // skip-on-error: a single bad server cannot blank the inventory.
            Err(_) => continue,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    //! Inline unit coverage for the `McpToolInfo -> McpToolEntry` mapping. The
    //! `mcp_tool_entries` gather (over a mock transport) + the T32 sub-(3)
    //! `invoke_tool` rejection live in `tests/inventory.rs`.
    use super::*;

    // MJ-01 — server_id preserved, empty-object params_schema, fields mapped.
    #[test]
    fn mj_01_from_infos_preserves_server_id_and_empty_schema() {
        let out = mcp_tool_entries_from_infos(vec![McpToolInfo {
            name: "web-search".into(),
            description: "Search the web".into(),
            server_id: "srv-1".into(),
            input_schema: None,
        }]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "web-search");
        assert_eq!(out[0].description, "Search the web");
        assert_eq!(out[0].server_id, "srv-1");
        assert_eq!(out[0].params_schema, serde_json::json!({}));
    }

    // A captured input schema becomes the entry's params_schema.
    #[test]
    fn a_captured_input_schema_becomes_the_params_schema() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {"query": {"type": "string"}},
        });
        let out = mcp_tool_entries_from_infos(vec![McpToolInfo {
            name: "search".into(),
            description: String::new(),
            server_id: "srv-1".into(),
            input_schema: Some(schema.clone()),
        }]);
        assert_eq!(out[0].params_schema, schema);
    }

    // MJ-02 — empty input maps to empty output (no panic).
    #[test]
    fn mj_02_empty_input_maps_to_empty_output() {
        assert!(mcp_tool_entries_from_infos(Vec::new()).is_empty());
    }
}

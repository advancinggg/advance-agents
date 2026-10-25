//! Catalog projector: host-fn ∪ WASM methods ∪ MCP tools, L0 filter,
//! collision host-fn > wasm-tool > mcp-tool (ADR 2026-10-24 D3 / D9).

use std::collections::BTreeMap;
use std::sync::Arc;

use advance_context_engine::inventory::{HostFnEntry, HostFnInventoryReader};
use advance_runtime::callable_registry::{
    CallableDefinition, CallableRegistry, CallableSource, CallableSpec,
};
use advance_shared_types::capability::{McpToolEntry, ToolEntry};

/// Result of a catalog projection. `shadowed` names were dropped because a
/// higher-precedence source already claimed them. `shadow_logs` is the
/// once-per-projection log line (no tracing crate — MODULE-019 AC-13).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProjectedCatalog {
    pub entries: Vec<CallableDefinition>,
    pub shadowed: Vec<String>,
    pub shadow_logs: Vec<String>,
}

/// Merge three sources in view order. Host-fn wins, then WASM, then MCP.
/// `wasm` / `mcp` vectors should already be L0-gated by the caller (empty
/// when `tools` / `mcp` is not in the agent's declared caps).
pub fn project_catalog(
    host: Vec<CallableDefinition>,
    wasm: Vec<CallableDefinition>,
    mcp: Vec<CallableDefinition>,
) -> ProjectedCatalog {
    let mut seen: BTreeMap<String, CallableSource> = BTreeMap::new();
    let mut entries = Vec::new();
    let mut shadowed = Vec::new();
    let mut shadow_logs = Vec::new();
    for entry in host.into_iter().chain(wasm).chain(mcp) {
        if let Some(winner) = seen.get(&entry.name).copied() {
            shadow_logs.push(catalog_shadow_log(&entry.name, winner, entry.source));
            shadowed.push(entry.name);
        } else {
            seen.insert(entry.name.clone(), entry.source);
            entries.push(entry);
        }
    }
    ProjectedCatalog {
        entries,
        shadowed,
        shadow_logs,
    }
}

/// One log line per shadowed catalog name (ADR 2026-10-24 D3).
pub fn catalog_shadow_log(name: &str, winning: CallableSource, losing: CallableSource) -> String {
    format!(
        "callable catalog shadowed name={name} winning_source={} losing_source={}",
        winning.as_wit_name(),
        losing.as_wit_name()
    )
}

/// Project the three inventories for one agent. Host specs are filtered by
/// `spec.capability ∈ caps`. WASM/MCP entries are included only when `tools`
/// / `mcp` is in `caps`.
pub fn project_for_caps(
    host_specs: Vec<CallableSpec>,
    wasm: Vec<ToolEntry>,
    mcp: Vec<McpToolEntry>,
    caps: &[String],
) -> ProjectedCatalog {
    let host: Vec<CallableDefinition> = host_specs
        .into_iter()
        .filter(|s| caps.iter().any(|c| c == &s.capability))
        .map(spec_to_def)
        .collect();
    let wasm_defs = if caps.iter().any(|c| c == "tools") {
        wasm.into_iter()
            .map(|t| CallableDefinition {
                name: t.name,
                description: t.description,
                parameters: t.params_schema,
                source: CallableSource::WasmTool,
                idempotent: None,
            })
            .collect()
    } else {
        Vec::new()
    };
    let mcp_defs = if caps.iter().any(|c| c == "mcp") {
        mcp.into_iter()
            .map(|t| CallableDefinition {
                name: mcp_display_name(&t),
                description: t.description,
                parameters: t.params_schema,
                source: CallableSource::McpTool,
                idempotent: None,
            })
            .collect()
    } else {
        Vec::new()
    };
    project_catalog(host, wasm_defs, mcp_defs)
}

fn spec_to_def(s: CallableSpec) -> CallableDefinition {
    CallableDefinition {
        name: s.name,
        description: s.description,
        parameters: s.parameters,
        source: CallableSource::HostFn,
        idempotent: Some(s.idempotent),
    }
}

fn mcp_display_name(entry: &McpToolEntry) -> String {
    let prefix = format!("{}__", entry.server_id);
    if entry.server_id.is_empty() || entry.name.starts_with(&prefix) {
        entry.name.clone()
    } else {
        format!("{}{}", prefix, entry.name)
    }
}

/// `# Available Tools` host-fn half sourced from the callable catalog.
pub struct CatalogHostFnInventory {
    registry: Arc<dyn CallableRegistry>,
    caps: Vec<String>,
}

impl CatalogHostFnInventory {
    pub fn new(registry: Arc<dyn CallableRegistry>, caps: Vec<String>) -> Self {
        Self { registry, caps }
    }
}

impl HostFnInventoryReader for CatalogHostFnInventory {
    fn list_host_fns(&self, _agent_id: &str) -> Vec<HostFnEntry> {
        self.registry
            .list_for_capabilities(&self.caps)
            .into_iter()
            .map(|s| HostFnEntry {
                name: s.name,
                description: s.description,
                params_schema: s.parameters,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use advance_runtime::callable_registry::{
        CallableError, CallableHandler, CallableOutcome, CallableSpec,
    };
    use advance_runtime::host_registry::HostCallContext;
    use std::future::Future;
    use std::pin::Pin;

    struct Stub;
    impl CallableHandler for Stub {
        fn call(
            &self,
            _ctx: HostCallContext,
            call_id: String,
            _arguments: serde_json::Value,
        ) -> Pin<Box<dyn Future<Output = Result<CallableOutcome, CallableError>> + Send + 'static>>
        {
            Box::pin(async move {
                Ok(CallableOutcome {
                    call_id,
                    content: "ok".into(),
                    is_error: false,
                })
            })
        }
    }

    fn host(cap: &str, name: &str) -> CallableSpec {
        CallableSpec {
            capability: cap.into(),
            name: name.into(),
            description: format!("{name} callable"),
            parameters: serde_json::json!({"type": "object"}),
            idempotent: false,
            original_function: format!("advance:runtime/agent-{cap}@0.1.0::{name}"),
            handler: Arc::new(Stub),
        }
    }

    fn wasm(name: &str) -> ToolEntry {
        ToolEntry {
            name: name.into(),
            description: format!("{name} wasm"),
            params_schema: serde_json::json!({"type": "object"}),
        }
    }

    fn mcp(server: &str, tool: &str) -> McpToolEntry {
        McpToolEntry {
            name: tool.into(),
            description: format!("{tool} mcp"),
            params_schema: serde_json::json!({"type": "object"}),
            server_id: server.into(),
        }
    }

    /// V4 — L0 `{llm, fs}` projection has no memory / tools / mcp entry.
    #[test]
    fn v4_l0_projection_hides_memory_tools_mcp() {
        let projected = project_for_caps(
            vec![host("fs", "write"), host("memory", "remember")],
            vec![wasm("data__describe")],
            vec![mcp("srv", "echo")],
            &["llm".into(), "fs".into()],
        );
        let names: Vec<_> = projected.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["write"]);
        assert!(projected
            .entries
            .iter()
            .all(|e| e.source == CallableSource::HostFn));
        assert!(projected.shadowed.is_empty());
    }

    #[test]
    fn collision_host_wins_over_wasm_and_mcp() {
        let projected = project_catalog(
            vec![CallableDefinition {
                name: "write".into(),
                description: "fs".into(),
                parameters: serde_json::json!({}),
                source: CallableSource::HostFn,
                idempotent: Some(false),
            }],
            vec![CallableDefinition {
                name: "write".into(),
                description: "wasm".into(),
                parameters: serde_json::json!({}),
                source: CallableSource::WasmTool,
                idempotent: None,
            }],
            vec![CallableDefinition {
                name: "write".into(),
                description: "mcp".into(),
                parameters: serde_json::json!({}),
                source: CallableSource::McpTool,
                idempotent: None,
            }],
        );
        assert_eq!(projected.entries.len(), 1);
        assert_eq!(projected.entries[0].source, CallableSource::HostFn);
        assert_eq!(projected.shadowed, vec!["write", "write"]);
    }

    /// V6 — names identical across full form, compact form, and catalog.
    #[test]
    fn v6_names_match_across_both_renderings() {
        use advance_context_engine::{
            assemble_unified, catalog_tool_names, format_available_tools_section,
            format_available_tools_section_compact, HostFnEntry,
        };
        let projected = project_for_caps(
            vec![host("fs", "write"), host("fs", "read")],
            vec![wasm("data__describe")],
            vec![mcp("github", "search")],
            &["fs".into(), "tools".into(), "mcp".into()],
        );
        let catalog_names: Vec<String> = projected.entries.iter().map(|e| e.name.clone()).collect();
        let host_fns: Vec<HostFnEntry> = projected
            .entries
            .iter()
            .filter(|e| e.source == CallableSource::HostFn)
            .map(|e| HostFnEntry {
                name: e.name.clone(),
                description: e.description.clone(),
                params_schema: e.parameters.clone(),
            })
            .collect();
        let wasm_tools: Vec<ToolEntry> = projected
            .entries
            .iter()
            .filter(|e| e.source == CallableSource::WasmTool)
            .map(|e| ToolEntry {
                name: e.name.clone(),
                description: e.description.clone(),
                params_schema: e.parameters.clone(),
            })
            .collect();
        let mcp_tools: Vec<McpToolEntry> = projected
            .entries
            .iter()
            .filter(|e| e.source == CallableSource::McpTool)
            .map(|e| {
                let (server, tool) = e.name.split_once("__").unwrap();
                McpToolEntry {
                    name: tool.into(),
                    description: e.description.clone(),
                    params_schema: e.parameters.clone(),
                    server_id: server.into(),
                }
            })
            .collect();
        let unified = assemble_unified(host_fns, wasm_tools, mcp_tools);
        assert_eq!(catalog_tool_names(&unified), catalog_names);
        let full = format_available_tools_section(&unified);
        let compact = format_available_tools_section_compact(&unified);
        for name in &catalog_names {
            assert!(full.contains(name), "full form missing {name}: {full}");
            assert!(
                compact.contains(name),
                "compact form missing {name}: {compact}"
            );
        }
        assert!(!full.contains("generate"), "{full}");
        assert!(!compact.contains("generate"), "{compact}");
    }

    /// V19 — a shadowed catalog name is logged once with winning/losing sources.
    #[test]
    fn v19_shadow_log_line() {
        let projected = project_catalog(
            vec![CallableDefinition {
                name: "write".into(),
                description: "fs".into(),
                parameters: serde_json::json!({}),
                source: CallableSource::HostFn,
                idempotent: Some(false),
            }],
            vec![CallableDefinition {
                name: "write".into(),
                description: "wasm".into(),
                parameters: serde_json::json!({}),
                source: CallableSource::WasmTool,
                idempotent: None,
            }],
            vec![],
        );
        assert_eq!(projected.shadowed, vec!["write"]);
        assert_eq!(projected.shadow_logs.len(), 1);
        let logs = projected.shadow_logs.join(" | ");
        assert!(
            logs.contains("name=write") && logs.contains("host-fn") && logs.contains("wasm-tool"),
            "shadow log line: {logs}"
        );
        assert_eq!(
            projected.shadow_logs[0],
            catalog_shadow_log("write", CallableSource::HostFn, CallableSource::WasmTool)
        );
    }
}

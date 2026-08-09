//! Slice J (V1-b) — production `CallableInventoryReader` (CONTRACT-165).
//!
//! MODULE-017's runtime-internal projection of the WASM tool + MCP tool
//! inventories for MODULE-010 Callable Framework Layer 3 (`# Available Tools`)
//! assembly. Per MODULE-017-AC-30, the two inventories are exposed through two
//! **distinct methods returning two distinct types** — `list_wasm_tools ->
//! Vec<ToolEntry>` and `list_mcp_tools -> Vec<McpToolEntry>` — and are **never
//! combined inside this module** (the Layer-3 merge is M010 AC-18's job — see
//! `advance_context_engine::tier2::assemble_unified`).
//!
//! ## Snapshot model (sync trait over async sources)
//!
//! [`CallableInventoryReader`]'s methods are SYNC, while the sources
//! ([`ToolRegistry::list`], `cap_mcp::McpClient::list_tools`) are async. Rather
//! than block-on inside a sync method (deadlock/panic risk in an async
//! context), [`CallableInventory`] holds two **point-in-time snapshot** vectors
//! gathered async at construction via [`wasm_tool_entries`] (WASM half) +
//! `cap_mcp::mcp_tool_entries` (MCP half). Tools/servers registered later are
//! not reflected until re-gathered; a live-refresh model is future work
//! (MODULE-017 §3.6 (J-a)).
//!
//! ## `params_schema = {}` (empty object)
//!
//! A WASM tool's invocable surface is its set of per-method input-schemas
//! ([`ToolInfo::methods`], each with an optional `input_schema`); there is no
//! single tool-LEVEL params shape. The Tier-2 line therefore renders
//! `- name() — desc`. Surfacing per-method schemas into the line is a future
//! refinement.
//!
//! ## `agent_id` WASM filter (CONTRACT-183, Wave-15 Lane E)
//!
//! `list_wasm_tools(agent_id)` REALIZES CONTRACT-165's documented post-L1-`tools`-grant
//! filter: when a [`ToolsGrantReader`](advance_shared_types::traits::ToolsGrantReader)
//! (CONTRACT-183) is wired via [`CallableInventory::with_tools_grant_reader`], the WASM
//! set is narrowed to the agent's effective `tools.ids` allowlist (`None` allowlist =
//! wildcard/all; `Some(set)` = retain granted names). With NO reader wired the set is
//! returned unfiltered (matching the `MockCallableInventory`/`EmptyCallableInventory`
//! precedent — and production currently wires `EmptyCallableInventory`, so the filter is
//! dormant in prod). The MCP half (`list_mcp_tools`) per-agent `mcp.servers`/
//! `mcp.tool-patterns` L1 narrowing remains L1-V2-deferred (MODULE-017 §3.6 (m)); the
//! `mcp.tool-patterns` filter IS already applied inside `McpClient::list_tools` at gather.
//!
//! ## No cap-* cycle
//!
//! [`CallableInventory`] holds plain `advance-shared-types` vectors
//! ([`ToolEntry`] / [`McpToolEntry`]), NOT live `cap-mcp` handles, so cap-tools
//! does not depend on cap-mcp. The MCP half is produced by `cap_mcp`'s own
//! mapping/gather helpers and handed in at the composition site (the wiring
//! layer, or a test).

use std::sync::Arc;

use advance_shared_types::capability::{McpToolEntry, ToolEntry};
use advance_shared_types::traits::{CallableInventoryReader, ToolsGrantReader};

use crate::registry::{ToolInfo, ToolRegistry};

/// Map a registry [`ToolInfo`] snapshot into the CONTRACT-165 [`ToolEntry`]
/// projection: `id -> name`, `description -> description`, and an empty-object
/// `params_schema` (see the module rustdoc for why a WASM tool has no single
/// tool-level params shape).
pub fn tool_entries_from_infos(infos: Vec<ToolInfo>) -> Vec<ToolEntry> {
    infos
        .into_iter()
        .map(|info| ToolEntry {
            name: info.id,
            description: info.description,
            params_schema: serde_json::json!({}),
        })
        .collect()
}

/// Gather a snapshot of WASM tool entries from a live [`ToolRegistry`].
///
/// Does NOT force-`load()` each tool — `ToolRegistry::list()` returns
/// registered-but-unloaded tools with empty descriptions (MODULE-017 §2.7
/// "enumerate what is registered, descriptions opportunistic"); populating
/// descriptions requires the engine-bearing registry + a built component, which
/// is cargo-component-blocked (MODULE-017 §3.6 (e)). A future bootstrap slice
/// that wires the tool engine will `load()` before gathering.
pub async fn wasm_tool_entries(registry: &dyn ToolRegistry) -> Vec<ToolEntry> {
    tool_entries_from_infos(registry.list().await)
}

/// Production CONTRACT-165 [`CallableInventoryReader`] — MODULE-017's projection
/// of the WASM tool + MCP tool inventories for MODULE-010 Layer-3 assembly.
///
/// Holds the two inventories as **separate** snapshot vectors and returns each
/// through its own method; they are never combined inside this type (AC-30).
/// Construct via [`CallableInventory::new`] from the two gather helpers
/// (`wasm_tool_entries` here + `cap_mcp::mcp_tool_entries`) at the composition
/// site.
#[derive(Clone, Debug, Default)]
pub struct CallableInventory {
    wasm: Vec<ToolEntry>,
    mcp: Vec<McpToolEntry>,
    /// CONTRACT-183 — optional per-agent WASM `tools.ids` grant filter (Wave-15
    /// Lane E). `None` (the default + [`new`](Self::new)) ⇒ unfiltered, byte-identical
    /// to the pre-filter behaviour; `Some` ⇒ [`list_wasm_tools`](Self::list_wasm_tools)
    /// narrows to the agent's effective allowlist. The dependency-inverted
    /// `ToolsGrantReader` trait lives in MODULE-001 shared types, so cap-tools never
    /// imports cap-grant (no cycle).
    tools_grant: Option<Arc<dyn ToolsGrantReader>>,
}

impl CallableInventory {
    /// Construct from a pre-gathered WASM-tool snapshot and MCP-tool snapshot.
    /// No grant filter is wired (`list_wasm_tools` returns the full WASM set);
    /// add one via [`with_tools_grant_reader`](Self::with_tools_grant_reader).
    pub fn new(wasm: Vec<ToolEntry>, mcp: Vec<McpToolEntry>) -> Self {
        Self {
            wasm,
            mcp,
            tools_grant: None,
        }
    }

    /// Wire a CONTRACT-183 [`ToolsGrantReader`] so `list_wasm_tools(agent_id)` REALIZES
    /// CONTRACT-165's documented post-L1-`tools`-grant filter — narrowing the WASM set
    /// to the agent's effective `tools.ids` allowlist. Additive; `new` stays filter-free.
    pub fn with_tools_grant_reader(mut self, reader: Arc<dyn ToolsGrantReader>) -> Self {
        self.tools_grant = Some(reader);
        self
    }
}

impl CallableInventoryReader for CallableInventory {
    fn list_wasm_tools(&self, agent_id: &str) -> Vec<ToolEntry> {
        // CONTRACT-165 "post L1 `tools` grant filter" (Wave-15 Lane E): when a
        // CONTRACT-183 `ToolsGrantReader` is wired, narrow the WASM set to the agent's
        // effective `tools.ids` allowlist — `None` allowlist = wildcard (all tools,
        // parity with the capability-level GrantCheck allow); `Some(set)` = retain only
        // entries whose `name` is granted. With NO reader wired the set is returned
        // unfiltered (byte-identical to the pre-filter behaviour — preserves SYS-AC-010
        // and the production `EmptyCallableInventory` dormant path). Returns ONLY the
        // WASM inventory; never the MCP entries (AC-30 never-combined).
        match &self.tools_grant {
            None => self.wasm.clone(),
            Some(reader) => match reader.tool_allowlist(agent_id) {
                None => self.wasm.clone(),
                Some(allow) => self
                    .wasm
                    .iter()
                    .filter(|t| allow.iter().any(|a| a == &t.name))
                    .cloned()
                    .collect(),
            },
        }
    }

    fn list_mcp_tools(&self, _agent_id: &str) -> Vec<McpToolEntry> {
        // Returns ONLY the MCP inventory (post `mcp.tool-patterns` filter, which
        // `McpClient::list_tools` applied at gather time); never the WASM entries.
        self.mcp.clone()
    }
}

#[cfg(test)]
mod tests {
    //! Inline unit coverage for the WASM `ToolInfo -> ToolEntry` mapping. The
    //! AC-30 architectural test (T32) + the e2e against the real
    //! `ContextAssembler` live in `tests/callable_inventory.rs` (they need
    //! `advance-context-engine` + `cap-mcp` dev-deps).
    use super::*;
    use crate::registry::MethodInfo;

    fn info(id: &str, desc: &str) -> ToolInfo {
        ToolInfo {
            id: id.into(),
            description: desc.into(),
            methods: vec![MethodInfo {
                name: "run".into(),
                description: None,
                input_schema: None,
                output_schema: None,
                idempotent: None,
            }],
        }
    }

    // TJ-01 — id->name, description passthrough, empty-object params_schema.
    #[test]
    fn tj_01_tool_entries_from_infos_maps_fields() {
        let out = tool_entries_from_infos(vec![info("fs-read", "Read a file")]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "fs-read");
        assert_eq!(out[0].description, "Read a file");
        assert_eq!(out[0].params_schema, serde_json::json!({}));
    }

    // TJ-02 — a registered-but-unloaded tool (empty description, no methods, as
    // `LazyToolRegistry::list` synthesizes) maps cleanly without panicking.
    #[test]
    fn tj_02_unloaded_tool_maps_to_empty_description() {
        let out = tool_entries_from_infos(vec![ToolInfo {
            id: "lazy-tool".into(),
            description: String::new(),
            methods: Vec::new(),
        }]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "lazy-tool");
        assert!(out[0].description.is_empty());
        assert_eq!(out[0].params_schema, serde_json::json!({}));
    }

    // TJ-03 — the two reader methods return ONLY their own kind (no crossover).
    #[test]
    fn tj_03_reader_returns_only_its_own_kind() {
        let wasm = tool_entries_from_infos(vec![info("w1", "d1")]);
        let mcp = vec![McpToolEntry {
            name: "m1".into(),
            description: "md".into(),
            params_schema: serde_json::json!({}),
            server_id: "srv".into(),
        }];
        let inv = CallableInventory::new(wasm, mcp);
        let w = inv.list_wasm_tools("agent-x");
        let m = inv.list_mcp_tools("agent-x");
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].name, "w1");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].name, "m1");
        assert_eq!(m[0].server_id, "srv");
    }

    // CONTRACT-183 grant filter (Wave-15 Lane E).
    #[derive(Debug)]
    struct MockToolsGrant(Option<Vec<String>>);
    impl advance_shared_types::traits::ToolsGrantReader for MockToolsGrant {
        fn tool_allowlist(&self, _agent_id: &str) -> Option<Vec<String>> {
            self.0.clone()
        }
    }

    fn two_tool_inv() -> CallableInventory {
        CallableInventory::new(
            tool_entries_from_infos(vec![info("w1", "d1"), info("w2", "d2")]),
            vec![],
        )
    }

    // TJ-04 — no reader wired ⇒ unfiltered (byte-identical to the pre-filter path).
    #[test]
    fn tj_04_no_reader_is_unfiltered() {
        let names: Vec<String> = two_tool_inv()
            .list_wasm_tools("agent-x")
            .into_iter()
            .map(|t| t.name)
            .collect();
        assert_eq!(names, vec!["w1".to_string(), "w2".to_string()]);
    }

    // TJ-05 — reader returns None (wildcard) ⇒ all tools.
    #[test]
    fn tj_05_wildcard_reader_returns_all() {
        let inv = two_tool_inv().with_tools_grant_reader(std::sync::Arc::new(MockToolsGrant(None)));
        assert_eq!(inv.list_wasm_tools("agent-x").len(), 2);
    }

    // TJ-06 — reader narrows to the allowlist ⇒ only granted names survive.
    #[test]
    fn tj_06_narrow_reader_filters() {
        let inv = two_tool_inv()
            .with_tools_grant_reader(std::sync::Arc::new(MockToolsGrant(Some(vec!["w1".into()]))));
        let names: Vec<String> = inv
            .list_wasm_tools("agent-x")
            .into_iter()
            .map(|t| t.name)
            .collect();
        assert_eq!(
            names,
            vec!["w1".to_string()],
            "w2 (ungranted) must be absent"
        );
    }

    // TJ-07 — reader returns an empty allowlist ⇒ deny all WASM tools.
    #[test]
    fn tj_07_empty_allowlist_denies_all() {
        let inv = two_tool_inv()
            .with_tools_grant_reader(std::sync::Arc::new(MockToolsGrant(Some(vec![]))));
        assert!(inv.list_wasm_tools("agent-x").is_empty());
    }
}

//! Slice-A local trait for per-agent host-function inventory.
//!
//! Pending the M001 HostRegistry per-agent host-fn enumeration surface change
//! — see MODULE-010 §3.6 Known Gaps row 1 + §3.8 Slice-A sub-section. A future
//! M010 ↔ M001 wire-up slice will either promote this trait into shared-types
//! as a new CONTRACT-NNN or extend CONTRACT-001 HostRegistry with a
//! `list_host_fns_for_agent(agent_id)` method. Slice A makes no commitment
//! between (a) and (b); both paths preserve source compatibility for
//! context-engine since no external consumer reaches the trait today.

use serde::{Deserialize, Serialize};

/// MODULE-001 L0 host function inventory entry (Slice-A local shape, parallel
/// to MODULE-017 [`advance_shared_types::capability::ToolEntry`]).
///
/// `params_schema` is `serde_json::Value` to mirror the upstream `ToolEntry` /
/// `McpToolEntry` types — the formatter (see [`crate::tier2`]) extracts
/// top-level `properties` keys to render `name(args) — desc` lines.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostFnEntry {
    pub name: String,
    pub description: String,
    pub params_schema: serde_json::Value,
}

/// Read-only per-agent host-function inventory accessor. Consumed by
/// [`crate::assembler::ContextAssemblerImpl::assemble`] to build the
/// `# Available Tools` Tier-2 section (AC-18 Callable Framework Layer 3).
///
/// Implementer invariants:
/// - **Read-only**: implementations MUST NOT mutate runtime state on lookup.
/// - **Bounded**: implementations should cap the returned `Vec` length to a
///   reasonable per-agent inventory size (recommend ≤ 1024 entries).
/// - **Identifier validation**: `agent_id` should be whitelist-validated at
///   the call site; this trait does NOT enforce.
///
// TODO(M010 future slice): promote to shared-types or fold into CONTRACT-001
// HostRegistry. See MODULE-010 §3.6 Known Gaps row 1.
pub trait HostFnInventoryReader: Send + Sync {
    fn list_host_fns(&self, agent_id: &str) -> Vec<HostFnEntry>;
}

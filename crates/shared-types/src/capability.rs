//! Shared data types for capability-based authorization wiring
//! (MODULE-001 §1.4.1 + §3.2) plus supporting Slice A' types.
//!
//! - `CapabilityId` (Slice I): newtype over `String`, used as the internal
//!   map key in `InMemoryHostRegistry`. Implements `Borrow<str>` so
//!   `HostRegistry::lookup(&self, cap: &str)` works without alloc.
//! - `CapRequest` (Slice I): component-manifest declaration that a WASM
//!   component requests access to a capability. Used by MODULE-018
//!   `PackComponentResolution` and MODULE-001 §1.4.1 `CapabilityInjector::inject`.
//! - `CapParams` (Slice I): opaque parameter tree passed to `GrantCheck::check`
//!   (MODULE-013 CONTRACT-121) at per-host-call authorization time.
//! - `BudgetDecision`, `ToolEntry`, `McpToolEntry` (Slice A'): canonical data
//!   types for the Slice A' dependency-inversion traits.
//!
//! Every type in this module is verified canonical against a specific line in a downstream
//! MODULE spec. No invented shapes, no stub types, no forward references.

use serde::{Deserialize, Serialize};

/// Canonical source: `docs/modules/MODULE-001-runtime-host.md` line 762
///
/// `pub enum BudgetDecision { Allow, Deny(String) }`
///
/// **Intentionally NOT `#[non_exhaustive]`** — a budget decision is a closed two-state
/// authorization gate (`Allow` | `Deny`). Marking the enum non-exhaustive would force
/// every downstream consumer (MODULE-009 cap-llm and the future 14 trait consumers) to
/// add a wildcard match arm, and a wildcard arm is typically written as fail-open
/// (treat unknown variant as "not denial") — the exact opposite of the fail-closed
/// semantics a budget gate requires. Forward compatibility for future variants such
/// as `Defer(Duration)` is deliberately deferred to an explicit cross-module /spec
/// change that updates every consumer's match discipline simultaneously, not sneaked
/// in as a Slice A' hardening attribute.
///
/// `#[serde(deny_unknown_fields)]` is a forward-looking attribute: it is inert for
/// today's tuple variant wire format (`{"Deny":"msg"}`) AND remains inert for any
/// future tuple variants; it only becomes load-bearing when a future variant is added
/// in **struct form** (e.g. `Defer { until: Timestamp, reason: String }`). Maintainers
/// adding tuple-form variants must not rely on `deny_unknown_fields` and should add a
/// dedicated negative regression test for that variant's wire format.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum BudgetDecision {
    Allow,
    Deny(String),
}

/// Canonical source: `docs/modules/MODULE-017-skills-tools-mcp.md` lines 350-354
///
/// 3-field record describing a WASM tool discoverable through
/// [`crate::traits::CallableInventoryReader::list_wasm_tools`].
///
/// Derives `PartialEq` (not `Eq`) because `params_schema` is `serde_json::Value` — a
/// defensive forward-compatible choice since future `serde_json` features (e.g.
/// `arbitrary_precision`) may affect the `Number` arm's `Eq` impl.
///
/// `#[serde(deny_unknown_fields)]` rejects any extra fields at deserialization time to
/// protect downstream consumers that receive tool-inventory JSON from untrusted sources
/// (MCP server responses, skill pack manifests, LLM tool-call payloads).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolEntry {
    pub name: String,
    pub description: String,
    pub params_schema: serde_json::Value,
}

/// Canonical source: `docs/modules/MODULE-017-skills-tools-mcp.md` lines 356-361
///
/// 4-field record describing an MCP tool discoverable through
/// [`crate::traits::CallableInventoryReader::list_mcp_tools`]. Same `PartialEq`-only
/// rationale as [`ToolEntry`].
///
/// `#[serde(deny_unknown_fields)]` rejects any extra fields at deserialization time.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpToolEntry {
    pub name: String,
    pub description: String,
    pub params_schema: serde_json::Value,
    pub server_id: String,
}

// ============================================================================
// Slice I — capability wiring data types
// ============================================================================

/// Identifier for a capability (e.g. `"cap-fs-read"`, `"cap-llm"`). Newtype
/// over `String` so once consumers code against `&CapabilityId` the compiler
/// catches ordinary string mix-ups. Serde transparent — wire format is a
/// plain string.
///
/// Implements `Borrow<str>` so `HashMap<CapabilityId, V>::get(&str)` works
/// without temporary `CapabilityId` allocation. This is the load-bearing
/// trait that allows `InMemoryHostRegistry` to internally key on
/// `CapabilityId` while the trait method `HostRegistry::lookup(&self, cap: &str)`
/// keeps its signature byte-identical (MODULE-001 §1.4.1).
///
/// Canonical source: `docs/modules/MODULE-001-runtime-host.md` §3.2
/// (line 1100) and §1.4.1 pseudocode line 202.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilityId(String);

impl CapabilityId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for CapabilityId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::borrow::Borrow<str> for CapabilityId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl From<&str> for CapabilityId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for CapabilityId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Component-manifest declaration that a WASM component requests access to
/// a capability. MODULE-001 §1.4.1 `CapabilityInjector::inject` walks
/// `&[CapRequest]` and looks each up in the `HostRegistry`.
///
/// This slice ships only the single field every cited consumer reads
/// (`capability`). Additional fields implied by MODULE-001 §1.4.1 / MODULE-018
/// manifest parsing are NOT included — they will be added when MODULE-018's
/// pack manifest schema lands and pins the exact field set. `#[serde(default)]`
/// on any future fields will preserve backward compat.
///
/// `#[serde(deny_unknown_fields)]` protects against field-drift bugs today.
///
/// Canonical source: `docs/modules/MODULE-001-runtime-host.md` §3.2 +
/// `docs/modules/MODULE-018-pack-system.md` line 318.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapRequest {
    pub capability: CapabilityId,
}

/// Opaque parameter tree passed to `GrantCheck::check` at per-host-call
/// authorization time (MODULE-013 CONTRACT-121). MODULE-013's SubsetValidator
/// reads this tree; no field-level schema is declared here.
///
/// Serde transparent — wire format is the wrapped `serde_json::Value`.
///
/// Canonical source: `docs/modules/MODULE-001-runtime-host.md` line 805 +
/// MODULE-013 line 432.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapParams(pub serde_json::Value);

impl CapParams {
    pub fn new(v: serde_json::Value) -> Self {
        Self(v)
    }
    pub fn as_value(&self) -> &serde_json::Value {
        &self.0
    }
    /// Null-valued `CapParams` — used by callers that need to invoke
    /// `GrantCheck::check` without any host-call-specific parameters yet.
    /// Slice T's `CapabilityInjector` uses this at the L1 gate since the
    /// params-to-CapParams lowering from the WASM call frame is deferred
    /// to a later slice.
    pub fn empty() -> Self {
        Self(serde_json::Value::Null)
    }
}

impl From<serde_json::Value> for CapParams {
    fn from(v: serde_json::Value) -> Self {
        Self(v)
    }
}

/// CONTRACT-121 invocation-gate decision — 2-state, matches MODULE-001
/// §1.4.1:245-249 (`GrantDecision::Allow` / `GrantDecision::Deny(reason)`
/// pattern-matched by the L1 gate). The spec does not carry an explicit
/// `pub enum` block for this type; the variants are unambiguous from the
/// usage pattern at MODULE-001 lines 244-249.
///
/// This is the invocation-gate return type only. MODULE-013's dynamic-grant
/// *resolver chain* uses a separate 3-state `GrantDecision::Approved/Denied/
/// Pending` enum (MODULE-013:162-173). When MODULE-013's crate ships it
/// must either namespace or rename that internal enum to avoid collision
/// with this one — that is a future /spec concern, not CONTRACT-121's.
///
/// `#[serde(deny_unknown_fields)]` is inert for today's tuple-variant wire
/// format (`"Allow"` / `{"Deny":"reason"}`) — same posture as Slice A'
/// `BudgetDecision` (see `BudgetDecision` rustdoc above for the full
/// rationale on forward compatibility).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum GrantDecision {
    Allow,
    Deny(String),
}

//! MODULE-017 `cap-tools` — Tool registry + `agent-tools` host_fn surface.
//!
//! ## Slice A baseline (declarations only)
//!
//! - [`ToolRegistry`] trait (CONTRACT-163) + [`InMemoryToolRegistry`] stub.
//! - WIT ABI records ([`ToolInfo`] / [`MethodInfo`] / [`ToolDescription`]
//!   with `serde(rename_all = "kebab-case")` matching the WIT canonical
//!   form).
//! - [`ToolError`] 6-arm error variant matching the WIT shape.
//!
//! ## Slice B additions (2026-05-14)
//!
//! - [`validator::validate_tool_component`] — `tool-exports` /
//!   `runnable` mutual-exclusion structural-presence check via
//!   `wasmparser::Payload::ComponentExportSection` walk.
//! - [`lazy_registry::LazyToolRegistry`] — production `ToolRegistry`
//!   impl with two-phase locking, LRU cache, lazy load, validation
//!   gate, fail-closed `max_result_bytes`.
//! - [`host_fn::register_agent_tools`] — registers `tool-invoke` +
//!   `list-tools` HostFunctionSpecs under capability `"tools"`.
//!
//! ## Slice B scope clarifier
//!
//! Slice B verifies AC-09/10/11/12/14 at the **dispatch chain layer**
//! (validator gate, LRU + lazy load, failed-load hidden,
//! mutual-exclusion, host_fn Val round-trip). In-WASM tool
//! `execute()` invocation is a Slice B' refinement on top of this
//! skeleton — see MODULE-017 §2.7 Core Logic for the scope note.

pub use host_fn::{
    register_agent_tools, register_agent_tools_with_guard, AgentToolsInvokeHandler,
    AgentToolsListHandler, MAX_TOOL_PARAMS_BYTES, MAX_TOOL_STRING_PARAM_BYTES,
};
pub use lazy_registry::{LazyRegistryConfig, LazyToolRegistry};
pub use registry::{
    InMemoryToolRegistry, MethodInfo, ToolDescription, ToolError, ToolInfo, ToolInstance,
    ToolRegistry,
};
pub use validator::{
    validate_runnable_component, validate_tool_component, ExportSource, ValidationOutcome,
};

// Slice J (V1-b) — production CONTRACT-165 CallableInventoryReader + WASM
// mapping/gather helpers.
pub use inventory::{tool_entries_from_infos, wasm_tool_entries, CallableInventory};

pub mod host_fn;
pub mod inventory;
pub mod lazy_registry;
mod registry;
pub mod validator;

// Slice F — observability emit + runtime JSON-Schema validation gate.
mod events;
mod schema_guard;

// Slice G — AC-24 tool-retry idempotency gate + harness.
mod retry;

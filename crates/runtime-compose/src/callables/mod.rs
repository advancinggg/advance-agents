//! Layer 3 callable catalog + dispatch (ADR 2026-10-24 S2).

pub mod catalog;
pub mod dispatch;
pub mod host_fn;
pub mod specs;

pub use catalog::{project_catalog, CatalogHostFnInventory, ProjectedCatalog};
pub use dispatch::{
    mcp_invoke_grant_parts, AgentCapsLookup, CallableDispatcher, StaticCaps, TreeCapsLookup,
    INVOKE_MCP_TOOL_FUNCTION, TOOL_INVOKE_FUNCTION,
};
pub use host_fn::register_agent_callables;
pub use specs::{register_fs_callables, register_genui_callables, register_memory_callables};

//! cap-mcp — MODULE-017 MCP-client transport + WIT host_fn dispatch.
//!
//! Slice B (2026-05-14) shipped the HTTP/SSE transport foundation +
//! JSON-RPC wire shapes + `McpError` surface.
//!
//! Slice D (2026-05-18) adds:
//! - `StdioMcpTransport` — `tokio::process::Command` subprocess + line-delimited
//!   JSON-RPC framing + LeakDetector on responses (AC-17).
//! - `McpClient` — high-level dispatch surface over `Arc<dyn McpTransport>` with
//!   per-server transport handles, tool-pattern filter, and schema-validated
//!   `invoke_tool` (AC-15).
//! - `McpServersConfig` — programmatic whitelist + per-server `tool_patterns` glob
//!   filter + per-tool schemas (AC-23 layers 1 + 2).
//! - `SchemaValidator` — wraps `jsonschema::JSONSchema` for input/output validation
//!   with a recursive `$ref` pre-scan that rejects external references (AC-13).
//! - `register_mcp_client` — registers 7 `HostFunctionHandler` impls covering the
//!   `mcp-client` WIT interface, split across `mcp.servers` (5 server-level
//!   methods) and `mcp.tool-patterns` (2 tool-level methods) capability dimensions
//!   per MODULE-017 AC-30 architectural split.

pub use client::{McpClient, McpToolInfo, McpTransport};
// Slice J (V1-b) — MCP half of the CONTRACT-165 inventory feed.
pub use error::{McpError, McpErrorKind};
pub use host_fn::register_mcp_client;
pub use http_transport::HttpMcpTransport;
pub use inventory::{mcp_tool_entries, mcp_tool_entries_from_infos};
pub use jsonrpc::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
pub use schema_validator::SchemaValidator;
pub use stdio_transport::StdioMcpTransport;
pub use whitelist::{
    McpServerEntry, McpServersConfig, McpServersConfigBuilder, McpTransportSpec, ToolPattern,
    ToolSchemas,
};

mod client;
mod error;
mod host_fn;
mod http_transport;
mod inventory;
mod jsonrpc;
mod schema_validator;
mod stdio_transport;
mod whitelist;

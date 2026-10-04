//! cap-mcp — MODULE-017 MCP-client transport + WIT host_fn dispatch.
//!
//! - `HttpMcpTransport` — JSON-RPC over the cap-http security chain, with
//!   `application/json` and SSE responses.
//! - `StdioMcpTransport` — a subprocess speaking line-delimited JSON-RPC: bounded
//!   reads, LeakDetector on both directions, answers to server `ping` requests,
//!   and the whole process group stopped on close (AC-17).
//! - `McpClient` — high-level dispatch surface over `Arc<dyn McpTransport>` with
//!   one connection slot per server (stdio servers spawned and initialized with
//!   the MCP `initialize` exchange, dead transports evicted and reconnected with
//!   backoff), tool-pattern filter, and schema-validated `invoke_tool` (AC-15).
//! - `McpServersConfig` — programmatic whitelist + per-server `tool_patterns` glob
//!   filter + per-tool schemas (AC-23 layers 1 + 2).
//! - `SchemaValidator` — wraps `jsonschema::JSONSchema` for input/output validation
//!   with a recursive `$ref` pre-scan that rejects external references (AC-13).
//! - `register_mcp_client` — registers 7 `HostFunctionHandler` impls covering the
//!   `mcp-client` WIT interface, split across `mcp.servers` (5 server-level
//!   methods) and `mcp.tool-patterns` (2 tool-level methods) capability dimensions
//!   per MODULE-017 AC-30 architectural split.

pub use client::{
    McpClient, McpClientLimits, McpToolInfo, McpTransport, MCP_PROTOCOL_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
};
// Slice J (V1-b) — MCP half of the CONTRACT-165 inventory feed.
pub use error::{McpError, McpErrorKind};
pub use host_fn::{register_mcp_client, register_mcp_client_with_web_grant};
pub use http_transport::HttpMcpTransport;
pub use inventory::{mcp_tool_entries, mcp_tool_entries_from_infos};
pub use jsonrpc::{JsonRpcError, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse};
pub use schema_validator::SchemaValidator;
pub use stdio_transport::{StdioMcpTransport, StdioOptions};
pub use web_provider::refuse_stdio_web_provider;
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
mod web_provider;
mod whitelist;

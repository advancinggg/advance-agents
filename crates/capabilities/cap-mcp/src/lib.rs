//! cap-mcp — MODULE-017 MCP-client transport + WIT host_fn dispatch.
//!
//! - `HttpMcpTransport` — the MCP Streamable HTTP transport: JSON-RPC POSTs
//!   through the cap-http security chain, `application/json` and SSE answers,
//!   the session id and protocol-version headers, a new session when the
//!   server ends one, and errors that never carry server-sent text.
//! - `StdioMcpTransport` — a subprocess speaking line-delimited JSON-RPC: bounded
//!   reads, LeakDetector on both directions, answers to server `ping` requests,
//!   and the whole process group stopped on close (AC-17).
//! - `McpClient` — high-level dispatch surface over `Arc<dyn McpTransport>` with
//!   one connection slot per server (servers initialized with the MCP
//!   `initialize` exchange, dead transports evicted and reconnected with
//!   backoff, connections reported as `mcp.server_started` /
//!   `mcp.server_died`), requests attributed to the calling agent, paginated and
//!   bounded tool listings kept in a tool cache, tool-pattern filter, and
//!   schema-validated `invoke_tool` (AC-15). `McpClient::shutdown` closes every
//!   connection at once and stops the stdio servers, which do not end with the
//!   host process on their own.
//! - `McpServersConfig` — programmatic whitelist + per-server `tool_patterns` glob
//!   filter + per-tool schemas (AC-23 layers 1 + 2).
//! - `SchemaValidator` — wraps `jsonschema::JSONSchema` for input/output validation
//!   with a recursive `$ref` pre-scan that rejects external references (AC-13).
//! - `register_mcp_client` — registers the 7 `mcp-client` WIT host functions under
//!   the one capability `mcp`. Each call is decided against the caller's `mcp`
//!   grants by an `McpGate` (AC-23 layer 3): calls through the grant check,
//!   listings through the silent grant readers, which write no `authz.checked`
//!   event; the web family tools also need the `web` grant (`McpWebGrant`) and
//!   are refused from stdio servers. The handlers emit the `mcp.*` call events.

pub use client::{
    McpClient, McpClientLimits, McpToolInfo, McpTransport, MCP_PROTOCOL_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
};
// Slice J (V1-b) — MCP half of the CONTRACT-165 inventory feed.
pub use error::{McpError, McpErrorKind};
pub use gate::{McpGate, McpScopes, McpWebGrant, MCP_CAPABILITY};
pub use host_fn::register_mcp_client;
pub use http_transport::{HttpMcpTransport, HttpOptions, MAX_SESSION_ID_BYTES};
pub use inventory::{mcp_tool_entries, mcp_tool_entries_from_infos};
pub use jsonrpc::{JsonRpcError, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse};
pub use listing::{
    CachedToolListing, MAX_CACHED_TOOLS, MAX_TOOLS_PER_SERVER, MAX_TOOL_DESCRIPTION_BYTES,
    MAX_TOOL_LIST_CURSOR_BYTES, MAX_TOOL_LIST_PAGES, MAX_TOOL_NAME_BYTES, MAX_TOOL_SCHEMA_BYTES,
};
pub use schema_validator::SchemaValidator;
pub use stdio_transport::{StdioMcpTransport, StdioOptions};
pub use web_provider::refuse_stdio_web_provider;
pub use whitelist::{
    McpServerEntry, McpServersConfig, McpServersConfigBuilder, McpTransportSpec, ToolPattern,
    ToolSchemas, MAX_SERVERS,
};

mod client;
mod error;
mod events;
mod gate;
mod host_fn;
mod http_transport;
mod inventory;
mod jsonrpc;
mod listing;
mod schema_validator;
mod stdio_transport;
mod web_provider;
mod whitelist;

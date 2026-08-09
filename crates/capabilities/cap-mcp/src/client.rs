//! `McpClient` — high-level MCP dispatch surface (Slice D AC-15).
//!
//! Aggregates the per-server transport handles + tool-pattern filter + per-tool
//! schemas; exposes the 7 method surfaces consumed by `host_fn.rs`:
//!
//! - `list_servers` / `list_tools` / `list_prompts` / `list_resources` — server &
//!   tool inventory.
//! - `get_prompt` / `read_resource` — read-shaped retrieval.
//! - `invoke_tool` — schema-validated tool call with tool-pattern gate.
//!
//! All dispatch routes through an `Arc<dyn McpTransport>` per server (cached
//! lazily on first use), so HTTP and stdio transports are uniform behind the
//! same call site.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use advance_shared_types::security_validator::LeakDetector;
use async_trait::async_trait;

use crate::error::McpError;
use crate::http_transport::HttpMcpTransport;
use crate::schema_validator::SchemaValidator;
use crate::stdio_transport::StdioMcpTransport;
use crate::whitelist::{McpServerEntry, McpServersConfig, McpTransportSpec};

/// Trait shared by HTTP and stdio transports. Slice D's `McpClient` dispatches
/// through `Arc<dyn McpTransport>` so both transport classes can be cached
/// behind the same per-server handle.
#[async_trait]
pub trait McpTransport: Send + Sync {
    async fn invoke(&self, method: &str, params: serde_json::Value) -> Result<Vec<u8>, McpError>;

    fn server_id(&self) -> &str;
}

/// Per-server info surfaced by `list_servers`. Mirrors the WIT
/// `mcp-server-info` record at `crates/runtime/wit/advance.wit:174-177`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpServerInfo {
    pub id: String,
    pub description: String,
}

/// Per-tool info surfaced by `list_tools`. Mirrors `mcp-tool-info`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpToolInfo {
    pub name: String,
    pub description: String,
    pub server_id: String,
}

/// Per-prompt info surfaced by `list_prompts`. Mirrors `mcp-prompt-info`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpPromptInfo {
    pub name: String,
    pub description: String,
    pub server_id: String,
}

/// Per-resource info surfaced by `list_resources`. Mirrors `mcp-resource-info`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpResourceInfo {
    pub uri: String,
    pub description: String,
    pub server_id: String,
}

/// High-level MCP client. Owns the `McpServersConfig` whitelist + lazy
/// transport pool.
pub struct McpClient {
    config: Arc<McpServersConfig>,
    transports: RwLock<HashMap<String, Arc<dyn McpTransport>>>,
    leak_detector: Arc<dyn LeakDetector>,
    http_chain: Option<Arc<dyn advance_shared_types::security_validator::HttpSecurityChain>>,
}

impl McpClient {
    /// Construct a new client.
    ///
    /// `leak_detector` is plumbed into stdio transports for inbound response
    /// scanning. `http_chain` is required for HTTP transports — passed as
    /// Option so test fixtures with no HTTP servers can omit it.
    pub fn new(
        config: Arc<McpServersConfig>,
        leak_detector: Arc<dyn LeakDetector>,
        http_chain: Option<Arc<dyn advance_shared_types::security_validator::HttpSecurityChain>>,
    ) -> Self {
        Self {
            config,
            transports: RwLock::new(HashMap::new()),
            leak_detector,
            http_chain,
        }
    }

    /// Construct a test-only client where transports are pre-injected (no lazy
    /// spawn). Used by `tests/support/mock_transport.rs` and
    /// `tests/client_surface.rs`.
    #[doc(hidden)]
    pub fn new_with_transports(
        config: Arc<McpServersConfig>,
        leak_detector: Arc<dyn LeakDetector>,
        injected: HashMap<String, Arc<dyn McpTransport>>,
    ) -> Self {
        Self {
            config,
            transports: RwLock::new(injected),
            leak_detector,
            http_chain: None,
        }
    }

    /// List configured servers (filtered by whitelist).
    pub async fn list_servers(&self) -> Vec<McpServerInfo> {
        self.config
            .list_servers()
            .map(|e| McpServerInfo {
                id: e.server_id.clone(),
                description: e.description.clone(),
            })
            .collect()
    }

    /// List tools on a server. Dispatches `tools/list` over the server's
    /// transport and applies the tool-patterns filter.
    pub async fn list_tools(&self, server_id: &str) -> Result<Vec<McpToolInfo>, McpError> {
        let entry = self.config.get(server_id)?;
        let transport = self.transport_for(entry).await?;
        let bytes = transport
            .invoke("tools/list", serde_json::Value::Object(Default::default()))
            .await?;
        let parsed: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| McpError::invalid_response(format!("parse tools/list result: {e}")))?;
        let arr = parsed
            .get("tools")
            .and_then(|v| v.as_array())
            .ok_or_else(|| McpError::invalid_response("tools/list missing 'tools' array"))?;
        let mut out = Vec::new();
        for v in arr {
            let name = v
                .get("name")
                .and_then(|n| n.as_str())
                .ok_or_else(|| McpError::invalid_response("tool entry missing 'name'"))?;
            if !entry.tool_allowed(name) {
                continue;
            }
            let description = v
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or_default()
                .to_string();
            out.push(McpToolInfo {
                name: name.to_string(),
                description,
                server_id: server_id.to_string(),
            });
        }
        Ok(out)
    }

    /// List prompts on a server (no filter).
    pub async fn list_prompts(&self, server_id: &str) -> Result<Vec<McpPromptInfo>, McpError> {
        let entry = self.config.get(server_id)?;
        let transport = self.transport_for(entry).await?;
        let bytes = transport
            .invoke(
                "prompts/list",
                serde_json::Value::Object(Default::default()),
            )
            .await?;
        let parsed: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| McpError::invalid_response(format!("parse prompts/list result: {e}")))?;
        let arr = parsed
            .get("prompts")
            .and_then(|v| v.as_array())
            .ok_or_else(|| McpError::invalid_response("prompts/list missing 'prompts' array"))?;
        let mut out = Vec::new();
        for v in arr {
            let name = v
                .get("name")
                .and_then(|n| n.as_str())
                .ok_or_else(|| McpError::invalid_response("prompt entry missing 'name'"))?;
            let description = v
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or_default()
                .to_string();
            out.push(McpPromptInfo {
                name: name.to_string(),
                description,
                server_id: server_id.to_string(),
            });
        }
        Ok(out)
    }

    pub async fn get_prompt(
        &self,
        server_id: &str,
        prompt_name: &str,
        args: Vec<(String, String)>,
    ) -> Result<Vec<u8>, McpError> {
        let entry = self.config.get(server_id)?;
        let transport = self.transport_for(entry).await?;
        let args_obj: serde_json::Map<String, serde_json::Value> = args
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        let params = serde_json::json!({"name": prompt_name, "arguments": args_obj});
        transport.invoke("prompts/get", params).await
    }

    pub async fn list_resources(&self, server_id: &str) -> Result<Vec<McpResourceInfo>, McpError> {
        let entry = self.config.get(server_id)?;
        let transport = self.transport_for(entry).await?;
        let bytes = transport
            .invoke(
                "resources/list",
                serde_json::Value::Object(Default::default()),
            )
            .await?;
        let parsed: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| McpError::invalid_response(format!("parse resources/list result: {e}")))?;
        let arr = parsed
            .get("resources")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                McpError::invalid_response("resources/list missing 'resources' array")
            })?;
        let mut out = Vec::new();
        for v in arr {
            let uri = v
                .get("uri")
                .and_then(|n| n.as_str())
                .ok_or_else(|| McpError::invalid_response("resource entry missing 'uri'"))?;
            let description = v
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or_default()
                .to_string();
            out.push(McpResourceInfo {
                uri: uri.to_string(),
                description,
                server_id: server_id.to_string(),
            });
        }
        Ok(out)
    }

    pub async fn read_resource(&self, server_id: &str, uri: &str) -> Result<Vec<u8>, McpError> {
        let entry = self.config.get(server_id)?;
        let transport = self.transport_for(entry).await?;
        let params = serde_json::json!({"uri": uri});
        transport.invoke("resources/read", params).await
    }

    /// Invoke a tool. Order:
    /// 1. Whitelist gate (config.get) — `McpError::not_found` for unknown server.
    /// 2. Tool-pattern gate — `McpError::tool_not_found` if blocked.
    /// 3. Input schema validation (if schema present) — fails BEFORE dispatch.
    /// 4. Transport invoke `tools/call`.
    /// 5. Output schema validation (if schema present).
    pub async fn invoke_tool(
        &self,
        server_id: &str,
        tool_name: &str,
        params_bytes: &[u8],
    ) -> Result<Vec<u8>, McpError> {
        // Audit round 1 Info: defense-in-depth bytes cap at the client API
        // boundary — the host_fn decoder already enforces MAX_MCP_PARAMS_BYTES,
        // but Rust-side composers calling invoke_tool directly (tests, future
        // adapter slices) skip the host_fn layer.
        const MAX_INVOKE_TOOL_PARAMS_BYTES: usize = 4 * 1024 * 1024;
        if params_bytes.len() > MAX_INVOKE_TOOL_PARAMS_BYTES {
            return Err(McpError::invalid_response(format!(
                "invoke_tool params exceed {MAX_INVOKE_TOOL_PARAMS_BYTES} bytes"
            )));
        }

        let entry = self.config.get(server_id)?;
        if !entry.tool_allowed(tool_name) {
            return Err(McpError::tool_not_found(format!(
                "tool '{tool_name}' does not match mcp.tool-patterns for '{server_id}'"
            )));
        }
        let schemas = entry.tool_schemas.get(tool_name);

        // Parse params once (we need it for both schema-validate and dispatch).
        let params_json: serde_json::Value = if params_bytes.is_empty() {
            serde_json::Value::Object(Default::default())
        } else {
            serde_json::from_slice(params_bytes)
                .map_err(|e| McpError::invalid_response(format!("parse params: {e}")))?
        };

        if let Some(s) = schemas {
            if let Some(input_schema) = &s.input {
                let v = SchemaValidator::new(input_schema)?;
                v.validate(&params_json)?;
            }
        }

        let transport = self.transport_for(entry).await?;
        let call_params = serde_json::json!({
            "name": tool_name,
            "arguments": params_json,
        });
        let bytes = transport.invoke("tools/call", call_params).await?;

        if let Some(s) = schemas {
            if let Some(output_schema) = &s.output {
                let v = SchemaValidator::new(output_schema)?;
                let parsed: serde_json::Value = serde_json::from_slice(&bytes)
                    .map_err(|e| McpError::invalid_response(format!("parse output: {e}")))?;
                v.validate(&parsed)?;
            }
        }

        Ok(bytes)
    }

    /// Get or lazily spawn the transport for a server. Stdio transports are
    /// not cloneable, so we cache them as `Arc<dyn McpTransport>` keyed by id.
    ///
    /// Audit round 1 W10 fix: hold the write lock across `spawn_transport`
    /// so concurrent first-touch callers don't each fork a real subprocess
    /// (stdio) only for the losers' transports to immediately drop. Previously
    /// the read-check / spawn-outside-lock / write-check pattern admitted N
    /// parallel spawn attempts under burst. `spawn_transport` is fully sync
    /// (no `.await` inside) so blocking the RwLock briefly is acceptable.
    async fn transport_for(
        &self,
        entry: &McpServerEntry,
    ) -> Result<Arc<dyn McpTransport>, McpError> {
        if let Some(t) = self
            .transports
            .read()
            .expect("rwlock")
            .get(&entry.server_id)
        {
            return Ok(Arc::clone(t));
        }
        let mut guard = self.transports.write().expect("rwlock");
        // Re-check under the write lock: a concurrent caller may have just
        // populated the slot.
        if let Some(t) = guard.get(&entry.server_id) {
            return Ok(Arc::clone(t));
        }
        let new_transport = self.spawn_transport(entry)?;
        guard.insert(entry.server_id.clone(), Arc::clone(&new_transport));
        Ok(new_transport)
    }

    fn spawn_transport(&self, entry: &McpServerEntry) -> Result<Arc<dyn McpTransport>, McpError> {
        match &entry.transport {
            McpTransportSpec::Http {
                endpoint_url,
                capability,
            } => {
                let chain = self.http_chain.as_ref().ok_or_else(|| {
                    McpError::transport(
                        "http transport requested but McpClient has no http_chain configured",
                    )
                })?;
                Ok(Arc::new(HttpMcpTransport::new(
                    Arc::clone(chain),
                    entry.server_id.clone(),
                    endpoint_url.clone(),
                    capability.clone(),
                )))
            }
            McpTransportSpec::Stdio { command, args, env } => {
                let t = StdioMcpTransport::spawn(
                    entry.server_id.clone(),
                    command,
                    args,
                    env,
                    Arc::clone(&self.leak_detector),
                )?;
                Ok(Arc::new(t))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn _assert_send_sync()
    where
        McpClient: Send + Sync,
    {
    }
}

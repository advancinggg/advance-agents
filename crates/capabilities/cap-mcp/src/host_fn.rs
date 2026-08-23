//! `mcp-client` WIT host_fn registration — MODULE-017 Slice D AC-15 + AC-23.
//!
//! Wires the 7 canonical `mcp-client` WIT methods into the runtime
//! `HostRegistry`. Capability registration is SPLIT across two L1 grant
//! dimensions per MODULE-013 §1.5 + AC-30 architectural intent:
//!
//! - `mcp.servers` — gates server-level reads:
//!   - `list-mcp-servers`
//!   - `list-mcp-prompts`
//!   - `get-mcp-prompt`
//!   - `list-mcp-resources`
//!   - `read-mcp-resource`
//!
//! - `mcp.tool-patterns` — gates tool-level operations:
//!   - `list-mcp-tools`
//!   - `invoke-mcp-tool`
//!
//! The framework `CapabilityInjector` calls `gc.check(agent_id, capability,
//! function, CapParams::empty())` before every invoke, so registering under
//! the correct dimension auto-applies the L1 GrantCheck gate. PARAM-level
//! subset enforcement at L1 (per-call CapParams carrying server_id /
//! tool_name) is L1-V2 / future-slice scope mirroring MODULE-013 AC-21 §3.3
//! T37.
//!
//! ## Idempotent flag
//!
//! Read-shaped methods (`list-*`, `get-*`, `read-*`) carry `idempotent: true`
//! per WIT semantics. Only `invoke-mcp-tool` has side-effects on the remote
//! MCP server, so it stays non-idempotent.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use advance_runtime::host_registry::{
    HostCallContext, HostCallError, HostFunctionHandler, HostFunctionSpec, HostRegistry,
};
use advance_shared_types::capability::{CapParams, GrantDecision};
use advance_shared_types::traits::GrantCheck;
use advance_shared_types::web_search::{is_web_tool_id, WEB_GRANT_CAPABILITY};
use wasmtime::component::Val;

use crate::client::{McpClient, McpPromptInfo, McpResourceInfo, McpServerInfo, McpToolInfo};
use crate::error::McpError;

#[cfg(test)]
use crate::error::McpErrorKind;

const NAMESPACE: &str = "advance:runtime/mcp-client@0.1.0";
pub const CAPABILITY_SERVERS: &str = "mcp.servers";
pub const CAPABILITY_TOOL_PATTERNS: &str = "mcp.tool-patterns";

/// Max bytes for a single string parameter (server_id / tool_name /
/// prompt_name / uri). Conservative: 1 KiB allows long URIs.
pub const MAX_MCP_STRING_PARAM_BYTES: usize = 1024;

/// Max bytes for the `list<u8>` params payload on `invoke-mcp-tool`. Matches
/// MAX_STDIO_REQ_BYTES / MAX_JSONRPC_REQ_BYTES for symmetry.
pub const MAX_MCP_PARAMS_BYTES: usize = 4 * 1024 * 1024;

// ─────────────────────────────────────────────────────────────────────────
// Val decode helpers
// ─────────────────────────────────────────────────────────────────────────

fn decode_string(val: &Val) -> Result<&str, HostCallError> {
    match val {
        Val::String(s) => {
            if s.len() > MAX_MCP_STRING_PARAM_BYTES {
                return Err(HostCallError::HandlerError(format!(
                    "string param exceeds {MAX_MCP_STRING_PARAM_BYTES} bytes"
                )));
            }
            Ok(s.as_str())
        }
        _ => Err(HostCallError::HandlerError(
            "expected string parameter".to_string(),
        )),
    }
}

fn decode_byte_list(val: &Val) -> Result<Vec<u8>, HostCallError> {
    match val {
        Val::List(items) => {
            // Audit round 1 C2 fix: element-count == output-byte-count for
            // `list<u8>`, so capping `items.len()` at MAX_MCP_PARAMS_BYTES
            // bounds the post-`.collect()` Vec<u8> at ≤ 4 MiB. The upstream
            // Val::List materialization (~24B × items.len()) is wasmtime's
            // memory accounting concern, not ours — this guard's intent is
            // strictly to bound the OUTPUT bytes the host commits to after
            // decoding (mirrors cap-tools SB-23 collect-side defense).
            if items.len() > MAX_MCP_PARAMS_BYTES {
                return Err(HostCallError::HandlerError(format!(
                    "params list exceeds {MAX_MCP_PARAMS_BYTES} elements (1 byte each)"
                )));
            }
            items
                .iter()
                .map(|v| match v {
                    Val::U8(b) => Ok(*b),
                    _ => Err(HostCallError::HandlerError(
                        "expected list<u8> for params".to_string(),
                    )),
                })
                .collect()
        }
        _ => Err(HostCallError::HandlerError(
            "expected list<u8> parameter".to_string(),
        )),
    }
}

/// Decode `list<cap-param>` (used by get-mcp-prompt). Each `cap-param` is a
/// `record { key: string, value: string }`. Returns `Vec<(String, String)>`.
///
/// Audit round 1 C1 fix: inner key + value strings are bounded by
/// `MAX_MCP_STRING_PARAM_BYTES` (1 KiB each), symmetric with `decode_string`.
/// Without this guard, a guest could submit 256 cap-params each carrying
/// multi-MiB strings since `Val::String` parsing in wasmtime is upstream and
/// uncapped.
fn decode_cap_param_list(val: &Val) -> Result<Vec<(String, String)>, HostCallError> {
    match val {
        Val::List(items) => {
            if items.len() > 256 {
                return Err(HostCallError::HandlerError(
                    "cap-param list exceeds 256 entries".to_string(),
                ));
            }
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let fields = match item {
                    Val::Record(f) => f,
                    _ => {
                        return Err(HostCallError::HandlerError(
                            "expected record for cap-param".to_string(),
                        ))
                    }
                };
                let mut key: Option<String> = None;
                let mut value: Option<String> = None;
                for (name, v) in fields {
                    match (name.as_str(), v) {
                        ("key", Val::String(s)) => key = Some(s.clone()),
                        ("key", _) => {
                            return Err(HostCallError::HandlerError(
                                "cap-param 'key' must be a string".to_string(),
                            ))
                        }
                        ("value", Val::String(s)) => value = Some(s.clone()),
                        ("value", _) => {
                            return Err(HostCallError::HandlerError(
                                "cap-param 'value' must be a string".to_string(),
                            ))
                        }
                        _ => {}
                    }
                }
                let key = key.ok_or_else(|| {
                    HostCallError::HandlerError("cap-param missing 'key'".to_string())
                })?;
                let value = value.ok_or_else(|| {
                    HostCallError::HandlerError("cap-param missing 'value'".to_string())
                })?;
                if key.len() > MAX_MCP_STRING_PARAM_BYTES {
                    return Err(HostCallError::HandlerError(format!(
                        "cap-param key exceeds {MAX_MCP_STRING_PARAM_BYTES} bytes"
                    )));
                }
                if value.len() > MAX_MCP_STRING_PARAM_BYTES {
                    return Err(HostCallError::HandlerError(format!(
                        "cap-param value exceeds {MAX_MCP_STRING_PARAM_BYTES} bytes"
                    )));
                }
                out.push((key, value));
            }
            Ok(out)
        }
        _ => Err(HostCallError::HandlerError(
            "expected list<cap-param>".to_string(),
        )),
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Val encode helpers
// ─────────────────────────────────────────────────────────────────────────

fn encode_mcp_error(err: &McpError) -> Val {
    Val::Variant(
        err.kind.as_kebab().to_string(),
        Some(Box::new(Val::String(err.message.clone()))),
    )
}

fn encode_byte_list(bytes: &[u8]) -> Val {
    Val::List(bytes.iter().map(|b| Val::U8(*b)).collect())
}

fn encode_result_bytes(r: Result<Vec<u8>, McpError>) -> Val {
    match r {
        Ok(bytes) => Val::Result(Ok(Some(Box::new(encode_byte_list(&bytes))))),
        Err(e) => Val::Result(Err(Some(Box::new(encode_mcp_error(&e))))),
    }
}

fn encode_server_info(info: &McpServerInfo) -> Val {
    Val::Record(vec![
        ("id".to_string(), Val::String(info.id.clone())),
        (
            "description".to_string(),
            Val::String(info.description.clone()),
        ),
    ])
}

fn encode_tool_info(info: &McpToolInfo) -> Val {
    Val::Record(vec![
        ("name".to_string(), Val::String(info.name.clone())),
        (
            "description".to_string(),
            Val::String(info.description.clone()),
        ),
        ("server-id".to_string(), Val::String(info.server_id.clone())),
    ])
}

fn encode_prompt_info(info: &McpPromptInfo) -> Val {
    Val::Record(vec![
        ("name".to_string(), Val::String(info.name.clone())),
        (
            "description".to_string(),
            Val::String(info.description.clone()),
        ),
        ("server-id".to_string(), Val::String(info.server_id.clone())),
    ])
}

fn encode_resource_info(info: &McpResourceInfo) -> Val {
    Val::Record(vec![
        ("uri".to_string(), Val::String(info.uri.clone())),
        (
            "description".to_string(),
            Val::String(info.description.clone()),
        ),
        ("server-id".to_string(), Val::String(info.server_id.clone())),
    ])
}

fn encode_result_server_list(r: Result<Vec<McpServerInfo>, McpError>) -> Val {
    match r {
        Ok(items) => {
            let list = items.iter().map(encode_server_info).collect();
            Val::Result(Ok(Some(Box::new(Val::List(list)))))
        }
        Err(e) => Val::Result(Err(Some(Box::new(encode_mcp_error(&e))))),
    }
}

fn encode_result_tool_list(r: Result<Vec<McpToolInfo>, McpError>) -> Val {
    match r {
        Ok(items) => {
            let list = items.iter().map(encode_tool_info).collect();
            Val::Result(Ok(Some(Box::new(Val::List(list)))))
        }
        Err(e) => Val::Result(Err(Some(Box::new(encode_mcp_error(&e))))),
    }
}

fn encode_result_prompt_list(r: Result<Vec<McpPromptInfo>, McpError>) -> Val {
    match r {
        Ok(items) => {
            let list = items.iter().map(encode_prompt_info).collect();
            Val::Result(Ok(Some(Box::new(Val::List(list)))))
        }
        Err(e) => Val::Result(Err(Some(Box::new(encode_mcp_error(&e))))),
    }
}

fn encode_result_resource_list(r: Result<Vec<McpResourceInfo>, McpError>) -> Val {
    match r {
        Ok(items) => {
            let list = items.iter().map(encode_resource_info).collect();
            Val::Result(Ok(Some(Box::new(Val::List(list)))))
        }
        Err(e) => Val::Result(Err(Some(Box::new(encode_mcp_error(&e))))),
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────

/// Register all 7 mcp-client handlers under the SPLIT capability dimensions.
///
/// Family ids `web.search` / `web.extract` fail-closed (omit / permission-denied)
/// because no [`GrantCheck`] is bound. Use
/// [`register_mcp_client_with_web_grant`] for the realization-independent
/// MODULE-013 `"web"` gate.
pub fn register_mcp_client(registry: &dyn HostRegistry, client: Arc<McpClient>) {
    register_mcp_client_inner(registry, client, None);
}

/// Same as [`register_mcp_client`], with a bound `"web"` family grant checker.
pub fn register_mcp_client_with_web_grant(
    registry: &dyn HostRegistry,
    client: Arc<McpClient>,
    web_grant: Arc<dyn GrantCheck>,
) {
    register_mcp_client_inner(registry, client, Some(web_grant));
}

fn register_mcp_client_inner(
    registry: &dyn HostRegistry,
    client: Arc<McpClient>,
    web_grant: Option<Arc<dyn GrantCheck>>,
) {
    let entries: Vec<(&'static str, &'static str, Arc<dyn HostFunctionHandler>)> = vec![
        // server-level reads → mcp.servers
        (
            "list-mcp-servers",
            CAPABILITY_SERVERS,
            Arc::new(ListMcpServersHandler {
                client: client.clone(),
            }),
        ),
        (
            "list-mcp-prompts",
            CAPABILITY_SERVERS,
            Arc::new(ListMcpPromptsHandler {
                client: client.clone(),
            }),
        ),
        (
            "get-mcp-prompt",
            CAPABILITY_SERVERS,
            Arc::new(GetMcpPromptHandler {
                client: client.clone(),
            }),
        ),
        (
            "list-mcp-resources",
            CAPABILITY_SERVERS,
            Arc::new(ListMcpResourcesHandler {
                client: client.clone(),
            }),
        ),
        (
            "read-mcp-resource",
            CAPABILITY_SERVERS,
            Arc::new(ReadMcpResourceHandler {
                client: client.clone(),
            }),
        ),
        // tool-level operations → mcp.tool-patterns
        (
            "list-mcp-tools",
            CAPABILITY_TOOL_PATTERNS,
            Arc::new(ListMcpToolsHandler {
                client: client.clone(),
                web_grant: web_grant.clone(),
            }),
        ),
        (
            "invoke-mcp-tool",
            CAPABILITY_TOOL_PATTERNS,
            Arc::new(InvokeMcpToolHandler {
                client: client.clone(),
                web_grant: web_grant.clone(),
            }),
        ),
    ];

    for (name, capability, handler) in entries {
        let idempotent =
            name.starts_with("list-") || name.starts_with("get-") || name.starts_with("read-");
        registry.register(HostFunctionSpec {
            capability: capability.to_string(),
            namespace: NAMESPACE.to_string(),
            name: name.to_string(),
            handler,
            idempotent,
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Handlers
// ─────────────────────────────────────────────────────────────────────────

pub struct ListMcpServersHandler {
    pub client: Arc<McpClient>,
}
impl HostFunctionHandler for ListMcpServersHandler {
    fn call(
        &self,
        _ctx: HostCallContext,
        _params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let client = Arc::clone(&self.client);
        Box::pin(async move {
            let r: Result<Vec<McpServerInfo>, McpError> = Ok(client.list_servers().await);
            Ok(vec![encode_result_server_list(r)])
        })
    }
}

pub struct ListMcpToolsHandler {
    pub client: Arc<McpClient>,
    pub web_grant: Option<Arc<dyn GrantCheck>>,
}
impl HostFunctionHandler for ListMcpToolsHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let client = Arc::clone(&self.client);
        let web_grant = self.web_grant.clone();
        let agent_id = ctx.agent_id.clone();
        Box::pin(async move {
            if params.len() < 1 {
                return Err(HostCallError::HandlerError(
                    "list-mcp-tools: expected 1 param".to_string(),
                ));
            }
            let server_id = decode_string(&params[0])?.to_string();
            let allow_web = web_family_allowed(web_grant.as_deref(), &agent_id, "list-mcp-tools");
            let r = client.list_tools(&server_id).await.map(|infos| {
                infos
                    .into_iter()
                    .filter(|info| !is_web_tool_id(&info.name) || allow_web)
                    .collect::<Vec<_>>()
            });
            Ok(vec![encode_result_tool_list(r)])
        })
    }
}

pub struct ListMcpPromptsHandler {
    pub client: Arc<McpClient>,
}
impl HostFunctionHandler for ListMcpPromptsHandler {
    fn call(
        &self,
        _ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let client = Arc::clone(&self.client);
        Box::pin(async move {
            if params.len() < 1 {
                return Err(HostCallError::HandlerError(
                    "list-mcp-prompts: expected 1 param".to_string(),
                ));
            }
            let server_id = decode_string(&params[0])?.to_string();
            let r = client.list_prompts(&server_id).await;
            Ok(vec![encode_result_prompt_list(r)])
        })
    }
}

pub struct GetMcpPromptHandler {
    pub client: Arc<McpClient>,
}
impl HostFunctionHandler for GetMcpPromptHandler {
    fn call(
        &self,
        _ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let client = Arc::clone(&self.client);
        Box::pin(async move {
            if params.len() < 3 {
                return Err(HostCallError::HandlerError(
                    "get-mcp-prompt: expected 3 params".to_string(),
                ));
            }
            let server_id = decode_string(&params[0])?.to_string();
            let prompt_name = decode_string(&params[1])?.to_string();
            let args = decode_cap_param_list(&params[2])?;
            let r = client.get_prompt(&server_id, &prompt_name, args).await;
            Ok(vec![encode_result_bytes(r)])
        })
    }
}

pub struct ListMcpResourcesHandler {
    pub client: Arc<McpClient>,
}
impl HostFunctionHandler for ListMcpResourcesHandler {
    fn call(
        &self,
        _ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let client = Arc::clone(&self.client);
        Box::pin(async move {
            if params.len() < 1 {
                return Err(HostCallError::HandlerError(
                    "list-mcp-resources: expected 1 param".to_string(),
                ));
            }
            let server_id = decode_string(&params[0])?.to_string();
            let r = client.list_resources(&server_id).await;
            Ok(vec![encode_result_resource_list(r)])
        })
    }
}

pub struct ReadMcpResourceHandler {
    pub client: Arc<McpClient>,
}
impl HostFunctionHandler for ReadMcpResourceHandler {
    fn call(
        &self,
        _ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let client = Arc::clone(&self.client);
        Box::pin(async move {
            if params.len() < 2 {
                return Err(HostCallError::HandlerError(
                    "read-mcp-resource: expected 2 params".to_string(),
                ));
            }
            let server_id = decode_string(&params[0])?.to_string();
            let uri = decode_string(&params[1])?.to_string();
            let r = client.read_resource(&server_id, &uri).await;
            Ok(vec![encode_result_bytes(r)])
        })
    }
}

pub struct InvokeMcpToolHandler {
    pub client: Arc<McpClient>,
    pub web_grant: Option<Arc<dyn GrantCheck>>,
}
impl HostFunctionHandler for InvokeMcpToolHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let client = Arc::clone(&self.client);
        let web_grant = self.web_grant.clone();
        let agent_id = ctx.agent_id.clone();
        Box::pin(async move {
            if params.len() < 3 {
                return Err(HostCallError::HandlerError(
                    "invoke-mcp-tool: expected 3 params".to_string(),
                ));
            }
            let server_id = decode_string(&params[0])?.to_string();
            let tool_name = decode_string(&params[1])?.to_string();
            let params_bytes = decode_byte_list(&params[2])?;
            if is_web_tool_id(&tool_name) {
                match web_family_decision(web_grant.as_deref(), &agent_id, "invoke-mcp-tool") {
                    GrantDecision::Deny(reason) => {
                        return Ok(vec![encode_result_bytes(Err(McpError::permission_denied(
                            reason,
                        )))]);
                    }
                    GrantDecision::Allow => {}
                }
            }
            let r = client
                .invoke_tool(&server_id, &tool_name, &params_bytes)
                .await;
            Ok(vec![encode_result_bytes(r)])
        })
    }
}

fn web_family_decision(
    grant: Option<&dyn GrantCheck>,
    agent_id: &str,
    function: &str,
) -> GrantDecision {
    match grant {
        None => GrantDecision::Deny("web grant checker unbound".into()),
        Some(g) => g.check(
            agent_id,
            WEB_GRANT_CAPABILITY,
            function,
            &CapParams::empty(),
        ),
    }
}

fn web_family_allowed(grant: Option<&dyn GrantCheck>, agent_id: &str, function: &str) -> bool {
    matches!(
        web_family_decision(grant, agent_id, function),
        GrantDecision::Allow
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_mcp_error_round_trip() {
        let err = McpError::not_found("server x not in whitelist");
        let v = encode_mcp_error(&err);
        match v {
            Val::Variant(case, Some(payload)) => {
                assert_eq!(case, "not-found");
                match *payload {
                    Val::String(s) => assert!(s.contains("not in whitelist")),
                    _ => panic!("expected string payload"),
                }
            }
            _ => panic!("expected variant"),
        }
    }

    #[test]
    fn encode_mcp_error_all_kinds_kebab() {
        for k in [
            McpErrorKind::NotFound,
            McpErrorKind::ToolNotFound,
            McpErrorKind::TransportError,
            McpErrorKind::PermissionDenied,
            McpErrorKind::InvalidResponse,
            McpErrorKind::ServerError,
        ] {
            let v = encode_mcp_error(&McpError::new(k.clone(), "x"));
            if let Val::Variant(case, _) = v {
                assert_eq!(case, k.as_kebab());
            } else {
                panic!("not variant");
            }
        }
    }
}

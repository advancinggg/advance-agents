//! `mcp-client` WIT host functions.
//!
//! [`register_mcp_client`] registers the seven `mcp-client` functions under the
//! one capability `mcp` ([`MCP_CAPABILITY`]), in the namespace
//! `advance:runtime/mcp-client@0.1.0`. The injector lets an agent call them
//! only while it holds an `mcp` grant. Each handler then asks the [`McpGate`]
//! about the server and tool the call names, before any request reaches a
//! server, and answers a refusal with the `permission-denied` arm:
//!
//! - `invoke-mcp-tool` needs a grant covering the tool on the server;
//!   `get-mcp-prompt` and `read-mcp-resource` need a grant reaching the server
//!   with an unrestricted tool axis. These are decided by the grant check.
//! - `list-mcp-servers` lists the servers a grant reaches; `list-mcp-tools`
//!   needs a grant reaching the server and lists the tools a grant covers;
//!   `list-mcp-prompts` and `list-mcp-resources` need what `get-mcp-prompt`
//!   needs. These read the grants through silent readers and write no
//!   `authz.checked` event.
//! - The web family tools (`web.search`, `web.extract`) also need the `web`
//!   grant: `invoke-mcp-tool` asks its check, `list-mcp-tools` its silent
//!   reader. They are hidden and refused on a stdio server.
//!
//! ## Caller
//!
//! Each handler that reaches a server makes its request for the calling agent
//! (`HostCallContext::agent_id`): an http server's traffic is attributed to
//! that agent in the security chain (rate limits, `http.*` events), not to the
//! server.
//!
//! ## Events
//!
//! `invoke-mcp-tool` emits `mcp.tool_invoked` when it returns a result and
//! `mcp.tool_error` when it fails, refusals included. A tool that fails while
//! running answers with a result marked `isError: true`: the guest receives
//! that result, and the event is `mcp.tool_error` with the `error_type`
//! `tool-error`. `get-mcp-prompt` emits `mcp.prompt_fetched`, and
//! `read-mcp-resource` `mcp.resource_read` (with the URI reduced to its scheme
//! and host), when they return one. The listings emit no `mcp.*` event.
//!
//! ## Idempotent flag
//!
//! Read-shaped methods (`list-*`, `get-*`, `read-*`) carry `idempotent: true`
//! per WIT semantics. Only `invoke-mcp-tool` has side-effects on the remote
//! MCP server, so it stays non-idempotent.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use advance_runtime::host_registry::{
    HostCallContext, HostCallError, HostFunctionHandler, HostFunctionSpec, HostRegistry,
};
use advance_shared_types::traits::EventBusEmit;
use advance_shared_types::web_search::is_web_tool_id;
use wasmtime::component::Val;

use crate::client::{McpClient, McpPromptInfo, McpResourceInfo, McpServerInfo, McpToolInfo};
use crate::error::McpError;
use crate::events;
use crate::gate::{server_denied, server_wide_denied, McpGate, MCP_CAPABILITY};

#[cfg(test)]
use crate::error::McpErrorKind;

const NAMESPACE: &str = "advance:runtime/mcp-client@0.1.0";

/// `"{namespace}::{name}"`: how the grant check's event names a host function.
fn function_id(name: &str) -> String {
    format!("{NAMESPACE}::{name}")
}

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

/// Register the seven mcp-client host functions under the capability `mcp`
/// ([`MCP_CAPABILITY`]). Each handler decides its calls with `gate` (see the
/// module docs), reaches servers through `client`, and emits its `mcp.*`
/// events on `emitter`.
pub fn register_mcp_client(
    registry: &dyn HostRegistry,
    client: Arc<McpClient>,
    gate: McpGate,
    emitter: Arc<dyn EventBusEmit>,
) {
    let entries: Vec<(&'static str, Arc<dyn HostFunctionHandler>)> = vec![
        (
            "list-mcp-servers",
            Arc::new(ListMcpServersHandler {
                client: client.clone(),
                gate: gate.clone(),
            }),
        ),
        (
            "list-mcp-tools",
            Arc::new(ListMcpToolsHandler {
                client: client.clone(),
                gate: gate.clone(),
            }),
        ),
        (
            "list-mcp-prompts",
            Arc::new(ListMcpPromptsHandler {
                client: client.clone(),
                gate: gate.clone(),
            }),
        ),
        (
            "get-mcp-prompt",
            Arc::new(GetMcpPromptHandler {
                client: client.clone(),
                gate: gate.clone(),
                emitter: emitter.clone(),
            }),
        ),
        (
            "list-mcp-resources",
            Arc::new(ListMcpResourcesHandler {
                client: client.clone(),
                gate: gate.clone(),
            }),
        ),
        (
            "read-mcp-resource",
            Arc::new(ReadMcpResourceHandler {
                client: client.clone(),
                gate: gate.clone(),
                emitter: emitter.clone(),
            }),
        ),
        (
            "invoke-mcp-tool",
            Arc::new(InvokeMcpToolHandler {
                client,
                gate,
                emitter,
            }),
        ),
    ];

    for (name, handler) in entries {
        let idempotent =
            name.starts_with("list-") || name.starts_with("get-") || name.starts_with("read-");
        registry.register(HostFunctionSpec {
            capability: MCP_CAPABILITY.to_string(),
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

/// `list-mcp-servers`: the configured servers one of the caller's `mcp` grants
/// reaches.
pub struct ListMcpServersHandler {
    pub client: Arc<McpClient>,
    pub gate: McpGate,
}
impl HostFunctionHandler for ListMcpServersHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        _params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let client = Arc::clone(&self.client);
        let gate = self.gate.clone();
        Box::pin(async move {
            let scopes = gate.scopes(&ctx.agent_id);
            let mut servers = client.list_servers().await;
            servers.retain(|server| scopes.reaches_server(&server.id));
            Ok(vec![encode_result_server_list(Ok(servers))])
        })
    }
}

/// `list-mcp-tools(server-id)`: the server's tools one of the caller's `mcp`
/// grants covers, less the web family tools it may not use.
pub struct ListMcpToolsHandler {
    pub client: Arc<McpClient>,
    pub gate: McpGate,
}
impl HostFunctionHandler for ListMcpToolsHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let client = Arc::clone(&self.client);
        let gate = self.gate.clone();
        Box::pin(async move {
            if params.is_empty() {
                return Err(HostCallError::HandlerError(
                    "list-mcp-tools: expected 1 param".to_string(),
                ));
            }
            let server_id = decode_string(&params[0])?.to_string();
            let agent_id = ctx.agent_id.as_str();
            let scopes = gate.scopes(agent_id);
            if !scopes.reaches_server(&server_id) {
                return Ok(vec![encode_result_tool_list(Err(server_denied(
                    &server_id,
                )))]);
            }
            let refuses_web = client.refuses_web_tools(&server_id);
            let r = client
                .list_tools(Some(agent_id), &server_id)
                .await
                .map(|tools| gate.visible_tools(agent_id, &scopes, refuses_web, tools));
            Ok(vec![encode_result_tool_list(r)])
        })
    }
}

/// `list-mcp-prompts(server-id)`: the server's prompts, for a caller whose
/// `mcp` grant reaches the server with an unrestricted tool axis.
pub struct ListMcpPromptsHandler {
    pub client: Arc<McpClient>,
    pub gate: McpGate,
}
impl HostFunctionHandler for ListMcpPromptsHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let client = Arc::clone(&self.client);
        let gate = self.gate.clone();
        Box::pin(async move {
            if params.is_empty() {
                return Err(HostCallError::HandlerError(
                    "list-mcp-prompts: expected 1 param".to_string(),
                ));
            }
            let server_id = decode_string(&params[0])?.to_string();
            if !gate.scopes(&ctx.agent_id).reaches_server_wide(&server_id) {
                return Ok(vec![encode_result_prompt_list(Err(server_wide_denied(
                    &server_id, None,
                )))]);
            }
            let r = client.list_prompts(Some(&ctx.agent_id), &server_id).await;
            Ok(vec![encode_result_prompt_list(r)])
        })
    }
}

/// `get-mcp-prompt(server-id, prompt-name, args)`: one prompt, for a caller
/// whose `mcp` grant reaches the server with an unrestricted tool axis.
pub struct GetMcpPromptHandler {
    pub client: Arc<McpClient>,
    pub gate: McpGate,
    pub emitter: Arc<dyn EventBusEmit>,
}
impl HostFunctionHandler for GetMcpPromptHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let client = Arc::clone(&self.client);
        let gate = self.gate.clone();
        let emitter = Arc::clone(&self.emitter);
        Box::pin(async move {
            if params.len() < 3 {
                return Err(HostCallError::HandlerError(
                    "get-mcp-prompt: expected 3 params".to_string(),
                ));
            }
            let server_id = decode_string(&params[0])?.to_string();
            let prompt_name = decode_string(&params[1])?.to_string();
            let args = decode_cap_param_list(&params[2])?;
            let agent_id = ctx.agent_id.as_str();
            if let Err(denied) =
                gate.check_server_wide(agent_id, &function_id("get-mcp-prompt"), &server_id)
            {
                return Ok(vec![encode_result_bytes(Err(denied))]);
            }
            let started = Instant::now();
            let r = client
                .get_prompt(Some(agent_id), &server_id, &prompt_name, args)
                .await;
            if r.is_ok() {
                emitter.emit(events::prompt_fetched(
                    &ctx,
                    &server_id,
                    &prompt_name,
                    elapsed_ms(started),
                ));
            }
            Ok(vec![encode_result_bytes(r)])
        })
    }
}

/// `list-mcp-resources(server-id)`: the server's resources, for a caller whose
/// `mcp` grant reaches the server with an unrestricted tool axis.
pub struct ListMcpResourcesHandler {
    pub client: Arc<McpClient>,
    pub gate: McpGate,
}
impl HostFunctionHandler for ListMcpResourcesHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let client = Arc::clone(&self.client);
        let gate = self.gate.clone();
        Box::pin(async move {
            if params.is_empty() {
                return Err(HostCallError::HandlerError(
                    "list-mcp-resources: expected 1 param".to_string(),
                ));
            }
            let server_id = decode_string(&params[0])?.to_string();
            if !gate.scopes(&ctx.agent_id).reaches_server_wide(&server_id) {
                return Ok(vec![encode_result_resource_list(Err(server_wide_denied(
                    &server_id, None,
                )))]);
            }
            let r = client.list_resources(Some(&ctx.agent_id), &server_id).await;
            Ok(vec![encode_result_resource_list(r)])
        })
    }
}

/// `read-mcp-resource(server-id, uri)`: one resource, for a caller whose `mcp`
/// grant reaches the server with an unrestricted tool axis.
pub struct ReadMcpResourceHandler {
    pub client: Arc<McpClient>,
    pub gate: McpGate,
    pub emitter: Arc<dyn EventBusEmit>,
}
impl HostFunctionHandler for ReadMcpResourceHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let client = Arc::clone(&self.client);
        let gate = self.gate.clone();
        let emitter = Arc::clone(&self.emitter);
        Box::pin(async move {
            if params.len() < 2 {
                return Err(HostCallError::HandlerError(
                    "read-mcp-resource: expected 2 params".to_string(),
                ));
            }
            let server_id = decode_string(&params[0])?.to_string();
            let uri = decode_string(&params[1])?.to_string();
            let agent_id = ctx.agent_id.as_str();
            if let Err(denied) =
                gate.check_server_wide(agent_id, &function_id("read-mcp-resource"), &server_id)
            {
                return Ok(vec![encode_result_bytes(Err(denied))]);
            }
            let started = Instant::now();
            let r = client.read_resource(Some(agent_id), &server_id, &uri).await;
            if let Ok(bytes) = &r {
                emitter.emit(events::resource_read(
                    &ctx,
                    &server_id,
                    &uri,
                    bytes.len(),
                    elapsed_ms(started),
                ));
            }
            Ok(vec![encode_result_bytes(r)])
        })
    }
}

/// `invoke-mcp-tool(server-id, tool-name, params)`: one tool call, for a caller
/// whose `mcp` grant covers the tool on the server.
pub struct InvokeMcpToolHandler {
    pub client: Arc<McpClient>,
    pub gate: McpGate,
    pub emitter: Arc<dyn EventBusEmit>,
}
impl HostFunctionHandler for InvokeMcpToolHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let client = Arc::clone(&self.client);
        let gate = self.gate.clone();
        let emitter = Arc::clone(&self.emitter);
        Box::pin(async move {
            if params.len() < 3 {
                return Err(HostCallError::HandlerError(
                    "invoke-mcp-tool: expected 3 params".to_string(),
                ));
            }
            let server_id = decode_string(&params[0])?.to_string();
            let tool_name = decode_string(&params[1])?.to_string();
            let params_bytes = decode_byte_list(&params[2])?;
            let agent_id = ctx.agent_id.as_str();
            let authorized = authorize_tool_call(&gate, &client, agent_id, &server_id, &tool_name);
            let started = Instant::now();
            let r = match authorized {
                Ok(()) => {
                    client
                        .invoke_tool(Some(agent_id), &server_id, &tool_name, &params_bytes)
                        .await
                }
                Err(denied) => Err(denied),
            };
            match &r {
                Ok(result) if reports_tool_failure(result) => emitter.emit(events::tool_error(
                    &ctx,
                    &server_id,
                    &tool_name,
                    events::TOOL_FAILED,
                )),
                Ok(_) => emitter.emit(events::tool_invoked(
                    &ctx,
                    &server_id,
                    &tool_name,
                    elapsed_ms(started),
                )),
                Err(e) => emitter.emit(events::tool_error(
                    &ctx,
                    &server_id,
                    &tool_name,
                    e.kind.as_kebab(),
                )),
            }
            Ok(vec![encode_result_bytes(r)])
        })
    }
}

/// Whether `agent` may call `tool` on `server`: one of its `mcp` grants must
/// cover the call, and a web family tool also needs a server that does not
/// refuse them and the agent's `web` grant.
fn authorize_tool_call(
    gate: &McpGate,
    client: &McpClient,
    agent: &str,
    server: &str,
    tool: &str,
) -> Result<(), McpError> {
    gate.check_tool(agent, &function_id("invoke-mcp-tool"), server, tool)?;
    if is_web_tool_id(tool) {
        if client.refuses_web_tools(server) {
            return Err(McpError::permission_denied(format!(
                "web family tools are refused from stdio server {server:?}"
            )));
        }
        gate.check_web(agent, "invoke-mcp-tool")?;
    }
    Ok(())
}

/// Whether a `tools/call` result reports that the tool failed: MCP answers a
/// tool that fails while running with a result whose top-level `isError` is
/// `true`, not with a JSON-RPC error. Any other result, malformed ones
/// included, reports no failure.
fn reports_tool_failure(result: &[u8]) -> bool {
    #[derive(serde::Deserialize)]
    struct ToolCallResult {
        #[serde(rename = "isError", default)]
        is_error: Option<bool>,
    }
    // Only an object: a struct would also accept a JSON array.
    let is_object = result.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{');
    is_object
        && serde_json::from_slice::<ToolCallResult>(result)
            .is_ok_and(|parsed| parsed.is_error == Some(true))
}

/// Milliseconds since `started`.
fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_mcp_error_round_trip() {
        let err = McpError::not_found("server 'x' is not configured");
        let v = encode_mcp_error(&err);
        match v {
            Val::Variant(case, Some(payload)) => {
                assert_eq!(case, "not-found");
                match *payload {
                    Val::String(s) => assert!(s.contains("is not configured")),
                    _ => panic!("expected string payload"),
                }
            }
            _ => panic!("expected variant"),
        }
    }

    #[test]
    fn only_a_top_level_is_error_true_reports_a_tool_failure() {
        let failed: &[&[u8]] = &[
            br#"{"content":[{"type":"text","text":"rate limited"}],"isError":true}"#,
            br#"  {"isError": true}"#,
        ];
        for result in failed {
            assert!(
                reports_tool_failure(result),
                "{}",
                String::from_utf8_lossy(result)
            );
        }
        let succeeded: &[&[u8]] = &[
            br#"{"content":[]}"#,
            br#"{"content":[],"isError":false}"#,
            br#"{"isError":"true"}"#,
            br#"{"isError":1}"#,
            br#"{"isError":null}"#,
            br#"{"content":[{"type":"text","text":"{\"isError\":true}"}],"meta":{"isError":true}}"#,
            br#"[true]"#,
            br#"true"#,
            b"",
            b"not json",
        ];
        for result in succeeded {
            assert!(
                !reports_tool_failure(result),
                "{}",
                String::from_utf8_lossy(result)
            );
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

//! `McpClient` — high-level MCP dispatch surface (MODULE-017 AC-15).
//!
//! Aggregates the per-server connections + tool-pattern filter + per-tool
//! schemas; exposes the 7 method surfaces consumed by `host_fn.rs`:
//!
//! - `list_servers` / `list_tools` / `list_prompts` / `list_resources` — server &
//!   tool inventory.
//! - `get_prompt` / `read_resource` — read-shaped retrieval.
//! - `invoke_tool` — schema-validated tool call with tool-pattern gate.
//!
//! All dispatch routes through an `Arc<dyn McpTransport>` per server, so HTTP
//! and stdio transports are uniform behind the same call site.
//!
//! ## Connections
//!
//! Each server has a slot holding its live transport. The first call to a
//! server connects it: a stdio server is spawned and initialized (`initialize`
//! carrying [`MCP_PROTOCOL_VERSION`], a check that the server chose a version in
//! [`SUPPORTED_PROTOCOL_VERSIONS`], then `notifications/initialized`) within
//! [`McpClientLimits::startup_timeout`]; an http server's transport is built.
//! Concurrent first calls share one connection attempt, and no std lock is held
//! while it runs.
//!
//! A slot belongs to one generation. [`McpClient::disconnect`] retires it: a
//! connection attempt that completes for a retired slot publishes nothing, and
//! its process is stopped.
//!
//! A transport that reports itself closed (its process exited, a line
//! overflowed) is evicted, and a later call reconnects the server. A server
//! whose connection attempt fails, or whose transport dies before it has run
//! for [`McpClientLimits::restart_backoff_max`], is not reconnected for
//! [`McpClientLimits::restart_backoff_initial`], doubling with each further
//! failure up to the maximum; calls in that window fail fast. A transport that
//! ran longer is replaced at once.
//!
//! Stdio transports are spawned on, and run their tasks on, the runtime given
//! to [`McpClient::with_runtime`] (by default the one current when the client
//! was built), never on the runtime of whichever call connects them. A client
//! built outside any runtime and given none refuses to start stdio servers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use advance_shared_types::security_validator::{HttpSecurityChain, LeakDetector};
use async_trait::async_trait;
use tokio::runtime::Handle;

use crate::error::McpError;
use crate::http_transport::HttpMcpTransport;
use crate::schema_validator::SchemaValidator;
use crate::stdio_transport::{
    sanitize_log_text, StdioMcpTransport, StdioOptions, MAX_STDIO_LINE_BYTES, MAX_STDIO_WALL_CLOCK,
};
use crate::whitelist::{McpServerEntry, McpServersConfig, McpTransportSpec};

/// MCP protocol version this client asks for in `initialize`.
pub const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

/// Protocol versions this client accepts as a server's `initialize` answer,
/// newest first. A server that chooses any other version is disconnected.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

/// Trait shared by HTTP and stdio transports. `McpClient` dispatches through
/// `Arc<dyn McpTransport>` so both transport classes can be cached behind the
/// same per-server handle.
#[async_trait]
pub trait McpTransport: Send + Sync {
    /// Send a JSON-RPC request and return its `result` as JSON bytes.
    async fn invoke(&self, method: &str, params: serde_json::Value) -> Result<Vec<u8>, McpError>;

    /// Send a JSON-RPC notification: a message without an id, which the server
    /// never answers.
    async fn notify(&self, method: &str, params: Option<serde_json::Value>)
        -> Result<(), McpError>;

    fn server_id(&self) -> &str;

    /// True once the transport can carry no further calls (its process exited,
    /// its stream overflowed). The client then evicts it and reconnects the
    /// server on a later call. Defaults to `false`.
    fn is_closed(&self) -> bool {
        false
    }
}

/// Bounds on one client's connections and calls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpClientLimits {
    /// Budget for one call on a stdio server: sending it and receiving the
    /// answer.
    pub request_timeout: Duration,
    /// Budget for connecting a stdio server: spawning it and completing the
    /// `initialize` exchange.
    pub startup_timeout: Duration,
    /// Largest result, in bytes, that a call returns; a larger one fails the
    /// call.
    pub max_result_bytes: usize,
    /// Longest stdout line, in bytes, a stdio server may write; a longer one
    /// closes its transport.
    pub max_line_bytes: usize,
    /// Wait before reconnecting a server after one failure; it doubles with
    /// each further consecutive failure.
    pub restart_backoff_initial: Duration,
    /// Longest wait before reconnecting. A transport that ran at least this
    /// long before dying counts as healthy: it is replaced at once.
    pub restart_backoff_max: Duration,
}

impl Default for McpClientLimits {
    fn default() -> Self {
        Self {
            request_timeout: MAX_STDIO_WALL_CLOCK,
            startup_timeout: Duration::from_secs(10),
            max_result_bytes: 4 * 1024 * 1024,
            max_line_bytes: MAX_STDIO_LINE_BYTES,
            restart_backoff_initial: Duration::from_secs(1),
            restart_backoff_max: Duration::from_secs(60),
        }
    }
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

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One server's connection state for one generation. [`McpClient::disconnect`]
/// replaces the slot; an attempt still holding a replaced slot publishes
/// nothing.
struct ServerSlot {
    /// Serializes connection attempts, so concurrent first calls start one
    /// server. An async lock: it is held across the attempt's awaits.
    connecting: tokio::sync::Mutex<()>,
    state: Mutex<SlotState>,
}

#[derive(Default)]
struct SlotState {
    live: Option<Live>,
    /// Consecutive failures: failed connection attempts and transports that
    /// died young.
    failures: u32,
    /// No connection attempt before this instant.
    retry_at: Option<Instant>,
}

struct Live {
    transport: Arc<dyn McpTransport>,
    since: Instant,
    /// Version agreed in `initialize`; `None` for a transport the client did
    /// not initialize.
    protocol_version: Option<String>,
}

impl ServerSlot {
    fn new() -> Self {
        Self {
            connecting: tokio::sync::Mutex::new(()),
            state: Mutex::new(SlotState::default()),
        }
    }

    fn state(&self) -> MutexGuard<'_, SlotState> {
        lock(&self.state)
    }

    /// The live transport; `None` when there is none, after evicting one that
    /// has closed.
    fn live_transport(&self, limits: &McpClientLimits) -> Option<Arc<dyn McpTransport>> {
        let mut state = self.state();
        let transport = Arc::clone(&state.live.as_ref()?.transport);
        if !transport.is_closed() {
            return Some(transport);
        }
        let evicted = state.evict(Instant::now(), limits);
        drop(state);
        // The evicted transport is dropped (its process stopped) outside the
        // lock.
        drop(evicted);
        None
    }

    /// How long a connection attempt must still wait.
    fn backoff_remaining(&self, now: Instant) -> Option<Duration> {
        self.state()
            .retry_at
            .map(|at| at.saturating_duration_since(now))
            .filter(|wait| !wait.is_zero())
    }
}

impl SlotState {
    /// Take the live transport out and arm the backoff for its death. A
    /// transport that ran at least `restart_backoff_max` resets the failure
    /// count and is replaced at once.
    fn evict(&mut self, now: Instant, limits: &McpClientLimits) -> Option<Live> {
        let live = self.live.take()?;
        if now.saturating_duration_since(live.since) >= limits.restart_backoff_max {
            self.failures = 0;
            self.retry_at = None;
        } else {
            self.fail(now, limits);
        }
        Some(live)
    }

    fn fail(&mut self, now: Instant, limits: &McpClientLimits) {
        self.failures = self.failures.saturating_add(1);
        self.retry_at = Some(now + backoff(self.failures, limits));
    }
}

/// Wait after `failures` consecutive failures: the initial wait, doubled for
/// each failure after the first, capped at the maximum.
fn backoff(failures: u32, limits: &McpClientLimits) -> Duration {
    let doublings = failures.saturating_sub(1).min(20);
    limits
        .restart_backoff_initial
        .saturating_mul(1u32 << doublings)
        .min(limits.restart_backoff_max)
}

/// High-level MCP client. Owns the `McpServersConfig` whitelist + the
/// per-server connection slots.
pub struct McpClient {
    config: Arc<McpServersConfig>,
    slots: Mutex<HashMap<String, Arc<ServerSlot>>>,
    leak_detector: Arc<dyn LeakDetector>,
    http_chain: Option<Arc<dyn HttpSecurityChain>>,
    limits: McpClientLimits,
    runtime: Option<Handle>,
}

impl McpClient {
    /// Construct a new client with the default [`McpClientLimits`].
    ///
    /// `leak_detector` is plumbed into stdio transports for request and
    /// response scanning. `http_chain` is required for HTTP transports — passed
    /// as Option so test fixtures with no HTTP servers can omit it. Stdio
    /// transports run on the runtime current at construction; a client built
    /// outside any runtime needs [`with_runtime`](Self::with_runtime) before it
    /// can start stdio servers.
    pub fn new(
        config: Arc<McpServersConfig>,
        leak_detector: Arc<dyn LeakDetector>,
        http_chain: Option<Arc<dyn HttpSecurityChain>>,
    ) -> Self {
        Self {
            config,
            slots: Mutex::new(HashMap::new()),
            leak_detector,
            http_chain,
            limits: McpClientLimits::default(),
            runtime: Handle::try_current().ok(),
        }
    }

    /// Replace the limits.
    pub fn with_limits(mut self, limits: McpClientLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Spawn stdio servers on `runtime` and run their transports' tasks there,
    /// whatever runtime the connecting call runs on. Pass the daemon's runtime:
    /// a transport outlives the call that connects it.
    pub fn with_runtime(mut self, runtime: Handle) -> Self {
        self.runtime = Some(runtime);
        self
    }

    /// Construct a test-only client where transports are pre-injected as live,
    /// already-initialized connections. Used by `tests/support/mock_transport.rs`
    /// and `tests/client_surface.rs`.
    #[doc(hidden)]
    pub fn new_with_transports(
        config: Arc<McpServersConfig>,
        leak_detector: Arc<dyn LeakDetector>,
        injected: HashMap<String, Arc<dyn McpTransport>>,
    ) -> Self {
        let since = Instant::now();
        let slots = injected
            .into_iter()
            .map(|(server_id, transport)| {
                let slot = ServerSlot::new();
                slot.state().live = Some(Live {
                    transport,
                    since,
                    protocol_version: None,
                });
                (server_id, Arc::new(slot))
            })
            .collect();
        Self {
            config,
            slots: Mutex::new(slots),
            leak_detector,
            http_chain: None,
            limits: McpClientLimits::default(),
            runtime: Handle::try_current().ok(),
        }
    }

    /// The protocol version agreed with the server when the client initialized
    /// its live connection; `None` when it has no live connection or the client
    /// did not initialize it.
    pub fn protocol_version(&self, server_id: &str) -> Option<String> {
        let slot = self.slots().get(server_id).cloned()?;
        let state = slot.state();
        state.live.as_ref()?.protocol_version.clone()
    }

    /// Drop the server's connection. Calls still running on it finish, and its
    /// process stops once they have; a connection attempt in flight publishes
    /// nothing. The next call connects afresh, with no backoff carried over.
    pub fn disconnect(&self, server_id: &str) {
        let Some(slot) = self.slots().remove(server_id) else {
            return;
        };
        let live = slot.state().live.take();
        drop(live);
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
        let bytes = self
            .call(
                entry,
                "tools/list",
                serde_json::Value::Object(Default::default()),
            )
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
        let bytes = self
            .call(
                entry,
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
        let args_obj: serde_json::Map<String, serde_json::Value> = args
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        let params = serde_json::json!({"name": prompt_name, "arguments": args_obj});
        self.call(entry, "prompts/get", params).await
    }

    pub async fn list_resources(&self, server_id: &str) -> Result<Vec<McpResourceInfo>, McpError> {
        let entry = self.config.get(server_id)?;
        let bytes = self
            .call(
                entry,
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
        let params = serde_json::json!({"uri": uri});
        self.call(entry, "resources/read", params).await
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
        // Bytes cap at the client API boundary: the host_fn decoder already
        // enforces MAX_MCP_PARAMS_BYTES, but Rust-side callers of invoke_tool
        // skip that layer.
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

        let call_params = serde_json::json!({
            "name": tool_name,
            "arguments": params_json,
        });
        let bytes = self.call(entry, "tools/call", call_params).await?;

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

    /// Send one request to the server. A failed call that found the transport
    /// closed evicts it; a result over `max_result_bytes` fails the call.
    async fn call(
        &self,
        entry: &McpServerEntry,
        method: &str,
        params: serde_json::Value,
    ) -> Result<Vec<u8>, McpError> {
        let transport = self.transport_for(entry).await?;
        let result = transport.invoke(method, params).await;
        if result.is_err() {
            self.evict_if_closed(&entry.server_id, &transport);
        }
        let bytes = result?;
        if bytes.len() > self.limits.max_result_bytes {
            return Err(McpError::transport(format!(
                "result exceeds {} bytes",
                self.limits.max_result_bytes
            )));
        }
        Ok(bytes)
    }

    fn slots(&self) -> MutexGuard<'_, HashMap<String, Arc<ServerSlot>>> {
        lock(&self.slots)
    }

    /// The server's current slot, created on first use. Only whitelisted ids
    /// reach here, so the map is bounded by the config.
    fn slot(&self, server_id: &str) -> Arc<ServerSlot> {
        let mut slots = self.slots();
        Arc::clone(
            slots
                .entry(server_id.to_string())
                .or_insert_with(|| Arc::new(ServerSlot::new())),
        )
    }

    /// The server's live transport, connecting it if it has none (see the
    /// module docs: one attempt at a time per server, backoff after failures).
    async fn transport_for(
        &self,
        entry: &McpServerEntry,
    ) -> Result<Arc<dyn McpTransport>, McpError> {
        loop {
            let slot = self.slot(&entry.server_id);
            if let Some(transport) = slot.live_transport(&self.limits) {
                return Ok(transport);
            }
            let _attempt = slot.connecting.lock().await;
            // `disconnect` may have retired the slot while this caller waited
            // for the attempt lock: use the server's new slot instead.
            if !self.is_current(&entry.server_id, &slot) {
                continue;
            }
            // A concurrent caller may have connected the server meanwhile.
            if let Some(transport) = slot.live_transport(&self.limits) {
                return Ok(transport);
            }
            if let Some(wait) = slot.backoff_remaining(Instant::now()) {
                return Err(McpError::transport(format!(
                    "server '{}' is unavailable after a failure; retry in {} ms",
                    entry.server_id,
                    wait.as_millis().max(1)
                )));
            }
            return match self.connect(entry).await {
                Ok((transport, protocol_version)) => {
                    let live = Live {
                        transport: Arc::clone(&transport),
                        since: Instant::now(),
                        protocol_version,
                    };
                    if self.publish(&entry.server_id, &slot, live) {
                        Ok(transport)
                    } else {
                        Err(McpError::transport(format!(
                            "server '{}' was disconnected while connecting",
                            entry.server_id
                        )))
                    }
                }
                Err(error) => {
                    slot.state().fail(Instant::now(), &self.limits);
                    Err(error)
                }
            };
        }
    }

    /// Whether `slot` is still the server's current slot.
    fn is_current(&self, server_id: &str, slot: &Arc<ServerSlot>) -> bool {
        self.slots()
            .get(server_id)
            .is_some_and(|current| Arc::ptr_eq(current, slot))
    }

    /// Store `live` in `slot` if the slot is still the server's current one.
    /// Returns whether it was stored; otherwise `live` is dropped, which stops
    /// its process once no call holds it.
    fn publish(&self, server_id: &str, slot: &Arc<ServerSlot>, live: Live) -> bool {
        let slots = self.slots();
        let current = slots
            .get(server_id)
            .is_some_and(|current| Arc::ptr_eq(current, slot));
        if current {
            slot.state().live = Some(live);
        }
        drop(slots);
        current
    }

    /// Evict `transport` if it has closed and is still the server's live one.
    fn evict_if_closed(&self, server_id: &str, transport: &Arc<dyn McpTransport>) {
        if !transport.is_closed() {
            return;
        }
        let Some(slot) = self.slots().get(server_id).cloned() else {
            return;
        };
        let evicted = {
            let mut state = slot.state();
            let is_live = state.live.as_ref().is_some_and(|live| {
                std::ptr::addr_eq(Arc::as_ptr(&live.transport), Arc::as_ptr(transport))
            });
            if is_live {
                state.evict(Instant::now(), &self.limits)
            } else {
                None
            }
        };
        drop(evicted);
    }

    /// Open a transport for `entry`. A stdio server is spawned on the client's
    /// runtime and initialized within the startup timeout; a failed or late
    /// initialization drops the transport, which stops the process.
    async fn connect(
        &self,
        entry: &McpServerEntry,
    ) -> Result<(Arc<dyn McpTransport>, Option<String>), McpError> {
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
                let transport: Arc<dyn McpTransport> = Arc::new(HttpMcpTransport::new(
                    Arc::clone(chain),
                    entry.server_id.clone(),
                    endpoint_url.clone(),
                    capability.clone(),
                ));
                Ok((transport, None))
            }
            McpTransportSpec::Stdio { command, args, env } => {
                let options = StdioOptions {
                    request_timeout: self.limits.request_timeout,
                    max_line_bytes: self.limits.max_line_bytes,
                    runtime: Some(self.runtime()?),
                };
                let transport: Arc<dyn McpTransport> =
                    Arc::new(StdioMcpTransport::spawn_with_options(
                        entry.server_id.clone(),
                        command,
                        args,
                        env,
                        Arc::clone(&self.leak_detector),
                        options,
                    )?);
                let startup = self.limits.startup_timeout;
                let version =
                    match tokio::time::timeout(startup, initialize(transport.as_ref())).await {
                        Ok(result) => result?,
                        Err(_elapsed) => {
                            return Err(McpError::transport(format!(
                                "server '{}' did not complete initialize within {} ms",
                                entry.server_id,
                                startup.as_millis()
                            )))
                        }
                    };
                Ok((transport, Some(version)))
            }
        }
    }

    /// The runtime stdio transports run on: the one given to `with_runtime`, or
    /// the one current when the client was built. Never the connecting call's.
    fn runtime(&self) -> Result<Handle, McpError> {
        self.runtime.clone().ok_or_else(|| {
            McpError::transport(
                "no runtime for stdio servers: build the McpClient inside a tokio runtime or \
                 give one with `with_runtime`",
            )
        })
    }
}

/// Open an MCP session on `transport`: send `initialize`, check that the server
/// chose a version in [`SUPPORTED_PROTOCOL_VERSIONS`], then send
/// `notifications/initialized`. Returns the agreed version. A server-chosen
/// version string never reaches the caller; it goes to the host log, sanitized.
async fn initialize(transport: &dyn McpTransport) -> Result<String, McpError> {
    let params = serde_json::json!({
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "advance", "version": env!("CARGO_PKG_VERSION")},
    });
    let bytes = transport
        .invoke("initialize", params)
        .await
        .map_err(|e| McpError::new(e.kind, format!("initialize: {}", e.message)))?;
    let result: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| McpError::invalid_response("initialize: result is not JSON"))?;
    let chosen = result
        .get("protocolVersion")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| McpError::invalid_response("initialize: result has no protocolVersion"))?;
    let Some(version) = SUPPORTED_PROTOCOL_VERSIONS
        .iter()
        .find(|supported| **supported == chosen)
    else {
        eprintln!(
            "[cap_mcp {}] server chose unsupported protocol version {}",
            transport.server_id(),
            sanitize_log_text(chosen.as_bytes(), 64)
        );
        return Err(McpError::invalid_response(
            "initialize: server chose an unsupported protocol version",
        ));
    };
    transport
        .notify("notifications/initialized", None)
        .await
        .map_err(|e| McpError::new(e.kind, format!("notifications/initialized: {}", e.message)))?;
    Ok((*version).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn _assert_send_sync()
    where
        McpClient: Send + Sync,
    {
    }

    #[test]
    fn backoff_doubles_from_the_initial_wait_up_to_the_maximum() {
        let limits = McpClientLimits {
            restart_backoff_initial: Duration::from_millis(100),
            restart_backoff_max: Duration::from_millis(1000),
            ..McpClientLimits::default()
        };
        let waits: Vec<u128> = (1..=6).map(|n| backoff(n, &limits).as_millis()).collect();
        assert_eq!(waits, vec![100, 200, 400, 800, 1000, 1000]);
        assert_eq!(backoff(u32::MAX, &limits), Duration::from_millis(1000));
    }

    #[test]
    fn a_transport_that_dies_young_backs_off_and_a_long_run_resets_the_count() {
        let limits = McpClientLimits {
            restart_backoff_initial: Duration::from_millis(100),
            restart_backoff_max: Duration::from_secs(10),
            ..McpClientLimits::default()
        };
        let start = Instant::now();
        let mut state = SlotState::default();
        let live = |since| Live {
            transport: Arc::new(ClosedTransport) as Arc<dyn McpTransport>,
            since,
            protocol_version: None,
        };

        state.live = Some(live(start));
        assert!(state
            .evict(start + Duration::from_secs(1), &limits)
            .is_some());
        assert_eq!(state.failures, 1);
        assert_eq!(
            state.retry_at,
            Some(start + Duration::from_secs(1) + Duration::from_millis(100))
        );

        state.fail(start, &limits);
        assert_eq!(state.failures, 2);

        state.live = Some(live(start));
        assert!(state
            .evict(start + Duration::from_secs(10), &limits)
            .is_some());
        assert_eq!(state.failures, 0);
        assert_eq!(state.retry_at, None);
        assert!(state.evict(start, &limits).is_none());
    }

    struct ClosedTransport;

    #[async_trait]
    impl McpTransport for ClosedTransport {
        async fn invoke(
            &self,
            _method: &str,
            _params: serde_json::Value,
        ) -> Result<Vec<u8>, McpError> {
            Err(McpError::transport("closed"))
        }

        async fn notify(
            &self,
            _method: &str,
            _params: Option<serde_json::Value>,
        ) -> Result<(), McpError> {
            Err(McpError::transport("closed"))
        }

        fn server_id(&self) -> &str {
            "closed"
        }

        fn is_closed(&self) -> bool {
            true
        }
    }
}

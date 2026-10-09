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
//! server connects it within [`McpClientLimits::startup_timeout`]: a stdio
//! server is spawned and initialized (`initialize` carrying
//! [`MCP_PROTOCOL_VERSION`], a check that the server chose a version in
//! [`SUPPORTED_PROTOCOL_VERSIONS`], then `notifications/initialized`); an http
//! server's transport is built and goes through the same exchange, which also
//! starts its session ([`HttpMcpTransport::initialize`]). Concurrent first calls
//! share one connection attempt, and no std lock is held while it runs.
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
//! ran longer is replaced at once. A transport's run and the wait after it are
//! measured from when it closed ([`McpTransport::closed_at`]), not from when a
//! call noticed: a server that died while idle long ago is reconnected at once.
//!
//! Stdio transports are spawned on, and run their tasks on, the runtime given
//! to [`McpClient::with_runtime`], and only that one: never the runtime current
//! when the client was built, nor that of the call that connects them. A
//! client given no runtime refuses to start stdio servers.
//!
//! A client given an event bus ([`McpClient::with_event_bus`]) reports each
//! connection it makes as `mcp.server_started` (`server_id`, `transport`), and
//! each live connection it finds closed and evicts as `mcp.server_died`
//! (`server_id`; `exit_code` is `null`, no exit status being collected), both
//! with the agent id `runtime`: a connection serves every agent. A connection
//! attempt that fails, or one retired by [`McpClient::disconnect`] or
//! [`McpClient::shutdown`], reports nothing.
//!
//! ## Shutdown
//!
//! [`McpClient::shutdown`] ends the client: every connection is closed at
//! once, whether live or still being connected and whatever calls run on it.
//! A stdio server's process group is stopped and the calls waiting on it
//! fail; an http request already under way runs to its end, and nothing is
//! sent after it. No connection is made afterwards: every later call fails
//! without starting a server. A stdio server leads its own process group and
//! does not end with the host process: the host shuts the client down before
//! it exits.
//!
//! ## Callers
//!
//! Each method that sends a request takes `caller`: the agent the request is
//! made for, or `None` for one made on no agent's behalf (an operator's
//! listing, the tool inventory). An http server's transport executes the
//! request through the security chain as that agent, so rate limits and
//! `http.*` events are the agent's; a request for no agent, and the
//! handshake, are attributed to the server id.
//!
//! ## Tool listings
//!
//! [`McpClient::list_tools`] reads `tools/list` page by page, at most
//! [`MAX_TOOL_LIST_PAGES`](crate::MAX_TOOL_LIST_PAGES) pages, and keeps a tool
//! when it meets the entry limits: a name of at most
//! [`MAX_TOOL_NAME_BYTES`](crate::MAX_TOOL_NAME_BYTES) that a call can carry,
//! listed once; a description cut to
//! [`MAX_TOOL_DESCRIPTION_BYTES`](crate::MAX_TOOL_DESCRIPTION_BYTES); an
//! `inputSchema` kept when it is an object of at most
//! [`MAX_TOOL_SCHEMA_BYTES`](crate::MAX_TOOL_SCHEMA_BYTES) whose references stay
//! inside it. A listing keeps at most
//! [`MAX_TOOLS_PER_SERVER`](crate::MAX_TOOLS_PER_SERVER) tools. Each server's
//! latest listing is kept in a tool cache of at most
//! [`MAX_CACHED_TOOLS`](crate::MAX_CACHED_TOOLS) tools across all servers,
//! shared fairly among them, and read without any I/O through
//! [`McpClient::cached_tools`]; an entry says when the cache keeps only part of
//! its listing.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, Instant};

use advance_shared_types::event::Event;
use advance_shared_types::security_validator::{HttpSecurityChain, LeakDetector};
use advance_shared_types::traits::EventBusEmit;
use async_trait::async_trait;
use tokio::runtime::Handle;

use crate::error::McpError;
use crate::events;
use crate::http_transport::{HttpMcpTransport, HttpOptions};
use crate::listing::{CachedToolListing, ToolCache, ToolListing, MAX_TOOL_LIST_PAGES};
use crate::schema_validator::SchemaValidator;
use crate::stdio_transport::{
    sanitize_log_text, StdioMcpTransport, StdioOptions, MAX_STDIO_LINE_BYTES, MAX_STDIO_WALL_CLOCK,
};
use crate::web_provider::refuse_stdio_web_provider;
use crate::whitelist::{McpServerEntry, McpServersConfig, McpTransportSpec};

/// MCP protocol version this client asks for in `initialize`.
pub const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

/// Protocol versions this client accepts as a server's `initialize` answer,
/// newest first. A server that chooses any other version is disconnected.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

/// Default budget for connecting a server ([`McpClientLimits::startup_timeout`]).
pub(crate) const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Trait shared by HTTP and stdio transports. `McpClient` dispatches through
/// `Arc<dyn McpTransport>` so both transport classes can be cached behind the
/// same per-server handle.
#[async_trait]
pub trait McpTransport: Send + Sync {
    /// Send a JSON-RPC request and return its `result` as JSON bytes.
    ///
    /// `caller` is the agent the request is made for, `None` when it is made on
    /// no agent's behalf. A transport whose traffic passes the http security
    /// chain attributes the request to that agent, and to the server id when
    /// `None`; a stdio transport attributes it to no one.
    async fn invoke(
        &self,
        caller: Option<&str>,
        method: &str,
        params: serde_json::Value,
    ) -> Result<Vec<u8>, McpError>;

    /// Send a JSON-RPC notification: a message without an id, which the server
    /// never answers.
    async fn notify(&self, method: &str, params: Option<serde_json::Value>)
        -> Result<(), McpError>;

    fn server_id(&self) -> &str;

    /// When the transport closed, once it can carry no further calls (its
    /// process exited, its stream overflowed); `None` while it is open.
    /// Defaults to `None`.
    fn closed_at(&self) -> Option<Instant> {
        None
    }

    /// True once the transport can carry no further calls. The client then
    /// evicts it and reconnects the server on a later call, measuring how long
    /// the transport ran, and the wait before reconnecting, from
    /// [`closed_at`](Self::closed_at) (from the moment it noticed, when that is
    /// `None`). Defaults to `closed_at().is_some()`.
    fn is_closed(&self) -> bool {
        self.closed_at().is_some()
    }

    /// Close the transport now: it carries no further call. A stdio transport
    /// fails the calls waiting on it and stops its server's process group; an
    /// http transport lets a request already under way run to its end. A
    /// second close changes nothing. Defaults to doing nothing: a transport
    /// that holds no process and no connection has nothing to release.
    fn close(&self) {}
}

/// Bounds on one client's connections and calls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpClientLimits {
    /// Budget for one call. On a stdio server it covers sending the request
    /// and receiving the answer; on an http server, each POST through the
    /// security chain, response included. The chain's executor bounds a POST
    /// by its own timeout as well, so a budget longer than that executor's
    /// takes effect only with an executor built to allow it.
    pub request_timeout: Duration,
    /// Budget for connecting a server: spawning a stdio server, then
    /// completing the `initialize` exchange; on an http server, also for
    /// starting a session again after the server ended one.
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
            startup_timeout: DEFAULT_STARTUP_TIMEOUT,
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

/// Per-tool info surfaced by `list_tools`. Mirrors `mcp-tool-info`, plus the
/// tool's input schema, which stays on the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpToolInfo {
    pub name: String,
    pub description: String,
    pub server_id: String,
    /// The tool's `inputSchema`, when the server gave one within the listing
    /// limits (see [`McpClient::list_tools`]).
    pub input_schema: Option<serde_json::Value>,
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
    /// The transport the connection attempt in flight has opened, if any:
    /// [`McpClient::shutdown`] closes it without waiting for the attempt.
    opening: Option<Weak<dyn McpTransport>>,
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

    /// The live transport, or `Err` when there is none. A live transport that
    /// has closed is evicted and returned in the `Err`, for the caller to
    /// report and drop (stopping its process) outside the lock.
    fn live_transport(
        &self,
        limits: &McpClientLimits,
    ) -> Result<Arc<dyn McpTransport>, Option<Live>> {
        let mut state = self.state();
        let Some(live) = state.live.as_ref() else {
            return Err(None);
        };
        let transport = Arc::clone(&live.transport);
        if !transport.is_closed() {
            return Ok(transport);
        }
        Err(state.evict(Instant::now(), limits))
    }

    /// How long a connection attempt must still wait.
    fn backoff_remaining(&self, now: Instant) -> Option<Duration> {
        self.state()
            .retry_at
            .map(|at| at.saturating_duration_since(now))
            .filter(|wait| !wait.is_zero())
    }

    /// Close the slot's live transport and the one its connection attempt has
    /// opened, outside the state lock.
    fn close_transports(&self) {
        let (live, opening) = {
            let mut state = self.state();
            (state.live.take(), state.opening.take())
        };
        if let Some(live) = live {
            live.transport.close();
        }
        if let Some(transport) = opening.and_then(|transport| transport.upgrade()) {
            transport.close();
        }
    }
}

impl SlotState {
    /// Take the live transport out and arm the backoff for its death, dated by
    /// the transport's [`McpTransport::closed_at`] (by `now` when it gives
    /// none), so a transport found closed long after it died is judged by when
    /// it died. A transport that ran at least `restart_backoff_max` resets the
    /// failure count and is replaced at once; otherwise the wait runs from its
    /// death.
    fn evict(&mut self, now: Instant, limits: &McpClientLimits) -> Option<Live> {
        let live = self.live.take()?;
        // Within the transport's life: not before it was published, not after now.
        let died = live
            .transport
            .closed_at()
            .unwrap_or(now)
            .min(now)
            .max(live.since);
        if died.saturating_duration_since(live.since) >= limits.restart_backoff_max {
            self.failures = 0;
            self.retry_at = None;
        } else {
            self.fail(died, limits);
        }
        Some(live)
    }

    /// Count a failure that happened at `at`: no connection attempt before the
    /// backoff after it has passed.
    fn fail(&mut self, at: Instant, limits: &McpClientLimits) {
        self.failures = self.failures.saturating_add(1);
        self.retry_at = Some(at + backoff(self.failures, limits));
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

/// What [`McpClient::replace_config`] changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct McpReconfig {
    /// Server ids that were not configured before.
    pub added: Vec<String>,
    /// Server ids that are no longer configured.
    pub removed: Vec<String>,
    /// Server ids whose fingerprint changed (transport, patterns or schemas).
    pub changed: Vec<String>,
}

/// High-level MCP client. Owns the `McpServersConfig` whitelist, the
/// per-server connection slots and the tool cache.
pub struct McpClient {
    config: Mutex<Arc<McpServersConfig>>,
    slots: Mutex<HashMap<String, Arc<ServerSlot>>>,
    tool_cache: Mutex<ToolCache>,
    leak_detector: Arc<dyn LeakDetector>,
    http_chain: Option<Arc<dyn HttpSecurityChain>>,
    limits: McpClientLimits,
    /// The runtime stdio servers run on; `None` until
    /// [`with_runtime`](McpClient::with_runtime) gives one.
    runtime: Option<Handle>,
    /// Where connections are reported (see the module docs); `None` until
    /// [`with_event_bus`](McpClient::with_event_bus) gives one.
    event_bus: Option<Arc<dyn EventBusEmit>>,
    /// Set by [`shutdown`](McpClient::shutdown). Written and read under the
    /// `slots` lock, so no slot is created once it is set.
    shut_down: AtomicBool,
}

impl McpClient {
    /// Construct a new client with the default [`McpClientLimits`].
    ///
    /// `leak_detector` is plumbed into stdio transports for request and
    /// response scanning. `http_chain` is required for HTTP transports — passed
    /// as Option so test fixtures with no HTTP servers can omit it.
    ///
    /// The client holds no runtime: until [`with_runtime`](Self::with_runtime)
    /// gives one, a call to a stdio server fails without starting it. The
    /// client never takes the runtime current when it is built, or the one of
    /// the call that connects a server: a stdio transport outlives that call,
    /// and on a runtime that exists for one call (a Client API request runs on
    /// one) its tasks would stop with that runtime, leaving the server
    /// unreachable.
    pub fn new(
        config: Arc<McpServersConfig>,
        leak_detector: Arc<dyn LeakDetector>,
        http_chain: Option<Arc<dyn HttpSecurityChain>>,
    ) -> Self {
        Self {
            config: Mutex::new(config),
            slots: Mutex::new(HashMap::new()),
            tool_cache: Mutex::new(ToolCache::default()),
            leak_detector,
            http_chain,
            limits: McpClientLimits::default(),
            runtime: None,
            event_bus: None,
            shut_down: AtomicBool::new(false),
        }
    }

    /// Replace the limits.
    pub fn with_limits(mut self, limits: McpClientLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Report connections on `event_bus`: `mcp.server_started` and
    /// `mcp.server_died` (see the module docs).
    pub fn with_event_bus(mut self, event_bus: Arc<dyn EventBusEmit>) -> Self {
        self.event_bus = Some(event_bus);
        self
    }

    /// Spawn stdio servers on `runtime` and run their transports' tasks there,
    /// whatever runtime the connecting call runs on. Pass the daemon's runtime:
    /// a transport outlives the call that connects it, and its server becomes
    /// unreachable when `runtime` shuts down.
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
            config: Mutex::new(config),
            slots: Mutex::new(slots),
            tool_cache: Mutex::new(ToolCache::default()),
            leak_detector,
            http_chain: None,
            limits: McpClientLimits::default(),
            runtime: None,
            event_bus: None,
            shut_down: AtomicBool::new(false),
        }
    }

    fn servers(&self) -> Arc<McpServersConfig> {
        Arc::clone(&lock(&self.config))
    }

    /// Replace the configured servers. Connections of a removed or changed
    /// server are closed ([`disconnect`](Self::disconnect)); their tool-cache
    /// entries are dropped. An unchanged server keeps its connection. A client
    /// that has been shut down ignores the new set.
    pub fn replace_config(&self, new: McpServersConfig) -> McpReconfig {
        if self.is_shut_down() {
            return McpReconfig::default();
        }
        let new = Arc::new(new);
        let old = {
            let mut guard = lock(&self.config);
            let old = Arc::clone(&*guard);
            *guard = Arc::clone(&new);
            old
        };
        let mut reconfig = McpReconfig::default();
        for entry in old.list_servers() {
            match new.get(&entry.server_id) {
                Ok(next) if next.fingerprint() == entry.fingerprint() => {}
                Ok(_) => reconfig.changed.push(entry.server_id.clone()),
                Err(_) => reconfig.removed.push(entry.server_id.clone()),
            }
        }
        for entry in new.list_servers() {
            if old.get(&entry.server_id).is_err() {
                reconfig.added.push(entry.server_id.clone());
            }
        }
        for id in reconfig.removed.iter().chain(reconfig.changed.iter()) {
            self.disconnect(id);
            lock(&self.tool_cache).drop_server(id);
        }
        reconfig
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

    /// End the client (see the module docs): close every connection now, live
    /// or still being connected, and make none afterwards. Each stdio server's
    /// process group is stopped and the calls waiting on it fail, and every
    /// later call fails without starting a server. A second call changes
    /// nothing.
    pub fn shutdown(&self) {
        let retired: Vec<Arc<ServerSlot>> = {
            let mut slots = self.slots();
            self.shut_down.store(true, Ordering::SeqCst);
            slots.drain().map(|(_, slot)| slot).collect()
        };
        for slot in retired {
            slot.close_transports();
        }
    }

    /// Whether [`shutdown`](Self::shutdown) has ended the client.
    pub fn is_shut_down(&self) -> bool {
        self.shut_down.load(Ordering::SeqCst)
    }

    /// Whether the web family tools (`web.search`, `web.extract`) of
    /// `server_id` are refused whatever the caller's grants: a stdio server
    /// reaches the network outside the http security chain, with keys of its
    /// own, so the mcp-client host functions hide its web family tools and
    /// refuse calls to them. False for an http server and for an id that is not
    /// configured.
    pub fn refuses_web_tools(&self, server_id: &str) -> bool {
        self.servers()
            .get(server_id)
            .is_ok_and(|entry| refuse_stdio_web_provider(&entry.transport).is_err())
    }

    /// List configured servers (filtered by whitelist).
    pub async fn list_servers(&self) -> Vec<McpServerInfo> {
        self.servers()
            .list_servers()
            .map(|e| McpServerInfo {
                id: e.server_id.clone(),
                description: e.description.clone(),
            })
            .collect()
    }

    /// List the tools a server offers, for `caller` (see the module docs).
    ///
    /// Sends `tools/list`, then follows `nextCursor` with `tools/list
    /// {cursor}` for at most [`MAX_TOOL_LIST_PAGES`](crate::MAX_TOOL_LIST_PAGES)
    /// pages in all; the listing ends at a page without a usable cursor
    /// (missing, not a string, empty, longer than
    /// [`MAX_TOOL_LIST_CURSOR_BYTES`](crate::MAX_TOOL_LIST_CURSOR_BYTES) or the
    /// same as the one that asked for the page) and once it holds
    /// [`MAX_TOOLS_PER_SERVER`](crate::MAX_TOOLS_PER_SERVER) tools. A tool is
    /// kept when the server's tool patterns allow it and it meets the entry
    /// limits (see the module docs). The caller receives the whole listing; it
    /// also becomes the server's entry in the tool cache
    /// ([`cached_tools`](Self::cached_tools)), within the server's share. A
    /// failed listing leaves the cache as it was.
    pub async fn list_tools(
        &self,
        caller: Option<&str>,
        server_id: &str,
    ) -> Result<Vec<McpToolInfo>, McpError> {
        let servers = self.servers();
        let entry = servers.get(server_id)?;
        let mut listing = ToolListing::new(server_id);
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_TOOL_LIST_PAGES {
            let params = match &cursor {
                None => serde_json::json!({}),
                Some(cursor) => serde_json::json!({ "cursor": cursor }),
            };
            let bytes = self.call(caller, entry, "tools/list", params).await?;
            let page: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|_| McpError::invalid_response("tools/list result is not JSON"))?;
            match listing.read_page(entry, page)? {
                Some(next) if !listing.is_full() && cursor.as_deref() != Some(next.as_str()) => {
                    cursor = Some(next);
                }
                _ => break,
            }
        }
        let tools = listing.into_tools();
        lock(&self.tool_cache).store(server_id, &tools);
        Ok(tools)
    }

    /// Each server's latest successful [`list_tools`](Self::list_tools), in
    /// server-id order, read without contacting any server. A server not yet
    /// listed has no entry; one that listed no tools has an empty entry.
    ///
    /// The cache holds at most [`MAX_CACHED_TOOLS`](crate::MAX_CACHED_TOOLS)
    /// tools across all servers, shared fairly among them: a listing larger
    /// than its server's share is kept in part, its first tools only, and its
    /// entry says so ([`CachedToolListing::is_truncated`],
    /// [`CachedToolListing::listed`]). The entries are shared, so a read clones
    /// no tool.
    ///
    /// The entries hold what each server lists, narrowed only by the server's
    /// own tool patterns and the listing limits. They are not filtered by any
    /// agent's `mcp` grant, nor by the rules for the web family tools
    /// (`web.search`, `web.extract`), which are hidden from an agent without
    /// the `web` grant and, on a server that
    /// [refuses them](Self::refuses_web_tools), from every agent. Filter them
    /// before showing them to an agent, as
    /// [`McpGate::visible_tools`](crate::McpGate::visible_tools) does.
    pub fn cached_tools(&self) -> Vec<Arc<CachedToolListing>> {
        lock(&self.tool_cache).listings()
    }

    /// The configured servers a [`list_tools`](Self::list_tools) would add
    /// tools to the cache for, in id order, read without contacting any
    /// server: a server the cache holds no listing of (not listed yet, or every
    /// listing of it failed), and one whose cached listing is cut
    /// ([`CachedToolListing::is_truncated`]) to fewer tools than the cache now
    /// has room for it, room another server's listing took and has since given
    /// back. A listing cut to its share of a full cache is not among them:
    /// listing it again would cut it the same way.
    pub fn servers_to_list(&self) -> Vec<String> {
        let servers = self.servers();
        let cache = lock(&self.tool_cache);
        let growable = cache.growable();
        servers
            .list_servers()
            .filter(|entry| !cache.holds(&entry.server_id) || growable.contains(&entry.server_id))
            .map(|entry| entry.server_id.clone())
            .collect()
    }

    /// Put `tools` in the cache as the listing of `server_id`, without contacting
    /// the server.
    #[doc(hidden)]
    pub fn store_cached_tools(&self, server_id: &str, tools: Vec<McpToolInfo>) {
        lock(&self.tool_cache).store(server_id, &tools);
    }

    /// List prompts on a server (no filter), for `caller` (see the module
    /// docs).
    pub async fn list_prompts(
        &self,
        caller: Option<&str>,
        server_id: &str,
    ) -> Result<Vec<McpPromptInfo>, McpError> {
        let servers = self.servers();
        let entry = servers.get(server_id)?;
        let bytes = self
            .call(
                caller,
                entry,
                "prompts/list",
                serde_json::Value::Object(Default::default()),
            )
            .await?;
        let parsed: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| McpError::invalid_response("prompts/list result is not JSON"))?;
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

    /// Fetch a prompt, for `caller` (see the module docs).
    pub async fn get_prompt(
        &self,
        caller: Option<&str>,
        server_id: &str,
        prompt_name: &str,
        args: Vec<(String, String)>,
    ) -> Result<Vec<u8>, McpError> {
        let servers = self.servers();
        let entry = servers.get(server_id)?;
        let args_obj: serde_json::Map<String, serde_json::Value> = args
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        let params = serde_json::json!({"name": prompt_name, "arguments": args_obj});
        self.call(caller, entry, "prompts/get", params).await
    }

    /// List resources on a server, for `caller` (see the module docs).
    pub async fn list_resources(
        &self,
        caller: Option<&str>,
        server_id: &str,
    ) -> Result<Vec<McpResourceInfo>, McpError> {
        let servers = self.servers();
        let entry = servers.get(server_id)?;
        let bytes = self
            .call(
                caller,
                entry,
                "resources/list",
                serde_json::Value::Object(Default::default()),
            )
            .await?;
        let parsed: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| McpError::invalid_response("resources/list result is not JSON"))?;
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

    /// Read a resource, for `caller` (see the module docs).
    pub async fn read_resource(
        &self,
        caller: Option<&str>,
        server_id: &str,
        uri: &str,
    ) -> Result<Vec<u8>, McpError> {
        let servers = self.servers();
        let entry = servers.get(server_id)?;
        let params = serde_json::json!({"uri": uri});
        self.call(caller, entry, "resources/read", params).await
    }

    /// Invoke a tool, for `caller` (see the module docs). Order:
    /// 1. Whitelist gate (config.get) — `McpError::not_found` for unknown server.
    /// 2. Tool-pattern gate — `McpError::tool_not_found` if blocked.
    /// 3. Input schema validation (if schema present) — fails BEFORE dispatch.
    /// 4. Transport invoke `tools/call`.
    /// 5. Output schema validation (if schema present).
    pub async fn invoke_tool(
        &self,
        caller: Option<&str>,
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

        let servers = self.servers();
        let entry = servers.get(server_id)?;
        if !entry.tool_allowed(tool_name) {
            return Err(McpError::tool_not_found(format!(
                "tool '{tool_name}' does not match the tool patterns configured for server \
                 '{server_id}'"
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
        let bytes = self.call(caller, entry, "tools/call", call_params).await?;

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

    /// Send one request to the server for `caller`. A failed call that found
    /// the transport closed evicts it; a result over `max_result_bytes` fails
    /// the call.
    async fn call(
        &self,
        caller: Option<&str>,
        entry: &McpServerEntry,
        method: &str,
        params: serde_json::Value,
    ) -> Result<Vec<u8>, McpError> {
        let transport = self.transport_for(entry).await?;
        let result = transport.invoke(caller, method, params).await;
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

    /// The server's current slot, created on first use; none once the client
    /// is shut down. Only whitelisted ids reach here, so the map is bounded by
    /// the config.
    fn slot(&self, server_id: &str) -> Result<Arc<ServerSlot>, McpError> {
        let mut slots = self.slots();
        if self.shut_down.load(Ordering::SeqCst) {
            return Err(McpError::transport("the mcp client is shut down"));
        }
        Ok(Arc::clone(
            slots
                .entry(server_id.to_string())
                .or_insert_with(|| Arc::new(ServerSlot::new())),
        ))
    }

    /// The server's live transport, connecting it if it has none (see the
    /// module docs: one attempt at a time per server, backoff after failures).
    async fn transport_for(
        &self,
        entry: &McpServerEntry,
    ) -> Result<Arc<dyn McpTransport>, McpError> {
        loop {
            let slot = self.slot(&entry.server_id)?;
            if let Some(transport) = self.live_transport(&entry.server_id, &slot) {
                return Ok(transport);
            }
            let _attempt = slot.connecting.lock().await;
            // `disconnect` may have retired the slot while this caller waited
            // for the attempt lock: use the server's new slot instead.
            if !self.is_current(&entry.server_id, &slot) {
                continue;
            }
            // A concurrent caller may have connected the server meanwhile.
            if let Some(transport) = self.live_transport(&entry.server_id, &slot) {
                return Ok(transport);
            }
            if let Some(wait) = slot.backoff_remaining(Instant::now()) {
                return Err(McpError::transport(format!(
                    "server '{}' is unavailable after a failure; retry in {} ms",
                    entry.server_id,
                    wait.as_millis().max(1)
                )));
            }
            return match self.connect(entry, &slot).await {
                Ok((transport, protocol_version)) => {
                    let live = Live {
                        transport: Arc::clone(&transport),
                        since: Instant::now(),
                        protocol_version,
                    };
                    if self.publish(&entry.server_id, &slot, live) {
                        self.report(events::server_started(
                            &entry.server_id,
                            transport_kind(&entry.transport),
                        ));
                        Ok(transport)
                    } else {
                        Err(disconnected_while_connecting(&entry.server_id))
                    }
                }
                Err(error) => {
                    slot.state().fail(Instant::now(), &self.limits);
                    Err(error)
                }
            };
        }
    }

    /// The live transport in the server's `slot`, if any. A live transport
    /// found closed is evicted and reported dead.
    fn live_transport(&self, server_id: &str, slot: &ServerSlot) -> Option<Arc<dyn McpTransport>> {
        match slot.live_transport(&self.limits) {
            Ok(transport) => Some(transport),
            Err(evicted) => {
                if let Some(dead) = evicted {
                    self.report_dead(server_id, dead);
                }
                None
            }
        }
    }

    /// Report an evicted connection as `mcp.server_died`, then drop it, which
    /// stops its process once no call holds it.
    fn report_dead(&self, server_id: &str, dead: Live) {
        self.report(events::server_died(server_id));
        drop(dead);
    }

    /// Emit `event` on the client's event bus, if it has one.
    fn report(&self, event: Event) {
        if let Some(bus) = &self.event_bus {
            bus.emit(event);
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
            let mut state = slot.state();
            state.live = Some(live);
            state.opening = None;
        }
        drop(slots);
        current
    }

    /// Record `transport` as the one the attempt on `slot` has opened, so that
    /// [`shutdown`](Self::shutdown) can close it. A slot retired before the
    /// transport was recorded is not seen by the call that retired it: the
    /// transport is then closed here and the attempt fails.
    fn opened(
        &self,
        server_id: &str,
        slot: &Arc<ServerSlot>,
        transport: &Arc<dyn McpTransport>,
    ) -> Result<(), McpError> {
        slot.state().opening = Some(Arc::downgrade(transport));
        if self.is_current(server_id, slot) {
            return Ok(());
        }
        transport.close();
        Err(disconnected_while_connecting(server_id))
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
        if let Some(dead) = evicted {
            self.report_dead(server_id, dead);
        }
    }

    /// Open a transport for `entry` and initialize it within the startup
    /// timeout. A stdio server is spawned on the client's runtime; an http
    /// transport posts through the client's security chain with the client's
    /// request timeout. A failed or late initialization drops the transport,
    /// which stops a stdio server's process. The transport is recorded in
    /// `slot` while it connects (see [`opened`](Self::opened)).
    async fn connect(
        &self,
        entry: &McpServerEntry,
        slot: &Arc<ServerSlot>,
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
                let transport = Arc::new(HttpMcpTransport::with_options(
                    Arc::clone(chain),
                    entry.server_id.clone(),
                    endpoint_url.clone(),
                    capability.clone(),
                    HttpOptions {
                        request_timeout: self.limits.request_timeout,
                        startup_timeout: self.limits.startup_timeout,
                    },
                ));
                let shared: Arc<dyn McpTransport> = transport.clone();
                self.opened(&entry.server_id, slot, &shared)?;
                let version = transport.initialize().await?;
                Ok((shared, Some(version.to_string())))
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
                self.opened(&entry.server_id, slot, &transport)?;
                let startup = self.limits.startup_timeout;
                let version = match tokio::time::timeout(startup, initialize(transport.as_ref()))
                    .await
                {
                    Ok(result) => result?,
                    Err(_elapsed) => return Err(startup_timeout_error(&entry.server_id, startup)),
                };
                Ok((transport, Some(version.to_string())))
            }
        }
    }

    /// The runtime stdio transports run on: the one given to `with_runtime`.
    fn runtime(&self) -> Result<Handle, McpError> {
        self.runtime.clone().ok_or_else(|| {
            McpError::transport(
                "no runtime for stdio servers: give the McpClient one with `with_runtime`",
            )
        })
    }
}

/// The error of a connection attempt whose slot was retired meanwhile.
fn disconnected_while_connecting(server_id: &str) -> McpError {
    McpError::transport(format!(
        "server '{server_id}' was disconnected while connecting"
    ))
}

/// The transport name a connection event carries.
fn transport_kind(spec: &McpTransportSpec) -> &'static str {
    match spec {
        McpTransportSpec::Http { .. } => "http",
        McpTransportSpec::Stdio { .. } => "stdio",
    }
}

/// Open an MCP session on `transport`: send `initialize`, check that the server
/// chose a version in [`SUPPORTED_PROTOCOL_VERSIONS`], then send
/// `notifications/initialized`. Returns the agreed version. The exchange is
/// made on no agent's behalf.
async fn initialize(transport: &dyn McpTransport) -> Result<&'static str, McpError> {
    let bytes = transport
        .invoke(None, "initialize", initialize_params())
        .await
        .map_err(|e| with_step("initialize", e))?;
    let version = agreed_protocol_version(transport.server_id(), &bytes)?;
    transport
        .notify("notifications/initialized", None)
        .await
        .map_err(|e| with_step("notifications/initialized", e))?;
    Ok(version)
}

/// The params of an `initialize` request: the version this client asks for,
/// no client capabilities, and the client's name and version.
pub(crate) fn initialize_params() -> serde_json::Value {
    serde_json::json!({
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "advance", "version": env!("CARGO_PKG_VERSION")},
    })
}

/// The protocol version `server_id` chose in its `initialize` result, when it
/// is one of [`SUPPORTED_PROTOCOL_VERSIONS`]. A server-chosen version string
/// never reaches the caller; it goes to the host log, sanitized, once per
/// connection attempt (the failure arms the reconnect backoff, which spaces the
/// attempts out).
pub(crate) fn agreed_protocol_version(
    server_id: &str,
    result: &[u8],
) -> Result<&'static str, McpError> {
    let result: serde_json::Value = serde_json::from_slice(result)
        .map_err(|_| McpError::invalid_response("initialize: result is not JSON"))?;
    let chosen = result
        .get("protocolVersion")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| McpError::invalid_response("initialize: result has no protocolVersion"))?;
    match SUPPORTED_PROTOCOL_VERSIONS
        .iter()
        .find(|supported| **supported == chosen)
    {
        Some(version) => Ok(version),
        None => {
            eprintln!(
                "[cap_mcp {server_id}] server chose unsupported protocol version {}",
                sanitize_log_text(chosen.as_bytes(), 64)
            );
            Err(McpError::invalid_response(
                "initialize: server chose an unsupported protocol version",
            ))
        }
    }
}

/// The error of a server that did not complete `initialize` within `startup`.
pub(crate) fn startup_timeout_error(server_id: &str, startup: Duration) -> McpError {
    McpError::transport(format!(
        "server '{server_id}' did not complete initialize within {} ms",
        startup.as_millis()
    ))
}

/// `error` with its message prefixed by the protocol step that failed.
pub(crate) fn with_step(step: &str, error: McpError) -> McpError {
    McpError::new(error.kind, format!("{step}: {}", error.message))
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

    // A transport that does not say when it closed is dated by the moment the
    // client noticed.
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
            transport: Arc::new(ClosedTransport { at: None }) as Arc<dyn McpTransport>,
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

    // The run and the wait are measured from when the transport closed: a
    // transport that died young while idle is found closed long after, and the
    // call that finds it reconnects at once.
    #[test]
    fn the_backoff_runs_from_when_the_transport_closed() {
        let limits = McpClientLimits {
            restart_backoff_initial: Duration::from_secs(1),
            restart_backoff_max: Duration::from_secs(60),
            ..McpClientLimits::default()
        };
        let start = Instant::now();
        // A slot whose live transport was published at `start` and closed at `at`.
        let slot = |at, failures| SlotState {
            live: Some(Live {
                transport: Arc::new(ClosedTransport { at }) as Arc<dyn McpTransport>,
                since: start,
                protocol_version: None,
            }),
            opening: None,
            failures,
            retry_at: None,
        };
        let died = start + Duration::from_secs(5);

        // Found 25 s after its death: it died young, but its wait is long over.
        let mut state = slot(Some(died), 0);
        let found = start + Duration::from_secs(30);
        assert!(state.evict(found, &limits).is_some());
        assert_eq!(state.failures, 1);
        assert_eq!(state.retry_at, Some(died + Duration::from_secs(1)));
        assert!(state.retry_at.is_some_and(|at| at <= found));

        // Found right after its death: the rest of the wait remains.
        let mut state = slot(Some(died), 0);
        assert!(state
            .evict(died + Duration::from_millis(200), &limits)
            .is_some());
        assert_eq!(state.retry_at, Some(died + Duration::from_secs(1)));

        // It ran the maximum before it closed: replaced at once, the count reset.
        let mut state = slot(Some(start + Duration::from_secs(60)), 3);
        assert!(state
            .evict(start + Duration::from_secs(600), &limits)
            .is_some());
        assert_eq!((state.failures, state.retry_at), (0, None));

        // A closing instant outside the transport's life is held within it.
        let mut state = slot(Some(start + Duration::from_secs(900)), 0);
        assert!(state.evict(died, &limits).is_some());
        assert_eq!(state.retry_at, Some(died + Duration::from_secs(1)));
    }

    /// A transport that has closed, at `at` when it says so.
    struct ClosedTransport {
        at: Option<Instant>,
    }

    #[async_trait]
    impl McpTransport for ClosedTransport {
        async fn invoke(
            &self,
            _caller: Option<&str>,
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

        fn closed_at(&self) -> Option<Instant> {
            self.at
        }

        fn is_closed(&self) -> bool {
            true
        }
    }
}

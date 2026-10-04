//! `HttpMcpTransport` — the MCP Streamable HTTP transport (MODULE-017).
//!
//! Every message is a JSON-RPC 2.0 POST to the server's one MCP endpoint,
//! routed through an `Arc<dyn HttpSecurityChain>` (CONTRACT-111: allowlist,
//! leak scans, credential injection, SSRF, rate limit, redirect re-check). A
//! request is answered with an `application/json` or a `text/event-stream`
//! body; a notification is accepted with any 2xx, usually `202 Accepted` and no
//! body. The stdio transport lives in `stdio_transport.rs`.
//!
//! ## Sessions
//!
//! [`HttpMcpTransport::initialize`] starts a session: it POSTs `initialize`
//! without session headers, checks that the server chose a version in
//! [`SUPPORTED_PROTOCOL_VERSIONS`](crate::SUPPORTED_PROTOCOL_VERSIONS), keeps
//! the `Mcp-Session-Id` the server may assign in that answer, then sends
//! `notifications/initialized`. Every later POST carries
//! `MCP-Protocol-Version: <agreed version>` and, when the server assigned one,
//! the session id. A session id must be 1..=[`MAX_SESSION_ID_BYTES`] visible
//! ASCII characters; the server's answer is refused otherwise.
//!
//! A `404` to a POST that carried a session id means the server ended the
//! session. The transport starts a new one (calls that found the same session
//! ended share one restart) and sends the message once more. The restart must
//! complete within [`HttpOptions::startup_timeout`] and agree the same protocol
//! version; otherwise the transport closes ([`McpTransport::closed_at`]), later
//! calls fail at once, and the client reconnects the server.
//!
//! A server that refuses the `initialize` POST with `404` or `405`, or answers
//! it with an `endpoint` event, speaks the older HTTP+SSE transport (a GET
//! stream, often `/sse`, plus a separate endpoint for messages). That
//! transport is not supported, and the error says so.
//!
//! ## Attribution
//!
//! A request made for an agent goes through the chain as that agent, so rate
//! limits and `http.*` events are the agent's. The handshake and requests made
//! for no agent are attributed to the server id.
//!
//! ## What reaches the caller
//!
//! Errors carry fixed text, HTTP status codes and JSON-RPC error codes only,
//! never text the server sent (an error message, a content type, a URL), which
//! could carry injected instructions. A server's JSON-RPC error message and an
//! unsupported content type go to the host log instead, sanitized, within a
//! budget of `LOG_LINES_PER_WINDOW` lines per `LOG_WINDOW` per transport; the
//! count of lines over the budget is logged with the first line of a later
//! window.
//!
//! ## Bounds
//!
//! - `MAX_JSONRPC_REQ_BYTES = 4 MiB` — request body cap.
//! - `MAX_SSE_TOTAL_BYTES = 4 MiB` — response body cap, JSON or SSE.
//! - `MAX_SSE_FRAME_BYTES = 1 MiB` — per-`event` block bytes.
//! - [`HttpOptions::request_timeout`] (default `MAX_SSE_WALL_CLOCK = 30 s`) —
//!   one POST through the chain, response included.
//! - [`HttpOptions::startup_timeout`] (default 10 s) — starting a session.
//!
//! ## Reading an answer
//!
//! A JSON body, or each SSE event's data, holds one message or a batch (a JSON
//! array). The answer is the message without `method` whose `id` is the
//! request's; a message carrying `method` (a server request or notification)
//! is skipped, whatever its `id`.
//!
//! The SSE parser implements the WHATWG subset this needs:
//!
//! - Lines split by `\n` (with `\r\n` normalized to `\n`).
//! - `:`-prefixed lines are comments → SKIP.
//! - Field lines parsed by colon-split (`event:`, `id:`, `retry:`, `data:`).
//! - Within each event block (terminated by blank line), all `data:` field
//!   values are concatenated with `\n` per WHATWG multi-line folding rule.
//! - `event:` names the block's type: an `endpoint` block marks the older
//!   transport. `id:` and `retry:` are ignored.
//!
//! SSE reconnect, `Last-Event-ID` and a standing GET stream for server-sent
//! messages are not implemented.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use advance_shared_types::security_validator::{
    HttpCapability, HttpError, HttpMethod, HttpRequest, HttpResponse, HttpSecurityChain,
};
use async_trait::async_trait;
use serde::Serialize;
use serde_json::Value;

use crate::client::{
    agreed_protocol_version, initialize_params, startup_timeout_error, with_step, McpTransport,
    DEFAULT_STARTUP_TIMEOUT,
};
use crate::error::{McpError, McpErrorKind};
use crate::jsonrpc::{JsonRpcNotification, JsonRpcRequest};
use crate::stdio_transport::{sanitize_log_text, LogBudget};

/// Maximum JSON-RPC request body bytes; rejects oversize requests at the
/// boundary before submitting to HttpSecurityChain. Matches `MAX_SSE_TOTAL_BYTES`
/// symmetry per MODULE-017 §2.11.
pub const MAX_JSONRPC_REQ_BYTES: usize = 4 * 1024 * 1024;

/// Total response body bytes the parser accepts, JSON or SSE; a larger body
/// fails the call with `transport-error`.
pub const MAX_SSE_TOTAL_BYTES: usize = 4 * 1024 * 1024;

/// Per-SSE-event-block bytes cap.
pub const MAX_SSE_FRAME_BYTES: usize = 1024 * 1024;

/// Default budget for one POST ([`HttpOptions::request_timeout`]). Matches
/// `tools.lazy_load_timeout_sec` default for operational consistency.
pub const MAX_SSE_WALL_CLOCK: Duration = Duration::from_secs(30);

/// Longest `Mcp-Session-Id` accepted, in bytes.
pub const MAX_SESSION_ID_BYTES: usize = 1024;

/// The header that carries the session id.
const SESSION_ID_HEADER: &str = "mcp-session-id";

/// The header that carries the agreed protocol version.
const PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";

/// Longest part of a server-sent text copied into the host log, in bytes.
const MAX_LOGGED_TEXT_BYTES: usize = 512;

/// What the error for a server on the older HTTP+SSE transport adds.
const OLD_TRANSPORT: &str = "servers on the older HTTP+SSE transport (a GET stream such as /sse \
                             with a separate message endpoint) are not supported; configure the \
                             server's Streamable HTTP endpoint";

/// How an http transport runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpOptions {
    /// Budget for one POST through the security chain, response included.
    pub request_timeout: Duration,
    /// Budget for starting a session: `initialize` and
    /// `notifications/initialized` together.
    pub startup_timeout: Duration,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            request_timeout: MAX_SSE_WALL_CLOCK,
            startup_timeout: DEFAULT_STARTUP_TIMEOUT,
        }
    }
}

/// The MCP session the transport speaks in.
#[derive(Clone, Debug, Default)]
struct Session {
    /// How many sessions the transport has started: a call that found the
    /// session ended restarts it only when no other call has meanwhile.
    epoch: u64,
    /// The `Mcp-Session-Id` the server assigned when the session started.
    id: Option<String>,
    /// The protocol version agreed when the session started.
    protocol_version: Option<&'static str>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// HTTP-routed MCP transport. Each `HttpMcpTransport` instance binds to one
/// server `(server_id, endpoint_url)` and a shared
/// `Arc<dyn HttpSecurityChain>` chain that enforces allowlist + SSRF +
/// leak-scan + credential-injection.
pub struct HttpMcpTransport {
    chain: Arc<dyn HttpSecurityChain>,
    server_id: String,
    endpoint_url: String,
    capability: HttpCapability,
    next_id: AtomicU64,
    options: HttpOptions,
    session: Mutex<Session>,
    /// Serializes session starts.
    restarting: tokio::sync::Mutex<()>,
    /// When a session restart failed; the transport carries no calls since.
    closed_at: Mutex<Option<Instant>>,
    /// The budget of host log lines this transport may write.
    log_budget: Mutex<LogBudget>,
}

impl HttpMcpTransport {
    /// A transport with the default [`HttpOptions`].
    pub fn new(
        chain: Arc<dyn HttpSecurityChain>,
        server_id: impl Into<String>,
        endpoint_url: impl Into<String>,
        capability: HttpCapability,
    ) -> Self {
        Self::with_options(
            chain,
            server_id,
            endpoint_url,
            capability,
            HttpOptions::default(),
        )
    }

    /// A transport with explicit timeouts.
    pub fn with_options(
        chain: Arc<dyn HttpSecurityChain>,
        server_id: impl Into<String>,
        endpoint_url: impl Into<String>,
        capability: HttpCapability,
        options: HttpOptions,
    ) -> Self {
        Self {
            chain,
            server_id: server_id.into(),
            endpoint_url: endpoint_url.into(),
            capability,
            next_id: AtomicU64::new(1),
            options,
            session: Mutex::new(Session::default()),
            restarting: tokio::sync::Mutex::new(()),
            closed_at: Mutex::new(None),
            log_budget: Mutex::new(LogBudget::new(Instant::now())),
        }
    }

    /// Monotonically allocate the next JSON-RPC request id.
    fn allocate_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    /// The protocol version agreed for the current session; `None` before
    /// [`initialize`](Self::initialize).
    pub fn protocol_version(&self) -> Option<&'static str> {
        self.session().protocol_version
    }

    /// The session id the server assigned to the current session, if any.
    pub fn session_id(&self) -> Option<String> {
        self.session().id.clone()
    }

    /// When the transport closed (a session restart failed); `None` while it
    /// is open.
    pub fn closed_at(&self) -> Option<Instant> {
        *lock(&self.closed_at)
    }

    /// Start a session within [`HttpOptions::startup_timeout`] (see the module
    /// docs) and return the agreed protocol version. The exchange is
    /// attributed to the server id.
    pub async fn initialize(&self) -> Result<&'static str, McpError> {
        self.fail_if_closed()?;
        let _start = self.restarting.lock().await;
        self.start_session_within_timeout().await
    }

    /// Invoke an MCP JSON-RPC method for `caller` (see the module docs),
    /// returning the `result` JSON bytes on success.
    ///
    /// Routes through `HttpSecurityChain::execute` so SSRF / allowlist /
    /// leak-scan / credential-injection all run before the bytes leave
    /// the host (AC-16 verification surface).
    pub async fn invoke(
        &self,
        caller: Option<&str>,
        method: &str,
        params: Value,
    ) -> Result<Vec<u8>, McpError> {
        self.fail_if_closed()?;
        let id = self.allocate_id();
        let body = message_body(&JsonRpcRequest::new(id, method, params))?;
        let response = self.send(caller, body).await?;
        self.answer(response, id)
    }

    /// Send a JSON-RPC notification (no id; the server sends no JSON-RPC
    /// answer). Any 2xx status, `202 Accepted` included, means the server took
    /// it; the response body is ignored.
    pub async fn notify(&self, method: &str, params: Option<Value>) -> Result<(), McpError> {
        self.fail_if_closed()?;
        let body = message_body(&JsonRpcNotification::new(method, params))?;
        let response = self.send(None, body).await?;
        accepted(&response)
    }

    /// POST `body` in the current session. When the server answers that it
    /// ended the session, start a new one and POST `body` once more.
    async fn send(&self, caller: Option<&str>, body: Vec<u8>) -> Result<HttpResponse, McpError> {
        let session = self.session().clone();
        // Only a session id makes a 404 mean "session ended", so only then can
        // the body be needed again.
        let resend = session.id.is_some().then(|| body.clone());
        let response = self.post(caller, &session, body).await?;
        match resend {
            Some(body) if response.status == 404 => {
                self.restart(session.epoch).await?;
                let session = self.session().clone();
                self.post(caller, &session, body).await
            }
            _ => Ok(response),
        }
    }

    /// Start a new session after the server ended session `ended`, unless
    /// another call has started one since. A restart that fails, or agrees a
    /// different protocol version, closes the transport.
    async fn restart(&self, ended: u64) -> Result<(), McpError> {
        let _start = self.restarting.lock().await;
        self.fail_if_closed()?;
        let (epoch, previous) = {
            let session = self.session();
            (session.epoch, session.protocol_version)
        };
        if epoch != ended {
            return Ok(());
        }
        let outcome = match self.start_session_within_timeout().await {
            Ok(version) if Some(version) == previous => Ok(()),
            Ok(_) => Err(McpError::invalid_response(
                "the server chose another protocol version for the new session",
            )),
            Err(error) => Err(error),
        };
        if outcome.is_err() {
            let mut closed_at = lock(&self.closed_at);
            closed_at.get_or_insert_with(Instant::now);
        }
        outcome.map_err(|e| with_step("session restart", e))
    }

    async fn start_session_within_timeout(&self) -> Result<&'static str, McpError> {
        let startup = self.options.startup_timeout;
        match tokio::time::timeout(startup, self.start_session()).await {
            Ok(result) => result,
            Err(_elapsed) => Err(startup_timeout_error(&self.server_id, startup)),
        }
    }

    /// The `initialize` exchange (see the module docs). The new session
    /// replaces the current one once the server's answer is accepted.
    async fn start_session(&self) -> Result<&'static str, McpError> {
        let id = self.allocate_id();
        let body = message_body(&JsonRpcRequest::new(id, "initialize", initialize_params()))?;
        let response = self
            .post(None, &Session::default(), body)
            .await
            .map_err(|e| with_step("initialize", e))?;
        if matches!(response.status, 404 | 405) {
            return Err(McpError::transport(format!(
                "initialize: http {}: the endpoint does not take MCP messages by POST; \
                 {OLD_TRANSPORT}",
                response.status
            )));
        }
        let session_id = session_id_of(&response);
        let result = self
            .answer(response, id)
            .map_err(|e| with_step("initialize", e))?;
        let session_id = session_id?;
        let version = agreed_protocol_version(&self.server_id, &result)?;
        let session = {
            let mut session = self.session();
            session.epoch += 1;
            session.id = session_id;
            session.protocol_version = Some(version);
            session.clone()
        };
        let body = message_body(&JsonRpcNotification::new("notifications/initialized", None))?;
        let response = self
            .post(None, &session, body)
            .await
            .map_err(|e| with_step("notifications/initialized", e))?;
        accepted(&response).map_err(|e| with_step("notifications/initialized", e))?;
        Ok(version)
    }

    /// POST one JSON-RPC message through the security chain in `session`, for
    /// `caller`, under the size cap and the request timeout.
    async fn post(
        &self,
        caller: Option<&str>,
        session: &Session,
        body: Vec<u8>,
    ) -> Result<HttpResponse, McpError> {
        if body.len() > MAX_JSONRPC_REQ_BYTES {
            return Err(McpError::new(
                McpErrorKind::TransportError,
                format!("jsonrpc request exceeds {MAX_JSONRPC_REQ_BYTES} bytes"),
            ));
        }
        let mut headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            (
                "accept".to_string(),
                "application/json, text/event-stream".to_string(),
            ),
        ];
        if let Some(version) = session.protocol_version {
            headers.push((PROTOCOL_VERSION_HEADER.to_string(), version.to_string()));
        }
        if let Some(id) = &session.id {
            headers.push((SESSION_ID_HEADER.to_string(), id.clone()));
        }
        let http_req = HttpRequest {
            method: HttpMethod::Post,
            url: self.endpoint_url.clone(),
            headers,
            body,
        };
        let agent = caller.unwrap_or(&self.server_id);
        tokio::time::timeout(
            self.options.request_timeout,
            self.chain.execute(agent, http_req, &self.capability),
        )
        .await
        .map_err(|_| McpError::transport("wall-clock timeout"))?
        .map_err(map_http_error)
    }

    /// The `result` of the answer to request `expected_id` in `response`.
    fn answer(&self, response: HttpResponse, expected_id: u64) -> Result<Vec<u8>, McpError> {
        if !(200..300).contains(&response.status) {
            return Err(McpError::server_error(format!(
                "http {} from mcp server",
                response.status
            )));
        }
        if response.body.is_empty() {
            return Err(McpError::invalid_response(format!(
                "http {}: the server sent no answer to the request",
                response.status
            )));
        }
        let content_type = header(&response, "content-type").unwrap_or_default();
        let media_type = content_type.split(';').next().unwrap_or_default().trim();
        let answer = if media_type.eq_ignore_ascii_case("application/json") {
            decode_single_json(&response.body, expected_id)?
        } else if media_type.eq_ignore_ascii_case("text/event-stream") {
            decode_sse(&response.body, expected_id)?
        } else {
            self.log(|| {
                format!(
                    "unsupported content-type {}",
                    sanitize_log_text(content_type.as_bytes(), MAX_LOGGED_TEXT_BYTES)
                )
            });
            return Err(McpError::transport("unsupported content-type"));
        };
        match answer {
            Answer::Result(bytes) => Ok(bytes),
            Answer::Error { code, message } => {
                let code = code.map_or_else(|| "?".to_string(), |c| c.to_string());
                self.log(|| {
                    format!(
                        "server error id={expected_id} code={code} message={}",
                        sanitize_log_text(message.as_bytes(), MAX_LOGGED_TEXT_BYTES)
                    )
                });
                Err(McpError::server_error(format!("jsonrpc error code {code}")))
            }
        }
    }

    fn session(&self) -> MutexGuard<'_, Session> {
        lock(&self.session)
    }

    fn fail_if_closed(&self) -> Result<(), McpError> {
        match self.closed_at() {
            Some(_) => Err(McpError::transport(
                "the server ended the session and a new one could not be started",
            )),
            None => Ok(()),
        }
    }

    /// Write one line about this server to the host log, unless the
    /// transport's log budget for the current window is spent. `line` is built
    /// only when the line is written.
    fn log(&self, line: impl FnOnce() -> String) {
        let (admitted, suppressed) = lock(&self.log_budget).admit(Instant::now());
        if let Some(count) = suppressed {
            eprintln!(
                "[cap_mcp http:{}] {count} log lines suppressed",
                self.server_id
            );
        }
        if admitted {
            eprintln!("[cap_mcp http:{}] {}", self.server_id, line());
        }
    }
}

/// A JSON-RPC message serialized for the wire.
fn message_body(message: &impl Serialize) -> Result<Vec<u8>, McpError> {
    serde_json::to_vec(message).map_err(|_| McpError::invalid_response("serialize request"))
}

/// The value of the first header named `name` (any case).
fn header<'a>(response: &'a HttpResponse, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// The session id the server assigned in its `initialize` answer.
fn session_id_of(response: &HttpResponse) -> Result<Option<String>, McpError> {
    match header(response, SESSION_ID_HEADER) {
        None => Ok(None),
        Some(id)
            if !id.is_empty()
                && id.len() <= MAX_SESSION_ID_BYTES
                && id.bytes().all(|b| (0x21..=0x7e).contains(&b)) =>
        {
            Ok(Some(id.to_string()))
        }
        Some(_) => Err(McpError::invalid_response(
            "initialize: the server sent an invalid Mcp-Session-Id",
        )),
    }
}

/// Whether a notification was accepted: any 2xx.
fn accepted(response: &HttpResponse) -> Result<(), McpError> {
    if (200..300).contains(&response.status) {
        Ok(())
    } else {
        Err(McpError::server_error(format!(
            "http {} from mcp server",
            response.status
        )))
    }
}

/// The answer to one request.
#[derive(Debug, PartialEq)]
enum Answer {
    /// The JSON-RPC `result`, serialized.
    Result(Vec<u8>),
    /// A JSON-RPC error: its code, and the head of its message, which goes to
    /// the host log only.
    Error { code: Option<i64>, message: String },
}

/// Decode a single `application/json` body: one message or a batch.
fn decode_single_json(body: &[u8], expected_id: u64) -> Result<Answer, McpError> {
    if body.len() > MAX_SSE_TOTAL_BYTES {
        return Err(McpError::transport(format!(
            "response body exceeds {MAX_SSE_TOTAL_BYTES} bytes"
        )));
    }
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| McpError::invalid_response("response is not JSON"))?;
    find_answer(value, expected_id)?
        .ok_or_else(|| McpError::invalid_response("the response does not answer the request"))
}

/// Parse the SSE body per the WHATWG subset described in the module docs and
/// return the answer to request `expected_id`.
fn decode_sse(body: &[u8], expected_id: u64) -> Result<Answer, McpError> {
    if body.len() > MAX_SSE_TOTAL_BYTES {
        return Err(McpError::transport(format!(
            "sse response body exceeds {MAX_SSE_TOTAL_BYTES} bytes"
        )));
    }
    let text = std::str::from_utf8(body)
        .map_err(|_| McpError::invalid_response("sse body is not utf-8"))?;
    let normalized = text.replace("\r\n", "\n");
    let mut block = SseBlock::default();
    let mut saw_endpoint = false;
    for line in normalized.split('\n') {
        if line.is_empty() {
            // End of an event block.
            if let Some(answer) = block.finish(expected_id, &mut saw_endpoint)? {
                return Ok(answer);
            }
            continue;
        }
        if line.starts_with(':') {
            // SSE comment — skip.
            continue;
        }
        // Split on the first colon to get field name + value.
        let (field, value) = match line.split_once(':') {
            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
            None => (line, ""), // line is just a field name; per WHATWG, value is empty
        };
        match field {
            "data" => {
                block.size = block.size.saturating_add(value.len()).saturating_add(1);
                if block.size > MAX_SSE_FRAME_BYTES {
                    return Err(McpError::transport(format!(
                        "sse event-block exceeds {MAX_SSE_FRAME_BYTES} bytes"
                    )));
                }
                block.data.push(value);
            }
            "event" => block.event = Some(value),
            // id:, retry:, and unknown fields are ignored.
            _ => {}
        }
    }
    // Body ended without a blank-line terminator: read the last block too.
    if let Some(answer) = block.finish(expected_id, &mut saw_endpoint)? {
        return Ok(answer);
    }
    if saw_endpoint {
        return Err(McpError::transport(format!(
            "the server answered with an `endpoint` event; {OLD_TRANSPORT}"
        )));
    }
    Err(McpError::invalid_response(format!(
        "no jsonrpc response with id={expected_id} in sse stream"
    )))
}

/// One SSE event block being read.
#[derive(Default)]
struct SseBlock<'a> {
    event: Option<&'a str>,
    data: Vec<&'a str>,
    size: usize,
}

impl SseBlock<'_> {
    /// End the block: the answer to `expected_id` when the block holds it. An
    /// `endpoint` block sets `saw_endpoint`. The block starts over empty.
    fn finish(
        &mut self,
        expected_id: u64,
        saw_endpoint: &mut bool,
    ) -> Result<Option<Answer>, McpError> {
        let block = std::mem::take(self);
        if block.event == Some("endpoint") {
            *saw_endpoint = true;
            return Ok(None);
        }
        if block.data.is_empty() {
            return Ok(None);
        }
        match serde_json::from_str::<Value>(&block.data.join("\n")) {
            Ok(value) => find_answer(value, expected_id),
            Err(_) => Ok(None),
        }
    }
}

/// The answer to request `expected_id` among the messages in `value` (one
/// message, or a batch): a message without `method` whose `id` is
/// `expected_id`.
fn find_answer(value: Value, expected_id: u64) -> Result<Option<Answer>, McpError> {
    let messages = match value {
        Value::Array(items) => items,
        other => vec![other],
    };
    for message in messages {
        let Value::Object(mut message) = message else {
            continue;
        };
        if message.contains_key("method")
            || message.get("id").and_then(Value::as_u64) != Some(expected_id)
        {
            continue;
        }
        if let Some(error) = message.remove("error").filter(|e| !e.is_null()) {
            let code = error.get("code").and_then(Value::as_i64);
            let head = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .chars()
                .take(MAX_LOGGED_TEXT_BYTES)
                .collect();
            return Ok(Some(Answer::Error {
                code,
                message: head,
            }));
        }
        return match message.remove("result") {
            Some(result) => serde_json::to_vec(&result)
                .map(|bytes| Some(Answer::Result(bytes)))
                .map_err(|_| McpError::invalid_response("serialize result")),
            None => Err(McpError::invalid_response(
                "jsonrpc response missing both result and error",
            )),
        };
    }
    Ok(None)
}

/// The caller-facing error for a chain refusal: fixed text only, never the
/// URL or findings the refusal carries.
fn map_http_error(err: HttpError) -> McpError {
    match err {
        HttpError::AllowlistBlocked(_) => {
            McpError::new(McpErrorKind::PermissionDenied, "allowlist blocked")
        }
        HttpError::LeakBlocked(_) => McpError::new(
            McpErrorKind::PermissionDenied,
            "outbound leak detected; request blocked",
        ),
        HttpError::InboundLeakBlocked(_) => {
            McpError::invalid_response("inbound leak detected; response sanitized away")
        }
        HttpError::SecretResolution(_) => {
            McpError::new(McpErrorKind::PermissionDenied, "secret resolution failure")
        }
        HttpError::SsrfBlocked(_) => McpError::new(McpErrorKind::PermissionDenied, "ssrf blocked"),
        HttpError::RateLimited { retry_after_ms } => {
            McpError::transport(format!("rate-limited; retry after {retry_after_ms} ms"))
        }
        HttpError::Transport(_) => McpError::transport("transport error"),
        HttpError::RedirectRejected { .. } => {
            McpError::new(McpErrorKind::PermissionDenied, "redirect rejected")
        }
        HttpError::InvalidUrl(_) => McpError::transport("invalid url"),
    }
}

// `McpClient` dispatches through `Arc<dyn McpTransport>`, so HTTP and stdio
// share one call site; each method delegates to the inherent one.
#[async_trait]
impl McpTransport for HttpMcpTransport {
    async fn invoke(
        &self,
        caller: Option<&str>,
        method: &str,
        params: Value,
    ) -> Result<Vec<u8>, McpError> {
        HttpMcpTransport::invoke(self, caller, method, params).await
    }

    async fn notify(&self, method: &str, params: Option<Value>) -> Result<(), McpError> {
        HttpMcpTransport::notify(self, method, params).await
    }

    fn server_id(&self) -> &str {
        HttpMcpTransport::server_id(self)
    }

    fn closed_at(&self) -> Option<Instant> {
        HttpMcpTransport::closed_at(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result_text(answer: Answer) -> String {
        match answer {
            Answer::Result(bytes) => String::from_utf8(bytes).unwrap(),
            other => panic!("expected a result, got {other:?}"),
        }
    }

    #[test]
    fn decode_single_json_round_trip() {
        let body = br#"{"jsonrpc":"2.0","id":7,"result":{"ok":true}}"#.to_vec();
        let out = decode_single_json(&body, 7).expect("decode ok");
        assert!(result_text(out).contains("\"ok\":true"));
    }

    #[test]
    fn decode_single_json_id_mismatch_rejected() {
        let body = br#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_vec();
        let err = decode_single_json(&body, 7).expect_err("must reject");
        assert_eq!(err.kind, McpErrorKind::InvalidResponse);
    }

    #[test]
    fn decode_sse_single_frame() {
        let body = b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"hello\":\"world\"}}\n\n";
        let out = decode_sse(body, 1).expect("decode");
        assert!(result_text(out).contains("hello"));
    }

    #[test]
    fn decode_sse_multiline_data_folded() {
        // Multi-line data: per WHATWG, joined with `\n`.
        let body =
            b"event: rpc\ndata: {\"jsonrpc\":\"2.0\",\ndata: \"id\":1,\ndata: \"result\":42}\n\n";
        let out = decode_sse(body, 1).expect("decode multi-line");
        assert_eq!(result_text(out), "42");
    }

    #[test]
    fn decode_sse_skips_comments() {
        let body = b": keepalive\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"ok\"}\n\n";
        let out = decode_sse(body, 1).expect("decode");
        assert!(result_text(out).contains("ok"));
    }

    #[test]
    fn decode_sse_oversize_total_rejected() {
        let huge = vec![b'x'; MAX_SSE_TOTAL_BYTES + 1];
        let err = decode_sse(&huge, 1).expect_err("must reject");
        assert_eq!(err.kind, McpErrorKind::TransportError);
        assert!(err.message.contains("exceeds"));
    }

    #[test]
    fn decode_sse_no_matching_id() {
        let body = b"data: {\"jsonrpc\":\"2.0\",\"id\":99,\"result\":1}\n\n";
        let err = decode_sse(body, 1).expect_err("no match");
        assert_eq!(err.kind, McpErrorKind::InvalidResponse);
    }

    #[test]
    fn decode_sse_oversize_frame_rejected() {
        // Single data: line over MAX_SSE_FRAME_BYTES but total under MAX_SSE_TOTAL_BYTES.
        let mut s = String::from("data: ");
        s.push_str(&"x".repeat(MAX_SSE_FRAME_BYTES + 100));
        s.push_str("\n\n");
        let err = decode_sse(s.as_bytes(), 1).expect_err("must reject");
        assert_eq!(err.kind, McpErrorKind::TransportError);
        assert!(err.message.contains("event-block"));
    }

    // A server request or notification never answers a call, whatever its id;
    // a batch is searched message by message.
    #[test]
    fn messages_carrying_method_are_never_answers() {
        let body = concat!(
            "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n\n",
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n",
            "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n",
        );
        assert_eq!(
            result_text(decode_sse(body.as_bytes(), 1).expect("the answer")),
            r#"{"ok":true}"#
        );
        let batch = br#"[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":9,"result":0},{"jsonrpc":"2.0","id":1,"result":{"ok":true}}]"#;
        assert_eq!(
            result_text(decode_single_json(batch, 1).expect("the answer")),
            r#"{"ok":true}"#
        );
        let only_a_request = br#"{"jsonrpc":"2.0","id":1,"method":"roots/list"}"#;
        assert!(decode_single_json(only_a_request, 1).is_err());
    }

    // A JSON-RPC error answer keeps the head of its message for the host log.
    #[test]
    fn an_error_answer_keeps_the_code_and_the_head_of_the_message() {
        let long = "m".repeat(MAX_LOGGED_TEXT_BYTES * 3);
        let body = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0", "id": 4, "error": {"code": -32000, "message": long}
        }))
        .unwrap();
        match decode_single_json(&body, 4).expect("an answer") {
            Answer::Error { code, message } => {
                assert_eq!(code, Some(-32000));
                assert_eq!(message.len(), MAX_LOGGED_TEXT_BYTES);
            }
            other => panic!("expected an error answer, got {other:?}"),
        }
    }
}

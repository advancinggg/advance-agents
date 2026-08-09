//! `HttpMcpTransport` — MODULE-017 Slice B MCP HTTP/SSE transport foundation.
//!
//! Routes JSON-RPC 2.0 over an `Arc<dyn HttpSecurityChain>` (CONTRACT-111),
//! parsing both `application/json` single-response and `text/event-stream`
//! streaming responses. Stdio transport is **out of scope** this slice
//! (deferred to Slice C per MODULE-017 §3.7).
//!
//! ## Bounds (Slice B foundation)
//!
//! - `MAX_JSONRPC_REQ_BYTES = 4 MiB` — request body cap.
//! - `MAX_SSE_TOTAL_BYTES = 4 MiB` — total accumulated SSE body bytes.
//! - `MAX_SSE_FRAME_BYTES = 1 MiB` — per-`event` block bytes.
//! - `MAX_SSE_WALL_CLOCK = 30 s` — overall response-read budget.
//!
//! ## SSE parser shape
//!
//! Implements a minimal WHATWG SSE subset sufficient for JSON-RPC matched-id
//! retrieval:
//!
//! - Lines split by `\n` (with `\r\n` normalized to `\n`).
//! - `:`-prefixed lines are comments → SKIP.
//! - Field lines parsed by colon-split (`event:`, `id:`, `retry:`, `data:`).
//! - Within each event block (terminated by blank line), all `data:` field
//!   values are concatenated with `\n` per WHATWG multi-line folding rule.
//! - `event:`, `id:`, `retry:` are parsed-but-ignored for the JSON-RPC
//!   matched-id flow (the MCP server may use them for stream metadata).
//! - For each completed event block, attempt to parse the concatenated data
//!   as [`JsonRpcResponse`]; if `id` matches the request id, return its
//!   `result` bytes.
//!
//! SSE reconnect, `Last-Event-ID`, server-push event filtering, and
//! `retry:` honored are out of scope (Slice C).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use advance_shared_types::security_validator::{
    HttpCapability, HttpError, HttpMethod, HttpRequest, HttpResponse, HttpSecurityChain,
};
use async_trait::async_trait;

use crate::client::McpTransport;
use crate::error::{McpError, McpErrorKind};
use crate::jsonrpc::{JsonRpcRequest, JsonRpcResponse};

/// Maximum JSON-RPC request body bytes; rejects oversize requests at the
/// boundary before submitting to HttpSecurityChain. Matches `MAX_SSE_TOTAL_BYTES`
/// symmetry per MODULE-017 §2.11.
pub const MAX_JSONRPC_REQ_BYTES: usize = 4 * 1024 * 1024;

/// Total SSE response body bytes the parser will accumulate before
/// rejecting with `transport-error`. Bounded for DoS-defense at the
/// transport boundary; matches the spec recommendation that an MCP HTTP/SSE
/// stream completes in a single connection.
pub const MAX_SSE_TOTAL_BYTES: usize = 4 * 1024 * 1024;

/// Per-SSE-event-block bytes cap.
pub const MAX_SSE_FRAME_BYTES: usize = 1024 * 1024;

/// Overall response-read wall-clock budget. Matches
/// `tools.lazy_load_timeout_sec` default for operational consistency.
pub const MAX_SSE_WALL_CLOCK: Duration = Duration::from_secs(30);

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
}

impl HttpMcpTransport {
    pub fn new(
        chain: Arc<dyn HttpSecurityChain>,
        server_id: impl Into<String>,
        endpoint_url: impl Into<String>,
        capability: HttpCapability,
    ) -> Self {
        Self {
            chain,
            server_id: server_id.into(),
            endpoint_url: endpoint_url.into(),
            capability,
            next_id: AtomicU64::new(1),
        }
    }

    /// Monotonically allocate the next JSON-RPC request id.
    fn allocate_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    /// Invoke an MCP JSON-RPC method, returning the `result` JSON bytes on
    /// success. `params` is a JSON value forwarded into the JSON-RPC
    /// request envelope.
    ///
    /// Routes through `HttpSecurityChain::execute` so SSRF / allowlist /
    /// leak-scan / credential-injection all run before the bytes leave
    /// the host (AC-16 verification surface).
    pub async fn invoke(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<Vec<u8>, McpError> {
        let id = self.allocate_id();
        let req = JsonRpcRequest::new(id, method, params);
        let body = serde_json::to_vec(&req)
            .map_err(|e| McpError::invalid_response(format!("serialize request: {e}")))?;
        if body.len() > MAX_JSONRPC_REQ_BYTES {
            return Err(McpError::new(
                McpErrorKind::TransportError,
                format!("jsonrpc request exceeds {MAX_JSONRPC_REQ_BYTES} bytes"),
            ));
        }
        let http_req = HttpRequest {
            method: HttpMethod::Post,
            url: self.endpoint_url.clone(),
            headers: vec![
                ("content-type".into(), "application/json".into()),
                (
                    "accept".into(),
                    "application/json, text/event-stream".into(),
                ),
            ],
            body,
        };
        let response = tokio::time::timeout(
            MAX_SSE_WALL_CLOCK,
            self.chain
                .execute(&self.server_id, http_req, &self.capability),
        )
        .await
        .map_err(|_| McpError::transport("wall-clock timeout"))?
        .map_err(map_http_error)?;
        self.decode_response(response, id)
    }

    fn decode_response(
        &self,
        response: HttpResponse,
        expected_id: u64,
    ) -> Result<Vec<u8>, McpError> {
        if response.status >= 400 {
            return Err(McpError::server_error(format!(
                "http {} from mcp server",
                response.status
            )));
        }
        let ct = response
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.to_lowercase())
            .unwrap_or_default();
        if ct.starts_with("application/json") {
            decode_single_json(&response.body, expected_id)
        } else if ct.starts_with("text/event-stream") {
            decode_sse(&response.body, expected_id)
        } else {
            Err(McpError::transport(format!(
                "unsupported content-type: {ct}"
            )))
        }
    }
}

/// Decode a single `application/json` JSON-RPC response.
fn decode_single_json(body: &[u8], expected_id: u64) -> Result<Vec<u8>, McpError> {
    if body.len() > MAX_SSE_TOTAL_BYTES {
        return Err(McpError::transport(format!(
            "response body exceeds {MAX_SSE_TOTAL_BYTES} bytes"
        )));
    }
    let resp: JsonRpcResponse = serde_json::from_slice(body)
        .map_err(|e| McpError::invalid_response(format!("parse response: {e}")))?;
    extract_result(resp, expected_id)
}

/// Parse the SSE body per the WHATWG minimal subset described in the
/// module rustdoc. Returns the `result` bytes of the JSON-RPC response
/// whose `id` matches `expected_id`.
fn decode_sse(body: &[u8], expected_id: u64) -> Result<Vec<u8>, McpError> {
    if body.len() > MAX_SSE_TOTAL_BYTES {
        return Err(McpError::transport(format!(
            "sse response body exceeds {MAX_SSE_TOTAL_BYTES} bytes"
        )));
    }
    let text = std::str::from_utf8(body)
        .map_err(|_| McpError::invalid_response("sse body is not utf-8"))?;
    let normalized = text.replace("\r\n", "\n");
    let mut current_data: Vec<String> = Vec::new();
    let mut current_size: usize = 0;
    for line in normalized.split('\n') {
        if line.is_empty() {
            // End of an event block: try parse the accumulated data.
            if !current_data.is_empty() {
                let payload = current_data.join("\n");
                if let Ok(resp) = serde_json::from_str::<JsonRpcResponse>(&payload) {
                    if resp.id == expected_id {
                        return extract_result(resp, expected_id);
                    }
                }
                current_data.clear();
                current_size = 0;
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
                current_size = current_size.saturating_add(value.len()).saturating_add(1);
                if current_size > MAX_SSE_FRAME_BYTES {
                    return Err(McpError::transport(format!(
                        "sse event-block exceeds {MAX_SSE_FRAME_BYTES} bytes"
                    )));
                }
                current_data.push(value.to_string());
            }
            // event:, id:, retry:, and unknown fields — parsed-but-ignored for
            // the JSON-RPC matched-id flow.
            _ => {}
        }
    }
    // Body ended without a blank-line terminator: try the last accumulated block.
    if !current_data.is_empty() {
        let payload = current_data.join("\n");
        if let Ok(resp) = serde_json::from_str::<JsonRpcResponse>(&payload) {
            if resp.id == expected_id {
                return extract_result(resp, expected_id);
            }
        }
    }
    Err(McpError::invalid_response(format!(
        "no jsonrpc response with id={expected_id} in sse stream"
    )))
}

fn extract_result(resp: JsonRpcResponse, expected_id: u64) -> Result<Vec<u8>, McpError> {
    if resp.id != expected_id {
        return Err(McpError::invalid_response(format!(
            "response id mismatch: got {} expected {}",
            resp.id, expected_id
        )));
    }
    if let Some(err) = resp.error {
        return Err(McpError::server_error(format!(
            "jsonrpc error {}: {}",
            err.code, err.message
        )));
    }
    let result = resp.result.ok_or_else(|| {
        McpError::invalid_response("jsonrpc response missing both result and error")
    })?;
    serde_json::to_vec(&result)
        .map_err(|e| McpError::invalid_response(format!("serialize result: {e}")))
}

fn map_http_error(err: HttpError) -> McpError {
    match err {
        HttpError::AllowlistBlocked(url) => McpError::new(
            McpErrorKind::PermissionDenied,
            format!("allowlist blocked: {url}"),
        ),
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

// Slice D additive trait impl — `McpClient` dispatches via `Arc<dyn McpTransport>`
// so HTTP and stdio share the same call site. Explicitly delegates to the
// inherent `HttpMcpTransport::invoke` to keep SB-13..SB-17b's behaviour
// byte-identical (the inherent path is unambiguous unless callers explicitly
// import the `McpTransport` trait into scope).
#[async_trait]
impl McpTransport for HttpMcpTransport {
    async fn invoke(&self, method: &str, params: serde_json::Value) -> Result<Vec<u8>, McpError> {
        HttpMcpTransport::invoke(self, method, params).await
    }

    fn server_id(&self) -> &str {
        HttpMcpTransport::server_id(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_single_json_round_trip() {
        let body = br#"{"jsonrpc":"2.0","id":7,"result":{"ok":true}}"#.to_vec();
        let out = decode_single_json(&body, 7).expect("decode ok");
        assert!(std::str::from_utf8(&out).unwrap().contains("\"ok\":true"));
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
        assert!(std::str::from_utf8(&out).unwrap().contains("hello"));
    }

    #[test]
    fn decode_sse_multiline_data_folded() {
        // Multi-line data: per WHATWG, joined with `\n`.
        let body =
            b"event: rpc\ndata: {\"jsonrpc\":\"2.0\",\ndata: \"id\":1,\ndata: \"result\":42}\n\n";
        let out = decode_sse(body, 1).expect("decode multi-line");
        assert_eq!(std::str::from_utf8(&out).unwrap(), "42");
    }

    #[test]
    fn decode_sse_skips_comments() {
        let body = b": keepalive\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"ok\"}\n\n";
        let out = decode_sse(body, 1).expect("decode");
        assert!(std::str::from_utf8(&out).unwrap().contains("ok"));
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
}

//! Integration tests for `HttpMcpTransport` — SB-13..SB-17 + SB-17b.
//!
//! Use a locally-defined `MockHttpSecurityChain` that captures the request
//! + returns scripted responses, mirroring the cap-llm test pattern at
//! `cap-llm/src/test_support/mock_chain.rs`. Verifies the AC-16 invariant
//! that every MCP HTTP invocation routes through HttpSecurityChain.

use std::sync::{Arc, Mutex};

use advance_shared_types::security_validator::{
    Allowlist, HttpCapability, HttpError, HttpRequest, HttpResponse, HttpSecurityChain,
};
use async_trait::async_trait;

use cap_mcp::{HttpMcpTransport, McpErrorKind};

#[derive(Default)]
struct MockChain {
    scripted: Mutex<Vec<Result<HttpResponse, HttpError>>>,
    captured: Mutex<Vec<HttpRequest>>,
}

impl MockChain {
    fn push(&self, resp: Result<HttpResponse, HttpError>) {
        self.scripted.lock().unwrap().push(resp);
    }

    fn captured(&self) -> Vec<HttpRequest> {
        self.captured.lock().unwrap().clone()
    }
}

#[async_trait]
impl HttpSecurityChain for MockChain {
    async fn execute(
        &self,
        _agent_id: &str,
        req: HttpRequest,
        _cap: &HttpCapability,
    ) -> Result<HttpResponse, HttpError> {
        self.captured.lock().unwrap().push(req);
        let mut q = self.scripted.lock().unwrap();
        if q.is_empty() {
            return Err(HttpError::Transport(
                advance_shared_types::security_validator::TransportErrorKind::Other,
            ));
        }
        q.remove(0)
    }
}

fn dummy_cap() -> HttpCapability {
    HttpCapability {
        allowlist: Allowlist {
            patterns: vec!["*.example.com".to_string()],
        },
        credentials: vec![],
        component_id: "test-server".into(),
    }
}

fn ok_response(body: &[u8], content_type: &str) -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: vec![("content-type".into(), content_type.into())],
        body: body.to_vec(),
    }
}

// ─────────────────────────────────────────────────────────────────────────
// SB-13 — HTTP path round-trips a single JSON-RPC application/json response.
// ─────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sb_13_http_invoke_round_trips_json_rpc() {
    let chain = Arc::new(MockChain::default());
    // The transport allocates id 1 for the first request.
    let body = br#"{"jsonrpc":"2.0","id":1,"result":{"tools":["a","b"]}}"#;
    chain.push(Ok(ok_response(body, "application/json")));

    let transport = HttpMcpTransport::new(
        chain.clone(),
        "test-server",
        "https://mcp.example.com/v1",
        dummy_cap(),
    );
    let out = transport
        .invoke("list-tools", serde_json::json!({}))
        .await
        .expect("invoke ok");
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(parsed["tools"], serde_json::json!(["a", "b"]));
}

// ─────────────────────────────────────────────────────────────────────────
// SB-14 — SSE path: single-frame text/event-stream parsed correctly.
// ─────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sb_14_sse_frame_decoded() {
    let chain = Arc::new(MockChain::default());
    let body = b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n";
    chain.push(Ok(ok_response(body, "text/event-stream")));

    let transport = HttpMcpTransport::new(
        chain.clone(),
        "sse-server",
        "https://mcp.example.com/sse",
        dummy_cap(),
    );
    let out = transport
        .invoke("subscribe", serde_json::json!({}))
        .await
        .expect("sse invoke ok");
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(parsed["ok"], serde_json::json!(true));
}

// ─────────────────────────────────────────────────────────────────────────
// SB-15 — Chain integration: every invoke calls HttpSecurityChain.execute
// exactly once (AC-16 surface-presence proof).
// ─────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sb_15_routes_through_http_security_chain() {
    let chain = Arc::new(MockChain::default());
    chain.push(Ok(ok_response(
        br#"{"jsonrpc":"2.0","id":1,"result":1}"#,
        "application/json",
    )));

    let transport = HttpMcpTransport::new(
        chain.clone(),
        "srv",
        "https://api.example.com/mcp",
        dummy_cap(),
    );
    let _ = transport
        .invoke("ping", serde_json::json!({}))
        .await
        .expect("ok");
    let captured = chain.captured();
    assert_eq!(
        captured.len(),
        1,
        "chain should be called exactly once per invoke"
    );
    let req = &captured[0];
    assert_eq!(req.url, "https://api.example.com/mcp");
    assert!(req
        .headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v == "application/json"));
    let req_json: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(req_json["jsonrpc"], "2.0");
    assert_eq!(req_json["method"], "ping");
}

// ─────────────────────────────────────────────────────────────────────────
// SB-16 — Oversize response body rejected at decode boundary.
// ─────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sb_16_oversize_response_rejected() {
    let chain = Arc::new(MockChain::default());
    // 5 MiB body — exceeds MAX_SSE_TOTAL_BYTES = 4 MiB.
    let huge = vec![b'x'; 5 * 1024 * 1024];
    chain.push(Ok(ok_response(&huge, "application/json")));

    let transport = HttpMcpTransport::new(
        chain.clone(),
        "srv",
        "https://api.example.com/mcp",
        dummy_cap(),
    );
    let err = transport
        .invoke("big", serde_json::json!({}))
        .await
        .expect_err("must reject");
    assert_eq!(err.kind, McpErrorKind::TransportError);
    assert!(err.message.contains("exceeds"));
}

// ─────────────────────────────────────────────────────────────────────────
// SB-17 — Oversize SSE total bytes rejected.
// ─────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sb_17_sse_total_byte_cap_enforced() {
    let chain = Arc::new(MockChain::default());
    let huge = vec![b'x'; 5 * 1024 * 1024];
    chain.push(Ok(ok_response(&huge, "text/event-stream")));

    let transport = HttpMcpTransport::new(
        chain.clone(),
        "srv",
        "https://api.example.com/sse",
        dummy_cap(),
    );
    let err = transport
        .invoke("big", serde_json::json!({}))
        .await
        .expect_err("must reject");
    assert_eq!(err.kind, McpErrorKind::TransportError);
}

// ─────────────────────────────────────────────────────────────────────────
// SB-17b — SSE multi-line data: folded with `\n` per WHATWG spec.
// ─────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sb_17b_sse_multiline_data_folding() {
    let chain = Arc::new(MockChain::default());
    let body = b": keepalive comment\nevent: rpc-response\ndata: {\"jsonrpc\":\"2.0\",\ndata: \"id\":1,\ndata: \"result\":{\"value\":42}}\n\n";
    chain.push(Ok(ok_response(body, "text/event-stream")));

    let transport = HttpMcpTransport::new(
        chain.clone(),
        "srv",
        "https://api.example.com/sse",
        dummy_cap(),
    );
    let out = transport
        .invoke("rpc", serde_json::json!({}))
        .await
        .expect("multi-line ok");
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(parsed["value"], 42);
}

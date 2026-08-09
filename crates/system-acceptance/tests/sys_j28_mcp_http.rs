//! SYS-J-28 — an MCP tool invoked over an HTTP transport that passes through the
//! cap-http security chain (allowlist / SSRF / leak / credential), returning the result.
//! Chain: MODULE-017 (cap-mcp) → MODULE-012 (cap-http security) → MODULE-019.
//!
//! Witnessed test-local against the REAL `cap_mcp::McpClient` + REAL `HttpMcpTransport`
//! routing JSON-RPC through the REAL `cap_http::DefaultHttpSecurityChain` (real
//! `ReqwestHttpExecutor` doing a REAL TCP request to a local axum MCP server). Only the
//! external MCP server is doubled; no transport/security module is mocked.
//!
//! In-scope SYS-AC: 086, 087, 088, 089, 220, 221.
//!
//! Note on events: the parenthetical `(http.blocked/security.ssrf_blocked)` in SYS-AC-087
//! names taxonomy event types never emitted by product code; the block BEHAVIOUR (no
//! outbound reaches the target) is the witnessed observable. `McpError` has no
//! `connection-failed` variant (SYS-AC-220 doc label); the unreachable leg surfaces
//! `transport-error`.

#[path = "e_support/mod.rs"]
mod e_support;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use advance_shared_types::security_validator::{Allowlist, HttpCapability, HttpSecurityChain};
use cap_http::DefaultHttpSecurityChain;
use cap_mcp::{
    McpClient, McpErrorKind, McpServerEntry, McpServersConfig, McpTransportSpec, ToolPattern,
};
use e_support::*;

const ENDPOINT: &str = "http://mcp.test/rpc";

/// Build a real `McpClient` with one HTTP server `"srv"` whose transport routes through a
/// real cap-http chain (configurable allowlist / SSRF map / dns override / tool patterns).
fn mcp_client(
    allowlist: &[&str],
    ssrf: &[(&str, &str)],
    dns: &[(String, SocketAddr)],
    tools: &[&str],
) -> McpClient {
    let cap = HttpCapability {
        allowlist: Allowlist {
            patterns: allowlist.iter().map(|s| s.to_string()).collect(),
        },
        credentials: Vec::new(),
        component_id: "srv".into(),
    };
    let chain: Arc<dyn HttpSecurityChain> = Arc::new(DefaultHttpSecurityChain::new(
        empty_secret_store(),
        leak(),
        ssrf_guard(ssrf),
        rate_allow(),
        reqwest_executor(dns),
    ));
    let config = McpServersConfig::builder()
        .add_server(McpServerEntry {
            server_id: "srv".into(),
            description: "track-e mcp http".into(),
            transport: McpTransportSpec::Http {
                endpoint_url: ENDPOINT.into(),
                capability: cap,
            },
            tool_patterns: Some(
                tools
                    .iter()
                    .map(|t| ToolPattern::compile(t).expect("pattern"))
                    .collect(),
            ),
            tool_schemas: BTreeMap::new(),
        })
        .expect("add server")
        .build();
    McpClient::new(Arc::new(config), leak(), Some(chain))
}

/// Build a JSON-RPC success response echoing the request's id with `result`.
fn mcp_response(req: &RecordedReq, result: serde_json::Value) -> BackendResp {
    let id = serde_json::from_slice::<serde_json::Value>(&req.body)
        .ok()
        .and_then(|v| v.get("id").and_then(|i| i.as_u64()))
        .unwrap_or(1);
    let body = serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string();
    BackendResp::ok_json(&body)
}

fn dead_addr() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let a = l.local_addr().expect("addr");
    drop(l); // free the port → connection refused
    a
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_086_invoke_tool_over_http_transport_through_chain() {
    let backend = Backend::spawn("mcp.test", |_, req| {
        mcp_response(req, serde_json::json!({"ok": true, "tool": "echo"}))
    })
    .await;
    let client = mcp_client(
        &["mcp.test"],
        &[("mcp.test", PUBLIC_IP)],
        &[backend.dns_override()],
        &["echo"],
    );

    let out = client
        .invoke_tool("srv", "echo", br#"{"x":1}"#)
        .await
        .expect("tool result returned after passing the cap-http chain");
    let parsed: serde_json::Value = serde_json::from_slice(&out).expect("result json");
    assert_eq!(parsed["ok"], serde_json::json!(true));
    assert_eq!(
        backend.recorded().len(),
        1,
        "exactly one real HTTP request reached the MCP server"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_087_non_allowlisted_or_ssrf_host_rejected_no_outbound() {
    // (a) endpoint host not on the allowlist → blocked at the chain; no server hit.
    let client_a = mcp_client(&["other.test"], &[("mcp.test", PUBLIC_IP)], &[], &["echo"]);
    let err_a = client_a
        .invoke_tool("srv", "echo", br#"{}"#)
        .await
        .expect_err("non-allowlisted MCP host blocked");
    assert_eq!(err_a.kind, McpErrorKind::PermissionDenied, "got {err_a:?}");

    // (b) endpoint host resolves to a private IP → SSRF-blocked at the chain; no server hit.
    let client_b = mcp_client(&["mcp.test"], &[("mcp.test", PRIVATE_IP)], &[], &["echo"]);
    let err_b = client_b
        .invoke_tool("srv", "echo", br#"{}"#)
        .await
        .expect_err("SSRF MCP host blocked");
    assert_eq!(err_b.kind, McpErrorKind::PermissionDenied, "got {err_b:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_088_tool_not_found_for_unregistered_tool() {
    // Only "echo" is allowed by tool-patterns; "delete-all" is rejected before transport.
    let client = mcp_client(&["mcp.test"], &[("mcp.test", PUBLIC_IP)], &[], &["echo"]);
    let err = client
        .invoke_tool("srv", "delete-all", br#"{}"#)
        .await
        .expect_err("unregistered tool is rejected");
    assert_eq!(err.kind, McpErrorKind::ToolNotFound, "got {err:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_089_inbound_credential_in_response_blocked_before_guest() {
    // The MCP server returns a result carrying a Block-class credential; the chain's
    // inbound leak scan blocks it → the credential bytes never reach the caller.
    let backend = Backend::spawn("mcp.test", |_, req| {
        mcp_response(req, serde_json::json!({"data": SECRET_OPENAI}))
    })
    .await;
    let client = mcp_client(
        &["mcp.test"],
        &[("mcp.test", PUBLIC_IP)],
        &[backend.dns_override()],
        &["echo"],
    );
    let err = client
        .invoke_tool("srv", "echo", br#"{}"#)
        .await
        .expect_err("inbound credential in the MCP response is blocked");
    assert_eq!(err.kind, McpErrorKind::InvalidResponse, "got {err:?}");
    assert!(
        !err.message.contains("sk-proj"),
        "the credential is not echoed into the guest-visible error"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_220_unreachable_server_surfaces_transport_error() {
    // dns_override points the MCP host at a closed port → connection refused → transport error.
    let dns = vec![("mcp.test".to_string(), dead_addr())];
    let client = mcp_client(&["mcp.test"], &[("mcp.test", PUBLIC_IP)], &dns, &["echo"]);
    let err = client
        .invoke_tool("srv", "echo", br#"{}"#)
        .await
        .expect_err("unreachable MCP server surfaces a transport error (not a hang)");
    assert_eq!(err.kind, McpErrorKind::TransportError, "got {err:?}");
}

/// Spawn an MCP backend that returns a fixed-size body of `n` bytes (status 200).
async fn oversize_backend(n: usize) -> Backend {
    Backend::spawn("mcp.test", move |_, _| BackendResp {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())],
        body: vec![b'x'; n],
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_221_oversize_response_aborted_not_buffered_unboundedly() {
    // The criterion's literal 4 MiB transport SSE bound is UNREACHABLE through the real
    // chain — it is shadowed by two earlier reachable limits. This test pins BOTH reachable
    // oversize-abort thresholds, proving an oversize response is always aborted rather than
    // buffered unboundedly:
    //
    //   (a) > 1 MiB body  → step-8 inbound leak scan fails closed (MAX_SCAN_BYTES = 1 MiB)
    //                       → InboundLeakBlocked → McpError::InvalidResponse.
    //   (b) > 8 MiB body  → executor streaming cap (DEFAULT_MAX_RESPONSE_BYTES = 8 MiB)
    //                       aborts mid-stream → HttpError::Transport → McpError::TransportError.
    //
    // The 4 MiB transport bound never fires because (a) blocks any body over 1 MiB first;
    // a regression to the (dead) transport bound is unobservable, but a regression that
    // removed either the 1 MiB scan-overflow or the 8 MiB executor cap WOULD be caught here.

    // (a) 2 MiB → scan-overflow abort (invalid-response). Not buffered past the scan cap.
    let backend_scan = oversize_backend(2 * 1024 * 1024).await;
    let client_scan = mcp_client(
        &["mcp.test"],
        &[("mcp.test", PUBLIC_IP)],
        &[backend_scan.dns_override()],
        &["echo"],
    );
    let err_scan = client_scan
        .invoke_tool("srv", "echo", br#"{}"#)
        .await
        .expect_err("2 MiB response aborted at the 1 MiB scan-overflow");
    assert_eq!(
        err_scan.kind,
        McpErrorKind::InvalidResponse,
        "got {err_scan:?}"
    );

    // (b) 9 MiB → executor streaming-cap abort (transport-error). The criterion's
    //     "aborted with a transport error rather than buffered unboundedly".
    let backend_exec = oversize_backend(9 * 1024 * 1024).await;
    let client_exec = mcp_client(
        &["mcp.test"],
        &[("mcp.test", PUBLIC_IP)],
        &[backend_exec.dns_override()],
        &["echo"],
    );
    let err_exec = client_exec
        .invoke_tool("srv", "echo", br#"{}"#)
        .await
        .expect_err("9 MiB response aborted at the 8 MiB executor streaming cap");
    assert_eq!(
        err_exec.kind,
        McpErrorKind::TransportError,
        "got {err_exec:?}"
    );
}

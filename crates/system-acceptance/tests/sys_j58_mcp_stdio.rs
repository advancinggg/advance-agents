//! SYS-J-58 — an MCP tool over a stdio-transport server: spawn a managed subprocess,
//! exchange line-framed JSON-RPC, run the inbound LeakDetector, return the result, and
//! tear down the subprocess on drop.
//! Chain: MODULE-017 (cap-mcp) → MODULE-012 (cap-http LeakDetector) → MODULE-019.
//!
//! Witnessed test-local against the REAL `cap_mcp::McpClient` + REAL `StdioMcpTransport`
//! spawning a REAL `bash` subprocess speaking line-framed JSON-RPC over stdin/stdout, with
//! the REAL `cap_http::DefaultLeakDetector` scanning each inbound line. Only the external
//! subprocess peer is the boundary; no transport/scan module is mocked.
//!
//! In-scope SYS-AC: 180, 181, 182, 255.

#[path = "e_support/mod.rs"]
mod e_support;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use cap_mcp::{
    McpClient, McpErrorKind, McpServerEntry, McpServersConfig, McpTransportSpec, StdioMcpTransport,
    ToolPattern,
};
use e_support::*;

/// Minimal PATH so the subprocess can resolve coreutils (`head`/`tr`) — `env_clear()` in
/// `StdioMcpTransport::spawn` drops the host env (no secret leak); `read`/`printf`/`echo`
/// are bash builtins and need no PATH.
fn shell_env() -> BTreeMap<String, String> {
    let mut e = BTreeMap::new();
    e.insert(
        "PATH".to_string(),
        "/usr/bin:/bin:/usr/sbin:/sbin".to_string(),
    );
    e
}

/// A real `McpClient` with one stdio server `"srv"` running `bash -c <script>`.
fn stdio_client(script: &str) -> McpClient {
    let config = McpServersConfig::builder()
        .add_server(McpServerEntry {
            server_id: "srv".into(),
            description: "track-e mcp stdio".into(),
            transport: McpTransportSpec::Stdio {
                command: "bash".into(),
                args: vec!["-c".into(), script.into()],
                env: shell_env(),
            },
            tool_patterns: Some(vec![ToolPattern::compile("echo").expect("pattern")]),
            tool_schemas: BTreeMap::new(),
        })
        .expect("add server")
        .build();
    McpClient::new(Arc::new(config), leak(), None)
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_180_stdio_subprocess_json_rpc_round_trip() {
    // First invoke on a fresh transport allocates JSON-RPC id 1; the subprocess reads the
    // request line and replies with a matching-id result.
    let script = r#"read line; printf '{"jsonrpc":"2.0","id":1,"result":{"echoed":true}}\n'"#;
    let client = stdio_client(script);
    let out = client
        .invoke_tool("srv", "echo", br#"{"x":1}"#)
        .await
        .expect("stdio subprocess returns the tool result over line-framed JSON-RPC");
    let parsed: serde_json::Value = serde_json::from_slice(&out).expect("result json");
    assert_eq!(parsed["echoed"], serde_json::json!(true));
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_181_stdio_inbound_credential_blocked_by_leak_detector() {
    // The subprocess returns a result carrying a Block-class credential; the inbound
    // LeakDetector blocks the line → the credential bytes never reach the caller.
    let script = r#"read line; printf '{"jsonrpc":"2.0","id":1,"result":{"data":"sk-proj-AAAAAAAAAAAAAAAAAAAAAAAA"}}\n'"#;
    let client = stdio_client(script);
    let err = client
        .invoke_tool("srv", "echo", br#"{}"#)
        .await
        .expect_err("inbound credential in the stdio response is blocked");
    assert_eq!(err.kind, McpErrorKind::InvalidResponse, "got {err:?}");
    assert!(
        !err.message.contains("sk-proj"),
        "the credential is not echoed into the guest-visible error"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_182_subprocess_terminated_on_transport_drop() {
    // The subprocess writes its PID, then blocks on `read` (builtin) staying alive.
    let pid_path = std::env::temp_dir().join(format!("track-e-j58-{}.pid", std::process::id()));
    let _ = std::fs::remove_file(&pid_path);
    let script = format!("echo $$ > '{}'; read x", pid_path.display());

    let transport = StdioMcpTransport::spawn(
        "srv",
        "bash",
        &["-c".to_string(), script],
        &shell_env(),
        leak(),
    )
    .expect("spawn stdio subprocess");

    // Wait for the subprocess to publish its PID.
    let pid = read_pid(&pid_path).await.expect("subprocess wrote its PID");
    assert!(
        pid_alive(&pid),
        "subprocess is alive before the transport is dropped"
    );

    drop(transport); // Drop → start_kill() (SIGKILL) + kill_on_drop.

    // The subprocess exits (observable: the PID is no longer alive).
    let mut gone = false;
    for _ in 0..200 {
        if !pid_alive(&pid) {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let _ = std::fs::remove_file(&pid_path);
    assert!(
        gone,
        "subprocess (pid {pid}) terminated after the transport was dropped"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_255_oversize_stdio_line_aborted_with_transport_error() {
    // The subprocess emits a single response line exceeding MAX_STDIO_LINE_BYTES (4 MiB) →
    // the reader aborts with a transport error rather than buffering unboundedly.
    let script = r#"head -c 5000000 /dev/zero | tr '\0' x; echo"#;
    let client = stdio_client(script);
    let err = client
        .invoke_tool("srv", "echo", br#"{}"#)
        .await
        .expect_err("oversize stdio response line aborts with a transport error");
    assert_eq!(err.kind, McpErrorKind::TransportError, "got {err:?}");
}

/// Poll-read the subprocess PID file until it has content (bounded ~2s).
async fn read_pid(path: &std::path::Path) -> Option<String> {
    for _ in 0..100 {
        if let Ok(s) = std::fs::read_to_string(path) {
            let trimmed = s.trim().to_string();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    None
}

/// `kill -0 <pid>` — exit 0 iff the process exists.
fn pid_alive(pid: &str) -> bool {
    std::process::Command::new("kill")
        .args(["-0", pid])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

//! Slice D AC-17 — stdio transport (SD-01..SD-10d).
//!
//! Strategy: use shell-pipeline fixtures so each test scripts the subprocess
//! response inline. `bash -c "..."` snippets read stdin lines and emit
//! pre-formatted JSON-RPC responses on stdout. Each test scopes its transport
//! in an inner block so Drop fires before the test function returns; the
//! Drop impl aborts spawned tasks + start_kill's the child.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use advance_shared_types::security_validator::{Finding, LeakDetector, ScanContext, ScanResult};
use cap_mcp::{McpErrorKind, StdioMcpTransport};

// ─────────────────────────────────────────────────────────────────────────
// LeakDetector fixtures
// ─────────────────────────────────────────────────────────────────────────

struct NoOpDetector;
impl LeakDetector for NoOpDetector {
    fn scan(&self, _t: &str, _c: ScanContext) -> ScanResult {
        ScanResult::Clean
    }
    fn scan_headers(&self, _h: &[(String, String)]) -> ScanResult {
        ScanResult::Clean
    }
}

/// LeakDetector that returns Blocked iff the scanned text contains
/// `<LEAK-MARKER>`.
struct MarkerDetector {
    pub seen: Mutex<Vec<String>>,
}
impl LeakDetector for MarkerDetector {
    fn scan(&self, text: &str, _c: ScanContext) -> ScanResult {
        self.seen.lock().unwrap().push(text.to_string());
        if text.contains("<LEAK-MARKER>") {
            ScanResult::Blocked {
                findings: vec![Finding {
                    pattern_name: "marker".to_string(),
                    offset: 0,
                    length: text.len(),
                    action: advance_shared_types::security_validator::Action::Block,
                }],
            }
        } else {
            ScanResult::Clean
        }
    }
    fn scan_headers(&self, _h: &[(String, String)]) -> ScanResult {
        ScanResult::Clean
    }
}

fn bash(script: &str) -> (String, Vec<String>) {
    (
        "bash".to_string(),
        vec!["-c".to_string(), script.to_string()],
    )
}

fn empty_env() -> BTreeMap<String, String> {
    BTreeMap::new()
}

// ─────────────────────────────────────────────────────────────────────────
// SD-01 — echo round-trip (subprocess reads one line, echoes a JSON-RPC
// response with the same id).
// ─────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sd_01_echo_round_trip() {
    // The subprocess reads ONE line and emits a fixed response with id=1.
    // The transport allocates id=1 for the first invoke.
    let script = r#"
read line
printf '{"jsonrpc":"2.0","id":1,"result":{"v":1}}\n'
sleep 1
"#;
    let (cmd, args) = bash(script);
    let transport = StdioMcpTransport::spawn(
        "echo-srv",
        &cmd,
        &args,
        &empty_env(),
        Arc::new(NoOpDetector),
    )
    .expect("spawn");
    let out = transport
        .invoke("echo", serde_json::json!({"v": 1}))
        .await
        .expect("ok");
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(parsed["v"], serde_json::json!(1));
}

// ─────────────────────────────────────────────────────────────────────────
// SD-02 — id mismatch (subprocess returns wrong id; invoke times out via
// wall-clock since the pending slot waits for id=1).
// We use a SHORT wall-clock to keep the test fast.
// ─────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sd_02_id_mismatch_times_out() {
    let script = r#"
read line
printf '{"jsonrpc":"2.0","id":999,"result":{}}\n'
sleep 2
"#;
    let (cmd, args) = bash(script);
    let transport = StdioMcpTransport::spawn_with_wall_clock(
        "srv",
        &cmd,
        &args,
        &empty_env(),
        Arc::new(NoOpDetector),
        Duration::from_millis(300),
    )
    .expect("spawn");
    let err = transport
        .invoke("x", serde_json::json!({}))
        .await
        .expect_err("must timeout (or fail)");
    assert_eq!(err.kind, McpErrorKind::TransportError);
    // Either wall-clock or subprocess channel — both are acceptable for SD-02.
    assert!(
        err.message.contains("timeout") || err.message.contains("subprocess"),
        "msg={}",
        err.message
    );
}

// ─────────────────────────────────────────────────────────────────────────
// SD-03 — server returns JSON-RPC error envelope → McpErrorKind::ServerError
// ─────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sd_03_jsonrpc_error_envelope() {
    let script = r#"
read line
printf '{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"internal"}}\n'
sleep 1
"#;
    let (cmd, args) = bash(script);
    let transport =
        StdioMcpTransport::spawn("srv", &cmd, &args, &empty_env(), Arc::new(NoOpDetector))
            .expect("spawn");
    let err = transport
        .invoke("x", serde_json::json!({}))
        .await
        .expect_err("must error");
    assert_eq!(err.kind, McpErrorKind::ServerError);
    assert!(err.message.contains("-32603"));
    // Audit round 1 W9 redaction: server-supplied error.message is NOT
    // inlined into agent-facing error string (would be a prompt-injection
    // / exfil channel). Only the JSON-RPC error code stays in the message.
    assert!(!err.message.contains("internal"));
}

// ─────────────────────────────────────────────────────────────────────────
// SD-04 — subprocess exits immediately → TransportError containing "subprocess"
// ─────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sd_04_subprocess_exits_immediately() {
    let (cmd, args) = bash("exit 0");
    let transport = StdioMcpTransport::spawn_with_wall_clock(
        "srv",
        &cmd,
        &args,
        &empty_env(),
        Arc::new(NoOpDetector),
        Duration::from_millis(500),
    )
    .expect("spawn");
    let err = transport
        .invoke("x", serde_json::json!({}))
        .await
        .expect_err("must error");
    assert_eq!(err.kind, McpErrorKind::TransportError);
    assert!(err.message.contains("subprocess"), "msg={}", err.message);
}

// ─────────────────────────────────────────────────────────────────────────
// SD-05 — request body > MAX_STDIO_REQ_BYTES rejected at writer boundary
// (uses a 5 MiB string in params; writer task surfaces TransportError to
// invoke caller via the pending channel).
// ─────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sd_05_oversize_request_rejected() {
    let (cmd, args) = bash("sleep 5");
    let transport = StdioMcpTransport::spawn_with_wall_clock(
        "srv",
        &cmd,
        &args,
        &empty_env(),
        Arc::new(NoOpDetector),
        Duration::from_millis(500),
    )
    .expect("spawn");

    // 5 MiB string > MAX_STDIO_REQ_BYTES (4 MiB).
    let huge = "x".repeat(5 * 1024 * 1024);
    let err = transport
        .invoke("big", serde_json::json!({"v": huge}))
        .await
        .expect_err("oversize");
    assert_eq!(err.kind, McpErrorKind::TransportError);
    assert!(err.message.contains("exceeds"), "msg={}", err.message);
}

// ─────────────────────────────────────────────────────────────────────────
// SD-07 — wall-clock timeout
// ─────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sd_07_wall_clock_timeout() {
    let (cmd, args) = bash("sleep 5");
    let transport = StdioMcpTransport::spawn_with_wall_clock(
        "srv",
        &cmd,
        &args,
        &empty_env(),
        Arc::new(NoOpDetector),
        Duration::from_millis(200),
    )
    .expect("spawn");
    let err = transport
        .invoke("x", serde_json::json!({}))
        .await
        .expect_err("timeout");
    assert_eq!(err.kind, McpErrorKind::TransportError);
    assert!(err.message.contains("timeout"));
}

// ─────────────────────────────────────────────────────────────────────────
// SD-08 — concurrent invokes with out-of-order responses
// ─────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sd_08_concurrent_invokes_oneshot_correlation() {
    // Subprocess reads two lines, returns id=2 first then id=1.
    let script = r#"
read line1
read line2
printf '{"jsonrpc":"2.0","id":2,"result":{"who":"two"}}\n'
printf '{"jsonrpc":"2.0","id":1,"result":{"who":"one"}}\n'
sleep 1
"#;
    let (cmd, args) = bash(script);
    let transport = Arc::new(
        StdioMcpTransport::spawn("srv", &cmd, &args, &empty_env(), Arc::new(NoOpDetector))
            .expect("spawn"),
    );

    let t1 = Arc::clone(&transport);
    let t2 = Arc::clone(&transport);
    let h1 = tokio::spawn(async move { t1.invoke("a", serde_json::json!({})).await });
    let h2 = tokio::spawn(async move { t2.invoke("b", serde_json::json!({})).await });
    let (r1, r2) = (h1.await.unwrap(), h2.await.unwrap());
    let p1: serde_json::Value = serde_json::from_slice(&r1.expect("ok")).unwrap();
    let p2: serde_json::Value = serde_json::from_slice(&r2.expect("ok")).unwrap();
    // r1 should be the id=1 response, r2 should be id=2.
    assert_eq!(p1["who"], serde_json::json!("one"));
    assert_eq!(p2["who"], serde_json::json!("two"));
}

// ─────────────────────────────────────────────────────────────────────────
// SD-09 — empty command rejected
// ─────────────────────────────────────────────────────────────────────────
#[test]
fn sd_09_empty_command_rejected() {
    let err = StdioMcpTransport::spawn("srv", "", &[], &empty_env(), Arc::new(NoOpDetector))
        .expect_err("empty");
    assert_eq!(err.kind, McpErrorKind::TransportError);
    assert!(err.message.contains("empty command"));
}

// ─────────────────────────────────────────────────────────────────────────
// SD-10 — stderr captured to eprintln; response decode does NOT include stderr
// ─────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sd_10_stderr_not_returned_as_response() {
    let script = r#"
read line
echo "this is stderr noise" >&2
printf '{"jsonrpc":"2.0","id":1,"result":{"clean":"yes"}}\n'
sleep 1
"#;
    let (cmd, args) = bash(script);
    let transport =
        StdioMcpTransport::spawn("srv", &cmd, &args, &empty_env(), Arc::new(NoOpDetector))
            .expect("spawn");
    let out = transport
        .invoke("x", serde_json::json!({}))
        .await
        .expect("ok");
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(parsed["clean"], serde_json::json!("yes"));
    // The "stderr noise" string MUST NOT appear in the response body.
    let body_str = String::from_utf8_lossy(&out);
    assert!(
        !body_str.contains("stderr noise"),
        "stderr bytes leaked into response body: {body_str}"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// SD-10c — LeakDetector mock returns Blocked → invoke gets InvalidResponse
// ─────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sd_10c_leak_detector_blocks_response() {
    let script = r#"
read line
printf '{"jsonrpc":"2.0","id":1,"result":{"leaked":"<LEAK-MARKER>secret"}}\n'
sleep 1
"#;
    let (cmd, args) = bash(script);
    let detector = Arc::new(MarkerDetector {
        seen: Mutex::new(Vec::new()),
    });
    let transport = StdioMcpTransport::spawn("srv", &cmd, &args, &empty_env(), detector.clone())
        .expect("spawn");
    let err = transport
        .invoke("x", serde_json::json!({}))
        .await
        .expect_err("blocked");
    assert_eq!(err.kind, McpErrorKind::InvalidResponse);
    assert!(err.message.contains("inbound leak detected"));
    let seen = detector.seen.lock().unwrap();
    assert!(seen.iter().any(|s| s.contains("LEAK-MARKER")));
}

// ─────────────────────────────────────────────────────────────────────────
// SD-10e — adversarial round 1 C1: subprocess does NOT inherit host env vars
// (env_clear() must wipe parent env before envs() merges the explicit map)
// ─────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sd_10e_env_clear_isolates_subprocess() {
    // Set a fake "secret" env var on the host process. The subprocess MUST
    // NOT see it.
    std::env::set_var("CAP_MCP_TEST_SECRET", "should-not-leak");
    let script = r#"
read line
# Echo the env var content as the JSON-RPC result. If env_clear worked,
# the var is unset and bash returns empty string.
val="${CAP_MCP_TEST_SECRET:-NOT_SET}"
printf '{"jsonrpc":"2.0","id":1,"result":"%s"}\n' "$val"
sleep 1
"#;
    let (cmd, args) = bash(script);
    let transport =
        StdioMcpTransport::spawn("srv", &cmd, &args, &empty_env(), Arc::new(NoOpDetector))
            .expect("spawn");
    let out = transport
        .invoke("x", serde_json::json!({}))
        .await
        .expect("ok");
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    // The subprocess should see "NOT_SET" (the bash default) because the
    // host env was cleared before envs() was applied.
    assert_eq!(
        parsed.as_str().unwrap(),
        "NOT_SET",
        "env_clear failed: subprocess inherited host env var (value: {:?})",
        parsed
    );
    std::env::remove_var("CAP_MCP_TEST_SECRET");
}

// ─────────────────────────────────────────────────────────────────────────
// SD-10f — adversarial round 1 W1: outbound LeakDetector scans request body
// before writing to subprocess stdin. Marker in params bytes blocks send.
// ─────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sd_10f_outbound_leak_blocks_send() {
    // Subprocess that would echo (but we expect the writer to block before
    // sending anything).
    let script = r#"
read line
printf '{"jsonrpc":"2.0","id":1,"result":"got-it"}\n'
sleep 1
"#;
    let (cmd, args) = bash(script);
    let detector = Arc::new(MarkerDetector {
        seen: Mutex::new(Vec::new()),
    });
    let transport = StdioMcpTransport::spawn("srv", &cmd, &args, &empty_env(), detector.clone())
        .expect("spawn");
    // params contain the marker → writer-task leak scan blocks
    let err = transport
        .invoke(
            "tools/call",
            serde_json::json!({"name": "x", "arguments": {"oops": "<LEAK-MARKER>credential"}}),
        )
        .await
        .expect_err("outbound leak must block send");
    assert_eq!(err.kind, McpErrorKind::PermissionDenied);
    assert!(
        err.message.contains("outbound leak detected"),
        "msg: {}",
        err.message
    );
}

// ─────────────────────────────────────────────────────────────────────────
// SD-10d — subprocess closes mid-line (no trailing newline) → mid-line error
// ─────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn sd_10d_partial_line_at_eof() {
    // Emit a response WITHOUT trailing newline, then exit.
    let script = r#"
read line
printf '{"jsonrpc":"2.0","id":1,"result":42}'
"#;
    let (cmd, args) = bash(script);
    let transport = StdioMcpTransport::spawn_with_wall_clock(
        "srv",
        &cmd,
        &args,
        &empty_env(),
        Arc::new(NoOpDetector),
        Duration::from_millis(500),
    )
    .expect("spawn");
    let err = transport
        .invoke("x", serde_json::json!({}))
        .await
        .expect_err("partial");
    assert_eq!(err.kind, McpErrorKind::TransportError);
    // Accept either "mid-line" (deterministic protocol violation) or any other
    // subprocess-exited message that races with the writer task.
    assert!(err.message.contains("subprocess"), "msg={}", err.message);
}

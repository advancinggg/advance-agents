//! MODULE-017 AC-17 — stdio transport (SD-01..SD-10d), plus the stdio server
//! lifecycle through `McpClient` (initialize, eviction, backoff, runtime, calls
//! under way when the configuration changes).
//!
//! Strategy: use shell-pipeline fixtures so each test scripts the subprocess
//! response inline. `bash -c "..."` snippets read stdin lines and emit
//! pre-formatted JSON-RPC responses on stdout. Each test scopes its transport
//! in an inner block so Drop fires before the test function returns; the
//! Drop impl aborts spawned tasks + kills the child's process group.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use advance_shared_types::security_validator::{Finding, LeakDetector, ScanContext, ScanResult};
use cap_mcp::{
    McpClient, McpClientLimits, McpError, McpErrorKind, McpServerEntry, McpServersConfig,
    McpToolInfo, McpTransportSpec, StdioMcpTransport, StdioOptions, SUPPORTED_PROTOCOL_VERSIONS,
};

mod support;
use support::gate::CapturingBus;

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

// ─────────────────────────────────────────────────────────────────────────
// Server-to-client traffic, notifications and the bounded reader
// ─────────────────────────────────────────────────────────────────────────

const PATH_VALUE: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

fn path_env() -> BTreeMap<String, String> {
    BTreeMap::from([("PATH".to_string(), PATH_VALUE.to_string())])
}

fn lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

/// `kill -0 <pid>` — exit 0 iff the process exists.
fn pid_alive(pid: &str) -> bool {
    std::process::Command::new("kill")
        .args(["-0", pid])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Poll `condition` every 20 ms until it holds or `limit` passes.
async fn wait_until(mut condition: impl FnMut() -> bool, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    condition()
}

fn json_of(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).expect("result is json")
}

// A server `ping` carrying the id of the pending call is answered with an
// empty result and never resolves that call; a server notification is dropped.
#[tokio::test]
async fn a_server_ping_with_a_colliding_id_is_answered_and_never_answers_the_call() {
    let script = r#"
read -r req
printf '{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"hi"}}\n'
printf '{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
read -r pong
ok=false
case "$pong" in *'"id":1'*) case "$pong" in *'"result":{}'*) case "$pong" in *'"method"'*) ;; *) ok=true ;; esac ;; esac ;; esac
printf '{"jsonrpc":"2.0","id":1,"result":{"pong_ok":%s}}\n' "$ok"
sleep 1
"#;
    let (cmd, args) = bash(script);
    let transport = StdioMcpTransport::spawn_with_wall_clock(
        "srv",
        &cmd,
        &args,
        &empty_env(),
        Arc::new(NoOpDetector),
        Duration::from_secs(5),
    )
    .expect("spawn");
    let out = transport
        .invoke("x", serde_json::json!({}))
        .await
        .expect("the call gets its own answer");
    assert_eq!(json_of(&out), serde_json::json!({"pong_ok": true}));
}

// Any other server request gets JSON-RPC error -32601 (method not found), so
// a server waiting for an answer is not left hanging.
#[tokio::test]
async fn an_unknown_server_request_gets_method_not_found() {
    let script = r#"
read -r req
printf '{"jsonrpc":"2.0","id":"s-1","method":"sampling/createMessage","params":{}}\n'
read -r reply
ok=false
case "$reply" in *'"code":-32601'*) case "$reply" in *'"id":"s-1"'*) ok=true ;; esac ;; esac
printf '{"jsonrpc":"2.0","id":1,"result":{"refused":%s}}\n' "$ok"
sleep 1
"#;
    let (cmd, args) = bash(script);
    let transport = StdioMcpTransport::spawn_with_wall_clock(
        "srv",
        &cmd,
        &args,
        &empty_env(),
        Arc::new(NoOpDetector),
        Duration::from_secs(5),
    )
    .expect("spawn");
    let out = transport
        .invoke("x", serde_json::json!({}))
        .await
        .expect("the server answers after reading the refusal");
    assert_eq!(json_of(&out), serde_json::json!({"refused": true}));
}

// A notification is one line without an id.
#[tokio::test]
async fn notify_writes_one_line_without_an_id() {
    let script = r#"
read -r note
read -r req
ok=false
case "$note" in *'"method":"notifications/initialized"'*) case "$note" in *'"id"'*) ;; *) ok=true ;; esac ;; esac
printf '{"jsonrpc":"2.0","id":1,"result":{"note_ok":%s}}\n' "$ok"
sleep 1
"#;
    let (cmd, args) = bash(script);
    let transport = StdioMcpTransport::spawn_with_wall_clock(
        "srv",
        &cmd,
        &args,
        &empty_env(),
        Arc::new(NoOpDetector),
        Duration::from_secs(5),
    )
    .expect("spawn");
    transport
        .notify("notifications/initialized", None)
        .await
        .expect("written");
    let out = transport
        .invoke("x", serde_json::json!({}))
        .await
        .expect("answered");
    assert_eq!(json_of(&out), serde_json::json!({"note_ok": true}));
}

// The line cap holds while reading: a stdout line that never ends closes the
// transport at the cap instead of being buffered until the call times out,
// and the closed transport fails later calls at once with the same reason.
#[tokio::test]
async fn an_endless_stdout_line_closes_the_transport_at_the_line_cap() {
    let script = r#"
read -r req
while :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; done
"#;
    let (cmd, args) = bash(script);
    let transport = StdioMcpTransport::spawn_with_options(
        "srv",
        &cmd,
        &args,
        &empty_env(),
        Arc::new(NoOpDetector),
        StdioOptions {
            request_timeout: Duration::from_secs(20),
            max_line_bytes: 64 * 1024,
            ..StdioOptions::default()
        },
    )
    .expect("spawn");
    let started = Instant::now();
    let err = transport
        .invoke("x", serde_json::json!({}))
        .await
        .expect_err("the line overflows the cap");
    assert_eq!(err.kind, McpErrorKind::TransportError);
    assert!(
        err.message.contains("exceeds 65536 bytes"),
        "msg={}",
        err.message
    );
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(transport.is_closed());
    let again = transport
        .invoke("y", serde_json::json!({}))
        .await
        .expect_err("a closed transport fails at once");
    assert!(again.message.contains("exceeds"), "msg={}", again.message);
}

// A server that exits closes the transport; a later call fails at once rather
// than waiting out its budget.
#[tokio::test]
async fn a_server_that_exits_closes_the_transport() {
    let (cmd, args) = bash("exit 0");
    let transport = StdioMcpTransport::spawn_with_wall_clock(
        "srv",
        &cmd,
        &args,
        &empty_env(),
        Arc::new(NoOpDetector),
        Duration::from_secs(20),
    )
    .expect("spawn");
    assert!(wait_until(|| transport.is_closed(), Duration::from_secs(5)).await);
    let closed_at = transport
        .closed_at()
        .expect("a closed transport says when it closed");
    assert!(closed_at <= Instant::now());
    let started = Instant::now();
    let err = transport
        .invoke("x", serde_json::json!({}))
        .await
        .expect_err("closed");
    assert_eq!(err.kind, McpErrorKind::TransportError);
    assert!(err.message.contains("subprocess"), "msg={}", err.message);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(transport.closed_at(), Some(closed_at));
}

// A server request whose string id is too long to echo is dropped unanswered,
// so a server that never reads its stdin cannot pin large replies in the
// writer queue; a request with a short id is still answered.
#[tokio::test]
async fn a_server_request_with_an_overlong_id_is_dropped_unanswered() {
    let long_id = "i".repeat(129);
    let script = format!(
        r#"
read -r req
printf '{{"jsonrpc":"2.0","id":"{long_id}","method":"ping"}}\n'
printf '{{"jsonrpc":"2.0","id":"short","method":"ping"}}\n'
read -r reply
ok=false
case "$reply" in *'"id":"short"'*) ok=true ;; esac
printf '{{"jsonrpc":"2.0","id":1,"result":{{"first_reply_is_short":%s}}}}\n' "$ok"
sleep 1
"#
    );
    let (cmd, args) = bash(&script);
    let transport = StdioMcpTransport::spawn_with_wall_clock(
        "srv",
        &cmd,
        &args,
        &empty_env(),
        Arc::new(NoOpDetector),
        Duration::from_secs(5),
    )
    .expect("spawn");
    let out = transport
        .invoke("x", serde_json::json!({}))
        .await
        .expect("the server answers after reading one reply");
    assert_eq!(
        json_of(&out),
        serde_json::json!({"first_reply_is_short": true})
    );
}

// The server leads its own process group: dropping the transport also stops
// the processes it started (as `npx` / `uvx` wrappers do).
#[tokio::test]
async fn dropping_the_transport_stops_the_processes_the_server_started() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("grandchild");
    let script = format!("sleep 300 & echo $! > '{}'; read -r x", marker.display());
    let transport = StdioMcpTransport::spawn(
        "srv",
        "bash",
        &["-c".to_string(), script],
        &path_env(),
        Arc::new(NoOpDetector),
    )
    .expect("spawn");
    assert!(wait_until(|| !lines(&marker).is_empty(), Duration::from_secs(5)).await);
    let pid = lines(&marker)[0].clone();
    assert!(pid_alive(&pid), "the server's child {pid} runs");

    drop(transport);

    let stopped = wait_until(|| !pid_alive(&pid), Duration::from_secs(5)).await;
    if !stopped {
        let _ = std::process::Command::new("kill")
            .args(["-9", &pid])
            .status();
    }
    assert!(stopped, "the server's child {pid} outlived the transport");
}

// ─────────────────────────────────────────────────────────────────────────
// The stdio server lifecycle through McpClient
// ─────────────────────────────────────────────────────────────────────────

/// Records the server's pid, one line per start.
const LOG_START: &str = r#"
echo $$ >> '@DIR@/starts'
"#;

/// Answers `initialize` (id 1) with protocol version `@VERSION@`, then requires
/// `notifications/initialized` (without an id) as the next line. A message out
/// of order makes the server exit, which fails the caller's call.
const HANDSHAKE: &str = r#"
read -r init
case "$init" in *'"method":"initialize"'*'"id":1'*) ;; *) exit 3 ;; esac
case "$init" in *'"protocolVersion":"2025-06-18"'*) ;; *) exit 4 ;; esac
case "$init" in *'"clientInfo":{"name":"advance"'*) ;; *) exit 4 ;; esac
printf '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"@VERSION@","capabilities":{"tools":{}},"serverInfo":{"name":"t","version":"1"}}}\n'
read -r note
case "$note" in *'"method":"notifications/initialized"'*) ;; *) exit 5 ;; esac
case "$note" in *'"id"'*) exit 6 ;; esac
"#;

/// Answers every further request with `{"pid": <server pid>}`, echoing its id.
const SERVE: &str = r#"
while read -r line; do
  id=${line##*\"id\":}; id=${id%%[!0-9]*}
  printf '{"jsonrpc":"2.0","id":%s,"result":{"pid":%s}}\n' "$id" "$$"
done
"#;

/// Answers one further request like [`SERVE`], then exits.
const SERVE_ONCE: &str = r#"
read -r line
id=${line##*\"id\":}; id=${id%%[!0-9]*}
printf '{"jsonrpc":"2.0","id":%s,"result":{"pid":%s}}\n' "$id" "$$"
"#;

fn server_script(parts: &[&str], dir: &Path, version: &str) -> String {
    parts
        .concat()
        .replace("@DIR@", &dir.display().to_string())
        .replace("@VERSION@", version)
}

/// A client with one stdio server `srv` running `bash -c <script>`, given no
/// runtime for its stdio servers.
fn stdio_client_without_runtime(script: String, limits: McpClientLimits) -> McpClient {
    let config = McpServersConfig::builder()
        .add_server(McpServerEntry {
            server_id: "srv".into(),
            description: "stdio".into(),
            transport: McpTransportSpec::Stdio {
                command: "bash".into(),
                args: vec!["-c".into(), script],
                env: path_env(),
                cwd: None,
            },
            tool_patterns: None,
            tool_schemas: BTreeMap::new(),
        })
        .expect("add server")
        .build();
    McpClient::new(Arc::new(config), Arc::new(NoOpDetector), None).with_limits(limits)
}

/// [`stdio_client_without_runtime`] whose stdio servers run on the test's
/// runtime, which outlives the client.
fn stdio_client(script: String, limits: McpClientLimits) -> McpClient {
    stdio_client_without_runtime(script, limits).with_runtime(tokio::runtime::Handle::current())
}

// The first call initializes the server (`initialize`, then
// `notifications/initialized`) before the tool call, for every protocol version
// the client accepts.
#[tokio::test]
async fn the_client_initializes_a_stdio_server_before_its_first_call() {
    for version in SUPPORTED_PROTOCOL_VERSIONS {
        let dir = tempfile::tempdir().expect("tempdir");
        let client = stdio_client(
            server_script(&[HANDSHAKE, SERVE], dir.path(), version),
            McpClientLimits::default(),
        );
        let out = client
            .invoke_tool(None, "srv", "echo", br#"{"x":1}"#)
            .await
            .expect("initialized, then called");
        assert!(json_of(&out)["pid"].is_u64());
        assert_eq!(client.protocol_version("srv").as_deref(), Some(*version));
    }
}

// A server that chooses a protocol version the client does not speak is
// stopped before it receives anything else.
#[tokio::test]
async fn the_client_refuses_a_server_that_chooses_an_unsupported_protocol_version() {
    let dir = tempfile::tempdir().expect("tempdir");
    let script = r#"
read -r init
printf '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"1999-01-01","capabilities":{}}}\n'
while read -r more; do echo "$more" >> '@DIR@/after'; done
"#;
    let client = stdio_client(
        server_script(&[LOG_START, script], dir.path(), ""),
        McpClientLimits::default(),
    );
    let err = client
        .invoke_tool(None, "srv", "echo", b"{}")
        .await
        .expect_err("unsupported protocol version");
    assert_eq!(err.kind, McpErrorKind::InvalidResponse);
    assert!(
        err.message.contains("protocol version"),
        "msg={}",
        err.message
    );
    assert_eq!(client.protocol_version("srv"), None);
    let pid = lines(&dir.path().join("starts"))[0].clone();
    assert!(
        wait_until(|| !pid_alive(&pid), Duration::from_secs(5)).await,
        "the refused server is stopped"
    );
    assert!(lines(&dir.path().join("after")).is_empty());
}

// `initialize` is bounded by the startup timeout, and a server that misses it
// is stopped.
#[tokio::test]
async fn the_client_bounds_initialize_by_the_startup_timeout() {
    let dir = tempfile::tempdir().expect("tempdir");
    let script = r#"
read -r init
sleep 30
"#;
    let client = stdio_client(
        server_script(&[LOG_START, script], dir.path(), ""),
        McpClientLimits {
            startup_timeout: Duration::from_millis(300),
            ..McpClientLimits::default()
        },
    );
    let started = Instant::now();
    let err = client
        .invoke_tool(None, "srv", "echo", b"{}")
        .await
        .expect_err("initialize never answered");
    assert_eq!(err.kind, McpErrorKind::TransportError);
    assert!(err.message.contains("initialize"), "msg={}", err.message);
    assert!(started.elapsed() < Duration::from_secs(5));
    let pid = lines(&dir.path().join("starts"))[0].clone();
    assert!(
        wait_until(|| !pid_alive(&pid), Duration::from_secs(5)).await,
        "the silent server is stopped"
    );
}

// Concurrent first calls share one connection attempt: one server starts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_first_calls_start_one_server() {
    let dir = tempfile::tempdir().expect("tempdir");
    let client = Arc::new(stdio_client(
        server_script(&[LOG_START, HANDSHAKE, SERVE], dir.path(), "2025-06-18"),
        McpClientLimits::default(),
    ));
    let calls: Vec<_> = (0..8)
        .map(|_| {
            let client = Arc::clone(&client);
            tokio::spawn(async move { client.invoke_tool(None, "srv", "echo", b"{}").await })
        })
        .collect();
    for call in calls {
        call.await.expect("join").expect("call");
    }
    assert_eq!(lines(&dir.path().join("starts")).len(), 1);
}

// A server that dies is evicted; reconnecting waits out the backoff (calls in
// the window fail fast without starting a server), then a new server starts.
#[tokio::test]
async fn a_server_that_dies_is_restarted_after_the_backoff() {
    let dir = tempfile::tempdir().expect("tempdir");
    // The first server dies on its first tool call; later ones serve.
    let crash_once = r#"
if [ ! -e '@DIR@/crashed' ]; then read -r call; : > '@DIR@/crashed'; exit 1; fi
"#;
    let client = stdio_client(
        server_script(
            &[LOG_START, HANDSHAKE, crash_once, SERVE],
            dir.path(),
            "2025-06-18",
        ),
        McpClientLimits {
            restart_backoff_initial: Duration::from_millis(500),
            restart_backoff_max: Duration::from_secs(30),
            ..McpClientLimits::default()
        },
    );
    let starts = dir.path().join("starts");

    let died = client
        .invoke_tool(None, "srv", "echo", b"{}")
        .await
        .expect_err("the server dies during the call");
    assert_eq!(died.kind, McpErrorKind::TransportError);

    let waiting = client
        .invoke_tool(None, "srv", "echo", b"{}")
        .await
        .expect_err("inside the backoff window");
    assert_eq!(waiting.kind, McpErrorKind::TransportError);
    assert!(
        waiting.message.contains("retry in"),
        "msg={}",
        waiting.message
    );
    assert_eq!(
        lines(&starts).len(),
        1,
        "no server starts inside the window"
    );

    tokio::time::sleep(Duration::from_millis(700)).await;
    let out = client
        .invoke_tool(None, "srv", "echo", b"{}")
        .await
        .expect("a new server after the backoff");
    assert_eq!(lines(&starts).len(), 2);
    assert_eq!(
        json_of(&out)["pid"].to_string(),
        lines(&starts)[1],
        "the call is answered by the new server"
    );
}

// A client given an event bus reports each connection it makes and each death
// it finds, as the runtime: a server that dies during a call, then the server
// that replaces it after the backoff. Retiring a connection reports nothing.
#[tokio::test]
async fn the_client_reports_each_connection_and_each_death() {
    let dir = tempfile::tempdir().expect("tempdir");
    // The first server dies on its first tool call; later ones serve.
    let crash_once = r#"
if [ ! -e '@DIR@/crashed' ]; then read -r call; : > '@DIR@/crashed'; exit 1; fi
"#;
    let bus = CapturingBus::new();
    let client = stdio_client(
        server_script(&[HANDSHAKE, crash_once, SERVE], dir.path(), "2025-06-18"),
        McpClientLimits {
            restart_backoff_initial: Duration::from_millis(100),
            restart_backoff_max: Duration::from_secs(30),
            ..McpClientLimits::default()
        },
    )
    .with_event_bus(bus.clone());

    client
        .invoke_tool(Some("agent-1"), "srv", "echo", b"{}")
        .await
        .expect_err("the server dies during the call");
    assert_eq!(bus.types(), ["mcp.server_started", "mcp.server_died"]);

    tokio::time::sleep(Duration::from_millis(300)).await;
    client
        .invoke_tool(Some("agent-1"), "srv", "echo", b"{}")
        .await
        .expect("a new server after the backoff");
    client.disconnect("srv");

    assert_eq!(
        bus.types(),
        [
            "mcp.server_started",
            "mcp.server_died",
            "mcp.server_started"
        ]
    );
    let events = bus.events();
    assert!(events.iter().all(|e| e.agent_id == "runtime"), "{events:?}");
    assert_eq!(
        events[0].payload,
        serde_json::json!({"server_id": "srv", "transport": "stdio"})
    );
    assert_eq!(
        events[1].payload,
        serde_json::json!({"server_id": "srv", "exit_code": null})
    );
}

// A server that dies while idle is judged by when it died: the call that finds
// it closed, after the backoff counted from that death has passed, reconnects
// at once instead of starting a new wait.
#[tokio::test]
async fn a_server_that_died_while_idle_is_reconnected_once_its_backoff_has_passed() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Each server answers one tool call and exits right after.
    let client = stdio_client(
        server_script(
            &[LOG_START, HANDSHAKE, SERVE_ONCE],
            dir.path(),
            "2025-06-18",
        ),
        McpClientLimits {
            restart_backoff_initial: Duration::from_millis(300),
            restart_backoff_max: Duration::from_secs(30),
            ..McpClientLimits::default()
        },
    );
    let starts = dir.path().join("starts");
    client
        .invoke_tool(None, "srv", "echo", b"{}")
        .await
        .expect("the first server answers, then exits");

    // The server died young, so a wait follows its death; let it pass.
    tokio::time::sleep(Duration::from_millis(900)).await;
    let out = client
        .invoke_tool(None, "srv", "echo", b"{}")
        .await
        .expect("reconnected at once: the wait counted from the death is over");
    assert_eq!(lines(&starts).len(), 2);
    assert_eq!(json_of(&out)["pid"].to_string(), lines(&starts)[1]);
}

// A connection attempt that completes after `disconnect` retired its slot
// publishes nothing: its caller gets an error, its server is stopped, and the
// next call starts a new server.
#[tokio::test]
async fn a_connection_completing_after_disconnect_publishes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let slow_start = r#"
sleep 1
"#;
    let client = Arc::new(stdio_client(
        server_script(
            &[LOG_START, slow_start, HANDSHAKE, SERVE],
            dir.path(),
            "2025-06-18",
        ),
        McpClientLimits::default(),
    ));
    let starts = dir.path().join("starts");
    let first = {
        let client = Arc::clone(&client);
        tokio::spawn(async move { client.invoke_tool(None, "srv", "echo", b"{}").await })
    };
    assert!(wait_until(|| lines(&starts).len() == 1, Duration::from_secs(5)).await);

    client.disconnect("srv");

    let err = first
        .await
        .expect("join")
        .expect_err("the attempt's slot was retired");
    assert_eq!(err.kind, McpErrorKind::TransportError);
    assert!(err.message.contains("disconnected"), "msg={}", err.message);
    let first_pid = lines(&starts)[0].clone();
    assert!(
        wait_until(|| !pid_alive(&first_pid), Duration::from_secs(5)).await,
        "the retired attempt's server is stopped"
    );

    let out = client
        .invoke_tool(None, "srv", "echo", b"{}")
        .await
        .expect("a fresh connection");
    assert_eq!(lines(&starts).len(), 2);
    assert_eq!(json_of(&out)["pid"].to_string(), lines(&starts)[1]);
}

// ─────────────────────────────────────────────────────────────────────────
// Calls under way when the configuration changes
// ─────────────────────────────────────────────────────────────────────────

/// Records the server's pid and the tool it serves (`$TOOL`, which its entry
/// sets), one line per start.
const LOG_START_TOOL: &str = r#"
echo "$$ $TOOL" >> '@DIR@/starts'
"#;

/// The first server started waits, before it reads anything, until the test
/// creates `@DIR@/go`; later servers go on at once.
const FIRST_WAITS: &str = r#"
if mkdir '@DIR@/first' 2>/dev/null; then
  while [ ! -e '@DIR@/go' ]; do sleep 0.02; done
fi
"#;

/// On the first server started, the first request after the handshake is
/// recorded in `@DIR@/held` and answered like [`SERVE_TOOL`] only once the test
/// creates `@DIR@/go`; later servers answer at once.
const FIRST_ANSWER_WAITS: &str = r#"
if mkdir '@DIR@/first' 2>/dev/null; then
  read -r line
  echo held >> '@DIR@/held'
  while [ ! -e '@DIR@/go' ]; do sleep 0.02; done
  id=${line##*\"id\":}; id=${id%%[!0-9]*}
  printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"%s"}],"pid":%s}}\n' "$id" "$TOOL" "$$"
fi
"#;

/// Answers every further request with a `tools/list` result: one tool, named
/// `$TOOL`, and the server's pid, echoing the request's id.
const SERVE_TOOL: &str = r#"
while read -r line; do
  id=${line##*\"id\":}; id=${id%%[!0-9]*}
  printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"%s"}],"pid":%s}}\n' "$id" "$TOOL" "$$"
done
"#;

/// A listing running in a task of its own.
type Listing = tokio::task::JoinHandle<Result<Vec<McpToolInfo>, McpError>>;

/// The stdio server `srv` running `bash -c <script>` and serving the tool
/// `tool`: entries serving different tools differ in their fingerprint.
fn tool_entry(script: &str, tool: &str) -> McpServerEntry {
    let mut env = path_env();
    env.insert("TOOL".to_string(), tool.to_string());
    McpServerEntry {
        server_id: "srv".into(),
        description: "stdio".into(),
        transport: McpTransportSpec::Stdio {
            command: "bash".into(),
            args: vec!["-c".into(), script.to_string()],
            env,
            cwd: None,
        },
        tool_patterns: None,
        tool_schemas: BTreeMap::new(),
    }
}

/// A configuration holding `entries`.
fn config_of(entries: impl IntoIterator<Item = McpServerEntry>) -> McpServersConfig {
    entries
        .into_iter()
        .fold(McpServersConfig::builder(), |builder, entry| {
            builder.add_server(entry).expect("add server")
        })
        .build()
}

/// A client configured with `srv` serving `tool`, whose stdio servers run on
/// the test's runtime.
fn tool_client(script: &str, tool: &str) -> Arc<McpClient> {
    Arc::new(
        McpClient::new(
            Arc::new(config_of([tool_entry(script, tool)])),
            Arc::new(NoOpDetector),
            None,
        )
        .with_runtime(tokio::runtime::Handle::current()),
    )
}

/// List the tools of `srv` in a task of its own.
fn spawn_listing(client: &Arc<McpClient>) -> Listing {
    let client = Arc::clone(client);
    tokio::spawn(async move { client.list_tools(None, "srv").await })
}

/// The names of the tools the cache holds for `srv`; `None` when it holds no
/// listing of it.
fn cached_names(client: &McpClient) -> Option<Vec<String>> {
    client
        .cached_tools()
        .into_iter()
        .find(|listing| listing.server_id == "srv")
        .map(|listing| listing.tools.iter().map(|t| t.name.clone()).collect())
}

/// Start two listings of `srv`. The first connects the server, whose first
/// start waits for the test ([`FIRST_WAITS`]), so it holds the connection
/// attempt; the second runs up to that attempt's lock and waits there. Both
/// have taken `srv`'s entry from the configuration current now.
async fn calls_waiting_to_connect(client: &Arc<McpClient>, dir: &Path) -> Vec<Listing> {
    let connecting = spawn_listing(client);
    assert!(
        wait_until(
            || lines(&dir.join("starts")).len() == 1,
            Duration::from_secs(5)
        )
        .await,
        "the first call started the server"
    );
    let waiting = spawn_listing(client);
    // On this current-thread runtime, the yield runs `waiting` until it waits
    // for the attempt lock `connecting` holds.
    tokio::task::yield_now().await;
    assert!(!waiting.is_finished());
    vec![connecting, waiting]
}

/// Start a listing of `srv` and wait until its server holds the `tools/list`
/// request ([`FIRST_ANSWER_WAITS`]).
async fn listing_held_by_the_server(client: &Arc<McpClient>, dir: &Path) -> Listing {
    let listing = spawn_listing(client);
    assert!(
        wait_until(
            || !lines(&dir.join("held")).is_empty(),
            Duration::from_secs(5)
        )
        .await,
        "the server holds the listing's request"
    );
    listing
}

/// Let the first server go on, and return the error each listing ends with.
async fn release(dir: &Path, listings: Vec<Listing>) -> Vec<McpError> {
    std::fs::write(dir.join("go"), "").expect("go");
    let mut errors = Vec::new();
    for listing in listings {
        let result = tokio::time::timeout(Duration::from_secs(10), listing)
            .await
            .expect("the listing ends")
            .expect("join");
        errors.push(result.expect_err("the configuration no longer holds the entry it targets"));
    }
    errors
}

/// Only the first server started, and it is stopped: nothing keeps a
/// connection, or any cached tools, for the entry the configuration dropped.
async fn assert_nothing_kept(client: &McpClient, dir: &Path) {
    let starts = lines(&dir.join("starts"));
    assert_eq!(
        starts.len(),
        1,
        "no server starts for the entry the configuration dropped: {starts:?}"
    );
    assert_eq!(cached_names(client), None, "nothing is cached for it");
    assert_eq!(
        client.protocol_version("srv"),
        None,
        "no connection is kept"
    );
    let pid = starts[0].split(' ').next().expect("pid").to_string();
    assert!(
        wait_until(|| !pid_alive(&pid), Duration::from_secs(5)).await,
        "the first server is stopped"
    );
}

/// A listing of `srv` connects a new server for the entry serving `new`, and
/// is cached.
async fn assert_lists_the_new_entry(client: &McpClient, dir: &Path) {
    let tools = client.list_tools(None, "srv").await.expect("listed");
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, ["new"]);
    assert_eq!(cached_names(client), Some(vec!["new".to_string()]));
    let starts = lines(&dir.join("starts"));
    assert_eq!(starts.len(), 2, "{starts:?}");
    assert!(starts[1].ends_with(" new"), "{starts:?}");
}

// A server removed while one call connects it and another waits for that
// connection attempt: both calls fail with `not-found`, no server starts or
// stays for the removed entry, and nothing is cached for it. Configured again
// under the same id, the server is connected afresh with its new entry.
#[tokio::test]
async fn calls_waiting_to_connect_a_removed_server_connect_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let script = server_script(
        &[LOG_START_TOOL, FIRST_WAITS, HANDSHAKE, SERVE_TOOL],
        dir.path(),
        "2025-06-18",
    );
    let client = tool_client(&script, "old");
    let calls = calls_waiting_to_connect(&client, dir.path()).await;

    let reconfig = client.replace_config(McpServersConfig::builder().build());
    assert_eq!(reconfig.removed, ["srv"]);
    for err in release(dir.path(), calls).await {
        assert_eq!(err.kind, McpErrorKind::NotFound, "{err:?}");
        assert_eq!(err.message, "server 'srv' is no longer configured");
    }
    assert_nothing_kept(&client, dir.path()).await;

    let reconfig = client.replace_config(config_of([tool_entry(&script, "new")]));
    assert_eq!(reconfig.added, ["srv"]);
    assert_lists_the_new_entry(&client, dir.path()).await;
}

// The same when the server's entry changes: both calls fail with
// `transport-error`, no server starts or stays for the old entry, and the next
// call connects the new one.
#[tokio::test]
async fn calls_waiting_to_connect_a_changed_server_connect_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let script = server_script(
        &[LOG_START_TOOL, FIRST_WAITS, HANDSHAKE, SERVE_TOOL],
        dir.path(),
        "2025-06-18",
    );
    let client = tool_client(&script, "old");
    let calls = calls_waiting_to_connect(&client, dir.path()).await;

    let reconfig = client.replace_config(config_of([tool_entry(&script, "new")]));
    assert_eq!(reconfig.changed, ["srv"]);
    for err in release(dir.path(), calls).await {
        assert_eq!(err.kind, McpErrorKind::TransportError, "{err:?}");
        assert_eq!(
            err.message,
            "server 'srv' was reconfigured while the call was under way"
        );
    }
    assert_nothing_kept(&client, dir.path()).await;
    assert_lists_the_new_entry(&client, dir.path()).await;
}

// A listing whose request the server still holds when the server's entry
// changes is neither cached nor returned: the server is left to be listed, and
// the next listing connects the new entry and is cached.
#[tokio::test]
async fn a_listing_under_way_when_its_server_changes_is_not_cached() {
    let dir = tempfile::tempdir().expect("tempdir");
    let script = server_script(
        &[LOG_START_TOOL, HANDSHAKE, FIRST_ANSWER_WAITS, SERVE_TOOL],
        dir.path(),
        "2025-06-18",
    );
    let client = tool_client(&script, "old");
    let listing = listing_held_by_the_server(&client, dir.path()).await;

    let reconfig = client.replace_config(config_of([tool_entry(&script, "new")]));
    assert_eq!(reconfig.changed, ["srv"]);
    let errors = release(dir.path(), vec![listing]).await;
    assert_eq!(errors[0].kind, McpErrorKind::TransportError, "{errors:?}");
    assert_eq!(
        errors[0].message,
        "server 'srv' was reconfigured while the call was under way"
    );
    assert_eq!(
        client.servers_to_list(),
        ["srv"],
        "the server is left to be listed"
    );
    assert_nothing_kept(&client, dir.path()).await;
    assert_lists_the_new_entry(&client, dir.path()).await;
    assert!(client.servers_to_list().is_empty());
}

// The same when the server is removed: the listing fails with `not-found` and
// nothing is cached; configured again, the server is listed with its new entry.
#[tokio::test]
async fn a_listing_under_way_when_its_server_is_removed_is_not_cached() {
    let dir = tempfile::tempdir().expect("tempdir");
    let script = server_script(
        &[LOG_START_TOOL, HANDSHAKE, FIRST_ANSWER_WAITS, SERVE_TOOL],
        dir.path(),
        "2025-06-18",
    );
    let client = tool_client(&script, "old");
    let listing = listing_held_by_the_server(&client, dir.path()).await;

    let reconfig = client.replace_config(McpServersConfig::builder().build());
    assert_eq!(reconfig.removed, ["srv"]);
    let errors = release(dir.path(), vec![listing]).await;
    assert_eq!(errors[0].kind, McpErrorKind::NotFound, "{errors:?}");
    assert_eq!(errors[0].message, "server 'srv' is no longer configured");
    assert!(client.servers_to_list().is_empty());
    assert_nothing_kept(&client, dir.path()).await;

    let reconfig = client.replace_config(config_of([tool_entry(&script, "new")]));
    assert_eq!(reconfig.added, ["srv"]);
    assert_lists_the_new_entry(&client, dir.path()).await;
}

// Transport tasks run on the client's runtime, not on the runtime of the call
// that connected the server: after that runtime is gone, the same server keeps
// answering.
#[test]
fn stdio_transports_outlive_the_runtime_of_the_call_that_started_them() {
    let daemon = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("daemon runtime");
    let dir = tempfile::tempdir().expect("tempdir");
    let client = Arc::new(
        stdio_client_without_runtime(
            server_script(&[LOG_START, HANDSHAKE, SERVE], dir.path(), "2025-06-18"),
            McpClientLimits::default(),
        )
        .with_runtime(daemon.handle().clone()),
    );

    let first = {
        let client = Arc::clone(&client);
        std::thread::spawn(move || {
            let call_runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("call runtime");
            call_runtime.block_on(client.invoke_tool(None, "srv", "echo", b"{}"))
        })
        .join()
        .expect("call thread")
        .expect("first call")
    };
    // The call runtime has shut down; the server must still be reachable.
    let second = daemon
        .block_on(client.invoke_tool(None, "srv", "echo", b"{}"))
        .expect("second call");
    assert_eq!(json_of(&first)["pid"], json_of(&second)["pid"]);
    assert_eq!(lines(&dir.path().join("starts")).len(), 1);
}

// A client given no runtime never takes one: neither the runtime current when
// it is built (here a per-call runtime, as a Client API request has) nor that of
// the call that would connect a stdio server. It refuses to start one.
#[test]
fn a_client_given_no_runtime_starts_no_stdio_server() {
    let dir = tempfile::tempdir().expect("tempdir");
    let call_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("call runtime");
    let client = call_runtime.block_on(async {
        stdio_client_without_runtime(
            server_script(&[LOG_START, HANDSHAKE, SERVE], dir.path(), "2025-06-18"),
            McpClientLimits::default(),
        )
    });
    let err = call_runtime
        .block_on(client.invoke_tool(None, "srv", "echo", b"{}"))
        .expect_err("no runtime for stdio servers");
    assert_eq!(err.kind, McpErrorKind::TransportError);
    assert!(err.message.contains("with_runtime"), "msg={}", err.message);
    assert!(lines(&dir.path().join("starts")).is_empty());
}

// ─────────────────────────────────────────────────────────────────────────
// Shutdown
// ─────────────────────────────────────────────────────────────────────────

/// Starts a process of the server's own and records its pid, one line per
/// start.
const LOG_CHILD: &str = r#"
sleep 300 &
echo $! >> '@DIR@/children'
"#;

/// Answers one further request like [`SERVE`], then reads requests without
/// ever answering, recording each.
const SERVE_ONCE_THEN_HANG: &str = r#"
read -r line
id=${line##*\"id\":}; id=${id%%[!0-9]*}
printf '{"jsonrpc":"2.0","id":%s,"result":{"pid":%s}}\n' "$id" "$$"
while read -r line; do echo got >> '@DIR@/unanswered'; done
"#;

// Shutting the client down stops a server at once, with a call still running
// on it: the call fails without waiting out its timeout, the server and the
// process it started are gone, and no later call starts a server again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_stops_a_server_whatever_calls_run_on_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let client = Arc::new(stdio_client(
        server_script(
            &[LOG_START, LOG_CHILD, HANDSHAKE, SERVE_ONCE_THEN_HANG],
            dir.path(),
            "2025-06-18",
        ),
        McpClientLimits::default(),
    ));
    let starts = dir.path().join("starts");
    client
        .invoke_tool(None, "srv", "echo", b"{}")
        .await
        .expect("the server answers its first call");
    let server = lines(&starts)[0].clone();
    let child = lines(&dir.path().join("children"))[0].clone();
    assert!(pid_alive(&server) && pid_alive(&child));
    assert!(!client.is_shut_down());

    // A call the server never answers holds the connection for the request
    // timeout, 30 s.
    let hung = {
        let client = Arc::clone(&client);
        tokio::spawn(async move { client.invoke_tool(None, "srv", "echo", b"{}").await })
    };
    assert!(
        wait_until(
            || !lines(&dir.path().join("unanswered")).is_empty(),
            Duration::from_secs(5)
        )
        .await,
        "the server read the call it will not answer"
    );

    client.shutdown();

    let err = tokio::time::timeout(Duration::from_secs(5), hung)
        .await
        .expect("the call ends with the shutdown, not with its timeout")
        .expect("join")
        .expect_err("its connection was closed");
    assert_eq!(err.kind, McpErrorKind::TransportError);
    for pid in [&child, &server] {
        let stopped = wait_until(|| !pid_alive(pid), Duration::from_secs(5)).await;
        if !stopped {
            let _ = std::process::Command::new("kill")
                .args(["-9", pid])
                .status();
        }
        assert!(stopped, "process {pid} outlived the shutdown");
    }
    assert!(client.is_shut_down());
    assert_eq!(client.protocol_version("srv"), None);

    // Nothing connects afterwards, and a second shutdown changes nothing.
    client.shutdown();
    let err = client
        .invoke_tool(None, "srv", "echo", b"{}")
        .await
        .expect_err("the client is shut down");
    assert_eq!(err.kind, McpErrorKind::TransportError);
    assert!(err.message.contains("shut down"), "msg={}", err.message);
    assert!(client.list_tools(None, "srv").await.is_err());
    assert_eq!(lines(&starts).len(), 1, "no server starts after a shutdown");
}

// A server still being connected is stopped too: its attempt fails at once
// instead of holding the server for the startup timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_stops_a_server_that_is_still_connecting() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Reads `initialize` and never answers it.
    let silent = r#"
read -r init
sleep 300
"#;
    let client = Arc::new(stdio_client(
        server_script(&[LOG_START, LOG_CHILD, silent], dir.path(), "2025-06-18"),
        McpClientLimits {
            startup_timeout: Duration::from_secs(60),
            ..McpClientLimits::default()
        },
    ));
    let connecting = {
        let client = Arc::clone(&client);
        tokio::spawn(async move { client.invoke_tool(None, "srv", "echo", b"{}").await })
    };
    let children = dir.path().join("children");
    assert!(wait_until(|| !lines(&children).is_empty(), Duration::from_secs(5)).await);
    let server = lines(&dir.path().join("starts"))[0].clone();
    let child = lines(&children)[0].clone();
    assert!(pid_alive(&server) && pid_alive(&child));

    client.shutdown();

    let err = tokio::time::timeout(Duration::from_secs(5), connecting)
        .await
        .expect("the attempt ends with the shutdown, not with the startup timeout")
        .expect("join")
        .expect_err("the server it was connecting was stopped");
    assert_eq!(err.kind, McpErrorKind::TransportError);
    for pid in [&child, &server] {
        let stopped = wait_until(|| !pid_alive(pid), Duration::from_secs(5)).await;
        if !stopped {
            let _ = std::process::Command::new("kill")
                .args(["-9", pid])
                .status();
        }
        assert!(stopped, "process {pid} outlived the shutdown");
    }
    assert!(client
        .invoke_tool(None, "srv", "echo", b"{}")
        .await
        .is_err());
    assert_eq!(lines(&dir.path().join("starts")).len(), 1);
}

// Closing a transport is what its owner does to stop the server while calls
// still hold the transport: they fail, and the process group is killed.
#[tokio::test]
async fn closing_a_transport_fails_its_calls_and_stops_the_server() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("grandchild");
    // Reads every request and answers none.
    let script = format!(
        "sleep 300 & echo $! > '{}'; while read -r x; do :; done",
        marker.display()
    );
    let transport = Arc::new(
        StdioMcpTransport::spawn(
            "srv",
            "bash",
            &["-c".to_string(), script],
            &path_env(),
            Arc::new(NoOpDetector),
        )
        .expect("spawn"),
    );
    assert!(wait_until(|| !lines(&marker).is_empty(), Duration::from_secs(5)).await);
    let pid = lines(&marker)[0].clone();
    let waiting = {
        let transport = Arc::clone(&transport);
        tokio::spawn(async move { transport.invoke("tools/call", serde_json::json!({})).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!transport.is_closed());

    transport.close();
    transport.close();

    assert!(transport.is_closed() && transport.closed_at().is_some());
    let err = tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .expect("the waiting call fails at once")
        .expect("join")
        .expect_err("closed");
    assert_eq!(err.kind, McpErrorKind::TransportError);
    assert_eq!(err.message, "the transport was closed");
    let stopped = wait_until(|| !pid_alive(&pid), Duration::from_secs(5)).await;
    if !stopped {
        let _ = std::process::Command::new("kill")
            .args(["-9", &pid])
            .status();
    }
    assert!(
        stopped,
        "the server's child {pid} outlived the closed transport"
    );
    let err = transport
        .invoke("tools/call", serde_json::json!({}))
        .await
        .expect_err("a closed transport carries no call");
    assert_eq!(err.message, "the transport was closed");
}

// ─────────────────────────────────────────────────────────────────────────
// The working directory of a stdio server
// ─────────────────────────────────────────────────────────────────────────

/// Answers every further request with `{"pwd": <the server's working
/// directory>}`, echoing its id.
const SERVE_PWD: &str = r#"
while read -r line; do
  id=${line##*\"id\":}; id=${id%%[!0-9]*}
  printf '{"jsonrpc":"2.0","id":%s,"result":{"pwd":"%s"}}\n' "$id" "$(pwd -P)"
done
"#;

/// The stdio server `id` running `bash -c <script>` in the working directory
/// `cwd`.
fn entry_in(id: &str, script: &str, cwd: Option<&Path>) -> McpServerEntry {
    McpServerEntry {
        server_id: id.into(),
        description: "stdio".into(),
        transport: McpTransportSpec::Stdio {
            command: "bash".into(),
            args: vec!["-c".into(), script.to_string()],
            env: path_env(),
            cwd: cwd.map(Path::to_path_buf),
        },
        tool_patterns: None,
        tool_schemas: BTreeMap::new(),
    }
}

// A server's entry names the directory the client starts it in; without one
// the server runs in `/`.
#[tokio::test]
async fn a_stdio_server_runs_in_the_working_directory_of_its_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let workdir = std::fs::canonicalize(dir.path()).expect("canonical tempdir");
    let script = server_script(&[HANDSHAKE, SERVE_PWD], dir.path(), "2025-06-18");
    let client = McpClient::new(
        Arc::new(config_of([
            entry_in("here", &script, Some(&workdir)),
            entry_in("rooted", &script, None),
        ])),
        Arc::new(NoOpDetector),
        None,
    )
    .with_runtime(tokio::runtime::Handle::current());

    let here = client
        .invoke_tool(None, "here", "pwd", b"{}")
        .await
        .expect("the server answers");
    assert_eq!(json_of(&here)["pwd"], workdir.display().to_string());
    let rooted = client
        .invoke_tool(None, "rooted", "pwd", b"{}")
        .await
        .expect("the server answers");
    assert_eq!(json_of(&rooted)["pwd"], "/");
}

// A working directory that is not a directory fails the spawn with an error
// naming it, whether it is a file or missing, and through the client the
// server never starts.
#[tokio::test]
async fn a_working_directory_that_is_not_a_directory_fails_the_spawn_naming_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("not-a-dir");
    std::fs::write(&file, "x").expect("write");
    let missing = dir.path().join("missing");
    let spawn_in = |cwd: &Path| {
        StdioMcpTransport::spawn_with_options(
            "srv",
            "bash",
            &["-c".to_string(), "sleep 30".to_string()],
            &path_env(),
            Arc::new(NoOpDetector),
            StdioOptions {
                cwd: Some(cwd.to_path_buf()),
                ..StdioOptions::default()
            },
        )
    };

    let err = spawn_in(&file).expect_err("a file is no working directory");
    assert_eq!(err.kind, McpErrorKind::TransportError);
    assert_eq!(
        err.message,
        format!(
            "stdio: working directory {} is not a directory",
            file.display()
        )
    );
    let err = spawn_in(&missing).expect_err("a missing working directory");
    assert_eq!(err.kind, McpErrorKind::TransportError);
    assert!(
        err.message.starts_with(&format!(
            "stdio: working directory {} cannot be used: ",
            missing.display()
        )),
        "msg={}",
        err.message
    );

    let script = server_script(&[LOG_START, HANDSHAKE, SERVE], dir.path(), "2025-06-18");
    let client = McpClient::new(
        Arc::new(config_of([entry_in("srv", &script, Some(&file))])),
        Arc::new(NoOpDetector),
        None,
    )
    .with_runtime(tokio::runtime::Handle::current());
    let err = client
        .invoke_tool(None, "srv", "echo", b"{}")
        .await
        .expect_err("the server cannot start");
    assert_eq!(err.kind, McpErrorKind::TransportError);
    assert!(
        err.message.contains(&file.display().to_string())
            && err.message.contains("is not a directory"),
        "msg={}",
        err.message
    );
    assert!(
        lines(&dir.path().join("starts")).is_empty(),
        "no server process started"
    );
}

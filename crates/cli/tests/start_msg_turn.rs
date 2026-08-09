//! /dev WS-A — full-daemon e2e (test 10, the headline success criterion).
//!
//! `advance start` + `POST /msg` wakes a turn on the REAL production daemon: an
//! HTTP POST is delivered into the shared `MailboxStore`, the parked single-turn
//! `run_agent` wakes, the deployed skeleton guest's `handle-message` runs, and
//! its `fs.write` lands `j01.txt` whose content == the posted payload.
//!
//! The fixture (`guest-rust-j01-skeleton.core.wasm`) is read-only-reused from
//! the existing `sys_acceptance_full_turn.rs` witness (which asserts the same
//! `j01.txt == payload` behavior through `recv → handle_message`). It is a raw
//! CORE module, so it MUST be `ComponentEncoder`-encoded into a WASM COMPONENT
//! before deploy — the daemon's `load_component` parses components only (a raw
//! core module fails boot).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wit_component::ComponentEncoder;

/// Read-only reuse of the existing skeleton guest fixture (a raw core module).
const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");
const START_MSG_RUNTIME_CONFIG: &str = "\
wasm:
  max_memory_pages: 256
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers: []

cron:
  max_jitter_ratio: 0.1

git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10

secrets:
  master-key-source: env-var
  env-var-name: ADVANCE_START_MSG_TEST_MASTER_KEY_UNUSED

post-processor:
  llm-model: start-msg-smoke
  llm-failure-cooldown-seconds: 300

database:
  db-path: \".runtime/index.db\"
  pool-size: 1
";

fn advance_bin() -> std::path::PathBuf {
    assert_cmd::cargo::cargo_bin("advance")
}

fn configure_start_msg_workspace(workspace: &Path) {
    std::fs::write(
        workspace.join(".advance").join("runtime-config.yaml"),
        START_MSG_RUNTIME_CONFIG,
    )
    .expect("write start msg runtime config");
    std::fs::write(
        workspace.join(".agent").join("config.yaml"),
        "capabilities:\n  fs: true\n",
    )
    .expect("write fs-only agent config");
}

#[test]
#[cfg(unix)]
fn advance_start_post_msg_wakes_a_turn() {
    let dir = tempfile::tempdir().unwrap();
    let ws = dir.path().to_path_buf();

    // 1. init the workspace, then trim the fixture to the only guest capability
    //    this smoke test needs: fs.
    let status = Command::new(advance_bin())
        .arg("init")
        .arg(&ws)
        .status()
        .expect("spawn advance init");
    assert!(status.success(), "advance init failed: {status:?}");
    configure_start_msg_workspace(&ws);

    // 2. Encode the j01-skeleton CORE module into a WASM COMPONENT and deploy it
    //    at the conventional path. The daemon's `load_component` parses a
    //    component, NOT a core module (a raw core module would fail boot), so
    //    the encode step is mandatory (mirrors sys_acceptance_full_turn.rs).
    let component = ComponentEncoder::default()
        .validate(true)
        .module(CORE_BYTES)
        .expect("wrap core module")
        .encode()
        .expect("encode component");
    std::fs::write(
        ws.join(".agent").join("behavior.component.wasm"),
        &component,
    )
    .expect("write deployed component");

    // 3. Spawn `advance start`.
    let mut child = Command::new(advance_bin())
        .arg("start")
        .arg("--workspace")
        .arg(&ws)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn advance start");

    let stdout = child.stdout.take().expect("child stdout");
    let stderr_handle = child.stderr.take().expect("child stderr");
    // Drain stderr in a thread so its pipe buffer can't fill + deadlock the child.
    let stderr_join = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = Read::read_to_string(&mut BufReader::new(stderr_handle), &mut buf);
        buf
    });

    // 4. Wait (≤30s cold-start budget) for the msg-listener address line.
    let mut reader = BufReader::new(stdout);
    let mut addr: Option<String> = None;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break, // EOF — child exited
            Ok(_) => {
                // "advance: msg listener on http://127.0.0.1:PORT/msg"
                if let Some(rest) = line.trim().strip_prefix("advance: msg listener on http://") {
                    if let Some(a) = rest.strip_suffix("/msg") {
                        addr = Some(a.to_string());
                        break;
                    }
                }
            }
            Err(e) => panic!("stdout read error: {e}"),
        }
    }
    let addr = match addr {
        Some(a) => a,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            let err = stderr_join.join().unwrap_or_default();
            panic!("did not see the msg-listener address within 30s; stderr:\n{err}");
        }
    };

    // 5. POST /msg with the payload (raw HTTP/1.1 — no HTTP-client dep needed).
    let payload = "hello-msg-turn";
    let body = format!("{{\"payload\":\"{payload}\"}}");
    let req = format!(
        "POST /msg HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut resp = String::new();
    {
        let mut stream = TcpStream::connect(&addr).expect("connect to msg listener");
        stream.write_all(req.as_bytes()).expect("write POST /msg");
        stream
            .read_to_string(&mut resp)
            .expect("read POST /msg response");
    }
    assert!(
        resp.starts_with("HTTP/1.1 202"),
        "POST /msg should be 202 Accepted; status line: {:?}",
        resp.lines().next().unwrap_or("")
    );

    // 6. Bounded poll (≤10s) for the turn's observable side effect: the skeleton
    //    guest's fs.write lands `j01.txt` (under the default-agent territory =
    //    the workspace) whose content == the posted payload.
    let written = ws.join("j01.txt");
    let poll_deadline = Instant::now() + Duration::from_secs(10);
    let mut content: Option<Vec<u8>> = None;
    while Instant::now() < poll_deadline {
        if let Ok(bytes) = std::fs::read(&written) {
            if !bytes.is_empty() {
                content = Some(bytes);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Tear the daemon down regardless of outcome before asserting.
    let _ = child.kill();
    let _ = child.wait();
    let err = stderr_join.join().unwrap_or_default();

    match content {
        Some(bytes) => assert_eq!(
            bytes,
            payload.as_bytes(),
            "the turn's fs.write should land j01.txt == the posted payload"
        ),
        None => panic!(
            "turn did not write {} within 10s of POST /msg (daemon never ran the turn?); stderr:\n{err}",
            written.display()
        ),
    }
}

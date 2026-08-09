//! /dev Phase-2 Step-2 — full-daemon e2e: `advance start` serves TWO consecutive
//! `POST /msg` requests (the headline serving-loop success criterion).
//!
//! Under the pre-Phase-2 single-turn `run_agent`, the agent processed ONE message
//! then the task ended (`done=true`), so the 2nd POST got 503. With the `serve`
//! loop, the daemon keeps serving: POST `alpha` → 202 + `j01.txt == alpha`, then
//! POST `bravo` → 202 + `j01.txt == bravo`. The 2nd POST landing 202 with the new
//! content is only possible if the agent survived turn 1 — i.e. the serving loop.
//!
//! The fixture (`guest-rust-j01-skeleton.core.wasm`) is read-only-reused (it
//! overwrites a single `j01.txt` with the inbound payload and returns no action →
//! 202). It is a raw CORE module, so it is `ComponentEncoder`-wrapped into a WASM
//! COMPONENT before deploy (the daemon's `load_component` parses components only).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wit_component::ComponentEncoder;

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

/// Send one raw HTTP/1.1 `POST /msg` with `{"payload": <payload>}`; return the
/// HTTP status code (0 if unparseable).
fn post_msg(addr: &str, payload: &str) -> u16 {
    let body = format!("{{\"payload\":\"{payload}\"}}");
    let req = format!(
        "POST /msg HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut resp = String::new();
    let mut stream = TcpStream::connect(addr).expect("connect to msg listener");
    stream.write_all(req.as_bytes()).expect("write POST /msg");
    stream
        .read_to_string(&mut resp)
        .expect("read POST /msg response");
    resp.lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0)
}

/// POST, retrying on a transient `409` (the narrow window where the previous
/// turn's `WatchTurnObserver` has not YET cleared `in_flight`) until `deadline`.
fn post_msg_retry_409(addr: &str, payload: &str, deadline: Instant) -> u16 {
    loop {
        let status = post_msg(addr, payload);
        if status != 409 || Instant::now() >= deadline {
            return status;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Poll `path` until its bytes equal `expected` or `deadline` elapses.
fn poll_file_eq(path: &Path, expected: &[u8], deadline: Instant) -> bool {
    while Instant::now() < deadline {
        if let Ok(bytes) = std::fs::read(path) {
            if bytes == expected {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
#[cfg(unix)]
fn advance_start_serves_two_consecutive_posts() {
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

    // 2. Encode the j01-skeleton CORE module into a COMPONENT and deploy it.
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

    let j01 = ws.join("j01.txt");

    // 5. POST #1 "alpha" → 202; the turn's fs.write lands j01.txt == "alpha".
    let post1 = post_msg(&addr, "alpha");
    let file1 = poll_file_eq(&j01, b"alpha", Instant::now() + Duration::from_secs(10));

    // 6. POST #2 "bravo" → 202 (retry on the transient 409 window); j01.txt == "bravo".
    //    Under single-turn this would be 503 (the one turn already ran).
    let post2 = post_msg_retry_409(&addr, "bravo", Instant::now() + Duration::from_secs(5));
    let file2 = poll_file_eq(&j01, b"bravo", Instant::now() + Duration::from_secs(10));

    // Tear the daemon down before asserting.
    let _ = child.kill();
    let _ = child.wait();
    let err = stderr_join.join().unwrap_or_default();

    assert_eq!(post1, 202, "POST #1 should be 202 Accepted; stderr:\n{err}");
    assert!(
        file1,
        "turn 1 did not write j01.txt == \"alpha\"; stderr:\n{err}"
    );
    assert_eq!(
        post2, 202,
        "POST #2 should be 202 — the serving loop served a 2nd message (single-turn → 503); stderr:\n{err}"
    );
    assert!(
        file2,
        "turn 2 did not write j01.txt == \"bravo\" — the agent did not serve the 2nd message; stderr:\n{err}"
    );
}

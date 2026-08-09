//! Slice AE (2026-05-09) — `advance start` CLI smoke tests.
//!
//! T68 happy-path: `advance start` parks until SIGINT, then exits 0 cleanly.
//! T70 friendly missing-config diagnostic.

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use predicates::prelude::*;
use tempfile::TempDir;

const START_READY_TIMEOUT: Duration = Duration::from_secs(90);
const START_SMOKE_RUNTIME_CONFIG: &str = "\
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
  env-var-name: ADVANCE_START_TEST_MASTER_KEY_UNUSED

post-processor:
  llm-model: start-smoke
  llm-failure-cooldown-seconds: 300

database:
  db-path: \".runtime/index.db\"
  pool-size: 1
";

fn advance_bin() -> std::path::PathBuf {
    assert_cmd::cargo::cargo_bin("advance")
}

fn init_workspace(tempdir: &TempDir) -> std::path::PathBuf {
    let ws = tempdir.path().to_path_buf();
    let status = Command::new(advance_bin())
        .arg("init")
        .arg(&ws)
        .status()
        .expect("spawn advance init");
    assert!(status.success(), "advance init failed: {status:?}");
    ws
}

fn configure_start_smoke_workspace(workspace: &Path) {
    std::fs::write(
        workspace.join(".advance").join("runtime-config.yaml"),
        START_SMOKE_RUNTIME_CONFIG,
    )
    .expect("write start smoke runtime config");
    std::fs::write(
        workspace.join(".agent").join("config.yaml"),
        "capabilities: {}\n",
    )
    .expect("write no-capability agent config");
}

#[test]
#[cfg(unix)]
fn t68_advance_start_parks_and_exits_cleanly_on_sigint() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let workspace = init_workspace(&dir);
    configure_start_smoke_workspace(&workspace);

    let mut child = Command::new(advance_bin())
        .arg("start")
        .arg("--workspace")
        .arg(&workspace)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn advance start");

    let stdout = child.stdout.take().expect("child stdout");
    let stderr_handle = child.stderr.take().expect("child stderr");
    // Capture stderr in a thread so it doesn't fill its pipe buffer.
    let stderr_join = std::thread::spawn(move || {
        let mut buf = String::new();
        let mut reader = BufReader::new(stderr_handle);
        let _ = std::io::Read::read_to_string(&mut reader, &mut buf);
        buf
    });

    // Wait for the "runtime ready" line on stdout, with a 90s cold-start budget
    // (per T68 P1 priority — first-run engine compile + sqlite-vec auto-extension
    // can be slow on cold caches). The reader lives on a helper thread so the
    // timeout is real even if the child stays alive without printing a newline.
    let (ready_tx, ready_rx) = mpsc::channel();
    let stdout_join = std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let mut ready_sent = false;
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    if !ready_sent {
                        let _ =
                            ready_tx.send(Err("stdout closed before runtime ready".to_string()));
                    }
                    break;
                }
                Ok(_) if !ready_sent && line.contains("runtime ready") => {
                    let _ = ready_tx.send(Ok(()));
                    ready_sent = true;
                }
                Ok(_) => {}
                Err(e) => {
                    if !ready_sent {
                        let _ = ready_tx.send(Err(format!("stdout read error: {e}")));
                    }
                    break;
                }
            }
        }
    });

    let ready_result = ready_rx
        .recv_timeout(START_READY_TIMEOUT)
        .unwrap_or_else(|_| Err("did not see 'runtime ready' within 90s".to_string()));
    if let Err(reason) = ready_result {
        // Kill the child so the test exits; surface a diagnostic.
        let _ = child.kill();
        let _ = child.wait();
        let _ = stdout_join.join();
        let stderr = stderr_join.join().unwrap_or_default();
        panic!("{reason}; stderr: {stderr}");
    }

    // Send SIGINT (ctrl_c equivalent) — emulates user pressing ^C.
    let pid = child.id() as i32;
    // SAFETY: kill(2) with SIGINT is a normal process-control operation; pid is
    // valid because we just spawned the child and have not yet wait()'d.
    let rc = unsafe { libc::kill(pid, libc::SIGINT) };
    assert_eq!(
        rc,
        0,
        "kill(SIGINT) failed: errno={}",
        std::io::Error::last_os_error()
    );

    // Wait at most 5s for clean exit.
    let exit_deadline = std::time::Instant::now() + Duration::from_secs(5);
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {
                if std::time::Instant::now() >= exit_deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    let stderr = stderr_join.join().unwrap_or_default();
                    panic!("child did not exit within 5s of SIGINT; stderr: {stderr}");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("try_wait error: {e}"),
        }
    };
    let _ = stdout_join.join();
    let stderr_buf = stderr_join.join().unwrap_or_default();
    let _ = std::io::stdout().flush();

    assert!(
        status.success(),
        "advance start should exit 0 on SIGINT, got {status:?}; stderr: {stderr_buf}"
    );

    // Lock file should be removed by RuntimeLock::Drop.
    let lock_path = workspace.join(".runtime").join("runtime.lock");
    assert!(
        !lock_path.exists(),
        "runtime.lock should be removed on graceful shutdown; still at {}",
        lock_path.display()
    );
}

#[test]
fn t70_advance_start_friendly_diagnostic_when_config_missing() {
    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path().to_path_buf();
    // Workspace exists but has NO .advance/runtime-config.yaml.
    std::fs::create_dir_all(workspace.join(".advance")).unwrap();

    assert_cmd::Command::cargo_bin("advance")
        .unwrap()
        .arg("start")
        .arg("--workspace")
        .arg(&workspace)
        .assert()
        .failure()
        .stderr(predicate::str::contains("runtime-config.yaml not found"))
        .stderr(predicate::str::contains("advance init"));

    // No lock file should be created when bootstrap fails.
    let lock_path = workspace.join(".runtime").join("runtime.lock");
    assert!(
        !lock_path.exists(),
        "runtime.lock should not be created when bootstrap fails"
    );
}

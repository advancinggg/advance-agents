//! Shared helper of MODULE-001-T113 (7): a live `advance start` child whose pid lock
//! the in-process `compose` of this binary (and later the bridge v2 handle) probes.
//!
//! The prober and the daemon share every locale/TZ variable — `platform_uid` embeds
//! `ps -o lstart=` as formatted under the prober's locale and TZ.
#![cfg(unix)]
#![allow(dead_code)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tempfile::TempDir;

/// The master key the home's runtime config names (`secrets.env-var-name`).
pub const MASTER_KEY_ENV: &str = "ADVANCE_D5_GOLDEN_MASTER_KEY";
pub const MASTER_KEY_HEX: &str = "d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5";

/// Cold-start budget until `advance: runtime ready`.
const READY_BUDGET: Duration = Duration::from_secs(180);
/// How long a run gets to exit after SIGTERM (the goldens' budget).
pub const SIGTERM_EXIT_BUDGET_SECS: u64 = 15;

/// Every test of this binary holds this for its whole body (process-global spawn counter).
pub static SERIAL: Mutex<()> = Mutex::new(());

/// Copies from `std::env::vars_os()` every variable named `LANG`, `LANGUAGE`,
/// `LOCPATH`, `TZ`, `TZDIR` or starting with `LC_` into `cmd`.
pub fn live_daemon_env(cmd: &mut Command) {
    for (key, value) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name == "LANG"
            || name == "LANGUAGE"
            || name == "LOCPATH"
            || name == "TZ"
            || name == "TZDIR"
            || name.starts_with("LC_")
        {
            cmd.env(key, value);
        }
    }
}

/// One stream of a child, read to its end on a thread of its own.
struct Captured {
    text: Arc<Mutex<String>>,
    reader: Option<JoinHandle<()>>,
}

impl Captured {
    fn new(mut stream: impl Read + Send + 'static) -> Captured {
        let text = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&text);
        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => sink
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push_str(&String::from_utf8_lossy(&buf[..n])),
                }
            }
        });
        Captured {
            text,
            reader: Some(reader),
        }
    }

    fn text(&self) -> String {
        self.text.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn finish(&mut self) -> String {
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        self.text()
    }
}

/// A live `advance start` on a home that declares `fs`.
pub struct LiveDaemon {
    pub home: PathBuf,
    pub pid: u32,
    child: Child,
    stdout: Captured,
    stderr: Captured,
    _root: TempDir,
}

impl LiveDaemon {
    pub fn start() -> LiveDaemon {
        let dir = tempfile::tempdir().expect("tempdir");
        let raw_root = dir.path().to_path_buf();
        let root = std::fs::canonicalize(&raw_root).expect("canonicalize temp root");
        std::fs::create_dir_all(root.join("home")).expect("HOME");
        std::fs::create_dir_all(root.join("tmp")).expect("TMPDIR");
        let ws = root.join("ws");

        let init_status = {
            let mut cmd = command(&root, &["init", ws.to_str().expect("utf-8 workspace")]);
            cmd.output().expect("advance init").status
        };
        assert!(
            init_status.success(),
            "advance init failed: {init_status:?}"
        );

        std::fs::write(ws.join(".advance/runtime-config.yaml"), runtime_yaml())
            .expect("runtime config");
        std::fs::write(ws.join(".agent/config.yaml"), "capabilities:\n  fs: true\n")
            .expect("agent config");

        let home = std::fs::canonicalize(&ws).expect("canonicalize home");
        let mut cmd = command(
            &root,
            &["start", "--workspace", home.to_str().expect("utf-8 home")],
        );
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("advance start");
        let stdout = Captured::new(child.stdout.take().expect("stdout"));
        let stderr = Captured::new(child.stderr.take().expect("stderr"));
        let mut daemon = LiveDaemon {
            home,
            pid: child.id(),
            child,
            stdout,
            stderr,
            _root: dir,
        };
        daemon.wait_ready();
        daemon.pid = lock_pid(&daemon.home).expect("runtime.lock pid");
        daemon
    }

    fn wait_ready(&mut self) {
        let deadline = Instant::now() + READY_BUDGET;
        while !self.stdout.text().contains("advance: runtime ready") {
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!(
                    "advance start exited ({status:?}) before the readiness line; stderr:\n{}",
                    self.stderr.finish()
                );
            }
            assert!(
                Instant::now() < deadline,
                "no readiness line within {READY_BUDGET:?}; stderr:\n{}",
                self.stderr.text()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Every line of `.runtime/runtime.lock` except `heartbeat_at:`.
    pub fn lock_fields(&self) -> String {
        let text =
            std::fs::read_to_string(self.home.join(".runtime/runtime.lock")).expect("runtime.lock");
        text.lines()
            .filter(|line| !line.starts_with("heartbeat_at:"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// `http://127.0.0.1:<port>` from `.runtime/client-api`.
    pub fn client_api_base(&self) -> String {
        let text = std::fs::read_to_string(self.home.join(".runtime/client-api"))
            .expect("client-api discovery");
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("client_api_base:") {
                let v = rest.trim().trim_matches('"');
                if !v.is_empty() {
                    return v.to_owned();
                }
            }
        }
        panic!("no client_api_base in discovery:\n{text}");
    }

    /// SIGTERM the lock's pid; the child exits 0 within [`SIGTERM_EXIT_BUDGET_SECS`].
    pub fn sigterm_and_wait(&mut self) -> ExitStatus {
        // SAFETY: kill(2) with SIGTERM on the child this test spawned and has not reaped.
        let rc = unsafe { libc::kill(self.pid as i32, libc::SIGTERM) };
        assert_eq!(rc, 0, "kill(SIGTERM): {}", std::io::Error::last_os_error());
        let deadline = Instant::now() + Duration::from_secs(SIGTERM_EXIT_BUDGET_SECS);
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return status;
            }
            if Instant::now() >= deadline {
                panic!(
                    "advance start did not exit within {}s of SIGTERM; stderr:\n{}",
                    SIGTERM_EXIT_BUDGET_SECS,
                    self.stderr.text()
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for LiveDaemon {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn command(root: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_advance"));
    cmd.args(args)
        .env_clear()
        .env("HOME", root.join("home"))
        .env("TMPDIR", root.join("tmp"))
        .env(MASTER_KEY_ENV, MASTER_KEY_HEX)
        .stdin(Stdio::null());
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    live_daemon_env(&mut cmd);
    cmd
}

fn lock_pid(home: &Path) -> Option<u32> {
    let text = std::fs::read_to_string(home.join(".runtime/runtime.lock")).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("pid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

fn runtime_yaml() -> String {
    format!(
        r#"wasm:
  max_memory_pages: 1024
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
  env-var-name: {MASTER_KEY_ENV}

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: ".runtime/index.db"
  pool-size: 4
"#
    )
}

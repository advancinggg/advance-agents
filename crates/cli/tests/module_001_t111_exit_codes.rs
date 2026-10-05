//! MODULE-001-T111 (1) / MODULE-001-AC-30 — the thin `advance start` over `compose`: the
//! exit codes of the real binary (1 after a startup failure, 0 after SIGTERM on the home
//! declaring every capability on a git repository, which never exited before the lane), what
//! a restart does on a home declaring `lifecycle`, and the order of the thin `main` (runtime,
//! signal listeners before the lock, workspace, then `compose`).
#![cfg(unix)]

#[path = "support/all_caps_home.rs"]
mod all_caps_home;

use std::io::Read;
use std::process::{Child, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use all_caps_home::{spawn_locked, AllCapsHome};

/// Cold-start budget until the readiness line (first-run engine compile on a cold cache).
const READY_BUDGET: Duration = Duration::from_secs(180);
/// How long a run gets to exit after SIGTERM (the goldens' budget).
const SIGTERM_EXIT_BUDGET: Duration = Duration::from_secs(15);
/// How long a startup failure gets to exit on its own.
const FAILURE_EXIT_BUDGET: Duration = Duration::from_secs(180);

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
                        .unwrap()
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
        self.text.lock().unwrap().clone()
    }

    /// The whole stream, once the child has exited.
    fn finish(&mut self) -> String {
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        self.text()
    }
}

/// `advance start --workspace <ws>` with both streams captured; killed if still running when
/// dropped.
struct Daemon {
    child: Child,
    stdout: Captured,
    stderr: Captured,
}

impl Daemon {
    fn start(home: &AllCapsHome) -> Daemon {
        let ws = home.ws.to_str().expect("utf-8 workspace").to_owned();
        let mut cmd = home.command(&["start", "--workspace", &ws]);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = spawn_locked(&mut cmd);
        let stdout = Captured::new(child.stdout.take().expect("stdout"));
        let stderr = Captured::new(child.stderr.take().expect("stderr"));
        Daemon {
            child,
            stdout,
            stderr,
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
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

    fn sigterm(&self) {
        // SAFETY: kill(2) with SIGTERM on the child this test spawned and has not reaped.
        let rc = unsafe { libc::kill(self.pid() as i32, libc::SIGTERM) };
        assert_eq!(rc, 0, "kill(SIGTERM): {}", std::io::Error::last_os_error());
    }

    fn wait_exit(&mut self, budget: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + budget;
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// SIGTERM, then the exit status within the goldens' budget and how long it took.
    fn stop(&mut self) -> (ExitStatus, Duration) {
        let started = Instant::now();
        self.sigterm();
        let status = self.wait_exit(SIGTERM_EXIT_BUDGET).unwrap_or_else(|| {
            panic!(
                "advance start did not exit within {SIGTERM_EXIT_BUDGET:?} of SIGTERM; stderr:\n{}",
                self.stderr.text()
            )
        });
        (status, started.elapsed())
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// What a restart of `advance start` does on a home declaring `lifecycle` (here with `fs`
/// and `llm`) is what it did before `compose`: the first run registers the root agent with
/// the CONTRACT-219 projector and exits 0 after SIGTERM; the second run, a new process,
/// registers the root agent again, which conflicts with the live registration the first run
/// left, and exits 1 with that wiring failure. Reusing the registration is limited to a
/// composition earlier in the same process
/// (`crates/runtime-compose/tests/module_001_compose_lifecycle_again.rs`).
#[test]
fn module_001_ac30_lifecycle_home_restart_keeps_its_wiring_failure() {
    let home = AllCapsHome::declaring(&["fs", "llm", "lifecycle"], true);
    let mut first = Daemon::start(&home);
    first.wait_ready();
    let (status, _) = first.stop();
    assert_eq!(
        status.code(),
        Some(0),
        "the first run exits 0 after SIGTERM; stderr:\n{}",
        first.stderr.finish()
    );

    let mut second = Daemon::start(&home);
    let status = second
        .wait_exit(FAILURE_EXIT_BUDGET)
        .expect("the second run exits on its own");
    let stderr = second.stderr.finish();
    let stdout = second.stdout.finish();
    assert_eq!(status.code(), Some(1), "stderr:\n{stderr}");
    assert_eq!(
        stderr.lines().last(),
        Some(
            "advance start: wiring failed: agent-tree config materialization failure: \
             begin C219 agent registration: InvalidIdentity"
        ),
        "stderr:\n{stderr}"
    );
    assert!(
        !stdout.contains("advance: runtime ready"),
        "the second run fails before readiness; stdout:\n{stdout}"
    );
    assert!(
        !home.ws.join(".runtime/runtime.lock").exists(),
        "the failed run released the runtime lock"
    );
}

/// A second `advance start` on a home whose daemon is up exits 1 with the lock failure,
/// naming the running daemon's pid; the first daemon is untouched.
#[test]
fn module_001_ac30_t111_1_second_daemon_same_home_exits_1() {
    let home = AllCapsHome::declaring(&["fs"], false);
    let mut first = Daemon::start(&home);
    first.wait_ready();

    let mut second = Daemon::start(&home);
    let status = second
        .wait_exit(FAILURE_EXIT_BUDGET)
        .expect("the second advance start exits on its own");
    let stderr = second.stderr.finish();
    let stdout = second.stdout.finish();
    assert_eq!(status.code(), Some(1), "stderr:\n{stderr}");
    assert_eq!(
        stderr,
        format!(
            "advance start: failed to acquire runtime lock: another runtime active (pid={})\n",
            first.pid()
        )
    );
    assert_eq!(stdout, "", "the refused start prints nothing on stdout");

    let (status, _) = first.stop();
    assert_eq!(
        status.code(),
        Some(0),
        "the first daemon still exits 0; stderr:\n{}",
        first.stderr.finish()
    );
}

/// The home declaring every capability on a git repository — the one case that never exited
/// after SIGTERM before the lane — exits 0, with `advance: shutting down` as its last stdout
/// line, the runtime lock removed and the discovery and selected-provider files kept.
#[test]
fn module_001_ac30_t111_1_sigterm_exits_0_on_all_capabilities_git_home() {
    let home = AllCapsHome::new();
    let mut daemon = Daemon::start(&home);
    daemon.wait_ready();
    let (status, took) = daemon.stop();
    let stdout = daemon.stdout.finish();
    let stderr = daemon.stderr.finish();
    eprintln!("all-capabilities git home: exit {status:?} {took:?} after SIGTERM");
    assert_eq!(status.code(), Some(0), "stderr:\n{stderr}");
    assert_eq!(
        stdout.lines().last(),
        Some("advance: shutting down"),
        "stdout:\n{stdout}"
    );
    let runtime = home.ws.join(".runtime");
    assert!(
        !runtime.join("runtime.lock").exists(),
        "runtime.lock removed"
    );
    assert!(runtime.join("client-api").exists(), "client-api kept");
    assert!(
        runtime.join("selected-provider").exists(),
        "selected-provider kept"
    );
}

/// The thin `main` keeps today's order: the current-thread runtime, then (inside it) the
/// signal listeners before the workspace is resolved and before `compose` takes the lock.
/// No lock is taken by `advance start` itself.
#[test]
fn module_001_ac30_thin_start_installs_signal_listeners_before_compose() {
    let source = include_str!("../src/commands/start.rs");
    let runtime = source
        .find("new_current_thread()")
        .expect("run builds a current-thread runtime");
    let drives = source
        .find("rt.block_on(run_async(")
        .expect("run drives run_async on it");
    assert!(runtime < drives);

    let start = source
        .find("async fn run_async(")
        .expect("the thin start's run_async");
    let body = &source[start..];
    let body = &body[..body.find("\n}\n").expect("end of run_async")];
    let position = |needle: &str| {
        body.find(needle)
            .unwrap_or_else(|| panic!("run_async calls {needle}"))
    };
    let signals = position("install_unix_listeners()");
    let workspace = position("resolve_workspace(");
    let compose = position("compose(");
    let park = position("park_until_shutdown_unix(");
    let shutdown = position(".shutdown().await");
    assert!(
        signals < workspace && workspace < compose && compose < park && park < shutdown,
        "run_async order: signals {signals}, workspace {workspace}, compose {compose}, \
         park {park}, shutdown {shutdown}"
    );
    assert!(
        !source.contains("RuntimeLock"),
        "the lock is the composition's, never the thin start's"
    );
}

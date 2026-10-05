//! `advance start [--workspace <path>]` — runs the runtime daemon: a thin `main` over
//! [`advance_runtime_compose::compose`].
//!
//! The order is the one `advance start` has always followed: build the current-thread
//! runtime; install the SIGINT / SIGTERM listeners, so a signal that arrives while the
//! runtime lock is being acquired is caught; resolve the workspace (`--workspace`, then
//! `$ADVANCE_WORKSPACE`, then the current directory); compose the runtime with the
//! daemon options (the composition takes the lock and emits every line through this
//! command's [`StdioComposeLog`]); wait for a signal; shut the runtime down. Exit 1 on
//! any startup failure, 0 after a clean shutdown.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use advance_runtime_compose::{
    compose, ComposeError, ComposeLog, ComposeLogLine, ComposeOptions, LogStream,
};

pub use advance_runtime_compose::daemon::DEFAULT_MSG_AGENT_ID;
#[cfg(feature = "test-support")]
pub use advance_runtime_compose::daemon::{spawn_test_agent_loop, TestServeLoop};

/// Render a `Path` for safe stderr emission. Adversarial R1 W4 fix: a path
/// sourced from user input (e.g. `--workspace`, `$ADVANCE_WORKSPACE`, or
/// pulled from a tampered config file) may carry ANSI escapes, terminal
/// control sequences, or newlines. `Path::display()` does NOT escape these;
/// `{:?}` formatting routes through Debug → `escape_debug` and DOES.
fn safe_path(p: &Path) -> String {
    format!("{p:?}")
}

/// Sync entry point invoked from `main.rs`. Builds a current-thread Tokio
/// runtime and drives `run_async`.
///
/// Incident (grok-housekeeping clippy stage 1): blessed CLI sync entry.
/// This uses an *owned* `tokio::runtime::Runtime::block_on`, never
/// `Handle::block_on` (nested-runtime panic) and never
/// `futures::executor::block_on`. Root `clippy.toml` bans those two
/// paths. `Runtime::block_on` itself is not banned; the allow documents
/// the named site from DEV-TASK / Item 5.
#[allow(
    clippy::disallowed_methods,
    reason = "blessed CLI sync entry: owned Runtime::block_on, not Handle::block_on or futures::executor::block_on"
)]
pub fn run(workspace: Option<PathBuf>) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("advance start: failed to build tokio runtime: {e}");
            return ExitCode::from(1);
        }
    };
    rt.block_on(run_async(workspace))
}

async fn run_async(workspace: Option<PathBuf>) -> ExitCode {
    // 1. Install signal listeners FIRST. Tokio's `signal(SignalKind::*)` is
    //    synchronous (installs the kernel handler eagerly), so subsequent
    //    SIGINT/SIGTERM during lock-acquire or bootstrap is captured and
    //    pending — preventing a window where the kernel default handler kills
    //    the process before the lock can be released or bootstrap can clean up.
    //    (Audit R1 W1 fix.)
    #[cfg(unix)]
    let listeners = match install_unix_listeners() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("advance start: failed to install signal listeners: {e}");
            return ExitCode::from(1);
        }
    };

    // 2. Resolve workspace: --workspace → $ADVANCE_WORKSPACE → CWD.
    let workspace = match resolve_workspace(workspace) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("advance start: {msg}");
            return ExitCode::from(1);
        }
    };

    // 3. Workspace must exist as a directory. canonicalize() requires the path
    //    to exist; check first to produce a friendly error.
    if !workspace.is_dir() {
        eprintln!(
            "advance start: workspace does not exist or is not a directory: {}",
            safe_path(&workspace)
        );
        return ExitCode::from(1);
    }
    let workspace = match workspace.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "advance start: failed to canonicalize workspace {}: {e}",
                safe_path(&workspace)
            );
            return ExitCode::from(1);
        }
    };

    // 4. Compose: the instance guard (the runtime lock, heartbeat 30 s per MODULE-001
    //    §1.4.3), the runtime host, the capability graph, the readiness line, the agent
    //    loop and its listeners. A failure after part of it started stops what started
    //    (no line printed), then is reported.
    let log: Arc<dyn ComposeLog> = Arc::new(StdioComposeLog);
    let runtime = match compose(ComposeOptions::daemon(workspace, log), Vec::new()).await {
        Ok(runtime) => runtime,
        Err(error) => return startup_failed(error),
    };

    // 5. Park until SIGINT / SIGTERM. Listeners were installed in step 1 (above
    //    lock-acquire) so any signal received during lock-acquire or bootstrap
    //    is captured and pending; the .recv() here just resolves immediately
    //    in that case.
    #[cfg(unix)]
    park_until_shutdown_unix(listeners).await;
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }

    // 6. The ordered shutdown: ingress, loops (then `advance: shutting down`), the
    //    holds in dependency order, the runtime lock last.
    match runtime.shutdown().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => startup_failed(error),
    }
}

/// Report a failure the way `advance start` always has (`advance start: …` on stderr)
/// and exit 1.
fn startup_failed(error: ComposeError) -> ExitCode {
    eprintln!("advance start: {error}");
    ExitCode::from(1)
}

/// The daemon's output: every line the composition emits goes to the stream it names,
/// exactly as `advance start` has always printed it.
///
/// A line is written with `writeln!` on the locked stream: the bytes and the buffering
/// are those of `println!` / `eprintln!` (the text and its `\n` in one `write_fmt`), but
/// a line its stream refuses (the reader closed the pipe) is dropped instead of
/// panicking, so a task that reports through the log never unwinds because nobody reads
/// its output. The readiness line is written and flushed on the locked stdout, so a
/// supervisor reading stdout through a pipe sees it at once; a write or flush that fails
/// is returned, the composition stops, and `advance start` exits 1.
struct StdioComposeLog;

impl ComposeLog for StdioComposeLog {
    fn line(&self, line: &ComposeLogLine) {
        let _ = match line.stream {
            LogStream::Stdout => writeln!(std::io::stdout().lock(), "{}", line.text),
            LogStream::Stderr => writeln!(std::io::stderr().lock(), "{}", line.text),
        };
    }

    fn ready(&self, line: &ComposeLogLine) -> std::io::Result<()> {
        let mut out = std::io::stdout().lock();
        writeln!(out, "{}", line.text)?;
        out.flush()
    }
}

#[cfg(unix)]
struct UnixSignalListeners {
    sigint: tokio::signal::unix::Signal,
    sigterm: tokio::signal::unix::Signal,
}

#[cfg(unix)]
fn install_unix_listeners() -> std::io::Result<UnixSignalListeners> {
    use tokio::signal::unix::{signal, SignalKind};
    Ok(UnixSignalListeners {
        sigint: signal(SignalKind::interrupt())?,
        sigterm: signal(SignalKind::terminate())?,
    })
}

#[cfg(unix)]
async fn park_until_shutdown_unix(mut listeners: UnixSignalListeners) {
    tokio::select! {
        _ = listeners.sigint.recv() => {}
        _ = listeners.sigterm.recv() => {}
    }
}

fn resolve_workspace(explicit: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    if let Some(ws) = std::env::var_os("ADVANCE_WORKSPACE") {
        if !ws.is_empty() {
            return Ok(PathBuf::from(ws));
        }
    }
    std::env::current_dir().map_err(|e| format!("cannot resolve CWD as workspace: {e}"))
}

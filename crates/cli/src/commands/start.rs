//! `advance start [--workspace <path>]` — runs the runtime daemon.
//!
//! The daemon itself (runtime, signal listeners, workspace resolution, lock,
//! bootstrap, capability wiring, agent loop, listeners, shutdown) lives in
//! [`advance_runtime_compose::daemon`]; this command forwards to it.

use std::path::PathBuf;
use std::process::ExitCode;

pub use advance_runtime_compose::daemon::DEFAULT_MSG_AGENT_ID;
#[cfg(feature = "test-support")]
pub use advance_runtime_compose::daemon::{spawn_test_agent_loop, TestServeLoop};

/// Sync entry point invoked from `main.rs`.
pub fn run(workspace: Option<PathBuf>) -> ExitCode {
    advance_runtime_compose::run_daemon(workspace)
}

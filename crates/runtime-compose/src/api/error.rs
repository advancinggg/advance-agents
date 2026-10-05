//! Why the composition did not start.
//!
//! Every variant's `Display` is the text `advance start` prints after
//! `advance start: ` for that failure.

use std::fmt;
use std::path::PathBuf;

/// A composition that did not start. Whatever had started is stopped before the
/// error is returned.
#[non_exhaustive]
#[derive(Debug)]
pub enum ComposeError {
    /// The home has no `.advance/runtime-config.yaml`.
    ConfigNotFound { path: PathBuf },
    /// The instance guard could not be taken.
    Lock(LockFailure),
    /// The runtime host could not be built from the runtime config.
    Bootstrap(String),
    /// The capability wiring failed.
    Wiring(String),
    /// The deployed agent component could not be read, encoded or loaded.
    AgentLoop(String),
    /// A listener the composition needs could not be bound.
    Listener(String),
    /// The readiness line could not be written.
    Readiness(std::io::Error),
}

/// Why the instance guard could not be taken.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockFailure {
    /// A live runtime process holds the home's runtime lock.
    ActiveRuntime { pid: u32 },
    /// A composition in this process already holds the home.
    HeldInProcess,
    /// The process-local registry of composed homes is poisoned.
    RegistryPoisoned,
    /// The runtime lock could not be read or written.
    Io(String),
    /// The runtime lock could not be parsed.
    Parse(String),
}

impl LockFailure {
    /// The failure a [`RuntimeLock::acquire`] error reports.
    ///
    /// [`RuntimeLock::acquire`]: advance_runtime::runtime_lock::RuntimeLock::acquire
    pub(crate) fn from_lock_error(error: &advance_runtime::runtime_lock::LockError) -> Self {
        use advance_runtime::runtime_lock::LockError;
        match error {
            LockError::ActiveRuntime(pid) => LockFailure::ActiveRuntime { pid: *pid },
            LockError::Io(e) => LockFailure::Io(e.to_string()),
            LockError::Parse(msg) => LockFailure::Parse(msg.clone()),
        }
    }
}

impl fmt::Display for LockFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LockFailure::ActiveRuntime { pid } => write!(f, "another runtime active (pid={pid})"),
            LockFailure::HeldInProcess => {
                write!(f, "another runtime active (pid={})", std::process::id())
            }
            LockFailure::RegistryPoisoned => f.write_str("process-local registry lock poisoned"),
            LockFailure::Io(msg) => write!(f, "lock I/O error: {msg}"),
            LockFailure::Parse(msg) => write!(f, "lock parse error: {msg}"),
        }
    }
}

impl fmt::Display for ComposeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ComposeError::ConfigNotFound { path } => write!(
                f,
                "runtime-config.yaml not found at {path:?}; run `advance init <workspace>` first"
            ),
            ComposeError::Lock(failure) => write!(f, "failed to acquire runtime lock: {failure}"),
            ComposeError::Bootstrap(msg) => write!(f, "bootstrap failed: {msg}"),
            ComposeError::Wiring(msg) => write!(f, "wiring failed: {msg}"),
            ComposeError::AgentLoop(msg) | ComposeError::Listener(msg) => f.write_str(msg),
            ComposeError::Readiness(e) => write!(f, "failed to flush readiness signal: {e}"),
        }
    }
}

impl std::error::Error for ComposeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ComposeError::Readiness(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use advance_runtime::runtime_lock::LockError;

    #[test]
    fn module_001_ac30_lock_failures_render_as_the_lock_errors_they_come_from() {
        let errors = [
            LockError::ActiveRuntime(4242),
            LockError::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            LockError::Parse("bad yaml".to_owned()),
        ];
        for error in &errors {
            assert_eq!(
                ComposeError::Lock(LockFailure::from_lock_error(error)).to_string(),
                format!("failed to acquire runtime lock: {error}")
            );
        }
    }
}

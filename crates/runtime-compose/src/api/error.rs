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
    /// An extension's Client API route was refused.
    Registration {
        extension: &'static str,
        route: String,
        reason: String,
    },
    /// An extension's claim on an inference entry was refused.
    InferenceClaim {
        extension: &'static str,
        entry: String,
        reason: String,
    },
    /// An extension's capability name was refused.
    CapabilityCollision {
        extension: &'static str,
        capability: String,
        reason: CapabilityRefusal,
    },
    /// An extension's host function was refused.
    HostFunction {
        extension: &'static str,
        refusal: super::host_functions::HostFunctionRefusal,
    },
    /// An extension's native tool was refused.
    Tool {
        extension: &'static str,
        refusal: super::tools::ToolRefusal,
    },
    /// An extension callback failed or panicked.
    Extension {
        extension: &'static str,
        phase: ExtensionPhase,
        failure: ExtensionFailure,
    },
    /// These options ask for something this build or this home cannot compose. Nothing
    /// was started.
    Unsupported(Unsupported),
}

/// Why [`ComposeError::CapabilityCollision`] refused a name.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityRefusal {
    /// The name is in `KNOWN_CAPABILITIES` or `RESERVED_CAPABILITY_NAMES`.
    Known,
    /// An earlier extension already declared it.
    OtherExtension { owner: &'static str },
    /// The same extension listed it twice.
    Duplicate,
    /// The name is not `<id>.<name>` (the text says why).
    Malformed(&'static str),
    /// The part before `.` is not this extension's id.
    ForeignPrefix,
    /// More than `MAX_EXTENSION_CAPABILITIES` names in this compose.
    TooMany { limit: usize },
}

/// The composition step an extension callback belongs to.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionPhase {
    Capabilities,
    Inference,
    HostFunctions,
    Tools,
    ClientFamilies,
}

/// How an extension callback ended badly.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionFailure {
    /// It returned an error (its message).
    Failed(String),
    /// It panicked (the panic message).
    Panicked(String),
}

/// What [`ComposeError::Unsupported`] refused.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unsupported {
    /// An option value this build does not compose yet (its name).
    NotYetAvailable(&'static str),
    /// The home is not an absolute, canonical directory.
    HomeNotCanonical(PathBuf),
    /// The state root is unusable, and why.
    StateRoot { path: PathBuf, reason: &'static str },
    /// A Client API discovery file was asked for without the pid-lock instance guard.
    DiscoveryRequiresPidLock,
    /// The home's config needs a listener these options disable (its name).
    ListenerRequired(&'static str),
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
            ComposeError::Registration {
                extension,
                route,
                reason,
            } => write!(f, "extension {extension}: route {route} refused: {reason}"),
            ComposeError::InferenceClaim {
                extension,
                entry,
                reason,
            } => write!(
                f,
                "extension {extension}: inference claim on {entry} refused: {reason}"
            ),
            ComposeError::CapabilityCollision {
                extension,
                capability,
                reason,
            } => write!(
                f,
                "extension {extension}: capability {capability} refused: {reason}"
            ),
            ComposeError::HostFunction { extension, refusal } => {
                write!(f, "extension {extension}: host function refused: {refusal}")
            }
            ComposeError::Tool { extension, refusal } => {
                write!(f, "extension {extension}: tool refused: {refusal}")
            }
            ComposeError::Extension {
                extension,
                phase,
                failure: ExtensionFailure::Failed(msg),
            } => write!(f, "extension {extension} failed in {phase}: {msg}"),
            ComposeError::Extension {
                extension,
                phase,
                failure: ExtensionFailure::Panicked(msg),
            } => write!(f, "extension {extension} panicked in {phase}: {msg}"),
            ComposeError::Unsupported(what) => write!(f, "unsupported: {what}"),
        }
    }
}

impl fmt::Display for CapabilityRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapabilityRefusal::Known => f.write_str("it is an OSS capability name"),
            CapabilityRefusal::OtherExtension { owner } => {
                write!(f, "extension {owner} already declares it")
            }
            CapabilityRefusal::Duplicate => f.write_str("declared twice"),
            CapabilityRefusal::Malformed(why) => f.write_str(why),
            CapabilityRefusal::ForeignPrefix => {
                f.write_str("its prefix is not this extension's id")
            }
            CapabilityRefusal::TooMany { limit } => {
                write!(f, "more than {limit} extension capabilities")
            }
        }
    }
}

impl fmt::Display for ExtensionPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ExtensionPhase::Capabilities => "capabilities",
            ExtensionPhase::Inference => "inference",
            ExtensionPhase::HostFunctions => "host_functions",
            ExtensionPhase::Tools => "tools",
            ExtensionPhase::ClientFamilies => "client_families",
        })
    }
}

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unsupported::NotYetAvailable(what) => {
                write!(f, "{what} is not available in this build")
            }
            Unsupported::HomeNotCanonical(path) => {
                write!(f, "home {path:?} is not an absolute canonical directory")
            }
            Unsupported::StateRoot { path, reason } => write!(f, "state_root {path:?} {reason}"),
            Unsupported::DiscoveryRequiresPidLock => {
                f.write_str("a Client API discovery file requires the pid-lock instance guard")
            }
            Unsupported::ListenerRequired(which) => write!(
                f,
                "the home's config needs the {which} listener, which these options disable"
            ),
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

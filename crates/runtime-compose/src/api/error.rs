//! Why the composition did not start.
//!
//! Every variant's `Display` is the text `advance start` prints after
//! `advance start: ` for that failure.

use std::fmt;
use std::path::PathBuf;

use advance_client_api::families::RouteRefusalReason;

use super::options::{HostPlatform, PlatformRule};

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
        reason: RouteRefusalReason,
    },
    /// An extension's claim on an inference entry, profile, or mesh dispatch was refused.
    InferenceClaim {
        extension: &'static str,
        subject: InferenceSubject,
        reason: InferenceRefusal,
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

/// What an inference contribution named.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InferenceSubject {
    Entry(String),
    Profile(String),
    MeshDispatch,
}

/// Why [`ComposeError::InferenceClaim`] refused a record.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InferenceRefusal {
    /// No `llm-providers` entry with this id in the home's boot config.
    AbsentEntry,
    /// The entry already has a claimant (`by` may be the refused extension itself).
    AlreadyClaimed { by: &'static str },
    /// OSS binds this entry, decided by its backend class.
    BoundByOss(OssBinding),
    /// `local` with a sidecar under `ProcessPolicy::Forbid`: bound to a typed refusal.
    SidecarUnderForbid,
    /// `mesh-remote` entries are served by the (one) mesh dispatch, never claimed.
    MeshRemoteEntry,
    /// A profile with this id was already added (`by` may be the refused extension itself).
    DuplicateProfile { by: &'static str },
    /// `ModelProfileCatalog::insert` refused the profile; its text.
    InvalidProfile(String),
    /// A mesh dispatch was already supplied (`first` may be the refused extension itself).
    SecondMeshDispatch { first: &'static str },
}

/// The OSS binding that refused a claim, decided by backend class.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OssBinding {
    LocalSidecar,
    AgentCli,
    CloudWireAdapter,
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
    /// `Embedded { platform }` with an option the D3 table does not allow on that row.
    PlatformTable {
        platform: HostPlatform,
        rule: PlatformRule,
    },
    /// A binary compiled for iOS / Android composes only `Embedded { platform: <that os> }`.
    PlatformMismatch { compiled: HostPlatform },
    /// iOS / Android need a `state_root` (outside the home).
    StateRootRequired { platform: HostPlatform },
    /// `ProcessLocal` binds no listener but the Client API (D3 "No daemon artefacts on mobile").
    ListenerUnderProcessLocal(&'static str),
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
            } => {
                if matches!(
                    reason,
                    RouteRefusalReason::InvalidBudget { .. } | RouteRefusalReason::BudgetAlreadySet
                ) {
                    write!(f, "extension {extension}: family budget refused: {reason}")
                } else {
                    write!(f, "extension {extension}: route {route} refused: {reason}")
                }
            }
            ComposeError::InferenceClaim {
                extension,
                subject,
                reason,
            } => write!(
                f,
                "extension {extension}: inference claim on {subject} refused: {reason}"
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

impl fmt::Display for InferenceSubject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InferenceSubject::Entry(id) => write!(f, "entry {id:?}"),
            InferenceSubject::Profile(id) => write!(f, "profile {id:?}"),
            InferenceSubject::MeshDispatch => f.write_str("mesh dispatch"),
        }
    }
}

impl fmt::Display for InferenceRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InferenceRefusal::AbsentEntry => {
                f.write_str("no such entry in the home's llm-providers")
            }
            InferenceRefusal::AlreadyClaimed { by } => {
                write!(f, "already claimed by extension {by}")
            }
            InferenceRefusal::BoundByOss(binding) => write!(f, "bound by OSS ({binding})"),
            InferenceRefusal::SidecarUnderForbid => f.write_str(
                "a local entry with a sidecar is bound to a typed refusal under ProcessPolicy::Forbid",
            ),
            InferenceRefusal::MeshRemoteEntry => {
                f.write_str("mesh-remote entries are served by the mesh dispatch")
            }
            InferenceRefusal::DuplicateProfile { by } => {
                write!(f, "profile id already added by extension {by}")
            }
            InferenceRefusal::InvalidProfile(message) => {
                write!(f, "the catalog refused the profile: {message}")
            }
            InferenceRefusal::SecondMeshDispatch { first } => {
                write!(
                    f,
                    "a mesh dispatch is already supplied by extension {first}"
                )
            }
        }
    }
}

impl fmt::Display for OssBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OssBinding::LocalSidecar => "local sidecar",
            OssBinding::AgentCli => "agent-cli",
            OssBinding::CloudWireAdapter => "cloud wire adapter",
        })
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
            Unsupported::PlatformTable { platform, rule } => match rule {
                PlatformRule::Instance if platform.is_mobile() => write!(
                    f,
                    "the {platform} embedded profile requires the process-local instance guard"
                ),
                PlatformRule::Instance => write!(
                    f,
                    "the {platform} embedded profile requires the pid-lock instance guard"
                ),
                PlatformRule::Processes => {
                    write!(f, "the {platform} embedded profile requires processes forbid")
                }
                PlatformRule::Engine => write!(
                    f,
                    "the {platform} embedded profile requires the pulley engine"
                ),
            },
            Unsupported::PlatformMismatch { compiled } => write!(
                f,
                "this build targets {compiled}; only the {compiled} embedded profile can compose here"
            ),
            Unsupported::StateRootRequired { platform } => write!(
                f,
                "the {platform} embedded profile requires a state_root outside the home"
            ),
            Unsupported::ListenerUnderProcessLocal(which) => write!(
                f,
                "the {which} listener is not available with the process-local instance guard"
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

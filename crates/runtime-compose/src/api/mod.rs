//! The composition API: the types an embedder names to compose the runtime, receive
//! its output and stop it.

mod compose_log;
mod error;
mod extension;
mod options;
mod runtime;

pub use crate::compose::compose;
pub use compose_log::log_keys;
pub use compose_log::ComposeLog;
pub use compose_log::ComposeLogLine;
pub use compose_log::LogStream;
pub use compose_log::NullComposeLog;
pub use error::ComposeError;
pub use error::ExtensionFailure;
pub use error::ExtensionPhase;
pub use error::LockFailure;
pub use error::Unsupported;
pub use extension::BoxFuture;
pub use extension::ComposeExtension;
pub use options::Admission;
pub use options::ClientApiOptions;
pub use options::ComposeOptions;
pub use options::ComposeProfile;
pub use options::HostPlatform;
pub use options::InstanceGuard;
pub use options::ListenerOptions;
pub use options::MasterKeyInput;
pub use options::ProcessPolicy;
pub use options::WasmEngine;
pub use options::Zeroizing;
pub use runtime::ClientApiEndpoint;
pub use runtime::ComposedRuntime;
pub use runtime::InstanceGuardKind;
pub use runtime::RuntimeHealthView;
pub use runtime::RuntimePhase;
pub use runtime::ShutdownHandle;

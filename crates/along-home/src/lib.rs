//! CONTRACT-243 Along-home first-open host library.
//!
//! Callable before any daemon or CONTRACT-210 embed exists. Never returns
//! provider key material.

#![deny(unsafe_code)]

pub mod cancel;
pub mod connect;
pub mod contract;
pub mod create;
pub mod discovery;
pub mod display_name;
pub mod impls;
pub mod ports;
pub mod provider;
pub mod recognize;
pub mod runtime_state;
pub mod scaffold;
pub mod secret_bytes;

pub use cancel::CancelToken;
pub use connect::ProcessLauncher;
pub use contract::{
    AdoptError, AlongHomeFirstOpen, AlongHomeHandle, ConnectError, ConnectedAlong, CreateError,
    DisplayNameError, PreflightFail, PreflightPass, ProviderStatus, RecognizeClass, RuntimeState,
};
pub use discovery::{write_client_api_discovery, ClientApiDiscovery};
pub use display_name::TopLevelDisplayName;
pub use impls::HostAlongHome;
pub use ports::{AdoptPort, GeneratePathPreflight, PreflightPort, RuntimeLauncher};
pub use runtime_state::{write_selected_provider, SelectedProvider};
pub use scaffold::{write_recognizable_home, AGENT_CONFIG_STARTER, MINIMAL_STARTER};
pub use secret_bytes::SecretBytes;

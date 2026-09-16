//! CONTRACT-243 workspace-home first-open host library.
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
pub mod secrets_mode;

pub use cancel::CancelToken;
pub use connect::ProcessLauncher;
pub use contract::{
    AdoptError, ConnectError, ConnectedRuntime, CreateError, DisplayNameError, PreflightFail,
    PreflightPass, ProviderStatus, RecognizeClass, RuntimeState, WorkspaceHomeFirstOpen,
    WorkspaceHomeHandle,
};
pub use create::create_with_secrets_mode;
pub use discovery::{write_client_api_discovery, ClientApiDiscovery};
pub use display_name::{TopLevelDisplayName, DISPLAY_NAME_KEY};
pub use impls::HostWorkspaceHome;
pub use ports::{AdoptPort, GeneratePathPreflight, PreflightPort, RuntimeLauncher};
pub use provider::{
    list_provider_entries, open_home_secret_store, remove_provider_entry, select_provider,
    upsert_provider_entry, ProviderWriteError, UpsertMode,
};
pub use runtime_state::{write_selected_provider, SelectedProvider};
pub use scaffold::{
    starter_for_mode, write_recognizable_home, write_recognizable_home_with_mode, SecretsMode,
    AGENT_CONFIG_STARTER, MINIMAL_STARTER,
};
pub use secret_bytes::SecretBytes;
pub use secrets_mode::{
    read_secrets_mode, rewrite_secrets_mode, SecretsModeChange, SecretsModeView,
    SecretsModeWriteError,
};

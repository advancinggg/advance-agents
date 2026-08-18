//! CONTRACT-243 types and trait.

use std::path::{Path, PathBuf};

use crate::cancel::CancelToken;
use crate::secret_bytes::SecretBytes;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecognizeClass {
    Recognized { path: PathBuf },
    NotAnAlongHome,
    Unreadable,
    Unwritable,
    Damaged,
}

/// Opaque handle. No key field.
#[derive(Clone)]
pub struct AlongHomeHandle {
    pub(crate) path: PathBuf,
}

impl AlongHomeHandle {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl std::fmt::Debug for AlongHomeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlongHomeHandle")
            .field("path", &self.path)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightPass {
    pub provider_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectedAlong {
    pub home: PathBuf,
    pub client_api_base: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderStatus {
    Absent,
    Present { provider_id: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeState {
    Idle,
    Starting,
    Running,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateError {
    ExistsNotAlongHome,
    ParentUnusable(RecognizeClass),
    InvalidName,
    Io,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayNameError {
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightFail {
    Cancelled,
    MissingProvider,
    ProviderRejected { reason: String },
}

impl std::fmt::Display for PreflightFail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(f, "cancelled"),
            Self::MissingProvider => write!(f, "missing-provider"),
            Self::ProviderRejected { reason } => write!(f, "provider-rejected:{reason}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectError {
    Cancelled,
    LaunchFailed { reason: String },
    UnattachableThenFailed { reason: String },
    AdoptFailed { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdoptError {
    Cancelled,
    NotRunning,
    ProviderNotAdopted { reason: String },
}

pub trait AlongHomeFirstOpen: Send + Sync {
    fn recognize(&self, path: &Path) -> RecognizeClass;
    fn open(&self, path: &Path) -> Result<AlongHomeHandle, RecognizeClass>;
    fn create(&self, parent: &Path, name: &str) -> Result<AlongHomeHandle, CreateError>;
    fn provider_status(&self, home: &AlongHomeHandle) -> ProviderStatus;
    fn runtime_state(&self, home: &AlongHomeHandle) -> RuntimeState;
    fn store_and_preflight(
        &self,
        home: &AlongHomeHandle,
        provider_id: &str,
        key: SecretBytes,
        cancel: &CancelToken,
    ) -> Result<PreflightPass, PreflightFail>;
    fn confirm_existing_provider(
        &self,
        home: &AlongHomeHandle,
        cancel: &CancelToken,
    ) -> Result<PreflightPass, PreflightFail>;
    fn set_display_name(&self, home: &AlongHomeHandle, name: &str) -> Result<(), DisplayNameError>;
    fn current_display_name(&self, home: &AlongHomeHandle) -> Option<String>;
    fn start_or_attach(
        &self,
        home: &AlongHomeHandle,
        cancel: &CancelToken,
    ) -> Result<ConnectedAlong, ConnectError>;
    fn adopt_provider_on_running(
        &self,
        home: &AlongHomeHandle,
        cancel: &CancelToken,
    ) -> Result<(), AdoptError>;
}

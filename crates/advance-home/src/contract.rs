//! CONTRACT-243 types and trait.

use std::path::{Path, PathBuf};

use crate::cancel::CancelToken;
use crate::secret_bytes::SecretBytes;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecognizeClass {
    Recognized { path: PathBuf },
    NotAWorkspaceHome,
    Unreadable,
    Unwritable,
    Damaged,
}

/// Opaque handle. No key field.
#[derive(Clone)]
pub struct WorkspaceHomeHandle {
    pub(crate) path: PathBuf,
}

impl WorkspaceHomeHandle {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl std::fmt::Debug for WorkspaceHomeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkspaceHomeHandle")
            .field("path", &self.path)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightPass {
    pub provider_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectedRuntime {
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
    ExistsNotWorkspaceHome,
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

pub trait WorkspaceHomeFirstOpen: Send + Sync {
    fn recognize(&self, path: &Path) -> RecognizeClass;
    fn open(&self, path: &Path) -> Result<WorkspaceHomeHandle, RecognizeClass>;
    fn create(&self, parent: &Path, name: &str) -> Result<WorkspaceHomeHandle, CreateError>;
    fn provider_status(&self, home: &WorkspaceHomeHandle) -> ProviderStatus;
    fn runtime_state(&self, home: &WorkspaceHomeHandle) -> RuntimeState;
    fn store_and_preflight(
        &self,
        home: &WorkspaceHomeHandle,
        provider_id: &str,
        key: SecretBytes,
        cancel: &CancelToken,
    ) -> Result<PreflightPass, PreflightFail>;
    fn confirm_existing_provider(
        &self,
        home: &WorkspaceHomeHandle,
        cancel: &CancelToken,
    ) -> Result<PreflightPass, PreflightFail>;
    fn set_display_name(
        &self,
        home: &WorkspaceHomeHandle,
        name: &str,
    ) -> Result<(), DisplayNameError>;
    fn current_display_name(&self, home: &WorkspaceHomeHandle) -> Option<String>;
    fn start_or_attach(
        &self,
        home: &WorkspaceHomeHandle,
        cancel: &CancelToken,
    ) -> Result<ConnectedRuntime, ConnectError>;
    fn adopt_provider_on_running(
        &self,
        home: &WorkspaceHomeHandle,
        cancel: &CancelToken,
    ) -> Result<(), AdoptError>;
}

//! Production `WorkspaceHomeFirstOpen` composition.

use std::sync::Arc;
use std::time::Duration;

use crate::cancel::CancelToken;
use crate::connect::{adopt_on_running, start_or_attach, FileAdoptPort, ProcessLauncher};
use crate::contract::{
    AdoptError, ConnectError, ConnectedRuntime, CreateError, DisplayNameError, PreflightFail,
    PreflightPass, ProviderStatus, RecognizeClass, RuntimeState, WorkspaceHomeFirstOpen,
    WorkspaceHomeHandle,
};
use crate::display_name::TopLevelDisplayName;
use crate::ports::{AdoptPort, GeneratePathPreflight, PreflightPort, RuntimeLauncher};
use crate::secret_bytes::SecretBytes;

pub struct HostWorkspaceHome {
    preflight: Arc<dyn PreflightPort>,
    launcher: Arc<dyn RuntimeLauncher>,
    adopt: Arc<dyn AdoptPort>,
    wait_bound: Duration,
}

impl HostWorkspaceHome {
    pub fn production() -> Self {
        Self {
            preflight: Arc::new(GeneratePathPreflight::default()),
            launcher: Arc::new(ProcessLauncher),
            adopt: Arc::new(FileAdoptPort::default()),
            wait_bound: Duration::from_secs(30),
        }
    }

    pub fn with_ports(
        preflight: Arc<dyn PreflightPort>,
        launcher: Arc<dyn RuntimeLauncher>,
        adopt: Arc<dyn AdoptPort>,
    ) -> Self {
        Self::with_ports_and_wait(preflight, launcher, adopt, Duration::from_millis(80))
    }

    pub fn with_ports_and_wait(
        preflight: Arc<dyn PreflightPort>,
        launcher: Arc<dyn RuntimeLauncher>,
        adopt: Arc<dyn AdoptPort>,
        wait_bound: Duration,
    ) -> Self {
        Self {
            preflight,
            launcher,
            adopt,
            wait_bound,
        }
    }
}

impl Default for HostWorkspaceHome {
    fn default() -> Self {
        Self::production()
    }
}

impl WorkspaceHomeFirstOpen for HostWorkspaceHome {
    fn recognize(&self, path: &std::path::Path) -> RecognizeClass {
        crate::recognize::recognize(path)
    }

    fn open(&self, path: &std::path::Path) -> Result<WorkspaceHomeHandle, RecognizeClass> {
        crate::recognize::open(path)
    }

    fn create(
        &self,
        parent: &std::path::Path,
        name: &str,
    ) -> Result<WorkspaceHomeHandle, CreateError> {
        crate::create::create(parent, name)
    }

    fn provider_status(&self, home: &WorkspaceHomeHandle) -> ProviderStatus {
        crate::provider::provider_status(&home.path)
    }

    fn runtime_state(&self, home: &WorkspaceHomeHandle) -> RuntimeState {
        crate::runtime_state::runtime_state(&home.path)
    }

    fn store_and_preflight(
        &self,
        home: &WorkspaceHomeHandle,
        provider_id: &str,
        key: SecretBytes,
        cancel: &CancelToken,
    ) -> Result<PreflightPass, PreflightFail> {
        crate::provider::store_and_preflight(
            &home.path,
            provider_id,
            key,
            cancel,
            self.preflight.as_ref(),
        )
    }

    fn confirm_existing_provider(
        &self,
        home: &WorkspaceHomeHandle,
        cancel: &CancelToken,
    ) -> Result<PreflightPass, PreflightFail> {
        crate::provider::confirm_existing_provider(&home.path, cancel, self.preflight.as_ref())
    }

    fn set_display_name(
        &self,
        home: &WorkspaceHomeHandle,
        name: &str,
    ) -> Result<(), DisplayNameError> {
        TopLevelDisplayName::set(&home.path, name)
    }

    fn current_display_name(&self, home: &WorkspaceHomeHandle) -> Option<String> {
        TopLevelDisplayName::get(&home.path)
    }

    fn start_or_attach(
        &self,
        home: &WorkspaceHomeHandle,
        cancel: &CancelToken,
    ) -> Result<ConnectedRuntime, ConnectError> {
        start_or_attach(
            &home.path,
            cancel,
            self.launcher.as_ref(),
            self.adopt.as_ref(),
            self.wait_bound,
        )
    }

    fn adopt_provider_on_running(
        &self,
        home: &WorkspaceHomeHandle,
        cancel: &CancelToken,
    ) -> Result<(), AdoptError> {
        adopt_on_running(&home.path, cancel, self.adopt.as_ref())
    }
}

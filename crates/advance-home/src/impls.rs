//! Production `WorkspaceHomeFirstOpen` composition.

use std::sync::Arc;
use std::time::Duration;

use crate::cancel::CancelToken;
use crate::connect::{
    adopt_on_running, start_or_attach_via, FileAdoptPort, FileAttachSource, GuardedFileAdoptPort,
    GuardedProcessLauncher, ProcessLauncher, SourceAdoptPort,
};
use crate::contract::{
    AdoptError, ConnectError, ConnectedRuntime, CreateError, DisplayNameError, PreflightFail,
    PreflightPass, ProviderStatus, RecognizeClass, RuntimeState, WorkspaceHomeFirstOpen,
    WorkspaceHomeHandle,
};
use crate::display_name::TopLevelDisplayName;
use crate::ports::{
    AdoptPort, GeneratePathPreflight, PreflightPort, RuntimeAttachSource, RuntimeLauncher,
};
use crate::secret_bytes::SecretBytes;
use advance_shared_types::process_policy::ProcessPolicy;

pub struct HostWorkspaceHome {
    preflight: Arc<dyn PreflightPort>,
    launcher: Arc<dyn RuntimeLauncher>,
    adopt: Arc<dyn AdoptPort>,
    wait_bound: Duration,
    process_policy: ProcessPolicy,
    source: Option<Arc<dyn RuntimeAttachSource>>,
}

impl HostWorkspaceHome {
    pub fn production() -> Self {
        Self {
            preflight: Arc::new(GeneratePathPreflight::default()),
            launcher: Arc::new(ProcessLauncher),
            adopt: Arc::new(FileAdoptPort::default()),
            wait_bound: Duration::from_secs(30),
            process_policy: ProcessPolicy::Allow,
            source: None,
        }
    }

    /// `production()` with `GuardedProcessLauncher::new(policy)`, an adopt port whose lock reads use
    /// `policy`'s probe, and every lock read of `runtime_state` / `start_or_attach` through it.
    pub fn production_with_policy(policy: ProcessPolicy) -> Self {
        Self {
            preflight: Arc::new(GeneratePathPreflight::default()),
            launcher: Arc::new(GuardedProcessLauncher::new(policy)),
            adopt: Arc::new(GuardedFileAdoptPort::new(policy)),
            wait_bound: Duration::from_secs(30),
            process_policy: policy,
            source: None,
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
            process_policy: ProcessPolicy::Allow,
            source: None,
        }
    }

    /// The lock-read policy of the default (file) source. Has no effect on a source set with
    /// `with_attach_source` / `with_ports_source_and_wait`.
    pub fn with_process_policy(mut self, policy: ProcessPolicy) -> Self {
        self.process_policy = policy;
        self
    }

    /// MODULE-001-AC-34: start, attach, adopt and `runtime_state` read `source`. The adopt wait goes
    /// through a [`SourceAdoptPort`] over the same source (30 s); the start/attach wait is 30 s, as in
    /// `production`. With runtime-compose's `ProcessLocalAttachSource`, pass its `InProcessLauncher`
    /// (a `ProcessLauncher` would start a daemon this source cannot see) and call this home from a
    /// thread that is not a worker of the launcher's Tokio runtime.
    pub fn with_attach_source(
        preflight: Arc<dyn PreflightPort>,
        launcher: Arc<dyn RuntimeLauncher>,
        source: Arc<dyn RuntimeAttachSource>,
    ) -> Self {
        Self {
            preflight,
            launcher,
            adopt: Arc::new(SourceAdoptPort::new(Arc::clone(&source))),
            wait_bound: Duration::from_secs(30),
            process_policy: ProcessPolicy::Allow,
            source: Some(source),
        }
    }

    /// Every port explicit (tests).
    pub fn with_ports_source_and_wait(
        preflight: Arc<dyn PreflightPort>,
        launcher: Arc<dyn RuntimeLauncher>,
        adopt: Arc<dyn AdoptPort>,
        source: Arc<dyn RuntimeAttachSource>,
        wait_bound: Duration,
    ) -> Self {
        Self {
            preflight,
            launcher,
            adopt,
            wait_bound,
            process_policy: ProcessPolicy::Allow,
            source: Some(source),
        }
    }

    fn with_source<R>(&self, f: impl FnOnce(&dyn RuntimeAttachSource) -> R) -> R {
        match &self.source {
            Some(source) => f(source.as_ref()),
            None => f(&FileAttachSource::with_policy(self.process_policy)),
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
        self.with_source(|source| source.runtime_state(&home.path))
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
        self.with_source(|source| {
            start_or_attach_via(
                &home.path,
                cancel,
                self.launcher.as_ref(),
                self.adopt.as_ref(),
                source,
                self.wait_bound,
            )
        })
    }

    fn adopt_provider_on_running(
        &self,
        home: &WorkspaceHomeHandle,
        cancel: &CancelToken,
    ) -> Result<(), AdoptError> {
        adopt_on_running(&home.path, cancel, self.adopt.as_ref())
    }
}

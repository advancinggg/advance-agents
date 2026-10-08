//! Injectable seams for preflight, launch, and adopt.

use std::path::Path;
use std::sync::Arc;

use advance_runtime::config::LlmProviderConfig;
use cap_http::HttpExecutor;

use advance_shared_types::traits::EventBusEmit;

use crate::cancel::CancelToken;
use crate::contract::{AdoptError, AttachSession, ConnectError, PreflightFail, RuntimeState};
use crate::runtime_state::SelectedProvider;
use crate::secret_bytes::SecretBytes;

pub trait PreflightPort: Send + Sync {
    fn preflight(
        &self,
        home: &Path,
        provider: &LlmProviderConfig,
        key: &SecretBytes,
        cancel: &CancelToken,
    ) -> Result<(), PreflightFail>;
}

pub trait RuntimeLauncher: Send + Sync {
    fn start(&self, home: &Path, cancel: &CancelToken) -> Result<(), ConnectError>;
}

/// CONTRACT-243 attach source (MODULE-001-AC-34, ADR 2026-10-03 D3). `start_or_attach`, its adopt
/// and attach steps, [`SourceAdoptPort`](crate::connect::SourceAdoptPort) and
/// [`HostWorkspaceHome`](crate::HostWorkspaceHome) read a home's runtime through it: its state, the
/// live instance, the provider it adopted and its Client API. They also take the one-starter launch
/// claim through it. The default, [`FileAttachSource`](crate::connect::FileAttachSource), is the
/// pid-lock + discovery logic. An in-process implementation answers from memory.
pub trait RuntimeAttachSource: Send + Sync {
    /// `Idle` / `Starting` / `Running` (MODULE-001 §1.4.5).
    fn runtime_state(&self, home: &Path) -> RuntimeState;
    /// Pid of the live instance that owns `home`, if any. A selected provider counts as adopted
    /// only when its `pid` equals this.
    fn live_pid(&self, home: &Path) -> Option<u32>;
    /// The provider the instance reports it adopted (`.runtime/selected-provider`).
    fn selected_provider(&self, home: &Path) -> Option<SelectedProvider>;
    /// The attach target of a running instance; `None` when it cannot be attached now.
    fn attach(&self, home: &Path) -> Option<AttachTarget>;
    /// Take the per-home launch claim; `false` while another starter holds a fresh one.
    fn claim_launch(&self, home: &Path) -> bool;
    /// Release the launch claim. Idempotent.
    fn release_launch(&self, home: &Path);
}

/// What [`RuntimeAttachSource::attach`] hands `start_or_attach`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachTarget {
    /// Loopback Client API base (CONTRACT-190/193).
    pub client_api_base: String,
    /// A session minted in-process for this caller (in-process sources); `None` from
    /// [`FileAttachSource`](crate::connect::FileAttachSource).
    pub session: Option<AttachSession>,
}

pub trait AdoptPort: Send + Sync {
    fn wait_adopted(
        &self,
        home: &Path,
        expected_provider: &str,
        cancel: &CancelToken,
    ) -> Result<(), AdoptError>;
}

/// Production preflight: real generate-path with an injectable HTTP executor.
pub struct GeneratePathPreflight {
    pub executor: Arc<dyn HttpExecutor>,
    pub ssrf: Arc<dyn advance_shared_types::security_validator::SsrfGuard>,
    /// Production: `DiscardEventBus`. T35 injects a recording bus.
    pub event_bus: Arc<dyn EventBusEmit>,
}

impl Default for GeneratePathPreflight {
    fn default() -> Self {
        Self {
            executor: Arc::new(cap_http::ReqwestHttpExecutor::new()),
            ssrf: Arc::new(cap_http::DefaultSsrfGuard::new()),
            event_bus: Arc::new(cap_llm::DiscardEventBus),
        }
    }
}

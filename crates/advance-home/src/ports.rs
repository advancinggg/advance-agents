//! Injectable seams for preflight, launch, and adopt.

use std::path::Path;
use std::sync::Arc;

use advance_runtime::config::LlmProviderConfig;
use cap_http::HttpExecutor;

use advance_shared_types::traits::EventBusEmit;

use crate::cancel::CancelToken;
use crate::contract::{AdoptError, ConnectError, PreflightFail};
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

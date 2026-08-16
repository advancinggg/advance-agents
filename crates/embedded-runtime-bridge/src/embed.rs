//! Embed composition: RuntimeLock + RuntimeHostBuilder + register_cap_grant.

use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use advance_runtime::runtime_lock::RuntimeLock;
use advance_runtime::RuntimeHostBuilder;
use advance_shared_types::traits::EventBusEmit;
use cap_grant::register_cap_grant;

use crate::config::{resolve_config_path, BridgeConfig};
use crate::error::BridgeError;
use crate::handle::{default_lifecycle, BridgeHandle, BridgeInner, ModeState};
use crate::noop_bus::NoopEventBus;
use crate::profile::uses_runtime_lock;
use crate::registry;
use crate::workspace::prepare_workspace;

const DEFAULT_AGENT: &str = "default-agent";
const LOCK_HEARTBEAT: Duration = Duration::from_secs(30);

/// Embed start (must run on GLOBAL_RT).
pub async fn start_embed(
    workspace_root: &Path,
    config: BridgeConfig,
) -> Result<BridgeHandle, BridgeError> {
    config.validate()?;
    let workspace = prepare_workspace(workspace_root)?;
    registry::reserve(workspace.clone())?;

    let result = start_embed_inner(workspace.clone(), config).await;
    if result.is_err() {
        registry::release(&workspace);
    }
    result
}

async fn start_embed_inner(
    workspace: std::path::PathBuf,
    config: BridgeConfig,
) -> Result<BridgeHandle, BridgeError> {
    let config_path = resolve_config_path(&workspace, &config);
    if !config_path.is_file() {
        return Err(BridgeError::Config(format!(
            "missing runtime-config.yaml at {}",
            config_path.display()
        )));
    }

    let lock = if uses_runtime_lock() {
        Some(
            RuntimeLock::acquire(&workspace, LOCK_HEARTBEAT)
                .await
                .map_err(|e| match e {
                    advance_runtime::runtime_lock::LockError::ActiveRuntime(_) => {
                        BridgeError::AlreadyRunning
                    }
                    other => BridgeError::Bootstrap(other.to_string()),
                })?,
        )
    } else {
        None
    };

    let builder = RuntimeHostBuilder::new(&config_path, &workspace)
        .await
        .map_err(|e| BridgeError::Bootstrap(e.to_string()))?;

    let bus: Arc<dyn EventBusEmit> = Arc::new(NoopEventBus);
    let agent_yaml = workspace.join(".agent").join("config.yaml");
    let static_path = if agent_yaml.is_file() {
        Some(agent_yaml.as_path())
    } else {
        None
    };
    let grant_handles = register_cap_grant(
        builder.sqlite_index_handle(),
        bus,
        static_path,
        DEFAULT_AGENT.to_string(),
        None,
    )
    .map_err(|e| BridgeError::Bootstrap(e.to_string()))?;

    let host = builder
        .build(grant_handles.grant_check)
        .map_err(|e| BridgeError::Bootstrap(e.to_string()))?;

    let inner = Arc::new(BridgeInner {
        workspace,
        config,
        lifecycle: Mutex::new(default_lifecycle()),
        mode: Mutex::new(ModeState::Embed {
            host: Some(host),
            lock,
        }),
        stopped: AtomicBool::new(false),
        reserved: AtomicBool::new(true),
    });
    Ok(BridgeHandle::new(inner))
}

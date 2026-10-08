//! Embed composition: RuntimeLock + RuntimeHostBuilder + register_cap_grant.

use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use advance_runtime::runtime_lock::RuntimeLock;
use advance_runtime::{RuntimeHostBuilder, WasmBackend};
use advance_runtime_compose::ProcessPolicy;
use advance_shared_types::traits::EventBusEmit;
use cap_grant::register_cap_grant;

use crate::config::{resolve_config_path, BridgeConfig};
use crate::error::BridgeError;
use crate::handle::{default_lifecycle, BridgeHandle, BridgeInner, ModeState, V2Settings};
use crate::noop_bus::NoopEventBus;
use crate::profile::uses_runtime_lock;
use crate::registry;
use crate::workspace::prepare_workspace;

const LOCK_HEARTBEAT: Duration = Duration::from_secs(30);

pub(crate) struct EmbedKnobs {
    pub backend: WasmBackend,
    pub lock_probe: ProcessPolicy,
}

impl EmbedKnobs {
    pub(crate) const V1: Self = Self {
        backend: WasmBackend::Native,
        lock_probe: ProcessPolicy::Allow,
    };
}

/// Embed start (must run on GLOBAL_RT).
pub async fn start_embed(
    workspace_root: &Path,
    config: BridgeConfig,
) -> Result<BridgeHandle, BridgeError> {
    start_embed_with(workspace_root, config, EmbedKnobs::V1, None).await
}

/// Embed start with v2 knobs (`host_only`). v1 is [`EmbedKnobs::V1`] and `v2: None`.
pub async fn start_embed_with(
    workspace_root: &Path,
    config: BridgeConfig,
    knobs: EmbedKnobs,
    v2: Option<V2Settings>,
) -> Result<BridgeHandle, BridgeError> {
    config.validate()?;
    let workspace = prepare_workspace(workspace_root)?;
    let reservation = registry::Reservation::acquire(workspace.clone())?;

    let result = start_embed_inner(workspace, config, knobs, v2).await;
    if result.is_ok() {
        reservation.persist();
    }
    result
}

async fn start_embed_inner(
    workspace: std::path::PathBuf,
    config: BridgeConfig,
    knobs: EmbedKnobs,
    v2: Option<V2Settings>,
) -> Result<BridgeHandle, BridgeError> {
    let config_path = resolve_config_path(&workspace, &config)?;
    if !config_path.is_file() {
        return Err(BridgeError::Config(format!(
            "missing runtime-config.yaml at {}",
            config_path.display()
        )));
    }

    let lock = if uses_runtime_lock() {
        let acquired = if knobs.lock_probe == ProcessPolicy::Forbid {
            RuntimeLock::acquire_with_policy(&workspace, LOCK_HEARTBEAT, ProcessPolicy::Forbid)
                .await
        } else {
            RuntimeLock::acquire(&workspace, LOCK_HEARTBEAT).await
        };
        Some(acquired.map_err(|e| match e {
            advance_runtime::runtime_lock::LockError::ActiveRuntime(_) => {
                BridgeError::AlreadyRunning
            }
            other => BridgeError::Bootstrap(other.to_string()),
        })?)
    } else {
        None
    };

    let mut builder = RuntimeHostBuilder::new(&config_path, &workspace)
        .await
        .map_err(|e| BridgeError::Bootstrap(e.to_string()))?;
    if knobs.backend == WasmBackend::Pulley {
        builder = builder.with_wasm_backend(WasmBackend::Pulley);
    }

    let bus: Arc<dyn EventBusEmit> = Arc::new(NoopEventBus);
    let agent_yaml = workspace.join(".agent").join("config.yaml");
    let static_path = if agent_yaml.is_file() {
        Some(agent_yaml.as_path())
    } else {
        None
    };
    // The root agent's immutable id (persisted in `.agent/config.yaml`; minted on first use).
    let root_agent_id = if static_path.is_some() {
        cap_lifecycle::identity::ensure_agent_id(&workspace)
            .map_err(|e| BridgeError::Bootstrap(format!("root agent id: {e}")))?
    } else {
        cap_lifecycle::identity::new_agent_id()
    };
    let grant_handles = register_cap_grant(
        builder.sqlite_index_handle(),
        bus,
        static_path,
        root_agent_id,
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
        v2,
    });
    Ok(BridgeHandle::new(inner))
}

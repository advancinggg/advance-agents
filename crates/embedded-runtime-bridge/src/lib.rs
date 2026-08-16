//! CONTRACT-210 `EmbeddedRuntimeBridge` — born-OSS embed/supervise surface.
//!
//! Native shells and third parties compose the **same** M001 runtime core
//! (`RuntimeHostBuilder` + `RuntimeLock` + real `GrantCheck`) without a
//! product-private Wasmtime host.

// FFI module requires `unsafe` for the documented C ABI; all other modules stay safe.
#![deny(unsafe_op_in_unsafe_fn)]

pub mod config;
pub mod embed;
pub mod error;
#[allow(unsafe_code)]
pub mod ffi;

// Re-export safe C ABI version for tests without needing unsafe in callers.
pub use ffi::advance_bridge_abi_version;
pub mod handle;
pub mod lock_status;
pub mod noop_bus;
pub mod profile;
pub mod registry;
pub mod runtime_rt;
pub mod supervise;
pub mod types;
pub mod workspace;

pub use config::BridgeConfig;
pub use error::BridgeError;
pub use handle::BridgeHandle;
pub use types::{
    BridgeHealth, BridgeLifecycleInput, BridgePlatform, CompositionMode, EmbeddedRuntimeBridge,
    EngineMode, HostBackend, LockExclusivity, PlatformLifecycleState, RuntimeHostProfileView,
    StorageProfile, SuperviseReadiness, ADVANCE_BRIDGE_ABI_VERSION, HEALTH_SCHEMA_VERSION,
};

use std::path::Path;

use crate::types::CompositionMode as CM;

/// Default implementation of [`EmbeddedRuntimeBridge`].
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultEmbeddedRuntimeBridge;

impl EmbeddedRuntimeBridge for DefaultEmbeddedRuntimeBridge {
    fn start(
        &self,
        workspace_root: &Path,
        config: BridgeConfig,
    ) -> Result<BridgeHandle, BridgeError> {
        start(workspace_root, config)
    }

    fn stop(&self, handle: BridgeHandle) -> Result<(), BridgeError> {
        stop(handle)
    }

    fn health(&self, handle: &BridgeHandle) -> Result<BridgeHealth, BridgeError> {
        health(handle)
    }

    fn on_lifecycle(
        &self,
        handle: &BridgeHandle,
        input: BridgeLifecycleInput,
    ) -> Result<(), BridgeError> {
        on_lifecycle(handle, input)
    }
}

/// Sync start. Returns NestedRuntime if already inside Tokio (use [`start_async`]).
pub fn start(workspace_root: impl AsRef<Path>, config: BridgeConfig) -> Result<BridgeHandle, BridgeError> {
    if runtime_rt::in_tokio() {
        return Err(BridgeError::NestedRuntime);
    }
    let root = workspace_root.as_ref().to_path_buf();
    runtime_rt::block_on_global(async move { start_async(&root, config).await })
}

/// Async start — always drives embed/supervise work on GLOBAL_RT.
pub async fn start_async(
    workspace_root: &Path,
    config: BridgeConfig,
) -> Result<BridgeHandle, BridgeError> {
    let root = workspace_root.to_path_buf();
    let cfg = config;
    // Hop to GLOBAL_RT so host background tasks / child stay affine there.
    runtime_rt::global_rt()
        .spawn(async move {
            match cfg.composition_mode {
                CM::Embed => embed::start_embed(&root, cfg).await,
                CM::Supervise => supervise::start_supervise(&root, cfg).await,
            }
        })
        .await
        .map_err(|e| BridgeError::Internal(format!("join: {e}")))?
}

/// Stop handle (idempotent reap).
pub fn stop(handle: BridgeHandle) -> Result<(), BridgeError> {
    handle.stop()
}

/// Health snapshot.
pub fn health(handle: &BridgeHandle) -> Result<BridgeHealth, BridgeError> {
    handle.health()
}

/// Lifecycle update.
pub fn on_lifecycle(
    handle: &BridgeHandle,
    input: BridgeLifecycleInput,
) -> Result<(), BridgeError> {
    handle.on_lifecycle(input)
}

/// Async health (same as sync; provided for API symmetry).
pub async fn health_async(handle: &BridgeHandle) -> Result<BridgeHealth, BridgeError> {
    handle.health()
}

/// Async stop.
pub async fn stop_async(handle: BridgeHandle) -> Result<(), BridgeError> {
    // stop uses block_on_global internally; call directly.
    handle.stop()
}

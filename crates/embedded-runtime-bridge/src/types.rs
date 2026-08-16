//! CONTRACT-210 public types (OSS-local; no device-mesh dependency).

use serde::{Deserialize, Serialize};

/// C ABI version.
pub const ADVANCE_BRIDGE_ABI_VERSION: u32 = 1;

/// Health JSON schema version.
pub const HEALTH_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgePlatform {
    Mac,
    Ios,
    Android,
    Windows,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineMode {
    Jit,
    Interpreter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompositionMode {
    Embed,
    Supervise,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostBackend {
    Cranelift,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformLifecycleState {
    Foreground,
    Background,
    Suspended,
    Restricted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageProfile {
    Ephemeral,
    Bounded,
    Persistent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockExclusivity {
    RuntimeLock,
    ProcessLocal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuperviseReadiness {
    DaemonReadyLine,
    ReadyFile,
}

/// Lifecycle input (MODULE-022 battery/network).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeLifecycleInput {
    pub state: PlatformLifecycleState,
    pub battery_pct: Option<u8>,
    pub network_class: Option<String>,
}

/// RuntimeHostProfile-shaped honesty fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeHostProfileView {
    pub agent_host_available: bool,
    pub supported_wit_versions: Vec<String>,
    pub max_concurrent_runs: u32,
    pub platform_lifecycle_state: PlatformLifecycleState,
    pub storage_profile: StorageProfile,
    pub requires_human_presence: bool,
    pub engine_mode: EngineMode,
    pub host_backend: HostBackend,
    pub battery_pct: Option<u8>,
    pub network_class: Option<String>,
}

/// Health snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeHealth {
    pub schema_version: u32,
    pub runtime_up: bool,
    pub profile: RuntimeHostProfileView,
    pub last_heartbeat_ok: bool,
    pub composition_mode: CompositionMode,
    pub lock_exclusivity: LockExclusivity,
    pub supervise_readiness: Option<SuperviseReadiness>,
}

/// CONTRACT-210 trait (searchable type name for pin probes).
pub trait EmbeddedRuntimeBridge: Send + Sync {
    fn start(
        &self,
        workspace_root: &std::path::Path,
        config: crate::config::BridgeConfig,
    ) -> Result<crate::handle::BridgeHandle, crate::error::BridgeError>;

    fn stop(&self, handle: crate::handle::BridgeHandle) -> Result<(), crate::error::BridgeError>;

    fn health(
        &self,
        handle: &crate::handle::BridgeHandle,
    ) -> Result<BridgeHealth, crate::error::BridgeError>;

    fn on_lifecycle(
        &self,
        handle: &crate::handle::BridgeHandle,
        input: BridgeLifecycleInput,
    ) -> Result<(), crate::error::BridgeError>;
}

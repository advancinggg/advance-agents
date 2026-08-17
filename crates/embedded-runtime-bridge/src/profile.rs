//! Platform honesty map (sim-aligned FG capacity).

use crate::types::{
    BridgePlatform, EngineMode, HostBackend, PlatformLifecycleState, RuntimeHostProfileView,
    StorageProfile,
};

const WIT: &str = "0.1.0";

/// Foreground max concurrent runs by platform class.
pub fn fg_max_concurrent(platform: BridgePlatform) -> u32 {
    match platform {
        BridgePlatform::Mac | BridgePlatform::Windows => 8,
        BridgePlatform::Android => 4,
        BridgePlatform::Ios => 2,
    }
}

pub fn storage_profile(platform: BridgePlatform) -> StorageProfile {
    match platform {
        BridgePlatform::Mac | BridgePlatform::Windows => StorageProfile::Persistent,
        BridgePlatform::Ios | BridgePlatform::Android => StorageProfile::Bounded,
    }
}

pub fn requires_human_presence(platform: BridgePlatform) -> bool {
    matches!(platform, BridgePlatform::Ios)
}

/// Build honesty profile.
///
/// Mobile + Cranelift: `agent_host_available=false` even at foreground
/// (cannot honestly advertise a functional no-JIT host).
pub fn build_profile(
    platform: BridgePlatform,
    engine_mode: EngineMode,
    lifecycle: PlatformLifecycleState,
    runtime_up: bool,
    battery_pct: Option<u8>,
    network_class: Option<String>,
) -> RuntimeHostProfileView {
    // Compiled mobile target cannot be bypassed by passing BridgePlatform::Mac.
    let platform = {
        #[cfg(target_os = "ios")]
        {
            let _ = platform;
            BridgePlatform::Ios
        }
        #[cfg(target_os = "android")]
        {
            let _ = platform;
            BridgePlatform::Android
        }
        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        {
            platform
        }
    };

    let host_backend = HostBackend::Cranelift;
    let non_fg = !matches!(lifecycle, PlatformLifecycleState::Foreground);
    let mobile = matches!(platform, BridgePlatform::Ios | BridgePlatform::Android);
    let mut max = if non_fg { 0 } else { fg_max_concurrent(platform) };
    let mut available = runtime_up && !non_fg && max >= 1;
    if mobile && matches!(host_backend, HostBackend::Cranelift) {
        available = false;
        // Keep capacity class for honesty map but clear availability.
        if non_fg {
            max = 0;
        }
    }
    RuntimeHostProfileView {
        agent_host_available: available,
        supported_wit_versions: if runtime_up {
            vec![WIT.to_string()]
        } else {
            vec![]
        },
        max_concurrent_runs: max,
        platform_lifecycle_state: lifecycle,
        storage_profile: storage_profile(platform),
        requires_human_presence: requires_human_presence(platform),
        engine_mode,
        host_backend,
        battery_pct,
        network_class,
    }
}

/// Whether this target uses RuntimeLock for embed.
pub fn uses_runtime_lock() -> bool {
    cfg!(any(target_os = "linux", target_os = "macos"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t04_ios_profile_honesty() {
        let p = build_profile(
            BridgePlatform::Ios,
            EngineMode::Interpreter,
            PlatformLifecycleState::Foreground,
            true,
            None,
            None,
        );
        assert_eq!(p.max_concurrent_runs, 2);
        assert_eq!(p.engine_mode, EngineMode::Interpreter);
        assert_eq!(p.host_backend, HostBackend::Cranelift);
        assert_eq!(p.storage_profile, StorageProfile::Bounded);
        assert!(p.requires_human_presence);
        assert!(!p.agent_host_available); // Cranelift honesty
    }

    #[test]
    fn t05_non_foreground_clears_capacity() {
        let p = build_profile(
            BridgePlatform::Mac,
            EngineMode::Jit,
            PlatformLifecycleState::Background,
            true,
            None,
            None,
        );
        assert_eq!(p.max_concurrent_runs, 0);
        assert!(!p.agent_host_available);
    }

    #[test]
    fn t29_mobile_cranelift_unavailable() {
        let p = build_profile(
            BridgePlatform::Ios,
            EngineMode::Interpreter,
            PlatformLifecycleState::Foreground,
            true,
            None,
            None,
        );
        assert!(!p.agent_host_available);
    }
}

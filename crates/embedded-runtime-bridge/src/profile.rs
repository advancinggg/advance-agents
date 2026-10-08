//! Platform honesty map (sim-aligned FG capacity).

use advance_runtime_compose::HostPlatform;

use crate::types::{
    BridgePlatform, CompositionProfile, EngineMode, HostBackend, PlatformLifecycleState,
    RuntimeHostProfileView, StorageProfile,
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
    let mut max = if non_fg {
        0
    } else {
        fg_max_concurrent(platform)
    };
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

/// Desktop Linux shares macOS's honesty class (capacity 8, persistent, no presence).
pub(crate) fn honesty_class(platform: HostPlatform) -> BridgePlatform {
    match platform {
        HostPlatform::MacOs | HostPlatform::Linux => BridgePlatform::Mac,
        HostPlatform::Windows => BridgePlatform::Windows,
        HostPlatform::Ios => BridgePlatform::Ios,
        HostPlatform::Android => BridgePlatform::Android,
        _ => BridgePlatform::Mac,
    }
}

pub(crate) struct ProfileV2 {
    pub platform: HostPlatform,
    pub backend: HostBackend,
    pub lifecycle: PlatformLifecycleState,
    pub runtime_up: bool,
    pub agent_loop_up: bool,
    pub composition: CompositionProfile,
    pub battery_pct: Option<u8>,
    pub network_class: Option<String>,
}

/// Honesty profile for a v2 handle. `build_profile` stays the v1 path.
pub(crate) fn build_profile_v2(input: ProfileV2) -> RuntimeHostProfileView {
    let platform = {
        #[cfg(target_os = "ios")]
        {
            let _ = input.platform;
            BridgePlatform::Ios
        }
        #[cfg(target_os = "android")]
        {
            let _ = input.platform;
            BridgePlatform::Android
        }
        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        {
            honesty_class(input.platform)
        }
    };

    let non_fg = !matches!(input.lifecycle, PlatformLifecycleState::Foreground);
    let mobile = matches!(platform, BridgePlatform::Ios | BridgePlatform::Android);
    let max = if non_fg {
        0
    } else {
        fg_max_concurrent(platform)
    };
    let mut available = input.runtime_up && !non_fg && max >= 1;
    match input.composition {
        CompositionProfile::Full => {
            available = available
                && input.agent_loop_up
                && (!mobile || input.backend == HostBackend::Pulley);
        }
        CompositionProfile::HostOnly => {
            if mobile {
                available = false;
            }
        }
    }
    let engine_mode = if input.backend == HostBackend::Pulley {
        EngineMode::Interpreter
    } else {
        EngineMode::Jit
    };
    RuntimeHostProfileView {
        agent_host_available: available,
        supported_wit_versions: if input.runtime_up {
            vec![WIT.to_string()]
        } else {
            vec![]
        },
        max_concurrent_runs: max,
        platform_lifecycle_state: input.lifecycle,
        storage_profile: storage_profile(platform),
        requires_human_presence: requires_human_presence(platform),
        engine_mode,
        host_backend: input.backend,
        battery_pct: input.battery_pct,
        network_class: input.network_class,
    }
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

    #[test]
    fn module_001_ac32_profile_v2_engine_mode_follows_the_backend() {
        for backend in [HostBackend::Cranelift, HostBackend::Pulley] {
            let p = build_profile_v2(ProfileV2 {
                platform: HostPlatform::MacOs,
                backend,
                lifecycle: PlatformLifecycleState::Foreground,
                runtime_up: true,
                agent_loop_up: true,
                composition: CompositionProfile::Full,
                battery_pct: None,
                network_class: None,
            });
            assert_eq!(p.host_backend, backend);
            assert_eq!(
                p.engine_mode,
                if backend == HostBackend::Pulley {
                    EngineMode::Interpreter
                } else {
                    EngineMode::Jit
                }
            );
        }
    }

    #[test]
    fn module_001_ac32_profile_v2_availability_table() {
        let platforms = [
            HostPlatform::MacOs,
            HostPlatform::Ios,
            HostPlatform::Android,
            HostPlatform::Windows,
            HostPlatform::Linux,
        ];
        let backends = [HostBackend::Cranelift, HostBackend::Pulley];
        let lifecycles = [
            PlatformLifecycleState::Foreground,
            PlatformLifecycleState::Background,
            PlatformLifecycleState::Suspended,
            PlatformLifecycleState::Restricted,
        ];
        for platform in platforms {
            for backend in backends {
                for lifecycle in lifecycles {
                    for runtime_up in [true, false] {
                        for agent_loop_up in [true, false] {
                            for composition in
                                [CompositionProfile::Full, CompositionProfile::HostOnly]
                            {
                                let p = build_profile_v2(ProfileV2 {
                                    platform,
                                    backend,
                                    lifecycle,
                                    runtime_up,
                                    agent_loop_up,
                                    composition,
                                    battery_pct: None,
                                    network_class: None,
                                });
                                let class = honesty_class(platform);
                                let mobile =
                                    matches!(class, BridgePlatform::Ios | BridgePlatform::Android);
                                let non_fg = lifecycle != PlatformLifecycleState::Foreground;
                                let expected_max =
                                    if non_fg { 0 } else { fg_max_concurrent(class) };
                                assert_eq!(p.max_concurrent_runs, expected_max);
                                let mut expected = runtime_up && !non_fg && expected_max >= 1;
                                match composition {
                                    CompositionProfile::Full => {
                                        expected = expected
                                            && agent_loop_up
                                            && (!mobile || backend == HostBackend::Pulley);
                                    }
                                    CompositionProfile::HostOnly => {
                                        if mobile {
                                            expected = false;
                                        }
                                    }
                                }
                                assert_eq!(
                                    p.agent_host_available, expected,
                                    "{platform:?} {backend:?} {lifecycle:?} up={runtime_up} loop={agent_loop_up} {composition:?}"
                                );
                                assert_eq!(p.supported_wit_versions.is_empty(), !runtime_up);
                            }
                        }
                    }
                }
            }
        }
    }
}

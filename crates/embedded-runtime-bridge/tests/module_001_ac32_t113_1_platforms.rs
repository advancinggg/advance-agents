//! MODULE-001-T113 (1) — each platform label through `advance_bridge_start_v2`.

mod common;

use advance_embedded_runtime_bridge::ffi::handle_from_raw;
use advance_runtime_compose::test_support::fixture::FixtureDriver;
use advance_runtime_compose::{
    ComposeProfile, HostPlatform, InstanceGuardKind, ProcessPolicy, WasmEngine,
};
use common::{c_health, c_start_v2, c_stop_free, fixture_home, json_with_state_root};
use serde_json::json;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[test]
fn module_001_ac32_t113_1_each_platform_gets_its_table_row() {
    let _g = SERIAL.blocking_lock();
    let fixture = fixture_home(&["fs"], FixtureDriver::None);
    let ws = fixture.home();
    let sr = fixture.state_root();
    let lock_path = ws.join(".runtime/runtime.lock");

    for platform in [
        HostPlatform::MacOs,
        HostPlatform::Ios,
        HostPlatform::Android,
        HostPlatform::Windows,
        HostPlatform::Linux,
    ] {
        let json = json_with_state_root(json!({ "platform": platform.as_str() }), sr);
        let started = c_start_v2(ws, Some(&json));
        assert_eq!(
            started.code,
            0,
            "{}: {}",
            platform.as_str(),
            started.last_error
        );

        let rust = unsafe { handle_from_raw(started.handle) }.expect("handle");
        let rt = rust.composed_runtime().expect("composed");
        let health = rt.health();
        assert_eq!(health.profile, ComposeProfile::Embedded { platform });
        if platform.is_mobile() {
            assert_eq!(health.instance_guard, InstanceGuardKind::ProcessLocal);
            assert_eq!(health.processes, ProcessPolicy::Forbid);
            assert_eq!(health.wasm_engine, WasmEngine::Pulley);
            assert!(
                !lock_path.exists(),
                "{}: runtime.lock must be absent",
                platform.as_str()
            );
        } else {
            assert_eq!(health.instance_guard, InstanceGuardKind::PidLockFile);
            assert_eq!(health.processes, ProcessPolicy::Allow);
            assert_eq!(health.wasm_engine, WasmEngine::Native);
            assert!(
                lock_path.exists(),
                "{}: runtime.lock while running",
                platform.as_str()
            );
        }

        let h = c_health(started.handle);
        assert_eq!(h.code, 0, "{}", h.last_error);
        let v: serde_json::Value =
            serde_json::from_str(h.value.as_deref().expect("health json")).unwrap();
        if platform.is_mobile() {
            assert_eq!(v["lock_exclusivity"], "process_local");
            assert_eq!(v["profile"]["host_backend"], "pulley");
            assert_eq!(v["profile"]["engine_mode"], "interpreter");
        } else {
            assert_eq!(v["lock_exclusivity"], "runtime_lock");
            assert_eq!(v["profile"]["host_backend"], "cranelift");
            assert_eq!(v["profile"]["engine_mode"], "jit");
        }

        c_stop_free(started.handle);
    }
}

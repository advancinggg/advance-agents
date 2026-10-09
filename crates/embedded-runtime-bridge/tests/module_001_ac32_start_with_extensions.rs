//! MODULE-001-AC-32: `start_with_extensions` (+ async), options key/log, session,
//! config_path, host_only health.

mod common;

use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_client_api::API_VERSION;
use advance_embedded_runtime_bridge::ffi::{
    advance_bridge_start_v2, handle_from_raw, AdvanceBridgeHandle,
};
use advance_embedded_runtime_bridge::{
    client_api_session, health, health_v2, on_lifecycle_async, start_with_extensions,
    start_with_extensions_async, stop, stop_async, BridgeError, BridgeLifecycleInput,
    BridgeOptions, CompositionProfile, HostBackend, MasterKeyInput, PlatformLifecycleState,
    Zeroizing,
};
use advance_runtime_compose::log_keys;
use advance_runtime_compose::test_support::fixture::{
    FixtureDriver, FixtureExtension, FixtureFamilies, FIXTURE_ID, FIXTURE_MASTER_KEY,
};
use advance_runtime_compose::test_support::{reserved_homes, MemoryComposeLog};
use common::{c_start_v2, c_stop_free, fixture_home, http, json_with_state_root, last_error};
use serde_json::json;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn default_options(state_root: &std::path::Path) -> BridgeOptions {
    BridgeOptions::default().with_state_root(state_root)
}

#[test]
fn module_001_ac32_start_with_extensions_refuses_a_nested_runtime() {
    let _g = SERIAL.blocking_lock();
    let fixture = fixture_home(&["fs"], FixtureDriver::None);
    let options = default_options(fixture.state_root());
    let nested = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread");
    nested.block_on(async {
        let err = start_with_extensions(fixture.home(), options.clone(), vec![])
            .expect_err("nested runtime");
        assert!(matches!(err, BridgeError::NestedRuntime));
        assert_eq!(err.c_code(), 11);

        let ws = std::ffi::CString::new(fixture.home().to_str().unwrap()).unwrap();
        let json = json_with_state_root(json!({}), fixture.state_root());
        let opt = std::ffi::CString::new(json).unwrap();
        let mut out: *mut AdvanceBridgeHandle = std::ptr::null_mut();
        let code = unsafe { advance_bridge_start_v2(ws.as_ptr(), opt.as_ptr(), &mut out) };
        assert_eq!(code, 11, "{}", last_error());
        assert!(out.is_null());
    });
}

#[test]
fn module_001_ac32_start_with_extensions_async_composes_on_the_global_runtime() {
    let _g = SERIAL.blocking_lock();
    let fixture = fixture_home(&["fs"], FixtureDriver::None);
    let options = default_options(fixture.state_root());
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread");
    rt.block_on(async {
        let handle = start_with_extensions_async(fixture.home(), options, vec![])
            .await
            .expect("async compose");
        on_lifecycle_async(
            &handle,
            BridgeLifecycleInput {
                state: PlatformLifecycleState::Foreground,
                battery_pct: None,
                network_class: None,
            },
        )
        .await
        .expect("foreground");
        stop_async(handle).await.expect("stop");
    });
}

#[test]
fn module_001_ac32_bridge_options_key_and_log_reach_the_composition() {
    let _g = SERIAL.blocking_lock();
    let fixture = fixture_home(&["fs", "llm"], FixtureDriver::None);
    let mem = MemoryComposeLog::new();
    let options = BridgeOptions::default()
        .with_log(Arc::new(mem.clone()))
        .with_state_root(fixture.state_root())
        .with_master_key(MasterKeyInput::Provided(Zeroizing::new(FIXTURE_MASTER_KEY)));
    let handle =
        start_with_extensions(fixture.home(), options, vec![]).expect("provided key composes");
    assert!(
        mem.count(log_keys::CLIENT_API_LISTENING_IN_PROCESS) >= 1,
        "in-process listen line: {:?}",
        mem.lines()
    );
    stop(handle).expect("stop");
}

#[test]
fn module_001_ac32_start_with_extensions_session_reaches_the_extension_family() {
    let _g = SERIAL.blocking_lock();
    let fixture = fixture_home(&["fs"], FixtureDriver::None);
    let ext = FixtureExtension::new(FIXTURE_ID).with_families(FixtureFamilies::standard());
    let handle = start_with_extensions(
        fixture.home(),
        default_options(fixture.state_root()),
        vec![ext.arc()],
    )
    .expect("compose with fixture family");
    let token = client_api_session(&handle).expect("session");
    let ep = handle
        .composed_runtime()
        .expect("full handle")
        .client_api()
        .expect("client api");
    let auth = format!("Bearer {}", token.as_str());
    let (ok, _) = http(
        ep.socket_addr,
        "GET",
        "/client/fixture/status",
        &[
            ("Authorization", auth.as_str()),
            ("x-advance-api-version", API_VERSION),
        ],
        &[],
    );
    assert_eq!(ok, 200);
    let (denied, _) = http(
        ep.socket_addr,
        "GET",
        "/client/fixture/status",
        &[("x-advance-api-version", API_VERSION)],
        &[],
    );
    assert_eq!(denied, 401);
    stop(handle).expect("stop");
}

#[test]
fn module_001_ac32_config_path_full_accepts_only_the_default() {
    let _g = SERIAL.blocking_lock();
    let fixture = fixture_home(&["fs"], FixtureDriver::None);
    let sr = fixture.state_root();
    let default_rel = ".advance/runtime-config.yaml";
    let default_abs = fixture.home().join(default_rel);

    for json in [
        json_with_state_root(json!({ "config_path": default_rel }), sr),
        json_with_state_root(json!({ "config_path": default_abs.to_str().unwrap() }), sr),
    ] {
        let started = c_start_v2(fixture.home(), Some(&json));
        assert_eq!(started.code, 0, "{}", started.last_error);
        c_stop_free(started.handle);
    }

    let other = fixture.home().join(".advance/other.yaml");
    fs::write(&other, "wasm:\n  max_memory_pages: 1\n").unwrap();
    let refused = [
        json_with_state_root(json!({ "config_path": ".advance/other.yaml" }), sr),
        json_with_state_root(json!({ "config_path": "../x" }), sr),
        json_with_state_root(
            json!({ "config_path": "/tmp/advance-bridge-outside.yaml" }),
            sr,
        ),
    ];
    for json in refused {
        let started = c_start_v2(fixture.home(), Some(&json));
        assert_eq!(started.code, 14, "{}", started.last_error);
        assert!(started.handle.is_null());
        assert!(started
            .last_error
            .contains(r#"composition "full" reads only"#));
    }

    let host_only = json_with_state_root(
        json!({ "composition": "host_only", "config_path": "../x" }),
        sr,
    );
    let started = c_start_v2(fixture.home(), Some(&host_only));
    assert_eq!(started.code, 3, "{}", started.last_error);
    assert!(started.handle.is_null());
}

#[test]
fn module_001_ac32_host_only_v2_reports_health_v2() {
    let _g = SERIAL.blocking_lock();
    let fixture = fixture_home(&["fs"], FixtureDriver::None);
    let sr = fixture.state_root();

    let json = json_with_state_root(json!({ "composition": "host_only" }), sr);
    let started = c_start_v2(fixture.home(), Some(&json));
    assert_eq!(started.code, 0, "{}", started.last_error);
    let health = common::c_health(started.handle);
    assert_eq!(health.code, 0, "{}", health.last_error);
    let v: serde_json::Value = serde_json::from_str(health.value.as_deref().unwrap()).unwrap();
    assert_eq!(v["schema_version"], 2);
    assert_eq!(v["composition_profile"], "host_only");
    assert_eq!(v["agent_loop_up"], false);
    assert!(v["client_api_base"].is_null());
    c_stop_free(started.handle);

    let empty = tempfile::tempdir().unwrap();
    let missing = json_with_state_root(json!({ "composition": "host_only" }), sr);
    let started = c_start_v2(empty.path(), Some(&missing));
    assert_eq!(started.code, 7, "{}", started.last_error);

    let first = c_start_v2(
        fixture.home(),
        Some(&json_with_state_root(
            json!({ "composition": "host_only" }),
            sr,
        )),
    );
    assert_eq!(first.code, 0, "{}", first.last_error);
    let second = c_start_v2(
        fixture.home(),
        Some(&json_with_state_root(
            json!({ "composition": "host_only" }),
            sr,
        )),
    );
    assert_eq!(second.code, 5, "{}", second.last_error);
    assert!(second.handle.is_null());
    c_stop_free(first.handle);

    let pulley = json_with_state_root(
        json!({ "composition": "host_only", "engine": "pulley" }),
        sr,
    );
    let started = c_start_v2(fixture.home(), Some(&pulley));
    assert_eq!(started.code, 0, "{}", started.last_error);
    let rust = unsafe { handle_from_raw(started.handle) }.expect("handle");
    let v2 = rust.health_v2().expect("health v2");
    assert_eq!(v2.composition_profile, CompositionProfile::HostOnly);
    assert!(!v2.agent_loop_up);
    assert!(v2.client_api_base.is_none());
    assert_eq!(v2.profile.host_backend, HostBackend::Pulley);
    c_stop_free(started.handle);
}

#[test]
fn module_001_ac32_dropped_async_start_still_shuts_its_composition_down() {
    let _g = SERIAL.blocking_lock();
    let fixture = fixture_home(&["fs"], FixtureDriver::None);
    let home = std::fs::canonicalize(fixture.home()).expect("canonical home");
    let mem = MemoryComposeLog::new();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread");
    let dropped = rt.block_on(async {
        tokio::time::timeout(
            Duration::from_millis(1),
            start_with_extensions_async(
                fixture.home(),
                default_options(fixture.state_root()).with_log(Arc::new(mem.clone())),
                vec![],
            ),
        )
        .await
    });
    assert!(
        dropped.is_err(),
        "the start must still be composing when its future is dropped"
    );
    // The detached start still composes, then shuts down the composition nobody waits for,
    // which releases the home.
    let started = Instant::now();
    while mem.count(log_keys::READY) == 0 {
        assert!(
            started.elapsed() < Duration::from_secs(120),
            "the dropped start never composed: {:?}",
            mem.lines()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let composed = Instant::now();
    while reserved_homes().iter().any(|p| p == &home) {
        assert!(
            composed.elapsed() < Duration::from_secs(120),
            "the home is still reserved 120 s after the dropped start composed ({:?} to compose)",
            composed.duration_since(started)
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    let handle = start_with_extensions(
        fixture.home(),
        default_options(fixture.state_root()),
        vec![],
    )
    .expect("a fresh start on the released home");
    stop(handle).expect("stop");
}

#[test]
fn module_001_ac32_v2_handle_v1_health_is_the_v1_projection() {
    let _g = SERIAL.blocking_lock();
    let fixture = fixture_home(&["fs"], FixtureDriver::Minimal);
    let handle = start_with_extensions(
        fixture.home(),
        default_options(fixture.state_root()),
        vec![],
    )
    .expect("compose");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let v2 = health_v2(&handle).expect("health v2");
        if v2.agent_loop_up || Instant::now() > deadline {
            let v1 = health(&handle).expect("health v1");
            assert_eq!(v1.schema_version, 1);
            assert_eq!(v1.runtime_up, v2.runtime_up);
            assert_eq!(v1.profile, v2.profile);
            assert_eq!(v1.last_heartbeat_ok, v2.last_heartbeat_ok);
            assert_eq!(v1.composition_mode, v2.composition_mode);
            assert_eq!(v1.lock_exclusivity, v2.lock_exclusivity);
            assert_eq!(v1.supervise_readiness, v2.supervise_readiness);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    stop(handle).expect("stop");
}

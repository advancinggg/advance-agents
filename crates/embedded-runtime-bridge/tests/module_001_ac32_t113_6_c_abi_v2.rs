//! MODULE-001-T113 (1) pure refusals and (6) native / C ABI v2 legs.

mod common;

use std::ffi::{c_char, CString};
use std::fs;
use std::path::PathBuf;
use std::ptr;
use std::time::{Duration, Instant};

use advance_embedded_runtime_bridge::ffi::{
    advance_bridge_abi_version, advance_bridge_client_api_base, advance_bridge_client_api_session,
    advance_bridge_free_handle, advance_bridge_last_error, advance_bridge_on_lifecycle,
    advance_bridge_start_v2, advance_bridge_stop, handle_from_raw, AdvanceBridgeHandle,
};
use advance_embedded_runtime_bridge::{
    health_v2, start, BridgeConfig, BridgeError, CompositionMode, EngineMode,
    ADVANCE_BRIDGE_ABI_VERSION,
};
use advance_runtime_compose::test_support::fixture::{CapDecl, FixtureDriver};
use advance_runtime_compose::{
    ComposeError, HostPlatform, InstanceGuardKind, PlatformRule, Unsupported, WasmEngine,
};
use common::{
    c_base, c_getter_into, c_health, c_session, c_start_v2, c_stop_free, fixture_home,
    json_with_state_root, last_error,
};
use serde_json::json;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const _: unsafe extern "C" fn(*const c_char, *const c_char, *mut *mut AdvanceBridgeHandle) -> i32 =
    advance_bridge_start_v2;
const _: unsafe extern "C" fn(*const AdvanceBridgeHandle, *mut c_char, usize, *mut usize) -> i32 =
    advance_bridge_client_api_base;
const _: unsafe extern "C" fn(*const AdvanceBridgeHandle, *mut c_char, usize, *mut usize) -> i32 =
    advance_bridge_client_api_session;

#[test]
fn module_001_ac32_t113_6_abi_version_is_2() {
    let v = advance_bridge_abi_version();
    assert_eq!(v, 2);
    assert_eq!(v, ADVANCE_BRIDGE_ABI_VERSION);
    let header = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("include/advance_bridge.h");
    let text = fs::read_to_string(&header).expect("header");
    assert!(text.contains("#define ADVANCE_BRIDGE_ABI_VERSION 2"));
    assert!(text.contains("#define ADVANCE_BRIDGE_ERR_UNSUPPORTED   14"));
    assert!(text.contains("#define ADVANCE_BRIDGE_ERR_COMPOSE       15"));
    assert!(text.contains("advance_bridge_start_v2"));
    assert!(text.contains("advance_bridge_client_api_base"));
    assert!(text.contains("advance_bridge_client_api_session"));
}

#[test]
fn module_001_ac32_t113_1_forbidden_combinations_answer_14() {
    let parent = tempfile::tempdir().unwrap();
    let sr = tempfile::tempdir().unwrap();
    let cases: &[(&str, HostPlatform, PlatformRule)] = &[
        ("ios", HostPlatform::Ios, PlatformRule::Engine),
        ("ios", HostPlatform::Ios, PlatformRule::Processes),
        ("android", HostPlatform::Android, PlatformRule::Engine),
        ("android", HostPlatform::Android, PlatformRule::Processes),
    ];
    for (platform, host, rule) in cases {
        let missing = parent.path().join(format!("absent-{platform}-{rule:?}"));
        assert!(!missing.exists());
        let json = match rule {
            PlatformRule::Engine => json_with_state_root(
                json!({ "platform": platform, "engine": "native" }),
                sr.path(),
            ),
            PlatformRule::Processes => json_with_state_root(
                json!({ "platform": platform, "processes": "allow" }),
                sr.path(),
            ),
            _ => unreachable!(),
        };
        let started = c_start_v2(&missing, Some(&json));
        assert_eq!(
            started.code, 14,
            "{platform} {rule:?}: {}",
            started.last_error
        );
        assert!(started.handle.is_null());
        assert_eq!(
            started.last_error,
            ComposeError::Unsupported(Unsupported::PlatformTable {
                platform: *host,
                rule: *rule,
            })
            .to_string()
        );
        assert!(!missing.exists(), "prepare_workspace must not run");
    }
}

#[test]
fn module_001_ac32_t113_1_malformed_json_and_unknown_keys_answer_3() {
    let _g = SERIAL.blocking_lock();
    let fixture = fixture_home(&["fs"], FixtureDriver::None);
    let ws = fixture.home();
    for json in [
        r#"{"platform":"#,
        "[]",
        r#""x""#,
        r#"{"bogus":1}"#,
        r#"{"client_api":{"port":0,"x":1}}"#,
        r#"{"platform":"beos"}"#,
        r#"{"client_api":{"port":70000}}"#,
        r#"{"platform":"mac","platform":"ios"}"#,
    ] {
        let started = c_start_v2(ws, Some(json));
        assert_eq!(started.code, 3, "{json}: {}", started.last_error);
        assert!(started.handle.is_null());
    }

    let ws_c = CString::new(ws.to_str().unwrap()).unwrap();
    let bad = [0xffu8, 0];
    let mut out: *mut AdvanceBridgeHandle = ptr::null_mut();
    let code =
        unsafe { advance_bridge_start_v2(ws_c.as_ptr(), bad.as_ptr() as *const c_char, &mut out) };
    assert_eq!(code, 2, "{}", last_error());
    assert!(out.is_null());

    let old_home = std::env::var("HOME").ok();
    let old_xdg = std::env::var("XDG_STATE_HOME").ok();
    std::env::set_var("HOME", fixture.state_root());
    std::env::set_var("XDG_STATE_HOME", fixture.state_root());
    let started = c_start_v2(ws, None);
    match old_home {
        Some(v) => std::env::set_var("HOME", v),
        None => std::env::remove_var("HOME"),
    }
    match old_xdg {
        Some(v) => std::env::set_var("XDG_STATE_HOME", v),
        None => std::env::remove_var("XDG_STATE_HOME"),
    }
    assert_eq!(started.code, 0, "NULL options: {}", started.last_error);
    c_stop_free(started.handle);
}

#[test]
fn module_001_ac32_t113_6_v2_health_of_a_native_full_handle() {
    let _g = SERIAL.blocking_lock();
    let fixture = fixture_home(&["fs"], FixtureDriver::Minimal);
    let json = json_with_state_root(json!({}), fixture.state_root());
    let started = c_start_v2(fixture.home(), Some(&json));
    assert_eq!(started.code, 0, "{}", started.last_error);

    let deadline = Instant::now() + Duration::from_secs(30);
    let health_json = loop {
        let h = c_health(started.handle);
        assert_eq!(h.code, 0, "{}", h.last_error);
        let text = h.value.expect("health json");
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        if v["agent_loop_up"] == true || Instant::now() > deadline {
            break (text, v);
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let (text, v) = health_json;
    assert_eq!(v["schema_version"], 2);
    assert_eq!(v["composition_profile"], "full");
    assert_eq!(v["agent_loop_up"], true, "{text}");
    assert_eq!(v["profile"]["host_backend"], "cranelift");
    assert_eq!(v["profile"]["engine_mode"], "jit");
    assert_eq!(v["lock_exclusivity"], "runtime_lock");
    assert!(v["supervise_readiness"].is_null());

    let rust = unsafe { handle_from_raw(started.handle) }.expect("handle");
    let v2 = rust.health_v2().expect("health v2");
    let expected = serde_json::to_string(&v2).expect("serialize health v2");
    assert_eq!(
        text, expected,
        "C ABI JSON is field order of BridgeHealthV2"
    );

    let rt = rust.composed_runtime().expect("composed");
    let rh = rt.health();
    assert_eq!(rh.wasm_engine, WasmEngine::Native);
    assert_eq!(rh.instance_guard, InstanceGuardKind::PidLockFile);
    let base = c_base(started.handle);
    assert_eq!(base.code, 0, "{}", base.last_error);
    let expected = rt.client_api().expect("endpoint").base_url;
    assert_eq!(base.value.as_deref(), Some(expected.as_str()));
    assert_eq!(v["client_api_base"], expected);

    c_stop_free(started.handle);
}

#[test]
fn module_001_ac32_t113_6_client_api_symbols_answer_14_without_client_api() {
    let _g = SERIAL.blocking_lock();
    let fixture = fixture_home(&["fs"], FixtureDriver::None);
    let sr = fixture.state_root();

    let off = json_with_state_root(json!({ "client_api": null }), sr);
    let started = c_start_v2(fixture.home(), Some(&off));
    assert_eq!(started.code, 0, "{}", started.last_error);
    assert_getter_14(started.handle, "no Client API on this handle");
    c_stop_free(started.handle);

    let host_only = json_with_state_root(json!({ "composition": "host_only" }), sr);
    let started = c_start_v2(fixture.home(), Some(&host_only));
    assert_eq!(started.code, 0, "{}", started.last_error);
    assert_getter_14(started.handle, "no Client API on this handle");
    c_stop_free(started.handle);

    let v1 = start(
        fixture.home(),
        BridgeConfig {
            platform: advance_embedded_runtime_bridge::BridgePlatform::Mac,
            engine_mode: EngineMode::Jit,
            composition_mode: CompositionMode::Embed,
            ..BridgeConfig::default()
        },
    )
    .expect("v1 start");
    let err = health_v2(&v1).expect_err("health v2 of v1");
    assert!(matches!(err, BridgeError::Unsupported(_)));
    assert_eq!(
        err.to_string(),
        "health v2 is reported only for handles started through v2"
    );
    let raw = advance_embedded_runtime_bridge::ffi::into_raw_handle(v1);
    assert_getter_14(raw, "no Client API on this handle");
    unsafe {
        let _ = advance_bridge_stop(raw);
        advance_bridge_free_handle(raw);
    }

    let started = c_start_v2(fixture.home(), Some(&json_with_state_root(json!({}), sr)));
    assert_eq!(started.code, 0, "{}", started.last_error);
    unsafe {
        let _ = advance_bridge_stop(started.handle);
    }
    assert_getter_14(
        started.handle,
        "the Client API listener is not bound (a foreground rebind failed or the runtime is stopping)",
    );
    c_stop_free(started.handle);

    let refused = json_with_state_root(
        json!({ "composition": "host_only", "client_api": { "port": 0 } }),
        sr,
    );
    let started = c_start_v2(fixture.home(), Some(&refused));
    assert_eq!(started.code, 14, "{}", started.last_error);
    assert!(started.handle.is_null());
    assert_eq!(
        started.last_error,
        r#"composition "host_only" has no Client API"#
    );
}

#[test]
fn module_001_ac32_t113_6_forced_composition_failure_answers_15_redacted() {
    let _g = SERIAL.blocking_lock();

    let fixture = fixture_home(&["fs", "llm"], FixtureDriver::None);
    let yaml_path = fixture.home().join(".advance/runtime-config.yaml");
    let original = fs::read_to_string(&yaml_path).unwrap();
    let env_name = format!(
        "ADVANCE_T113_UNSET_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let patched = original.replace(
        "env-var-name: ADV_FIXTURE_MASTER_KEY_UNUSED",
        &format!("env-var-name: {env_name}"),
    );
    assert_ne!(patched, original, "fixture yaml names the unused env var");
    fs::write(&yaml_path, patched).unwrap();
    let started = c_start_v2(
        fixture.home(),
        Some(&json_with_state_root(json!({}), fixture.state_root())),
    );
    assert_eq!(started.code, 15, "{}", started.last_error);
    assert!(started.handle.is_null());
    assert_eq!(started.last_error, "redacted error");
    fs::write(&yaml_path, &original).unwrap();
    fixture
        .rewrite_agent_config(&[CapDecl::Granted("fs")])
        .unwrap();
    let recovered = c_start_v2(
        fixture.home(),
        Some(&json_with_state_root(json!({}), fixture.state_root())),
    );
    assert_eq!(recovered.code, 0, "{}", recovered.last_error);
    c_stop_free(recovered.handle);

    let fixture = fixture_home(&["fs"], FixtureDriver::None);
    let yaml_path = fixture.home().join(".advance/runtime-config.yaml");
    let original = fs::read_to_string(&yaml_path).unwrap();
    fs::write(&yaml_path, "this is not yaml: [\n").unwrap();
    let started = c_start_v2(
        fixture.home(),
        Some(&json_with_state_root(json!({}), fixture.state_root())),
    );
    assert_eq!(started.code, 15, "{}", started.last_error);
    assert!(started.handle.is_null());
    assert!(
        started.last_error.starts_with("bootstrap failed:"),
        "{}",
        started.last_error
    );
    fs::write(&yaml_path, original).unwrap();
    let recovered = c_start_v2(
        fixture.home(),
        Some(&json_with_state_root(json!({}), fixture.state_root())),
    );
    assert_eq!(recovered.code, 0, "{}", recovered.last_error);
    c_stop_free(recovered.handle);
}

fn assert_getter_14(handle: *mut AdvanceBridgeHandle, text: &str) {
    let mut buf = vec![0xAAu8; 64];
    let (code, _, err) = c_getter_into(handle, advance_bridge_client_api_base, &mut buf);
    assert_eq!(code, 14, "base: {err}");
    assert_eq!(err, text);
    assert!(buf.iter().all(|&b| b == 0xAA), "base buffer untouched");

    let mut buf = vec![0xAAu8; 64];
    let (code, _, err) = c_getter_into(handle, advance_bridge_client_api_session, &mut buf);
    assert_eq!(code, 14, "session: {err}");
    assert_eq!(err, text);
    assert!(buf.iter().all(|&b| b == 0xAA), "session buffer untouched");
}

// Keep last_error / on_lifecycle / start symbols referenced so the pin stays live in this binary.
#[allow(dead_code)]
fn _touch_v1_symbols() {
    let _ = advance_bridge_last_error;
    let _ = advance_bridge_on_lifecycle;
    let _ = c_session;
    let _ = c_base;
}

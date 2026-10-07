//! MODULE-001-T113 (6) baseline: pin the v1 C ABI health JSON and prototypes
//! to the OSS v0.1.26 bytes. Lands before any v2 / Pulley change to the bridge.

use std::ffi::{c_char, CStr};
use std::fs;
use std::path::PathBuf;

use advance_embedded_runtime_bridge::ffi::{
    advance_bridge_abi_version, advance_bridge_free_handle, advance_bridge_health,
    advance_bridge_last_error, advance_bridge_on_lifecycle, advance_bridge_start,
    advance_bridge_stop, AdvanceBridgeHandle,
};

// Compile-time: the seven v1 symbols keep the v0.1.26 prototypes.
const _: unsafe extern "C" fn(
    *const c_char,
    i32,
    i32,
    i32,
    *const c_char,
    *const c_char,
    i32,
    *const c_char,
    *mut *mut AdvanceBridgeHandle,
) -> i32 = advance_bridge_start;
const _: unsafe extern "C" fn(*mut AdvanceBridgeHandle) -> i32 = advance_bridge_stop;
const _: unsafe extern "C" fn(*const AdvanceBridgeHandle, *mut c_char, usize, *mut usize) -> i32 =
    advance_bridge_health;
const _: unsafe extern "C" fn(*mut AdvanceBridgeHandle, i32, i32, *const c_char) -> i32 =
    advance_bridge_on_lifecycle;
const _: extern "C" fn() -> *const c_char = advance_bridge_last_error;
const _: unsafe extern "C" fn(*mut AdvanceBridgeHandle) = advance_bridge_free_handle;
const _: extern "C" fn() -> u32 = advance_bridge_abi_version;

/// v0.1.26 `advance_bridge.h` lines 27–80 (`typedef` … `advance_bridge_abi_version(void);`).
const V1_PROTOTYPES: &str = "\
typedef struct AdvanceBridgeHandle AdvanceBridgeHandle;

/*
 * On success: *out_handle is non-null.
 * On failure: *out_handle is set to NULL (when out_handle non-null); status != 0.
 */
int32_t advance_bridge_start(
    const char *workspace_root_utf8,
    int32_t platform,          /* 0=Mac 1=Ios 2=Android 3=Windows */
    int32_t engine_mode,       /* 0=Jit 1=Interpreter */
    int32_t composition_mode,  /* 0=Embed 1=Supervise */
    const char *config_path_utf8_or_null,
    const char *supervise_command_utf8_or_null,
    int32_t supervise_kill_on_drop, /* 1=default true; 0=keep-available detach */
    const char *supervise_ready_file_utf8_or_null,
    AdvanceBridgeHandle **out_handle
);

/* Idempotent while handle pointer is live. Does NOT free memory. */
int32_t advance_bridge_stop(AdvanceBridgeHandle *handle);

/*
 * Writes NUL-terminated UTF-8 JSON into json_out when buffer is large enough.
 * On ADVANCE_BRIDGE_ERR_BUFFER: writes required size (including NUL) into
 * *required_len if non-null; does not partially write JSON.
 */
int32_t advance_bridge_health(
    const AdvanceBridgeHandle *handle,
    char *json_out,
    size_t json_out_len,
    size_t *required_len_or_null
);

/* battery_pct: 0-100, or -1 if unknown. network_class_utf8_or_null may be NULL. */
int32_t advance_bridge_on_lifecycle(
    AdvanceBridgeHandle *handle,
    int32_t lifecycle_state, /* 0=Foreground 1=Background 2=Suspended 3=Restricted */
    int32_t battery_pct,
    const char *network_class_utf8_or_null
);

/* Thread-local UTF-8; valid until next bridge call on this thread. Redacted. */
const char *advance_bridge_last_error(void);

/*
 * Terminal free. After this returns, the pointer must not be passed to any
 * bridge function (UB / must-not). No-op on NULL.
 * Embed: always stops if not already stopped.
 * Supervise: stops/reaps if supervise_kill_on_drop (default true); if false,
 * detaches without killing the child (keep-available opt-in).
 */
void advance_bridge_free_handle(AdvanceBridgeHandle *handle);

uint32_t advance_bridge_abi_version(void);";

/// v0.1.26 `#define`s 0–13 (and the ABI version).
const V1_DEFINES: &str = "\
#define ADVANCE_BRIDGE_ABI_VERSION 1

#define ADVANCE_BRIDGE_OK                 0
#define ADVANCE_BRIDGE_ERR_INVALID_ARG    1
#define ADVANCE_BRIDGE_ERR_INVALID_UTF8   2
#define ADVANCE_BRIDGE_ERR_INVALID_CONFIG 3
#define ADVANCE_BRIDGE_ERR_INVALID_WS     4
#define ADVANCE_BRIDGE_ERR_ALREADY_RUN    5
#define ADVANCE_BRIDGE_ERR_INVALID_HANDLE 6
#define ADVANCE_BRIDGE_ERR_CONFIG         7
#define ADVANCE_BRIDGE_ERR_BOOTSTRAP      8
#define ADVANCE_BRIDGE_ERR_SUPERVISE      9
#define ADVANCE_BRIDGE_ERR_TIMEOUT       10
#define ADVANCE_BRIDGE_ERR_NESTED_RT     11
#define ADVANCE_BRIDGE_ERR_BUFFER        12
#define ADVANCE_BRIDGE_ERR_INTERNAL      13";

#[test]
fn module_001_ac32_t113_6_v1_prototypes_unchanged() {
    let header = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("include/advance_bridge.h");
    let text = fs::read_to_string(&header).expect("advance_bridge.h");
    assert!(
        text.contains(V1_PROTOTYPES),
        "v1 prototypes (header lines 27-80) must match v0.1.26"
    );
    assert!(
        text.contains(V1_DEFINES),
        "v1 #defines 0-13 must match v0.1.26"
    );
}

/// Copy of `embed_lifecycle.rs`'s `MINIMAL_YAML`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const MINIMAL_YAML: &str = r#"
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false

llm-providers:
  - id: anthropic
    endpoint: https://api.anthropic.com
    api-key-secret: anthropic-api-key
    model-aliases:
      sonnet: claude-sonnet-4-5
    cost-per-mtoken-in: 3.00
    cost-per-mtoken-out: 15.00
    rate-limit:
      requests-per-minute: 1000
      tokens-per-minute: 400000

cron:
  max_jitter_ratio: 0.1

git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10

secrets:
  master-key-source: env-var
  env-var-name: SECRETS_MASTER_KEY

post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600

database:
  db-path: ".runtime/index.db"
  pool-size: 4
"#;

// Provenance: hand-derived at v0.1.26; `git diff --stat v0.1.26 -- crates/embedded-runtime-bridge/src`
// lists only `registry.rs`. types.rs / profile.rs / handle.rs / ffi.rs are byte-identical, so the
// C ABI health JSON is the v0.1.26 bytes. Any live difference would mean these literals are wrong.

#[cfg(any(target_os = "linux", target_os = "macos"))]
const HEALTH_A: &str = r#"{"schema_version":1,"runtime_up":true,"profile":{"agent_host_available":true,"supported_wit_versions":["0.1.0"],"max_concurrent_runs":8,"platform_lifecycle_state":"foreground","storage_profile":"persistent","requires_human_presence":false,"engine_mode":"jit","host_backend":"cranelift","battery_pct":null,"network_class":null},"last_heartbeat_ok":true,"composition_mode":"embed","lock_exclusivity":"runtime_lock","supervise_readiness":null}"#;

#[cfg(any(target_os = "linux", target_os = "macos"))]
const HEALTH_B: &str = r#"{"schema_version":1,"runtime_up":true,"profile":{"agent_host_available":false,"supported_wit_versions":["0.1.0"],"max_concurrent_runs":0,"platform_lifecycle_state":"background","storage_profile":"persistent","requires_human_presence":false,"engine_mode":"jit","host_backend":"cranelift","battery_pct":50,"network_class":"wifi"},"last_heartbeat_ok":true,"composition_mode":"embed","lock_exclusivity":"runtime_lock","supervise_readiness":null}"#;

#[cfg(any(target_os = "linux", target_os = "macos"))]
const HEALTH_C: &str = r#"{"schema_version":1,"runtime_up":true,"profile":{"agent_host_available":false,"supported_wit_versions":["0.1.0"],"max_concurrent_runs":2,"platform_lifecycle_state":"foreground","storage_profile":"bounded","requires_human_presence":true,"engine_mode":"interpreter","host_backend":"cranelift","battery_pct":null,"network_class":null},"last_heartbeat_ok":true,"composition_mode":"embed","lock_exclusivity":"runtime_lock","supervise_readiness":null}"#;

// (d) is handle (a) after (b) then stop: lifecycle input is kept; runtime_up and
// last_heartbeat_ok go false; supported_wit_versions is emptied. The profile is
// not reset to foreground: live v1 bytes keep Background.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const HEALTH_D: &str = r#"{"schema_version":1,"runtime_up":false,"profile":{"agent_host_available":false,"supported_wit_versions":[],"max_concurrent_runs":0,"platform_lifecycle_state":"background","storage_profile":"persistent","requires_human_presence":false,"engine_mode":"jit","host_backend":"cranelift","battery_pct":50,"network_class":"wifi"},"last_heartbeat_ok":false,"composition_mode":"embed","lock_exclusivity":"runtime_lock","supervise_readiness":null}"#;

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn write_workspace() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = fs::canonicalize(dir.path()).expect("canon");
    fs::create_dir_all(workspace.join(".advance")).unwrap();
    fs::create_dir_all(workspace.join(".runtime")).unwrap();
    fs::write(
        workspace.join(".advance").join("runtime-config.yaml"),
        MINIMAL_YAML,
    )
    .unwrap();
    (dir, workspace)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn c_health_json(handle: *const AdvanceBridgeHandle) -> String {
    let mut needed = 0usize;
    let rc = unsafe { advance_bridge_health(handle, std::ptr::null_mut(), 0, &mut needed) };
    assert_eq!(rc, 12, "health size probe");
    assert!(needed > 1);
    let mut buf = vec![0u8; needed];
    let rc = unsafe {
        advance_bridge_health(
            handle,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "health write");
    CStr::from_bytes_until_nul(&buf)
        .expect("nul")
        .to_str()
        .expect("utf8")
        .to_owned()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn c_start(ws: &std::path::Path, platform: i32, engine: i32) -> *mut AdvanceBridgeHandle {
    let ws_c = std::ffi::CString::new(ws.to_str().expect("utf8 path")).unwrap();
    let mut handle: *mut AdvanceBridgeHandle = std::ptr::null_mut();
    let rc = unsafe {
        advance_bridge_start(
            ws_c.as_ptr(),
            platform,
            engine,
            0,
            std::ptr::null(),
            std::ptr::null(),
            1,
            std::ptr::null(),
            &mut handle,
        )
    };
    assert_eq!(rc, 0, "v1 start rc");
    assert!(!handle.is_null(), "v1 start handle");
    handle
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn module_001_ac32_t113_6_v1_health_json_matches_v0_1_26() {
    // (a) fresh FG Mac jit cranelift embed runtime_lock; health within 120 s of start.
    let (_keep_a, ws_a) = write_workspace();
    let started = std::time::Instant::now();
    let handle_a = c_start(&ws_a, 0, 0);
    let json_a = c_health_json(handle_a);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(120),
        "health of a live v1 handle must be read within 120 s of start"
    );
    assert_eq!(json_a, HEALTH_A, "health (a) fresh FG Mac jit");

    // (b) after on_lifecycle Background 50 wifi
    let wifi = std::ffi::CString::new("wifi").unwrap();
    let rc = unsafe { advance_bridge_on_lifecycle(handle_a, 1, 50, wifi.as_ptr()) };
    assert_eq!(rc, 0, "on_lifecycle Background");
    let json_b = c_health_json(handle_a);
    assert_eq!(json_b, HEALTH_B, "health (b) after Background 50 wifi");

    // (d) handle (a) after stop
    assert_eq!(unsafe { advance_bridge_stop(handle_a) }, 0, "stop (a)");
    let json_d = c_health_json(handle_a);
    assert_eq!(json_d, HEALTH_D, "health (d) after stop");
    unsafe { advance_bridge_free_handle(handle_a) };

    // (c) v1 start platform Ios engine Interpreter embed bounded cranelift
    let (_keep_c, ws_c) = write_workspace();
    let handle_c = c_start(&ws_c, 1, 1);
    let json_c = c_health_json(handle_c);
    assert_eq!(json_c, HEALTH_C, "health (c) Ios Interpreter");
    assert_eq!(unsafe { advance_bridge_stop(handle_c) }, 0, "stop (c)");
    unsafe { advance_bridge_free_handle(handle_c) };
}

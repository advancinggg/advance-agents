//! Documented C ABI (advance_bridge.h).

use std::cell::RefCell;
use std::ffi::{c_char, CStr, CString};
use std::path::PathBuf;
use std::ptr;
use std::slice;

use crate::config::BridgeConfig;
use crate::error::BridgeError;
use crate::handle::BridgeHandle;
use crate::types::{
    BridgeLifecycleInput, BridgePlatform, CompositionMode, EngineMode, PlatformLifecycleState,
    ADVANCE_BRIDGE_ABI_VERSION,
};
use crate::{health, on_lifecycle, start, stop};

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::new("").unwrap());
}

fn set_last_error(msg: &str) {
    let safe = CString::new(msg.replace('\0', "")).unwrap_or_else(|_| CString::new("error").unwrap());
    LAST_ERROR.with(|e| *e.borrow_mut() = safe);
}

fn cstr_to_path(p: *const c_char) -> Result<Option<PathBuf>, BridgeError> {
    if p.is_null() {
        return Ok(None);
    }
    let s = unsafe { CStr::from_ptr(p) }
        .to_str()
        .map_err(|_| BridgeError::InvalidUtf8)?;
    Ok(Some(PathBuf::from(s)))
}

fn map_platform(v: i32) -> Result<BridgePlatform, BridgeError> {
    match v {
        0 => Ok(BridgePlatform::Mac),
        1 => Ok(BridgePlatform::Ios),
        2 => Ok(BridgePlatform::Android),
        3 => Ok(BridgePlatform::Windows),
        _ => Err(BridgeError::InvalidArg),
    }
}

fn map_engine(v: i32) -> Result<EngineMode, BridgeError> {
    match v {
        0 => Ok(EngineMode::Jit),
        1 => Ok(EngineMode::Interpreter),
        _ => Err(BridgeError::InvalidArg),
    }
}

fn map_composition(v: i32) -> Result<CompositionMode, BridgeError> {
    match v {
        0 => Ok(CompositionMode::Embed),
        1 => Ok(CompositionMode::Supervise),
        _ => Err(BridgeError::InvalidArg),
    }
}

fn map_lifecycle(v: i32) -> Result<PlatformLifecycleState, BridgeError> {
    match v {
        0 => Ok(PlatformLifecycleState::Foreground),
        1 => Ok(PlatformLifecycleState::Background),
        2 => Ok(PlatformLifecycleState::Suspended),
        3 => Ok(PlatformLifecycleState::Restricted),
        _ => Err(BridgeError::InvalidArg),
    }
}

/// Opaque C handle = boxed BridgeHandle.
pub struct AdvanceBridgeHandle {
    handle: BridgeHandle,
}

/// # Safety
/// `out_handle` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn advance_bridge_start(
    workspace_root_utf8: *const c_char,
    platform: i32,
    engine_mode: i32,
    composition_mode: i32,
    config_path_utf8_or_null: *const c_char,
    supervise_command_utf8_or_null: *const c_char,
    supervise_kill_on_drop: i32,
    supervise_ready_file_utf8_or_null: *const c_char,
    out_handle: *mut *mut AdvanceBridgeHandle,
) -> i32 {
    let result = std::panic::catch_unwind(|| {
        if out_handle.is_null() {
            return Err(BridgeError::InvalidArg);
        }
        unsafe { *out_handle = ptr::null_mut() };
        if workspace_root_utf8.is_null() {
            return Err(BridgeError::InvalidArg);
        }
        if supervise_kill_on_drop != 0 && supervise_kill_on_drop != 1 {
            return Err(BridgeError::InvalidArg);
        }
        let ws = unsafe { CStr::from_ptr(workspace_root_utf8) }
            .to_str()
            .map_err(|_| BridgeError::InvalidUtf8)?;
        let mut cfg = BridgeConfig {
            platform: map_platform(platform)?,
            engine_mode: map_engine(engine_mode)?,
            composition_mode: map_composition(composition_mode)?,
            config_path: cstr_to_path(config_path_utf8_or_null)?,
            supervise_command: cstr_to_path(supervise_command_utf8_or_null)?,
            supervise_ready_marker: None,
            supervise_ready_file: cstr_to_path(supervise_ready_file_utf8_or_null)?,
            supervise_ready_timeout: None,
            supervise_kill_on_drop: supervise_kill_on_drop == 1,
        };
        // silence unused mut if any
        let _ = &mut cfg;
        let handle = start(PathBuf::from(ws), cfg)?;
        let boxed = Box::new(AdvanceBridgeHandle { handle });
        unsafe { *out_handle = Box::into_raw(boxed) };
        Ok(())
    });
    match result {
        Ok(Ok(())) => {
            set_last_error("");
            0
        }
        Ok(Err(e)) => {
            // redacted_message is char-safe; still inside no further panic risk
            let msg = std::panic::catch_unwind(|| e.redacted_message())
                .unwrap_or_else(|_| "error".into());
            set_last_error(&msg);
            e.c_code()
        }
        Err(_) => {
            set_last_error("panic");
            BridgeError::Internal("panic".into()).c_code()
        }
    }
}

/// # Safety
/// `handle` must be null or a live pointer from start.
#[no_mangle]
pub unsafe extern "C" fn advance_bridge_stop(handle: *mut AdvanceBridgeHandle) -> i32 {
    let result = std::panic::catch_unwind(|| {
        if handle.is_null() {
            return Err(BridgeError::InvalidArg);
        }
        // Shared ref only — concurrent stop/health is safe (inner uses Mutex).
        let h = unsafe { &*handle };
        let cloned = h.handle.clone();
        let res = stop(cloned);
        let code = match &res {
            Ok(()) => 0,
            Err(e) => {
                set_last_error(&e.redacted_message());
                e.c_code()
            }
        };
        Ok(code)
    });
    match result {
        Ok(Ok(code)) => {
            if code == 0 {
                set_last_error("");
            }
            code
        }
        Ok(Err(e)) => {
            set_last_error(&e.redacted_message());
            e.c_code()
        }
        Err(_) => {
            set_last_error("panic");
            13
        }
    }
}

/// # Safety
/// `handle` live; `json_out` may be null only if json_out_len==0.
#[no_mangle]
pub unsafe extern "C" fn advance_bridge_health(
    handle: *const AdvanceBridgeHandle,
    json_out: *mut c_char,
    json_out_len: usize,
    required_len_or_null: *mut usize,
) -> i32 {
    let result = std::panic::catch_unwind(|| {
        if handle.is_null() {
            return Err(BridgeError::InvalidArg);
        }
        let h = unsafe { &*handle };
        let health = health(&h.handle)?;
        let json = serde_json::to_string(&health)
            .map_err(|e| BridgeError::Internal(e.to_string()))?;
        let needed = json.len() + 1;
        if !required_len_or_null.is_null() {
            unsafe { *required_len_or_null = needed };
        }
        if json_out.is_null() || json_out_len < needed {
            return Err(BridgeError::BufferTooSmall { required: needed });
        }
        let bytes = json.as_bytes();
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), json_out as *mut u8, bytes.len());
            *json_out.add(bytes.len()) = 0;
        }
        Ok(())
    });
    match result {
        Ok(Ok(())) => {
            set_last_error("");
            0
        }
        Ok(Err(e)) => {
            set_last_error(&e.redacted_message());
            e.c_code()
        }
        Err(_) => {
            set_last_error("panic");
            13
        }
    }
}

/// # Safety
/// `handle` live.
#[no_mangle]
pub unsafe extern "C" fn advance_bridge_on_lifecycle(
    handle: *mut AdvanceBridgeHandle,
    lifecycle_state: i32,
    battery_pct: i32,
    network_class_utf8_or_null: *const c_char,
) -> i32 {
    let result = std::panic::catch_unwind(|| {
        if handle.is_null() {
            return Err(BridgeError::InvalidArg);
        }
        if battery_pct != -1 && !(0..=100).contains(&battery_pct) {
            return Err(BridgeError::InvalidArg);
        }
        let h = unsafe { &*handle };
        let state = map_lifecycle(lifecycle_state)?;
        let network_class = if network_class_utf8_or_null.is_null() {
            None
        } else {
            Some(
                unsafe { CStr::from_ptr(network_class_utf8_or_null) }
                    .to_str()
                    .map_err(|_| BridgeError::InvalidUtf8)?
                    .to_string(),
            )
        };
        let input = BridgeLifecycleInput {
            state,
            battery_pct: if battery_pct < 0 {
                None
            } else {
                Some(battery_pct as u8)
            },
            network_class,
        };
        on_lifecycle(&h.handle, input)
    });
    match result {
        Ok(Ok(())) => {
            set_last_error("");
            0
        }
        Ok(Err(e)) => {
            set_last_error(&e.redacted_message());
            e.c_code()
        }
        Err(_) => {
            set_last_error("panic");
            13
        }
    }
}

#[no_mangle]
pub extern "C" fn advance_bridge_last_error() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().as_ptr())
}

/// # Safety
/// `handle` null or from start; after this, pointer invalid.
#[no_mangle]
pub unsafe extern "C" fn advance_bridge_free_handle(handle: *mut AdvanceBridgeHandle) {
    if handle.is_null() {
        return;
    }
    let _ = std::panic::catch_unwind(|| {
        let boxed = unsafe { Box::from_raw(handle) };
        drop(boxed);
    });
}

#[no_mangle]
pub extern "C" fn advance_bridge_abi_version() -> u32 {
    ADVANCE_BRIDGE_ABI_VERSION
}

// silence unused import warning for slice
#[allow(dead_code)]
fn _slice_hint(p: *const u8, n: usize) -> &'static [u8] {
    unsafe { slice::from_raw_parts(p, n) }
}

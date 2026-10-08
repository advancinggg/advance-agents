//! Shared helpers for the bridge ABI v2 integration tests.

#![allow(dead_code)]

use std::ffi::{c_char, CStr, CString};
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::Duration;

use advance_embedded_runtime_bridge::ffi::{
    advance_bridge_client_api_base, advance_bridge_client_api_session, advance_bridge_free_handle,
    advance_bridge_health, advance_bridge_last_error, advance_bridge_start_v2, advance_bridge_stop,
    AdvanceBridgeHandle,
};
use advance_runtime_compose::test_support::fixture::{
    CapDecl, FixtureDriver, FixtureHome, FixtureHomeSpec,
};

pub fn fixture_home(caps: &[&'static str], driver: FixtureDriver) -> FixtureHome {
    FixtureHome::new(FixtureHomeSpec {
        capabilities: caps.iter().copied().map(CapDecl::Granted).collect(),
        driver,
        git: false,
        providers_yaml: None,
    })
    .expect("fixture home")
}

pub fn json_with_state_root(mut value: serde_json::Value, state_root: &Path) -> String {
    value.as_object_mut().expect("object").insert(
        "state_root".into(),
        serde_json::Value::String(state_root.to_str().expect("utf-8 state_root").to_owned()),
    );
    value.to_string()
}

pub fn last_error() -> String {
    unsafe { CStr::from_ptr(advance_bridge_last_error()) }
        .to_string_lossy()
        .into_owned()
}

pub struct StartV2 {
    pub code: i32,
    pub handle: *mut AdvanceBridgeHandle,
    pub last_error: String,
}

pub fn c_start_v2(workspace: &Path, options: Option<&str>) -> StartV2 {
    let ws = CString::new(workspace.to_str().expect("utf-8 workspace")).expect("workspace cstr");
    let opt = options.map(|s| CString::new(s).expect("options cstr"));
    let mut out: *mut AdvanceBridgeHandle = ptr::null_mut();
    let code = unsafe {
        advance_bridge_start_v2(
            ws.as_ptr(),
            opt.as_ref().map(|c| c.as_ptr()).unwrap_or(ptr::null()),
            &mut out,
        )
    };
    StartV2 {
        code,
        handle: out,
        last_error: last_error(),
    }
}

pub fn c_stop_free(handle: *mut AdvanceBridgeHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        let _ = advance_bridge_stop(handle);
        advance_bridge_free_handle(handle);
    }
}

pub struct Getter {
    pub code: i32,
    pub value: Option<String>,
    pub required: usize,
    pub last_error: String,
}

pub fn c_base(handle: *const AdvanceBridgeHandle) -> Getter {
    c_getter(handle, advance_bridge_client_api_base)
}

pub fn c_session(handle: *const AdvanceBridgeHandle) -> Getter {
    c_getter(handle, advance_bridge_client_api_session)
}

fn c_getter(
    handle: *const AdvanceBridgeHandle,
    f: unsafe extern "C" fn(*const AdvanceBridgeHandle, *mut c_char, usize, *mut usize) -> i32,
) -> Getter {
    let mut required = 0usize;
    let code = unsafe { f(handle, ptr::null_mut(), 0, &mut required) };
    if code != 12 {
        return Getter {
            code,
            value: None,
            required,
            last_error: last_error(),
        };
    }
    let mut buf = vec![0u8; required];
    let code = unsafe {
        f(
            handle,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            ptr::null_mut(),
        )
    };
    let value = if code == 0 {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        Some(String::from_utf8_lossy(&buf[..end]).into_owned())
    } else {
        None
    };
    Getter {
        code,
        value,
        required,
        last_error: last_error(),
    }
}

/// Call a getter into a pre-filled buffer (for "untouched on 14" checks).
pub fn c_getter_into(
    handle: *const AdvanceBridgeHandle,
    f: unsafe extern "C" fn(*const AdvanceBridgeHandle, *mut c_char, usize, *mut usize) -> i32,
    buf: &mut [u8],
) -> (i32, usize, String) {
    let mut required = 0usize;
    let code = unsafe {
        f(
            handle,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut required,
        )
    };
    (code, required, last_error())
}

pub fn c_health(handle: *const AdvanceBridgeHandle) -> Getter {
    let mut required = 0usize;
    let code = unsafe { advance_bridge_health(handle, ptr::null_mut(), 0, &mut required) };
    if code != 12 {
        return Getter {
            code,
            value: None,
            required,
            last_error: last_error(),
        };
    }
    let mut buf = vec![0u8; required];
    let code = unsafe {
        advance_bridge_health(
            handle,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            ptr::null_mut(),
        )
    };
    let value = if code == 0 {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        Some(String::from_utf8_lossy(&buf[..end]).into_owned())
    } else {
        None
    };
    Getter {
        code,
        value,
        required,
        last_error: last_error(),
    }
}

pub fn block_on_local<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("local runtime")
        .block_on(fut)
}

pub fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, String) {
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (k, v) in headers {
        request.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() {
        request.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    } else {
        request.push_str("\r\n");
    }
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .expect("write timeout");
    stream.write_all(request.as_bytes()).expect("write headers");
    if !body.is_empty() {
        stream.write_all(body).expect("write body");
    }
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("read response");
    parse_http(&response)
}

fn parse_http(bytes: &[u8]) -> (u16, String) {
    let text = String::from_utf8_lossy(bytes);
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let rest = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    (status, rest.to_owned())
}

pub fn walk_contains(dir: &Path, needle: &str) -> bool {
    fn rec(path: &Path, needle: &str) -> bool {
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.contains(needle))
        {
            return true;
        }
        if path.is_file() {
            if let Ok(bytes) = fs::read(path) {
                if String::from_utf8_lossy(&bytes).contains(needle) {
                    return true;
                }
            }
        } else if path.is_dir() {
            if let Ok(rd) = fs::read_dir(path) {
                for entry in rd.flatten() {
                    if rec(&entry.path(), needle) {
                        return true;
                    }
                }
            }
        }
        false
    }
    rec(dir, needle)
}

pub fn path_buf(p: &Path) -> PathBuf {
    p.to_path_buf()
}

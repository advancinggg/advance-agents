//! MODULE-001-T113 (5) — InProcessOnly admission, FFI session, foreground rebind.

mod common;

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::Command;
use std::ptr;
use std::sync::Arc;
use std::time::Duration;

use advance_client_api::{Platform, API_VERSION};
use advance_embedded_runtime_bridge::ffi::{
    advance_bridge_client_api_session, advance_bridge_on_lifecycle, handle_from_raw,
    into_raw_handle,
};
use advance_embedded_runtime_bridge::{start_with_extensions, BridgeOptions};
use advance_runtime_compose::log_keys;
use advance_runtime_compose::test_support::fixture::FixtureDriver;
use advance_runtime_compose::test_support::MemoryComposeLog;
use common::{
    block_on_local, c_base, c_session, c_stop_free, fixture_home, http, last_error, walk_contains,
};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const ZERO_BOOTSTRAP_JSON: &[u8] = br#"{"bootstrap_code":"00000000000000000000000000000000"}"#;

fn parse_base(base: &str) -> SocketAddr {
    base.strip_prefix("http://")
        .unwrap_or(base)
        .parse()
        .unwrap_or_else(|_| panic!("client api base is not a socket addr"))
}

fn json_error_code(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.pointer("/error/code")
                .and_then(|c| c.as_str())
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

fn auth(token: &str) -> String {
    format!("Bearer {token}")
}

fn get_runs(addr: SocketAddr, token: Option<&str>, origin: Option<&str>) -> (u16, String) {
    let auth_header;
    let mut headers: Vec<(&str, &str)> = vec![("x-advance-api-version", API_VERSION)];
    if let Some(tok) = token {
        auth_header = auth(tok);
        headers.push(("Authorization", auth_header.as_str()));
    }
    if let Some(o) = origin {
        headers.push(("Origin", o));
    }
    http(addr, "GET", "/client/runs", &headers, &[])
}

fn token_absent_from_disk_log_url(
    home: &std::path::Path,
    state_root: &std::path::Path,
    mem: &MemoryComposeLog,
    base: &str,
    token: &str,
) {
    assert!(
        !walk_contains(home, token),
        "session token appeared under the home"
    );
    assert!(
        !walk_contains(state_root, token),
        "session token appeared under the state root"
    );
    assert!(
        !mem.lines().iter().any(|line| line.text.contains(token)),
        "session token appeared in a compose log line"
    );
    assert!(
        !base.contains(token),
        "session token appeared in the Client API base"
    );
}

fn expect_rebound_or_diagnose(
    raw: *mut advance_embedded_runtime_bridge::ffi::AdvanceBridgeHandle,
    rt: &advance_runtime_compose::ComposedRuntime,
    previous: SocketAddr,
    old_base: &str,
    mem: &MemoryComposeLog,
) {
    let after = c_base(raw);
    assert_eq!(after.code, 0, "{}", after.last_error);
    let new_base = after.value.expect("base after foreground");
    if new_base == old_base {
        assert!(
            mem.count(log_keys::CLIENT_API_REBOUND) >= 1,
            "expected compose.client_api_rebound: {:?}",
            mem.lines()
        );
        return;
    }
    match TcpListener::bind(previous) {
        Ok(_free) => panic!(
            "expected Rebound on a free port, observed a move {} -> {}",
            previous, new_base
        ),
        Err(_) => {
            let severed = block_on_local(rt.sever_client_api_listener_for_test())
                .expect("sever moved listener");
            let moved_addr = parse_base(&new_base);
            assert_eq!(severed, moved_addr);
            let rc = unsafe { advance_bridge_on_lifecycle(raw, 0, -1, ptr::null()) };
            assert_eq!(rc, 0, "retry FG: {}", last_error());
            let retry = c_base(raw);
            assert_eq!(retry.code, 0, "{}", retry.last_error);
            assert_eq!(
                retry.value.as_deref(),
                Some(new_base.as_str()),
                "retry on the moved listener must Rebound"
            );
            assert!(
                mem.count(log_keys::CLIENT_API_REBOUND) >= 1,
                "expected compose.client_api_rebound after retry: {:?}",
                mem.lines()
            );
        }
    }
}

#[test]
fn module_001_ac32_t113_5_embedded_admission_and_foreground_rebind() {
    let _g = SERIAL.blocking_lock();
    let fixture = fixture_home(&["fs"], FixtureDriver::None);
    let mem = MemoryComposeLog::new();
    let handle = start_with_extensions(
        fixture.home(),
        BridgeOptions::default()
            .with_log(Arc::new(mem.clone()))
            .with_state_root(fixture.state_root()),
        vec![],
    )
    .expect("compose");
    let raw = into_raw_handle(handle.clone());

    let base_g = c_base(raw);
    assert_eq!(base_g.code, 0, "{}", base_g.last_error);
    let base = base_g.value.expect("client api base");
    let addr = parse_base(&base);
    let rust = unsafe { handle_from_raw(raw) }.expect("handle");
    let rt = rust.composed_runtime().expect("composed");
    let ep = rt.client_api().expect("endpoint");
    assert_eq!(ep.socket_addr, addr);

    // (a) second process, no credential.
    let probe = Command::new(std::env::current_exe().expect("current_exe"))
        .args([
            "module_001_ac32_t113_5_second_process_probe",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env("T113_PROBE_BASE", &base)
        .output()
        .expect("spawn second-process probe");
    let child_out = format!(
        "{}{}",
        String::from_utf8_lossy(&probe.stdout),
        String::from_utf8_lossy(&probe.stderr)
    );
    assert!(
        probe.status.success(),
        "second-process probe failed ({:?}):\n{child_out}",
        probe.status
    );
    let probes: Vec<Vec<String>> = child_out
        .split("PROBE ")
        .skip(1)
        .map(|rest| rest.split_whitespace().take(4).map(str::to_owned).collect())
        .collect();
    assert_eq!(probes.len(), 4, "expected four PROBE records:\n{child_out}");
    let mut bootstrap = 0usize;
    let mut unauth = 0usize;
    for (i, parts) in probes.iter().enumerate() {
        assert_eq!(parts.len(), 4, "{parts:?}");
        assert_eq!(parts[0], (i + 1).to_string(), "{parts:?}");
        assert_eq!(parts[1], "401", "{parts:?}");
        assert_eq!(parts[3], "false", "{parts:?}");
        match parts[2].as_str() {
            "invalid_bootstrap_code" => bootstrap += 1,
            "unauthenticated" => unauth += 1,
            other => panic!("unexpected probe code {other}"),
        }
    }
    assert_eq!(bootstrap, 3, "{child_out}");
    assert_eq!(unauth, 1, "{child_out}");
    assert!(
        !child_out.contains("\"token\""),
        "child body carried a token field"
    );
    assert_eq!(
        ep.api.upgrade().expect("api").sessions().len(),
        0,
        "child minted a session"
    );

    // (b) no console assets.
    for path in ["/", "/index.html", "/app.js", "/styles.css"] {
        let (status, body) = http(addr, "GET", path, &[], &[]);
        assert_eq!(status, 404, "{path}: {body}");
        assert!(!body.contains("<html"), "{path}: {body}");
        assert!(!body.contains("login-form"), "{path}: {body}");
    }

    // (c) browser Origin refused.
    let origin_headers = [
        ("Origin", base.as_str()),
        ("x-advance-api-version", API_VERSION),
    ];
    let (health_st, health_body) = http(addr, "GET", "/client/health", &origin_headers, &[]);
    assert_eq!(health_st, 403, "{health_body}");
    assert_eq!(json_error_code(&health_body), "origin_not_allowed");
    let login_headers = [
        ("Origin", base.as_str()),
        ("x-advance-api-version", API_VERSION),
        ("Content-Type", "application/json"),
    ];
    let (login_st, login_body) = http(addr, "POST", "/client/session/login", &login_headers, b"{}");
    assert_eq!(login_st, 403, "{login_body}");
    assert_eq!(json_error_code(&login_body), "origin_not_allowed");

    // (d) FFI session: buffer protocol, HTTP 200, no leak.
    let mut required = 0usize;
    let null_code =
        unsafe { advance_bridge_client_api_session(raw, ptr::null_mut(), 0, &mut required) };
    assert_eq!(null_code, 12, "{}", last_error());
    assert!(required > 1, "required={required}");
    let sess = c_session(raw);
    assert_eq!(sess.code, 0, "{}", sess.last_error);
    assert!(last_error().is_empty(), "{}", last_error());
    let tok = sess.value.expect("session");
    let (runs, runs_body) = get_runs(addr, Some(&tok), None);
    assert_eq!(runs, 200, "{runs_body}");
    let sess2 = c_session(raw);
    assert_eq!(sess2.code, 0, "{}", sess2.last_error);
    let tok2 = sess2.value.expect("session again");
    if tok != tok2 {
        panic!("second session getter rotated the token");
    }
    let (origin_tok_st, origin_tok_body) = get_runs(addr, Some(&tok), Some(base.as_str()));
    assert_eq!(origin_tok_st, 403, "{origin_tok_body}");
    assert_eq!(json_error_code(&origin_tok_body), "origin_not_allowed");
    token_absent_from_disk_log_url(fixture.home(), fixture.state_root(), &mem, &base, &tok);
    assert!(last_error().is_empty(), "{}", last_error());

    // (e) rebind on a free previous port: base and session unchanged.
    let w0 = rt.client_api().expect("endpoint").api;
    let previous = block_on_local(rt.sever_client_api_listener_for_test()).expect("sever");
    assert_eq!(previous, addr);
    TcpStream::connect_timeout(&previous, Duration::from_millis(200))
        .expect_err("severed listener still accepts");
    let rc = unsafe { advance_bridge_on_lifecycle(raw, 0, -1, ptr::null()) };
    assert_eq!(rc, 0, "FG: {}", last_error());
    expect_rebound_or_diagnose(raw, rt.as_ref(), previous, &base, &mem);
    let base_e = c_base(raw);
    assert_eq!(base_e.code, 0, "{}", base_e.last_error);
    let base_after = base_e.value.expect("base after rebind");
    let sess_e = c_session(raw);
    assert_eq!(sess_e.code, 0, "{}", sess_e.last_error);
    let tok_e = sess_e.value.expect("session after rebind");
    let addr_e = parse_base(&base_after);
    if base_after == base {
        if tok_e != tok {
            panic!("Rebound rotated the session");
        }
        let (ok, body) = get_runs(addr_e, Some(&tok_e), None);
        assert_eq!(ok, 200, "{body}");
    } else {
        let (ok, body) = get_runs(addr_e, Some(&tok_e), None);
        assert_eq!(ok, 200, "{body}");
    }
    let ep_e = rt.client_api().expect("endpoint after rebind");
    assert!(
        std::sync::Weak::ptr_eq(&w0, &ep_e.api),
        "ClientApi must be the same Arc"
    );

    // (f) previous port taken: same ClientApi, new base, rotated session.
    let extra = ep_e
        .api
        .upgrade()
        .expect("api")
        .mint_in_process_session(Platform::Mac)
        .token;
    let old_tok = tok_e;
    let old_base = base_after;
    let old_addr = addr_e;
    let p = block_on_local(rt.sever_client_api_listener_for_test()).expect("sever for move");
    assert_eq!(p, old_addr);
    let squat = TcpListener::bind(p).expect("squat the previous port");
    let rc = unsafe { advance_bridge_on_lifecycle(raw, 0, -1, ptr::null()) };
    assert_eq!(rc, 0, "FG move: {}", last_error());
    let base_f = c_base(raw);
    assert_eq!(base_f.code, 0, "{}", base_f.last_error);
    let new_base = base_f.value.expect("moved base");
    let new_addr = parse_base(&new_base);
    assert_ne!(new_addr.port(), p.port(), "base port must change");
    let ep_f = rt.client_api().expect("endpoint after move");
    assert!(
        std::sync::Weak::ptr_eq(&w0, &ep_f.api),
        "ClientApi must be the same Arc after move"
    );
    let sess_f = c_session(raw);
    assert_eq!(sess_f.code, 0, "{}", sess_f.last_error);
    let new_tok = sess_f.value.expect("rotated session");
    if new_tok == old_tok {
        panic!("move did not mint a new session");
    }
    let (ok, body) = get_runs(new_addr, Some(&new_tok), None);
    assert_eq!(ok, 200, "{body}");
    let (old_st, old_body) = get_runs(new_addr, Some(&old_tok), None);
    assert_eq!(old_st, 401, "{old_body}");
    assert_eq!(json_error_code(&old_body), "unauthenticated");
    let (extra_st, extra_body) = get_runs(new_addr, Some(&extra), None);
    assert_eq!(extra_st, 401, "{extra_body}");
    assert_eq!(json_error_code(&extra_body), "unauthenticated");
    assert!(
        mem.count(log_keys::CLIENT_API_MOVED) >= 1,
        "expected compose.client_api_moved: {:?}",
        mem.lines()
    );
    token_absent_from_disk_log_url(
        fixture.home(),
        fixture.state_root(),
        &mem,
        &new_base,
        &new_tok,
    );
    drop(squat);
    drop(old_base);

    c_stop_free(raw);
}

#[test]
#[ignore]
fn module_001_ac32_t113_5_second_process_probe() {
    let base = std::env::var("T113_PROBE_BASE").expect("T113_PROBE_BASE");
    let addr = parse_base(&base);
    let json_headers = [
        ("Content-Type", "application/json"),
        ("x-advance-api-version", API_VERSION),
    ];
    let bodies: &[&[u8]] = &[b"{}", br#"{"platform":"ios"}"#, ZERO_BOOTSTRAP_JSON];
    for (i, body) in bodies.iter().enumerate() {
        let (status, resp) = http(addr, "POST", "/client/session/login", &json_headers, body);
        let code = json_error_code(&resp);
        let has_token = resp.contains("\"token\"");
        println!("PROBE {} {status} {code} {has_token}", i + 1);
    }
    let (status, resp) = http(
        addr,
        "GET",
        "/client/runs",
        &[("x-advance-api-version", API_VERSION)],
        &[],
    );
    let code = json_error_code(&resp);
    let has_token = resp.contains("\"token\"");
    println!("PROBE 4 {status} {code} {has_token}");
}

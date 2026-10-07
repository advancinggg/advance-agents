//! MODULE-001-AC-32 — `Admission::InProcessOnly` composes; a failed in-process
//! listener bind fails compose; the embedded profile refuses same-user admission.

#[path = "support/t111.rs"]
mod t111;

use std::sync::Arc;

use advance_runtime_compose::registry::reserved_homes_for_test;
use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, CapDecl, FixtureDriver, FixtureHome, FixtureHomeSpec, Http,
};
use advance_runtime_compose::test_support::{ComposeProbe, MemoryComposeLog};
use advance_runtime_compose::{
    compose, log_keys, Admission, ClientApiOptions, ComposeError, ComposeProfile, HostPlatform,
    Unsupported,
};
use serde_json::json;
use t111::assert_steps;

static SERIAL: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

fn home(caps: &[&'static str]) -> FixtureHome {
    FixtureHome::new(FixtureHomeSpec {
        capabilities: caps.iter().copied().map(CapDecl::Granted).collect(),
        driver: FixtureDriver::None,
        git: false,
        providers_yaml: None,
    })
    .expect("home")
}

fn error_code(body: &serde_json::Value) -> &str {
    body.pointer("/error/code")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_in_process_only_refuses_credentialless_loopback_login() {
    let _serial = SERIAL.lock().await;
    let home = home(&["fs"]);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log.clone()), Arc::clone(&probe))
            .with_client_api(ClientApiOptions::loopback(
                0,
                false,
                Admission::InProcessOnly,
            )),
        Vec::new(),
    )
    .await
    .expect("in-process-only composes");
    let ep = rt.client_api().expect("client api");
    let addr = ep.socket_addr;

    let login = Http::post(addr, "/client/session/login")
        .json(json!({}))
        .await;
    assert_eq!(login.status, 401, "{:?}", login.body);
    assert_eq!(error_code(&login.body), "invalid_bootstrap_code");

    let console = Http::get(addr, "/").send().await;
    assert_eq!(console.status, 404, "{:?}", console.body);

    let origin = Http::get(addr, "/client/health")
        .origin(format!("http://{addr}"))
        .send()
        .await;
    assert_eq!(origin.status, 403, "{:?}", origin.body);
    assert_eq!(error_code(&origin.body), "origin_not_allowed");

    let health = Http::get(addr, "/client/health").send().await;
    assert_eq!(health.status, 200, "{:?}", health.body);

    assert!(log.count(log_keys::CLIENT_API_LISTENING_IN_PROCESS) >= 1);
    assert_eq!(log.count(log_keys::CLIENT_API_LISTENING), 0);
    assert!(!home.home().join(".runtime/client-api").exists());

    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_in_process_only_listener_bind_failure_fails_compose_typed() {
    let _serial = SERIAL.lock().await;
    let home = home(&["fs", "messaging"]);
    let holder = std::net::TcpListener::bind("127.0.0.1:0").expect("hold the port");
    let port = holder.local_addr().expect("held addr").port();
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let error = compose(
        home.options(Arc::new(log.clone()), Arc::clone(&probe))
            .with_client_api(ClientApiOptions::loopback(
                port,
                false,
                Admission::InProcessOnly,
            )),
        Vec::new(),
    )
    .await
    .expect_err("in-process bind failure fails compose");
    match &error {
        ComposeError::Listener(text) => {
            assert!(
                text.starts_with("failed to bind Client API listener:"),
                "{text}"
            );
        }
        other => panic!("expected ComposeError::Listener, got {other:?}"),
    }
    let rec = probe.record();
    assert_steps(&rec, &["holds.breaker", "holds.event_bus", "guard"]);
    assert!(
        !rec.step_names().contains(&"ingress.client_api"),
        "no Client API ingress:\n{}",
        rec.render_steps()
    );
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;

    drop(holder);
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(MemoryComposeLog::new()), Arc::clone(&probe))
            .with_client_api(ClientApiOptions::loopback(
                0,
                false,
                Admission::InProcessOnly,
            )),
        Vec::new(),
    )
    .await
    .expect("the home composes once the port is free");
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_embedded_profile_refuses_same_user_admission() {
    let _serial = SERIAL.lock().await;
    let home = home(&["fs"]);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let error = compose(
        home.options(Arc::new(log), Arc::clone(&probe))
            .with_profile(ComposeProfile::Embedded {
                platform: HostPlatform::compiled().unwrap(),
            })
            .with_client_api(ClientApiOptions::daemon()),
        Vec::new(),
    )
    .await
    .expect_err("embedded + same-user admission is refused");
    match error {
        ComposeError::Unsupported(what) => {
            assert_eq!(what, Unsupported::EmbeddedAdmission);
            assert_eq!(
                what.to_string(),
                "the embedded profile admits only in-process Client API sessions (Admission::InProcessOnly)"
            );
        }
        other => panic!("expected Unsupported::EmbeddedAdmission, got {other:?}"),
    }
    assert!(!home.home().join(".runtime/runtime.lock").exists());
    assert!(!reserved_homes_for_test().contains(&home.home().to_path_buf()));
    let rec = probe.record();
    assert!(
        rec.teardown_steps.is_empty() && rec.listeners.is_empty() && rec.client_api.is_none(),
        "validate has no side effect:\n{}",
        rec.render_steps()
    );
}

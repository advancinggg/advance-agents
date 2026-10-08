//! MODULE-001-AC-32 — Client API ingress: foreground re-verification and rebind
//! on the same `ClientApi`. Admission legs: `InProcessOnly` composes; a failed in-process
//! listener bind fails compose; the embedded profile refuses same-user admission.

#[path = "support/t111.rs"]
mod t111;

use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use advance_client_api::CLIENT_WS_PROTOCOL;
use advance_runtime_compose::registry::reserved_homes_for_test;
use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, mint_session, CapDecl, FixtureDriver, FixtureExtension, FixtureFamilies,
    FixtureHome, FixtureHomeSpec, Http, FIXTURE_ID,
};
use advance_runtime_compose::test_support::{ComposeProbe, MemoryComposeLog};
use advance_runtime_compose::{
    compose, log_keys, Admission, ClientApiCheck, ClientApiEndpoint, ClientApiOptions,
    ClientApiRebindError, ComposeError, ComposeOptions, ComposeProfile, ComposedRuntime,
    HostPlatform, Unsupported,
};
use futures::{SinkExt, StreamExt};
use serde_json::json;
use t111::assert_steps;
use tokio_tungstenite::tungstenite::Message;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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

fn in_process(
    home: &FixtureHome,
    log: Arc<MemoryComposeLog>,
    probe: Arc<ComposeProbe>,
    write_discovery: bool,
) -> ComposeOptions {
    home.options(log, probe)
        .with_client_api(ClientApiOptions::loopback(
            0,
            write_discovery,
            Admission::InProcessOnly,
        ))
}

fn error_code(body: &serde_json::Value) -> &str {
    body.pointer("/error/code")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
}

async fn token_answers(addr: SocketAddr, token: &str) -> u16 {
    Http::get(addr, "/client/runs")
        .session(token)
        .send()
        .await
        .status
}

fn same_api(left: &ClientApiEndpoint, right: &Weak<advance_client_api::ClientApi>) -> bool {
    Weak::ptr_eq(&left.api, right)
}

/// Open `/client/events/stream` without an `Origin` (InProcessOnly refuses browser origins).
async fn open_events_ws(endpoint: &ClientApiEndpoint, token: &str) -> t111::ClientWs {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL;

    let addr = endpoint.socket_addr;
    let mut request = format!("ws://{addr}/client/events/stream")
        .into_client_request()
        .expect("WebSocket request");
    request.headers_mut().insert(
        SEC_WEBSOCKET_PROTOCOL,
        format!("{CLIENT_WS_PROTOCOL}, advance.bearer.{token}")
            .parse()
            .expect("protocol header"),
    );
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect the Client API");
    let (mut ws, _) = tokio_tungstenite::client_async(request, tcp)
        .await
        .expect("WebSocket handshake");
    let _seed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(text))) => return text.to_string(),
                Some(Ok(Message::Ping(payload))) => {
                    let _ = ws.send(Message::Pong(payload)).await;
                }
                other => panic!("unexpected frame before the seed: {other:?}"),
            }
        }
    })
    .await
    .expect("the seed frame arrives");
    ws
}

async fn expect_rebound(rt: &ComposedRuntime, previous: SocketAddr) -> SocketAddr {
    match rt.reverify_client_api().await {
        Ok(ClientApiCheck::Rebound { addr }) => {
            assert_eq!(addr, previous);
            addr
        }
        Ok(ClientApiCheck::Moved {
            previous: moved_from,
            current,
        }) => {
            assert_eq!(moved_from, previous);
            match std::net::TcpListener::bind(previous) {
                Ok(_) => panic!(
                    "expected Rebound; previous port {previous} was free but reverify moved to {current}"
                ),
                Err(error) => panic!(
                    "expected Rebound; previous port {previous} was held ({error}) and reverify moved to {current}"
                ),
            }
        }
        other => panic!("expected Rebound, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_reverify_of_a_healthy_listener_changes_nothing() {
    let _serial = SERIAL.lock().await;
    let home = home(&["fs"]);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        in_process(&home, Arc::new(log), Arc::clone(&probe), false),
        Vec::new(),
    )
    .await
    .expect("compose");
    let ep = rt.client_api().expect("client api");
    let previous = ep.socket_addr;
    let api = ep.api.clone();
    let token = mint_session(&ep);
    assert_eq!(token_answers(previous, &token).await, 200);

    let check = rt.reverify_client_api().await.expect("reverify");
    assert_eq!(check, ClientApiCheck::Healthy);
    let after = rt.client_api().expect("still bound");
    assert_eq!(after.socket_addr, previous);
    assert!(same_api(&after, &api));
    assert_eq!(token_answers(previous, &token).await, 200);

    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_reverify_after_a_failed_probe_retires_and_rebinds_the_previous_port() {
    let _serial = SERIAL.lock().await;
    let home = home(&["fs"]);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        in_process(&home, Arc::new(log), Arc::clone(&probe), false),
        Vec::new(),
    )
    .await
    .expect("compose");
    let ep = rt.client_api().expect("client api");
    let previous = ep.socket_addr;
    let api = ep.api.clone();
    let token = mint_session(&ep);

    rt.fail_next_client_api_probe_for_test();
    let addr = expect_rebound(&rt, previous).await;
    let after = rt.client_api().expect("rebound");
    assert_eq!(after.socket_addr, addr);
    assert!(same_api(&after, &api));
    assert_eq!(token_answers(addr, &token).await, 200);

    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_reverify_after_sever_rebinds_the_previous_port() {
    let _serial = SERIAL.lock().await;
    let home = home(&["fs"]);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        in_process(&home, Arc::new(log), Arc::clone(&probe), false),
        Vec::new(),
    )
    .await
    .expect("compose");
    let previous = rt.client_api().expect("client api").socket_addr;
    let severed = rt
        .sever_client_api_listener_for_test()
        .await
        .expect("severed");
    assert_eq!(severed, previous);

    expect_rebound(&rt, previous).await;

    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_reverify_moves_when_the_previous_port_is_taken() {
    let _serial = SERIAL.lock().await;
    let home = home(&["fs"]);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        in_process(&home, Arc::new(log), Arc::clone(&probe), true),
        Vec::new(),
    )
    .await
    .expect("compose");
    let ep = rt.client_api().expect("client api");
    let previous = ep.socket_addr;
    let api = ep.api.clone();
    let token = mint_session(&ep);
    let mut events = open_events_ws(&ep, &token).await;

    let severed = rt
        .sever_client_api_listener_for_test()
        .await
        .expect("severed");
    assert_eq!(severed, previous);
    let squat = std::net::TcpListener::bind(previous).expect("squat the previous port");

    let check = rt.reverify_client_api().await.expect("reverify");
    let ClientApiCheck::Moved {
        previous: moved_from,
        current,
    } = check
    else {
        panic!("expected Moved, got {check:?}");
    };
    assert_eq!(moved_from, previous);
    assert_ne!(current, previous);
    let after = rt.client_api().expect("moved");
    assert_eq!(after.socket_addr, current);
    assert!(same_api(&after, &api));
    let discovery =
        std::fs::read_to_string(home.home().join(".runtime/client-api")).expect("discovery file");
    assert!(
        discovery.contains(&format!("http://{current}")),
        "{discovery}"
    );
    t111::assert_ws_closed(&mut events, Duration::from_secs(2)).await;
    assert_eq!(token_answers(current, &token).await, 200);

    drop(squat);
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_rebind_keeps_extension_families_serving() {
    let _serial = SERIAL.lock().await;
    let home = home(&["fs"]);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let ext = FixtureExtension::new(FIXTURE_ID).with_families(FixtureFamilies::standard());
    let rt = compose(
        in_process(&home, Arc::new(log), Arc::clone(&probe), false),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    let ep = rt.client_api().expect("client api");
    let previous = ep.socket_addr;
    let token = mint_session(&ep);

    async fn fixture_status(addr: SocketAddr, token: Option<&str>) -> u16 {
        let req = Http::get(addr, "/client/fixture/status");
        let req = match token {
            Some(token) => req.session(token),
            None => req,
        };
        req.send().await.status
    }

    rt.fail_next_client_api_probe_for_test();
    let rebound = expect_rebound(&rt, previous).await;
    assert_eq!(fixture_status(rebound, Some(&token)).await, 200);
    assert_eq!(fixture_status(rebound, None).await, 401);

    let severed = rt
        .sever_client_api_listener_for_test()
        .await
        .expect("severed");
    assert_eq!(severed, rebound);
    let squat = std::net::TcpListener::bind(rebound).expect("squat");
    let check = rt.reverify_client_api().await.expect("moved");
    let ClientApiCheck::Moved { current, .. } = check else {
        panic!("expected Moved, got {check:?}");
    };
    assert_eq!(fixture_status(current, Some(&token)).await, 200);
    assert_eq!(fixture_status(current, None).await, 401);

    drop(squat);
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_rebound_listener_serves_no_console() {
    let _serial = SERIAL.lock().await;
    let home = home(&["fs"]);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        in_process(&home, Arc::new(log), Arc::clone(&probe), false),
        Vec::new(),
    )
    .await
    .expect("compose");
    let previous = rt.client_api().expect("client api").socket_addr;
    rt.fail_next_client_api_probe_for_test();
    let addr = expect_rebound(&rt, previous).await;

    let console = Http::get(addr, "/").send().await;
    assert_eq!(console.status, 404, "{:?}", console.body);
    let origin = Http::get(addr, "/client/health")
        .origin(format!("http://{addr}"))
        .send()
        .await;
    assert_eq!(origin.status, 403, "{:?}", origin.body);
    assert_eq!(error_code(&origin.body), "origin_not_allowed");

    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_failed_rebind_leaves_the_api_unbound_until_the_next_reverify() {
    let _serial = SERIAL.lock().await;
    let home = home(&["fs"]);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        in_process(&home, Arc::new(log.clone()), Arc::clone(&probe), false),
        Vec::new(),
    )
    .await
    .expect("compose");
    let previous = rt.client_api().expect("client api").socket_addr;
    rt.sever_client_api_listener_for_test()
        .await
        .expect("severed");
    rt.fail_next_client_api_rebind_for_test();

    let error = rt
        .reverify_client_api()
        .await
        .expect_err("both binds failed");
    match &error {
        ClientApiRebindError::Bind { previous: addr, .. } => assert_eq!(*addr, previous),
        other => panic!("expected Bind, got {other:?}"),
    }
    assert!(rt.client_api().is_none());
    assert!(rt.health().client_api_base.is_none());
    assert!(log.count(log_keys::CLIENT_API_REBIND_FAILED) >= 1);

    let recovered = rt.reverify_client_api().await.expect("next reverify");
    match recovered {
        ClientApiCheck::Rebound { addr } => assert_eq!(addr, previous),
        ClientApiCheck::Moved {
            previous: from,
            current,
        } => {
            assert_eq!(from, previous);
            assert_ne!(current, previous);
        }
        other => panic!("expected Rebound or Moved, got {other:?}"),
    }
    assert!(rt.client_api().is_some());

    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_shutdown_without_a_listener_completes_and_frees_the_home() {
    let _serial = SERIAL.lock().await;
    let home = home(&["fs"]);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        in_process(&home, Arc::new(log), Arc::clone(&probe), false),
        Vec::new(),
    )
    .await
    .expect("compose");
    let api = rt.client_api().expect("client api").api.clone();
    rt.sever_client_api_listener_for_test()
        .await
        .expect("severed");
    rt.fail_next_client_api_rebind_for_test();
    rt.reverify_client_api().await.expect_err("unbound");

    rt.shutdown().await.expect("shutdown");
    let rec = probe.record();
    assert!(
        rec.step_names().contains(&"ingress.client_api"),
        "shutdown_unbound still records ingress.client_api:\n{}",
        rec.render_steps()
    );
    assert!(api.upgrade().is_none(), "Weak<ClientApi> is dead");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_reverify_is_refused_for_same_user_admission() {
    let _serial = SERIAL.lock().await;
    let home = home(&["fs"]);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(home.options(Arc::new(log), Arc::clone(&probe)), Vec::new())
        .await
        .expect("daemon composes");
    let error = rt
        .reverify_client_api()
        .await
        .expect_err("daemon is never rebound");
    assert!(
        matches!(error, ClientApiRebindError::NotInProcessAdmission),
        "{error:?}"
    );

    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_reverify_without_a_client_api_is_not_composed() {
    let _serial = SERIAL.lock().await;
    let home = home(&["fs"]);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe))
            .with_client_api(ClientApiOptions::Off),
        Vec::new(),
    )
    .await
    .expect("compose without a Client API");
    let error = rt
        .reverify_client_api()
        .await
        .expect_err("nothing to reverify");
    assert!(
        matches!(error, ClientApiRebindError::NotComposed),
        "{error:?}"
    );

    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_reverify_after_shutdown_started_is_refused() {
    let _serial = SERIAL.lock().await;
    let home = home(&["fs"]);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        in_process(&home, Arc::new(log), Arc::clone(&probe), false),
        Vec::new(),
    )
    .await
    .expect("compose");
    rt.shutdown_handle().trigger();
    let error = rt
        .reverify_client_api()
        .await
        .expect_err("shutdown has started");
    assert!(
        matches!(error, ClientApiRebindError::ShuttingDown),
        "{error:?}"
    );
    rt.wait().await;
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_reverify_racing_shutdown_step_1_answers_shutting_down() {
    let _serial = SERIAL.lock().await;
    let home = home(&["fs"]);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        in_process(&home, Arc::new(log), Arc::clone(&probe), false),
        Vec::new(),
    )
    .await
    .expect("compose");
    let pause = rt
        .pause_next_client_api_reverify_for_test()
        .expect("ingress");
    let (check, _) = tokio::join!(rt.reverify_client_api(), async {
        pause.reached.notified().await;
        rt.shutdown_handle().trigger();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if probe.record().step_names().contains(&"ingress.client_api") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "shutdown step 1 did not record ingress.client_api:\n{}",
                probe.record().render_steps()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        pause.resume.notify_one();
    });
    assert!(
        matches!(check, Err(ClientApiRebindError::ShuttingDown)),
        "{check:?}"
    );
    rt.wait().await;
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_shutdown_after_a_move_frees_every_listener() {
    let _serial = SERIAL.lock().await;
    let home = home(&["fs"]);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        in_process(&home, Arc::new(log), Arc::clone(&probe), false),
        Vec::new(),
    )
    .await
    .expect("compose");
    let api = rt.client_api().expect("client api").api.clone();
    let previous = rt.client_api().expect("client api").socket_addr;
    rt.sever_client_api_listener_for_test()
        .await
        .expect("severed");
    let squat = std::net::TcpListener::bind(previous).expect("squat");
    let check = rt.reverify_client_api().await.expect("moved");
    let ClientApiCheck::Moved { current, .. } = check else {
        panic!("expected Moved, got {check:?}");
    };
    assert_ne!(current, previous);
    drop(squat);

    rt.shutdown().await.expect("shutdown");
    assert!(api.upgrade().is_none(), "Weak<ClientApi> is dead");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
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

//! MODULE-001-AC-32 — `SessionAdmission::InProcessOnly` login, origin, console, mint.

use std::net::SocketAddr;
use std::sync::Arc;

use advance_client_api::api::HandlerSpec;
use advance_client_api::audit::RecordingSink;
use advance_client_api::clock::{Clock, TestClock};
use advance_client_api::request::Method;
use advance_client_api::{
    ClientApi, ClientApiConfig, ClientApiServer, ClientErrorCode, ClientRequest, Platform, Scope,
    SessionAdmission,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn in_process_cfg() -> ClientApiConfig {
    ClientApiConfig {
        session_admission: SessionAdmission::InProcessOnly,
        allowed_origins: vec!["https://console.local".into()],
        ..ClientApiConfig::default()
    }
}

fn api_with(config: ClientApiConfig, clock: Arc<TestClock>, sink: Arc<RecordingSink>) -> ClientApi {
    let mut api = ClientApi::with_parts(config, "tester", clock as Arc<dyn Clock>, sink);
    api.register(
        Method::Get,
        "/client/whoami",
        HandlerSpec::read(true, |ctx| {
            Ok(json!({
                "id": ctx.principal.as_ref().map(|p| p.id.clone()).unwrap_or_default()
            }))
        }),
    );
    api
}

#[test]
fn module_001_ac32_in_process_only_login_requires_a_credential_even_from_loopback() {
    let clock = Arc::new(TestClock::new(1_000_000));
    let sink = Arc::new(RecordingSink::new());
    let api = api_with(in_process_cfg(), clock.clone(), sink);

    let empty = api.handle(ClientRequest::post("/client/session/login", json!({})));
    assert_eq!(
        empty.error_code(),
        Some(ClientErrorCode::InvalidBootstrapCode)
    );
    let ios = api.handle(ClientRequest::post(
        "/client/session/login",
        json!({ "platform": "ios" }),
    ));
    assert_eq!(
        ios.error_code(),
        Some(ClientErrorCode::InvalidBootstrapCode)
    );
    assert_eq!(api.sessions().len(), 0);

    let code = api.auth().mint_bootstrap_code(clock.now_millis());
    let ok = api.handle(ClientRequest::post(
        "/client/session/login",
        json!({ "bootstrap_code": code }),
    ));
    assert!(ok.is_ok(), "{:?}", ok.error_code());
    let token = ok.data.as_ref().unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();

    let refreshed = api.handle(
        ClientRequest::post("/client/session/refresh", json!({})).with_session(token.as_str()),
    );
    assert!(refreshed.is_ok(), "{:?}", refreshed.error_code());
    let new_token = refreshed.data.as_ref().unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();

    let logout = api.handle(
        ClientRequest::post("/client/session/logout", json!({})).with_session(new_token.as_str()),
    );
    assert!(logout.is_ok(), "{:?}", logout.error_code());
    assert_eq!(api.sessions().len(), 0);
}

#[test]
fn module_001_ac32_in_process_only_refuses_every_browser_origin() {
    let clock = Arc::new(TestClock::new(1_000_000));
    let sink = Arc::new(RecordingSink::new());
    let api = api_with(in_process_cfg(), clock, sink);

    let with_origin =
        api.handle(ClientRequest::get("/client/health").with_origin("https://console.local"));
    assert_eq!(
        with_origin.error_code(),
        Some(ClientErrorCode::OriginNotAllowed)
    );

    let no_origin = api.handle(ClientRequest::get("/client/health"));
    assert!(no_origin.is_ok(), "{:?}", no_origin.error_code());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac32_in_process_only_router_serves_no_console() {
    let clock = Arc::new(TestClock::new(1_000_000));
    let sink = Arc::new(RecordingSink::new());
    let in_process = Arc::new(api_with(in_process_cfg(), clock, sink));
    let server = ClientApiServer::bind(in_process, 0).await.expect("bind");
    let addr = server.local_addr();
    for path in ["/", "/index.html", "/app.js", "/styles.css"] {
        let status = http_get(addr, path).await;
        assert_eq!(status, 404, "{path}");
    }
    server.shutdown().await.expect("shutdown");

    let clock = Arc::new(TestClock::new(1_000_000));
    let sink = Arc::new(RecordingSink::new());
    let default = Arc::new(api_with(ClientApiConfig::default(), clock, sink));
    let server = ClientApiServer::bind(default, 0)
        .await
        .expect("bind default");
    let addr = server.local_addr();
    let body = http_get_body(addr, "/").await;
    assert!(body.starts_with("HTTP/1.1 200"), "{body}");
    assert!(body
        .to_ascii_lowercase()
        .contains("content-security-policy:"));
    server.shutdown().await.expect("shutdown default");
}

#[test]
fn module_001_ac32_default_admission_is_unchanged() {
    let clock = Arc::new(TestClock::new(1_000_000));
    let sink = Arc::new(RecordingSink::new());
    let cfg = ClientApiConfig {
        allowed_origins: vec!["https://console.local".into()],
        ..ClientApiConfig::default()
    };
    assert_eq!(cfg.session_admission, SessionAdmission::SameUserLoopback);
    let api = api_with(cfg, clock, sink);
    let login = api.handle(ClientRequest::post(
        "/client/session/login",
        json!({ "platform": "mac" }),
    ));
    assert!(login.is_ok(), "{:?}", login.error_code());
    let health =
        api.handle(ClientRequest::get("/client/health").with_origin("https://console.local"));
    assert!(health.is_ok(), "{:?}", health.error_code());
}

#[test]
fn module_001_ac32_mint_in_process_session_is_an_operator_native_session() {
    let clock = Arc::new(TestClock::new(1_000_000));
    let sink = Arc::new(RecordingSink::new());
    let api = api_with(in_process_cfg(), clock.clone(), Arc::clone(&sink));
    let info = api.mint_in_process_session(Platform::Mac);
    assert_eq!(info.principal.os_user, "tester");
    assert_eq!(info.principal.id, "tester");
    assert_eq!(info.platform, Platform::Mac);
    assert_eq!(info.scopes, Scope::operator_default());
    assert!(info.csrf_token.is_none());
    assert_eq!(
        info.expires_at,
        1_000_000 + ClientApiConfig::default().session_ttl_ms
    );
    let debug = format!("{info:?}");
    assert!(!debug.contains(&info.token));
    assert!(debug.contains("<redacted>"));
    assert!(
        sink.events().is_empty(),
        "mint emits no audit event: {:?}",
        sink.events()
    );
    let who = api.handle(ClientRequest::get("/client/whoami").with_session(info.token.as_str()));
    assert!(who.is_ok(), "{:?}", who.error_code());
    assert_eq!(who.data.unwrap()["id"], "tester");

    let default_api = api_with(
        ClientApiConfig::default(),
        clock,
        Arc::new(RecordingSink::new()),
    );
    let other = default_api.mint_in_process_session(Platform::Ios);
    let who =
        default_api.handle(ClientRequest::get("/client/whoami").with_session(other.token.as_str()));
    assert!(who.is_ok(), "{:?}", who.error_code());
}

#[test]
fn module_001_ac32_session_valid_for_honours_the_margin() {
    let clock = Arc::new(TestClock::new(1_000_000));
    let sink = Arc::new(RecordingSink::new());
    let api = api_with(in_process_cfg(), clock.clone(), sink);
    let info = api.mint_in_process_session(Platform::Mac);
    let ttl = ClientApiConfig::default().session_ttl_ms;
    let five_min = 5 * 60_000;
    assert!(api.session_valid_for(&info.token, five_min));
    clock.advance(ttl - 60_000);
    assert!(!api.session_valid_for(&info.token, five_min));
    clock.advance(60_000);
    assert!(!api.session_valid_for(&info.token, 0));
    assert_eq!(api.sessions().len(), 0);
}

#[test]
fn module_001_ac32_revoke_all_revokes_every_session() {
    let clock = Arc::new(TestClock::new(1_000_000));
    let sink = Arc::new(RecordingSink::new());
    let api = api_with(in_process_cfg(), clock.clone(), sink);
    let a = api.mint_in_process_session(Platform::Mac);
    let b = api.mint_in_process_session(Platform::Ios);
    let code = api.auth().mint_bootstrap_code(clock.now_millis());
    let login = api.handle(ClientRequest::post(
        "/client/session/login",
        json!({ "bootstrap_code": code }),
    ));
    let login_token = login.data.as_ref().unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    let refreshed = api.handle(
        ClientRequest::post("/client/session/refresh", json!({}))
            .with_session(login_token.as_str()),
    );
    let c = refreshed.data.as_ref().unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(api.sessions().len(), 3);
    let n = api.sessions().revoke_all();
    assert_eq!(n, 3);
    for token in [a.token.as_str(), b.token.as_str(), c.as_str()] {
        let r = api.handle(ClientRequest::get("/client/whoami").with_session(token));
        assert_eq!(r.error_code(), Some(ClientErrorCode::Unauthenticated));
    }
}

async fn http_get(addr: SocketAddr, path: &str) -> u16 {
    let body = http_get_body(addr, path).await;
    body.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

async fn http_get_body(addr: SocketAddr, path: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

//! MODULE-020-AC-04 (integration) — session auth: authentication, CSRF/CORS for browsers, and
//! loopback-only default binding (witnessed by admission enforcement). (§3.3 MODULE-020-T04.)

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use serde_json::json;

use advance_client_api::api::{ClientApi, HandlerSpec};
use advance_client_api::audit::{AuditSink, NoopSink, RecordingSink};
use advance_client_api::clock::{Clock, TestClock};
use advance_client_api::config::ClientApiConfig;
use advance_client_api::envelope::ClientErrorCode;
use advance_client_api::request::{ClientRequest, Method};

const HOUR_MS: u64 = 3_600_000;
const ORIGIN: &str = "https://console.local";

fn build(
    config: ClientApiConfig,
    clock: Arc<TestClock>,
    audit: Arc<dyn AuditSink>,
) -> (ClientApi, Arc<AtomicUsize>) {
    let counter = Arc::new(AtomicUsize::new(0));
    let mut api = ClientApi::with_parts(config, "tester", clock as Arc<dyn Clock>, audit);
    api.register(
        Method::Get,
        "/client/whoami",
        HandlerSpec::read(true, |ctx| {
            Ok(json!({
                "id": ctx.principal.as_ref().map(|p| p.id.clone()).unwrap_or_default()
            }))
        }),
    );
    let c = counter.clone();
    api.register(
        Method::Post,
        "/client/test/mutate",
        HandlerSpec::mutation(true, move |_ctx| {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(json!({ "ok": true }))
        }),
    );
    (api, counter)
}

fn noop() -> Arc<dyn AuditSink> {
    Arc::new(NoopSink)
}

fn login_loopback(api: &ClientApi) -> String {
    let r = api.handle(ClientRequest::post(
        "/client/session/login",
        json!({ "platform": "mac" }),
    ));
    assert!(r.is_ok(), "loopback login: {:?}", r.error_code());
    r.data.unwrap()["token"].as_str().unwrap().to_string()
}

// ── T04a: loopback-only default ───────────────────────────────────────────────────────────
#[test]
fn t04a_loopback_default_bind() {
    let cfg = ClientApiConfig::default();
    assert_eq!(cfg.bind_addr, IpAddr::from([127, 0, 0, 1]));
    assert!(!cfg.remote_bind_enabled);
    assert!(cfg.allowed_origins.is_empty(), "fail-closed CORS default");
}

// ── T04b: remote / bootstrap gate ─────────────────────────────────────────────────────────
#[test]
fn t04b_remote_and_bootstrap_gate() {
    // non-loopback + remote disabled → refused at admission
    let (api, _) = build(
        ClientApiConfig::default(),
        Arc::new(TestClock::new(1)),
        noop(),
    );
    let r = api
        .handle(ClientRequest::post("/client/session/login", json!({})).with_loopback_peer(false));
    assert_eq!(r.error_code(), Some(ClientErrorCode::RemoteBindForbidden));

    // non-loopback + remote enabled, but no / wrong / valid bootstrap code
    let cfg = ClientApiConfig {
        remote_bind_enabled: true,
        ..ClientApiConfig::default()
    };
    let clock = Arc::new(TestClock::new(1_000_000));
    let (api, _) = build(cfg, clock.clone(), noop());

    let no_code = api
        .handle(ClientRequest::post("/client/session/login", json!({})).with_loopback_peer(false));
    assert_eq!(
        no_code.error_code(),
        Some(ClientErrorCode::InvalidBootstrapCode)
    );

    let code = api.auth().mint_bootstrap_code(clock.now_millis());
    assert_eq!(code.len(), 32, "128-bit code = 32 hex chars");

    let wrong = api.handle(
        ClientRequest::post(
            "/client/session/login",
            json!({ "bootstrap_code": "deadbeef" }),
        )
        .with_loopback_peer(false),
    );
    assert_eq!(
        wrong.error_code(),
        Some(ClientErrorCode::InvalidBootstrapCode)
    );

    let ok = api.handle(
        ClientRequest::post(
            "/client/session/login",
            json!({ "bootstrap_code": code.clone() }),
        )
        .with_loopback_peer(false),
    );
    assert!(
        ok.is_ok(),
        "valid code mints a session: {:?}",
        ok.error_code()
    );

    // single-use: the same code cannot be reused
    let reuse = api.handle(
        ClientRequest::post("/client/session/login", json!({ "bootstrap_code": code }))
            .with_loopback_peer(false),
    );
    assert_eq!(
        reuse.error_code(),
        Some(ClientErrorCode::InvalidBootstrapCode)
    );
}

// ── T04c: loopback bootstrap binds to OS user ─────────────────────────────────────────────
#[test]
fn t04c_loopback_bootstrap_os_user() {
    let (api, _) = build(
        ClientApiConfig::default(),
        Arc::new(TestClock::new(1)),
        noop(),
    );
    let r = api.handle(ClientRequest::post(
        "/client/session/login",
        json!({ "platform": "mac" }),
    ));
    assert!(r.is_ok());
    let data = r.data.unwrap();
    assert_eq!(data["principal"]["os_user"], "tester");
    assert_eq!(data["principal"]["id"], "tester");
}

// ── T04d: authentication enforced ─────────────────────────────────────────────────────────
#[test]
fn t04d_auth_enforced() {
    let clock = Arc::new(TestClock::new(1_000_000));
    let (api, _) = build(ClientApiConfig::default(), clock.clone(), noop());

    // missing session
    let r = api.handle(ClientRequest::get("/client/whoami"));
    assert_eq!(r.error_code(), Some(ClientErrorCode::Unauthenticated));

    // invalid token
    let r = api.handle(ClientRequest::get("/client/whoami").with_session("bogus"));
    assert_eq!(r.error_code(), Some(ClientErrorCode::Unauthenticated));

    // valid session
    let token = login_loopback(&api);
    let ok = api.handle(ClientRequest::get("/client/whoami").with_session(token.as_str()));
    assert!(ok.is_ok());
    assert_eq!(ok.data.unwrap()["id"], "tester");

    // expired session (session TTL is 8h; advance past it)
    clock.advance(9 * HOUR_MS);
    let expired = api.handle(ClientRequest::get("/client/whoami").with_session(token.as_str()));
    assert_eq!(expired.error_code(), Some(ClientErrorCode::SessionExpired));
}

// ── T04e: CSRF required for browser mutation ──────────────────────────────────────────────
#[test]
fn t04e_csrf_required_for_browser_mutation() {
    let cfg = ClientApiConfig {
        allowed_origins: vec![ORIGIN.to_string()],
        ..ClientApiConfig::default()
    };
    let (api, counter) = build(cfg, Arc::new(TestClock::new(1_000_000)), noop());

    let login = api.handle(
        ClientRequest::post("/client/session/login", json!({ "platform": "web" }))
            .with_origin(ORIGIN),
    );
    assert!(login.is_ok());
    let data = login.data.unwrap();
    let token = data["token"].as_str().unwrap().to_string();
    let csrf = data["csrf_token"].as_str().unwrap().to_string();

    // browser mutation WITHOUT csrf → rejected before the handler
    let no_csrf = api.handle(
        ClientRequest::post("/client/test/mutate", json!({}))
            .with_session(token.as_str())
            .with_origin(ORIGIN)
            .with_idempotency_key("K1"),
    );
    assert_eq!(no_csrf.error_code(), Some(ClientErrorCode::CsrfRequired));
    assert_eq!(counter.load(Ordering::SeqCst), 0);

    // browser mutation WITH correct csrf → allowed
    let ok = api.handle(
        ClientRequest::post("/client/test/mutate", json!({}))
            .with_session(token.as_str())
            .with_origin(ORIGIN)
            .with_csrf(csrf.as_str())
            .with_idempotency_key("K1"),
    );
    assert!(ok.is_ok(), "correct csrf: {:?}", ok.error_code());
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    // wrong csrf → csrf_invalid (before idempotency/handler)
    let bad = api.handle(
        ClientRequest::post("/client/test/mutate", json!({}))
            .with_session(token.as_str())
            .with_origin(ORIGIN)
            .with_csrf("wrong")
            .with_idempotency_key("K2"),
    );
    assert_eq!(bad.error_code(), Some(ClientErrorCode::CsrfInvalid));
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

// ── T04f: CORS allowlist + native path ────────────────────────────────────────────────────
#[test]
fn t04f_cors_and_native() {
    let cfg = ClientApiConfig {
        allowed_origins: vec![ORIGIN.to_string()],
        ..ClientApiConfig::default()
    };
    let (api, counter) = build(cfg, Arc::new(TestClock::new(1)), noop());

    // disallowed origin → origin_not_allowed
    let evil = api.handle(
        ClientRequest::post("/client/session/login", json!({})).with_origin("https://evil.example"),
    );
    assert_eq!(evil.error_code(), Some(ClientErrorCode::OriginNotAllowed));

    // native client (no Origin) mutation with a valid session → allowed without CSRF
    let token = login_loopback(&api);
    let ok = api.handle(
        ClientRequest::post("/client/test/mutate", json!({}))
            .with_session(token.as_str())
            .with_idempotency_key("N1"),
    );
    assert!(ok.is_ok(), "native no-csrf mutation: {:?}", ok.error_code());
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

// ── T04g: refresh + logout ────────────────────────────────────────────────────────────────
#[test]
fn t04g_refresh_and_logout() {
    let (api, _) = build(
        ClientApiConfig::default(),
        Arc::new(TestClock::new(1_000_000)),
        noop(),
    );
    let old = login_loopback(&api);

    let refreshed = api.handle(
        ClientRequest::post("/client/session/refresh", json!({})).with_session(old.as_str()),
    );
    assert!(refreshed.is_ok());
    let new = refreshed.data.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(new, old, "token rotates on refresh");

    // old token is now invalid
    let stale = api.handle(ClientRequest::get("/client/whoami").with_session(old.as_str()));
    assert_eq!(stale.error_code(), Some(ClientErrorCode::Unauthenticated));

    // logout revokes the new token
    let out = api.handle(
        ClientRequest::post("/client/session/logout", json!({})).with_session(new.as_str()),
    );
    assert!(out.is_ok());
    let after = api.handle(ClientRequest::get("/client/whoami").with_session(new.as_str()));
    assert_eq!(after.error_code(), Some(ClientErrorCode::Unauthenticated));
}

// ── T04h: secret hygiene (no secret in audit events) ──────────────────────────────────────
#[test]
fn t04h_secret_hygiene() {
    let cfg = ClientApiConfig {
        allowed_origins: vec![ORIGIN.to_string()],
        ..ClientApiConfig::default()
    };
    let sink = RecordingSink::new();
    let (api, _) = build(
        cfg,
        Arc::new(TestClock::new(1_000_000)),
        Arc::new(sink.clone()),
    );

    let login = api.handle(
        ClientRequest::post("/client/session/login", json!({ "platform": "web" }))
            .with_origin(ORIGIN),
    );
    let data = login.data.unwrap();
    let token = data["token"].as_str().unwrap().to_string();
    let csrf = data["csrf_token"].as_str().unwrap().to_string();
    let _ = api.handle(
        ClientRequest::post("/client/test/mutate", json!({}))
            .with_session(token.as_str())
            .with_origin(ORIGIN)
            .with_csrf(csrf.as_str())
            .with_idempotency_key("K"),
    );

    for ev in sink.events() {
        let dbg = format!("{ev:?}");
        assert!(!dbg.contains(&token), "audit event leaked session token");
        assert!(!dbg.contains(&csrf), "audit event leaked csrf token");
    }
}

// ── T04j: session store is bounded + swept (audit round-6 fix) ─────────────────────────────
#[test]
fn t04j_session_store_bounded_and_swept() {
    let cfg = ClientApiConfig {
        session_store_cap: 3,
        ..ClientApiConfig::default()
    };
    let clock = Arc::new(TestClock::new(1_000_000));
    let (api, _) = build(cfg, clock.clone(), noop());

    // Many abandoned-token logins → the store stays capped.
    for _ in 0..12 {
        let _ = login_loopback(&api);
    }
    assert!(
        api.sessions().len() <= 3,
        "session store honors its cap (was {})",
        api.sessions().len()
    );

    // Advancing past the session TTL + one more login sweeps the expired sessions.
    clock.advance(9 * HOUR_MS);
    let _ = login_loopback(&api);
    assert!(api.sessions().len() <= 3);
}

// ── T04k: logout revokes by session id (closes the logout/refresh rotation race) ───────────
#[test]
fn t04k_revoke_session_kills_all_tokens() {
    use advance_client_api::session::{ClientSession, Platform, Principal, Scope, SessionStore};
    let store = SessionStore::new(100);
    let now = 1_000u64;
    let mk = |sid: &str| ClientSession {
        session_id: sid.into(),
        principal: Principal::operator("op"),
        platform: Platform::Mac,
        scopes: Scope::operator_default(),
        csrf_token: None,
        expires_at: now + 10_000,
    };
    // Two live tokens sharing one session id (models the validate→refresh-rotate→revoke window),
    // plus an unrelated session.
    store.insert("tokA".into(), mk("sess-X"), now);
    store.insert("tokB".into(), mk("sess-X"), now);
    store.insert("tokC".into(), mk("sess-Y"), now);

    store.revoke_session("sess-X");
    assert!(store.get_valid("tokA", now).is_err(), "tokA killed");
    assert!(
        store.get_valid("tokB", now).is_err(),
        "rotated tokB killed too"
    );
    assert!(
        store.get_valid("tokC", now).is_ok(),
        "unrelated session untouched"
    );
}

// ── T04i: bootstrap brute-force lockout ───────────────────────────────────────────────────
#[test]
fn t04i_bootstrap_lockout() {
    let cfg = ClientApiConfig {
        remote_bind_enabled: true,
        bootstrap_max_attempts: 5,
        ..ClientApiConfig::default()
    };
    let clock = Arc::new(TestClock::new(1_000_000));
    let (api, _) = build(cfg, clock.clone(), noop());

    let code = api.auth().mint_bootstrap_code(clock.now_millis());

    // 5 wrong guesses invalidate the code
    for _ in 0..5 {
        let r = api.handle(
            ClientRequest::post(
                "/client/session/login",
                json!({ "bootstrap_code": "00000000000000000000000000000000" }),
            )
            .with_loopback_peer(false),
        );
        assert_eq!(r.error_code(), Some(ClientErrorCode::InvalidBootstrapCode));
    }

    // even the correct code now fails (locked out)
    let locked = api.handle(
        ClientRequest::post("/client/session/login", json!({ "bootstrap_code": code }))
            .with_loopback_peer(false),
    );
    assert_eq!(
        locked.error_code(),
        Some(ClientErrorCode::InvalidBootstrapCode)
    );
}

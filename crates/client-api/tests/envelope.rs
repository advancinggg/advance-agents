//! MODULE-020-AC-01 (integration) — the versioned envelope + deterministic errors + cursor
//! pagination + reserve-before-execute idempotency + `unsupported_api_version` fail-closed.
//! (§3.3 MODULE-020-T01.)

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use serde_json::json;

use advance_client_api::api::{ClientApi, HandlerSpec};
use advance_client_api::audit::NoopSink;
use advance_client_api::clock::{Clock, TestClock};
use advance_client_api::config::ClientApiConfig;
use advance_client_api::envelope::{ClientError, ClientErrorCode, API_VERSION};
use advance_client_api::pagination::{clamp_limit, Cursor, MAX_LIMIT};
use advance_client_api::request::{ClientRequest, Method};

const HOUR_MS: u64 = 3_600_000;

/// Build an api on a test clock with a counting test-mutation handler at `/client/test/mutate`.
/// (Disclosed drive-prod-fn witness: no in-scope endpoint is idempotency-keyed yet — mutations
/// are provider families, Wave-24 — so the store is exercised through a test-injected handler.)
fn build(config: ClientApiConfig, clock: Arc<TestClock>) -> (ClientApi, Arc<AtomicUsize>) {
    let counter = Arc::new(AtomicUsize::new(0));
    let mut api = ClientApi::with_parts(
        config,
        "tester",
        clock as Arc<dyn Clock>,
        Arc::new(NoopSink),
    );
    let c = counter.clone();
    api.register(
        Method::Post,
        "/client/test/mutate",
        HandlerSpec::mutation(true, move |_ctx| {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(json!({ "mutated": true }))
        }),
    );
    (api, counter)
}

fn login(api: &ClientApi) -> String {
    let resp = api.handle(ClientRequest::post(
        "/client/session/login",
        json!({ "platform": "mac" }),
    ));
    assert!(
        resp.is_ok(),
        "login should succeed: {:?}",
        resp.error_code()
    );
    resp.data.unwrap()["token"].as_str().unwrap().to_string()
}

fn mutate(token: &str, key: &str) -> ClientRequest {
    ClientRequest::post("/client/test/mutate", json!({}))
        .with_session(token)
        .with_idempotency_key(key)
}

// ── T01a: envelope shape ──────────────────────────────────────────────────────────────────
#[test]
fn t01a_versioned_envelope_shape() {
    let (api, _) = build(
        ClientApiConfig::default(),
        Arc::new(TestClock::new(1_000_000)),
    );
    let resp = api.handle(ClientRequest::get("/client/health"));
    assert!(resp.is_ok());
    assert_eq!(resp.api_version, API_VERSION);
    assert!(!resp.request_id.is_empty());
    assert!(resp.data.is_some());
    assert!(resp.error.is_none());
    assert_eq!(resp.data.unwrap()["status"], "ok");
}

// ── T01b: data XOR error ──────────────────────────────────────────────────────────────────
#[test]
fn t01b_data_xor_error() {
    let (api, _) = build(ClientApiConfig::default(), Arc::new(TestClock::new(1)));
    let ok = api.handle(ClientRequest::get("/client/health"));
    assert!(ok.is_ok() && ok.error.is_none() && ok.data.is_some());

    let err = api.handle(ClientRequest::get("/client/does-not-exist"));
    assert!(err.is_err() && err.data.is_none() && err.error.is_some());
    assert_eq!(err.error_code(), Some(ClientErrorCode::UnknownRoute));
}

// ── T01c: idempotency replay (never re-executes; echoes original request_id) ───────────────
#[test]
fn t01c_idempotency_replay_not_reexecute() {
    let (api, counter) = build(
        ClientApiConfig::default(),
        Arc::new(TestClock::new(1_000_000)),
    );
    let token = login(&api);

    let r1 = api.handle(mutate(&token, "K1"));
    assert!(r1.is_ok());
    let original_request_id = r1.request_id.clone();

    let r2 = api.handle(mutate(&token, "K1"));
    assert!(r2.is_ok());
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "handler must run exactly once"
    );
    assert_eq!(
        r2.request_id, original_request_id,
        "replay returns the recorded outcome (original request_id)"
    );
    assert!(
        r2.warnings.iter().any(|w| w.code == "idempotent_replay"),
        "replay echoes original request_id in a warning"
    );
}

// ── T01d: idempotency scope isolation (different family re-executes) ───────────────────────
#[test]
fn t01d_idempotency_scope_isolation() {
    let (mut api, counter) = build(ClientApiConfig::default(), Arc::new(TestClock::new(1)));
    let c2 = counter.clone();
    api.register(
        Method::Post,
        "/client/test2/mutate",
        HandlerSpec::mutation(true, move |_ctx| {
            c2.fetch_add(1, Ordering::SeqCst);
            Ok(json!({ "mutated2": true }))
        }),
    );
    let token = login(&api);

    let a = api.handle(mutate(&token, "SAME"));
    let b = api.handle(
        ClientRequest::post("/client/test2/mutate", json!({}))
            .with_session(token.as_str())
            .with_idempotency_key("SAME"),
    );
    assert!(a.is_ok() && b.is_ok());
    assert_eq!(
        counter.load(Ordering::SeqCst),
        2,
        "same key, different family → both execute"
    );
}

// ── T01e: version fail-closed before any handler ──────────────────────────────────────────
#[test]
fn t01e_version_fail_closed() {
    let (api, counter) = build(ClientApiConfig::default(), Arc::new(TestClock::new(1)));
    let token = login(&api);

    let mut req = mutate(&token, "K");
    req.api_version = "1999-01-01".to_string();
    let resp = api.handle(req);
    assert_eq!(
        resp.error_code(),
        Some(ClientErrorCode::UnsupportedApiVersion)
    );
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "no handler runs on bad version"
    );
    // the supported range is disclosed in details
    assert!(resp.error.unwrap().details.iter().any(|d| d == API_VERSION));
}

// ── T01f: deterministic error codes ───────────────────────────────────────────────────────
#[test]
fn t01f_deterministic_error_codes() {
    assert_eq!(
        ClientErrorCode::UnsupportedApiVersion.as_str(),
        "unsupported_api_version"
    );
    assert_eq!(
        ClientErrorCode::IdempotencyRequired.as_str(),
        "idempotency_required"
    );
    assert_eq!(
        ClientErrorCode::IdempotencyConflict.as_str(),
        "idempotency_conflict"
    );
    assert_eq!(
        ClientErrorCode::IdempotencyCapacity.as_str(),
        "idempotency_capacity"
    );
    assert_eq!(ClientErrorCode::UnknownRoute.as_str(), "unknown_route");
    assert_eq!(
        ClientErrorCode::RemoteBindForbidden.as_str(),
        "remote_bind_forbidden"
    );
    // m020-s2 additive provider-family codes.
    assert_eq!(ClientErrorCode::NotFound.as_str(), "not_found");
    assert_eq!(
        ClientErrorCode::ReplyNotAuthorized.as_str(),
        "reply_not_authorized"
    );
    assert_eq!(ClientErrorCode::InvalidState.as_str(), "invalid_state");
    assert_eq!(ClientErrorCode::Forbidden.as_str(), "forbidden");
    // The known (server-producible) code set is a fixed compatibility surface: 17 foundation codes
    // (including conflict and durable-capacity rejection) + 4 provider-family codes = 21.
    assert_eq!(ClientErrorCode::known_codes().len(), 21);
}

#[test]
fn t01f2_same_key_different_request_conflicts_before_handler() {
    let (api, counter) = build(
        ClientApiConfig::default(),
        Arc::new(TestClock::new(1_000_000)),
    );
    let token = login(&api);

    let first = api.handle(
        ClientRequest::post("/client/test/mutate", json!({ "decision": "approve" }))
            .with_session(&token)
            .with_idempotency_key("shared"),
    );
    assert!(first.is_ok());

    let conflict = api.handle(
        ClientRequest::post("/client/test/mutate", json!({ "decision": "deny" }))
            .with_session(&token)
            .with_idempotency_key("shared"),
    );
    assert_eq!(
        conflict.error_code(),
        Some(ClientErrorCode::IdempotencyConflict)
    );
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "provider/handler not re-entered"
    );
}

// ── T01g: cursor pagination ───────────────────────────────────────────────────────────────
#[test]
fn t01g_cursor_pagination() {
    let cursor = Cursor::new(50, Some("last-id".to_string()));
    let token = cursor.encode();
    assert_eq!(Cursor::decode(&token), Some(cursor));

    // malformed cursor → None (no panic)
    assert_eq!(Cursor::decode("!!!not-base64!!!"), None);
    // over-long cursor → None (bounded decode)
    let long = "A".repeat(1000);
    assert_eq!(Cursor::decode(&long), None);

    assert_eq!(clamp_limit(None), 50);
    assert_eq!(clamp_limit(Some(0)), 1);
    assert_eq!(clamp_limit(Some(1_000_000)), MAX_LIMIT);
}

// ── T01h: idempotency TTL expiry ──────────────────────────────────────────────────────────
#[test]
fn t01h_idempotency_ttl_expiry() {
    let clock = Arc::new(TestClock::new(1_000_000));
    let (api, counter) = build(ClientApiConfig::default(), clock.clone());

    let token1 = login(&api);
    let r1 = api.handle(mutate(&token1, "K"));
    assert!(r1.is_ok());
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    // advance past the 24h idempotency TTL; re-login (session TTL is shorter, 8h)
    clock.advance(24 * HOUR_MS + 1);
    let token2 = login(&api);
    let r2 = api.handle(mutate(&token2, "K"));
    assert!(r2.is_ok());
    assert_eq!(
        counter.load(Ordering::SeqCst),
        2,
        "expired record re-executes"
    );
    assert!(
        !r2.warnings.iter().any(|w| w.code == "idempotent_replay"),
        "not a replay after TTL"
    );
}

// ── T01i: input bounds (body cap + store cap) ─────────────────────────────────────────────
#[test]
fn t01i_input_bounds() {
    // body cap
    let (api, _) = build(ClientApiConfig::default(), Arc::new(TestClock::new(1)));
    let big = json!({ "blob": "x".repeat(2 * 1024 * 1024) });
    let resp = api.handle(ClientRequest::post("/client/test/mutate", big));
    assert_eq!(resp.error_code(), Some(ClientErrorCode::RequestTooLarge));

    // store cap
    let cfg = ClientApiConfig {
        idempotency_store_cap: 5,
        ..ClientApiConfig::default()
    };
    let (api, _) = build(cfg, Arc::new(TestClock::new(1_000_000)));
    let token = login(&api);
    for i in 0..30 {
        let _ = api.handle(mutate(&token, &format!("key-{i}")));
    }
    assert!(
        api.idempotency().len() <= 5,
        "store honors its cap (was {})",
        api.idempotency().len()
    );
}

// ── T01j: idempotency concurrency (reserve-before-execute) ────────────────────────────────
#[test]
fn t01j_idempotency_concurrency_single_execution() {
    let (api, counter) = build(
        ClientApiConfig::default(),
        Arc::new(TestClock::new(1_000_000)),
    );
    let token = login(&api);
    let api = Arc::new(api);

    let mut handles = Vec::new();
    for _ in 0..8 {
        let api = api.clone();
        let token = token.clone();
        handles.push(std::thread::spawn(move || {
            api.handle(mutate(&token, "CONC"));
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "concurrent same-key mutations execute the handler exactly once"
    );
}

// ── T01k: missing idempotency key → idempotency_required before handler ────────────────────
#[test]
fn t01k_missing_idempotency_key() {
    let (api, counter) = build(ClientApiConfig::default(), Arc::new(TestClock::new(1)));
    let token = login(&api);
    let resp =
        api.handle(ClientRequest::post("/client/test/mutate", json!({})).with_session(&token));
    assert_eq!(
        resp.error_code(),
        Some(ClientErrorCode::IdempotencyRequired)
    );
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "no handler on missing key"
    );
}

// ── T01l: reservation release on failure (no 24h wedge) ───────────────────────────────────
#[test]
fn t01l_reservation_release_on_failure() {
    let (mut api, _) = build(ClientApiConfig::default(), Arc::new(TestClock::new(1)));
    let fail_counter = Arc::new(AtomicUsize::new(0));
    let fc = fail_counter.clone();
    api.register(
        Method::Post,
        "/client/test/fail",
        HandlerSpec::mutation(true, move |_ctx| {
            fc.fetch_add(1, Ordering::SeqCst);
            Err(ClientError::new(ClientErrorCode::ModuleUnavailable, "boom"))
        }),
    );
    let token = login(&api);
    let fail = || {
        ClientRequest::post("/client/test/fail", json!({}))
            .with_session(token.as_str())
            .with_idempotency_key("F")
    };

    let r1 = api.handle(fail());
    assert_eq!(r1.error_code(), Some(ClientErrorCode::ModuleUnavailable));
    // The key must NOT be wedged — an immediate retry executes again (reservation released).
    let r2 = api.handle(fail());
    assert_eq!(r2.error_code(), Some(ClientErrorCode::ModuleUnavailable));
    assert_eq!(
        fail_counter.load(Ordering::SeqCst),
        2,
        "failed key is retryable, not wedged"
    );
}

// ── T01m: cap eviction never evicts a live Pending (audit round-4 fix) ─────────────────────
#[test]
fn t01m_cap_eviction_preserves_live_pending() {
    use advance_client_api::idempotency::{Begin, IdempotencyScope, IdempotencyStore};
    let store = IdempotencyStore::new(24 * HOUR_MS, 1); // cap == 1
    let now = 1_000_000;
    let scope = |k: &str| IdempotencyScope {
        principal: "p".into(),
        method: Method::Post,
        family: "f".into(),
        key: k.into(),
    };

    // Reserve A and hold the guard live.
    let _guard_a = match store.begin(&scope("A"), now) {
        Begin::Reserved(g) => g,
        _ => panic!("A should reserve"),
    };
    // Fill the cap with a committed distinct-key record B (cap pressure).
    match store.begin(&scope("B"), now) {
        Begin::Reserved(g) => g.commit(json!({}), "req_b".into(), now),
        _ => panic!("B should reserve"),
    };
    // A retry of A must see the LIVE pending (InProgress) — its reservation was NOT cap-evicted,
    // so no double-execute is possible.
    assert!(
        matches!(store.begin(&scope("A"), now), Begin::InProgress),
        "a live Pending must survive cap pressure"
    );
}

// ── T01n: a live Pending is released ONLY by its guard (no age-reclaim → exactly-once) ─────
#[test]
fn t01n_pending_released_only_by_guard() {
    use advance_client_api::idempotency::{Begin, IdempotencyScope, IdempotencyStore};
    let store = IdempotencyStore::new(24 * HOUR_MS, 100);
    let now = 1_000_000;
    let scope = IdempotencyScope {
        principal: "p".into(),
        method: Method::Post,
        family: "f".into(),
        key: "K".into(),
    };

    let guard = match store.begin(&scope, now) {
        Begin::Reserved(g) => g,
        _ => panic!("first reserve"),
    };
    // A live Pending is InProgress no matter how much time passes — it is NEVER age-reclaimed, so
    // a concurrent retry of an in-flight operation can never slip through to a second execution.
    assert!(
        matches!(
            store.begin(&scope, now + 1_000 * HOUR_MS),
            Begin::InProgress
        ),
        "a live Pending is never age-reclaimed"
    );
    // The guard's Drop is the sole release; after it, the scope is reservable again.
    drop(guard);
    assert!(
        matches!(store.begin(&scope, now), Begin::Reserved(_)),
        "guard Drop releases the reservation"
    );
}

// ── T01o: cap is restored after a live-Pending overflow commits (audit round-6 fix) ────────
#[test]
fn t01o_cap_restored_after_commit_burst() {
    use advance_client_api::idempotency::{Begin, IdempotencyScope, IdempotencyStore};
    let store = IdempotencyStore::new(24 * HOUR_MS, 2); // cap == 2
    let now = 1_000_000;
    let scope = |k: String| IdempotencyScope {
        principal: "p".into(),
        method: Method::Post,
        family: "f".into(),
        key: k,
    };

    // Reserve 5 live Pending (over cap — allowed only for live reservations).
    let guards: Vec<_> = (0..5)
        .map(|i| match store.begin(&scope(format!("k{i}")), now) {
            Begin::Reserved(g) => g,
            _ => panic!("reserve k{i}"),
        })
        .collect();
    assert_eq!(store.len(), 5, "live Pending may exceed cap");

    // Commit them all → each commit trims old Done back toward cap.
    for (i, g) in guards.into_iter().enumerate() {
        g.commit(json!({}), format!("r{i}"), now);
    }
    assert!(
        store.len() <= 2,
        "cap restored after the commit burst (was {})",
        store.len()
    );
    // The most-recently committed record survived its own commit's cap-trim (no self-evict) — a
    // sequential retry replays it rather than re-executing.
    match store.begin(&scope("k4".to_string()), now) {
        Begin::Replay(rec) => assert_eq!(rec.original_request_id, "r4"),
        _ => panic!("the just-committed record must survive its own commit trim"),
    }
}

// ── T01p: over-long idempotency key rejected before the handler ────────────────────────────
#[test]
fn t01p_idempotency_key_length_bound() {
    let (api, counter) = build(
        ClientApiConfig::default(),
        Arc::new(TestClock::new(1_000_000)),
    );
    let token = login(&api);
    let long_key = "k".repeat(1000); // > 256 default
    let resp = api.handle(mutate(&token, &long_key));
    assert_eq!(resp.error_code(), Some(ClientErrorCode::RequestTooLarge));
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "over-long key rejected before the handler"
    );
}

// ── T01q: over-long request path rejected at the front of the pipeline ─────────────────────
#[test]
fn t01q_path_length_bound() {
    let (api, _) = build(ClientApiConfig::default(), Arc::new(TestClock::new(1)));
    let long_path = format!("/client/{}", "x".repeat(1000)); // > 512 default
    let resp = api.handle(ClientRequest::get(long_path));
    assert_eq!(resp.error_code(), Some(ClientErrorCode::RequestTooLarge));
}

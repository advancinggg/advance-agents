//! MODULE-001-T112 (a) — gate chain, budgets, services, registrar refusals,
//! and the route-containment legs of (e).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use advance_client_api::families::{oss_route_table, ResponseScan};
use advance_client_api::{
    ClientErrorCode, ClientRequest, Method, RouteTableEntry, Scope, CLIENT_WS_PROTOCOL,
};
use advance_runtime_compose::test_support::fixture::inference::DropFlag;
use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, mint_session, mint_session_with, CapDecl, FixtureDriver,
    FixtureExtension, FixtureFamilies, FixtureHome, FixtureHomeSpec, FixtureInference, Http,
    HttpResponse, RouteRuleBreak, FIXTURE_ID, FIXTURE_TWO_ID,
};
use advance_runtime_compose::test_support::{ComposeProbe, MemoryComposeLog, TEARDOWN_ORDER};
use advance_runtime_compose::{
    compose, log_keys, ComposeError, DuplicateOf, FamilyBudget, PathDefect, RouteRefusalReason,
};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{ORIGIN, SEC_WEBSOCKET_PROTOCOL};
use tokio_tungstenite::tungstenite::Message;

const POLL: Duration = Duration::from_millis(10);
const WAIT: Duration = Duration::from_secs(5);
const BEARER_NOTE: &str = "Bearer eyJhbGciOiJIUzI1NiJ9.fixture";
const AWS_NOTE: &str = "key AKIAABCDEFGHIJKLMNOP";
const OPT_OUT_RAW: &str = "fixture: raw echo for the scan opt-out witness";
const OPT_OUT_CURSOR: &str = "fixture: returns an opaque extension cursor";

type WsClient = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

fn home(caps: &'static [&'static str], git: bool) -> FixtureHome {
    FixtureHome::new(FixtureHomeSpec {
        capabilities: caps.iter().copied().map(CapDecl::Granted).collect(),
        driver: FixtureDriver::None,
        git,
        providers_yaml: None,
    })
    .expect("home")
}

fn subsequence(haystack: &[&str], needle: &[&str]) -> bool {
    let mut rest = haystack;
    for wanted in needle {
        match rest.iter().position(|got| got == wanted) {
            Some(index) => rest = &rest[index + 1..],
            None => return false,
        }
    }
    true
}

fn names(rec: &advance_runtime_compose::test_support::ProbeRecord) -> Vec<&'static str> {
    rec.teardown_steps.iter().map(|(n, _)| *n).collect()
}

fn error_code(body: &Value) -> &str {
    body.pointer("/error/code")
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn error_message(body: &Value) -> &str {
    body.pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn details(body: &Value) -> Vec<&str> {
    body.pointer("/error/details")
        .and_then(Value::as_array)
        .map(|entries| entries.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn has_data(body: &Value) -> bool {
    !body.get("data").is_none_or(Value::is_null)
}

fn triple(resp: &HttpResponse) -> (u16, String, String) {
    (
        resp.status,
        error_code(&resp.body).to_owned(),
        error_message(&resp.body).to_owned(),
    )
}

fn warnings(body: &Value) -> Vec<&Value> {
    body.get("warnings")
        .and_then(Value::as_array)
        .map(|entries| entries.iter().collect())
        .unwrap_or_default()
}

fn warning_codes(body: &Value) -> Vec<&str> {
    warnings(body)
        .into_iter()
        .filter_map(|warning| warning.get("code").and_then(Value::as_str))
        .collect()
}

fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn query(path: &str, pairs: &[(&str, &str)]) -> String {
    let mut out = String::from(path);
    out.push('?');
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(k);
        out.push('=');
        out.push_str(&enc(v));
    }
    out
}

fn find_route<'a>(table: &'a [RouteTableEntry], method: Method, path: &str) -> &'a RouteTableEntry {
    table
        .iter()
        .find(|row| row.method == method && row.path == path)
        .unwrap_or_else(|| panic!("missing {method:?} {path} in {table:?}"))
}

fn assert_known_code(code: &str) {
    let parsed: ClientErrorCode = serde_json::from_value(json!(code)).expect(code);
    assert_ne!(parsed, ClientErrorCode::Unknown, "{code}");
    assert!(
        ClientErrorCode::known_codes().contains(&code),
        "{code} not in known_codes"
    );
}

async fn oss_twin(resp: HttpResponse) -> (u16, String, String) {
    triple(&resp)
}

async fn delta_ws(addr: SocketAddr, token: &str) -> WsClient {
    let mut request = format!("ws://{addr}/client/llm/deltas/stream")
        .into_client_request()
        .expect("WebSocket request");
    request.headers_mut().insert(
        SEC_WEBSOCKET_PROTOCOL,
        format!("{CLIENT_WS_PROTOCOL}, advance.bearer.{token}")
            .parse()
            .expect("protocol header"),
    );
    request.headers_mut().insert(
        ORIGIN,
        format!("http://{addr}").parse().expect("origin header"),
    );
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect the Client API");
    let (mut ws, _) = tokio_tungstenite::client_async(request, tcp)
        .await
        .expect("WebSocket handshake");
    let seed = next_text(&mut ws).await;
    let envelope: Value = serde_json::from_str(&seed).expect("seed json");
    assert_eq!(
        envelope.pointer("/data/subscribed"),
        Some(&Value::Bool(true)),
        "{envelope}"
    );
    ws
}

async fn next_text(ws: &mut WsClient) -> String {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(text))) => return text.to_string(),
                Some(Ok(Message::Ping(payload))) => {
                    let _ = ws.send(Message::Pong(payload)).await;
                }
                other => panic!("unexpected frame: {other:?}"),
            }
        }
    })
    .await
    .expect("text frame")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112_a_fixture_routes_run_the_gate_chain_and_wrapper() {
    let home = home(&["fs", "llm", "lifecycle"], false);
    let families = FixtureFamilies::standard();
    let control = families.control();
    let ext = FixtureExtension::new(FIXTURE_ID).with_families(families);
    let rec = ext.record();
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log.clone()), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    let ep = rt.client_api().expect("client api");
    let addr = ep.socket_addr;
    let origin = ep.base_url.clone();
    let mut codes: Vec<String> = Vec::new();

    {
        let api = ep.api.upgrade().expect("client api alive");
        let table = api.route_table();
        let create = find_route(&table, Method::Post, "/client/fixture/items:create");
        assert!(create.requires_session);
        assert!(create.is_mutation);
        assert!(!create.templated);
        assert_eq!(create.required_scopes, vec![Scope::WriteEntities]);
        let item = find_route(&table, Method::Get, "/client/fixture/items/{item_id}");
        assert!(item.templated);
        assert!(item.requires_session);
        assert!(!item.is_mutation);
        assert_eq!(item.required_scopes, vec![Scope::ReadInventory]);
        for path in [
            "/client/fixture/status",
            "/client/fixture/items",
            "/client/fixture/leak",
            "/client/fixture/leak-raw",
            "/client/fixture/error",
            "/client/fixture/error-unknown",
            "/client/fixture/panic",
            "/client/fixture/slow",
            "/client/fixture/cursor",
            "/client/fixture/cursor:open",
            "/client/fixture/clock",
            "/client/fixture/slot",
        ] {
            let row = find_route(&table, Method::Get, path);
            assert!(row.requires_session, "{path}");
            assert!(!row.templated, "{path}");
        }
        let search = find_route(&table, Method::Post, "/client/fixture/items:search");
        assert!(search.requires_session);
        assert!(!search.is_mutation);
        for oss in oss_route_table() {
            assert!(
                table.iter().any(|row| row == &oss),
                "OSS route missing: {} {:?}",
                oss.path,
                oss.method
            );
        }
        let report = api.extension_route_report();
        let opt_out = |path: &str, reason: &str| {
            report.iter().any(|info| {
                info.path == path
                    && matches!(info.response_scan, ResponseScan::OptOut { reason: r } if r == reason)
            })
        };
        assert!(
            opt_out("/client/fixture/leak-raw", OPT_OUT_RAW),
            "{report:?}"
        );
        assert!(
            opt_out("/client/fixture/cursor", OPT_OUT_CURSOR),
            "{report:?}"
        );
        assert!(
            opt_out("/client/fixture/cursor:open", OPT_OUT_CURSOR),
            "{report:?}"
        );
    }
    assert_eq!(log.count(log_keys::EXT_ROUTE_SCAN_OPT_OUT), 3);
    let family_calls: Vec<_> = rec
        .calls()
        .into_iter()
        .filter(|call| call.phase == "client_families")
        .collect();
    assert_eq!(family_calls.len(), 1, "{family_calls:?}");
    assert!(!family_calls[0].discovery_present);
    assert!(home.home().join(".runtime/client-api").exists());

    let none_status = Http::get(addr, "/client/fixture/status").send().await;
    let none_item = Http::get(addr, "/client/fixture/items/a1").send().await;
    let none_create = Http::post(addr, "/client/fixture/items:create")
        .idempotency_key("k-0")
        .json(json!({}))
        .await;
    let oss_none = oss_twin(Http::get(addr, "/client/runs").send().await).await;
    for resp in [&none_status, &none_item, &none_create] {
        assert_eq!(triple(resp), oss_none, "{:?}", resp.body);
        assert_eq!(resp.status, 401);
        assert_eq!(error_code(&resp.body), "unauthenticated");
        assert_eq!(error_message(&resp.body), "missing session");
        codes.push(error_code(&resp.body).to_owned());
    }

    let tok_r = mint_session_with(&ep, vec![Scope::ReadRuns], None);
    let low_status = Http::get(addr, "/client/fixture/status")
        .session(&tok_r)
        .send()
        .await;
    let low_item = Http::get(addr, "/client/fixture/items/a1")
        .session(&tok_r)
        .send()
        .await;
    let low_create = Http::post(addr, "/client/fixture/items:create")
        .session(&tok_r)
        .idempotency_key("k-low")
        .json(json!({}))
        .await;
    let oss_low = oss_twin(
        Http::get(addr, "/client/tools")
            .session(&tok_r)
            .send()
            .await,
    )
    .await;
    for resp in [&low_status, &low_item, &low_create] {
        assert_eq!(triple(resp), oss_low, "{:?}", resp.body);
        assert_eq!(resp.status, 403);
        assert_eq!(error_code(&resp.body), "forbidden");
        assert_eq!(error_message(&resp.body), "insufficient scope");
        codes.push(error_code(&resp.body).to_owned());
    }

    let tok = mint_session_with(&ep, Scope::operator_default(), Some("csrf-fixture"));
    let no_key = Http::post(addr, "/client/fixture/items:create")
        .session(&tok)
        .json(json!({}))
        .await;
    let oss_no_key = oss_twin(
        Http::post(addr, "/client/messages")
            .session(&tok)
            .json(json!({"to": "agent:root", "payload": "x"}))
            .await,
    )
    .await;
    assert_eq!(triple(&no_key), oss_no_key, "{:?}", no_key.body);
    assert_eq!(no_key.status, 400);
    assert_eq!(error_code(&no_key.body), "idempotency_required");
    assert_eq!(error_message(&no_key.body), "missing idempotency key");
    codes.push(error_code(&no_key.body).to_owned());

    let no_csrf = Http::post(addr, "/client/fixture/items:create")
        .session(&tok)
        .origin(&origin)
        .idempotency_key("k-1")
        .json(json!({}))
        .await;
    let oss_no_csrf = oss_twin(
        Http::post(addr, "/client/messages")
            .session(&tok)
            .origin(&origin)
            .idempotency_key("k-1")
            .json(json!({"to": "agent:root", "payload": "x"}))
            .await,
    )
    .await;
    assert_eq!(triple(&no_csrf), oss_no_csrf, "{:?}", no_csrf.body);
    assert_eq!(no_csrf.status, 403);
    assert_eq!(error_code(&no_csrf.body), "csrf_required");
    assert_eq!(error_message(&no_csrf.body), "csrf");
    codes.push(error_code(&no_csrf.body).to_owned());

    let created = Http::post(addr, "/client/fixture/items:create")
        .session(&tok)
        .origin(&origin)
        .csrf("csrf-fixture")
        .idempotency_key("k-1")
        .json(json!({"name": "n"}))
        .await;
    assert_eq!(created.status, 200, "{:?}", created.body);
    assert_eq!(created.body["data"]["created"], json!(1));
    let replay = Http::post(addr, "/client/fixture/items:create")
        .session(&tok)
        .origin(&origin)
        .csrf("csrf-fixture")
        .idempotency_key("k-1")
        .json(json!({"name": "n"}))
        .await;
    assert_eq!(replay.status, 200, "{:?}", replay.body);
    assert_eq!(replay.body["data"]["created"], json!(1));
    assert!(
        warning_codes(&replay.body).contains(&"idempotent_replay"),
        "{:?}",
        replay.body
    );
    assert_eq!(control.created(), 1);
    let search = Http::post(addr, "/client/fixture/items:search")
        .session(&tok)
        .origin(&origin)
        .json(json!({}))
        .await;
    assert_eq!(search.status, 200, "{:?}", search.body);
    assert_eq!(search.body["data"], json!({"matches": []}));
    let status_origin = Http::get(addr, "/client/fixture/status")
        .session(&tok)
        .origin(&origin)
        .send()
        .await;
    assert_eq!(status_origin.status, 200, "{:?}", status_origin.body);
    for resp in [&created, &replay, &search, &status_origin] {
        if let Some(code) = resp.body.pointer("/error/code").and_then(Value::as_str) {
            codes.push(code.to_owned());
        }
    }

    let err = Http::get(addr, "/client/fixture/error")
        .session(&tok)
        .send()
        .await;
    assert_eq!(err.status, 404, "{:?}", err.body);
    assert_eq!(error_code(&err.body), "not_found");
    assert_eq!(error_message(&err.body), "resource not found");
    assert_eq!(details(&err.body), ["fixture_missing"]);
    assert_eq!(log.count(log_keys::EXT_ROUTE_DETAILS_DROPPED), 1);
    let unknown = Http::get(addr, "/client/fixture/error-unknown")
        .session(&tok)
        .send()
        .await;
    assert_eq!(unknown.status, 503, "{:?}", unknown.body);
    assert_eq!(error_code(&unknown.body), "module_unavailable");
    assert_eq!(error_message(&unknown.body), "provider unavailable");
    assert_eq!(log.count(log_keys::EXT_ROUTE_CODE_REMAPPED), 1);
    let slot = Http::get(addr, "/client/fixture/slot")
        .session(&tok)
        .send()
        .await;
    assert_eq!(slot.status, 503, "{:?}", slot.body);
    assert_eq!(error_code(&slot.body), "module_unavailable");
    assert_eq!(error_message(&slot.body), "provider unavailable");
    assert_ne!(error_message(&slot.body), "provider not wired");
    codes.push(error_code(&err.body).to_owned());
    codes.push(error_code(&unknown.body).to_owned());
    codes.push(error_code(&slot.body).to_owned());

    control.set_note(BEARER_NOTE);
    let leak = Http::get(addr, "/client/fixture/leak")
        .session(&tok)
        .send()
        .await;
    assert_eq!(leak.status, 200, "{:?}", leak.body);
    let note = leak.body["data"]["note"].as_str().unwrap_or("");
    assert_ne!(note, BEARER_NOTE);
    assert!(note.contains("[REDACTED]"), "{note}");
    assert!(
        warnings(&leak.body).iter().any(|warning| {
            warning.get("code").and_then(Value::as_str) == Some("sensitive_value_redacted")
                && warning.get("message").and_then(Value::as_str)
                    == Some("sensitive value redacted at /note")
        }),
        "{:?}",
        leak.body
    );
    control.set_note(AWS_NOTE);
    let blocked = Http::get(addr, "/client/fixture/leak")
        .session(&tok)
        .send()
        .await;
    assert_eq!(blocked.status, 422, "{:?}", blocked.body);
    assert_eq!(error_code(&blocked.body), "projection_rejected");
    assert_eq!(error_message(&blocked.body), "client projection rejected");
    control.set_note(BEARER_NOTE);
    let raw = Http::get(addr, "/client/fixture/leak-raw")
        .session(&tok)
        .send()
        .await;
    assert_eq!(raw.status, 200, "{:?}", raw.body);
    assert_eq!(raw.body["data"]["note"], json!(BEARER_NOTE));
    assert!(
        warning_codes(&raw.body)
            .iter()
            .all(|code| !code.starts_with("sensitive_")),
        "{:?}",
        raw.body
    );
    if let Some(code) = leak.body.pointer("/error/code").and_then(Value::as_str) {
        codes.push(code.to_owned());
    }
    codes.push(error_code(&blocked.body).to_owned());
    if let Some(code) = raw.body.pointer("/error/code").and_then(Value::as_str) {
        codes.push(code.to_owned());
    }

    let seed = Http::get(addr, "/client/events/stream?limit=0")
        .session(&tok)
        .send()
        .await;
    assert_eq!(seed.status, 200, "{:?}", seed.body);
    let sid = seed.body["data"]["cursor"]["stream_id"]
        .as_str()
        .unwrap_or_else(|| panic!("stream_id: {:?}", seed.body))
        .to_owned();
    let t_oss = seed.body["data"]["cursor"]["last_event_id"]
        .as_str()
        .unwrap_or_else(|| panic!("last_event_id: {:?}", seed.body))
        .to_owned();
    let sealed = Http::get(
        addr,
        query(
            "/client/fixture/cursor",
            &[("stream_id", &sid), ("raw_id", "r1")],
        ),
    )
    .session(&tok)
    .send()
    .await;
    assert_eq!(sealed.status, 200, "{:?}", sealed.body);
    let t_ext = sealed.body["data"]["cursor"]
        .as_str()
        .unwrap_or_else(|| panic!("cursor: {:?}", sealed.body))
        .to_owned();
    let bad_events = Http::get(
        addr,
        query(
            "/client/events/stream",
            &[
                ("stream_id", &sid),
                ("last_event_id", &t_ext),
                ("limit", "10"),
            ],
        ),
    )
    .session(&tok)
    .send()
    .await;
    assert_eq!(bad_events.status, 404, "{:?}", bad_events.body);
    assert_eq!(error_code(&bad_events.body), "not_found");
    let good_events = Http::get(
        addr,
        query(
            "/client/events/stream",
            &[
                ("stream_id", &sid),
                ("last_event_id", &t_oss),
                ("limit", "10"),
            ],
        ),
    )
    .session(&tok)
    .send()
    .await;
    assert_eq!(good_events.status, 200, "{:?}", good_events.body);
    let sealed2 = Http::get(
        addr,
        query(
            "/client/fixture/cursor",
            &[("stream_id", "llm-deltas"), ("raw_id", "r2")],
        ),
    )
    .session(&tok)
    .send()
    .await;
    let t_ext2 = sealed2.body["data"]["cursor"]
        .as_str()
        .unwrap_or_else(|| panic!("cursor2: {:?}", sealed2.body))
        .to_owned();
    let mut ws = delta_ws(addr, &tok).await;
    ws.send(Message::Text(
        json!({"stream_key": "fixture-probe", "from_cursor": t_ext2})
            .to_string()
            .into(),
    ))
    .await
    .expect("bad cursor frame");
    let delta_err: Value = serde_json::from_str(&next_text(&mut ws).await).expect("delta json");
    assert_eq!(
        delta_err.pointer("/error/code").and_then(Value::as_str),
        Some("not_found"),
        "{delta_err}"
    );
    ws.send(Message::Text(
        json!({"stream_key": "fixture-probe"}).to_string().into(),
    ))
    .await
    .expect("accepted subscribe");
    let open_oss = Http::get(
        addr,
        query(
            "/client/fixture/cursor:open",
            &[("stream_id", &sid), ("token", &t_oss)],
        ),
    )
    .session(&tok)
    .send()
    .await;
    assert_eq!(open_oss.status, 404, "{:?}", open_oss.body);
    assert_eq!(error_code(&open_oss.body), "not_found");
    assert_eq!(error_message(&open_oss.body), "resource not found");
    let open_ext = Http::get(
        addr,
        query(
            "/client/fixture/cursor:open",
            &[("stream_id", &sid), ("token", &t_ext)],
        ),
    )
    .session(&tok)
    .send()
    .await;
    assert_eq!(open_ext.status, 200, "{:?}", open_ext.body);
    assert_eq!(open_ext.body["data"], json!({"raw_id": "r1"}));
    for resp in [
        &seed,
        &sealed,
        &bad_events,
        &good_events,
        &sealed2,
        &open_oss,
        &open_ext,
    ] {
        if let Some(code) = resp.body.pointer("/error/code").and_then(Value::as_str) {
            codes.push(code.to_owned());
        }
    }

    for code in &codes {
        assert_known_code(code);
    }

    drop(ws);
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112_a_extension_budgets_isolate_oss() {
    let home = home(&["fs", "llm"], false);
    let families = FixtureFamilies::standard().with_budget(FamilyBudget::new(2, 4));
    let control = families.control();
    let ext = FixtureExtension::new(FIXTURE_ID).with_families(families);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    let ep = rt.client_api().expect("client api");
    let addr = ep.socket_addr;
    let tok = mint_session(&ep);

    let oss_set = Http::post(addr, "/client/secrets:set-mode")
        .session(&tok)
        .idempotency_key("oss-1")
        .json(json!({"mode": "file"}))
        .await;
    assert_eq!(oss_set.status, 200, "{:?}", oss_set.body);
    let n0 = {
        let api = ep.api.upgrade().expect("client api alive");
        api.idempotency().len()
    };

    let tok_a = tok.clone();
    let tok_b = tok.clone();
    let slow_a = tokio::spawn(async move {
        Http::get(addr, "/client/fixture/slow")
            .session(tok_a)
            .send()
            .await
    });
    let slow_b = tokio::spawn(async move {
        Http::get(addr, "/client/fixture/slow")
            .session(tok_b)
            .send()
            .await
    });
    let deadline = Instant::now() + WAIT;
    loop {
        if control.holding() == 2 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "slow route did not hold two callers: {}",
            control.holding()
        );
        tokio::time::sleep(POLL).await;
    }
    {
        let api = ep.api.upgrade().expect("client api alive");
        let stats = api.extension_budget_stats();
        assert_eq!(stats[0].dispatch_available, 0, "{stats:?}");
    }
    let saturated = Http::get(addr, "/client/fixture/status")
        .session(&tok)
        .send()
        .await;
    assert_eq!(saturated.status, 503, "{:?}", saturated.body);
    assert_eq!(error_code(&saturated.body), "module_unavailable");
    assert_eq!(
        error_message(&saturated.body),
        "server at dispatch capacity"
    );
    let health = Http::get(addr, "/client/health").send().await;
    assert_eq!(health.status, 200, "{:?}", health.body);
    let runs = Http::get(addr, "/client/runs").session(&tok).send().await;
    assert_eq!(runs.status, 200, "{:?}", runs.body);
    assert!(has_data(&runs.body), "{:?}", runs.body);
    control.release_slow_route();
    let held_a = slow_a.await.expect("slow a");
    let held_b = slow_b.await.expect("slow b");
    for held in [&held_a, &held_b] {
        assert_eq!(held.status, 200, "{:?}", held.body);
        assert_eq!(held.body["data"], json!({"held": true}));
    }

    for i in 1..=6 {
        if i > 1 {
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        let created = Http::post(addr, "/client/fixture/items:create")
            .session(&tok)
            .idempotency_key(format!("e{i}"))
            .json(json!({"name": i}))
            .await;
        assert_eq!(created.status, 200, "e{i}: {:?}", created.body);
        assert_eq!(created.body["data"]["created"], json!(i));
    }
    {
        let api = ep.api.upgrade().expect("client api alive");
        let stats = api.extension_budget_stats();
        assert_eq!(stats[0].idempotency_records, 4, "{stats:?}");
        assert_eq!(api.idempotency().len(), n0);
    }
    let replay_e6 = Http::post(addr, "/client/fixture/items:create")
        .session(&tok)
        .idempotency_key("e6")
        .json(json!({"name": 6}))
        .await;
    assert!(
        warning_codes(&replay_e6.body).contains(&"idempotent_replay"),
        "{:?}",
        replay_e6.body
    );
    assert_eq!(replay_e6.body["data"]["created"], json!(6));
    let replay_e1 = Http::post(addr, "/client/fixture/items:create")
        .session(&tok)
        .idempotency_key("e1")
        .json(json!({"name": 1}))
        .await;
    assert!(
        !warning_codes(&replay_e1.body).contains(&"idempotent_replay"),
        "{:?}",
        replay_e1.body
    );
    assert_eq!(replay_e1.body["data"]["created"], json!(7));
    let replay_oss = Http::post(addr, "/client/secrets:set-mode")
        .session(&tok)
        .idempotency_key("oss-1")
        .json(json!({"mode": "file"}))
        .await;
    assert!(
        warning_codes(&replay_oss.body).contains(&"idempotent_replay"),
        "{:?}",
        replay_oss.body
    );

    drop(ep);
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

fn expect_refusal(brk: RouteRuleBreak) -> (&'static str, String, RouteRefusalReason) {
    match brk {
        RouteRuleBreak::EmptySegment => (
            "fixture",
            "GET /client/fixture//x".into(),
            RouteRefusalReason::InvalidPath(PathDefect::EmptySegment { index: 1 }),
        ),
        RouteRuleBreak::Dot => (
            "fixture",
            "GET /client/fixture/./x".into(),
            RouteRefusalReason::InvalidPath(PathDefect::DotSegment { index: 1 }),
        ),
        RouteRuleBreak::DotDot => (
            "fixture",
            "GET /client/fixture/../x".into(),
            RouteRefusalReason::InvalidPath(PathDefect::DotSegment { index: 1 }),
        ),
        RouteRuleBreak::Percent => (
            "fixture",
            "GET /client/fixture/%2e".into(),
            RouteRefusalReason::InvalidPath(PathDefect::PercentSegment { index: 1 }),
        ),
        RouteRuleBreak::Uppercase => (
            "fixture",
            "GET /client/fixture/Items".into(),
            RouteRefusalReason::InvalidPath(PathDefect::InvalidSegment { index: 1 }),
        ),
        RouteRuleBreak::TooLong => (
            "fixture",
            format!("GET /client/fixture/{}", "a".repeat(512)),
            RouteRefusalReason::InvalidPath(PathDefect::TooLong { len: 528, max: 512 }),
        ),
        RouteRuleBreak::LabelRoot => (
            "fixture",
            "GET /client/root/x".into(),
            RouteRefusalReason::ReservedLabel {
                label: "root".into(),
            },
        ),
        RouteRuleBreak::LabelStaticFloor => (
            "fixture",
            "GET /client/session/x".into(),
            RouteRefusalReason::ReservedLabel {
                label: "session".into(),
            },
        ),
        RouteRuleBreak::LabelLiveOss => (
            "fixture",
            "GET /client/runs/x".into(),
            RouteRefusalReason::ReservedLabel {
                label: "runs".into(),
            },
        ),
        RouteRuleBreak::StreamPath => (
            "fixture",
            "GET /client/events/stream".into(),
            RouteRefusalReason::ReservedPath,
        ),
        RouteRuleBreak::LabelOwnedByEarlier => (
            "fixture-two",
            "GET /client/fixture/b".into(),
            RouteRefusalReason::LabelOwnedByOtherExtension {
                label: "fixture".into(),
                owner: "fixture",
            },
        ),
        RouteRuleBreak::ParamFirstSegment => (
            "fixture",
            "GET /client/{x}/y".into(),
            RouteRefusalReason::ParameterisedFirstSegment,
        ),
        // The two duplicate-by-shape rows against OSS and against another extension answer the
        // label rule: every OSS label is reserved and every other extension's label is owned, and
        // that rule runs before the shape rule. The shape rule on its own is witnessed with the
        // label rules relaxed (client-api's `module_001_ac31_duplicate_shape_against_*_isolated`).
        RouteRuleBreak::DuplicateShapeOss => (
            "fixture",
            "GET /client/runs/{other}/history".into(),
            RouteRefusalReason::ReservedLabel {
                label: "runs".into(),
            },
        ),
        RouteRuleBreak::DuplicateShapeOtherExtension => (
            "fixture-two",
            "GET /client/fixture/items/{name}".into(),
            RouteRefusalReason::LabelOwnedByOtherExtension {
                label: "fixture".into(),
                owner: "fixture",
            },
        ),
        RouteRuleBreak::DuplicateShapeSameExtension => (
            "fixture",
            "GET /client/fixture/items/{id}".into(),
            RouteRefusalReason::DuplicateRoute {
                shape: "/client/fixture/items/{}".into(),
                of: DuplicateOf::Extension("fixture"),
            },
        ),
        RouteRuleBreak::PostRegisteredAsRead => (
            "fixture",
            "POST /client/fixture/x".into(),
            RouteRefusalReason::PostNotMutationOrPostRead,
        ),
        RouteRuleBreak::GetMutation => (
            "fixture",
            "GET /client/fixture/x".into(),
            RouteRefusalReason::GetMutation,
        ),
        RouteRuleBreak::NoSession => (
            "fixture",
            "GET /client/fixture/x".into(),
            RouteRefusalReason::NoSession,
        ),
        RouteRuleBreak::NoScope => (
            "fixture",
            "GET /client/fixture/x".into(),
            RouteRefusalReason::NoScope,
        ),
        RouteRuleBreak::MutationReadScopeOnly => (
            "fixture",
            "POST /client/fixture/x".into(),
            RouteRefusalReason::MutationWithoutWriteScope,
        ),
        RouteRuleBreak::ParamInExactPath => (
            "fixture",
            "GET /client/fixture/{id}".into(),
            RouteRefusalReason::ParamInExactPath,
        ),
        RouteRuleBreak::ScanOptOutWithoutReason => (
            "fixture",
            "GET /client/fixture/x".into(),
            RouteRefusalReason::ScanOptOutWithoutReason,
        ),
        RouteRuleBreak::BudgetOutOfRange => (
            "fixture",
            "budget".into(),
            RouteRefusalReason::InvalidBudget {
                field: "dispatch_permits",
                value: 0,
                max: 64,
            },
        ),
        RouteRuleBreak::BudgetTwice => (
            "fixture",
            "budget".into(),
            RouteRefusalReason::BudgetAlreadySet,
        ),
        _ => unreachable!("{brk:?}"),
    }
}

fn two_exts(brk: RouteRuleBreak) -> bool {
    matches!(
        brk,
        RouteRuleBreak::LabelOwnedByEarlier | RouteRuleBreak::DuplicateShapeOtherExtension
    )
}

fn is_budget(brk: RouteRuleBreak) -> bool {
    matches!(
        brk,
        RouteRuleBreak::BudgetOutOfRange | RouteRuleBreak::BudgetTwice
    )
}

fn extensions(brk: RouteRuleBreak) -> Vec<Arc<dyn advance_runtime_compose::ComposeExtension>> {
    if two_exts(brk) {
        vec![
            FixtureExtension::new(FIXTURE_ID)
                .with_families(FixtureFamilies::standard())
                .arc(),
            FixtureExtension::new(FIXTURE_TWO_ID)
                .with_families(FixtureFamilies::standard_with_label(FIXTURE_TWO_ID).with_break(brk))
                .arc(),
        ]
    } else {
        vec![FixtureExtension::new(FIXTURE_ID)
            .with_families(FixtureFamilies::standard().with_break(brk))
            .arc()]
    }
}

async fn assert_registration_gone(
    home: &FixtureHome,
    log: &MemoryComposeLog,
    probe: &ComposeProbe,
    baseline: usize,
    error: &ComposeError,
    brk: RouteRuleBreak,
    extra: &[&str],
) {
    let (extension, route, reason) = expect_refusal(brk);
    match error {
        ComposeError::Registration {
            extension: got_ext,
            route: got_route,
            reason: got_reason,
        } if *got_ext == extension && *got_route == route && *got_reason == reason => {}
        other => panic!("{brk:?}: {other:?}"),
    }
    let text = error.to_string();
    if is_budget(brk) {
        assert!(
            text.starts_with("extension fixture: family budget refused: "),
            "{text}"
        );
    } else {
        assert!(
            text.starts_with(&format!("extension {extension}: route {route} refused: ")),
            "{text}"
        );
    }
    assert_eq!(log.count(log_keys::READY), 0, "{brk:?}");
    assert_eq!(log.count(log_keys::EXT_ROUTE_SCAN_OPT_OUT), 0, "{brk:?}");
    let rec = probe.record();
    assert!(
        rec.listeners.iter().all(|(name, _)| *name != "client_api"),
        "{brk:?}: {:?}",
        rec.listeners
    );
    let steps = names(&rec);
    assert!(
        subsequence(TEARDOWN_ORDER, &steps),
        "{brk:?}: {steps:?} vs {TEARDOWN_ORDER:?}"
    );
    for step in [
        "extensions.hooks",
        "holds.watchers",
        "holds.packs_poll",
        "holds.event_bus",
        "holds.drop_graph",
        "guard",
    ]
    .into_iter()
    .chain(extra.iter().copied())
    {
        assert!(steps.contains(&step), "{brk:?} missing {step}: {steps:?}");
    }
    for step in [
        "ingress.client_api",
        "loops.root",
        "holds.selected_provider",
        "holds.breaker",
    ] {
        assert!(!steps.contains(&step), "{brk:?} has {step}: {steps:?}");
    }
    assert_gone_for_home(probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112_a_each_broken_registrar_rule_fails_compose_and_leaves_nothing() {
    let home_a = home(&["fs", "llm"], false);
    let rows = [
        RouteRuleBreak::EmptySegment,
        RouteRuleBreak::Dot,
        RouteRuleBreak::DotDot,
        RouteRuleBreak::Percent,
        RouteRuleBreak::Uppercase,
        RouteRuleBreak::TooLong,
        RouteRuleBreak::LabelRoot,
        RouteRuleBreak::LabelStaticFloor,
        RouteRuleBreak::LabelLiveOss,
        RouteRuleBreak::StreamPath,
        RouteRuleBreak::LabelOwnedByEarlier,
        RouteRuleBreak::ParamFirstSegment,
        RouteRuleBreak::DuplicateShapeOss,
        RouteRuleBreak::DuplicateShapeOtherExtension,
        RouteRuleBreak::DuplicateShapeSameExtension,
        RouteRuleBreak::PostRegisteredAsRead,
        RouteRuleBreak::GetMutation,
        RouteRuleBreak::NoSession,
        RouteRuleBreak::NoScope,
        RouteRuleBreak::MutationReadScopeOnly,
        RouteRuleBreak::ParamInExactPath,
        RouteRuleBreak::ScanOptOutWithoutReason,
        RouteRuleBreak::BudgetOutOfRange,
        RouteRuleBreak::BudgetTwice,
    ];
    for brk in rows {
        let log = MemoryComposeLog::new();
        let probe = Arc::new(ComposeProbe::new());
        let baseline = alive_tasks();
        let error = compose(
            home_a.options(Arc::new(log.clone()), Arc::clone(&probe)),
            extensions(brk),
        )
        .await
        .expect_err(&format!("{brk:?}"));
        assert_registration_gone(&home_a, &log, &probe, baseline, &error, brk, &[]).await;
    }

    let home_b = home(&["fs", "llm", "lifecycle", "messaging"], true);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let error = compose(
        home_b.options(Arc::new(log.clone()), Arc::clone(&probe)),
        extensions(RouteRuleBreak::NoScope),
    )
    .await
    .expect_err("home B NoScope");
    let extra = if probe.record().perchild_manager.is_some() {
        vec!["holds.git_queue", "loops.perchild"]
    } else {
        vec!["holds.git_queue"]
    };
    assert_registration_gone(
        &home_b,
        &log,
        &probe,
        baseline,
        &error,
        RouteRuleBreak::NoScope,
        &extra,
    )
    .await;

    let flag = DropFlag::default();
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let error = compose(
        home_a.options(Arc::new(log.clone()), Arc::clone(&probe)),
        vec![FixtureExtension::new(FIXTURE_ID)
            .with_inference(FixtureInference::new().hold(&flag))
            .with_families(FixtureFamilies::standard().with_break(RouteRuleBreak::NoScope))
            .arc()],
    )
    .await
    .expect_err("inference hold + NoScope");
    assert!(flag.dropped(), "inference hold survived a refused compose");
    assert_registration_gone(
        &home_a,
        &log,
        &probe,
        baseline,
        &error,
        RouteRuleBreak::NoScope,
        &["holds.extension_holds"],
    )
    .await;

    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home_a.options(Arc::new(log), Arc::clone(&probe)),
        vec![FixtureExtension::new(FIXTURE_ID)
            .with_families(FixtureFamilies::standard())
            .arc()],
    )
    .await
    .expect("plain standard() compose");
    let ep = rt.client_api().expect("client api");
    let tok = mint_session(&ep);
    let status = Http::get(ep.socket_addr, "/client/fixture/status")
        .session(&tok)
        .send()
        .await;
    assert_eq!(status.status, 200, "{:?}", status.body);
    drop(ep);
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home_a.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_services_present_on_every_home() {
    let home = home(&["fs"], false);
    let families = FixtureFamilies::standard();
    let control = families.control();
    let ext = FixtureExtension::new(FIXTURE_ID).with_families(families);
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    let ep = rt.client_api().expect("client api");
    let addr = ep.socket_addr;
    let tok = mint_session(&ep);

    let sealed = Http::get(
        addr,
        query(
            "/client/fixture/cursor",
            &[("stream_id", "s"), ("raw_id", "r")],
        ),
    )
    .session(&tok)
    .send()
    .await;
    let token = sealed.body["data"]["cursor"]
        .as_str()
        .unwrap_or_else(|| panic!("cursor: {:?}", sealed.body))
        .to_owned();
    let opened = Http::get(
        addr,
        query(
            "/client/fixture/cursor:open",
            &[("stream_id", "s"), ("token", &token)],
        ),
    )
    .session(&tok)
    .send()
    .await;
    assert_eq!(opened.status, 200, "{:?}", opened.body);
    assert_eq!(opened.body["data"], json!({"raw_id": "r"}));
    let other = Http::get(
        addr,
        query(
            "/client/fixture/cursor:open",
            &[("stream_id", "other"), ("token", &token)],
        ),
    )
    .session(&tok)
    .send()
    .await;
    assert_eq!(other.status, 404, "{:?}", other.body);

    control.set_note(BEARER_NOTE);
    let leak = Http::get(addr, "/client/fixture/leak")
        .session(&tok)
        .send()
        .await;
    assert_eq!(leak.status, 200, "{:?}", leak.body);
    let note = leak.body["data"]["note"].as_str().unwrap_or("");
    assert_ne!(note, BEARER_NOTE);
    assert!(note.contains("[REDACTED]"), "{note}");

    let clock = Http::get(addr, "/client/fixture/clock")
        .session(&tok)
        .send()
        .await;
    assert_eq!(clock.status, 200, "{:?}", clock.body);
    let now_ms = clock.body["data"]["now_ms"]
        .as_u64()
        .unwrap_or_else(|| panic!("now_ms: {:?}", clock.body)) as i128;
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("unix epoch")
        .as_millis() as i128;
    assert!(
        (now_ms - wall).abs() < 60_000,
        "now_ms={now_ms} wall={wall}"
    );

    drop(ep);
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112_e_route_panic_contained_and_after_shutdown_unavailable() {
    let home = home(&["fs"], false);
    let ext = FixtureExtension::new(FIXTURE_ID).with_families(FixtureFamilies::standard());
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let baseline = alive_tasks();
    let rt = compose(
        home.options(Arc::new(log.clone()), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    let ep = rt.client_api().expect("client api");
    let addr = ep.socket_addr;
    let tok = mint_session(&ep);

    let panic_one = Http::get(addr, "/client/fixture/panic")
        .session(&tok)
        .send()
        .await;
    assert_eq!(panic_one.status, 503, "{:?}", panic_one.body);
    assert_eq!(error_code(&panic_one.body), "module_unavailable");
    assert_eq!(error_message(&panic_one.body), "provider unavailable");
    assert_eq!(log.count(log_keys::EXT_ROUTE_PANICKED), 1);
    let line = log
        .lines()
        .into_iter()
        .find(|line| line.key == log_keys::EXT_ROUTE_PANICKED)
        .expect("panic log");
    assert_eq!(
        line.text,
        "advance: WARN extension fixture route GET /client/fixture/panic panicked; answered module_unavailable"
    );
    for line in log.lines() {
        assert!(
            !line.text.contains("fixture route panic"),
            "panic payload in log: {}",
            line.text
        );
    }

    for _ in 0..2 {
        let status = Http::get(addr, "/client/fixture/status")
            .session(&tok)
            .send()
            .await;
        assert_eq!(status.status, 200, "{:?}", status.body);
        assert_eq!(status.body["data"], json!({"status": "ok"}));
    }
    let panic_two = Http::get(addr, "/client/fixture/panic")
        .session(&tok)
        .send()
        .await;
    assert_eq!(panic_two.status, 503, "{:?}", panic_two.body);
    assert_eq!(error_message(&panic_two.body), "provider unavailable");
    assert_eq!(log.count(log_keys::EXT_ROUTE_PANICKED), 2);

    let api = ep.api.upgrade().expect("client api alive");
    assert!(rt.shutdown_handle().trigger());
    assert!(rt.client_api().is_none());
    let tok_h = tok.clone();
    let (gated, sessionless, health) = tokio::task::spawn_blocking(move || {
        let gated = api.handle(ClientRequest::get("/client/fixture/status").with_session(&tok_h));
        let sessionless = api.handle(ClientRequest::get("/client/fixture/status"));
        let health = api.handle(ClientRequest::get("/client/health"));
        drop(api);
        (gated, sessionless, health)
    })
    .await
    .expect("in-process handle");
    for env in [&gated, &sessionless] {
        let err = env.error.as_ref().expect("gated error");
        assert_eq!(err.code, ClientErrorCode::ModuleUnavailable);
        assert_eq!(err.message, "provider unavailable");
    }
    assert!(health.data.is_some(), "{health:?}");
    drop(ep);
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

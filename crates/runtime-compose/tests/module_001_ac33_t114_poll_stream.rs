//! MODULE-001-T114 — poll_stream GET+WebSocket, refusals, shutdown, stall, containment.

use std::net::{SocketAddr, TcpStream};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_client_api::CLIENT_WS_PROTOCOL;
use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, mint_session, CapDecl, FamiliesControl, FixtureDriver, FixtureExtension,
    FixtureFamilies, FixtureHome, FixtureHomeSpec, Http, FIXTURE_ID,
};
use advance_runtime_compose::test_support::{
    ComposeProbe, MemoryComposeLog, ProbeRecord, TEARDOWN_ORDER,
};
use advance_runtime_compose::{
    compose, log_keys, ClientFamilyRegistrar, ComposeCx, ComposeError, ComposeExtension,
    DuplicateOf, ExtensionError, HandlerSpec, Method, PathDefect, PollEmit, PollStreamSpec,
    RouteRefusalReason, Scope,
};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{ORIGIN, SEC_WEBSOCKET_PROTOCOL};
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::Message;

type WsClient = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

fn home() -> FixtureHome {
    home_with(&["fs"])
}

fn home_with(caps: &[&'static str]) -> FixtureHome {
    FixtureHome::new(FixtureHomeSpec {
        capabilities: caps.iter().copied().map(CapDecl::Granted).collect(),
        driver: FixtureDriver::None,
        git: false,
        providers_yaml: None,
    })
    .expect("home")
}

fn names(rec: &ProbeRecord) -> Vec<&'static str> {
    rec.step_names()
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

fn median_ms(gaps: &[u128]) -> u128 {
    let mut sorted = gaps.to_vec();
    sorted.sort_unstable();
    let n = sorted.len();
    assert!(n > 0, "no poll gaps");
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2
    }
}

async fn next_text(ws: &mut WsClient, budget: Duration) -> String {
    tokio::time::timeout(budget, async {
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

async fn assert_ws_closed(ws: &mut WsClient, budget: Duration) {
    let closed = tokio::time::timeout(budget, async {
        loop {
            match ws.next().await {
                None | Some(Ok(Message::Close(_))) | Some(Err(_)) => return,
                Some(Ok(_)) => continue,
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "WebSocket still open after {budget:?}");
}

fn handshake_body(err: WsError) -> (u16, Value) {
    match err {
        WsError::Http(resp) => {
            let status = resp.status().as_u16();
            let body = resp
                .body()
                .as_ref()
                .and_then(|bytes| serde_json::from_slice(bytes).ok())
                .unwrap_or(Value::Null);
            (status, body)
        }
        other => panic!("expected HTTP handshake refusal, got {other:?}"),
    }
}

async fn try_ws(
    addr: SocketAddr,
    path: &str,
    token: Option<&str>,
    origin: Option<&str>,
) -> Result<WsClient, (u16, Value)> {
    let mut request = format!("ws://{addr}{path}")
        .into_client_request()
        .expect("WebSocket request");
    let protocol = match token {
        Some(token) => format!("{CLIENT_WS_PROTOCOL}, advance.bearer.{token}"),
        None => CLIENT_WS_PROTOCOL.to_string(),
    };
    request.headers_mut().insert(
        SEC_WEBSOCKET_PROTOCOL,
        protocol.parse().expect("protocol header"),
    );
    if let Some(origin) = origin {
        request
            .headers_mut()
            .insert(ORIGIN, origin.parse().expect("origin header"));
    }
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect the Client API");
    match tokio_tungstenite::client_async(request, tcp).await {
        Ok((ws, response)) => {
            assert_eq!(response.status().as_u16(), 101, "{response:?}");
            Ok(ws)
        }
        Err(err) => Err(handshake_body(err)),
    }
}

async fn open_ws(
    addr: SocketAddr,
    path: &str,
    token: &str,
    origin: Option<&str>,
) -> (WsClient, Value) {
    let mut ws = try_ws(addr, path, Some(token), origin)
        .await
        .unwrap_or_else(|(status, body)| panic!("upgrade {path}: {status} {body}"));
    let text = next_text(&mut ws, Duration::from_secs(10)).await;
    let envelope: Value = serde_json::from_str(&text).expect("seed json");
    (ws, envelope)
}

fn feed_ext() -> (FixtureExtension, Arc<FamiliesControl>) {
    let families = FixtureFamilies::standard().with_feed();
    let control = families.control();
    (
        FixtureExtension::new(FIXTURE_ID).with_families(families),
        control,
    )
}

struct PollRefusal {
    path: &'static str,
    pre_get: bool,
}

impl ComposeExtension for PollRefusal {
    fn id(&self) -> &'static str {
        "fixture"
    }

    fn client_families(
        &self,
        _cx: &ComposeCx,
        reg: &mut ClientFamilyRegistrar<'_>,
    ) -> Result<(), ExtensionError> {
        let read =
            || HandlerSpec::read(true, |_| Ok(json!({}))).with_scopes(vec![Scope::ReadInventory]);
        if self.pre_get {
            reg.route(Method::Get, "/client/fixture/feed", read())?;
        }
        reg.poll_stream(
            self.path,
            PollStreamSpec::new(read(), "/cursor", PollEmit::NonEmptyArrayAt("/items")),
        )?;
        Ok(())
    }
}

async fn assert_registration_gone(
    home: &FixtureHome,
    log: &MemoryComposeLog,
    probe: &ComposeProbe,
    baseline: usize,
    error: &ComposeError,
    extension: &'static str,
    route: &str,
    reason: RouteRefusalReason,
) {
    match error {
        ComposeError::Registration {
            extension: got_ext,
            route: got_route,
            reason: got_reason,
        } if *got_ext == extension && *got_route == route && *got_reason == reason => {}
        other => panic!("{route}: {other:?}"),
    }
    let text = error.to_string();
    assert!(
        text.starts_with(&format!("extension {extension}: route {route} refused: ")),
        "{text}"
    );
    assert_eq!(log.count(log_keys::READY), 0, "{route}");
    let rec = probe.record();
    assert!(
        rec.listeners.iter().all(|(name, _)| *name != "client_api"),
        "{route}: {:?}",
        rec.listeners
    );
    let steps = names(&rec);
    assert!(
        subsequence(&TEARDOWN_ORDER, &steps),
        "{route}: {steps:?} vs {TEARDOWN_ORDER:?}"
    );
    for step in [
        "extensions.hooks",
        "holds.watchers",
        "holds.packs_poll",
        "holds.event_bus",
        "holds.drop_graph",
        "guard",
    ] {
        assert!(steps.contains(&step), "{route} missing {step}: {steps:?}");
    }
    for step in [
        "ingress.client_api",
        "loops.root",
        "holds.selected_provider",
        "holds.breaker",
    ] {
        assert!(!steps.contains(&step), "{route} has {step}: {steps:?}");
    }
    assert_gone_for_home(probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac33_t114_poll_stream() {
    let _serial = SERIAL.lock().await;
    let home = home_with(&["fs", "llm"]);
    let (ext, control) = feed_ext();
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
    let origin = format!("http://{addr}");
    let token = mint_session(&ep);

    let get = Http::get(addr, "/client/fixture/feed")
        .session(&token)
        .send()
        .await;
    assert_eq!(get.status, 200, "{:?}", get.body);
    assert_eq!(get.body["data"]["items"], json!([]));
    assert_eq!(get.body["data"]["cursor"], json!("c0"));

    let no_bearer = try_ws(addr, "/client/fixture/feed", None, Some(&origin))
        .await
        .expect_err("feed without bearer");
    let events_no_bearer = try_ws(addr, "/client/events/stream", None, Some(&origin))
        .await
        .expect_err("events without bearer");
    assert_eq!(no_bearer.0, 401, "{:?}", no_bearer.1);
    assert_eq!(error_code(&no_bearer.1), "unauthenticated");
    assert_eq!(
        (no_bearer.0, error_code(&no_bearer.1)),
        (events_no_bearer.0, error_code(&events_no_bearer.1)),
        "feed {:?} events {:?}",
        no_bearer.1,
        events_no_bearer.1
    );

    let evil = "http://evil.invalid";
    let bad_origin = try_ws(addr, "/client/fixture/feed", Some(&token), Some(evil))
        .await
        .expect_err("feed evil origin");
    let events_evil = try_ws(addr, "/client/events/stream", Some(&token), Some(evil))
        .await
        .expect_err("events evil origin");
    assert_eq!(bad_origin.0, 403, "{:?}", bad_origin.1);
    assert_eq!(error_code(&bad_origin.1), "origin_not_allowed");
    assert_eq!(
        (bad_origin.0, error_code(&bad_origin.1)),
        (events_evil.0, error_code(&events_evil.1)),
        "feed {:?} events {:?}",
        bad_origin.1,
        events_evil.1
    );

    {
        let (_events, events_seed) =
            open_ws(addr, "/client/events/stream", &token, Some(&origin)).await;
        assert!(
            events_seed.get("data").is_some_and(|data| !data.is_null()),
            "{events_seed}"
        );
    }
    {
        let (_deltas, delta_seed) =
            open_ws(addr, "/client/llm/deltas/stream", &token, Some(&origin)).await;
        assert_eq!(
            delta_seed.pointer("/data/subscribed"),
            Some(&Value::Bool(true)),
            "{delta_seed}"
        );
    }

    let polls_before = control.polls().len();
    let (mut feed, seed) = open_ws(addr, "/client/fixture/feed", &token, Some(&origin)).await;
    let seeded_at = Instant::now();
    assert!(seed.get("error").is_none_or(Value::is_null), "{seed}");
    assert_eq!(seed["data"]["items"], json!([]), "{seed}");
    assert_eq!(seed["data"]["cursor"], json!("c0"), "{seed}");

    let quiet_until = Instant::now() + Duration::from_millis(1500);
    while Instant::now() < quiet_until {
        let left = quiet_until.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, feed.next()).await {
            Err(_) => break,
            Ok(Some(Ok(Message::Text(text)))) => panic!("frame while feed empty: {text}"),
            Ok(Some(Ok(Message::Ping(_)))) => panic!("ping during the empty-page window"),
            Ok(Some(Ok(_))) => {}
            Ok(None) | Ok(Some(Err(_))) => panic!("feed closed while empty"),
        }
    }

    let polls = control.polls();
    let window = &polls[polls_before..];
    assert!(
        window.len() >= 4,
        "polls after the seed stream: {}",
        window.len()
    );
    let gaps: Vec<u128> = window
        .windows(2)
        .map(|pair| pair[1].0.duration_since(pair[0].0).as_millis())
        .collect();
    let median = median_ms(&gaps);
    assert!(
        (200..=400).contains(&median),
        "median gap {median} ms, gaps {gaps:?}"
    );
    for gap in &gaps {
        assert!(
            (100..=1000).contains(gap),
            "gap {gap} ms outside [100, 1000], gaps {gaps:?}"
        );
    }
    for (_, body) in window.iter().skip(1) {
        assert_eq!(
            body.pointer("/cursor").and_then(Value::as_str),
            Some("c0"),
            "{body}"
        );
    }

    let item = json!({"id": 1});
    control.push_feed(item.clone());
    let page = next_text(&mut feed, Duration::from_secs(1)).await;
    let page: Value = serde_json::from_str(&page).expect("page json");
    assert_eq!(page["data"]["items"], json!([item]), "{page}");

    let ping_budget = Duration::from_secs(16).saturating_sub(seeded_at.elapsed());
    let saw_ping = tokio::time::timeout(ping_budget, async {
        loop {
            match feed.next().await {
                Some(Ok(Message::Ping(payload))) => {
                    let _ = feed.send(Message::Pong(payload)).await;
                    return true;
                }
                Some(Ok(Message::Text(text))) => panic!("extra poll frame: {text}"),
                Some(Ok(Message::Pong(_))) | Some(Ok(Message::Binary(_))) => {}
                other => panic!("feed ended before ping: {other:?}"),
            }
        }
    })
    .await
    .expect("Ping within 16 s of the seed");
    assert!(saw_ping);

    rt.shutdown().await.expect("shutdown");
    assert_ws_closed(&mut feed, Duration::from_secs(2)).await;
    let rec = probe.record();
    assert_eq!(
        rec.client_api_ws_joined,
        Some(true),
        "{:?}",
        rec.step_names()
    );
    assert!(
        names(&rec).contains(&"ingress.client_api"),
        "{:?}",
        names(&rec)
    );
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac33_t114_poll_stream_refusals_fail_compose() {
    let _serial = SERIAL.lock().await;
    let home = home();
    let rows: [(&'static str, bool, &'static str, RouteRefusalReason); 3] = [
        (
            "/client/events/feed",
            false,
            "GET /client/events/feed",
            RouteRefusalReason::ReservedLabel {
                label: "events".into(),
            },
        ),
        (
            "/client/fixture//feed",
            false,
            "GET /client/fixture//feed",
            RouteRefusalReason::InvalidPath(PathDefect::EmptySegment { index: 1 }),
        ),
        (
            "/client/fixture/feed",
            true,
            "GET /client/fixture/feed",
            RouteRefusalReason::DuplicateRoute {
                shape: "/client/fixture/feed".into(),
                of: DuplicateOf::Extension("fixture"),
            },
        ),
    ];
    for (path, pre_get, route, reason) in rows {
        let log = MemoryComposeLog::new();
        let probe = Arc::new(ComposeProbe::new());
        let baseline = alive_tasks();
        let error = compose(
            home.options(Arc::new(log.clone()), Arc::clone(&probe)),
            vec![Arc::new(PollRefusal { path, pre_get })],
        )
        .await
        .expect_err(route);
        assert_registration_gone(
            &home, &log, &probe, baseline, &error, "fixture", route, reason,
        )
        .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac33_t114_shutdown_preempts_a_stalled_stream() {
    let _serial = SERIAL.lock().await;
    let home = home();
    let (ext, control) = feed_ext();
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
    let origin = format!("http://{addr}");
    let token = mint_session(&ep);

    let (seeded_tx, seeded_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let stall_thread = std::thread::spawn(move || {
        let mut request = format!("ws://{addr}/client/fixture/feed")
            .into_client_request()
            .expect("WebSocket request");
        request.headers_mut().insert(
            SEC_WEBSOCKET_PROTOCOL,
            format!("{CLIENT_WS_PROTOCOL}, advance.bearer.{token}")
                .parse()
                .expect("protocol header"),
        );
        request
            .headers_mut()
            .insert(ORIGIN, origin.parse().expect("origin header"));
        let stream = TcpStream::connect(addr).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("seed timeout");
        let (mut socket, _) =
            tokio_tungstenite::tungstenite::client::client(request, stream).expect("upgrade");
        loop {
            match socket.read() {
                Ok(Message::Text(_)) => break,
                Ok(Message::Ping(payload)) => {
                    socket.send(Message::Pong(payload)).expect("pong");
                }
                other => panic!("unexpected frame before the seed: {other:?}"),
            }
        }
        socket
            .get_mut()
            .set_read_timeout(None)
            .expect("clear timeout");
        seeded_tx.send(()).expect("seeded");
        let _ = release_rx.recv();
        drop(socket);
    });
    seeded_rx.recv().expect("stalled client read the seed");

    const ITEM_BYTES: usize = 65_536;
    const BURST: usize = 16;
    const CAP: usize = 256 * 1024 * 1024;
    let payload = "x".repeat(ITEM_BYTES);
    let mut pushed = 0usize;
    let mut last_len = control.polls().len();
    let mut last_change = Instant::now();
    loop {
        for _ in 0..BURST {
            control.push_feed(json!(payload.clone()));
            pushed += ITEM_BYTES;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let n = control.polls().len();
        if n != last_len {
            last_len = n;
            last_change = Instant::now();
        }
        if last_change.elapsed() >= Duration::from_secs(1) {
            break;
        }
        assert!(
            pushed < CAP,
            "no send stall after {pushed} bytes, polls={n}"
        );
    }

    let t = Instant::now();
    rt.shutdown().await.expect("shutdown");
    assert!(
        t.elapsed() <= Duration::from_secs(3),
        "shutdown of a stalled poll stream took {:?}",
        t.elapsed()
    );
    let rec = probe.record();
    assert_eq!(
        rec.client_api_ws_joined,
        Some(true),
        "{:?}",
        rec.step_names()
    );
    assert!(
        names(&rec).contains(&"ingress.client_api"),
        "{:?}",
        names(&rec)
    );
    let _ = release_tx.send(());
    stall_thread.join().expect("stall client");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac33_poll_stream_handler_panic_is_contained() {
    let _serial = SERIAL.lock().await;
    let home = home();
    let (ext, control) = feed_ext();
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
    let origin = format!("http://{addr}");
    let token = mint_session(&ep);

    let (mut feed, seed) = open_ws(addr, "/client/fixture/feed", &token, Some(&origin)).await;
    assert_eq!(seed["data"]["cursor"], json!("c0"), "{seed}");
    control.panic_next_poll();
    let panicked = next_text(&mut feed, Duration::from_secs(2)).await;
    let envelope: Value = serde_json::from_str(&panicked).expect("error envelope");
    assert_eq!(error_code(&envelope), "module_unavailable", "{envelope}");
    assert_eq!(
        error_message(&envelope),
        "provider unavailable",
        "{envelope}"
    );
    assert_ws_closed(&mut feed, Duration::from_secs(2)).await;
    assert_eq!(log.count(log_keys::EXT_ROUTE_PANICKED), 1);
    let line = log
        .lines()
        .into_iter()
        .find(|line| line.key == log_keys::EXT_ROUTE_PANICKED)
        .expect("panic log");
    assert_eq!(
        line.text,
        "advance: WARN extension fixture route GET /client/fixture/feed panicked; answered module_unavailable"
    );
    for line in log.lines() {
        assert!(
            !line.text.contains("fixture feed panic"),
            "panic payload in log: {}",
            line.text
        );
    }

    let (mut again, seed) = open_ws(addr, "/client/fixture/feed", &token, Some(&origin)).await;
    assert_eq!(seed["data"]["items"], json!([]), "{seed}");
    let get = Http::get(addr, "/client/fixture/feed")
        .session(&token)
        .send()
        .await;
    assert_eq!(get.status, 200, "{:?}", get.body);
    let item = json!({"id": "after-panic"});
    control.push_feed(item.clone());
    let page = next_text(&mut again, Duration::from_secs(1)).await;
    let page: Value = serde_json::from_str(&page).expect("page json");
    assert_eq!(page["data"]["items"], json!([item]), "{page}");

    drop(again);
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
}

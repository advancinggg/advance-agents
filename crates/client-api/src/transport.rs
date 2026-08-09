//! Public HTTP/WebSocket transport for CONTRACT-190/191 and the embedded Web Console.
//!
//! This module deliberately owns no provider adapters.  HTTP calls and every WebSocket poll are
//! converted to [`ClientRequest`] and pass through [`ClientApi::handle`], preserving the canonical
//! admission → version → body → origin → auth → CSRF/idempotency → provider gate order.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::connect_info::ConnectInfo;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, Path, State};
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, ORIGIN,
    SEC_WEBSOCKET_PROTOCOL, X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Map, Value};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Semaphore};
use tokio::task::JoinHandle;

use crate::cursor::ClientCursorCodec;
use crate::deltas::{
    resolve_stream_request, DeltaPumpExit, DeltaSubscriberPermit, LlmDeltaHub,
    LlmDeltaStreamRequest, LlmDeltaWirePage, ReauthDeadline,
};
use crate::envelope::{ClientEnvelope, ClientError, ClientErrorCode, API_VERSION};
use crate::events::{ClientEventPage, ClientEventStreamRequest};
use crate::request::{ClientRequest, Method};
use crate::routes;
use crate::ClientApi;

const INDEX_HTML: &str = include_str!("../../../clients/web-console/index.html");
const APP_JS: &str = include_str!("../../../clients/web-console/app.js");
const STYLES_CSS: &str = include_str!("../../../clients/web-console/styles.css");

const VERSION_HEADER: &str = "x-advance-api-version";
const CSRF_HEADER: &str = "x-csrf-token";
const IDEMPOTENCY_HEADER: &str = "idempotency-key";
const BEARER_PROTOCOL_PREFIX: &str = "advance.bearer.";
const POLL_INTERVAL_MS: u64 = 250;
const HEARTBEAT_INTERVAL_SECS: u64 = 15;
/// FIX 3: cap the delta pump's beat-arm inbound drain per wake. The drain always yields back to
/// the `select!` after this many frames, so an inbound flood cannot starve the cut / deadline
/// arms and the per-frame error-envelope write is bounded per wake.
const DELTA_INBOUND_DRAIN_PER_BEAT: usize = 32;

/// Browser-visible WebSocket protocol.  The bearer token is sent as a second, unselected
/// `advance.bearer.<hex>` protocol so it does not enter the URL, browser history, or proxy logs.
pub const CLIENT_WS_PROTOCOL: &str = "advance.client.2026-06-30";

#[derive(Clone)]
struct TransportState {
    api: Arc<ClientApi>,
    max_body_bytes: usize,
    /// Bounds concurrent blocking-pool dispatches (HTTP requests + WS seeds) so a caller cannot
    /// pin the pool / grow an unbounded queue; excess fails closed with `module_unavailable`.
    dispatch: Arc<Semaphore>,
}

/// Build the public router.  It contains only embedded console assets and `/client/*` routes.
/// ConnectInfo is required so the core can enforce loopback admission from the real peer address.
pub fn client_api_router(api: Arc<ClientApi>) -> Router {
    let max_body_bytes = api.config().max_body_bytes;
    // Clamp to a sane window: `.max(1)` guards a zero cap (would wedge the server); the upper clamp
    // guards a misconfigured huge value (above tokio's `Semaphore::MAX_PERMITS` would panic here).
    let dispatch_permits = api.config().max_concurrent_dispatch.clamp(1, 65_536);
    let dispatch = Arc::new(Semaphore::new(dispatch_permits));
    let state = TransportState {
        api,
        max_body_bytes,
        dispatch,
    };
    Router::new()
        .route("/", get(index))
        .route("/index.html", get(index))
        .route("/app.js", get(app_js))
        .route("/styles.css", get(styles_css))
        .route("/client/events/stream", get(event_stream_transport))
        .route(routes::PATH_LLM_DELTAS_STREAM, get(delta_stream_transport))
        .route(
            "/client/{*path}",
            get(http_client_request).post(http_client_request),
        )
        .with_state(state)
}

/// A bound public Client API server with deterministic graceful shutdown.
pub struct ClientApiServer {
    local_addr: SocketAddr,
    api: Arc<ClientApi>,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<io::Result<()>>,
}

impl ClientApiServer {
    /// Bind the configured IP and caller-selected port.  A non-loopback bind is rejected before
    /// touching the socket unless `remote_bind_enabled` is explicitly true.
    pub async fn bind(api: Arc<ClientApi>, port: u16) -> io::Result<Self> {
        let ip = api.config().bind_addr;
        if !ip.is_loopback() && !api.config().remote_bind_enabled {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "client API non-loopback bind is disabled",
            ));
        }
        let listener = TcpListener::bind(SocketAddr::new(ip, port)).await?;
        let local_addr = listener.local_addr()?;
        Self::serve(listener, local_addr, api)
    }

    /// Bind an OS-selected loopback socket first, then construct the API with
    /// knowledge of its exact same-origin URL. This keeps the default empty
    /// browser allowlist fail-closed while letting the production composition
    /// install only the actual local console origin (including its port).
    pub async fn bind_local_factory<F>(port: u16, factory: F) -> io::Result<Self>
    where
        F: FnOnce(SocketAddr) -> Arc<ClientApi>,
    {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).await?;
        let local_addr = listener.local_addr()?;
        let api = factory(local_addr);
        if api.config().bind_addr != local_addr.ip()
            || (!api.config().bind_addr.is_loopback() && !api.config().remote_bind_enabled)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "local console API configuration does not match its loopback listener",
            ));
        }
        Self::serve(listener, local_addr, api)
    }

    fn serve(
        listener: TcpListener,
        local_addr: SocketAddr,
        api: Arc<ClientApi>,
    ) -> io::Result<Self> {
        let router = client_api_router(Arc::clone(&api));
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .map_err(io::Error::other)
        });
        Ok(Self {
            local_addr,
            api,
            shutdown: Some(shutdown_tx),
            task,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn api(&self) -> Arc<ClientApi> {
        Arc::clone(&self.api)
    }

    pub async fn shutdown(mut self) -> io::Result<()> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        self.task
            .await
            .map_err(|error| io::Error::other(format!("client API task join: {error}")))?
    }
}

async fn index() -> Response {
    static_asset(Html(INDEX_HTML), "text/html; charset=utf-8", false)
}

async fn app_js() -> Response {
    static_asset(APP_JS, "text/javascript; charset=utf-8", true)
}

async fn styles_css() -> Response {
    static_asset(STYLES_CSS, "text/css; charset=utf-8", true)
}

fn static_asset(body: impl IntoResponse, content_type: &'static str, immutable: bool) -> Response {
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        content_type.parse().expect("static content type"),
    );
    headers.insert(X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    headers.insert(
        CONTENT_SECURITY_POLICY,
        "default-src 'self'; connect-src 'self' ws: wss:; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
            .parse()
            .unwrap(),
    );
    headers.insert(
        CACHE_CONTROL,
        if immutable {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        }
        .parse()
        .unwrap(),
    );
    response
}

async fn http_client_request(
    State(state): State<TransportState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(path): Path<String>,
    request: Request<Body>,
) -> Response {
    handle_http(state, peer.ip(), format!("/client/{path}"), request).await
}

async fn event_stream_transport(
    State(state): State<TransportState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response {
    if !is_websocket_upgrade(request.headers()) {
        return handle_http(state, peer.ip(), "/client/events/stream".into(), request).await;
    }

    let (mut parts, _body) = request.into_parts();
    let headers = parts.headers.clone();
    let token = websocket_bearer(&headers);
    let origin = header_string(&headers, ORIGIN.as_str());
    let api_version = websocket_version(&headers);
    let seed_request = ClientRequest {
        api_version,
        method: Method::Get,
        path: "/client/events/stream".into(),
        session_token: token.clone(),
        origin: origin.clone(),
        csrf_token: None,
        idempotency_key: None,
        is_loopback_peer: peer.ip().is_loopback(),
        body: serde_json::json!({ "limit": 0 }),
    };
    // `handle()` is sync and its provider adapters may bridge async host surfaces via `block_on`,
    // which panics on a tokio async worker. Run it on a blocking-pool thread (as the poll loop at
    // `websocket_loop` does); a join error (a panic escaping `handle()`) maps to a stable 503.
    // A dispatch permit bounds concurrent blocking-pool submissions (fail closed if saturated).
    let seed = match state.dispatch.clone().try_acquire_owned() {
        Ok(permit) => {
            let seed_api = Arc::clone(&state.api);
            // The permit is moved INTO the blocking closure so it is held for the real `handle()`
            // duration and released when the closure returns — NOT tied to this (cancellable) future.
            // If the client disconnects, the future is dropped but the detached `spawn_blocking`
            // closure keeps running AND keeps the permit, so the cap tracks real pool occupancy.
            match tokio::task::spawn_blocking(move || {
                let _permit = permit;
                seed_api.handle(seed_request)
            })
            .await
            {
                Ok(envelope) => envelope,
                Err(_) => transport_error(
                    ClientErrorCode::ModuleUnavailable,
                    "event stream unavailable",
                ),
            }
        }
        Err(_) => transport_error(
            ClientErrorCode::ModuleUnavailable,
            "server at dispatch capacity",
        ),
    };
    if seed.is_err() {
        return envelope_response(seed);
    }

    let ws = match WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
        Ok(ws) => ws,
        Err(rejection) => return rejection.into_response(),
    };
    let api = Arc::clone(&state.api);
    let dispatch = state.dispatch.clone();
    ws.protocols([CLIENT_WS_PROTOCOL])
        .on_upgrade(move |socket| {
            websocket_loop(socket, api, dispatch, peer.ip(), token, origin, seed)
        })
}

async fn handle_http(
    state: TransportState,
    peer_ip: IpAddr,
    path: String,
    request: Request<Body>,
) -> Response {
    let (parts, body) = request.into_parts();
    let method = match parts.method.as_str() {
        "GET" => Method::Get,
        "POST" => Method::Post,
        _ => {
            return envelope_response(transport_error(
                ClientErrorCode::UnknownRoute,
                "unsupported method",
            ))
        }
    };
    let body = if method == Method::Get {
        query_body(parts.uri.query())
    } else {
        match to_bytes(body, state.max_body_bytes).await {
            Ok(bytes) if bytes.is_empty() => Value::Null,
            Ok(bytes) => match serde_json::from_slice(&bytes) {
                Ok(value) => value,
                Err(_) => {
                    return envelope_response(transport_error(
                        ClientErrorCode::InvalidState,
                        "invalid JSON request body",
                    ))
                }
            },
            Err(_) => {
                return envelope_response(transport_error(
                    ClientErrorCode::RequestTooLarge,
                    "body exceeds max",
                ))
            }
        }
    };
    let req = ClientRequest {
        api_version: header_string(&parts.headers, VERSION_HEADER)
            .unwrap_or_else(|| API_VERSION.to_string()),
        method,
        path,
        session_token: bearer(&parts.headers),
        origin: header_string(&parts.headers, ORIGIN.as_str()),
        csrf_token: header_string(&parts.headers, CSRF_HEADER),
        idempotency_key: header_string(&parts.headers, IDEMPOTENCY_HEADER),
        is_loopback_peer: peer_ip.is_loopback(),
        body,
    };
    // Run the sync core on a blocking-pool thread (see the WS-seed note above): a `block_on`-bridging
    // provider would nested-runtime-panic if `handle()` ran directly on this async worker. A join
    // error (a panic escaping `handle()`, e.g. from an out-of-`run_handler` site) maps to a stable 503.
    // A dispatch permit bounds concurrent blocking-pool submissions so a caller cannot pin the pool /
    // grow an unbounded queue on the uncapped provider families; excess fails closed with 503.
    let permit = match state.dispatch.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return envelope_response(transport_error(
                ClientErrorCode::ModuleUnavailable,
                "server at dispatch capacity",
            ))
        }
    };
    let api = Arc::clone(&state.api);
    // Move the permit INTO the blocking closure so it tracks real pool occupancy: `spawn_blocking`
    // closures are not cancellable, so if this future is dropped on client disconnect the detached
    // closure keeps running AND keeps the permit until `handle()` returns.
    let envelope = match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        api.handle(req)
    })
    .await
    {
        Ok(envelope) => envelope,
        Err(_) => transport_error(
            ClientErrorCode::ModuleUnavailable,
            "client request unavailable",
        ),
    };
    envelope_response(envelope)
}

fn query_body(query: Option<&str>) -> Value {
    let Some(query) = query else {
        return Value::Null;
    };
    let mut object = Map::new();
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        let value = match key.as_ref() {
            "limit" | "offset" => value
                .parse::<u64>()
                .map(Value::from)
                .unwrap_or_else(|_| Value::String(value.into_owned())),
            _ => Value::String(value.into_owned()),
        };
        object.insert(key.into_owned(), value);
    }
    if object.is_empty() {
        Value::Null
    } else {
        Value::Object(object)
    }
}

async fn websocket_loop(
    mut socket: WebSocket,
    api: Arc<ClientApi>,
    dispatch: Arc<Semaphore>,
    peer_ip: IpAddr,
    token: Option<String>,
    origin: Option<String>,
    seed: ClientEnvelope<Value>,
) {
    let mut stream_request = seed
        .data
        .as_ref()
        .and_then(|data| serde_json::from_value::<ClientEventPage>(data.clone()).ok())
        .and_then(|page| page.cursor)
        .map(|cursor| ClientEventStreamRequest {
            stream_id: Some(cursor.stream_id),
            last_event_id: cursor.last_event_id,
            ..ClientEventStreamRequest::default()
        })
        .unwrap_or_default();

    if send_envelope(&mut socket, &seed).await.is_err() {
        return;
    }
    let mut poll = tokio::time::interval(Duration::from_millis(POLL_INTERVAL_MS));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut heartbeat = tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Consume the immediate ticks; the seed response already represents stream open.
    poll.tick().await;
    heartbeat.tick().await;

    loop {
        tokio::select! {
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<ClientEventStreamRequest>(&text) {
                            Ok(next) => stream_request = next,
                            Err(_) => {
                                let envelope = transport_error(ClientErrorCode::InvalidState, "invalid event stream request");
                                let _ = send_envelope(&mut socket, &envelope).await;
                                break;
                            }
                        }
                    }
                    Some(Ok(Message::Ping(bytes))) => {
                        if socket.send(Message::Pong(bytes)).await.is_err() { break; }
                    }
                    Some(Ok(Message::Pong(_))) | Some(Ok(Message::Binary(_))) => {}
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                }
            }
            _ = poll.tick() => {
                // Gate the poll on the same dispatch budget so a fleet of live connections cannot
                // submit unbounded blocking tasks around the cap. A permit held per-poll (in the
                // closure) is released the moment the poll returns, so it cannot starve HTTP; when the
                // budget is saturated we simply SKIP this tick (transient backpressure) and retry next
                // cycle — events are cursor-recoverable, so nothing is dropped.
                let permit = match dispatch.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => continue,
                };
                let request = ClientRequest {
                    api_version: API_VERSION.to_string(),
                    method: Method::Get,
                    path: "/client/events/stream".into(),
                    session_token: token.clone(),
                    origin: origin.clone(),
                    csrf_token: None,
                    idempotency_key: None,
                    is_loopback_peer: peer_ip.is_loopback(),
                    body: serde_json::to_value(&stream_request).unwrap_or(Value::Null),
                };
                let worker_api = Arc::clone(&api);
                let envelope = match tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    worker_api.handle(request)
                }).await {
                    Ok(envelope) => envelope,
                    Err(_) => transport_error(ClientErrorCode::ModuleUnavailable, "event stream unavailable"),
                };
                if let Some(data) = envelope.data.as_ref() {
                    if let Ok(page) = serde_json::from_value::<ClientEventPage>(data.clone()) {
                        if let Some(cursor) = page.cursor.as_ref() {
                            stream_request.stream_id = Some(cursor.stream_id.clone());
                            stream_request.last_event_id = cursor.last_event_id.clone();
                        }
                        let noteworthy = !page.events.is_empty()
                            || page.dropped_count > 0
                            || page.rejected_count > 0
                            || page.redacted_count > 0
                            || page.raw_limit_reached
                            || page.response_limit_reached;
                        if noteworthy && send_envelope(&mut socket, &envelope).await.is_err() { break; }
                    }
                } else {
                    let _ = send_envelope(&mut socket, &envelope).await;
                    break;
                }
            }
            _ = heartbeat.tick() => {
                if socket.send(Message::Ping(Vec::new().into())).await.is_err() { break; }
            }
        }
    }
}

// ── Tee T2 (CONTRACT-235): the LLM delta WS transport ────────────────────────────────────────

/// One pump-side stream subscription (set by inbound Text frames — never the query string).
struct DeltaSubscription {
    stream_key: String,
    from_seq: u64,
    /// The DTO terminal marker rides EVERY page after `Terminal` arrives; this only suppresses
    /// re-sending contentless duplicate pages (the FIRST post-terminal page always ships).
    terminal_sent: bool,
    /// Absent answers are delivered once per subscription request (an admitting `Begin` later
    /// resumes normal delivery — its pages read `absent: false`).
    absent_sent: bool,
}

async fn delta_stream_transport(
    State(state): State<TransportState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response {
    if !is_websocket_upgrade(request.headers()) {
        // Plain GET: the ordinary handle() path — consumes NO subscriber slot.
        return handle_http(
            state,
            peer.ip(),
            routes::PATH_LLM_DELTAS_STREAM.into(),
            request,
        )
        .await;
    }

    let (mut parts, _body) = request.into_parts();
    let headers = parts.headers.clone();
    let token = websocket_bearer(&headers);
    let origin = header_string(&headers, ORIGIN.as_str());
    let api_version = websocket_version(&headers);
    // The subscribe-time seed pass IS the initial re-auth anchor (§2.4: start-anchored — the
    // deadline is well-defined before any beat completes), so capture the beat-START instant
    // BEFORE dispatching the full handle() pass.
    let seed_start = tokio::time::Instant::now();
    let seed_request = ClientRequest {
        api_version,
        method: Method::Get,
        path: routes::PATH_LLM_DELTAS_STREAM.into(),
        session_token: token.clone(),
        origin: origin.clone(),
        csrf_token: None,
        idempotency_key: None,
        is_loopback_peer: peer.ip().is_loopback(),
        body: Value::Null,
    };
    // ONE full handle() seed pass — spawn_blocking + dispatch permit, the events-WS pattern
    // (see `event_stream_transport` for the permit-ownership rationale).
    let seed = match state.dispatch.clone().try_acquire_owned() {
        Ok(permit) => {
            let seed_api = Arc::clone(&state.api);
            match tokio::task::spawn_blocking(move || {
                let _permit = permit;
                seed_api.handle(seed_request)
            })
            .await
            {
                Ok(envelope) => envelope,
                Err(_) => transport_error(
                    ClientErrorCode::ModuleUnavailable,
                    "delta stream unavailable",
                ),
            }
        }
        Err(_) => transport_error(
            ClientErrorCode::ModuleUnavailable,
            "server at dispatch capacity",
        ),
    };
    if seed.is_err() {
        return envelope_response(seed);
    }

    // Subscriber permit: acquired by the async transport AFTER the successful seed, moved into
    // the pump, RAII-released on ANY exit including panic — handle() never touches it. Overflow
    // maps to the EXISTING stream_backpressure → 429 (refused at the seed stage, no upgrade);
    // a hub missing its detector/hold closure refuses with module_unavailable (fail closed).
    let Some(hub) = state.api.llm_delta_hub() else {
        return envelope_response(transport_error(
            ClientErrorCode::ModuleUnavailable,
            "llm delta hub not wired",
        ));
    };
    let permit = match hub.subscribe() {
        Ok(permit) => permit,
        Err(error) => return envelope_response(error_envelope(error)),
    };
    // Subscribe-time session lifetime cap (§2.11): resolved once, before the upgrade.
    let subscribe_now_ms = state.api.now_millis();
    let expires_at_ms = token
        .as_deref()
        .and_then(|t| state.api.session_expires_at(t));

    let ws = match WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
        Ok(ws) => ws,
        Err(rejection) => return rejection.into_response(),
    };
    let api = Arc::clone(&state.api);
    let dispatch = state.dispatch.clone();
    ws.protocols([CLIENT_WS_PROTOCOL])
        .on_upgrade(move |socket| async move {
            let exit = delta_pump(
                socket,
                Arc::clone(&api),
                dispatch,
                peer.ip(),
                token,
                origin,
                hub,
                permit,
                seed,
                seed_start,
                expires_at_ms,
                subscribe_now_ms,
            )
            .await;
            #[cfg(feature = "test-support")]
            if let Some(observer) = api.delta_pump_observer() {
                observer(exit);
            }
            #[cfg(not(feature = "test-support"))]
            {
                let _ = (exit, api);
            }
        })
}

/// The tee T2 pump. Obligations (§2.4, arm count free): wake on the hub generation watch
/// (armed-then-recheck); service `socket.recv`; re-auth every CADENCE through the FULL
/// `handle()` pipeline on the blocking pool under a dispatch permit (anchor = the beat's START,
/// promoted ONLY on success; saturation = no in-beat retry, no anchor refresh); an auth-failure
/// verdict cuts IMMEDIATELY; the unconditional `sleep_until(anchor + REAUTH_MAX_AGE)` cut; the
/// subscribe-time `expires_at` cut; ping every beat with the pong required by the next beat;
/// socket-error legs cut within the beat.
#[allow(clippy::too_many_arguments)]
async fn delta_pump(
    mut socket: WebSocket,
    api: Arc<ClientApi>,
    dispatch: Arc<Semaphore>,
    peer_ip: IpAddr,
    token: Option<String>,
    origin: Option<String>,
    hub: Arc<LlmDeltaHub>,
    permit: DeltaSubscriberPermit,
    seed: ClientEnvelope<Value>,
    seed_start: tokio::time::Instant,
    expires_at_ms: Option<u64>,
    subscribe_now_ms: u64,
) -> DeltaPumpExit {
    // The RAII subscriber permit lives exactly as long as this pump — any return OR panic
    // unwind through this frame releases the slot.
    let _permit = permit;
    let timing = hub.timing();
    let codec = api.cursor_codec();
    let mut gen_rx = hub.generation_watch();
    let mut subscription: Option<DeltaSubscription> = None;

    // Seed envelope down the socket first (events-WS pattern).
    if send_envelope(&mut socket, &seed).await.is_err() {
        let _ = socket.send(Message::Close(None)).await;
        return DeltaPumpExit::PeerDead;
    }

    // Start-anchored re-auth deadline, seeded by the subscribe-time handle() pass. The anchor,
    // monotonic promotion and deadline are the production `ReauthDeadline` state machine (the
    // SAME code U-14 witnesses) — no parallel inline copy. It ticks in nanoseconds relative to
    // `seed_start` (byte-exact with `tokio::time::Instant`, which has ns resolution): the ns tick
    // reconstructs the Instant with no loss, so the cut timing is unchanged. `seed_start` is tick
    // 0 (the initial anchor).
    let deadline_base = seed_start;
    let ticks_since_base =
        |i: tokio::time::Instant| i.saturating_duration_since(deadline_base).as_nanos() as u64;
    let instant_at_ticks = |ticks: u64| deadline_base + Duration::from_nanos(ticks);
    let mut reauth_deadline = ReauthDeadline::seed(0, timing.reauth_max_age.as_nanos() as u64);
    // Session lifetime cap. An unresolvable session (revoked in the seed→upgrade window) cuts
    // immediately; an unrepresentably far expiry disables the arm (never a panic).
    let expiry_deadline: Option<tokio::time::Instant> = match expires_at_ms {
        None => Some(tokio::time::Instant::now()),
        Some(at) => tokio::time::Instant::now()
            .checked_add(Duration::from_millis(at.saturating_sub(subscribe_now_ms))),
    };

    let mut beat = tokio::time::interval(timing.cadence);
    beat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Consume the immediate tick; the seed pass is beat zero.
    beat.tick().await;
    // FIX 5: correlate the pong. Only the Pong echoing the outstanding ping's monotonic nonce
    // clears the wait — an unsolicited / garbage Pong from a write-only half-open peer can no
    // longer keep a dead slot alive forever.
    let mut outstanding_ping: Option<u64> = None;
    let mut next_ping_id: u64 = 0;
    // FIX 2: the single in-flight detached re-auth for THIS connection. A re-auth that overruns
    // `allowance` detaches (the `spawn_blocking` closure keeps running and holds its shared
    // `dispatch` permit until `handle()` returns); we KEEP its JoinHandle here and refuse to start
    // a new re-auth beat while it is still unfinished, so a `handle()` slower than the cadence can
    // no longer accumulate `ceil(handle_time/cadence)` concurrent detached tasks each pinning a
    // permit. At most ONE dispatch permit per connection at a time — the pre-fix invariant.
    let mut reauth_inflight: Option<JoinHandle<ClientEnvelope<Value>>> = None;

    let exit = 'pump: loop {
        // Armed-then-recheck: mark the current generation seen, THEN read pages — a publish
        // racing this point re-fires `changed()` on the next select.
        {
            let _ = gen_rx.borrow_and_update();
        }

        // FIX 1 / FIX 4: the most-imminent cut instant — the nearer of the start-anchored re-auth
        // deadline and the subscribe-time `expires_at`. A send must never outlive it, and a page
        // must never ship to a session already past it.
        let reauth_cut = instant_at_ticks(reauth_deadline.deadline());
        let imminent_cut = match expiry_deadline {
            Some(exp) => reauth_cut.min(exp),
            None => reauth_cut,
        };
        // The reason the imminent cut carries: `expires_at` only when it is the nearer bound.
        let imminent_reason = match expiry_deadline {
            Some(exp) if exp <= reauth_cut => DeltaPumpExit::ExpiresAt,
            _ => DeltaPumpExit::ReauthDeadline,
        };

        // FIX 4: gate delivery on the imminent cut — an already-past instant cuts NOW, before a
        // page can ship to an already-revoked / expired session (with the biased cut arms below,
        // this closes the unconditional-pre-select-delivery escape).
        if tokio::time::Instant::now() >= imminent_cut {
            break imminent_reason;
        }

        // FIX 1: bound the whole delivery (its `socket.send` + flush) by the imminent cut, so the
        // cut fires while a send is in flight. A peer that stops reading applies TCP backpressure;
        // without this bound the blocking send parks the pump forever and a revoked session keeps
        // receiving post-revocation pages. On elapse we STOP delivering and cut; the immediate
        // Close below still runs and the RAII subscriber permit still drops.
        match tokio::time::timeout_at(
            imminent_cut,
            deliver_pending(&mut socket, &hub, codec.as_deref(), &mut subscription),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(())) => break DeltaPumpExit::PeerDead,
            Err(_) => break imminent_reason,
        }

        tokio::select! {
            // FIX 4: biased — the cut arms (deadline / expiry) and the beat (which carries the
            // auth-failure and pong-timeout cuts) are polled BEFORE the deliver/recv arms, so a
            // due cut always wins over a ready page or a ready inbound frame.
            biased;
            // Unconditional revocation-cut deadline (start-anchored): fires on or off the beat
            // grid; a saturated / failed / overrunning beat never pushed the anchor, so this holds.
            _ = tokio::time::sleep_until(reauth_cut) => {
                break DeltaPumpExit::ReauthDeadline;
            }
            // Subscribe-time session lifetime cap.
            _ = async { tokio::time::sleep_until(expiry_deadline.unwrap()).await },
                if expiry_deadline.is_some() =>
            {
                break DeltaPumpExit::ExpiresAt;
            }
            _ = beat.tick() => {
                // FIX 3: observe ALREADY-ARRIVED frames before judging the pong deadline (keeps
                // the pong-race fix), but CAP the drain per wake and always yield back to the
                // select — an inbound flood can no longer starve the cut / deadline arms, and the
                // per-frame error-envelope write is bounded per wake.
                for _ in 0..DELTA_INBOUND_DRAIN_PER_BEAT {
                    match tokio::time::timeout(Duration::ZERO, socket.recv()).await {
                        Err(_) => break, // nothing buffered
                        Ok(incoming) => {
                            if let Err(exit) = handle_delta_socket_message(
                                incoming,
                                &mut socket,
                                codec.as_deref(),
                                &mut subscription,
                                &mut outstanding_ping,
                                imminent_cut,
                                imminent_reason,
                            )
                            .await
                            {
                                break 'pump exit;
                            }
                        }
                    }
                }
                // FIX 5: half-open detection — the pong echoing the PREVIOUS beat's ping nonce
                // must have arrived by this beat (~2 beats wall from failure, B3(ii)); an
                // uncorrelated Pong no longer clears the wait.
                if outstanding_ping.is_some() {
                    break DeltaPumpExit::PongTimeout;
                }
                // Ping every beat with a fresh monotonic nonce; a ping-SEND error is the same
                // dead-peer class (B3(ii)). Bound the send by the imminent cut so a non-reading
                // peer cannot park the beat past the deadline.
                let ping_id = next_ping_id;
                next_ping_id = next_ping_id.wrapping_add(1);
                match tokio::time::timeout_at(
                    imminent_cut,
                    socket.send(Message::Ping(ping_id.to_be_bytes().to_vec().into())),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => break DeltaPumpExit::PeerDead,
                    Err(_) => break imminent_reason,
                }
                outstanding_ping = Some(ping_id);
                // Re-auth through the FULL handle() pipeline on the blocking pool under a dispatch
                // permit. The anchor candidate is this beat's START instant, promoted ONLY on a
                // successful verdict. A saturated permit neither retries in-beat nor refreshes the
                // anchor — saturation fails CLOSED toward the deadline cut.
                let beat_start = tokio::time::Instant::now();
                // FIX 2: reclaim the slot once a prior detached re-auth has finished (its permit is
                // already released), and while one is still outstanding COALESCE this beat's re-auth
                // — no new permit, no anchor refresh — so the connection pins at most ONE dispatch
                // permit at a time. Skipping does NOT touch the anchor, so the fail-closed deadline
                // timing is unchanged and the unconditional cut still fires on schedule.
                if let Some(inflight) = reauth_inflight.as_ref() {
                    if inflight.is_finished() {
                        reauth_inflight = None;
                    }
                }
                if reauth_inflight.is_none() {
                    match dispatch.clone().try_acquire_owned() {
                        Err(_) => {}
                        Ok(permit) => {
                            let request = ClientRequest {
                                api_version: API_VERSION.to_string(),
                                method: Method::Get,
                                path: routes::PATH_LLM_DELTAS_STREAM.into(),
                                session_token: token.clone(),
                                origin: origin.clone(),
                                csrf_token: None,
                                idempotency_key: None,
                                is_loopback_peer: peer_ip.is_loopback(),
                                body: Value::Null,
                            };
                            let worker_api = Arc::clone(&api);
                            // Bound the re-auth join by `allowance` via a MUTABLE borrow of the
                            // JoinHandle so an overrun can KEEP the handle (the task detaches and
                            // holds its permit until handle() returns, but we still track it to
                            // coalesce the next beat) instead of dropping it. An overrun does NOT
                            // refresh the anchor (fail-closed): the unconditional deadline still
                            // fires on schedule.
                            let mut join = tokio::task::spawn_blocking(move || {
                                let _permit = permit;
                                worker_api.handle(request)
                            });
                            match tokio::time::timeout(timing.allowance, &mut join).await {
                                Ok(Ok(envelope)) if envelope.is_ok() => {
                                    // Promote the anchor to this beat's START (monotonic — an
                                    // out-of-order older success never regresses it).
                                    reauth_deadline
                                        .record_success_start(ticks_since_base(beat_start));
                                }
                                // A failure verdict (revocation/expiry/scope loss/kill switch) or a
                                // panic escaping handle(): cut IMMEDIATELY (§2.4 A1).
                                Ok(Ok(_)) | Ok(Err(_)) => break DeltaPumpExit::AuthFailureImmediate,
                                // Re-auth overran `allowance`: KEEP the detached handle so the next
                                // beat coalesces until it finishes (one permit at a time); no anchor
                                // refresh; fail closed toward the deadline cut.
                                Err(_) => reauth_inflight = Some(join),
                            }
                        }
                    }
                }
            }
            changed = gen_rx.changed() => {
                if changed.is_err() {
                    // Hub dropped (teardown): end the pump as an orderly close.
                    break DeltaPumpExit::PeerClosed;
                }
            }
            incoming = socket.recv() => {
                if let Err(exit) = handle_delta_socket_message(
                    incoming,
                    &mut socket,
                    codec.as_deref(),
                    &mut subscription,
                    &mut outstanding_ping,
                    imminent_cut,
                    imminent_reason,
                )
                .await
                {
                    break exit;
                }
            }
        }
    };
    // Immediate cut: close without flushing any queued page — no delta frame after the close.
    // Bound the courtesy Close by `allowance` so a non-reading peer cannot park the pump (and
    // hold its RAII subscriber slot) after the cut has been decided.
    let _ = tokio::time::timeout(timing.allowance, socket.send(Message::Close(None))).await;
    exit
}

/// Handle one inbound socket message for the delta pump. `Err(exit)` = cut with that reason.
///
/// Text frames carry the stream-selection/resume request ([`LlmDeltaStreamRequest`],
/// both-or-neither — never the query string); an invalid request is REJECTED with an error
/// envelope while the socket stays up. Close/`None` ⇒ `peer_closed`; a recv or reply-send
/// error ⇒ `peer_dead` (B3(ii)).
///
/// FIX 1: EVERY reply this performs — the invalid-request error envelope AND the Ping→Pong echo —
/// is bounded by `imminent_cut`, the pump's most-imminent re-auth/expiry cut instant. A peer that
/// stops reading its socket and floods inbound invalid-Text / Ping frames drives these replies into
/// TCP backpressure; without the bound the reply-send parks the pump inside this function, the
/// `select!` stops being polled, and the re-auth deadline / expiry / auth-failure cut arms never
/// fire — a revoked session lives unbounded and leaks its RAII subscriber permit. On elapse the
/// reply is abandoned and the pump is cut with `imminent_reason` (the peer that will not accept our
/// replies is exactly the peer we must cut). A send that ERRORS (not merely times out) is still the
/// dead-peer class ⇒ `peer_dead`.
async fn handle_delta_socket_message(
    incoming: Option<Result<Message, axum::Error>>,
    socket: &mut WebSocket,
    codec: Option<&dyn ClientCursorCodec>,
    subscription: &mut Option<DeltaSubscription>,
    outstanding_ping: &mut Option<u64>,
    imminent_cut: tokio::time::Instant,
    imminent_reason: DeltaPumpExit,
) -> Result<(), DeltaPumpExit> {
    match incoming {
        Some(Ok(Message::Text(text))) => {
            match serde_json::from_str::<LlmDeltaStreamRequest>(&text)
                .map_err(|_| {
                    ClientError::new(
                        ClientErrorCode::InvalidState,
                        "invalid delta stream request",
                    )
                })
                .and_then(|request| resolve_stream_request(codec, &request))
            {
                Ok((stream_key, from_seq)) => {
                    *subscription = Some(DeltaSubscription {
                        stream_key,
                        from_seq,
                        terminal_sent: false,
                        absent_sent: false,
                    });
                    Ok(())
                }
                Err(error) => {
                    // Reject the REQUEST (both-or-neither shape, cross-domain or tampered
                    // cursor, plaintext↔sealed key mismatch); the error envelope is the
                    // answer and the socket stays up. FIX 1: bound the reply by `imminent_cut`
                    // so a non-reading peer's backpressure cannot park the pump past the cut.
                    match tokio::time::timeout_at(
                        imminent_cut,
                        send_envelope(socket, &error_envelope(error)),
                    )
                    .await
                    {
                        Ok(Ok(())) => Ok(()),
                        Ok(Err(())) => Err(DeltaPumpExit::PeerDead),
                        Err(_) => Err(imminent_reason),
                    }
                }
            }
        }
        Some(Ok(Message::Ping(bytes))) => {
            // FIX 1: bound the Pong echo by `imminent_cut` — an inbound Ping flood from a peer that
            // stops reading must not park the pump inside this reply-send past the cut.
            match tokio::time::timeout_at(imminent_cut, socket.send(Message::Pong(bytes))).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(_)) => Err(DeltaPumpExit::PeerDead),
                Err(_) => Err(imminent_reason),
            }
        }
        Some(Ok(Message::Pong(bytes))) => {
            // FIX 5: only the Pong echoing the OUTSTANDING ping's monotonic nonce clears the
            // wait; an unsolicited or garbage Pong (a write-only half-open peer) does not, so a
            // peer that never answers the actual ping is still cut at the pong deadline.
            if let Some(expected) = *outstanding_ping {
                if bytes.len() >= 8
                    && u64::from_be_bytes(bytes[..8].try_into().unwrap()) == expected
                {
                    *outstanding_ping = None;
                }
            }
            Ok(())
        }
        Some(Ok(Message::Binary(_))) => Ok(()),
        Some(Ok(Message::Close(_))) | None => Err(DeltaPumpExit::PeerClosed),
        Some(Err(_)) => Err(DeltaPumpExit::PeerDead),
    }
}

/// Drain noteworthy pages for the live subscription. Pages are assembled ONLY by
/// `hub.read_page` (release-gated; the ≤64-KiB copy happens under the per-stream lock inside
/// it) and the socket send happens AFTER that lock is released (`read_page` returns an owned
/// page). Bounded per wake; the generation watch re-fires for anything left over.
async fn deliver_pending(
    socket: &mut WebSocket,
    hub: &LlmDeltaHub,
    codec: Option<&dyn ClientCursorCodec>,
    subscription: &mut Option<DeltaSubscription>,
) -> Result<(), ()> {
    let Some(sub) = subscription.as_mut() else {
        return Ok(());
    };
    for _ in 0..64 {
        let page = hub.read_page(&sub.stream_key, sub.from_seq);
        let noteworthy = !page.deltas.is_empty()
            || (page.terminal.is_some() && !sub.terminal_sent)
            || (page.absent && !sub.absent_sent);
        if !noteworthy {
            return Ok(());
        }
        if let Some(last) = page.deltas.last() {
            sub.from_seq = last.to_seq.saturating_add(1);
        }
        if page.terminal.is_some() {
            sub.terminal_sent = true;
        }
        sub.absent_sent = page.absent;
        let wire = LlmDeltaWirePage::seal_from(page, codec);
        let value = serde_json::to_value(&wire).map_err(|_| ())?;
        let envelope = ClientEnvelope::ok(new_transport_request_id(), value, vec![]);
        send_envelope(socket, &envelope).await?;
    }
    Ok(())
}

async fn send_envelope(socket: &mut WebSocket, envelope: &ClientEnvelope<Value>) -> Result<(), ()> {
    let encoded = serde_json::to_string(envelope).map_err(|_| ())?;
    socket
        .send(Message::Text(encoded.into()))
        .await
        .map_err(|_| ())
}

fn envelope_response(envelope: ClientEnvelope<Value>) -> Response {
    let status = envelope
        .error
        .as_ref()
        .map(|error| status_for(&error.code))
        .unwrap_or(StatusCode::OK);
    (status, Json(envelope)).into_response()
}

fn status_for(code: &ClientErrorCode) -> StatusCode {
    match code {
        ClientErrorCode::Unauthenticated
        | ClientErrorCode::SessionExpired
        | ClientErrorCode::InvalidBootstrapCode => StatusCode::UNAUTHORIZED,
        ClientErrorCode::CsrfRequired
        | ClientErrorCode::CsrfInvalid
        | ClientErrorCode::OriginNotAllowed
        | ClientErrorCode::RemoteBindForbidden
        | ClientErrorCode::ReplyNotAuthorized
        | ClientErrorCode::Forbidden => StatusCode::FORBIDDEN,
        ClientErrorCode::UnknownRoute | ClientErrorCode::NotFound => StatusCode::NOT_FOUND,
        ClientErrorCode::RequestTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        ClientErrorCode::ModuleUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        ClientErrorCode::StreamBackpressure | ClientErrorCode::IdempotencyCapacity => {
            StatusCode::TOO_MANY_REQUESTS
        }
        ClientErrorCode::IdempotencyInProgress
        | ClientErrorCode::IdempotencyConflict
        | ClientErrorCode::InvalidState => StatusCode::CONFLICT,
        ClientErrorCode::ProjectionRejected => StatusCode::UNPROCESSABLE_ENTITY,
        ClientErrorCode::UnsupportedApiVersion
        | ClientErrorCode::IdempotencyRequired
        | ClientErrorCode::Unknown => StatusCode::BAD_REQUEST,
    }
}

fn transport_error(code: ClientErrorCode, message: &'static str) -> ClientEnvelope<Value> {
    error_envelope(ClientError::new(code, message))
}

fn error_envelope(error: ClientError) -> ClientEnvelope<Value> {
    ClientEnvelope::error(new_transport_request_id(), error, vec![])
}

fn new_transport_request_id() -> String {
    format!("req_{}", uuid::Uuid::new_v4().simple())
}

fn header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    header_string(headers, AUTHORIZATION.as_str())
        .and_then(|value| value.strip_prefix("Bearer ").map(str::to_owned))
        .filter(|value| !value.is_empty())
}

fn websocket_bearer(headers: &HeaderMap) -> Option<String> {
    header_string(headers, SEC_WEBSOCKET_PROTOCOL.as_str()).and_then(|value| {
        value.split(',').map(str::trim).find_map(|protocol| {
            protocol
                .strip_prefix(BEARER_PROTOCOL_PREFIX)
                .filter(|token| !token.is_empty())
                .map(str::to_owned)
        })
    })
}

fn websocket_version(headers: &HeaderMap) -> String {
    let offered = header_string(headers, SEC_WEBSOCKET_PROTOCOL.as_str()).unwrap_or_default();
    if offered
        .split(',')
        .map(str::trim)
        .any(|p| p == CLIENT_WS_PROTOCOL)
    {
        API_VERSION.to_string()
    } else {
        "unsupported-websocket-protocol".to_string()
    }
}

fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get("upgrade")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_values_are_bounded_typed_dtos() {
        assert_eq!(
            query_body(Some("limit=4&agent_id=a%2Fb")),
            serde_json::json!({"limit": 4, "agent_id": "a/b"})
        );
    }

    #[test]
    fn websocket_token_is_not_read_from_query_or_authorization() {
        let mut headers = HeaderMap::new();
        headers.insert(
            SEC_WEBSOCKET_PROTOCOL,
            format!("{CLIENT_WS_PROTOCOL}, {BEARER_PROTOCOL_PREFIX}abc123")
                .parse()
                .unwrap(),
        );
        headers.insert(AUTHORIZATION, "Bearer ignored".parse().unwrap());
        assert_eq!(websocket_bearer(&headers).as_deref(), Some("abc123"));
        assert_eq!(websocket_version(&headers), API_VERSION);
    }
}

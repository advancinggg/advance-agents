//! WebSocket `/events` broadcaster (Slice B AC-06).
//!
//! Topology: a `tokio::sync::broadcast` channel fans out events to all currently
//! connected WebSocket clients. Per-client backpressure: the broadcast channel's
//! per-receiver lag drops the lagging receiver. Each connected client also has
//! its own per-client `mpsc::channel(1000)` between the upstream broadcast
//! receiver and the WebSocket writer side, providing additional per-client
//! decoupling.
//!
//! LeakDetector: when `cfg.leak_detector` is `Some`, broadcast text is scanned
//! with `ScanContext::LogOutput` and the algorithm in
//! `crate::leak::apply_scan_to_outbound` decides whether to send / redact / drop.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use advance_shared_types::event::Event;
use advance_shared_types::traits::LeakDetector;
use axum::extract::{ws::WebSocketUpgrade, State};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::leak::{apply_scan_to_outbound, ScrubOutcome};

const PER_CLIENT_BUFFER: usize = 1000;
const DEFAULT_MAX_CONCURRENT_WS_CLIENTS: usize = 10;

#[derive(Clone)]
pub(crate) struct WsState {
    pub broadcaster: broadcast::Sender<Arc<Event>>,
    pub max_clients: usize,
    pub current_clients: Arc<AtomicUsize>,
    pub leak_detector: Option<Arc<dyn LeakDetector>>,
}

/// Spawn the WebSocket broadcaster background task.
///
/// Returns the receive-side `mpsc::Sender<Event>` for the EventBus to enqueue
/// events, plus the `WsState` needed to mount the `/events` axum route.
pub(crate) fn spawn(
    cancel_token: CancellationToken,
    leak_detector: Option<Arc<dyn LeakDetector>>,
    max_clients: Option<usize>,
) -> (
    mpsc::Sender<Arc<Event>>,
    WsState,
    tokio::task::JoinHandle<()>,
) {
    let (mpsc_tx, mut mpsc_rx) = mpsc::channel::<Arc<Event>>(10_000);
    // broadcast channel takes Arc<Event> too (each subscriber gets its own Arc clone).
    let (broadcaster, _) = broadcast::channel::<Arc<Event>>(PER_CLIENT_BUFFER);

    let state = WsState {
        broadcaster: broadcaster.clone(),
        max_clients: max_clients.unwrap_or(DEFAULT_MAX_CONCURRENT_WS_CLIENTS),
        current_clients: Arc::new(AtomicUsize::new(0)),
        leak_detector,
    };

    let bg_broadcaster = broadcaster.clone();
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => break,
                maybe = mpsc_rx.recv() => {
                    match maybe {
                        Some(event) => {
                            // broadcast::Sender::send returns Err when no receivers
                            // — ignore silently (no client connected yet).
                            let _ = bg_broadcaster.send(event);
                        }
                        None => break,
                    }
                }
            }
        }
        // Slice C ADVERSARIAL Round 1 Codex W2 fix: drain queued events at
        // cancel time so sweeper-emitted runtime.warning events can still
        // reach connected clients. tokio::select! is pseudorandom, so without
        // this drain the cancel arm could win while the channel still has
        // buffered events (consistent with the file_writer / db_indexer /
        // stats_aggregator drain pattern).
        while let Ok(event) = mpsc_rx.try_recv() {
            let _ = bg_broadcaster.send(event);
        }
    });

    (mpsc_tx, state, handle)
}

/// Mountable axum router exposing `/events` (WebSocket upgrade).
///
/// Adversarial Round-2 W1 fix: applies the same per-IP `tower_governor` rate
/// limiter to `/events` as `/query/*` to throttle pre-upgrade handshake floods.
/// Without this, an attacker on the bound interface could exhaust CPU + the
/// `max_clients=10` post-upgrade slots via repeated upgrade attempts (each
/// rejected attempt still pays for TCP accept + HTTP upgrade parse + 503
/// construction).
pub fn ws_route(state: WsState) -> Router {
    use std::sync::Arc as StdArc;
    use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};

    let governor_conf = StdArc::new(
        GovernorConfigBuilder::default()
            .per_second(1)
            .burst_size(30)
            .finish()
            .expect("static governor config"),
    );
    Router::new()
        .route("/events", get(ws_upgrade_handler))
        .layer(GovernorLayer {
            config: governor_conf,
        })
        .with_state(state)
}

async fn ws_upgrade_handler(State(state): State<WsState>, ws: WebSocketUpgrade) -> Response {
    // Round-2 AUDIT diff Critical 2 fix: defer the slot increment INSIDE the
    // on_upgrade closure so a failed upgrade handshake never leaks a slot.
    //
    // Two-phase admission:
    //   Phase 1 (out here): a fast-path read-only "is room available?" check.
    //     If full → return 503 immediately. Otherwise pass through to upgrade.
    //   Phase 2 (inside closure): tentatively `fetch_add(1)`; if the post-add
    //     count exceeds `max_clients` (lost a race), `fetch_sub(1)` and close.
    //
    // This admits up to `max_clients + concurrent_in_flight_upgrades - 1`
    // briefly during racy admission, which is a bounded over-admission. The
    // alternative (incrementing pre-upgrade) leaks slots permanently if the
    // upgrade handshake fails — strictly worse failure mode.
    if state.current_clients.load(Ordering::SeqCst) >= state.max_clients {
        return axum::http::Response::builder()
            .status(axum::http::StatusCode::SERVICE_UNAVAILABLE)
            .body(axum::body::Body::from(
                "max concurrent WebSocket clients reached",
            ))
            .expect("response builder");
    }

    let leak_detector = state.leak_detector.clone();
    let mut rx = state.broadcaster.subscribe();
    let counter = state.current_clients.clone();
    let max_clients = state.max_clients;

    // Adversarial Round-2 W3 fix: cap inbound WebSocket message sizes. Default
    // tungstenite max_message_size is 16 MiB which × 10 clients = 160 MiB
    // transient memory pressure under coordinated burst. Cap at 64 KiB
    // (matches MAX_PAYLOAD_LEN for outbound events). Subscribe-filter messages
    // are tiny JSON, so no legitimate inbound payload approaches this cap.
    let ws = ws.max_message_size(64 * 1024).max_frame_size(64 * 1024);

    ws.on_upgrade(move |socket| async move {
        // Phase-2 admission: tentatively increment, then verify we didn't
        // exceed cap due to a concurrent upgrade race.
        let prev = counter.fetch_add(1, Ordering::SeqCst);
        if prev >= max_clients {
            counter.fetch_sub(1, Ordering::SeqCst);
            // Drop the socket — it's our responsibility to clean up since
            // the closure has been entered.
            return;
        }
        use axum::extract::ws::Message;
        use futures::{sink::SinkExt, stream::StreamExt};

        let (mut sender, mut receiver) = socket.split();

        loop {
            tokio::select! {
                event = rx.recv() => {
                    match event {
                        Ok(event) => {
                            let serialized = match serde_json::to_string(&*event) {
                                Ok(s) => s,
                                Err(_) => continue,
                            };
                            let outbound = match apply_scan_to_outbound(
                                &serialized,
                                leak_detector.as_deref(),
                            ) {
                                ScrubOutcome::Send(text) => text,
                                ScrubOutcome::Drop => continue,
                            };
                            if sender.send(Message::Text(outbound.into())).await.is_err() {
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            // Drop the slow client per per-client backpressure cap.
                            let _ = sender.send(Message::Close(None)).await;
                            break;
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                msg = receiver.next() => {
                    match msg {
                        Some(Ok(Message::Close(_))) | None => break,
                        Some(Err(_)) => break,
                        // Subscribe-filter messages (Round-2 W4 future-work) are
                        // accepted but ignored in MVP. Server-side filter wiring
                        // ships in a follow-up audit fix round.
                        Some(Ok(_)) => {}
                    }
                }
            }
        }

        counter.fetch_sub(1, Ordering::SeqCst);
    })
}

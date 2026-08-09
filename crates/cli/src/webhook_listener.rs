//! Stage-F obs SLICE 2 — production axum `WebhookSource` (SYS-AC-105).
//!
//! The security core (`verify_webhook`, 413→401→200) and the runnable-run path
//! (production `WasmRunnableHook` + the unified watcher path) are already built;
//! the only missing piece was a live HTTP listener. [`WebhookListener`] is the
//! production impl of `advance_scheduler::hook::WebhookSource`: it binds an HTTP
//! port, validates each POST's HMAC via `verify_webhook`, and on success sends a
//! `TriggerFireEvent{trigger_type: "webhook"}` into the watcher's channel.
//!
//! It is DISTINCT from the channel-adapter `/hooks/{route}` listener
//! (`channels_boot.rs`): a different bind address + a per-trigger `cfg.path` route
//! namespace, so the two never shadow each other.
//!
//! NAMED residuals (out of this slice's scope — see MODULE-014 §3.7):
//! - **multi-webhook**: `WebhookSource::run` is invoked per webhook-triggered
//!   component on the SHARED `Arc<dyn WebhookSource>`; this listener binds its own
//!   addr per `run`, correct for a SINGLE active webhook. Multiple webhook
//!   components on one bind addr collide (bind-in-use → `HookError::Failure`,
//!   surfaced not panicked) — production needs a path-keyed multiplexer.
//! - **DoS hardening** (adversarial W1): like the EXISTING channel `/hooks` listener
//!   (`channels_boot.rs` — `DefaultBodyLimit` + raw `axum::serve`, no tower layers),
//!   this listener bounds per-request memory (1 MiB `DefaultBodyLimit`) but has no
//!   connection-concurrency cap / read-idle timeout (slowloris). That is a project-wide
//!   HTTP-listener-pattern + production-deployment concern (front with a reverse proxy /
//!   tower limits when the listener is wired) — out of this seam's scope.
//! - **replay** (adversarial W3): `verify_webhook` (pre-existing, shipped 2026-06-09)
//!   authenticates body bytes only — no nonce/timestamp freshness. Adding replay
//!   protection is a `verify_webhook` enhancement, not this listener seam.
//! - **persisted secret**: `ComponentRegistry::insert` redacts
//!   `WebhookConfig.secret`, so a persisted webhook materializes with `secret:
//!   None`. The listener FAILS CLOSED on a missing/weak secret (refuses to bind —
//!   no unauthenticated endpoint, defense-in-depth over `verify_webhook`'s
//!   per-request 401), so production wiring MUST re-hydrate the secret before the
//!   listener can serve at all.

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use advance_scheduler::hook::{HookError, WebhookSource};
use advance_scheduler::trigger_source::TriggerFireEvent;
use advance_scheduler::types::{TriggerContext, WebhookConfig};
use advance_scheduler::webhook_hmac::{
    verify_webhook, MIN_WEBHOOK_SECRET_BYTES, WEBHOOK_MAX_BODY_BYTES,
};

/// HTTP header carrying the hex HMAC-SHA256 signature of the request body.
const SIGNATURE_HEADER: &str = "x-signature";

/// Production axum-backed [`WebhookSource`].
pub struct WebhookListener {
    bind_addr: SocketAddr,
    /// Test-support: reports the bound `SocketAddr` (ephemeral port when binding
    /// `:0`) after a successful bind, so an integration test can POST to it.
    /// `None` in production. Interior mutability because `WebhookSource::run`
    /// takes `&self` while `oneshot::Sender::send` consumes the sender by value.
    ready: Mutex<Option<oneshot::Sender<SocketAddr>>>,
}

impl WebhookListener {
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self {
            bind_addr,
            ready: Mutex::new(None),
        }
    }

    /// Test-support builder: install a one-shot that `run` fires with the bound
    /// address once the listener is up. Production never sets this.
    pub fn with_ready_signal(self, tx: oneshot::Sender<SocketAddr>) -> Self {
        *self.ready.lock().unwrap() = Some(tx);
        self
    }
}

/// axum handler state. `Clone` (required by `State`): `WebhookConfig` is `Clone`,
/// `mpsc::Sender` is `Clone`.
#[derive(Clone)]
struct ListenerState {
    cfg: WebhookConfig,
    tx: mpsc::Sender<TriggerFireEvent>,
}

/// Reject paths that would panic `axum::Router::route`. A literal webhook path is
/// `/` + plain segment(s); axum 0.8 PANICS on capture/wildcard grammar, so reject
/// any `{` `}` (capture braces), `:` `*` (axum<0.8 / matchit param + wildcard
/// segment starts — still rejected by the 0.8 path-router), and `?` `#` / control
/// / whitespace (query/fragment confusion). Untrusted `cfg.path` → never panic.
fn is_valid_route_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() >= 2
        && path.chars().all(|c| {
            !matches!(c, '{' | '}' | ':' | '*' | '?' | '#') && !c.is_whitespace() && !c.is_control()
        })
}

fn epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

async fn handle_webhook(
    State(state): State<ListenerState>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let provided_sig = headers.get(SIGNATURE_HEADER).and_then(|v| v.to_str().ok());
    // 413 (oversized) → 401 (bad/missing sig or weak secret) → Ok.
    if let Err(rejection) = verify_webhook(&state.cfg, &body, provided_sig, WEBHOOK_MAX_BODY_BYTES)
    {
        return StatusCode::from_u16(rejection.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    }
    // Verified — fire the trigger. Bounded payload: the body is already capped at
    // WEBHOOK_MAX_BODY_BYTES (1 MiB) << the 64 MiB TriggerContext wire cap.
    let event = TriggerFireEvent {
        trigger_type: "webhook",
        trigger_context: Some(TriggerContext {
            event_type: "webhook".to_string(),
            timestamp: epoch_millis(),
            payload: body.to_vec(),
            trigger_chain_id: String::new(),
            chain_depth: 0,
        }),
    };
    match state.tx.send(event).await {
        Ok(()) => StatusCode::OK,
        Err(e) => {
            // Verified but the trigger pipeline is gone (channel closed) → 500.
            eprintln!("advance: webhook verified but trigger send failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[async_trait]
impl WebhookSource for WebhookListener {
    async fn run(
        &self,
        cfg: WebhookConfig,
        tx: mpsc::Sender<TriggerFireEvent>,
        cancel: CancellationToken,
    ) -> Result<(), HookError> {
        // (1) Validate cfg.path BEFORE Router::route (axum panics on malformed
        // paths; cfg.path is untrusted and unvalidated at admission).
        if !is_valid_route_path(&cfg.path) {
            return Err(HookError::Failure(format!(
                "webhook listener: invalid route path {:?} (must start with '/', \
                 len >= 2, no capture/wildcard/query chars)",
                cfg.path
            )));
        }
        // (1b) FAIL CLOSED on a missing/weak secret (eval Codex Critical): this is
        // an UNTRUSTED HTTP listener, and `verify_webhook` admits unauthenticated
        // when `cfg.secret` is None (and registry persistence redacts secrets to
        // None). MODULE-014 requires the HTTP listener to demand an explicit
        // secret — so refuse to bind/serve a no-auth webhook rather than expose an
        // unauthenticated endpoint. (Production must re-hydrate the persisted-then-
        // redacted secret BEFORE the listener can serve — named residual.)
        match cfg.secret.as_deref() {
            Some(s) if s.len() >= MIN_WEBHOOK_SECRET_BYTES => {}
            _ => {
                return Err(HookError::Failure(format!(
                    "webhook listener: refusing to serve {:?} without a configured \
                     secret of >= {} bytes (fail-closed — no unauthenticated webhook)",
                    cfg.path, MIN_WEBHOOK_SECRET_BYTES
                )));
            }
        }
        let route = cfg.path.clone();
        let app = Router::new()
            .route(&route, post(handle_webhook))
            .layer(DefaultBodyLimit::max(WEBHOOK_MAX_BODY_BYTES))
            .with_state(ListenerState { cfg, tx });

        // (2) Bind. Bind/port-in-use → HookError::Failure (NEVER panic the walk).
        let listener = tokio::net::TcpListener::bind(self.bind_addr)
            .await
            .map_err(|e| {
                HookError::Failure(format!(
                    "webhook listener: bind {} failed: {e}",
                    self.bind_addr
                ))
            })?;
        let bound = listener
            .local_addr()
            .map_err(|e| HookError::Failure(format!("webhook listener: local_addr failed: {e}")))?;

        // (3) Report the bound addr to a waiting test (no-op in production).
        if let Some(ready) = self.ready.lock().unwrap().take() {
            let _ = ready.send(bound);
        }

        // (4) Serve until cancelled (graceful shutdown).
        axum::serve(listener, app)
            .with_graceful_shutdown(async move { cancel.cancelled().await })
            .await
            .map_err(|e| HookError::Failure(format!("webhook listener: serve error: {e}")))
    }
}

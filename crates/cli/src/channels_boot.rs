//! /dev Phase-2 Step-3 — production daemon channel bring-up (MODULE-001
//! composition root). Consumes the `channels` config block and wires:
//! - a `SubscriptionManager` + per-channel `HostPump` subscriptions,
//! - a `TransportSupervisor` with `/hooks/{route}` routes + channel verifiers,
//! - the in-host `OutboundTransport` (`HttpEgress` over the real
//!   `DefaultHttpSecurityChain`; the channel egress uses no injected credentials
//!   — the bot token rides in the preset `url_template` — so a credential-less
//!   in-memory secret store backs the chain),
//! - an `IdentityResolver` from the channel `user_mappings` (WHO = sender id).
//!
//! `advance start` binds the shared `/hooks` listener + spawns the host pump
//! when (and only when) `channels.webhook_listen_addr` + at least one channel
//! are configured; otherwise the daemon keeps its prior `POST /msg`-only
//! behavior. The end-to-end SYS-AC-001 witness runs in the `system-acceptance`
//! harness over this same wiring (real chain, only the external Telegram peer
//! doubled).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;

use advance_messaging::{
    IdentityResolver, MailboxStore, Message, MessageKind, MsgError, UserChannelMapping,
};
use advance_runtime::config::RuntimeConfig;
use advance_shared_types::mailbox::MessageOrigin;
// Phase-3 kickoff (2026-06-06): thread an EventBus handle into the channel
// transport + egress so channel.raw_received / channel.raw_sent + http.* fire.
use advance_shared_types::traits::EventBusEmit;

use advance_runtime::config::RuntimeConfigProvider;
use advance_shared_types::security_validator::SsrfGuard;
use cap_channel::{
    AdapterType, ChannelConfig, HttpEgress, HttpMethod, InboundVerifier, OutboundConfig,
    OutboundTransport, RawEvent, SubscriptionId, SubscriptionManager, TelegramVerifier,
    TransportSupervisor, DEFAULT_MAX_BODY_BYTES,
};
use cap_http::{
    DefaultHttpSecurityChain, DefaultLeakDetector, DefaultRateLimiter, DefaultSsrfGuard,
    HttpExecutor, RealResolver, ReqwestHttpExecutor,
};
use cap_secrets::{InMemorySecretStorage, SecretStore};
use zeroize::Zeroizing;

use crate::execution_turn_ingress::ExecutionTurnIngress;

/// Build the three HTTP-security-chain components with their `security.*` tunables
/// sourced **live** off the `RuntimeConfigProvider` (Wave-16 Lane-4, MODULE-012
/// AC-17): a hot-reloaded `security.leak_detector.max_scan_bytes` /
/// `security.rate_limit.per_component_rps` / `security.ssrf.{dns_timeout_ms,
/// dns_cache_ttl_seconds}` takes effect without runtime restart. `None` (tests /
/// the bare `build_channel_runtime`) → compile-time defaults (prior behaviour).
/// Returns concrete Arcs; `DefaultHttpSecurityChain::new` coerces them to its
/// `Arc<dyn …>` params at the call site.
pub fn live_security_components(
    provider: Option<Arc<dyn RuntimeConfigProvider>>,
) -> (
    Arc<DefaultLeakDetector>,
    Arc<DefaultSsrfGuard>,
    Arc<DefaultRateLimiter>,
) {
    match provider {
        Some(p) => {
            let p_leak = p.clone();
            let leak = Arc::new(DefaultLeakDetector::new().with_scan_cap_source(Arc::new(
                move || p_leak.current().security.leak_detector.max_scan_bytes,
            )));
            let p_timeout = p.clone();
            let p_ttl = p.clone();
            let resolver = RealResolver::new().with_timeout_source(Arc::new(move || {
                p_timeout.current().security.ssrf.dns_timeout_ms
            }));
            let ssrf = Arc::new(
                DefaultSsrfGuard::with_resolver(Box::new(resolver)).with_cache_ttl_source(
                    Arc::new(move || p_ttl.current().security.ssrf.dns_cache_ttl_seconds),
                ),
            );
            let p_rps = p.clone();
            let rate = Arc::new(DefaultRateLimiter::new().with_rps_source(Arc::new(move || {
                p_rps.current().security.rate_limit.per_component_rps
            })));
            (leak, ssrf, rate)
        }
        None => (
            Arc::new(DefaultLeakDetector::new()),
            Arc::new(DefaultSsrfGuard::new()),
            Arc::new(DefaultRateLimiter::new()),
        ),
    }
}

/// Build the production reqwest HTTP executor with its connect-time DNS-rebinding
/// resolver's timeout sourced LIVE off the `RuntimeConfigProvider` (Wave-16 Lane-4,
/// MODULE-012 AC-17): a hot-reloaded `security.ssrf.dns_timeout_ms` applies to BOTH
/// the chain's pre-flight `DefaultSsrfGuard` resolver AND the executor's connect-time
/// resolver. `None` (tests / bare path) → the fixed-timeout executor (prior behaviour).
pub(crate) fn live_executor(
    provider: Option<Arc<dyn RuntimeConfigProvider>>,
) -> Arc<ReqwestHttpExecutor> {
    match provider {
        Some(p) => Arc::new(ReqwestHttpExecutor::with_dns_timeout_source(Arc::new(
            move || p.current().security.ssrf.dns_timeout_ms,
        ))),
        None => Arc::new(ReqwestHttpExecutor::new()),
    }
}

/// One configured host-pump channel subscription.
#[derive(Clone)]
pub struct ChannelSub {
    pub sub_id: SubscriptionId,
    pub adapter_kind: String,
}

/// The wired channel runtime — shared between the inbound listener+pump and the
/// outbound egress sink. All share the one `SubscriptionManager`.
pub struct ChannelRuntime {
    pub manager: Arc<SubscriptionManager>,
    pub transport: Arc<dyn OutboundTransport>,
    /// The exact same concrete egress instance as `transport`, retained for the
    /// CONTRACT-215 progress renderer.  Keeping the concrete handle here lets
    /// composition stage the typed renderer without constructing a second HTTP
    /// security chain or adding a downcast seam to `OutboundTransport`.
    pub progress_egress: Arc<HttpEgress>,
    pub supervisor: Arc<TransportSupervisor>,
    pub identity: Arc<IdentityResolver>,
    pub subs: Vec<ChannelSub>,
    pub listen_addr: SocketAddr,
}

/// Composition-test override for the two environment-facing portions of the
/// otherwise production-built channel security chain.  The leak detector,
/// rate limiter, secret store, EventBus wiring, `HttpEgress`, and full
/// `DefaultHttpSecurityChain` remain the production implementations.  Tests
/// replace only DNS resolution and the external network peer.
#[derive(Clone)]
pub(crate) struct ChannelSecurityTestOverride {
    ssrf: Arc<dyn SsrfGuard>,
    executor: Arc<dyn HttpExecutor>,
}

impl ChannelSecurityTestOverride {
    #[cfg(feature = "test-support")]
    pub(crate) fn new(ssrf: Arc<dyn SsrfGuard>, executor: Arc<dyn HttpExecutor>) -> Self {
        Self { ssrf, executor }
    }
}

/// Build the credential-less channel egress transport: an `HttpEgress` over a
/// `DefaultHttpSecurityChain` (real reqwest executor + leak/SSRF/rate guards),
/// event-bus-wired so `channel.raw_sent` (+ `http.*`/`security.*`) fire on a
/// successful outbound reply. Credential-less: the egress injects no credentials
/// (the bot token rides in the preset `url_template`), so an in-memory secret
/// store + zero master key is sufficient and never used.
///
/// Factored (Wave-7 Lane B, 2026-06-22) so the auto-loop degrade/halt notify
/// install (`wire_capabilities` → `build_auto_loop_driver_with_channel_notify`,
/// SYS-AC-257) builds the SAME egress class as the daemon's reply transport,
/// without duplicating the chain wiring (it cannot reuse the `ChannelRuntime`'s
/// transport — that is built later in `start.rs`, after the auto driver is
/// already shared into the round-advancer; see MODULE-016 §3.8).
/// BYTE-IDENTICAL bare form — compile-time security defaults (prior behaviour).
/// Kept so any caller of the original 1-arg signature compiles unchanged.
pub fn build_egress_transport(event_bus: Arc<dyn EventBusEmit>) -> Arc<dyn OutboundTransport> {
    build_egress_transport_with_security(event_bus, None)
}

/// Wave-16 Lane-4 (MODULE-012 AC-17): like [`build_egress_transport`] but threads a
/// live `security.*` source. `Some` → hot-reloadable leak/SSRF/rate tunables AND the
/// executor's connect-time DNS timeout on this egress chain; `None` → compile-time
/// defaults. The production callers (`wiring.rs` notify egress + the channel runtime
/// via `build_channel_runtime_with_config`) pass `Some`.
pub fn build_egress_transport_with_security(
    event_bus: Arc<dyn EventBusEmit>,
    config_provider: Option<Arc<dyn RuntimeConfigProvider>>,
) -> Arc<dyn OutboundTransport> {
    build_http_egress_with_security(event_bus, config_provider, None)
}

/// Build the concrete production egress used by both legacy replies and the
/// CONTRACT-215 progress-card renderer.  This helper is deliberately private:
/// only a fully built [`ChannelRuntime`] may expose the staged concrete handle.
fn build_http_egress_with_security(
    event_bus: Arc<dyn EventBusEmit>,
    config_provider: Option<Arc<dyn RuntimeConfigProvider>>,
    security_override: Option<ChannelSecurityTestOverride>,
) -> Arc<HttpEgress> {
    let secret_store = Arc::new(SecretStore::new(
        Zeroizing::new([0u8; 32]),
        Arc::new(InMemorySecretStorage::new()),
    ));
    let (leak, default_ssrf, rate) = live_security_components(config_provider.clone());
    let (ssrf, executor): (Arc<dyn SsrfGuard>, Arc<dyn HttpExecutor>) = match security_override {
        Some(overrides) => (overrides.ssrf, overrides.executor),
        None => (default_ssrf, live_executor(config_provider)),
    };
    // Wave-20 (MODULE-012-AC-19 ChannelBidi leg): the SAME live `DefaultLeakDetector`
    // also scans the PRE-render channel MESSAGE CONTENT under `ScanContext::ChannelBidi`
    // at `HttpEgress::send` (a surface distinct from the chain's post-render
    // `HttpOutbound` body scan). Cloned BEFORE `leak` is moved into the chain.
    let channel_bidi_leak = leak.clone();
    let chain = Arc::new(
        DefaultHttpSecurityChain::new(secret_store, leak, ssrf, rate, executor)
            // Phase-3 kickoff: emit http.*/security.* on the channel outbound egress.
            .with_event_bus(event_bus.clone()),
    );
    // Phase-3 kickoff: emit channel.raw_sent on a successful outbound reply.
    Arc::new(
        HttpEgress::new(chain)
            .with_event_bus(event_bus)
            .with_leak_detector(channel_bidi_leak),
    )
}

/// Stage the concrete channel egress even when no inbound channel runtime is
/// configured. Atomic composition uses this only as the `None` fallback; when
/// a [`ChannelRuntime`] exists its exact `progress_egress` handle remains the
/// canonical instance shared by legacy and typed progress delivery.
pub(crate) fn build_progress_egress_with_security(
    event_bus: Arc<dyn EventBusEmit>,
    config_provider: Option<Arc<dyn RuntimeConfigProvider>>,
) -> Arc<HttpEgress> {
    build_http_egress_with_security(event_bus, config_provider, None)
}

/// Build the channel runtime from the parsed config, owned by `owner_agent_id`
/// (the serving loop's messaging id — the egress ownership check matches it).
/// Returns `Ok(None)` when no listener addr or no channels are configured (the
/// daemon then keeps its `POST /msg`-only behavior). `Err` on a misconfiguration
/// (bad addr / unsupported adapter / duplicate identity pair).
///
/// BYTE-IDENTICAL 3-arg form (the egress chain uses compile-time security
/// defaults) — kept so existing test callers compile unchanged. Production
/// (`start.rs`) calls [`build_channel_runtime_with_config`] for live AC-17 tunables.
pub fn build_channel_runtime(
    config: &RuntimeConfig,
    owner_agent_id: &str,
    event_bus: Arc<dyn EventBusEmit>,
) -> Result<Option<ChannelRuntime>, String> {
    build_channel_runtime_inner(config, owner_agent_id, event_bus, None, None)
}

/// Wave-16 Lane-4 (MODULE-012 AC-17): like [`build_channel_runtime`] but threads
/// the `RuntimeConfigProvider` so the channel egress chain reads its `security.*`
/// tunables **live** (hot-reload without restart). The production daemon
/// (`start.rs`) calls this with `host.config_watcher()`.
pub fn build_channel_runtime_with_config(
    config: &RuntimeConfig,
    owner_agent_id: &str,
    event_bus: Arc<dyn EventBusEmit>,
    config_provider: Arc<dyn RuntimeConfigProvider>,
) -> Result<Option<ChannelRuntime>, String> {
    build_channel_runtime_inner(
        config,
        owner_agent_id,
        event_bus,
        Some(config_provider),
        None,
    )
}

#[cfg(feature = "test-support")]
pub(crate) fn build_channel_runtime_with_security_override_for_test(
    config: &RuntimeConfig,
    owner_agent_id: &str,
    event_bus: Arc<dyn EventBusEmit>,
    config_provider: Arc<dyn RuntimeConfigProvider>,
    security_override: ChannelSecurityTestOverride,
) -> Result<Option<ChannelRuntime>, String> {
    build_channel_runtime_inner(
        config,
        owner_agent_id,
        event_bus,
        Some(config_provider),
        Some(security_override),
    )
}

fn build_channel_runtime_inner(
    config: &RuntimeConfig,
    owner_agent_id: &str,
    event_bus: Arc<dyn EventBusEmit>,
    config_provider: Option<Arc<dyn RuntimeConfigProvider>>,
    security_override: Option<ChannelSecurityTestOverride>,
) -> Result<Option<ChannelRuntime>, String> {
    let ch = &config.channels;
    let addr_str = match &ch.webhook_listen_addr {
        Some(a) if !ch.channels.is_empty() => a,
        _ => return Ok(None),
    };
    let listen_addr: SocketAddr = addr_str
        .parse()
        .map_err(|e| format!("invalid channels.webhook_listen_addr {addr_str:?}: {e}"))?;

    let manager = Arc::new(SubscriptionManager::new());
    // Phase-3 kickoff: the supervisor emits channel.raw_received on a verified
    // inbound webhook (agent_id = the daemon's serving owner).
    let supervisor = Arc::new(
        TransportSupervisor::new(manager.clone()).with_event_bus(event_bus.clone(), owner_agent_id),
    );

    // The channel egress transport (credential-less HttpEgress; see
    // `build_egress_transport`). Factored so the auto-loop notify install
    // (`wire_capabilities`, SYS-AC-257) builds the SAME egress class.
    // AC-17: thread the live `security.*` source (None for the bare 3-arg form).
    let progress_egress = build_http_egress_with_security(
        event_bus.clone(),
        config_provider.clone(),
        security_override,
    );
    let transport: Arc<dyn OutboundTransport> = progress_egress.clone();

    let mut subs = Vec::new();
    let mut by_user: HashMap<String, Vec<HashMap<String, String>>> = HashMap::new();
    // Audit r8 adversarial W2: the `channels.*` block is not covered by
    // `validate_config`, so reject the silent-misconfiguration cases at boot here
    // (loud failure beats a channel that boots but is unreachable / un-deliverable).
    let mut seen_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut seen_routes: std::collections::HashSet<String> = std::collections::HashSet::new();

    for entry in &ch.channels {
        let adapter: AdapterType = entry
            .adapter
            .parse()
            .expect("AdapterType::from_str infallible");
        // ALL validation runs BEFORE any side-effecting wiring (audit r9 W1): an
        // early-return must not leave an orphaned host-pump subscription / route in
        // `manager`. Determine the inbound verifier FIRST — this rejects a
        // known-but-unsupported adapter (slack/signal/webhook) before `subscribe`.
        let verifier: Arc<dyn InboundVerifier> = match adapter {
            AdapterType::Telegram => Arc::new(TelegramVerifier::new(entry.secret.clone())),
            other => {
                return Err(format!(
                    "channel {:?}: adapter {} is not a supported inbound channel in Step-3 \
                     (only telegram)",
                    entry.name,
                    other.as_str()
                ))
            }
        };
        // Fail-closed at boot (audit r3): an empty inbound secret would disable
        // webhook auth (the verifier also rejects empty at request time, but failing
        // boot loudly is the documented behavior — MODULE-016 §2.10). Reject NUL too
        // (audit r9 W2: align with the project's `check_nonempty` standard).
        if entry.secret.trim().is_empty() || entry.secret.contains('\0') {
            return Err(format!(
                "channel {:?}: `secret` is empty/whitespace or contains NUL (webhook \
                 authentication would be disabled/malformed)",
                entry.name
            ));
        }
        // `route` becomes the SINGLE `/hooks/{route}` path segment. Reject empty,
        // an interior `/` (multi-segment), or any control char — all of which boot a
        // channel the listener can never match → silently unreachable (audit r9 W2,
        // the exact silent-misconfig class this validation closes).
        if entry.route.trim().is_empty()
            || entry.route.contains(['/', '?', '#'])
            || entry.route.chars().any(|c| c.is_control())
        {
            // `?`/`#` are URL query/fragment delimiters — axum truncates the inbound
            // path there, so such a route would register but never match (unreachable).
            return Err(format!(
                "channel {:?}: invalid `route` {:?} (must be a non-empty single path segment \
                 with no '/', '?', '#', or control characters)",
                entry.name, entry.route
            ));
        }
        // A blank/NUL `url-template` has no usable outbound egress target.
        if entry.url_template.trim().is_empty() || entry.url_template.contains('\0') {
            return Err(format!(
                "channel {:?}: `url-template` is empty or contains NUL (no usable outbound \
                 egress target)",
                entry.name
            ));
        }
        // Duplicate name → ambiguous diagnostics; duplicate route → only the last
        // would be reachable (also rejected at register_webhook; caught here first).
        if !seen_names.insert(entry.name.clone()) {
            return Err(format!(
                "duplicate channel name {:?} (names must be unique)",
                entry.name
            ));
        }
        if !seen_routes.insert(entry.route.clone()) {
            return Err(format!(
                "channel {:?}: duplicate route {:?} (two channels cannot share a /hooks route)",
                entry.name, entry.route
            ));
        }
        let outbound = OutboundConfig {
            method: HttpMethod::Post,
            url_template: entry.url_template.clone(),
            headers: vec![("Content-Type".into(), "application/json".into())],
        };
        let sub_config = ChannelConfig {
            adapter_type: adapter.clone(),
            params: vec![],
            outbound: Some(outbound),
        };
        // Wiring (side-effecting) only AFTER all validation has passed.
        let sub_id = manager
            .subscribe_host_pump(owner_agent_id, sub_config)
            .map_err(|e| format!("channel {:?} subscribe failed: {e:?}", entry.name))?;
        supervisor
            .register_webhook(
                entry.route.clone(),
                sub_id.clone(),
                adapter.clone(),
                verifier,
            )
            .map_err(|e| format!("channel {:?}: {e}", entry.name))?;
        subs.push(ChannelSub {
            sub_id,
            adapter_kind: adapter.as_str().to_string(),
        });

        for um in &entry.user_mappings {
            let mut single = HashMap::new();
            single.insert(um.channel_kind.clone(), um.sender_id.clone());
            by_user.entry(um.user.clone()).or_default().push(single);
        }
    }

    let user_mappings: Vec<UserChannelMapping> = by_user
        .into_iter()
        .map(|(id, channels)| UserChannelMapping { id, channels })
        .collect();
    let identity = Arc::new(
        IdentityResolver::from_user_mappings(&user_mappings)
            .map_err(|e| format!("channel identity resolver build failed: {e:?}"))?,
    );

    Ok(Some(ChannelRuntime {
        manager,
        transport,
        progress_egress,
        supervisor,
        identity,
        subs,
        listen_addr,
    }))
}

/// Shared state for the `/hooks/{route}` listener.
#[derive(Clone)]
struct HooksState {
    supervisor: Arc<TransportSupervisor>,
}

/// `POST /hooks/{route}` → resolve the route's verifier, normalize, enqueue.
async fn handle_hook(
    State(state): State<HooksState>,
    Path(route): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, &'static str) {
    let hdrs: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    // Audit r8 adversarial W3: `dispatch_inbound` is synchronous (constant-time
    // secret-token compare + up-to-1-MiB `serde_json` parse + enqueue). Run it on
    // the blocking pool, NOT inline on the daemon's single-thread reactor — a burst
    // of large inbound bodies would otherwise block the serving loop, the host pump,
    // and the `/msg` listener for the parse duration.
    let supervisor = state.supervisor.clone();
    match tokio::task::spawn_blocking(move || supervisor.dispatch_inbound(&route, &hdrs, &body))
        .await
    {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (status, resp.body)
        }
        // Join error (the blocking task panicked) → 500; never leak the panic.
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

/// Bind the shared `/hooks/{route}` listener on `addr`. Returns the serve task
/// handle (aborted on shutdown).
pub async fn spawn_hooks_listener(
    supervisor: Arc<TransportSupervisor>,
    addr: SocketAddr,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let app = Router::new()
        .route("/hooks/{route}", post(handle_hook))
        .layer(DefaultBodyLimit::max(DEFAULT_MAX_BODY_BYTES))
        .with_state(HooksState { supervisor });
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("failed to bind /hooks listener on {addr}: {e}"))?;
    let bound = listener
        .local_addr()
        .map_err(|e| format!("failed to read /hooks listener addr: {e}"))?;
    println!("advance: channel /hooks listener on http://{bound}/hooks/{{route}}");
    Ok(tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            eprintln!("advance: /hooks listener stopped: {e}");
        }
    }))
}

/// Spawn the host pump: drain `poll_host_pump` over every channel subscription,
/// build a `Message` (with `MessageOrigin.channel_metadata` populated per the
/// ADR keystone), and deliver it into the shared `MailboxStore` to wake the
/// serving loop. A simple poll loop (no enqueue-notify primitive exists for
/// `poll_host_pump`); 50 ms idle backoff.
pub fn spawn_host_pump(
    manager: Arc<SubscriptionManager>,
    identity: Arc<IdentityResolver>,
    subs: Vec<ChannelSub>,
    store: Arc<MailboxStore>,
    msg_agent_id: String,
) -> tokio::task::JoinHandle<()> {
    let publish: Arc<dyn Fn(Message) -> Result<(), MsgError> + Send + Sync> =
        Arc::new(move |message: Message| {
            let target = message.to.clone();
            store
                .get_or_create(&target)
                .and_then(|mailbox| mailbox.deliver(message))
        });
    spawn_host_pump_inner(manager, identity, subs, publish, msg_agent_id)
}

/// Joint C215/C216 production pump. Unlike the legacy additive helper above,
/// every normalized channel event is reserved/published as an
/// ExecutionBoundary-owned protected turn before it becomes dequeue-visible.
pub(crate) fn spawn_protected_host_pump(
    manager: Arc<SubscriptionManager>,
    identity: Arc<IdentityResolver>,
    subs: Vec<ChannelSub>,
    ingress: Arc<ExecutionTurnIngress>,
    msg_agent_id: String,
) -> tokio::task::JoinHandle<()> {
    let publish: Arc<dyn Fn(Message) -> Result<(), MsgError> + Send + Sync> =
        Arc::new(move |message| ingress.publish(message));
    spawn_host_pump_inner(manager, identity, subs, publish, msg_agent_id)
}

fn spawn_host_pump_inner(
    manager: Arc<SubscriptionManager>,
    identity: Arc<IdentityResolver>,
    subs: Vec<ChannelSub>,
    publish: Arc<dyn Fn(Message) -> Result<(), MsgError> + Send + Sync>,
    msg_agent_id: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let counter = AtomicU64::new(0);
        loop {
            let mut progressed = false;
            let mut backpressured = false;
            // All subscriptions feed ONE mailbox (`msg_agent_id`). Once it is full
            // no sub can deliver, so a deliver failure stops the WHOLE pass (not just
            // the current sub) and forces the backoff — otherwise a still-draining
            // sibling sub keeps `progressed` true and the remaining subs' events get
            // popped-and-dropped at full CPU with no backoff (audit r8 adversarial W:
            // the per-tick drop bound is defeated by a GLOBAL progress flag once
            // ≥2 channels are configured under asymmetric load).
            'pass: for s in &subs {
                while let Ok(Some(raw)) = manager.poll_host_pump(&s.sub_id) {
                    let n = counter.fetch_add(1, Ordering::Relaxed);
                    let Some(msg) = build_inbound_message(&identity, raw, &msg_agent_id, n) else {
                        eprintln!(
                            "advance: channel pump rejected inbound event with invalid adapter identity"
                        );
                        backpressured = true;
                        break 'pass;
                    };
                    match publish(msg) {
                        Ok(()) => progressed = true,
                        Err(e) => {
                            // The event was already popped → an at-most-once
                            // drop (logged, not silent).
                            eprintln!(
                                "advance: channel pump dropped an inbound event for {:?} \
                                 (mailbox publish failed: {:?}) — backpressure, pausing all drains",
                                msg_agent_id, e
                            );
                            backpressured = true;
                            break 'pass;
                        }
                    }
                }
            }
            // Back off when nothing was delivered (idle) OR the shared mailbox is
            // full (backpressure) — bounds CPU + log/drop rate to one per 50 ms tick
            // even with multiple channels under asymmetric load.
            if !progressed || backpressured {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    })
}

/// Build an inbound `Message` from a normalized `RawEvent`. The whole
/// `channel.*` metadata bag (conversation_id + the reply_address family +
/// adapter + sender + subscription_id) is copied into `MessageOrigin.channel_metadata`
/// per the keystone, so the outbound junction can build the per-message
/// `OutboundTarget` and resolve the originating subscription on reply.
fn build_inbound_message(
    identity: &IdentityResolver,
    raw: RawEvent,
    msg_agent_id: &str,
    n: u64,
) -> Option<Message> {
    let meta: HashMap<String, String> = raw
        .metadata
        .iter()
        .map(|p| (p.key.clone(), p.value.clone()))
        .collect();
    let channel_kind = meta.get("channel.adapter").cloned().unwrap_or_default();
    if channel_kind.is_empty()
        || channel_kind.len() > 256
        || channel_kind
            .bytes()
            .any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
    {
        return None;
    }
    let sender_id = meta.get("channel.sender_id").cloned().unwrap_or_default();
    // WHO resolution (sender → unified id); unmapped senders get a stable
    // synthetic user id so the turn still runs (reply routing is WHERE, from
    // channel_metadata, independent of this).
    let from = identity
        .resolve(&channel_kind, &sender_id)
        .unwrap_or_else(|| format!("user:{channel_kind}:{sender_id}"));
    let id = format!("channel-{n}-{}", uuid::Uuid::new_v4().simple());
    let origin = MessageOrigin {
        message_id: id.clone(),
        original_channel: channel_kind.clone(),
        original_sender: sender_id,
        // Host-authenticated adapter identity is a component of the protected
        // four-part ProgressCardKey; it is distinct from the serving agent id.
        adapter_id: channel_kind.clone(),
        channel_metadata: meta,
        received_at: advance_shared_types::chrono::Utc::now(),
        context: None,
    };
    Some(Message {
        id,
        kind: MessageKind::User,
        from,
        to: msg_agent_id.to_string(),
        payload: raw.data,
        context: None,
        timestamp: SystemTime::now(),
        origin: Some(origin),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use advance_runtime::config::{ChannelEntry, ChannelUserMapping, ChannelsConfig};
    use advance_shared_types::event::Event;

    /// Phase-3 kickoff: no-op EventBus for `build_channel_runtime` calls (these
    /// tests assert channel-runtime wiring, not observability emits).
    struct NoopBus;
    impl EventBusEmit for NoopBus {
        fn emit(&self, _event: Event) {}
    }
    fn noop_bus() -> Arc<dyn EventBusEmit> {
        Arc::new(NoopBus)
    }

    fn cfg_with_channels(addr: Option<&str>, channels: Vec<ChannelEntry>) -> RuntimeConfig {
        // Parse a minimal base config, then overlay the channels block.
        let yaml = r#"
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false
cron:
  max_jitter_ratio: 0.1
git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10
secrets:
  master-key-source: keychain
  env-var-name: SECRETS_MASTER_KEY
post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600
"#;
        let mut cfg: RuntimeConfig = serde_yml::from_str(yaml).expect("base config parses");
        cfg.channels = ChannelsConfig {
            webhook_listen_addr: addr.map(|s| s.to_string()),
            channels,
            notify: None,
        };
        cfg
    }

    fn tg_entry() -> ChannelEntry {
        ChannelEntry {
            name: "tg".into(),
            adapter: "telegram".into(),
            secret: "tok".into(),
            route: "tg".into(),
            url_template: "https://api.telegram.org/bot1/sendMessage".into(),
            user_mappings: vec![ChannelUserMapping {
                channel_kind: "telegram".into(),
                sender_id: "4242".into(),
                user: "user:alice".into(),
            }],
        }
    }

    /// Adversarial r1 (W1) regression guard: the PRODUCTION egress builder
    /// `build_egress_transport_with_security` MUST attach the `ScanContext::ChannelBidi`
    /// LeakDetector (the scan_points_t20 witness only proves the `HttpEgress` SEAM
    /// when handed a detector — it does NOT pin the prod builder's injection). Here
    /// we drive a real AWS access-key pattern (`Action::Block`) through the
    /// prod-BUILT transport; the live `DefaultLeakDetector` withholds it at the
    /// ChannelBidi scan — BEFORE render/chain/network (no network touched). The
    /// discriminator is the error STRING: a ChannelBidi block says "ChannelBidi",
    /// whereas a chain (post-render HttpOutbound) block would not — so if a future
    /// edit drops `.with_leak_detector` from the builder, the leak would instead be
    /// caught (or not) by the chain with a different message and this fails.
    #[tokio::test]
    async fn prod_egress_builder_wires_channelbidi_scan() {
        use advance_shared_types::outbound::OutboundTarget;
        use cap_channel::ChannelError;

        let transport = build_egress_transport_with_security(noop_bus(), None);
        let mgr = SubscriptionManager::new();
        let id = mgr
            .subscribe(
                "agent-x",
                ChannelConfig {
                    adapter_type: AdapterType::Telegram,
                    params: vec![],
                    outbound: Some(OutboundConfig {
                        method: HttpMethod::Post,
                        url_template: "https://api.telegram.org/bot1/sendMessage".into(),
                        headers: vec![],
                    }),
                },
            )
            .unwrap();
        let sub = mgr.lookup(&id).unwrap();
        let target = OutboundTarget::ChatReply {
            conversation_id: "1".into(),
            reply_address: vec![],
        };
        // A real AWS access-key pattern (AKIA + 16 upper-alnum) → Action::Block.
        let payload = br#"{"text":"oops AKIAIOSFODNN7EXAMPLE leaked"}"#;
        let err = transport
            .send("agent-x", sub.as_ref(), target, payload)
            .await
            .expect_err("ChannelBidi scan must block the leak");
        match &err {
            ChannelError::OutboundBlocked(msg) => {
                assert!(
                    msg.contains("ChannelBidi"),
                    "blocked specifically by the ChannelBidi scan (not the chain): {msg}"
                );
                // Operator-log safety: the raw key never appears in the error.
                assert!(!msg.contains("AKIA"), "no secret bytes in error: {msg}");
            }
            other => panic!("expected ChannelBidi OutboundBlocked, got {other:?}"),
        }
    }

    #[test]
    fn no_addr_or_no_channels_returns_none() {
        assert!(build_channel_runtime(
            &cfg_with_channels(None, vec![tg_entry()]),
            "agent:default",
            noop_bus()
        )
        .unwrap()
        .is_none());
        assert!(build_channel_runtime(
            &cfg_with_channels(Some("127.0.0.1:0"), vec![]),
            "agent:default",
            noop_bus()
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn builds_runtime_with_host_pump_sub_route_and_identity() {
        let cfg = cfg_with_channels(Some("127.0.0.1:0"), vec![tg_entry()]);
        let cr = build_channel_runtime(&cfg, "agent:default", noop_bus())
            .unwrap()
            .unwrap();
        assert_eq!(cr.subs.len(), 1);
        assert_eq!(cr.supervisor.route_count(), 1);
        // Identity resolves the configured sender → user (WHO).
        assert_eq!(
            cr.identity.resolve("telegram", "4242").as_deref(),
            Some("user:alice")
        );
        // The subscription is host-pump (drainable by poll_host_pump, not poll_raw).
        assert!(cr
            .manager
            .poll_host_pump(&cr.subs[0].sub_id)
            .unwrap()
            .is_none());
    }

    #[test]
    fn boot_rejects_silent_channel_misconfigurations() {
        // Audit r8 adversarial W2: each of these would otherwise boot a channel that
        // is unreachable / un-deliverable / ambiguous rather than failing loudly.
        let addr = Some("127.0.0.1:0");
        let err_for = |mutate: &dyn Fn(&mut ChannelEntry)| {
            let mut e = tg_entry();
            mutate(&mut e);
            build_channel_runtime(
                &cfg_with_channels(addr, vec![e]),
                "agent:default",
                noop_bus(),
            )
            .err()
            .expect("expected boot to reject")
        };
        assert!(err_for(&|e| e.secret = String::new()).contains("secret"));
        assert!(err_for(&|e| e.secret = "\0".into()).contains("secret")); // NUL secret
        assert!(err_for(&|e| e.secret = "   ".into()).contains("secret")); // whitespace-only secret
        assert!(err_for(&|e| e.route = "  ".into()).contains("route"));
        assert!(err_for(&|e| e.route = "a/b".into()).contains("route")); // interior '/'
        assert!(err_for(&|e| e.route = "a?b".into()).contains("route")); // query delimiter
        assert!(err_for(&|e| e.route = "a#b".into()).contains("route")); // fragment delimiter
        assert!(err_for(&|e| e.route = "a\0b".into()).contains("route")); // control char
        assert!(err_for(&|e| e.url_template = String::new()).contains("url-template"));
        assert!(err_for(&|e| e.url_template = "x\0y".into()).contains("url-template")); // NUL
                                                                                        // Unsupported (known-but-not-telegram) adapter rejects BEFORE any wiring.
        assert!(err_for(&|e| e.adapter = "slack".into()).contains("not a supported inbound"));
        // Duplicate name (distinct routes) → name collision.
        let mut a = tg_entry();
        let mut b = tg_entry();
        b.route = "tg2".into();
        let dup_name = build_channel_runtime(
            &cfg_with_channels(addr, vec![a.clone(), b]),
            "agent:default",
            noop_bus(),
        )
        .err()
        .expect("expected duplicate-name reject");
        assert!(dup_name.contains("duplicate channel name"), "{dup_name}");
        // Duplicate route (distinct names) → route collision.
        a.name = "tg-a".into();
        let mut c = tg_entry();
        c.name = "tg-b".into();
        let dup_route = build_channel_runtime(
            &cfg_with_channels(addr, vec![a, c]),
            "agent:default",
            noop_bus(),
        )
        .err()
        .expect("expected duplicate-route reject");
        assert!(dup_route.contains("duplicate route"), "{dup_route}");
    }

    #[test]
    fn end_to_end_inbound_dispatch_enqueues_then_pump_builds_message() {
        let cfg = cfg_with_channels(Some("127.0.0.1:0"), vec![tg_entry()]);
        let cr = build_channel_runtime(&cfg, "agent:default", noop_bus())
            .unwrap()
            .unwrap();
        // Simulate a Telegram webhook POST hitting the supervisor route.
        let body = serde_json::to_vec(&serde_json::json!({
            "message": { "date": 1700000000, "chat": {"id": 98765}, "from": {"id": 4242}, "text": "hi" }
        }))
        .unwrap();
        let headers = vec![(
            "X-Telegram-Bot-Api-Secret-Token".to_string(),
            "tok".to_string(),
        )];
        let resp = cr.supervisor.dispatch_inbound("tg", &headers, &body);
        assert_eq!(resp.status, 200);
        // The pump's build_inbound_message produces a Message whose origin carries
        // the conversation id + reply_address (for the egress) + resolved WHO.
        let raw = cr
            .manager
            .poll_host_pump(&cr.subs[0].sub_id)
            .unwrap()
            .unwrap();
        let msg = build_inbound_message(&cr.identity, raw, "agent:default", 0)
            .expect("authenticated adapter identity");
        assert_eq!(msg.from, "user:alice"); // resolved sender → unified id
        let origin = msg.origin.unwrap();
        assert_eq!(origin.channel_metadata["channel.conversation_id"], "98765");
        assert_eq!(
            origin.channel_metadata["channel.reply_address.chat_id"],
            "98765"
        );
        assert_eq!(origin.original_sender, "4242");
        assert_eq!(origin.adapter_id, "telegram");
    }
}

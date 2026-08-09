//! CONTRACT-190 — the `ClientApi` orchestration spine.
//!
//! Pipeline: admission (loopback-only default bind) → version fail-closed → body-size →
//! CORS/origin → session ops OR generic route → auth → (mutation: idempotency-required + CSRF +
//! reserve-before-execute) → handler → commit → envelope. Every step emits secret-free
//! `client_api.*` audit events through the [`AuditSink`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use serde_json::json;
use sha2::{Digest, Sha256};

use advance_shared_types::security_validator::LeakDetector;
use advance_shared_types::sensitive_observation::SensitiveObservationRedactor;

use crate::audit::{AuditEvent, AuditSink, NoopSink};
use crate::auth::ClientSessionAuth;
use crate::clock::{Clock, SystemClock};
use crate::config::ClientApiConfig;
use crate::cursor::ClientCursorCodec;
use crate::durable_idempotency::{
    DurableBegin, DurableIdempotencyRepository, DurableReservation, DurableReserveInput,
};
use crate::envelope::{ClientEnvelope, ClientError, ClientErrorCode, ClientWarning, API_VERSION};
use crate::events::{ClientEventProvider, EventConcurrency};
use crate::idempotency::{Begin, IdempotencyOutcome, IdempotencyScope, IdempotencyStore};
use crate::provider::{
    BoundGrantProviderSlot, BoundHistoryProviderSlot, CursorCodecSlot, EventProviderSlot,
    LeakDetectorSlot, MessagingProvider, MessagingProviderSlot, ObservationRedactorSlot,
    RunControlProvider, RunProviderSlot, ToolsProvider, ToolsProviderSlot,
};
use crate::providers::grants::BoundGrantApprovalPort;
use crate::providers::history::BoundHistoryReadPort;
use crate::request::{ClientRequest, Method};
use crate::routes::{self, RoutePattern, SessionOp};
use crate::session::{Platform, Principal, Scope, SessionInfo, SessionStore};

/// Context passed to a registered handler (owned; no borrow of request internals).
#[derive(Clone)]
pub struct HandlerCtx {
    /// Correlated request id (CONTRACT-190 additive; same id as the response envelope).
    pub request_id: String,
    pub principal: Option<Principal>,
    pub scopes: Vec<Scope>,
    pub body: serde_json::Value,
    /// Path parameters bound by a templated route (e.g. `run_id`, `message_id`); empty for exact
    /// routes. Additive since m020-s2 — s1 handlers ignore it.
    pub path_params: Vec<(String, String)>,
    /// Present only after the mutation idempotency reservation succeeds.
    pub mutation: Option<ClientMutationContext>,
}

/// Stable provider correlation for one admitted mutating request.
#[derive(Clone)]
pub struct ClientMutationContext {
    request_fingerprint: [u8; 32],
    mutation_id: [u8; 32],
    provider_entry_started: Arc<AtomicBool>,
    recovery_pending: Arc<AtomicBool>,
    durable: Option<DurableMutationControl>,
}

#[derive(Clone)]
struct DurableMutationControl {
    repository: Arc<DurableIdempotencyRepository>,
    reservation: DurableReservation,
    now_ms: u64,
}

impl ClientMutationContext {
    pub fn request_fingerprint(&self) -> [u8; 32] {
        self.request_fingerprint
    }

    pub fn mutation_id(&self) -> [u8; 32] {
        self.mutation_id
    }

    /// Mark the irreversible provider-entry boundary. Provider-backed handlers call this
    /// immediately before the first prepare method; errors after this point become replayable
    /// terminal outcomes instead of releasing the idempotency reservation.
    pub fn mark_provider_entry(&self) -> Result<(), ClientError> {
        if let Some(durable) = &self.durable {
            durable
                .repository
                .mark_provider_entry(&durable.reservation, durable.now_ms)
                .map_err(|_| durable_failure())?;
        }
        self.provider_entry_started.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Mark that an authenticated provider ticket is now the only safe recovery path. The outer
    /// pipeline retains the reservation if the provider still reports an unknown outcome.
    pub fn store_prepared_ticket(
        &self,
        ticket: &crate::ProviderMutationRecovery,
    ) -> Result<(), ClientError> {
        if let Some(durable) = &self.durable {
            durable
                .repository
                .store_prepared_ticket(&durable.reservation, ticket, durable.now_ms)
                .map_err(|_| durable_failure())?;
        }
        Ok(())
    }

    pub fn mark_recovering(
        &self,
        replacement: Option<&crate::ProviderMutationRecovery>,
    ) -> Result<(), ClientError> {
        if let Some(durable) = &self.durable {
            durable
                .repository
                .mark_recovering(&durable.reservation, replacement, durable.now_ms)
                .map_err(|_| durable_failure())?;
        }
        self.recovery_pending.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Mark a provider terminal outcome. Any later projection failure is a static replayable Done
    /// error rather than an indefinitely recovering mutation.
    pub fn mark_provider_terminal(&self) {
        self.recovery_pending.store(false, Ordering::SeqCst);
    }

    pub(crate) fn provider_entry_started(&self) -> bool {
        self.provider_entry_started.load(Ordering::SeqCst)
    }

    pub(crate) fn recovery_pending(&self) -> bool {
        self.recovery_pending.load(Ordering::SeqCst)
    }
}

impl HandlerCtx {
    /// Fetch a path parameter bound by the templated route (e.g. `run_id`, `message_id`).
    pub fn path_param(&self, name: &str) -> Result<String, ClientError> {
        self.path_params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .ok_or_else(|| ClientError::new(ClientErrorCode::NotFound, "missing path parameter"))
    }
}

/// A handler result before the outer versioned envelope is constructed.
pub struct HandlerResponse {
    pub data: serde_json::Value,
    pub warnings: Vec<ClientWarning>,
}

impl HandlerResponse {
    pub fn data(data: serde_json::Value) -> Self {
        Self {
            data,
            warnings: Vec::new(),
        }
    }

    pub fn with_warnings(data: serde_json::Value, warnings: Vec<ClientWarning>) -> Self {
        Self { data, warnings }
    }
}

type HandlerFn = Arc<dyn Fn(&HandlerCtx) -> Result<HandlerResponse, ClientError> + Send + Sync>;

/// Registration for a non-session route (health, and — in later slices — provider families).
#[derive(Clone)]
pub struct HandlerSpec {
    pub requires_session: bool,
    pub is_mutation: bool,
    /// Scopes the session MUST carry. Enforced by the pipeline AFTER authentication and BEFORE the
    /// mutation gate (so a replay by an under-scoped session is denied before the idempotency
    /// replay lookup) — never inside the handler. Empty = no scope requirement.
    pub required_scopes: Vec<Scope>,
    pub func: HandlerFn,
}

impl HandlerSpec {
    pub fn read<F>(requires_session: bool, func: F) -> Self
    where
        F: Fn(&HandlerCtx) -> Result<serde_json::Value, ClientError> + Send + Sync + 'static,
    {
        Self {
            requires_session,
            is_mutation: false,
            required_scopes: Vec::new(),
            func: Arc::new(move |ctx| func(ctx).map(HandlerResponse::data)),
        }
    }

    pub fn mutation<F>(requires_session: bool, func: F) -> Self
    where
        F: Fn(&HandlerCtx) -> Result<serde_json::Value, ClientError> + Send + Sync + 'static,
    {
        Self {
            requires_session,
            is_mutation: true,
            required_scopes: Vec::new(),
            func: Arc::new(move |ctx| func(ctx).map(HandlerResponse::data)),
        }
    }

    pub fn read_with_warnings<F>(requires_session: bool, func: F) -> Self
    where
        F: Fn(&HandlerCtx) -> Result<HandlerResponse, ClientError> + Send + Sync + 'static,
    {
        Self {
            requires_session,
            is_mutation: false,
            required_scopes: Vec::new(),
            func: Arc::new(func),
        }
    }

    pub fn mutation_with_warnings<F>(requires_session: bool, func: F) -> Self
    where
        F: Fn(&HandlerCtx) -> Result<HandlerResponse, ClientError> + Send + Sync + 'static,
    {
        Self {
            requires_session,
            is_mutation: true,
            required_scopes: Vec::new(),
            func: Arc::new(func),
        }
    }

    /// Require these client scopes (pipeline-enforced after auth, before the mutation gate).
    pub fn with_scopes(mut self, scopes: Vec<Scope>) -> Self {
        self.required_scopes = scopes;
        self
    }
}

/// The public Client API gateway (CONTRACT-190) + session/auth (CONTRACT-193).
pub struct ClientApi {
    config: ClientApiConfig,
    auth: Arc<ClientSessionAuth>,
    sessions: SessionStore,
    idempotency: IdempotencyStore,
    audit: Arc<dyn AuditSink>,
    clock: Arc<dyn Clock>,
    handlers: HashMap<(Method, String), HandlerSpec>,
    /// Templated routes (m020-s2), consulted only after an exact-path miss (see `handle`).
    routes: Vec<(Method, RoutePattern, HandlerSpec)>,
    /// Interior-mutable provider slots (m020-s2). Empty by default → `module_unavailable`; the
    /// composition root (Wave-25) / a witness injects a concrete adapter via a builder.
    run_provider: RunProviderSlot,
    messaging_provider: MessagingProviderSlot,
    tools_provider: ToolsProviderSlot,
    /// m020-s3 CONTRACT-191 slots (event provider / leak detector / cursor codec).
    event_provider: EventProviderSlot,
    leak_detector: LeakDetectorSlot,
    cursor_codec: CursorCodecSlot,
    bound_grant_provider: BoundGrantProviderSlot,
    bound_history_provider: BoundHistoryProviderSlot,
    observation_redactor: ObservationRedactorSlot,
    /// Tee T2 (CONTRACT-235) `LlmDeltaHub` slot. Empty by default → `module_unavailable`;
    /// the cli root wiring is EXPLICITLY out of scope (backlog #12) — the headless default
    /// upstream stays `NotWiredDeltaSink` and this slot stays empty.
    llm_delta_hub: crate::deltas::LlmDeltaHubSlot,
    /// Test-support pump-exit observer (T26 witnesses discriminate cuts by exit reason).
    #[cfg(feature = "test-support")]
    delta_pump_observer: Arc<RwLock<Option<crate::deltas::DeltaPumpExitObserver>>>,
    durable_idempotency: Option<Arc<DurableIdempotencyRepository>>,
    /// Per-instance event-read concurrency limiter.
    event_concurrency: Arc<EventConcurrency>,
}

impl ClientApi {
    /// Construct with the OS user detected from the environment, a system clock, and a no-op
    /// audit sink.
    pub fn new(config: ClientApiConfig) -> Self {
        let os_user = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "operator".to_string());
        Self::with_parts(config, os_user, Arc::new(SystemClock), Arc::new(NoopSink))
    }

    /// Construct with explicit parts (used by tests to inject a deterministic clock, os user,
    /// and recording audit sink).
    pub fn with_parts(
        config: ClientApiConfig,
        os_user: impl Into<String>,
        clock: Arc<dyn Clock>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        let auth = Arc::new(ClientSessionAuth::new(
            os_user,
            config.bootstrap_code_ttl_ms,
            config.bootstrap_max_attempts,
        ));
        let idempotency =
            IdempotencyStore::new(config.idempotency_ttl_ms, config.idempotency_store_cap);
        let sessions = SessionStore::new(config.session_store_cap);
        let max_reads = config
            .max_concurrent_event_reads
            .clamp(1, crate::events::MAX_CONCURRENT_EVENT_READS_HARD);
        let mut api = Self {
            config,
            auth,
            sessions,
            idempotency,
            audit,
            clock,
            handlers: HashMap::new(),
            routes: Vec::new(),
            run_provider: Arc::new(RwLock::new(None)),
            messaging_provider: Arc::new(RwLock::new(None)),
            tools_provider: Arc::new(RwLock::new(None)),
            event_provider: Arc::new(RwLock::new(None)),
            leak_detector: Arc::new(RwLock::new(None)),
            cursor_codec: Arc::new(RwLock::new(None)),
            bound_grant_provider: Arc::new(RwLock::new(None)),
            bound_history_provider: Arc::new(RwLock::new(None)),
            observation_redactor: Arc::new(RwLock::new(None)),
            llm_delta_hub: Arc::new(RwLock::new(None)),
            #[cfg(feature = "test-support")]
            delta_pump_observer: Arc::new(RwLock::new(None)),
            durable_idempotency: None,
            event_concurrency: Arc::new(EventConcurrency::new(max_reads)),
        };
        api.register_builtin_handlers();
        api.register_provider_families();
        api
    }

    fn register_builtin_handlers(&mut self) {
        // GET /client/health — unauthenticated liveness probe.
        self.register(
            Method::Get,
            routes::PATH_HEALTH,
            HandlerSpec::read(false, |_ctx| {
                Ok(json!({ "status": "ok", "api_version": API_VERSION }))
            }),
        );
    }

    /// Register the m020-s2 provider families (runs/messages/tools) and m020-s3 event family.
    /// Each family's routes capture a clone of the shared provider slot, so a builder can inject
    /// the concrete provider AFTER registration; an absent slot yields `module_unavailable`
    /// (routes are always registered, so an absent provider is NOT `unknown_route`). The slots are
    /// cloned before each `&mut self` call to avoid a borrow conflict with the family register fns.
    fn register_provider_families(&mut self) {
        let run_slot = Arc::clone(&self.run_provider);
        crate::runs::register(self, run_slot);
        let msg_slot = Arc::clone(&self.messaging_provider);
        crate::messages::register(self, msg_slot);
        let tools_slot = Arc::clone(&self.tools_provider);
        crate::tools::register(self, tools_slot);
        let event_slot = Arc::clone(&self.event_provider);
        let detector_slot = Arc::clone(&self.leak_detector);
        let codec_slot = Arc::clone(&self.cursor_codec);
        let concurrency = Arc::clone(&self.event_concurrency);
        let audit = Arc::clone(&self.audit);
        let cfg = self.config.clone();
        crate::events::register(
            self,
            event_slot,
            detector_slot,
            codec_slot,
            concurrency,
            audit,
            &cfg,
        );
        let grant_slot = Arc::clone(&self.bound_grant_provider);
        let grant_redactor = Arc::clone(&self.observation_redactor);
        let grant_detector = Arc::clone(&self.leak_detector);
        crate::providers::grants::register(self, grant_slot, grant_redactor, grant_detector);
        let history_slot = Arc::clone(&self.bound_history_provider);
        let history_redactor = Arc::clone(&self.observation_redactor);
        let history_detector = Arc::clone(&self.leak_detector);
        crate::providers::history::register(self, history_slot, history_redactor, history_detector);
        // Tee T2 (CONTRACT-235): the scope-gated LLM delta subscribe route.
        let delta_slot = Arc::clone(&self.llm_delta_hub);
        let llm_deltas_enabled = self.config.llm_deltas_enabled;
        crate::deltas::register(self, delta_slot, llm_deltas_enabled);
    }

    /// Register a non-session exact-path route (health, or a provider/test handler).
    pub fn register(&mut self, method: Method, path: impl Into<String>, spec: HandlerSpec) {
        self.handlers.insert((method, path.into()), spec);
    }

    /// Register a templated route (e.g. `/client/runs/{run_id}:pause`). Matched only after an
    /// exact-path miss, preserving the FROZEN s1 gate order. s3/s4 reuse this.
    pub fn register_templated(&mut self, method: Method, template: &str, spec: HandlerSpec) {
        self.routes
            .push((method, RoutePattern::parse(template), spec));
    }

    /// Inject the run-control provider (Wave-25 composition root / witness). Overwrites the slot the
    /// runs-family closures read; `None` (default) → `module_unavailable`.
    pub fn with_run_provider(self, provider: Arc<dyn RunControlProvider>) -> Self {
        *self.run_provider.write().unwrap() = Some(provider);
        self
    }

    /// Inject the messaging provider (Wave-25 composition root / witness).
    pub fn with_messaging_provider(self, provider: Arc<dyn MessagingProvider>) -> Self {
        *self.messaging_provider.write().unwrap() = Some(provider);
        self
    }

    /// Inject the tools provider (Wave-25 composition root / witness).
    pub fn with_tools_provider(self, provider: Arc<dyn ToolsProvider>) -> Self {
        *self.tools_provider.write().unwrap() = Some(provider);
        self
    }

    /// Inject the event provider (m020-s3 / Wave-25 composition root).
    pub fn with_event_provider(self, provider: Arc<dyn ClientEventProvider>) -> Self {
        *self.event_provider.write().unwrap() = Some(provider);
        self
    }

    /// Inject the CONTRACT-112 leak detector used by event projection.
    pub fn with_leak_detector(self, detector: Arc<dyn LeakDetector>) -> Self {
        *self.leak_detector.write().unwrap() = Some(detector);
        self
    }

    /// Inject the cursor codec used to seal/open event ids and stream cursors.
    pub fn with_cursor_codec(self, codec: Arc<dyn ClientCursorCodec>) -> Self {
        *self.cursor_codec.write().unwrap() = Some(codec);
        self
    }

    pub fn with_bound_grant_provider(self, provider: Arc<dyn BoundGrantApprovalPort>) -> Self {
        *self.bound_grant_provider.write().unwrap() = Some(provider);
        self
    }

    pub fn with_bound_history_provider(self, provider: Arc<dyn BoundHistoryReadPort>) -> Self {
        *self.bound_history_provider.write().unwrap() = Some(provider);
        self
    }

    pub fn with_observation_redactor(self, redactor: Arc<SensitiveObservationRedactor>) -> Self {
        *self.observation_redactor.write().unwrap() = Some(redactor);
        self
    }

    /// Inject the tee T2 `LlmDeltaHub` (CONTRACT-235). Overwrites the slot the delta subscribe
    /// handler + WS pump read; `None` (default) → `module_unavailable`. The cli root wiring is
    /// EXPLICITLY out of scope (backlog #12).
    pub fn with_llm_delta_hub(self, hub: Arc<crate::deltas::LlmDeltaHub>) -> Self {
        *self.llm_delta_hub.write().unwrap() = Some(hub);
        self
    }

    /// The injected delta hub, if wired (transport pump).
    pub(crate) fn llm_delta_hub(&self) -> Option<Arc<crate::deltas::LlmDeltaHub>> {
        self.llm_delta_hub
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The injected cursor codec, if wired (transport pump seals/opens delta cursors with it).
    pub(crate) fn cursor_codec(&self) -> Option<Arc<dyn ClientCursorCodec>> {
        self.cursor_codec
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Clock read for the transport (subscribe-time `expires_at` mapping).
    pub(crate) fn now_millis(&self) -> u64 {
        self.clock.now_millis()
    }

    /// The current session's `expires_at` for a bearer token (subscribe-time lifetime cap).
    pub(crate) fn session_expires_at(&self, token: &str) -> Option<u64> {
        self.sessions
            .get_valid(token, self.clock.now_millis())
            .ok()
            .map(|s| s.expires_at)
    }

    /// Install a pump-exit observer (T26 witnesses; test-support only).
    #[cfg(feature = "test-support")]
    pub fn with_delta_pump_observer(self, observer: crate::deltas::DeltaPumpExitObserver) -> Self {
        *self.delta_pump_observer.write().unwrap() = Some(observer);
        self
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn delta_pump_observer(&self) -> Option<crate::deltas::DeltaPumpExitObserver> {
        self.delta_pump_observer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Install the externally anchored idempotency repository used by provider-backed grant
    /// mutations. Order-5 composition creates and recovers this repository before route exposure.
    pub fn with_durable_idempotency(
        mut self,
        repository: Arc<DurableIdempotencyRepository>,
    ) -> Self {
        self.durable_idempotency = Some(repository);
        self
    }

    /// Reconcile every retained CONTRACT-123 mutation before the transport exposes routes. The
    /// caller composes providers first, calls this method, and starts serving only after success.
    pub fn recover_durable_grants(&self) -> Result<(), ClientError> {
        use crate::durable_idempotency::{
            PHASE_PENDING, PHASE_PROVIDER_PREPARED, PHASE_RECOVERING,
        };
        use crate::providers::grants::{
            decode_canonical_grant_mutation, project_mutation_document, BoundMutationOutcome,
            ProviderPrepareOutcome,
        };

        let repository = self
            .durable_idempotency
            .as_ref()
            .ok_or_else(durable_failure)?;
        let provider = self
            .bound_grant_provider
            .read()
            .map_err(|_| durable_failure())?
            .clone()
            .ok_or_else(durable_failure)?;
        let redactor = self
            .observation_redactor
            .read()
            .map_err(|_| durable_failure())?
            .clone()
            .ok_or_else(durable_failure)?;
        let detector = self
            .leak_detector
            .read()
            .map_err(|_| durable_failure())?
            .clone()
            .ok_or_else(durable_failure)?;

        for receipt in repository.done_receipts(1).map_err(|_| durable_failure())? {
            provider
                .acknowledge_client_done_bound(&receipt)
                .map_err(|_| durable_failure())?;
        }

        for row in repository.recovery_rows().map_err(|_| durable_failure())? {
            if row.reservation.provider_tag != 1 {
                return Err(durable_failure());
            }
            if row.phase == PHASE_PENDING && !row.provider_entry_started {
                repository
                    .release_before_provider(&row.reservation)
                    .map_err(|_| durable_failure())?;
                continue;
            }
            let (mutation, response_kind) =
                decode_canonical_grant_mutation(row.canonical_request.as_slice())?;
            let operation_tag = mutation.operation_tag();
            if operation_tag != row.reservation.operation_tag {
                return Err(durable_failure());
            }
            let mut phase = row.phase;
            let ticket = if phase == PHASE_PENDING {
                match provider.prepare_mutation_bound(
                    row.reservation.mutation_id,
                    row.reservation.request_fingerprint,
                    mutation,
                ) {
                    ProviderPrepareOutcome::Prepared(ticket) => {
                        provider
                            .verify_recovery_ticket_bound(
                                row.reservation.mutation_id,
                                row.reservation.request_fingerprint,
                                operation_tag,
                                &ticket,
                            )
                            .map_err(|_| durable_failure())?;
                        repository
                            .store_prepared_ticket(
                                &row.reservation,
                                &ticket,
                                self.clock.now_millis(),
                            )
                            .map_err(|_| durable_failure())?;
                        phase = PHASE_PROVIDER_PREPARED;
                        ticket
                    }
                    ProviderPrepareOutcome::Rejected(error) => {
                        let envelope = ClientEnvelope::<serde_json::Value>::error(
                            row.original_request_id,
                            error.into_client_error(),
                            Vec::new(),
                        );
                        self.finish_recovered_grant(
                            repository,
                            provider.as_ref(),
                            &row.reservation,
                            &envelope,
                        )?;
                        continue;
                    }
                }
            } else {
                row.recovery_ticket.ok_or_else(durable_failure)?
            };
            provider
                .verify_recovery_ticket_bound(
                    row.reservation.mutation_id,
                    row.reservation.request_fingerprint,
                    operation_tag,
                    &ticket,
                )
                .map_err(|_| durable_failure())?;
            let outcome = if phase == PHASE_PROVIDER_PREPARED {
                repository
                    .mark_recovering(&row.reservation, None, self.clock.now_millis())
                    .map_err(|_| durable_failure())?;
                provider.execute_prepared_bound(&ticket)
            } else if phase == PHASE_RECOVERING {
                provider.recover_mutation_bound(&ticket)
            } else {
                return Err(durable_failure());
            };
            let envelope = match outcome {
                BoundMutationOutcome::Committed(bound) => {
                    match project_mutation_document(
                        bound,
                        redactor.as_ref(),
                        detector.as_ref(),
                        response_kind,
                    ) {
                        Ok(response) => ClientEnvelope::ok(
                            row.original_request_id,
                            response.data,
                            response.warnings,
                        ),
                        Err(error) => {
                            ClientEnvelope::error(row.original_request_id, error, Vec::new())
                        }
                    }
                }
                BoundMutationOutcome::Rejected(error) => ClientEnvelope::error(
                    row.original_request_id,
                    error.into_client_error(),
                    Vec::new(),
                ),
                BoundMutationOutcome::OutcomeUnknown(next) => {
                    provider
                        .verify_recovery_ticket_bound(
                            row.reservation.mutation_id,
                            row.reservation.request_fingerprint,
                            operation_tag,
                            &next,
                        )
                        .map_err(|_| durable_failure())?;
                    repository
                        .mark_recovering(&row.reservation, Some(&next), self.clock.now_millis())
                        .map_err(|_| durable_failure())?;
                    return Err(durable_failure());
                }
            };
            self.finish_recovered_grant(
                repository,
                provider.as_ref(),
                &row.reservation,
                &envelope,
            )?;
        }
        Ok(())
    }

    fn finish_recovered_grant(
        &self,
        repository: &DurableIdempotencyRepository,
        provider: &dyn BoundGrantApprovalPort,
        reservation: &DurableReservation,
        envelope: &ClientEnvelope<serde_json::Value>,
    ) -> Result<(), ClientError> {
        let blob = serde_json::to_vec(envelope).map_err(|_| durable_failure())?;
        let receipt = repository
            .finish_done(reservation, &blob, self.clock.now_millis())
            .map_err(|_| durable_failure())?;
        provider
            .acknowledge_client_done_bound(&receipt)
            .map_err(|_| durable_failure())
    }

    /// Match a templated route (m020-s2), returning its spec + bound path params. Consulted only on
    /// an exact-path miss.
    fn match_templated(
        &self,
        method: Method,
        path: &str,
    ) -> Option<(HandlerSpec, Vec<(String, String)>)> {
        for (m, pattern, spec) in &self.routes {
            if *m == method {
                if let Some(params) = pattern.matches(path) {
                    return Some((spec.clone(), params));
                }
            }
        }
        None
    }

    pub fn auth(&self) -> &ClientSessionAuth {
        &self.auth
    }
    pub fn sessions(&self) -> &SessionStore {
        &self.sessions
    }
    pub fn idempotency(&self) -> &IdempotencyStore {
        &self.idempotency
    }
    pub fn config(&self) -> &ClientApiConfig {
        &self.config
    }

    // ── Request handling ────────────────────────────────────────────────────────────────

    /// Handle a client request, returning a versioned envelope. Never panics; never re-executes
    /// an idempotent mutation; never calls a handler when a gate fails.
    pub fn handle(&self, req: ClientRequest) -> ClientEnvelope<serde_json::Value> {
        let request_id = new_request_id();
        let now = self.clock.now_millis();
        let method_str = format!("{:?}", req.method);

        // Bound the path length before deriving the family / audit label (uniform with the
        // api_version and idempotency-key bounds), rejecting an over-long path at the very front.
        if req.path.len() > self.config.max_path_len {
            return self.denied(
                &request_id,
                "root",
                &method_str,
                ClientErrorCode::RequestTooLarge,
                "path exceeds max length",
            );
        }
        let family = routes::family_of(&req.path);

        self.audit.emit(AuditEvent::new(
            "client_api.request",
            &request_id,
            &family,
            &method_str,
        ));

        // 1. Admission — loopback-only default bind.
        if let Err(code) = ClientSessionAuth::check_admission(&self.config, req.is_loopback_peer) {
            return self.denied(&request_id, &family, &method_str, code, "non-loopback peer");
        }
        // 2. Version — fail closed before any handler/provider.
        if let Err(e) = crate::version::check_version(&req.api_version) {
            return self.denied_err(&request_id, &family, &method_str, e);
        }
        // 3. Body size cap.
        if req.body_size() > self.config.max_body_bytes {
            return self.denied(
                &request_id,
                &family,
                &method_str,
                ClientErrorCode::RequestTooLarge,
                "body exceeds max",
            );
        }
        // 4. CORS/origin (fail-closed for a disallowed browser Origin).
        if let Err(code) = ClientSessionAuth::check_origin(&self.config, req.origin.as_deref()) {
            return self.denied(
                &request_id,
                &family,
                &method_str,
                code,
                "origin not allowed",
            );
        }
        // 5. Session-family ops.
        if let Some(op) = routes::session_op(req.method, &req.path) {
            return self.handle_session_op(&request_id, &family, &method_str, op, &req, now);
        }
        // 6. Generic route — exact match first, then templated provider families (m020-s2). The
        //    templated fallback lives INSIDE this route-lookup step, so the gate order is unchanged.
        let (spec, path_params) = match self.handlers.get(&(req.method, req.path.clone())) {
            Some(s) => (s.clone(), Vec::new()),
            None => match self.match_templated(req.method, &req.path) {
                Some(v) => v,
                None => {
                    return self.denied(
                        &request_id,
                        &family,
                        &method_str,
                        ClientErrorCode::UnknownRoute,
                        "no route",
                    )
                }
            },
        };
        // 7. Auth.
        let session = if spec.requires_session {
            match req.session_token.as_deref() {
                None => {
                    return self.denied(
                        &request_id,
                        &family,
                        &method_str,
                        ClientErrorCode::Unauthenticated,
                        "missing session",
                    )
                }
                Some(tok) => match self.sessions.get_valid(tok, now) {
                    Ok(s) => Some(s),
                    Err(code) => {
                        return self.denied(&request_id, &family, &method_str, code, "session")
                    }
                },
            }
        } else {
            None
        };

        // 7.5 Scope authorization — enforced AFTER authentication and BEFORE the mutation gate, so
        // an authenticated-but-under-scoped session is denied before any idempotency reservation or
        // replay lookup (the replay must not surface a privileged outcome to an under-scoped caller).
        // A scoped route implies a session; a scoped route with no session → forbidden.
        if !spec.required_scopes.is_empty() {
            let authorized = session
                .as_ref()
                .map(|s| spec.required_scopes.iter().all(|r| s.scopes.contains(r)))
                .unwrap_or(false);
            if !authorized {
                return self.denied(
                    &request_id,
                    &family,
                    &method_str,
                    ClientErrorCode::Forbidden,
                    "insufficient scope",
                );
            }
        }

        let ctx = HandlerCtx {
            request_id: request_id.clone(),
            principal: session.as_ref().map(|s| s.principal.clone()),
            scopes: session
                .as_ref()
                .map(|s| s.scopes.clone())
                .unwrap_or_default(),
            body: req.body.clone(),
            path_params,
            mutation: None,
        };

        // 8. Mutation gating (idempotency + CSRF + reserve-before-execute).
        if spec.is_mutation {
            let key = match req.idempotency_key.as_deref() {
                None => {
                    return self.denied(
                        &request_id,
                        &family,
                        &method_str,
                        ClientErrorCode::IdempotencyRequired,
                        "missing idempotency key",
                    )
                }
                Some(k) => k.to_string(),
            };
            if key.len() > self.config.max_idempotency_key_len {
                return self.denied(
                    &request_id,
                    &family,
                    &method_str,
                    ClientErrorCode::RequestTooLarge,
                    "idempotency key exceeds max length",
                );
            }
            let session_csrf = session.as_ref().and_then(|s| s.csrf_token.as_deref());
            if let Err(code) = ClientSessionAuth::check_csrf(
                req.origin.as_deref(),
                req.csrf_token.as_deref(),
                session_csrf,
            ) {
                return self.denied(&request_id, &family, &method_str, code, "csrf");
            }
            let principal_id = session
                .as_ref()
                .map(|s| s.principal.id.clone())
                .unwrap_or_else(|| "anonymous".to_string());
            let scope = IdempotencyScope {
                principal: principal_id,
                method: req.method,
                family: family.clone(),
                key,
            };
            let request_fingerprint = request_fingerprint(&req);
            if let (Some(repository), Some((provider_tag, operation_tag))) = (
                self.durable_idempotency.as_ref(),
                durable_provider_operation(&req.path),
            ) {
                let grant_request =
                    match crate::providers::grants::canonical_grant_request(&req.path, &req.body) {
                        Ok(request) => request,
                        Err(error) => {
                            return self.denied_err(&request_id, &family, &method_str, error)
                        }
                    };
                let canonical_request = canonical_durable_request(&req, grant_request);
                let request_fingerprint = fingerprint_canonical_request(&canonical_request);
                return self.handle_durable_mutation(
                    Arc::clone(repository),
                    provider_tag,
                    operation_tag,
                    &spec,
                    ctx,
                    &request_id,
                    &family,
                    &method_str,
                    scope,
                    request_fingerprint,
                    canonical_request,
                    now,
                );
            }
            match self
                .idempotency
                .begin_fingerprinted(&scope, request_fingerprint, now)
            {
                Begin::Replay(record) => {
                    let mut warnings = record.warnings;
                    warnings.push(ClientWarning::new(
                        "idempotent_replay",
                        format!(
                            "replayed prior outcome; original request_id {}",
                            record.original_request_id
                        ),
                    ));
                    // Audit the CURRENT (replay) request so its request→response pair matches;
                    // the returned envelope keeps the ORIGINAL request_id (§1.4.1 replay echo).
                    self.audit.emit(AuditEvent::new(
                        "client_api.response",
                        &request_id,
                        &family,
                        &method_str,
                    ));
                    match record.outcome {
                        IdempotencyOutcome::Success(data) => {
                            ClientEnvelope::ok(record.original_request_id, data, warnings)
                        }
                        IdempotencyOutcome::Error(error) => {
                            ClientEnvelope::error(record.original_request_id, error, warnings)
                        }
                    }
                }
                Begin::InProgress => self.denied(
                    &request_id,
                    &family,
                    &method_str,
                    ClientErrorCode::IdempotencyInProgress,
                    "in progress",
                ),
                Begin::Conflict => self.denied(
                    &request_id,
                    &family,
                    &method_str,
                    ClientErrorCode::IdempotencyConflict,
                    "idempotency key used for a different request",
                ),
                Begin::Reserved(guard) => {
                    let mut mutation_ctx = ctx.clone();
                    mutation_ctx.mutation = Some(ClientMutationContext {
                        request_fingerprint,
                        mutation_id: mutation_id(&scope, request_fingerprint),
                        provider_entry_started: Arc::new(AtomicBool::new(false)),
                        recovery_pending: Arc::new(AtomicBool::new(false)),
                        durable: None,
                    });
                    match run_handler(&spec.func, &mutation_ctx) {
                        Ok(response) => {
                            guard.commit_with_warnings(
                                response.data.clone(),
                                request_id.clone(),
                                response.warnings.clone(),
                                now,
                            );
                            self.audit.emit(AuditEvent::new(
                                "client_api.response",
                                &request_id,
                                &family,
                                &method_str,
                            ));
                            ClientEnvelope::ok(request_id, response.data, response.warnings)
                        }
                        Err(e) => {
                            let provider_entered = mutation_ctx
                                .mutation
                                .as_ref()
                                .is_some_and(ClientMutationContext::provider_entry_started);
                            let recovery_pending = mutation_ctx
                                .mutation
                                .as_ref()
                                .is_some_and(ClientMutationContext::recovery_pending);
                            if recovery_pending {
                                guard.retain();
                            } else if provider_entered {
                                guard.commit_error(e.clone(), request_id.clone(), Vec::new(), now);
                            } else {
                                // Validation/provider-availability failures before provider entry
                                // remain retryable and release this reservation.
                                drop(guard);
                            }
                            self.denied_err(&request_id, &family, &method_str, e)
                        }
                    }
                }
            }
        } else {
            match run_handler(&spec.func, &ctx) {
                Ok(response) => {
                    self.audit.emit(AuditEvent::new(
                        "client_api.response",
                        &request_id,
                        &family,
                        &method_str,
                    ));
                    ClientEnvelope::ok(request_id, response.data, response.warnings)
                }
                Err(e) => self.denied_err(&request_id, &family, &method_str, e),
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_durable_mutation(
        &self,
        repository: Arc<DurableIdempotencyRepository>,
        provider_tag: u8,
        operation_tag: u8,
        spec: &HandlerSpec,
        mut ctx: HandlerCtx,
        request_id: &str,
        family: &str,
        method_str: &str,
        scope: IdempotencyScope,
        request_fingerprint: [u8; 32],
        canonical_request: Vec<u8>,
        now: u64,
    ) -> ClientEnvelope<serde_json::Value> {
        let input = DurableReserveInput {
            principal: scope.principal,
            method: method_str.to_ascii_uppercase(),
            family: scope.family,
            idempotency_key: scope.key,
            request_fingerprint,
            canonical_request,
            provider_tag,
            operation_tag,
            original_request_id: request_id.to_owned(),
            now_ms: now,
        };
        let begin = match repository.reserve(input) {
            Ok(begin) => begin,
            Err(_) => {
                return self.denied(
                    request_id,
                    family,
                    method_str,
                    ClientErrorCode::ModuleUnavailable,
                    "durable idempotency unavailable",
                )
            }
        };
        let reservation = match begin {
            DurableBegin::Replay(done) => {
                let mut envelope: ClientEnvelope<serde_json::Value> =
                    match serde_json::from_slice(&done.outcome_blob) {
                        Ok(envelope) => envelope,
                        Err(_) => {
                            return self.denied(
                                request_id,
                                family,
                                method_str,
                                ClientErrorCode::ModuleUnavailable,
                                "durable replay unavailable",
                            )
                        }
                    };
                envelope.warnings.push(ClientWarning::new(
                    "idempotent_replay",
                    format!(
                        "replayed prior outcome; original request_id {}",
                        done.original_request_id
                    ),
                ));
                self.audit.emit(AuditEvent::new(
                    "client_api.response",
                    request_id,
                    family,
                    method_str,
                ));
                return envelope;
            }
            DurableBegin::InProgress => {
                return self.denied(
                    request_id,
                    family,
                    method_str,
                    ClientErrorCode::IdempotencyInProgress,
                    "in progress",
                )
            }
            DurableBegin::Conflict => {
                return self.denied(
                    request_id,
                    family,
                    method_str,
                    ClientErrorCode::IdempotencyConflict,
                    "idempotency key used for a different request",
                )
            }
            DurableBegin::Capacity => {
                return self.denied(
                    request_id,
                    family,
                    method_str,
                    ClientErrorCode::IdempotencyCapacity,
                    "idempotency capacity exhausted",
                )
            }
            DurableBegin::Reserved(reservation) => reservation,
        };
        ctx.mutation = Some(ClientMutationContext {
            request_fingerprint,
            mutation_id: reservation.mutation_id,
            provider_entry_started: Arc::new(AtomicBool::new(false)),
            recovery_pending: Arc::new(AtomicBool::new(false)),
            durable: Some(DurableMutationControl {
                repository: Arc::clone(&repository),
                reservation: reservation.clone(),
                now_ms: now,
            }),
        });
        match run_handler(&spec.func, &ctx) {
            Ok(response) => {
                let envelope =
                    ClientEnvelope::ok(request_id.to_owned(), response.data, response.warnings);
                if self
                    .finish_durable_outcome(&repository, &reservation, &envelope)
                    .is_err()
                {
                    return self.denied(
                        request_id,
                        family,
                        method_str,
                        ClientErrorCode::ModuleUnavailable,
                        "durable outcome unavailable",
                    );
                }
                self.audit.emit(AuditEvent::new(
                    "client_api.response",
                    request_id,
                    family,
                    method_str,
                ));
                envelope
            }
            Err(error) => {
                let admitted = ctx.mutation.as_ref().expect("durable mutation context");
                if admitted.recovery_pending() {
                    return self.denied_err(request_id, family, method_str, error);
                }
                if admitted.provider_entry_started() {
                    let envelope = ClientEnvelope::<serde_json::Value>::error(
                        request_id.to_owned(),
                        error.clone(),
                        Vec::new(),
                    );
                    if self
                        .finish_durable_outcome(&repository, &reservation, &envelope)
                        .is_err()
                    {
                        return self.denied(
                            request_id,
                            family,
                            method_str,
                            ClientErrorCode::ModuleUnavailable,
                            "durable outcome unavailable",
                        );
                    }
                    self.denied_err(request_id, family, method_str, error)
                } else {
                    if repository.release_before_provider(&reservation).is_err() {
                        return self.denied(
                            request_id,
                            family,
                            method_str,
                            ClientErrorCode::ModuleUnavailable,
                            "durable reservation release unavailable",
                        );
                    }
                    self.denied_err(request_id, family, method_str, error)
                }
            }
        }
    }

    fn finish_durable_outcome(
        &self,
        repository: &DurableIdempotencyRepository,
        reservation: &DurableReservation,
        envelope: &ClientEnvelope<serde_json::Value>,
    ) -> Result<(), ()> {
        let blob = serde_json::to_vec(envelope).map_err(|_| ())?;
        let receipt = repository
            .finish_done(reservation, &blob, self.clock.now_millis())
            .map_err(|_| ())?;
        if reservation.provider_tag == 1 {
            if let Some(provider) = self.bound_grant_provider.read().unwrap().as_ref() {
                let _ = provider.acknowledge_client_done_bound(&receipt);
            }
        }
        Ok(())
    }

    fn handle_session_op(
        &self,
        request_id: &str,
        family: &str,
        method_str: &str,
        op: SessionOp,
        req: &ClientRequest,
        now: u64,
    ) -> ClientEnvelope<serde_json::Value> {
        match op {
            SessionOp::Login => self.session_login(request_id, family, method_str, req, now),
            SessionOp::Refresh => self.session_refresh(request_id, family, method_str, req, now),
            SessionOp::Logout => self.session_logout(request_id, family, method_str, req, now),
        }
    }

    fn session_login(
        &self,
        request_id: &str,
        family: &str,
        method_str: &str,
        req: &ClientRequest,
        now: u64,
    ) -> ClientEnvelope<serde_json::Value> {
        // Bootstrap: loopback → OS-user operator; non-loopback → one-time code.
        if !req.is_loopback_peer {
            let code = match req.body.get("bootstrap_code").and_then(|v| v.as_str()) {
                Some(c) => c,
                None => {
                    return self.denied(
                        request_id,
                        family,
                        method_str,
                        ClientErrorCode::InvalidBootstrapCode,
                        "bootstrap code required",
                    )
                }
            };
            if let Err(code) = self.auth.verify_bootstrap_code(code, now) {
                return self.denied(request_id, family, method_str, code, "bootstrap");
            }
        }

        let principal = Principal::operator(self.auth.os_user());
        let platform = platform_from_body(&req.body, req.origin.is_some());
        let csrf_token = if req.origin.is_some() {
            Some(self.auth.generate_csrf_token())
        } else {
            None
        };
        let token = self.auth.generate_token();
        let session_id = self.auth.generate_session_id();
        let expires_at = now.saturating_add(self.config.session_ttl_ms);
        let scopes = Scope::operator_default();

        let session = crate::session::ClientSession {
            session_id: session_id.clone(),
            principal: principal.clone(),
            platform,
            scopes: scopes.clone(),
            csrf_token: csrf_token.clone(),
            expires_at,
        };
        self.sessions.insert(token.clone(), session, now);

        let info = SessionInfo {
            session_id,
            token,
            principal,
            platform,
            scopes,
            csrf_token,
            expires_at,
        };
        self.audit.emit(AuditEvent::new(
            "client_api.response",
            request_id,
            family,
            method_str,
        ));
        ClientEnvelope::ok(
            request_id,
            serde_json::to_value(info).expect("SessionInfo serializes"),
            vec![],
        )
    }

    fn session_refresh(
        &self,
        request_id: &str,
        family: &str,
        method_str: &str,
        req: &ClientRequest,
        now: u64,
    ) -> ClientEnvelope<serde_json::Value> {
        let token = match req.session_token.as_deref() {
            Some(t) => t,
            None => {
                return self.denied(
                    request_id,
                    family,
                    method_str,
                    ClientErrorCode::Unauthenticated,
                    "missing session",
                )
            }
        };
        // Validate + CSRF (browser) before rotating.
        let current = match self.sessions.get_valid(token, now) {
            Ok(s) => s,
            Err(code) => return self.denied(request_id, family, method_str, code, "session"),
        };
        if let Err(code) = ClientSessionAuth::check_csrf(
            req.origin.as_deref(),
            req.csrf_token.as_deref(),
            current.csrf_token.as_deref(),
        ) {
            return self.denied(request_id, family, method_str, code, "csrf");
        }
        let new_token = self.auth.generate_token();
        let new_expires = now.saturating_add(self.config.session_ttl_ms);
        let (new_token, session) = match self.sessions.refresh(token, now, new_expires, new_token) {
            Ok(v) => v,
            Err(code) => return self.denied(request_id, family, method_str, code, "session"),
        };
        let info = SessionInfo {
            session_id: session.session_id,
            token: new_token,
            principal: session.principal,
            platform: session.platform,
            scopes: session.scopes,
            csrf_token: session.csrf_token,
            expires_at: session.expires_at,
        };
        self.audit.emit(AuditEvent::new(
            "client_api.response",
            request_id,
            family,
            method_str,
        ));
        ClientEnvelope::ok(
            request_id,
            serde_json::to_value(info).expect("SessionInfo serializes"),
            vec![],
        )
    }

    fn session_logout(
        &self,
        request_id: &str,
        family: &str,
        method_str: &str,
        req: &ClientRequest,
        now: u64,
    ) -> ClientEnvelope<serde_json::Value> {
        let token = match req.session_token.as_deref() {
            Some(t) => t,
            None => {
                return self.denied(
                    request_id,
                    family,
                    method_str,
                    ClientErrorCode::Unauthenticated,
                    "missing session",
                )
            }
        };
        let current = match self.sessions.get_valid(token, now) {
            Ok(s) => s,
            Err(code) => return self.denied(request_id, family, method_str, code, "session"),
        };
        if let Err(code) = ClientSessionAuth::check_csrf(
            req.origin.as_deref(),
            req.csrf_token.as_deref(),
            current.csrf_token.as_deref(),
        ) {
            return self.denied(request_id, family, method_str, code, "csrf");
        }
        // Revoke by session id (not just this token) so a concurrent refresh that rotated the
        // token in the validate→revoke window cannot keep the session alive.
        self.sessions.revoke_session(&current.session_id);
        self.audit.emit(AuditEvent::new(
            "client_api.response",
            request_id,
            family,
            method_str,
        ));
        ClientEnvelope::ok(request_id, json!({ "revoked": true }), vec![])
    }

    // ── Envelope helpers ────────────────────────────────────────────────────────────────

    fn denied(
        &self,
        request_id: &str,
        family: &str,
        method_str: &str,
        code: ClientErrorCode,
        message: &str,
    ) -> ClientEnvelope<serde_json::Value> {
        self.denied_err(
            request_id,
            family,
            method_str,
            ClientError::new(code, message),
        )
    }

    fn denied_err(
        &self,
        request_id: &str,
        family: &str,
        method_str: &str,
        err: ClientError,
    ) -> ClientEnvelope<serde_json::Value> {
        // Module unavailability → provider_unavailable; stream capacity → stream_backpressure;
        // all other denials → client_api.denied (D9).
        let kind = match err.code {
            ClientErrorCode::ModuleUnavailable => "client_api.provider_unavailable",
            ClientErrorCode::StreamBackpressure => "client_api.stream_backpressure",
            _ => "client_api.denied",
        };
        self.audit.emit(
            AuditEvent::new(kind, request_id, family, method_str).with_reason(err.code.as_str()),
        );
        ClientEnvelope::error(request_id, err, vec![])
    }
}

/// Invoke a handler, converting a panic into `module_unavailable` so the public API never
/// unwinds (the reservation guard's `Drop` still runs during unwind, releasing the slot).
fn run_handler(func: &HandlerFn, ctx: &HandlerCtx) -> Result<HandlerResponse, ClientError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| func(ctx))) {
        Ok(result) => result,
        Err(_) => Err(ClientError::new(
            ClientErrorCode::ModuleUnavailable,
            "handler panicked",
        )),
    }
}

fn durable_failure() -> ClientError {
    ClientError::new(
        ClientErrorCode::ModuleUnavailable,
        "durable mutation state unavailable",
    )
}

fn new_request_id() -> String {
    format!("req_{}", uuid::Uuid::new_v4().simple())
}

/// Stable request fingerprint used by the foundation idempotency gate.  Provider-backed grant
/// mutations additionally use their closed typed canonical encoders; this outer fingerprint still
/// ensures every mutation family rejects key reuse across API version, method, exact path/target,
/// and JSON body before entering a provider.
fn request_fingerprint(req: &ClientRequest) -> [u8; 32] {
    let canonical = canonical_request_bytes(req);
    fingerprint_canonical_request(&canonical)
}

fn fingerprint_canonical_request(canonical: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"advance.contract190.idempotency-request.v1\0");
    hasher.update(canonical);
    hasher.finalize().into()
}

fn canonical_durable_request(
    req: &ClientRequest,
    grant: crate::providers::grants::CanonicalGrantRequest,
) -> Vec<u8> {
    fn put(output: &mut Vec<u8>, value: &[u8]) {
        output.extend_from_slice(&(value.len() as u32).to_be_bytes());
        output.extend_from_slice(value);
    }

    let mut output = vec![1];
    put(&mut output, req.api_version.as_bytes());
    put(
        &mut output,
        match req.method {
            Method::Get => b"GET",
            Method::Post => b"POST",
        },
    );
    put(&mut output, grant.route_template.as_bytes());
    output.extend_from_slice(&(grant.path_params.len() as u32).to_be_bytes());
    for (name, value) in grant.path_params {
        put(&mut output, name.as_bytes());
        put(&mut output, value.as_bytes());
    }
    // The transport-agnostic request model has no independent query collection. Grant mutations
    // accept no query parameters, so the canonical query count is exactly zero.
    output.extend_from_slice(&0u32.to_be_bytes());
    output.extend_from_slice(&grant.body_schema_tag.to_be_bytes());
    output.extend_from_slice(&(grant.typed_body.len() as u32).to_be_bytes());
    output.extend_from_slice(&grant.typed_body);
    output
}

fn canonical_request_bytes(req: &ClientRequest) -> Vec<u8> {
    fn put(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(bytes);
    }

    let mut canonical = Vec::new();
    canonical.push(1);
    put(&mut canonical, req.api_version.as_bytes());
    put(
        &mut canonical,
        match req.method {
            Method::Get => b"GET",
            Method::Post => b"POST",
        },
    );
    put(&mut canonical, req.path.as_bytes());
    let body = crate::schema::canonical_json(&req.body);
    put(&mut canonical, body.as_bytes());
    canonical
}

fn durable_provider_operation(path: &str) -> Option<(u8, u8)> {
    if path.starts_with("/client/grants/pending/") && path.ends_with(":approve") {
        Some((1, 1))
    } else if path.starts_with("/client/grants/pending/") && path.ends_with(":deny") {
        Some((1, 2))
    } else if path.starts_with("/client/grants/pending/") && path.ends_with(":narrow") {
        Some((1, 3))
    } else if path.starts_with("/client/grants/") && path.ends_with(":revoke") {
        Some((1, 4))
    } else if path.starts_with("/client/presets/") && path.ends_with(":apply") {
        Some((1, 5))
    } else {
        None
    }
}

fn mutation_id(scope: &IdempotencyScope, request_fingerprint: [u8; 32]) -> [u8; 32] {
    fn put(hasher: &mut Sha256, bytes: &[u8]) {
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }

    let mut hasher = Sha256::new();
    hasher.update(b"advance.contract190.mutation-id.v1\0");
    put(&mut hasher, scope.principal.as_bytes());
    hasher.update([match scope.method {
        Method::Get => 1,
        Method::Post => 2,
    }]);
    put(&mut hasher, scope.family.as_bytes());
    put(&mut hasher, scope.key.as_bytes());
    hasher.update(request_fingerprint);
    hasher.finalize().into()
}

fn platform_from_body(body: &serde_json::Value, has_origin: bool) -> Platform {
    if let Some(p) = body.get("platform") {
        if let Ok(platform) = serde_json::from_value::<Platform>(p.clone()) {
            return platform;
        }
    }
    if has_origin {
        Platform::Web
    } else {
        Platform::Mac
    }
}

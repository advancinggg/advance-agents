//! CONTRACT-191 client event stream + historical query facade.
//!
//! Sync handlers for `GET /client/events` and `GET /client/events/stream`. All access goes through
//! `ClientApi::handle()`. Provider/detector/codec are injectable slots (fail-closed when absent).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, SecondsFormat, Utc};
use schemars::JsonSchema;
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::api::{ClientApi, HandlerCtx, HandlerSpec};
use crate::audit::{AuditEvent, AuditSink};
use crate::config::ClientApiConfig;
use crate::cursor::{
    ClientCursorCodec, OpenedSeal, SealPurpose, EMPTY_JOIN_WATERMARK_BODY, SEAL_TAG_EMPTY_JOIN,
    SEAL_TAG_RAW_ID,
};
use crate::envelope::{ClientError, ClientErrorCode};
use crate::projection::{self, ProjectOutcome};
use crate::provider::{
    provider_or_unavailable_msg, CursorCodecSlot, EventProviderSlot, LeakDetectorSlot,
    ProviderError,
};
use crate::request::Method;
use crate::routes;
use crate::session::Scope;
use advance_shared_types::security_validator::LeakDetector;

// ── Resource constants (D7) ───────────────────────────────────────────────────────────────

pub const HISTORY_RAW_WINDOW_ROWS: usize = 64;
pub const STREAM_DELIVERY_MAX_ROWS: usize = 32;
pub const STREAM_SCAN_MAX_ROWS: usize = 64;
pub const MAX_CONCURRENT_EVENT_READS_HARD: usize = 4;
pub const MAX_CONCURRENT_EVENT_STREAMS: usize = 1;
pub const MIN_EVENT_RESPONSE_BYTES: usize = 8 * 1024;
pub const MAX_EVENT_RESPONSE_BYTES_HARD: usize = 1024 * 1024;
pub const EVENT_RESPONSE_ENVELOPE_RESERVE_BYTES: usize = 4096;
pub const MIN_EVENT_STREAM_RECV_IDLE_MS: u64 = 50;
pub const MAX_EVENT_STREAM_RECV_IDLE_MS: u64 = 250;

const STREAM_FP_DOMAIN: &str = "advance/client-event-stream/v1";
const MAX_AGENT_FILTER: usize = 256;
const MAX_RUN_FILTER: usize = 64;
const MAX_TRACE_FILTER: usize = 256;
const MAX_SINCE_FILTER: usize = 64;
/// Conservative ASCII budget for sealed `c1.*` tokens in response-size trials (real AEAD tokens
/// are shorter; overestimate steers overflow into drop/defer rules rather than final fail-closed).
const SEALED_TOKEN_BUDGET_PLACEHOLDER: &str =
    "c1.default.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

// ── Wire DTOs ─────────────────────────────────────────────────────────────────────────────

/// Client-visible event priority (`normal` / `low`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClientEventPriority {
    Normal,
    Low,
}

/// Scalar leaf in `ClientEvent.data` (untagged JSON scalar).
#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum ClientScalar {
    Bool(bool),
    Unsigned(u64),
    Signed(i64),
    Float(f64),
    String(String),
}

impl<'de> Deserialize<'de> for ClientScalar {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v = Value::deserialize(deserializer)?;
        match v {
            Value::Bool(b) => Ok(ClientScalar::Bool(b)),
            Value::Number(n) => {
                if let Some(u) = n.as_u64() {
                    Ok(ClientScalar::Unsigned(u))
                } else if let Some(i) = n.as_i64() {
                    Ok(ClientScalar::Signed(i))
                } else if let Some(f) = n.as_f64() {
                    if f.is_finite() {
                        Ok(ClientScalar::Float(f))
                    } else {
                        Err(de::Error::custom("non-finite float"))
                    }
                } else {
                    Err(de::Error::custom("invalid number"))
                }
            }
            Value::String(s) => Ok(ClientScalar::String(s)),
            _ => Err(de::Error::custom("expected scalar")),
        }
    }
}

/// Projected client-safe event.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientEvent {
    pub event_id: String,
    pub event_type: String,
    pub timestamp: String,
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    pub priority: ClientEventPriority,
    pub data: BTreeMap<String, ClientScalar>,
}

/// Stream cursor: filter fingerprint + sealed last_event_id.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientEventCursor {
    pub stream_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_event_id: Option<String>,
}

/// Optional filter dimensions.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientEventFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
}

/// History request body (strict).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientEventsRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// Stream request body (strict).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientEventStreamRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_event_id: Option<String>,
}

/// Page of projected events + honesty counters.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientEventPage {
    pub events: Vec<ClientEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<ClientEventCursor>,
    pub dropped_count: u32,
    pub rejected_count: u32,
    pub redacted_count: u32,
    pub raw_limit_reached: bool,
    pub response_limit_reached: bool,
}

// ── Provider port ─────────────────────────────────────────────────────────────────────────

/// Owned raw row returned by the event provider (no raw id ever leaves sealed).
#[derive(Debug, Clone)]
pub struct RawEventRow {
    pub raw_id: String,
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub agent_id: String,
    pub run_id: Option<String>,
    pub trace_id: String,
    pub payload: Value,
}

/// Normalized filter passed to the provider (after client validation).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NormalizedEventFilter {
    pub event_type: Option<String>,
    pub agent_id: Option<String>,
    pub run_id: Option<String>,
    pub trace_id: Option<String>,
    /// Normalized UTC nanosecond form when present.
    pub since: Option<String>,
}

/// Sync client-api-owned event provider port.
pub trait ClientEventProvider: Send + Sync {
    /// Retention days copied from EventBus config at adapter construction.
    fn retention_days(&self) -> u32;
    /// High-water tip via CONTRACT-185 query limit 1. Err → module_unavailable.
    fn latest_raw_event_id(&self) -> Result<Option<String>, ProviderError>;
    /// History: most-recent-first raw window with provider filters.
    fn query_history(
        &self,
        filter: &NormalizedEventFilter,
        limit: usize,
    ) -> Result<Vec<RawEventRow>, ProviderError>;
    /// Stream drain: unfiltered at client dimensions; idle-bounded recv.
    /// `after_raw_id`: None = resume(None); Some = resume(Some(ReadCursor)).
    fn drain_stream(
        &self,
        after_raw_id: Option<&str>,
        scan_ceiling: usize,
        idle_ms: u64,
    ) -> Result<Vec<RawEventRow>, ProviderError>;
}

// ── Concurrency limiters ──────────────────────────────────────────────────────────────────

/// Per-ClientApi event-read concurrency (1 stream + up to 4 total reads).
pub struct EventConcurrency {
    stream_inflight: AtomicUsize,
    total_inflight: AtomicUsize,
    max_total: usize,
}

impl EventConcurrency {
    pub fn new(max_total: usize) -> Self {
        Self {
            stream_inflight: AtomicUsize::new(0),
            total_inflight: AtomicUsize::new(0),
            max_total: max_total.min(MAX_CONCURRENT_EVENT_READS_HARD).max(1),
        }
    }

    fn try_acquire_total(&self) -> Option<TotalGuard<'_>> {
        loop {
            let cur = self.total_inflight.load(Ordering::SeqCst);
            if cur >= self.max_total {
                return None;
            }
            if self
                .total_inflight
                .compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Some(TotalGuard { lim: self });
            }
        }
    }

    fn try_acquire_stream(&self) -> Option<StreamGuard<'_>> {
        // Stream slot first, then total-read.
        loop {
            let cur = self.stream_inflight.load(Ordering::SeqCst);
            if cur >= MAX_CONCURRENT_EVENT_STREAMS {
                return None;
            }
            if self
                .stream_inflight
                .compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                break;
            }
        }
        match self.try_acquire_total() {
            Some(total) => Some(StreamGuard {
                lim: self,
                _total: total,
            }),
            None => {
                self.stream_inflight.fetch_sub(1, Ordering::SeqCst);
                None
            }
        }
    }
}

struct TotalGuard<'a> {
    lim: &'a EventConcurrency,
}
impl Drop for TotalGuard<'_> {
    fn drop(&mut self) {
        self.lim.total_inflight.fetch_sub(1, Ordering::SeqCst);
    }
}

struct StreamGuard<'a> {
    lim: &'a EventConcurrency,
    _total: TotalGuard<'a>,
}
impl Drop for StreamGuard<'_> {
    fn drop(&mut self) {
        self.lim.stream_inflight.fetch_sub(1, Ordering::SeqCst);
    }
}

// ── Static error helpers (D8 event path — exact messages) ─────────────────────────────────

fn err_invalid_filter() -> ClientError {
    ClientError::new(ClientErrorCode::InvalidState, "invalid event filter")
}
fn err_cursor_incomplete() -> ClientError {
    ClientError::new(
        ClientErrorCode::InvalidState,
        "event stream cursor incomplete",
    )
}
fn err_stream_mismatch() -> ClientError {
    ClientError::new(
        ClientErrorCode::InvalidState,
        "event stream does not match filter",
    )
}
fn err_cursor_not_found() -> ClientError {
    ClientError::new(ClientErrorCode::NotFound, "event cursor not found")
}
fn err_provider_unavailable() -> ClientError {
    ClientError::new(
        ClientErrorCode::ModuleUnavailable,
        "event provider unavailable",
    )
}
fn err_provider_not_wired() -> ClientError {
    ClientError::new(
        ClientErrorCode::ModuleUnavailable,
        "event provider not wired",
    )
}
fn err_detector_not_wired() -> ClientError {
    ClientError::new(
        ClientErrorCode::ModuleUnavailable,
        "event leak detector not wired",
    )
}
fn err_codec_not_wired() -> ClientError {
    ClientError::new(
        ClientErrorCode::ModuleUnavailable,
        "event cursor codec not wired",
    )
}
fn err_config_invalid() -> ClientError {
    ClientError::new(ClientErrorCode::ModuleUnavailable, "event config invalid")
}
fn err_capacity() -> ClientError {
    ClientError::new(
        ClientErrorCode::StreamBackpressure,
        "event read capacity exceeded",
    )
}

fn map_provider_err(e: ProviderError) -> ClientError {
    match e {
        ProviderError::NotFound(_) => err_cursor_not_found(),
        ProviderError::InvalidState(_) => err_invalid_filter(),
        ProviderError::Unavailable(_) => err_provider_unavailable(),
        other => {
            // Event path never uses into_client_error messages.
            let _ = other;
            err_provider_unavailable()
        }
    }
}

// ── Filter normalization + stream_id ──────────────────────────────────────────────────────

fn filter_fingerprint_body(filter: &NormalizedEventFilter) -> Vec<u8> {
    let mut buf = Vec::new();
    push_lp_str(&mut buf, STREAM_FP_DOMAIN);
    push_lp_opt(&mut buf, filter.event_type.as_deref());
    push_lp_opt(&mut buf, filter.agent_id.as_deref());
    push_lp_opt(&mut buf, filter.run_id.as_deref());
    push_lp_opt(&mut buf, filter.trace_id.as_deref());
    push_lp_opt(&mut buf, filter.since.as_deref());
    buf
}

/// Wire `stream_id` = `ces1.` + base64url-no-pad(SHA-256(fingerprint body)).
pub fn stream_id_for_filter(filter: &NormalizedEventFilter) -> String {
    let body = filter_fingerprint_body(filter);
    let digest = Sha256::digest(&body);
    format!("ces1.{}", URL_SAFE_NO_PAD.encode(digest))
}

/// History event-id AAD stream-id field.
fn history_stream_id_aad(filter: &NormalizedEventFilter) -> String {
    let body = filter_fingerprint_body(filter);
    let digest = Sha256::digest(&body);
    format!("ces1.history.{}", URL_SAFE_NO_PAD.encode(digest))
}

fn push_lp_str(buf: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    buf.extend_from_slice(&(b.len() as u16).to_be_bytes());
    buf.extend_from_slice(b);
}

fn push_lp_opt(buf: &mut Vec<u8>, s: Option<&str>) {
    match s {
        Some(v) => push_lp_str(buf, v),
        None => buf.extend_from_slice(&0u16.to_be_bytes()),
    }
}

fn normalize_filter_fields(
    event_type: Option<String>,
    agent_id: Option<String>,
    run_id: Option<String>,
    trace_id: Option<String>,
    since: Option<String>,
) -> Result<NormalizedEventFilter, ClientError> {
    let event_type = match event_type {
        None => None,
        Some(s) => {
            if !projection::is_accepted_event_type(&s) {
                return Err(err_invalid_filter());
            }
            Some(s)
        }
    };
    let agent_id = match agent_id {
        None => None,
        Some(s) => {
            if s.is_empty() || s.len() > MAX_AGENT_FILTER {
                return Err(err_invalid_filter());
            }
            Some(s)
        }
    };
    let run_id = match run_id {
        None => None,
        Some(s) => {
            if s.is_empty() || s.len() > MAX_RUN_FILTER {
                return Err(err_invalid_filter());
            }
            Some(s)
        }
    };
    let trace_id = match trace_id {
        None => None,
        Some(s) => {
            if s.is_empty() || s.len() > MAX_TRACE_FILTER {
                return Err(err_invalid_filter());
            }
            Some(s)
        }
    };
    let since = match since {
        None => None,
        Some(s) => {
            if s.len() > MAX_SINCE_FILTER {
                return Err(err_invalid_filter());
            }
            let dt = DateTime::parse_from_rfc3339(&s)
                .map(|d| d.with_timezone(&Utc))
                .map_err(|_| err_invalid_filter())?;
            Some(dt.to_rfc3339_opts(SecondsFormat::Nanos, true))
        }
    };
    Ok(NormalizedEventFilter {
        event_type,
        agent_id,
        run_id,
        trace_id,
        since,
    })
}

// ── Null-first body parse ─────────────────────────────────────────────────────────────────

struct HistoryParse {
    filter: NormalizedEventFilter,
    limit: usize,
}

struct StreamParse {
    filter: NormalizedEventFilter,
    limit: usize,
    stream_id: Option<String>,
    last_event_id: Option<String>,
}

fn parse_history_body(body: &Value) -> Result<HistoryParse, ClientError> {
    match body {
        Value::Null => Ok(HistoryParse {
            filter: NormalizedEventFilter::default(),
            limit: HISTORY_RAW_WINDOW_ROWS,
        }),
        Value::Object(_) => {
            let req: ClientEventsRequest =
                serde_json::from_value(body.clone()).map_err(|_| err_invalid_filter())?;
            let filter = normalize_filter_fields(
                req.event_type,
                req.agent_id,
                req.run_id,
                req.trace_id,
                req.since,
            )?;
            let limit = match req.limit {
                None => HISTORY_RAW_WINDOW_ROWS,
                Some(0) => 0,
                Some(n) => (n as usize).min(HISTORY_RAW_WINDOW_ROWS),
            };
            Ok(HistoryParse { filter, limit })
        }
        _ => Err(err_invalid_filter()),
    }
}

fn parse_stream_body(body: &Value, max_event_buffer: usize) -> Result<StreamParse, ClientError> {
    let buf = max_event_buffer.max(1);
    match body {
        Value::Null => {
            let lim = STREAM_DELIVERY_MAX_ROWS
                .min(buf)
                .min(STREAM_DELIVERY_MAX_ROWS);
            Ok(StreamParse {
                filter: NormalizedEventFilter::default(),
                limit: lim,
                stream_id: None,
                last_event_id: None,
            })
        }
        Value::Object(_) => {
            let req: ClientEventStreamRequest =
                serde_json::from_value(body.clone()).map_err(|_| err_invalid_filter())?;
            let filter = normalize_filter_fields(
                req.event_type,
                req.agent_id,
                req.run_id,
                req.trace_id,
                req.since,
            )?;
            // Cursor shape after filter (multi-fault order: filter already done).
            let stream_id = req.stream_id;
            let last_event_id = req.last_event_id;
            match (&stream_id, &last_event_id) {
                (None, Some(_)) | (Some(_), None) => return Err(err_cursor_incomplete()),
                _ => {}
            }
            let limit = match req.limit {
                None => STREAM_DELIVERY_MAX_ROWS
                    .min(buf)
                    .min(STREAM_DELIVERY_MAX_ROWS),
                Some(0) => 0,
                Some(n) => (n as usize).min(buf).min(STREAM_DELIVERY_MAX_ROWS),
            };
            Ok(StreamParse {
                filter,
                limit,
                stream_id,
                last_event_id,
            })
        }
        _ => Err(err_invalid_filter()),
    }
}

// ── Config validation ─────────────────────────────────────────────────────────────────────

fn validate_event_config(cfg: &ClientApiConfig) -> Result<(), ClientError> {
    if cfg.max_concurrent_event_reads < 1
        || cfg.max_event_buffer < 1
        || cfg.max_event_response_bytes < MIN_EVENT_RESPONSE_BYTES
        || cfg.event_stream_recv_idle_ms < MIN_EVENT_STREAM_RECV_IDLE_MS
    {
        return Err(err_config_invalid());
    }
    Ok(())
}

// ── Response sizing ───────────────────────────────────────────────────────────────────────

fn json_size(v: &Value) -> usize {
    serde_json::to_vec(v).map(|b| b.len()).unwrap_or(usize::MAX)
}

fn page_fits(page: &ClientEventPage, cap: usize) -> bool {
    let v = serde_json::to_value(page).unwrap_or(Value::Null);
    json_size(&v).saturating_add(EVENT_RESPONSE_ENVELOPE_RESERVE_BYTES) <= cap
}

// ── Client filter match (stream post-filter) ──────────────────────────────────────────────

fn row_matches_filter(row: &RawEventRow, filter: &NormalizedEventFilter) -> bool {
    if let Some(ref et) = filter.event_type {
        if &row.event_type != et {
            return false;
        }
    }
    if let Some(ref a) = filter.agent_id {
        if &row.agent_id != a {
            return false;
        }
    }
    if let Some(ref r) = filter.run_id {
        if row.run_id.as_deref() != Some(r.as_str()) {
            return false;
        }
    }
    if let Some(ref t) = filter.trace_id {
        if &row.trace_id != t {
            return false;
        }
    }
    if let Some(ref since) = filter.since {
        if let Ok(bound) = DateTime::parse_from_rfc3339(since) {
            if row.timestamp < bound.with_timezone(&Utc) {
                return false;
            }
        }
    }
    true
}

// ── Handlers ──────────────────────────────────────────────────────────────────────────────

struct EventSlots {
    provider: EventProviderSlot,
    detector: LeakDetectorSlot,
    codec: CursorCodecSlot,
    concurrency: Arc<EventConcurrency>,
    audit: Arc<dyn AuditSink>,
    /// Raw config values for fail-closed validation (D7).
    max_event_buffer: usize,
    max_response_bytes_raw: usize,
    idle_ms_raw: u64,
    max_reads_raw: usize,
}

impl EventSlots {
    fn check_config(&self) -> Result<(usize, u64), ClientError> {
        if self.max_reads_raw < 1
            || self.max_event_buffer < 1
            || self.max_response_bytes_raw < MIN_EVENT_RESPONSE_BYTES
            || self.idle_ms_raw < MIN_EVENT_STREAM_RECV_IDLE_MS
        {
            return Err(err_config_invalid());
        }
        let response_cap = self
            .max_response_bytes_raw
            .min(MAX_EVENT_RESPONSE_BYTES_HARD);
        let idle = self.idle_ms_raw.min(MAX_EVENT_STREAM_RECV_IDLE_MS);
        Ok((response_cap, idle))
    }
}

/// Register event routes, capturing slots + audit + concurrency.
pub(crate) fn register(
    api: &mut ClientApi,
    provider: EventProviderSlot,
    detector: LeakDetectorSlot,
    codec: CursorCodecSlot,
    concurrency: Arc<EventConcurrency>,
    audit: Arc<dyn AuditSink>,
    cfg: &ClientApiConfig,
) {
    let make = |provider: EventProviderSlot,
                detector: LeakDetectorSlot,
                codec: CursorCodecSlot,
                concurrency: Arc<EventConcurrency>,
                audit: Arc<dyn AuditSink>| EventSlots {
        provider,
        detector,
        codec,
        concurrency,
        audit,
        max_event_buffer: cfg.max_event_buffer,
        max_response_bytes_raw: cfg.max_event_response_bytes,
        idle_ms_raw: cfg.event_stream_recv_idle_ms,
        max_reads_raw: cfg.max_concurrent_event_reads,
    };

    let hist = make(
        Arc::clone(&provider),
        Arc::clone(&detector),
        Arc::clone(&codec),
        Arc::clone(&concurrency),
        Arc::clone(&audit),
    );
    api.register(
        Method::Get,
        routes::PATH_EVENTS,
        HandlerSpec::read(true, move |ctx| handle_history(ctx, &hist))
            .with_scopes(vec![Scope::ReadEvents]),
    );

    let stream = make(provider, detector, codec, concurrency, audit);
    api.register(
        Method::Get,
        routes::PATH_EVENTS_STREAM,
        HandlerSpec::read(true, move |ctx| handle_stream(ctx, &stream))
            .with_scopes(vec![Scope::ReadEvents]),
    );
}

fn require_slots(
    slots: &EventSlots,
) -> Result<
    (
        Arc<dyn ClientEventProvider>,
        Arc<dyn LeakDetector>,
        Arc<dyn ClientCursorCodec>,
    ),
    ClientError,
> {
    let provider = provider_or_unavailable_msg(&slots.provider, "event provider not wired")?;
    let detector = provider_or_unavailable_msg(&slots.detector, "event leak detector not wired")?;
    let codec = provider_or_unavailable_msg(&slots.codec, "event cursor codec not wired")?;
    // Silence unused helpers if renamed.
    let _ = (
        err_provider_not_wired,
        err_detector_not_wired,
        err_codec_not_wired,
    );
    Ok((provider, detector, codec))
}

fn handle_history(ctx: &HandlerCtx, slots: &EventSlots) -> Result<Value, ClientError> {
    let (response_cap, _idle) = slots.check_config()?;

    let parsed = parse_history_body(&ctx.body)?;
    let _guard = slots
        .concurrency
        .try_acquire_total()
        .ok_or_else(err_capacity)?;

    // Fail closed on absent slots even when limit==0 (no provider query, but wiring must exist).
    let (provider, detector, codec) = require_slots(slots)?;
    if parsed.limit == 0 {
        let _ = (provider, detector, codec);
        let page = ClientEventPage {
            events: vec![],
            cursor: None,
            dropped_count: 0,
            rejected_count: 0,
            redacted_count: 0,
            raw_limit_reached: false,
            response_limit_reached: false,
        };
        return Ok(serde_json::to_value(page).expect("page serializes"));
    }

    let raw_rows = provider
        .query_history(&parsed.filter, HISTORY_RAW_WINDOW_ROWS)
        .map_err(map_provider_err)?;
    let raw_limit_reached = raw_rows.len() >= HISTORY_RAW_WINDOW_ROWS;

    let hist_aad = history_stream_id_aad(&parsed.filter);
    let mut events = Vec::new();
    let mut rejected_count = 0u32;
    let mut redacted_count = 0u32;
    let mut response_limit_reached = false;

    for row in &raw_rows {
        // Full client filter post-check (exact type/agent/run/trace/since — not only provider SQL).
        if !row_matches_filter(row, &parsed.filter) {
            continue;
        }

        match projection::project_raw(
            &row.event_type,
            &row.timestamp,
            &row.agent_id,
            row.run_id.as_deref(),
            &row.trace_id,
            &row.payload,
            detector.as_ref(),
        ) {
            ProjectOutcome::SilentConsume => {
                // History: silent consume still omits; no reject.
            }
            ProjectOutcome::Reject => {
                rejected_count = rejected_count.saturating_add(1);
            }
            ProjectOutcome::Deliver {
                event_type,
                timestamp,
                agent_id,
                run_id,
                trace_id,
                priority,
                data,
                redacted_leaves,
            } => {
                if events.len() >= parsed.limit {
                    response_limit_reached = true;
                    break;
                }
                let event_id = codec.seal(
                    SealPurpose::EventId,
                    &hist_aad,
                    SEAL_TAG_RAW_ID,
                    row.raw_id.as_bytes(),
                )?;
                let ev = ClientEvent {
                    event_id,
                    event_type,
                    timestamp,
                    agent_id,
                    run_id,
                    trace_id,
                    priority,
                    data,
                };
                // History response-cap: oversized single event rejected; later overflow stops.
                let mut trial = events.clone();
                trial.push(ev.clone());
                let trial_page = ClientEventPage {
                    events: trial,
                    cursor: None,
                    dropped_count: 0,
                    rejected_count,
                    redacted_count: redacted_count.saturating_add(redacted_leaves),
                    raw_limit_reached,
                    response_limit_reached: false,
                };
                if !page_fits(&trial_page, response_cap) {
                    if events.is_empty() {
                        // Individually oversized — reject and continue.
                        rejected_count = rejected_count.saturating_add(1);
                        continue;
                    }
                    response_limit_reached = true;
                    break;
                }
                redacted_count = redacted_count.saturating_add(redacted_leaves);
                events.push(ev);
            }
        }
    }

    let page = ClientEventPage {
        events,
        cursor: None,
        dropped_count: 0,
        rejected_count,
        redacted_count,
        raw_limit_reached,
        response_limit_reached,
    };
    emit_success_audits(slots, &ctx.request_id, &page, false);
    Ok(serde_json::to_value(page).expect("page serializes"))
}

fn handle_stream(ctx: &HandlerCtx, slots: &EventSlots) -> Result<Value, ClientError> {
    let (response_cap, idle_ms) = slots.check_config()?;

    let parsed = parse_stream_body(&ctx.body, slots.max_event_buffer)?;
    let _guard = slots
        .concurrency
        .try_acquire_stream()
        .ok_or_else(err_capacity)?;

    let (provider, detector, codec) = require_slots(slots)?;
    let stream_id = stream_id_for_filter(&parsed.filter);

    // Resume vs fresh.
    enum OpenMode {
        /// Fresh high-water: resume(Some(id))
        HighWater(String),
        /// Fresh empty-join first seed: bare resume(None)
        EmptyJoinFirst,
        /// Authenticated resume(None) from watermark
        AuthEmptyJoin,
        /// resume(Some(raw))
        AfterRaw(String),
        /// limit:0 seed only
        SeedOnlyHighWater(String),
        SeedOnlyEmptyJoin,
    }

    let (open_mode, incoming_token): (OpenMode, Option<String>) =
        match (&parsed.stream_id, &parsed.last_event_id) {
            (None, None) => {
                // Fresh stream.
                match provider.latest_raw_event_id() {
                    Ok(Some(id)) => {
                        if parsed.limit == 0 {
                            (OpenMode::SeedOnlyHighWater(id), None)
                        } else {
                            (OpenMode::HighWater(id), None)
                        }
                    }
                    Ok(None) => {
                        if parsed.limit == 0 {
                            (OpenMode::SeedOnlyEmptyJoin, None)
                        } else {
                            (OpenMode::EmptyJoinFirst, None)
                        }
                    }
                    Err(e) => return Err(map_provider_err(e)),
                }
            }
            (Some(sid), Some(tok)) => {
                if sid != &stream_id {
                    return Err(err_stream_mismatch());
                }
                if parsed.limit == 0 {
                    // Open for validation, preserve token, no drain.
                    let opened = codec
                        .open(SealPurpose::Cursor, sid, tok)
                        .map_err(|_| err_cursor_not_found())?;
                    let _ = opened;
                    // Short-circuit preserve.
                    let page = ClientEventPage {
                        events: vec![],
                        cursor: Some(ClientEventCursor {
                            stream_id: sid.clone(),
                            last_event_id: Some(tok.clone()),
                        }),
                        dropped_count: 0,
                        rejected_count: 0,
                        redacted_count: 0,
                        raw_limit_reached: false,
                        response_limit_reached: false,
                    };
                    return Ok(serde_json::to_value(page).expect("page serializes"));
                }
                match codec.open(SealPurpose::Cursor, sid, tok)? {
                    OpenedSeal::EmptyJoin => (OpenMode::AuthEmptyJoin, Some(tok.clone())),
                    OpenedSeal::RawId(raw) => (OpenMode::AfterRaw(raw), Some(tok.clone())),
                    // Tee T2 delta cursors NEVER resume an event stream: explicit reject (the
                    // AAD domain split makes this unreachable via `AeadClientCursorCodec`, but
                    // the event path must fail closed for ANY codec impl).
                    OpenedSeal::DeltaCursor { .. } => return Err(err_cursor_not_found()),
                }
            }
            _ => return Err(err_cursor_incomplete()),
        };

    // Seed-only paths (limit 0 fresh).
    match &open_mode {
        OpenMode::SeedOnlyHighWater(id) => {
            let sealed = codec.seal(
                SealPurpose::Cursor,
                &stream_id,
                SEAL_TAG_RAW_ID,
                id.as_bytes(),
            )?;
            let page = ClientEventPage {
                events: vec![],
                cursor: Some(ClientEventCursor {
                    stream_id: stream_id.clone(),
                    last_event_id: Some(sealed),
                }),
                dropped_count: 0,
                rejected_count: 0,
                redacted_count: 0,
                raw_limit_reached: false,
                response_limit_reached: false,
            };
            return Ok(serde_json::to_value(page).expect("page serializes"));
        }
        OpenMode::SeedOnlyEmptyJoin => {
            let sealed = codec.seal(
                SealPurpose::Cursor,
                &stream_id,
                SEAL_TAG_EMPTY_JOIN,
                EMPTY_JOIN_WATERMARK_BODY.as_bytes(),
            )?;
            let page = ClientEventPage {
                events: vec![],
                cursor: Some(ClientEventCursor {
                    stream_id: stream_id.clone(),
                    last_event_id: Some(sealed),
                }),
                dropped_count: 0,
                rejected_count: 0,
                redacted_count: 0,
                raw_limit_reached: false,
                response_limit_reached: false,
            };
            return Ok(serde_json::to_value(page).expect("page serializes"));
        }
        _ => {}
    }

    let (after, join_tip): (Option<String>, Option<String>) = match &open_mode {
        OpenMode::HighWater(id) => (Some(id.clone()), Some(id.clone())),
        OpenMode::EmptyJoinFirst | OpenMode::AuthEmptyJoin => (None, None),
        OpenMode::AfterRaw(id) => (Some(id.clone()), None),
        OpenMode::SeedOnlyHighWater(_) | OpenMode::SeedOnlyEmptyJoin => unreachable!(),
    };

    let delivery_cap = parsed.limit;
    let scan_ceiling = (delivery_cap.saturating_mul(2))
        .min(STREAM_SCAN_MAX_ROWS)
        .max(if delivery_cap == 0 { 0 } else { 1 });

    let raw_rows = if delivery_cap == 0 {
        vec![]
    } else {
        provider
            .drain_stream(after.as_deref(), scan_ceiling, idle_ms)
            .map_err(map_provider_err)?
    };

    let mut events = Vec::new();
    let mut dropped_count = 0u32;
    let mut rejected_count = 0u32;
    let mut redacted_count = 0u32;
    let mut response_limit_reached = false;
    let mut deferred_normal = false;
    let mut last_consumed_raw: Option<String> = None;
    let mut raw_scanned = 0usize;

    for row in &raw_rows {
        raw_scanned += 1;
        // Always consume raw progress for filter misses / projection rejects / Low drops.
        let matches = row_matches_filter(row, &parsed.filter);
        if !matches {
            last_consumed_raw = Some(row.raw_id.clone());
            continue;
        }

        match projection::project_raw(
            &row.event_type,
            &row.timestamp,
            &row.agent_id,
            row.run_id.as_deref(),
            &row.trace_id,
            &row.payload,
            detector.as_ref(),
        ) {
            ProjectOutcome::SilentConsume => {
                last_consumed_raw = Some(row.raw_id.clone());
            }
            ProjectOutcome::Reject => {
                rejected_count = rejected_count.saturating_add(1);
                last_consumed_raw = Some(row.raw_id.clone());
            }
            ProjectOutcome::Deliver {
                event_type,
                timestamp,
                agent_id,
                run_id,
                trace_id,
                priority,
                data,
                redacted_leaves,
            } => {
                if events.len() >= delivery_cap {
                    // Page full by count.
                    match priority {
                        ClientEventPriority::Low => {
                            dropped_count = dropped_count.saturating_add(1);
                            last_consumed_raw = Some(row.raw_id.clone());
                            response_limit_reached = true;
                        }
                        ClientEventPriority::Normal => {
                            deferred_normal = true;
                            response_limit_reached = true;
                            break; // not consumed
                        }
                    }
                    continue;
                }

                let event_id = codec.seal(
                    SealPurpose::EventId,
                    &stream_id,
                    SEAL_TAG_RAW_ID,
                    row.raw_id.as_bytes(),
                )?;
                let ev = ClientEvent {
                    event_id,
                    event_type,
                    timestamp,
                    agent_id,
                    run_id,
                    trace_id,
                    priority,
                    data,
                };
                let mut trial_events = events.clone();
                trial_events.push(ev.clone());
                let trial_page = ClientEventPage {
                    events: trial_events,
                    cursor: Some(ClientEventCursor {
                        stream_id: stream_id.clone(),
                        last_event_id: Some(SEALED_TOKEN_BUDGET_PLACEHOLDER.to_string()),
                    }),
                    dropped_count,
                    rejected_count,
                    redacted_count: redacted_count.saturating_add(redacted_leaves),
                    raw_limit_reached: false,
                    response_limit_reached: false,
                };
                if !page_fits(&trial_page, response_cap) {
                    if events.is_empty() {
                        // Rule 1: reject+consume oversized even for empty page.
                        rejected_count = rejected_count.saturating_add(1);
                        last_consumed_raw = Some(row.raw_id.clone());
                        continue;
                    }
                    match priority {
                        ClientEventPriority::Low => {
                            dropped_count = dropped_count.saturating_add(1);
                            last_consumed_raw = Some(row.raw_id.clone());
                            response_limit_reached = true;
                        }
                        ClientEventPriority::Normal => {
                            deferred_normal = true;
                            response_limit_reached = true;
                            break;
                        }
                    }
                    continue;
                }
                redacted_count = redacted_count.saturating_add(redacted_leaves);
                events.push(ev);
                last_consumed_raw = Some(row.raw_id.clone());
            }
        }
    }

    let raw_limit_reached = raw_scanned >= scan_ceiling
        && scan_ceiling > 0
        && !deferred_normal
        && raw_rows.len() >= scan_ceiling;

    // Seal cursor last_event_id.
    let last_event_id = if let Some(raw) = last_consumed_raw {
        codec.seal(
            SealPurpose::Cursor,
            &stream_id,
            SEAL_TAG_RAW_ID,
            raw.as_bytes(),
        )?
    } else if let Some(tok) = incoming_token {
        // Preserve incoming (including quiet watermark resume).
        tok
    } else if let Some(tip) = join_tip {
        // High-water zero-consume: seal join id.
        codec.seal(
            SealPurpose::Cursor,
            &stream_id,
            SEAL_TAG_RAW_ID,
            tip.as_bytes(),
        )?
    } else {
        // Empty-join first seed zero-consume: seal watermark.
        codec.seal(
            SealPurpose::Cursor,
            &stream_id,
            SEAL_TAG_EMPTY_JOIN,
            EMPTY_JOIN_WATERMARK_BODY.as_bytes(),
        )?
    };

    let page = ClientEventPage {
        events,
        cursor: Some(ClientEventCursor {
            stream_id,
            last_event_id: Some(last_event_id),
        }),
        dropped_count,
        rejected_count,
        redacted_count,
        raw_limit_reached,
        response_limit_reached,
    };
    if !page_fits(&page, response_cap) {
        return Err(err_config_invalid());
    }
    emit_success_audits(slots, &ctx.request_id, &page, deferred_normal);
    Ok(serde_json::to_value(page).expect("page serializes"))
}

fn emit_success_audits(
    slots: &EventSlots,
    request_id: &str,
    page: &ClientEventPage,
    deferred_normal: bool,
) {
    if page.rejected_count > 0 {
        slots.audit.emit(
            AuditEvent::new("client_api.denied", request_id, "events", "Get")
                .with_reason(format!("rejected_count={}", page.rejected_count)),
        );
    }
    let pressure = page.dropped_count > 0 || deferred_normal || page.response_limit_reached;
    if pressure {
        slots.audit.emit(
            AuditEvent::new(
                "client_api.stream_backpressure",
                request_id,
                "events",
                "Get",
            )
            .with_reason(format!(
                "dropped={} response_limit={} deferred_normal={}",
                page.dropped_count, page.response_limit_reached, deferred_normal
            )),
        );
    }
}

// Keep validate_event_config referenced for external/config probes.
#[allow(dead_code)]
pub(crate) fn check_event_config(cfg: &ClientApiConfig) -> Result<(), ClientError> {
    validate_event_config(cfg)
}

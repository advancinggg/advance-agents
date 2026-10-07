//! MODULE-019 observability EventBus — production impl (Slice B).
//!
//! Implements [`EventBusEmit`](advance_shared_types::traits::EventBusEmit)
//! (CONTRACT-180) with a bounded-channel async actor architecture: every emit()
//! fans out via `mpsc::try_send` (microsecond-scale, non-blocking). Background
//! tasks own the actual writers (file / db / ws / stats); a single axum HTTP
//! server multiplexes `/events` (WebSocket) and `/query/*` (HTTP).
//!
//! # Two modes
//!
//! - **`EventBus::new_synchronous_for_tests`** (Slice A): synchronous fan-out.
//!   Required by Slice A's 33 regression tests; preserved verbatim. **MUST NOT**
//!   be called from inside any async runtime executor thread (Tokio, async-std,
//!   etc.); the blocking SQLite + filesystem I/O will starve worker threads.
//!
//! - **`EventBus::new`** (Slice B, this slice): production async constructor.
//!   Spawns 4 background writer tasks (file / db / ws / stats) + 1 axum server
//!   task. `emit()` becomes non-blocking (target NFR p99 < 10 µs per §1.5).
//!   Must be called inside a tokio runtime; `EventBus::shutdown(self).await`
//!   gracefully tears down all background tasks.
//!
//! # AC-18 output-path scrubbing (both halves)
//!
//! 1. **LeakDetector pattern-scrub (AC-18 Slice-B half).** When
//!    `cfg.leak_detector` is `Some`, the file_writer actor and ws_broadcaster
//!    apply `LeakDetector::scan(text, ScanContext::LogOutput)` to the serialized
//!    event JSON before persisting / broadcasting. See `leak.rs`.
//! 2. **`sensitive_params` parameter-name-scrub (Wave-20 security lane — the
//!    previously-deferred AC-18 half).** When `cfg.sensitive_params_source` is
//!    `Some`, the declared sensitive param NAMES in `Event.payload` are masked to
//!    `[REDACTED]` on the 3 OBSERVATION sinks (file_writer JSONL / db_indexer
//!    SQLite / ws_broadcaster WS) before persist/broadcast — the original event
//!    flows to the EXECUTION path (`trigger_bus_dispatch`, §1.7 observation-only,
//!    witnessed by `observation_only_execution_path_sees_unredacted`) and to the
//!    aggregation sinks (`cost_tracker` / `stats_aggregator`). NB the aggregation
//!    sinks persist only counters/token-aggregates — NOT the event payload
//!    (`stats_aggregator.rs` UPSERTs counts; `cost_tracker` folds token/cost) — so
//!    routing them the original vs the redacted event is immaterial to the leak
//!    surface (nothing payload-bearing reaches a queryable store via them). See
//!    `redact.rs`. CONTRACT-217 v0.2 now persists `sensitive-params`, and the CLI
//!    publishes each admitted declaration into this source after the durable
//!    scheduler commit. The two public history/approval surfaces are projected
//!    separately through CONTRACT-219 in MODULE-020.

mod clock;
pub mod cost_ledger;
mod db_indexer;
pub mod error;
mod event_io;
mod file_writer;
mod leak;
pub mod query_api;
pub mod read_api;
mod rebuild;
mod redact;
mod schema;
mod stats_aggregator;
mod sweeper;
pub mod taxonomy;
mod ws_broadcaster;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use advance_cost_tracker::CostTracker;
use advance_scheduler::contracts::TriggerBusDispatch;
use advance_shared_types::traits::{CostTrackerQuery, EventBusEmit, LeakDetector};
use rusqlite::OpenFlags;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::Mutex as TokioMutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

pub use crate::clock::{Clock, SystemClock};
pub use crate::error::EventBusError;
pub use crate::event_io::Event;
pub use crate::leak::{apply_scan_to_outbound, ScrubOutcome};
pub use crate::rebuild::{rebuild_sqlite_from_jsonl, RebuildReport};
pub use crate::redact::{
    project_sensitive_params, redact_sensitive_params, SensitiveParamProjection,
    SensitiveParamsSource, REDACTED,
};
// CONTRACT-185 — host-side event read surface (Slice m019-readapi).
pub use crate::read_api::{
    EventBusReadApi, EventFilter, LiveSubscription, ObservabilityReadApi, ReadApiError, ReadCursor,
    ReadEvent, ReadNext, ResumeStream,
};

/// CONTRACT-219 projection result for payload-bearing observation sinks.
/// Execution, trigger dispatch, statistics, and cost aggregation always retain
/// the original event; only file/SQLite/WebSocket observation output consumes
/// this result.
pub enum ObservationProjection {
    Unchanged,
    Redacted(Event),
    Blocked,
}

/// CONTRACT-219 boundary installed by the composition root.  A projector owns
/// the authenticated source/identity/schema bindings required to decide
/// whether an event may leave the execution boundary.
pub trait ObservationProjector: Send + Sync {
    fn project(&self, event: &Event) -> ObservationProjection;
}

use crate::db_indexer::EventDbIndexer;
use crate::event_io::event_to_jsonl_line;
use crate::file_writer::EventFileWriter;
use crate::sweeper::{run_sweeper_loop, RetentionSweeperShared};

/// Per-field size limits (Event Implementer Invariant 2 enforcement, round-1
/// adversarial Critical 2 fix). Mirrors `crates/shared-types/src/event.rs`
/// rustdoc lines 35-49 recommendations.
pub(crate) const MAX_EVENT_TYPE_LEN: usize = 128;
pub(crate) const MAX_ID_LEN: usize = 256; // aligned to MODULE-006 MAX_ID_BYTES (raised from 64; MODULE-019-AC-21 / RESOLVED 2026-06-02)
pub(crate) const MAX_PAYLOAD_LEN: usize = 64 * 1024;

const ACTOR_BUFFER: usize = 10_000;

/// Slice C — sweeper config bounds. `EventBus::new` clamps `cfg.jsonl_retention_days`
/// to `MAX_RETENTION_DAYS` (≈100 years) so `chrono::Duration::try_days` cannot
/// overflow inside `sweep_once`. `cfg.retention_sweep_interval` is clamped UP to
/// `MIN_SWEEP_INTERVAL_SECS` to prevent pathological tight-loops.
pub const MAX_RETENTION_DAYS: u32 = 36_500;
pub const MIN_SWEEP_INTERVAL_SECS: u64 = 60;

/// Configuration for `EventBus::new` (production) and
/// `EventBus::new_synchronous_for_tests` (Slice A regression).
#[derive(Clone)]
pub struct EventBusConfig {
    /// Directory where daily-rotated JSONL files are written
    /// (`<jsonl_dir>/YYYY-MM-DD.jsonl`).
    pub jsonl_dir: PathBuf,
    /// Path to the SQLite events database file.
    pub db_path: PathBuf,
    /// Slice B: HTTP+WebSocket server bind address. Default `127.0.0.1:8081` per
    /// MODULE-019 §2.10. Tests typically use `127.0.0.1:0` for OS-assigned port.
    pub websocket_addr: SocketAddr,
    /// Slice B: max concurrent WebSocket clients. Default 10 per §1.5 NFR.
    pub max_concurrent_ws_clients: usize,
    /// Slice B: optional per-agent LRU cap for stats_aggregator (default 1000).
    pub max_tracked_agents: usize,
    /// Slice B: optional LeakDetector for AC-18 output-path scrubbing. Production
    /// SHOULD pass Some(detector); tests / dev environments may pass None.
    pub leak_detector: Option<Arc<dyn LeakDetector>>,
    /// Slice B: optional clock injection for deterministic 24h rolling-window tests.
    pub clock: Arc<dyn Clock>,
    /// Slice C: JSONL retention window in days. Default 30. Values exceeding
    /// `MAX_RETENTION_DAYS` (36 500 ≈ 100 years) are clamped at `EventBus::new`
    /// construction time so `chrono::Duration::try_days` cannot overflow inside
    /// `sweep_once`. `0` short-circuits the sweep_once function — no files
    /// removed, no `sweeper_state` write.
    pub jsonl_retention_days: u32,
    /// Slice C: sweep tick interval. Default 24h. Values shorter than
    /// `MIN_SWEEP_INTERVAL_SECS` (60s) are clamped UP at construction time to
    /// prevent pathological tight-loops. Test code overrides to short durations
    /// for run-loop tests, OR uses long intervals + `bus.sweep_once_for_tests()`
    /// for deterministic single-tick assertions.
    pub retention_sweep_interval: Duration,
    /// Slice E (m019-slice-e, 2026-05-15): optional Trigger Bus dispatcher
    /// (CONTRACT-131, MODULE-014). When `Some`, `EmitPipeline::emit` checks
    /// whitelisted events (`taxonomy::TRIGGER_BUS_WHITELIST`) and calls
    /// `dispatch.dispatch(event.clone())` synchronously in the same call frame.
    /// Default `None`: test/dev configurations skip dispatch entirely; the
    /// fan-out + cost_tracker.observe paths run unchanged. AC-08, AC-17.
    pub trigger_bus_dispatch: Option<Arc<dyn TriggerBusDispatch>>,
    /// Slice E: mailbox SLO breach threshold (milliseconds). On `msg.received`
    /// with `payload.delivery_latency_ms > mailbox_delivery_slow_threshold_ms`,
    /// a `mailbox.delivery_slow` mirror event is synthesized and emitted.
    /// Default 1000 (matches MODULE-006's `mailbox.delivery_slow_threshold_ms`
    /// config key value-wise; M019 mirrors at the breach-detection layer
    /// while M006 owns source-side `delivery_latency_ms` instrumentation). AC-10.
    pub mailbox_delivery_slow_threshold_ms: u64,
    /// Wave-20 security lane (MODULE-012-AC-10 / MODULE-019-AC-18 deferred half):
    /// optional `sensitive_params` source. When `Some`, `EmitPipeline::emit`
    /// masks the values of declared sensitive param NAMES in the event payload
    /// to `[REDACTED]` on the 3 OBSERVATION sinks (file/db/ws) only — the
    /// original event still flows to the execution/aggregation paths. `None`
    /// (default) → no param-name redaction (byte-identical). Production installs
    /// the registry-backed source before EventBus startup and publishes v0.2
    /// declarations after durable admission; see `redact.rs`.
    pub sensitive_params_source: Option<Arc<dyn SensitiveParamsSource>>,
    /// CONTRACT-219 structured projection. When present, it is authoritative
    /// and supersedes the legacy name-only source above. `Blocked` suppresses
    /// every payload-bearing observation sink while execution remains intact.
    pub observation_projector: Option<Arc<dyn ObservationProjector>>,
}

impl std::fmt::Debug for EventBusConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventBusConfig")
            .field("jsonl_dir", &self.jsonl_dir)
            .field("db_path", &self.db_path)
            .field("websocket_addr", &self.websocket_addr)
            .field("max_concurrent_ws_clients", &self.max_concurrent_ws_clients)
            .field("max_tracked_agents", &self.max_tracked_agents)
            .field(
                "leak_detector",
                &self.leak_detector.as_ref().map(|_| "<dyn>"),
            )
            .field("clock", &"<dyn>")
            .field("jsonl_retention_days", &self.jsonl_retention_days)
            .field("retention_sweep_interval", &self.retention_sweep_interval)
            .field(
                "trigger_bus_dispatch",
                &self.trigger_bus_dispatch.as_ref().map(|_| "<dyn>"),
            )
            .field(
                "mailbox_delivery_slow_threshold_ms",
                &self.mailbox_delivery_slow_threshold_ms,
            )
            .field(
                "sensitive_params_source",
                &self.sensitive_params_source.as_ref().map(|_| "<dyn>"),
            )
            .field(
                "observation_projector",
                &self.observation_projector.as_ref().map(|_| "<dyn>"),
            )
            .finish()
    }
}

impl EventBusConfig {
    /// Convenience constructor with production defaults (port 8081, 10 WS clients,
    /// 1000 tracked agents, no LeakDetector, system clock, 30-day retention,
    /// 24h sweep interval, no Trigger Bus dispatch, 1 s mailbox SLO threshold).
    pub fn new(jsonl_dir: PathBuf, db_path: PathBuf) -> Self {
        Self {
            jsonl_dir,
            db_path,
            websocket_addr: "127.0.0.1:8081".parse().expect("hard-coded literal"),
            max_concurrent_ws_clients: 10,
            max_tracked_agents: 1000,
            leak_detector: None,
            clock: Arc::new(SystemClock),
            jsonl_retention_days: 30,
            retention_sweep_interval: Duration::from_secs(86_400),
            trigger_bus_dispatch: None,
            mailbox_delivery_slow_threshold_ms: 1000,
            sensitive_params_source: None,
            observation_projector: None,
        }
    }
}

enum EventBusMode {
    /// Slice A synchronous fan-out — preserved for `new_synchronous_for_tests`.
    Sync {
        file_writer: EventFileWriter,
        db_indexer: EventDbIndexer,
        /// Wave-20: the `sensitive_params` source also applies in Sync mode (the
        /// 2 sync sinks file_writer+db_indexer redact; there is no ws/stats/
        /// trigger split, so cost_tracker keeps the original). Test-parity with
        /// the Async `EmitPipeline` redaction; `None` (default) → byte-identical.
        sensitive_params_source: Option<Arc<dyn SensitiveParamsSource>>,
        observation_projector: Option<Arc<dyn ObservationProjector>>,
    },
    /// Slice B production async fan-out.
    Async(AsyncState),
}

/// Slice C — the shared fan-out helper used by both `EventBus::emit` (Async branch)
/// and `RetentionSweeperShared::emit_warning`. Channels carry `Arc<Event>` so emit
/// performs one Arc allocation + 4 cheap clones (8 bytes each).
///
/// Slice E (m019-slice-e, 2026-05-15): extended with two new behaviors that run
/// AFTER the existing 4-channel fan-out + cost_tracker.observe path:
/// 1. **Trigger Bus projection** (AC-08, AC-17): if `trigger_bus_dispatch` is
///    `Some` AND `event_type` is in `taxonomy::TRIGGER_BUS_WHITELIST`, the event
///    is dispatched to MODULE-014's `TriggerBusDispatch::dispatch` synchronously
///    in the same call frame (no `.await` between fan-out and dispatch).
/// 2. **Mailbox SLO breach detection** (AC-10): if `event.event_type == "msg.received"`
///    AND `event.payload.delivery_latency_ms > mailbox_delivery_slow_threshold_ms`,
///    a `mailbox.delivery_slow` mirror event is synthesized and re-emitted through
///    THIS same pipeline. Anti-recursion: the mirror's event_type is
///    `mailbox.delivery_slow`, NOT `msg.received`, so the outer guard at step 6
///    naturally skips for the mirror.
#[derive(Clone)]
pub(crate) struct EmitPipeline {
    file_writer_tx: mpsc::Sender<Arc<Event>>,
    db_indexer_tx: mpsc::Sender<Arc<Event>>,
    ws_broadcaster_tx: mpsc::Sender<Arc<Event>>,
    stats_aggregator_tx: mpsc::Sender<Arc<Event>>,
    cost_tracker: Arc<CostTracker>,
    dropped_count: Arc<AtomicU64>,
    /// Slice E — optional Trigger Bus dispatcher. `None` means dispatch branch
    /// is skipped entirely (no overhead on hot path); `Some` enables the
    /// whitelisted projection.
    trigger_bus_dispatch: Option<Arc<dyn TriggerBusDispatch>>,
    /// Slice E — mailbox SLO breach threshold in milliseconds. Default 1000.
    mailbox_delivery_slow_threshold_ms: u64,
    /// Wave-20 — optional `sensitive_params` source. `None` (default) → no
    /// param-name redaction (byte-identical hot path: one branch test). `Some`
    /// → the event routed to the 3 OBSERVATION sinks has declared sensitive
    /// param values masked; the original flows to exec/aggregation paths.
    sensitive_params_source: Option<Arc<dyn SensitiveParamsSource>>,
    observation_projector: Option<Arc<dyn ObservationProjector>>,
}

impl EmitPipeline {
    pub(crate) fn emit(&self, event: Event) {
        if validate_event_size(&event).is_err() {
            self.dropped_count.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let arc_event = Arc::new(event);
        // Wave-20 (MODULE-012-AC-10 / MODULE-019-AC-18 deferred half): compute the
        // event for the 3 OBSERVATION sinks with declared `sensitive_params`
        // values masked. The ORIGINAL `arc_event` flows to the execution /
        // aggregation paths (stats / cost / trigger_bus) so execution is
        // unaltered (§1.7 observation-only). `None` source (default) or no match
        // → `obs_event` IS `arc_event` (one Arc clone, no payload allocation).
        let obs_event: Option<Arc<Event>> = match &self.observation_projector {
            Some(projector) => match projector.project(&arc_event) {
                ObservationProjection::Unchanged => Some(Arc::clone(&arc_event)),
                ObservationProjection::Redacted(event) => Some(Arc::new(event)),
                ObservationProjection::Blocked => None,
            },
            None => match &self.sensitive_params_source {
                Some(src) => match src.names_for(&arc_event.agent_id) {
                    Some(names) => {
                        match project_sensitive_params(&arc_event.payload, names.as_ref()) {
                            SensitiveParamProjection::Redacted(redacted_payload) => {
                                let mut e = (*arc_event).clone();
                                e.payload = redacted_payload;
                                Some(Arc::new(e))
                            }
                            SensitiveParamProjection::Unchanged => Some(Arc::clone(&arc_event)),
                            SensitiveParamProjection::Blocked => None,
                        }
                    }
                    None => Some(Arc::clone(&arc_event)),
                },
                None => Some(Arc::clone(&arc_event)),
            },
        };
        let mut dropped = false;
        if let Some(obs_event) = obs_event {
            if self.file_writer_tx.try_send(obs_event.clone()).is_err() {
                dropped = true;
            }
            if self.db_indexer_tx.try_send(obs_event.clone()).is_err() {
                dropped = true;
            }
            if self.ws_broadcaster_tx.try_send(obs_event).is_err() {
                dropped = true;
            }
        } else {
            // A blocked structured document is intentionally absent from every
            // payload-bearing observation sink.  Count the suppression, while
            // execution/aggregate paths below still receive the original.
            dropped = true;
        }
        if self
            .stats_aggregator_tx
            .try_send(arc_event.clone())
            .is_err()
        {
            dropped = true;
        }
        self.cost_tracker.observe(&arc_event);
        if dropped {
            self.dropped_count.fetch_add(1, Ordering::Relaxed);
        }

        // Slice E — Trigger Bus projection (AC-08, AC-17).
        // Whitelisted events fan out to MODULE-014's dispatcher in the same call
        // frame. The dispatch trait method is synchronous (`fn dispatch(&self,
        // event: Event)`), so no `.await` separates this from the user's
        // `emit()` return. Mirror invariant: T15 verifies whitelisted →
        // dispatch fires; non-whitelisted → dispatch skipped.
        if let Some(ref dispatch) = self.trigger_bus_dispatch {
            if taxonomy::TRIGGER_BUS_WHITELIST.contains(&arc_event.event_type.as_str()) {
                // Event is cloned because TriggerBusDispatch::dispatch takes
                // Event by value (MODULE-014 §2.3:62 signature). Payload bounded
                // by validate_event_size (≤ 64 KiB); single clone per whitelisted
                // emit. Hot path (non-whitelisted, ~99% of emits) keeps single
                // Arc::new + zero clone.
                dispatch.dispatch((*arc_event).clone());
            }
        }

        // Slice E — Mailbox SLO breach detection (AC-10).
        // Outer event_type guard ensures the breach check only runs on
        // msg.received. The mirror's event_type is mailbox.delivery_slow (≠
        // msg.received), so the recursive re-emit through this pipeline does
        // not re-trigger the breach check (single-layer anti-recursion).
        // CostTracker.observe early-exits on non-llm.response, so the mirror
        // does not corrupt cost-aggregation state. mailbox.delivery_slow is
        // NOT in TRIGGER_BUS_WHITELIST (verified scheduler/src/trigger_bus.rs:56-69),
        // so the mirror also skips dispatch on the recursive call.
        if arc_event.event_type == taxonomy::msg::RECEIVED {
            if let Some(latency_ms) = arc_event
                .payload
                .get("delivery_latency_ms")
                .and_then(|v| v.as_u64())
            {
                if latency_ms > self.mailbox_delivery_slow_threshold_ms {
                    self.emit_breach_mirror(&arc_event, latency_ms);
                }
            }
        }
    }

    /// Slice E — synthesize and emit a `mailbox.delivery_slow` mirror event.
    ///
    /// Payload schema (PRD §15.3.3 verbatim): `{ agent_id, latency_ms }` plus
    /// `queue_depth` IFF the source event provides it. The struct-level
    /// `agent_id` is propagated from the breaching event so stats_aggregator's
    /// per-agent rollup attributes the breach correctly. Identity fields
    /// (`id`, `trace_id`, `span_id`) are ULID-generated; `parent_span_id`
    /// references the breaching event's `span_id` so trace assembly links the
    /// mirror to its cause.
    fn emit_breach_mirror(&self, source: &Event, latency_ms: u64) {
        use serde_json::{json, Map, Value};
        let mut payload = Map::new();
        payload.insert("agent_id".into(), json!(source.agent_id.clone()));
        payload.insert("latency_ms".into(), json!(latency_ms));
        // queue_depth: include ONLY when source event provides it. Omitting the
        // key (vs emitting null/0) signals "not yet wired" honestly — PRD §15.3.3
        // does NOT list queue_depth on msg.received's payload; until MODULE-006
        // future-slice instrumentation adds it, the field is absent from the mirror.
        if let Some(qd) = source.payload.get("queue_depth").and_then(|v| v.as_u64()) {
            payload.insert("queue_depth".into(), json!(qd));
        }
        let mirror = Event {
            id: ulid::Ulid::new().to_string(),
            timestamp: chrono::Utc::now(),
            agent_id: source.agent_id.clone(),
            task_id: source.task_id.clone(),
            run_id: source.run_id.clone(),
            execution_id: source.execution_id.clone(),
            trace_id: source.trace_id.clone(),
            span_id: ulid::Ulid::new().to_string(),
            parent_span_id: Some(source.span_id.clone()),
            event_type: taxonomy::mailbox::DELIVERY_SLOW.to_string(),
            payload: Value::Object(payload),
            duration_ms: Some(latency_ms),
        };
        // Recursive call: the mirror's event_type fails the outer breach-check
        // guard (≠ "msg.received"), so no second-level mirror.
        self.emit(mirror);
    }
}

struct AsyncState {
    pipeline: EmitPipeline,
    sweeper_shared: Arc<RetentionSweeperShared>,
    cancel_token: CancellationToken,
    /// Slice E (m019-slice-e, closes §3.6 item 14): independent cancellation
    /// token for the sweeper task. `EventBus::shutdown` cancels this FIRST,
    /// awaits sweeper's join, runs a `tokio::task::yield_now().await` flush
    /// barrier, then cancels the main `cancel_token`. Decoupling the two
    /// tokens ensures any late `emit_warning` issued by sweep_once during
    /// shutdown lands in the bounded mpsc channels BEFORE durable sinks
    /// drain-and-exit (previously the shared cancel raced and could close
    /// writer channels before the sweeper's warning crossed try_send).
    sweeper_cancel_token: CancellationToken,
    /// Slice E: named `sweeper_handle` (NOT indexed into `join_handles` Vec)
    /// so `EventBus::shutdown` joins it first without ordering fragility (in
    /// place; the slot is cleared once the handle resolved). The other 5 task
    /// handles (file_writer / db_indexer / ws / stats / server) remain in
    /// `join_handles` since they share the main cancel_token and are joined
    /// together after the flush barrier.
    sweeper_handle: TokioMutex<Option<JoinHandle<()>>>,
    join_handles: TokioMutex<Vec<JoinHandle<()>>>,
    /// `None` when the bus was built by [`EventBus::new_without_server`].
    server_addr: Option<SocketAddr>,
    /// Cancels every connected `/events` WebSocket client; fired only by
    /// [`EventBus::shutdown_shared`] (independent of `cancel_token`, so
    /// [`EventBus::shutdown`] leaves the clients as they are).
    ws_cancel: CancellationToken,
    /// Tracks the upgraded `/events` client tasks, which axum spawns detached.
    ws_tasks: TaskTracker,
    /// Slice m019-readapi (CONTRACT-185) — additive read-substrate handles for
    /// `EventBus::read_api`. Clones of the SAME pool / broadcaster the production
    /// `/query` + `/events` surfaces use, so the read API sees identical persisted
    /// + live events. The emit path (`EmitPipeline`, the writer actors, `shutdown`)
    /// is UNCHANGED by these additive fields.
    read_pool: Arc<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>>,
    read_broadcaster: broadcast::Sender<Arc<Event>>,
    read_clock: Arc<dyn Clock>,
    read_retention_days: u32,
}

impl AsyncState {
    /// Steps 1–5 of [`EventBus::shutdown`]. Each handle is awaited in place, under
    /// the lock of the slot that holds it, and leaves the slot only once it has
    /// resolved (see [`EventBus::shutdown_shared`]).
    async fn stop_tasks(&self) {
        // Step 1: cancel sweeper first.
        self.sweeper_cancel_token.cancel();
        // Step 2: await the sweeper's join; its slot stays locked, and keeps the
        // handle, until the sweeper has ended.
        {
            let mut sweeper = self.sweeper_handle.lock().await;
            if let Some(handle) = sweeper.as_mut() {
                let _ = handle.await;
                *sweeper = None;
            }
        }
        // Step 3: soft flush barrier — yield once to let durable-sink actors poll
        // their channels for any late sweeper warnings.
        tokio::task::yield_now().await;
        // Step 4: cancel remaining actors.
        self.cancel_token.cancel();
        // Step 5: join remaining actor handles in order, each removed once it has
        // resolved (the guard is held across the joins, so a concurrent second
        // call waits for them).
        let mut handles = self.join_handles.lock().await;
        while let Some(handle) = handles.first_mut() {
            let _ = handle.await;
            handles.remove(0);
        }
    }
}

/// MODULE-019 EventBus — implements CONTRACT-180 EventBusEmit.
pub struct EventBus {
    mode: EventBusMode,
    cost_tracker: Arc<CostTracker>,
    dropped_count: Arc<AtomicU64>,
}

impl EventBus {
    // ─── Slice A constructor — preserved for regression tests ────────────────

    /// Construct an `EventBus` with synchronous fan-out (Slice A).
    ///
    /// The constructor name is deliberate: production code must use
    /// [`EventBus::new`]. Slice A's regression tests pin this entry point.
    pub fn new_synchronous_for_tests(cfg: EventBusConfig) -> Result<Self, EventBusError> {
        let file_writer = EventFileWriter::new(cfg.jsonl_dir)?;
        let db_indexer = EventDbIndexer::new(&cfg.db_path)?;
        Ok(Self {
            mode: EventBusMode::Sync {
                file_writer,
                db_indexer,
                sensitive_params_source: cfg.sensitive_params_source,
                observation_projector: cfg.observation_projector,
            },
            cost_tracker: Arc::new(CostTracker::new()),
            dropped_count: Arc::new(AtomicU64::new(0)),
        })
    }

    // ─── Slice B production constructor ──────────────────────────────────────

    /// Construct a production `EventBus` (Slice B).
    ///
    /// Spawns 4 background writer tasks + 1 stats_aggregator tick task + 1
    /// axum HTTP+WS server task. MUST be called inside a tokio runtime context.
    /// `emit()` is non-blocking after construction. Lifecycle (small-witness
    /// 2026-06-12 doc fix — there is NO `Drop` impl): the 4 sink actors exit
    /// naturally when the pipeline's channels close on Drop, but the HTTP/WS
    /// server task stops ONLY via [`EventBus::shutdown`] (its
    /// `CancellationToken`); dropping the bus without `shutdown()` leaks the
    /// server task + bound listener until process exit.
    pub async fn new(cfg: EventBusConfig) -> Result<Self, EventBusError> {
        Self::new_inner(cfg, true).await
    }

    /// Construct a production `EventBus` that binds no listener: no HTTP/WS server
    /// task, so neither `/events` nor `/query` is served and
    /// [`EventBus::server_addr`] is `None`. `cfg.websocket_addr` is ignored. Every
    /// other part is as in [`EventBus::new`]: the 4 sink actors, the stats tick,
    /// the retention sweeper, [`EventBus::read_api`] (live subscribe included) and
    /// [`EventBus::cost_ledger`].
    pub async fn new_without_server(cfg: EventBusConfig) -> Result<Self, EventBusError> {
        Self::new_inner(cfg, false).await
    }

    async fn new_inner(cfg: EventBusConfig, serve: bool) -> Result<Self, EventBusError> {
        // 1. Build SQLite pool with schema migration.
        let pool = build_pool(&cfg.db_path)?;

        // Slice m019-readapi (CONTRACT-185, adversarial round-12/14): a DEDICATED
        // read pool for `read_api`, ISOLATED from the writer pool the db_indexer /
        // stats / query surfaces use — so many polling `ResumeStream`s cannot
        // exhaust the shared 4-connection pool and starve a `db_indexer` INSERT
        // (→ dropped_count → the event never lands in the store this API serves).
        // Built HERE, BEFORE any actor/server/sweeper task is spawned (round-14
        // fix), so a build failure returns `Err` via `?` without leaking already-
        // spawned tasks. `schema::apply` inside `build_pool` is idempotent — the
        // writer just migrated; `read_api` only issues SELECTs.
        let read_pool = build_pool(&cfg.db_path)?;

        // 2. Build file writer (synchronous core; actor wraps it).
        let file_writer = Arc::new(EventFileWriter::new(cfg.jsonl_dir.clone())?);

        // 3. Build db indexer (sync core; actor wraps it).
        let db_indexer = Arc::new(EventDbIndexer::from_pool(pool.clone()));

        let cost_tracker = Arc::new(CostTracker::new());
        let cancel_token = CancellationToken::new();
        let dropped_count = Arc::new(AtomicU64::new(0));

        // 4. Spawn file_writer actor.
        let (file_writer_tx, file_writer_handle) = spawn_file_writer_actor(
            file_writer,
            cfg.leak_detector.clone(),
            dropped_count.clone(),
            cancel_token.clone(),
        );

        // 5. Spawn db_indexer actor.
        let (db_indexer_tx, db_indexer_handle) =
            spawn_db_indexer_actor(db_indexer, dropped_count.clone(), cancel_token.clone());

        // 6. Spawn ws_broadcaster actor + collect WsState.
        let (ws_broadcaster_tx, ws_state, ws_handle) = ws_broadcaster::spawn(
            cancel_token.clone(),
            cfg.leak_detector.clone(),
            Some(cfg.max_concurrent_ws_clients),
        );
        // Slice m019-readapi (CONTRACT-185): retain a clone of the SAME broadcast
        // Sender that WebSocket `/events` clients subscribe to, so `read_api()`'s
        // live subscribe sees identical live events. Cloned BEFORE `ws_state` is
        // moved into `ws_route` below (order-sensitive — the only such step).
        let read_broadcaster = ws_state.broadcaster.clone();
        let ws_cancel = ws_state.cancel.clone();
        let ws_tasks = ws_state.tasks.clone();

        // 7. Spawn stats_aggregator actor.
        let (stats_aggregator_tx, stats_handle) = stats_aggregator::spawn(
            pool.clone(),
            cfg.clock.clone(),
            cancel_token.clone(),
            Some(cfg.max_tracked_agents),
        );
        // dropped_count for actor-side write failures already constructed above.

        // 8. Build the merged axum router and spawn the HTTP server (skipped by
        //    `new_without_server`: no listener, no server task).
        let (server_addr, server_handle) = if serve {
            let query_state = query_api::QueryState { pool: pool.clone() };
            let router = axum::Router::new()
                .merge(ws_broadcaster::ws_route(ws_state))
                .nest("/query", query_api::query_router(query_state));

            // Adversarial Round-1 W2 fix: hard-fail on non-loopback bind unless the
            // caller explicitly opts in (escape-hatch via env var
            // `ADVANCE_EVENTBUS_ALLOW_NONLOOPBACK_BIND=1`). Per spec §1.6 / §2.9 the
            // /query and /events surfaces are local-only by design — they leak event
            // payloads (potentially containing PII / non-LeakDetector-caught secrets)
            // and have no auth layer this slice. Reject misconfigured 0.0.0.0 / public
            // IP binds at construction time rather than rely on caller discipline.
            if !cfg.websocket_addr.ip().is_loopback()
                && std::env::var("ADVANCE_EVENTBUS_ALLOW_NONLOOPBACK_BIND")
                    .ok()
                    .as_deref()
                    != Some("1")
            {
                return Err(EventBusError::BindFailed {
                    addr: cfg.websocket_addr.to_string(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "non-loopback bind rejected — set ADVANCE_EVENTBUS_ALLOW_NONLOOPBACK_BIND=1 to override (spec §1.6 / §2.9 local-only)",
                    ),
                });
            }
            let listener = tokio::net::TcpListener::bind(cfg.websocket_addr)
                .await
                .map_err(|e| EventBusError::BindFailed {
                    addr: cfg.websocket_addr.to_string(),
                    source: e,
                })?;
            let server_addr = listener
                .local_addr()
                .map_err(|e| EventBusError::BindFailed {
                    addr: cfg.websocket_addr.to_string(),
                    source: e,
                })?;
            let server_cancel = cancel_token.clone();
            // Round-2 AUDIT diff Critical 1 fix: tower_governor::GovernorLayer's
            // PeerIpKeyExtractor reads ConnectInfo<SocketAddr> from request
            // extensions. `axum::serve(listener, router.into_make_service())`
            // does NOT inject ConnectInfo; without it, the rate-limit layer
            // returns 500 "Unable To Extract Key!" on every request. Use
            // `into_make_service_with_connect_info::<SocketAddr>()` so axum
            // populates the extension on each connection.
            let server_handle = tokio::spawn(async move {
                let _ = axum::serve(
                    listener,
                    router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
                )
                .with_graceful_shutdown(async move { server_cancel.cancelled().await })
                .await;
            });
            (Some(server_addr), Some(server_handle))
        } else {
            drop(ws_state);
            (None, None)
        };

        // Slice C — build the EmitPipeline that fans out events to the 4 actors.
        // Both `EventBus::emit` (Async branch) and the retention sweeper
        // (`RetentionSweeperShared::emit_warning`) flow through the same pipeline,
        // so all events pass through `validate_event_size` and increment a single
        // `dropped_count` on fan-out failure.
        //
        // Slice E — pipeline carries Trigger Bus dispatch (AC-08, AC-17) and
        // mailbox SLO threshold (AC-10). Both default to no-op when `cfg`
        // doesn't enable them.
        let pipeline = EmitPipeline {
            file_writer_tx,
            db_indexer_tx,
            ws_broadcaster_tx,
            stats_aggregator_tx,
            cost_tracker: Arc::clone(&cost_tracker),
            dropped_count: Arc::clone(&dropped_count),
            trigger_bus_dispatch: cfg.trigger_bus_dispatch.clone(),
            mailbox_delivery_slow_threshold_ms: cfg.mailbox_delivery_slow_threshold_ms,
            sensitive_params_source: cfg.sensitive_params_source.clone(),
            observation_projector: cfg.observation_projector.clone(),
        };

        // Slice C — sweeper config clamping (defense-in-depth; sweep_once also
        // re-clamps internally).
        let clamped_retention_days = cfg.jsonl_retention_days.min(MAX_RETENTION_DAYS);
        let clamped_sweep_interval = cfg
            .retention_sweep_interval
            .max(Duration::from_secs(MIN_SWEEP_INTERVAL_SECS));

        // Slice C — construct the shared sweeper state. EventBus retains a clone
        // for `sweep_once_for_tests`; the run-loop task is also given a clone.
        let sweeper_shared = Arc::new(RetentionSweeperShared {
            jsonl_dir: cfg.jsonl_dir.clone(),
            retention_days: clamped_retention_days,
            clock: Arc::clone(&cfg.clock),
            pool: Arc::clone(&pool),
            pipeline: pipeline.clone(),
        });
        // Slice E (closes §3.6 item 14): sweeper gets its own independent
        // `sweeper_cancel_token` instead of sharing `cancel_token` with the
        // durable sinks. `EventBus::shutdown` cancels sweeper first → awaits its
        // join → runs a yield_now flush barrier → THEN cancels the main token
        // for the remaining 5 actors. Race window where sweeper's late
        // emit_warning could try_send into already-closed durable-sink channels
        // is closed (modulo the documented soft barrier in shutdown rustdoc).
        let sweeper_cancel_token = CancellationToken::new();
        let sweeper_handle = tokio::spawn(run_sweeper_loop(
            Arc::clone(&sweeper_shared),
            clamped_sweep_interval,
            sweeper_cancel_token.clone(),
        ));

        // Slice E: the other 5 actor handles share the main `cancel_token` and
        // are joined together AFTER the sweeper has fully drained. They live in
        // `join_handles` Vec; the sweeper lives in its own named field.
        let mut join_handles = vec![
            file_writer_handle,
            db_indexer_handle,
            ws_handle,
            stats_handle,
        ];
        join_handles.extend(server_handle);

        Ok(Self {
            mode: EventBusMode::Async(AsyncState {
                pipeline,
                sweeper_shared,
                cancel_token,
                sweeper_cancel_token,
                sweeper_handle: TokioMutex::new(Some(sweeper_handle)),
                join_handles: TokioMutex::new(join_handles),
                server_addr,
                ws_cancel,
                ws_tasks,
                // Slice m019-readapi (CONTRACT-185) — additive read substrate:
                // a DEDICATED read pool (isolated from the writer pool), the SAME
                // broadcaster, the bus clock, and the clamped retention window.
                read_pool,
                read_broadcaster,
                read_clock: Arc::clone(&cfg.clock),
                read_retention_days: clamped_retention_days,
            }),
            cost_tracker,
            dropped_count,
        })
    }

    /// Number of events that failed to fan out to one or more sinks since
    /// construction. Unified counter: 1 increment per emit even if multiple
    /// sinks fail (matches Slice A `t_s_audit2_dropped_count_increments_on_writer_failure`).
    pub fn dropped_count(&self) -> u64 {
        self.dropped_count.load(Ordering::Relaxed)
    }

    /// Slice B accessor for downstream consumers (M008 / M015) to query cost
    /// aggregates without compile-time edge to advance-event-bus.
    pub fn cost_tracker_query(&self) -> Arc<dyn CostTrackerQuery> {
        self.cost_tracker.clone()
    }

    /// Slice B: the actual bound socket address (useful for tests that bind to port 0).
    pub fn server_addr(&self) -> Option<SocketAddr> {
        match &self.mode {
            EventBusMode::Async(state) => state.server_addr,
            EventBusMode::Sync { .. } => None,
        }
    }

    /// Slice m019-readapi (CONTRACT-185): the host-side event READ surface
    /// (`ObservabilityReadApi`) — `Some` for the production async bus, `None` for
    /// the synchronous test bus (which has no broadcaster / server). The returned
    /// handle holds CLONES of this bus's read substrate (SQLite pool + broadcast
    /// Sender + Clock + clamped retention window); it does NOT hold an
    /// `Arc<EventBus>`, so it never affects the bus's own refcount / shutdown.
    /// Lane cost-attribution (2026-09-16): the DURABLE per-agent / per-provider
    /// cost ledger over this bus's `events` table. Available in BOTH modes (the
    /// sync test bus indexes into SQLite too). The handle holds a CLONE of the
    /// pool, never an `Arc<EventBus>`.
    pub fn cost_ledger(&self) -> Arc<dyn advance_shared_types::traits::CostLedgerQuery> {
        let pool = match &self.mode {
            EventBusMode::Async(state) => Arc::clone(&state.read_pool),
            EventBusMode::Sync { db_indexer, .. } => db_indexer.pool(),
        };
        Arc::new(cost_ledger::SqliteCostLedger::new(pool))
    }

    pub fn read_api(&self) -> Option<Arc<dyn read_api::ObservabilityReadApi>> {
        match &self.mode {
            EventBusMode::Async(state) => Some(Arc::new(read_api::EventBusReadApi::new(
                Arc::clone(&state.read_pool),
                state.read_broadcaster.clone(),
                Arc::clone(&state.read_clock),
                state.read_retention_days,
            ))),
            EventBusMode::Sync { .. } => None,
        }
    }

    /// Gracefully shut down all background tasks (Slice B; Slice E sequenced).
    ///
    /// Slice E (closes §3.6 item 14 — sweeper-emitted warnings during shutdown):
    /// the cancellation sequence is now explicitly ordered to ensure that any
    /// `runtime.warning` events emitted by the retention sweeper during a
    /// late-arriving sweep iteration land in the durable-sink channels BEFORE
    /// those sinks drain and exit.
    ///
    /// Sequence:
    ///   1. `sweeper_cancel_token.cancel()` — signal sweeper to exit.
    ///   2. Await the sweeper's JoinHandle (in place in the named
    ///      `sweeper_handle` field, cleared once it resolved; no Vec-index
    ///      ordering fragility).
    ///   3. `tokio::task::yield_now().await` — soft flush barrier. Each
    ///      sweeper-emitted warning was `try_send`'d into the bounded mpsc
    ///      channels (capacity 10000) BEFORE the sweeper exited, so the
    ///      warning is already enqueued; this yield gives writer-actor tasks
    ///      at least one polling iteration to drain. (Hard drain-marker
    ///      barrier is a future-slice strengthening.)
    ///   4. `cancel_token.cancel()` — signal the 5 durable sinks +
    ///      server task to drain-and-exit.
    ///   5. Await each remaining JoinHandle. Their existing post-cancel
    ///      `try_recv` drain (lib.rs spawn closures + stats_aggregator cancel
    ///      arm) processes any buffered events including the sweeper's late
    ///      warning.
    ///
    /// The upgraded `/events` WebSocket clients are left as they are: each one
    /// ends when its peer goes away or the event broadcast closes. Use
    /// [`EventBus::shutdown_shared`] to close and join them too.
    pub async fn shutdown(self) {
        if let EventBusMode::Async(state) = &self.mode {
            state.stop_tasks().await;
        }
    }

    /// The [`EventBus::shutdown`] sequence on a shared bus (`&self`), so an owner
    /// holding an `Arc<EventBus>` can stop it without `Arc::try_unwrap`, followed
    /// by:
    ///
    ///   6. Cancel every connected `/events` WebSocket client (each gets a
    ///      `Close` frame, bounded), then wait until no client task is left.
    ///      axum's graceful server shutdown does not wait for upgraded
    ///      connections.
    ///
    /// Idempotent and cancel-safe. Each join happens in place, under the lock of
    /// the slot that holds the handle, and the handle leaves its slot only once it
    /// has resolved. A concurrent call therefore waits for the sweeper's join
    /// before it cancels the actors (the step order holds for it too) and returns
    /// once the first call's joins are done; a call dropped part-way (an owner's
    /// timeout) leaves every task it had not joined for the next call. After it,
    /// `emit` still accepts events but the sinks are gone, so they only count as
    /// dropped (`dropped_count`). No-op on the synchronous test bus.
    pub async fn shutdown_shared(&self) {
        if let EventBusMode::Async(state) = &self.mode {
            state.stop_tasks().await;
            // Step 6: close and join the upgraded `/events` client tasks.
            state.ws_cancel.cancel();
            state.ws_tasks.close();
            state.ws_tasks.wait().await;
        }
    }

    /// Slice C — Async-mode-only test trigger that fires exactly ONE
    /// retention-sweep iteration deterministically by calling
    /// `RetentionSweeperShared::sweep_once` directly. Bypasses the run-loop
    /// entirely so tests can assert `sweep_count == N` without timer-wheel
    /// races on the spawned task's first poll.
    ///
    /// Panics on Sync-mode busses (`new_synchronous_for_tests` does not
    /// construct a sweeper).
    pub async fn sweep_once_for_tests(&self) -> Result<(), std::io::Error> {
        match &self.mode {
            EventBusMode::Async(state) => state.sweeper_shared.sweep_once().await,
            EventBusMode::Sync { .. } => {
                unimplemented!("sweep_once_for_tests is Async-mode only")
            }
        }
    }
}

impl EventBusEmit for EventBus {
    fn emit(&self, event: Event) {
        match &self.mode {
            EventBusMode::Sync {
                file_writer,
                db_indexer,
                sensitive_params_source,
                observation_projector,
            } => {
                if validate_event_size(&event).is_err() {
                    self.dropped_count.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                // Wave-20: redact `sensitive_params` for the 2 sync OBSERVATION
                // sinks (file_writer + db_indexer); cost_tracker keeps the
                // original (observation-only, mirroring the Async EmitPipeline).
                // `None` source / no match → `obs` borrows `event` (no clone).
                let projection: Option<Option<Event>> = match observation_projector {
                    Some(projector) => Some(match projector.project(&event) {
                        ObservationProjection::Unchanged => Some(event.clone()),
                        ObservationProjection::Redacted(event) => Some(event),
                        ObservationProjection::Blocked => None,
                    }),
                    None => match sensitive_params_source {
                        Some(src) => src.names_for(&event.agent_id).map(|names| {
                            match project_sensitive_params(&event.payload, names.as_ref()) {
                                SensitiveParamProjection::Redacted(payload) => {
                                    let mut e = event.clone();
                                    e.payload = payload;
                                    Some(e)
                                }
                                SensitiveParamProjection::Unchanged => Some(event.clone()),
                                SensitiveParamProjection::Blocked => None,
                            }
                        }),
                        None => None,
                    },
                };
                let mut dropped = false;
                match projection {
                    Some(Some(obs)) => {
                        if file_writer.append(&obs).is_err() {
                            dropped = true;
                        }
                        if db_indexer.index(&obs).is_err() {
                            dropped = true;
                        }
                    }
                    Some(None) => dropped = true,
                    None => {
                        if file_writer.append(&event).is_err() {
                            dropped = true;
                        }
                        if db_indexer.index(&event).is_err() {
                            dropped = true;
                        }
                    }
                }
                self.cost_tracker.observe(&event);
                if dropped {
                    self.dropped_count.fetch_add(1, Ordering::Relaxed);
                }
            }
            // Slice C — Async branch delegates to EmitPipeline. The pipeline
            // performs its own validate_event_size + dropped_count accounting,
            // so user emits and sweeper warning emits go through the same
            // validation + fan-out + counter discipline.
            EventBusMode::Async(state) => state.pipeline.emit(event),
        }
    }
}

/// Slice C — Event-shape pre-emit gate. Extracted from `EventBus::validate_event_size`
/// so `EmitPipeline::emit` can call it without going through `&self`. No state
/// dependency in the body; this is mechanical.
pub fn validate_event_size(event: &Event) -> Result<(), EventBusError> {
    if event.event_type.len() > MAX_EVENT_TYPE_LEN {
        return Err(EventBusError::OversizeEventField {
            field: "event_type",
            actual: event.event_type.len(),
            limit: MAX_EVENT_TYPE_LEN,
        });
    }
    for (name, value) in [
        ("id", event.id.as_str()),
        ("agent_id", event.agent_id.as_str()),
        ("trace_id", event.trace_id.as_str()),
        ("span_id", event.span_id.as_str()),
    ] {
        if value.len() > MAX_ID_LEN {
            return Err(EventBusError::OversizeEventField {
                field: name,
                actual: value.len(),
                limit: MAX_ID_LEN,
            });
        }
    }
    for (name, opt) in [
        ("task_id", &event.task_id),
        ("run_id", &event.run_id),
        ("execution_id", &event.execution_id),
        ("parent_span_id", &event.parent_span_id),
    ] {
        if let Some(value) = opt {
            if value.len() > MAX_ID_LEN {
                return Err(EventBusError::OversizeEventField {
                    field: name,
                    actual: value.len(),
                    limit: MAX_ID_LEN,
                });
            }
        }
    }
    let mut sink = CountingSink::new(MAX_PAYLOAD_LEN);
    match serde_json::to_writer(&mut sink, &event.payload) {
        Ok(()) => Ok(()),
        Err(err) => {
            if sink.exceeded() {
                Err(EventBusError::OversizeEventField {
                    field: "payload",
                    actual: sink.observed_or_limit(),
                    limit: MAX_PAYLOAD_LEN,
                })
            } else {
                Err(EventBusError::Json(err))
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Background actor spawners (Slice B).
// ─────────────────────────────────────────────────────────────────────────

fn spawn_file_writer_actor(
    writer: Arc<EventFileWriter>,
    leak_detector: Option<Arc<dyn LeakDetector>>,
    dropped_count: Arc<AtomicU64>,
    cancel_token: CancellationToken,
) -> (mpsc::Sender<Arc<Event>>, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel::<Arc<Event>>(ACTOR_BUFFER);
    let handle = tokio::spawn(async move {
        // Per-event handler. Both the select! recv arm AND the post-cancel
        // try_recv drain run this body so events buffered at shutdown are
        // durably persisted (Slice C plan Round 5 Codex W1 + Round 4 Critical 2 fix).
        let process = |event: Arc<Event>| {
            let line = match event_to_jsonl_line(&event) {
                Ok(l) => l,
                Err(_) => {
                    dropped_count.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };
            let trimmed = line.trim_end_matches('\n');
            let outbound = match apply_scan_to_outbound(trimmed, leak_detector.as_deref()) {
                ScrubOutcome::Send(t) => t + "\n",
                ScrubOutcome::Drop => return,
            };
            if writer
                .append_line(&outbound, event.timestamp.date_naive())
                .is_err()
            {
                dropped_count.fetch_add(1, Ordering::Relaxed);
            }
        };

        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => break,
                maybe = rx.recv() => match maybe {
                    Some(event) => process(event),
                    None => break,
                },
            }
        }
        // Slice C drain — process events queued at cancel time before exit.
        // tokio::select! arms are pseudorandom; without this, buffered events
        // are silently lost on the cancel path.
        while let Ok(event) = rx.try_recv() {
            process(event);
        }
    });
    (tx, handle)
}

fn spawn_db_indexer_actor(
    indexer: Arc<EventDbIndexer>,
    dropped_count: Arc<AtomicU64>,
    cancel_token: CancellationToken,
) -> (mpsc::Sender<Arc<Event>>, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel::<Arc<Event>>(ACTOR_BUFFER);
    let handle = tokio::spawn(async move {
        let process = |event: Arc<Event>| {
            // Adversarial Round-1 W5 fix: actor-side write failures
            // increment dropped_count so silent-loss telemetry is accurate.
            if indexer.index(&event).is_err() {
                dropped_count.fetch_add(1, Ordering::Relaxed);
            }
        };
        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => break,
                maybe = rx.recv() => match maybe {
                    Some(event) => process(event),
                    None => break,
                },
            }
        }
        // Slice C drain — process events queued at cancel time before exit.
        while let Ok(event) = rx.try_recv() {
            process(event);
        }
    });
    (tx, handle)
}

// ─────────────────────────────────────────────────────────────────────────
// Helpers.
// ─────────────────────────────────────────────────────────────────────────

fn build_pool(
    db_path: &std::path::Path,
) -> Result<Arc<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>>, EventBusError> {
    use r2d2::Pool;
    use r2d2_sqlite::SqliteConnectionManager;

    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let manager = SqliteConnectionManager::file(db_path).with_flags(flags);
    let pool = Pool::builder()
        .max_size(4)
        .connection_timeout(std::time::Duration::from_secs(5))
        .connection_customizer(Box::new(db_indexer::PragmaCustomizer))
        .build(manager)?;
    let mut conn = pool.get()?;
    schema::apply(&mut conn)?;
    drop(conn);
    Ok(Arc::new(pool))
}

// ─────────────────────────────────────────────────────────────────────────
// CountingSink (Slice A — preserved verbatim).
// ─────────────────────────────────────────────────────────────────────────

struct CountingSink {
    count: usize,
    limit: usize,
    exceeded: bool,
}

impl CountingSink {
    fn new(limit: usize) -> Self {
        Self {
            count: 0,
            limit,
            exceeded: false,
        }
    }

    fn exceeded(&self) -> bool {
        self.exceeded
    }

    fn observed_or_limit(&self) -> usize {
        if self.exceeded {
            self.limit + 1
        } else {
            self.count
        }
    }
}

impl std::io::Write for CountingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let new_count = self.count.saturating_add(buf.len());
        if new_count > self.limit {
            self.exceeded = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "CountingSink: payload exceeds MAX_PAYLOAD_LEN",
            ));
        }
        self.count = new_count;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod shutdown_tests {
    //! MODULE-001-AC-30 witnesses of the shutdown sequence's joins. Each test runs on a
    //! current-thread runtime and puts a stand-in task in one of the bus's slots that ends
    //! only when the test releases it, so "still waiting" and "returned" are decided by the
    //! test, never by timing.

    use super::*;
    use std::sync::atomic::AtomicBool;
    use tokio::sync::Notify;

    async fn async_bus(dir: &std::path::Path) -> EventBus {
        let mut cfg = EventBusConfig::new(dir.join("events"), dir.join("events.db"));
        cfg.websocket_addr = "127.0.0.1:0".parse().unwrap();
        EventBus::new(cfg).await.expect("bus")
    }

    fn state(bus: &EventBus) -> &AsyncState {
        match &bus.mode {
            EventBusMode::Async(state) => state,
            EventBusMode::Sync { .. } => unreachable!("an async bus"),
        }
    }

    /// A stand-in task: once `token` fires it waits for `release`, then sets `done`.
    fn held(
        token: CancellationToken,
        release: Arc<Notify>,
        done: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            token.cancelled().await;
            release.notified().await;
            done.store(true, Ordering::SeqCst);
        })
    }

    /// Yields to the runtime for `ms` milliseconds (lets the spawned calls progress).
    async fn settle(ms: u64) {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }

    /// A call dropped while it joins the actors leaves every actor it had not joined in
    /// its slot, and the next call joins them before it returns.
    #[tokio::test(flavor = "current_thread")]
    async fn module_001_ac30_eventbus_shutdown_shared_is_cancel_safe() {
        let temp = tempfile::TempDir::new().unwrap();
        let bus = Arc::new(async_bus(temp.path()).await);
        let st = state(&bus);
        let (release, done) = (Arc::new(Notify::new()), Arc::new(AtomicBool::new(false)));
        let actor = held(st.cancel_token.clone(), release.clone(), done.clone());
        st.join_handles.lock().await.push(actor);

        let dropped = tokio::time::timeout(Duration::from_millis(200), bus.shutdown_shared()).await;
        assert!(dropped.is_err(), "the held actor keeps the call waiting");
        assert!(
            !st.join_handles.lock().await.is_empty(),
            "the dropped call leaves the actor it had not joined in its slot"
        );

        let retry = tokio::spawn({
            let bus = Arc::clone(&bus);
            async move { bus.shutdown_shared().await }
        });
        settle(100).await;
        assert!(
            !retry.is_finished(),
            "the next call joins the actor the dropped call left"
        );
        release.notify_one();
        retry.await.unwrap();
        assert!(done.load(Ordering::SeqCst));
        assert!(st.join_handles.lock().await.is_empty());
    }

    /// `shutdown_shared` joins the `/events` client tasks, it does not only cancel them: a
    /// tracked client task that is still closing keeps the call waiting until it has ended.
    /// A real upgraded client's task holds a tracker token, and gets its `Close` frame.
    #[tokio::test(flavor = "current_thread")]
    async fn module_001_ac30_eventbus_shutdown_shared_waits_for_every_ws_client_task() {
        use futures::StreamExt;
        use tokio_tungstenite::tungstenite::Message;

        let temp = tempfile::TempDir::new().unwrap();
        let bus = Arc::new(async_bus(temp.path()).await);
        let st = state(&bus);
        let addr = bus.server_addr().expect("server_addr");
        let (mut client, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/events"))
            .await
            .expect("ws connect");
        assert_eq!(
            st.ws_tasks.len(),
            1,
            "the upgraded client's task is tracked"
        );

        // A client task that is still closing after the cancel, until the test releases it.
        let (release, done) = (Arc::new(Notify::new()), Arc::new(AtomicBool::new(false)));
        let closing = {
            let (cancel, release, done) = (st.ws_cancel.clone(), release.clone(), done.clone());
            st.ws_tasks.spawn(async move {
                cancel.cancelled().await;
                release.notified().await;
                done.store(true, Ordering::SeqCst);
            })
        };

        let call = tokio::spawn({
            let bus = Arc::clone(&bus);
            async move { bus.shutdown_shared().await }
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !st.ws_cancel.is_cancelled() {
            assert!(
                std::time::Instant::now() < deadline,
                "shutdown_shared reached step 6"
            );
            settle(10).await;
        }
        settle(100).await;
        assert!(
            !call.is_finished(),
            "shutdown_shared waits for the client task that is still closing"
        );

        release.notify_one();
        call.await.unwrap();
        assert!(
            done.load(Ordering::SeqCst) && closing.is_finished(),
            "the client task had ended when shutdown_shared returned"
        );
        assert!(st.ws_tasks.is_empty(), "no client task is left");
        match tokio::time::timeout(Duration::from_secs(2), client.next())
            .await
            .expect("the real client saw the shutdown")
        {
            None | Some(Ok(Message::Close(_))) | Some(Err(_)) => {}
            Some(Ok(other)) => panic!("expected Close or end of stream, got {other:?}"),
        }
    }

    /// `shutdown(self)` keeps its sequence (steps 1–5): it neither cancels the upgraded
    /// `/events` client tasks nor waits for them. Only `shutdown_shared` does (step 6).
    #[tokio::test(flavor = "current_thread")]
    async fn eventbus_shutdown_by_value_leaves_the_ws_clients_alone() {
        let temp = tempfile::TempDir::new().unwrap();
        let bus = async_bus(temp.path()).await;
        let (cancel, tasks) = {
            let st = state(&bus);
            (st.ws_cancel.clone(), st.ws_tasks.clone())
        };
        // A tracked client task that never ends by itself.
        let client = tasks.token();
        tokio::time::timeout(Duration::from_secs(10), bus.shutdown())
            .await
            .expect("shutdown(self) does not wait for the client tasks");
        assert!(
            !cancel.is_cancelled(),
            "shutdown(self) does not cancel the client tasks"
        );
        assert_eq!(tasks.len(), 1, "the client task is still tracked");
        drop(client);
    }

    /// A second call that arrives while the first one waits for the sweeper waits too: no
    /// call cancels the actors before the sweeper has ended.
    #[tokio::test(flavor = "current_thread")]
    async fn module_001_ac30_eventbus_concurrent_shutdown_keeps_the_sweeper_first() {
        let temp = tempfile::TempDir::new().unwrap();
        let bus = Arc::new(async_bus(temp.path()).await);
        let st = state(&bus);
        // The stand-in takes the sweeper's slot; the real sweeper is joined with the actors.
        let (release, done) = (Arc::new(Notify::new()), Arc::new(AtomicBool::new(false)));
        let sweeper = held(
            st.sweeper_cancel_token.clone(),
            release.clone(),
            done.clone(),
        );
        let real = st.sweeper_handle.lock().await.replace(sweeper);
        st.join_handles.lock().await.extend(real);

        let spawn_call = || {
            let bus = Arc::clone(&bus);
            tokio::spawn(async move { bus.shutdown_shared().await })
        };
        let first = spawn_call();
        settle(50).await;
        let second = spawn_call();
        settle(100).await;
        assert!(
            !st.cancel_token.is_cancelled(),
            "no call cancels the actors while the sweeper is still running"
        );
        assert!(!first.is_finished() && !second.is_finished());

        release.notify_one();
        first.await.unwrap();
        second.await.unwrap();
        assert!(done.load(Ordering::SeqCst));
        assert!(st.cancel_token.is_cancelled());
        assert!(st.sweeper_handle.lock().await.is_none());
        assert!(st.join_handles.lock().await.is_empty());
    }
}

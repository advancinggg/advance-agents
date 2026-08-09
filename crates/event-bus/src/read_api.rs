//! CONTRACT-185 `ObservabilityReadApi` — the host-side event READ surface
//! (MODULE-019-AC-23, Slice m019-readapi).
//!
//! A host-side consumer (NOT a WASM guest) can:
//!   (a) `subscribe`  — filtered, real-time live tail over the existing
//!       `ws_broadcaster` broadcast channel (best-effort, emit-order,
//!       `ReadNext::Lagged` surfaced; NO durable cursor);
//!   (b) `resume`     — durable, gap-free replay + live splice from a durable
//!       cursor, implemented as a single `rowid`-ordered tail over the unbounded
//!       SQLite `events` table (NOT a broadcast-splice — the DB is the sole
//!       ordered source, so the persist/broadcast actor skew cannot open a gap
//!       and there is no ring to overflow);
//!   (c) `query`      — historical query over the persisted store, honoring the
//!       MODULE-019 retention window.
//!
//! Hard boundaries (this file NEVER violates them):
//!   * It composes the EXISTING read substrate only — a clone of the
//!     `ws_broadcaster` `broadcast::Sender` and a clone of the `query_api`
//!     SQLite pool. It NEVER touches `EmitPipeline::emit`, the writer actors, or
//!     `shutdown` (CONTRACT-180 emit path byte-unchanged).
//!   * It returns the RAW host-side read. Client-safety / redaction is
//!     MODULE-020's projection (CONTRACT-185 consumer), NOT this contract.
//!
//! # Consumer trust-boundary responsibilities (round-12 adversarial)
//!
//! This is a HOST-SIDE, single-trust-domain surface. A consumer (MODULE-020) MUST
//! honour the following before crossing any client / untrusted boundary:
//!   1. **Redact before exposing.** `subscribe`/`resume`/`query` return the raw
//!      event. Payloads are `sensitive_params`-redacted at persist, but the
//!      `LeakDetector` secret-pattern scrub that the WebSocket `/events` route
//!      applies at SEND time is NOT applied here — `subscribe` reads the broadcast
//!      upstream of it. The consumer owns the client-safe projection (incl. leak
//!      scanning). `subscribe` is NOT equivalent to `/events` on the leak-scan axis.
//!   2. **A `ReadCursor` is not an authorization scope.** It is a forgeable,
//!      unauthenticated token (an event id); an unknown id yields `CursorNotFound`,
//!      but a consumer must never let a client resume from an arbitrary id it can
//!      enumerate as if it were access control.
//!   3. **Bound `recv()`.** `LiveSubscription::recv()` reports `Closed` only when
//!      ALL broadcast senders drop (a held read-api handle keeps one alive), and
//!      `ResumeStream::recv()` is a perpetual DB-tail that polls every 25 ms and
//!      never returns end-of-stream — neither observes `EventBus::shutdown`. The
//!      consumer must wrap both in a timeout (as the witnesses do) or drop the
//!      handle/stream at shutdown.
//!
//! Gap-freedom is over **committed SQLite rows**, not over emitted events: an
//! event dropped at emit under channel backpressure (`dropped_count`) is never
//! persisted and is a legitimate, pre-existing absence.
//!
//! **Filter application** (round-6 audit fix): `resume` fetches strictly
//! `rowid`-contiguous batches (no SQL filters) and applies ALL filters in Rust
//! while advancing its cursor over EVERY scanned row — guaranteeing forward
//! progress even for a sparse/never-matching filter (no repeated tail rescans).
//! `query` applies all filters (including `since`) in SQL so its `LIMIT` operates
//! on the filtered set (never on a rowid window that a post-`LIMIT` `since` drop
//! could silently under-count).

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use advance_shared_types::event::Event;
use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, Utc};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::OptionalExtension;
use tokio::sync::broadcast;

use crate::clock::Clock;
use crate::query_api::MAX_LIMIT;

/// Poll cadence for the `resume` DB-tail once it has caught up to the current
/// end of the `events` table. Documented latency/gap-freedom trade-off (§3.8):
/// resumed "live" events arrive at persist + one poll of latency, in exchange
/// for a provable no-gap guarantee. Tests bound `recv()` with `timeout`.
const RESUME_TAIL_POLL: Duration = Duration::from_millis(25);

/// Rows fetched per `resume` DB-tail batch. Batches are contiguous and
/// non-overlapping (`rowid > ?last ORDER BY rowid ASC LIMIT`); the cursor
/// advances over every scanned row so a full batch is drained without sleeping.
const RESUME_BATCH: usize = 512;

/// A durable resume position. Wraps a COMMITTED event `id` (the SQLite `events`
/// PRIMARY KEY — unique and rebuild-stable). A consumer OBTAINS one from a
/// delivered [`ReadEvent`] (`resume`/`query`) and persists its `id`; on reconnect
/// it reconstructs `ReadCursor(id)` to resume. The field is public precisely so
/// that durable reconstruction works across a restart. A cursor whose id is not a
/// committed event yields [`ReadApiError::CursorNotFound`] (defensive — since the
/// `events` table is never pruned, a genuinely-issued cursor is always present).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadCursor(pub String);

/// One delivered event plus its durable cursor (its own committed `id`).
#[derive(Debug, Clone)]
pub struct ReadEvent {
    pub cursor: ReadCursor,
    pub event: Arc<Event>,
}

/// The item yielded by the live [`LiveSubscription`] feed. Carries the raw event
/// with NO durable cursor (a broadcast event may not be persisted yet), plus the
/// two out-of-band signals a best-effort broadcast can raise.
#[derive(Debug, Clone)]
pub enum ReadNext {
    Event(Arc<Event>),
    /// The broadcast ring overran this receiver; `skipped` events were dropped.
    /// Switch to `resume` for a gap-free catch-up.
    Lagged {
        skipped: u64,
    },
    /// The bus (and this handle's `Sender` clone) dropped — stream ended.
    Closed,
}

/// Read filter. All-`None` ⇒ match everything.
///
/// `event_type_prefix` is a dotted-taxonomy prefix (e.g. `"llm."` matches every
/// `llm.*`). `agent_id` / `run_id` / `trace_id` are exact matches. `since` is an
/// RFC-3339 lower bound applied on BOTH DB read paths (`resume` and `query`) and
/// IGNORED on the live `subscribe` feed. The two DB paths honor `since` at
/// different granularity: `query` binds a UTC-normalized, whole-second-truncated
/// form into SQL (so `LIMIT` operates on the filtered set — a SAFE lexicographic
/// lower bound that never drops a valid row, but floors `since` to the second and
/// so may include up to the boundary second), while `resume` compares it as a
/// precise parsed instant. A non-RFC-3339 `since` ⇒ [`ReadApiError::BadFilter`].
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    pub event_type_prefix: Option<String>,
    pub agent_id: Option<String>,
    pub run_id: Option<String>,
    pub trace_id: Option<String>,
    pub since: Option<String>,
}

/// Errors surfaced by the DB read paths.
#[derive(Debug, thiserror::Error)]
pub enum ReadApiError {
    #[error("read-api SQLite error: {0}")]
    Db(String),
    /// The cursor's event id is not present in the store. Defensive-only — a
    /// cursor obtained from `resume`/`query` is always present (the `events`
    /// table is never pruned), so this signals a genuinely invalid/garbage cursor.
    #[error("read-api cursor not found: {0}")]
    CursorNotFound(String),
    #[error("read-api bad filter: {0}")]
    BadFilter(String),
}

/// The parsed form of an [`EventFilter`] carrying both the SQL-bindable strings
/// (for `query`) and the Rust-check forms (for the `resume` per-row filter).
/// The lexicographic successor of `prefix` (increment the last non-`0xFF` byte,
/// dropping trailing `0xFF`), so `event_type >= prefix AND event_type < upper` is
/// an index-usable range for `idx_events_type` covering exactly the `prefix`-set.
/// `None` only for an empty prefix or an all-`0xFF` / non-UTF-8-boundary prefix
/// (never a real dotted-taxonomy prefix), in which case the SQL keeps the
/// `substr(...)` residual as the sole correctness filter.
fn prefix_upper(prefix: &str) -> Option<String> {
    if prefix.is_empty() {
        return None;
    }
    let mut bytes = prefix.as_bytes().to_vec();
    while let Some(&last) = bytes.last() {
        if last < 0xFF {
            *bytes.last_mut().unwrap() = last + 1;
            return String::from_utf8(bytes).ok();
        }
        bytes.pop(); // carry past a 0xFF byte
    }
    None
}

#[derive(Clone)]
struct RowFilter {
    event_type_prefix: Option<String>,
    /// Lexicographic upper bound for the prefix range (index optimization).
    event_type_upper: Option<String>,
    agent_id: Option<String>,
    run_id: Option<String>,
    trace_id: Option<String>,
    /// SQL bind for `query` (`timestamp >= ?`) — the parsed instant NORMALIZED to
    /// UTC and truncated to the whole second (`"YYYY-MM-DDTHH:MM:SS"`, no fraction,
    /// no `Z`). This is a SAFE lexicographic lower bound against the stored
    /// variable-width `%FT%T%.fZ` format (any stored timestamp at-or-after this
    /// second — with or without a fraction — sorts `>=` this prefix), and it
    /// normalizes timezone offsets. It floors `since` to the second, so `query`
    /// may include up to the boundary second (safe: it never DROPS a valid row —
    /// the round-7 fix for the `'.' < 'Z'` / offset lexicographic hazard). `resume`
    /// uses the precise instant instead.
    since_sql: Option<String>,
    /// Rust check for `resume` (precise instant).
    since_instant: Option<DateTime<Utc>>,
    /// Retention cutoff — `"YYYY-MM-DD"` date-prefix string (SQL bind for `query`)
    /// + the same date as a `NaiveDate` (Rust check for `resume`). `None` ⇒ no
    /// retention bound (`retention_days == 0`).
    retention_cutoff_str: Option<String>,
    retention_cutoff_date: Option<NaiveDate>,
}

impl RowFilter {
    fn from_filter(
        filter: &EventFilter,
        retention_cutoff: Option<NaiveDate>,
    ) -> Result<Self, ReadApiError> {
        let (since_sql, since_instant) = match &filter.since {
            None => (None, None),
            Some(s) => {
                let dt = DateTime::parse_from_rfc3339(s)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| ReadApiError::BadFilter(format!("`since` not RFC-3339: {e}")))?;
                // UTC + whole-second truncation ⇒ a lexicographically-safe lower
                // bound against the stored `%FT%T%.fZ` format (never drops a valid
                // row; offset-normalized). See `since_sql` doc.
                (Some(dt.format("%Y-%m-%dT%H:%M:%S").to_string()), Some(dt))
            }
        };
        let event_type_upper = filter.event_type_prefix.as_deref().and_then(prefix_upper);
        Ok(Self {
            event_type_prefix: filter.event_type_prefix.clone(),
            event_type_upper,
            agent_id: filter.agent_id.clone(),
            run_id: filter.run_id.clone(),
            trace_id: filter.trace_id.clone(),
            since_sql,
            since_instant,
            retention_cutoff_str: retention_cutoff.map(|d| d.to_string()),
            retention_cutoff_date: retention_cutoff,
        })
    }

    /// Full Rust-side match for the `resume` path (which fetches unfiltered
    /// rowid-contiguous batches). Checks every filter dimension incl. retention +
    /// the precise `since` instant.
    fn matches(&self, ev: &Event) -> bool {
        if let Some(p) = &self.event_type_prefix {
            if !ev.event_type.starts_with(p) {
                return false;
            }
        }
        if let Some(a) = &self.agent_id {
            if &ev.agent_id != a {
                return false;
            }
        }
        if let Some(r) = &self.run_id {
            if ev.run_id.as_deref() != Some(r.as_str()) {
                return false;
            }
        }
        if let Some(t) = &self.trace_id {
            if &ev.trace_id != t {
                return false;
            }
        }
        if let Some(cutoff) = self.retention_cutoff_date {
            if ev.timestamp.date_naive() < cutoff {
                return false;
            }
        }
        if let Some(since) = self.since_instant {
            if ev.timestamp < since {
                return false;
            }
        }
        true
    }
}

/// Parse a stored `events.timestamp` TEXT (`%FT%T%.fZ`) back into a
/// `DateTime<Utc>`. Our own writer always emits valid RFC-3339; a malformed value
/// falls back to the UNIX epoch (which a `since` filter then excludes).
fn parse_ts(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| DateTime::<Utc>::from_timestamp(0, 0).expect("epoch is valid"))
}

/// SELECT column list — `rowid` first (internal ordering), then the 12 event
/// columns in schema order.
const SELECT_COLS: &str = "rowid, id, timestamp, agent_id, task_id, run_id, execution_id, \
     trace_id, span_id, parent_span_id, event_type, payload, duration_ms";

/// Map a `(rowid, <12 cols>)` row → `(rowid, Event)`. Mirrors
/// `query_api::event_row_from_sql` but reconstructs the strongly-typed `Event`
/// (nullable `agent_id`/`trace_id`/`span_id` TEXT → non-optional `String` via
/// `unwrap_or_default`; payload TEXT JSON → `serde_json::Value`; duration INTEGER
/// → `Option<u64>`).
fn row_to_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<(i64, Event)> {
    let rowid: i64 = row.get(0)?;
    let ts_str: String = row.get(2)?;
    let payload_str: Option<String> = row.get(11)?;
    let duration_ms: Option<i64> = row.get(12)?;
    let event = Event {
        id: row.get(1)?,
        timestamp: parse_ts(&ts_str),
        agent_id: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
        task_id: row.get(4)?,
        run_id: row.get(5)?,
        execution_id: row.get(6)?,
        trace_id: row.get::<_, Option<String>>(7)?.unwrap_or_default(),
        span_id: row.get::<_, Option<String>>(8)?.unwrap_or_default(),
        parent_span_id: row.get(9)?,
        event_type: row.get(10)?,
        payload: payload_str
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(serde_json::Value::Null),
        // A negative stored `duration_ms` (never written by this crate, but the
        // `events` table is shared/rebuildable) is dropped rather than wrapped to a
        // huge u64 via `as` (round-12 fix).
        duration_ms: duration_ms.filter(|d| *d >= 0).map(|d| d as u64),
    };
    Ok((rowid, event))
}

/// CONTRACT-185 — the host-side event read surface.
///
/// Object-safe (`async_trait` boxes the DB-touching futures); `dyn`-consumed by
/// MODULE-020. Obtained via [`crate::EventBus::read_api`] (`Some` in async mode,
/// `None` for the synchronous test bus).
#[async_trait]
pub trait ObservabilityReadApi: Send + Sync {
    /// (a) Real-time filtered live subscribe over the broadcast channel.
    /// Best-effort, emit-order, `Lagged` surfaced. No durable cursor.
    fn subscribe(&self, filter: EventFilter) -> LiveSubscription;

    /// (b) Durable, gap-free resume from a durable cursor (or `None` = start of
    /// the retention window). Replay backlog then live splice, over the
    /// `rowid`-ordered `events` table. Unknown cursor ⇒ `CursorNotFound`.
    async fn resume(
        &self,
        cursor: Option<ReadCursor>,
        filter: EventFilter,
    ) -> Result<ResumeStream, ReadApiError>;

    /// (c) Historical query honoring retention, most-recent-first, capped at
    /// `MAX_LIMIT`.
    async fn query(
        &self,
        filter: &EventFilter,
        limit: usize,
    ) -> Result<Vec<ReadEvent>, ReadApiError>;
}

/// Production impl over the existing `EventBus` read substrate. Holds CLONES of
/// the broadcaster + SQLite pool + clock (+ the clamped retention window) — NOT
/// an `Arc<EventBus>` — so wiring's `Arc::try_unwrap(bus_concrete)` invariant is
/// preserved.
pub struct EventBusReadApi {
    pool: Arc<Pool<SqliteConnectionManager>>,
    broadcaster: broadcast::Sender<Arc<Event>>,
    clock: Arc<dyn Clock>,
    /// Already clamped to `MAX_RETENTION_DAYS` by `EventBus::new`.
    retention_days: u32,
}

impl EventBusReadApi {
    pub(crate) fn new(
        pool: Arc<Pool<SqliteConnectionManager>>,
        broadcaster: broadcast::Sender<Arc<Event>>,
        clock: Arc<dyn Clock>,
        retention_days: u32,
    ) -> Self {
        Self {
            pool,
            broadcaster,
            clock,
            retention_days,
        }
    }

    /// The retention lower bound as a `NaiveDate`, or `None` when
    /// `retention_days == 0` (unbounded, matching the sweeper). The clamped
    /// `retention_days` makes the date-math `None` arms unreachable; a `None`
    /// result fails OPEN (no bound), which can only ever SHOW more retained data.
    fn retention_cutoff(&self) -> Option<NaiveDate> {
        if self.retention_days == 0 {
            return None;
        }
        let today = self.clock.now().date_naive();
        let dur = chrono::Duration::try_days(self.retention_days as i64)?;
        today.checked_sub_signed(dur)
    }
}

#[async_trait]
impl ObservabilityReadApi for EventBusReadApi {
    fn subscribe(&self, filter: EventFilter) -> LiveSubscription {
        LiveSubscription {
            rx: self.broadcaster.subscribe(),
            filter,
        }
    }

    async fn resume(
        &self,
        cursor: Option<ReadCursor>,
        filter: EventFilter,
    ) -> Result<ResumeStream, ReadApiError> {
        let row_filter = RowFilter::from_filter(&filter, self.retention_cutoff())?;

        // Map the durable cursor (an event id) → its rowid; tail rowid > that.
        // Unknown id ⇒ CursorNotFound (defensive).
        let last_rowid = match cursor {
            // `None` ⇒ start just before the FIRST in-retention row rather than
            // cold-scanning the never-pruned table from rowid 0 (round-12 fix —
            // bounds the replay to the retention window). `retention_days == 0`
            // (cutoff None) ⇒ genuinely unbounded, start at 0.
            None => match &row_filter.retention_cutoff_str {
                None => 0,
                Some(cutoff) => {
                    let pool = self.pool.clone();
                    let cutoff = cutoff.clone();
                    tokio::task::spawn_blocking(move || -> Result<i64, ReadApiError> {
                        let conn = pool.get().map_err(|e| ReadApiError::Db(e.to_string()))?;
                        // Compute the start rowid in ONE statement so MIN and MAX
                        // read the SAME snapshot (round-14 fix — two separate
                        // query_rows could skip a row that committed between them).
                        // `MIN(rowid)-1` when in-retention rows exist (deliver from
                        // MIN inclusive); else the current `MAX(rowid)` (tail only —
                        // any later in-window row has rowid > MAX, so it is caught);
                        // else 0 (empty table).
                        conn.query_row(
                            "SELECT COALESCE( \
                                 (SELECT MIN(rowid) - 1 FROM events WHERE timestamp >= ?1), \
                                 (SELECT MAX(rowid) FROM events), \
                                 0)",
                            [&cutoff],
                            |r| r.get::<_, i64>(0),
                        )
                        .map_err(|e| ReadApiError::Db(e.to_string()))
                    })
                    .await
                    .map_err(|e| ReadApiError::Db(e.to_string()))??
                }
            },
            Some(ReadCursor(id)) => {
                let pool = self.pool.clone();
                let id_for_query = id.clone();
                let found =
                    tokio::task::spawn_blocking(move || -> Result<Option<i64>, ReadApiError> {
                        let conn = pool.get().map_err(|e| ReadApiError::Db(e.to_string()))?;
                        conn.query_row(
                            "SELECT rowid FROM events WHERE id = ?1",
                            [id_for_query],
                            |r| r.get::<_, i64>(0),
                        )
                        .optional()
                        .map_err(|e| ReadApiError::Db(e.to_string()))
                    })
                    .await
                    .map_err(|e| ReadApiError::Db(e.to_string()))??;
                match found {
                    Some(rowid) => rowid,
                    None => return Err(ReadApiError::CursorNotFound(id)),
                }
            }
        };

        Ok(ResumeStream {
            pool: self.pool.clone(),
            last_rowid,
            filter: row_filter,
            buffer: VecDeque::new(),
        })
    }

    async fn query(
        &self,
        filter: &EventFilter,
        limit: usize,
    ) -> Result<Vec<ReadEvent>, ReadApiError> {
        let rf = RowFilter::from_filter(filter, self.retention_cutoff())?;
        let capped = limit.min(MAX_LIMIT as usize) as i64;
        let pool = self.pool.clone();
        // ALL filters (incl. `since`) applied in SQL so `LIMIT` operates on the
        // filtered set — never a rowid window a post-LIMIT `since` drop could
        // silently under-count (round-6 audit fix).
        let rows = tokio::task::spawn_blocking(move || -> Result<Vec<(i64, Event)>, ReadApiError> {
            use rusqlite::types::Value;
            let conn = pool.get().map_err(|e| ReadApiError::Db(e.to_string()))?;
            // Build the WHERE dynamically with ONLY the present filters, UNGUARDED,
            // so SQLite can use `idx_events_type` / `idx_events_*` (round-14 fix —
            // the prior `?N IS NULL OR (...)` wrappers forced a full SCAN, defeating
            // the round-12 index-range intent). Values are still bound parameters
            // (no injection); `SELECT_COLS` is a const.
            let mut clauses: Vec<&str> = Vec::new();
            let mut params: Vec<Value> = Vec::new();
            if let Some(p) = &rf.event_type_prefix {
                match &rf.event_type_upper {
                    // INDEX-USABLE range on idx_events_type + substr residual.
                    Some(up) => {
                        clauses.push(
                            "event_type >= ? AND event_type < ? AND substr(event_type, 1, length(?)) = ?",
                        );
                        params.push(Value::Text(p.clone()));
                        params.push(Value::Text(up.clone()));
                        params.push(Value::Text(p.clone()));
                        params.push(Value::Text(p.clone()));
                    }
                    // uncomputable-upper edge: substr-only (correct, non-indexed).
                    None => {
                        clauses.push("substr(event_type, 1, length(?)) = ?");
                        params.push(Value::Text(p.clone()));
                        params.push(Value::Text(p.clone()));
                    }
                }
            }
            if let Some(a) = &rf.agent_id {
                clauses.push("agent_id = ?");
                params.push(Value::Text(a.clone()));
            }
            if let Some(r) = &rf.run_id {
                clauses.push("run_id = ?");
                params.push(Value::Text(r.clone()));
            }
            if let Some(t) = &rf.trace_id {
                clauses.push("trace_id = ?");
                params.push(Value::Text(t.clone()));
            }
            if let Some(c) = &rf.retention_cutoff_str {
                clauses.push("timestamp >= ?");
                params.push(Value::Text(c.clone()));
            }
            if let Some(s) = &rf.since_sql {
                clauses.push("timestamp >= ?");
                params.push(Value::Text(s.clone()));
            }
            let where_sql = if clauses.is_empty() {
                "1=1".to_string()
            } else {
                clauses.join(" AND ")
            };
            params.push(Value::Integer(capped));
            let sql =
                format!("SELECT {SELECT_COLS} FROM events WHERE {where_sql} ORDER BY rowid DESC LIMIT ?");
            let mut stmt = conn.prepare_cached(&sql).map_err(|e| ReadApiError::Db(e.to_string()))?;
            let mapped = stmt
                .query_map(rusqlite::params_from_iter(params), row_to_event)
                .map_err(|e| ReadApiError::Db(e.to_string()))?;
            let mut out = Vec::new();
            for r in mapped {
                out.push(r.map_err(|e| ReadApiError::Db(e.to_string()))?);
            }
            Ok(out)
        })
        .await
        .map_err(|e| ReadApiError::Db(e.to_string()))??;

        Ok(rows
            .into_iter()
            .map(|(_, ev)| ReadEvent {
                cursor: ReadCursor(ev.id.clone()),
                event: Arc::new(ev),
            })
            .collect())
    }
}

/// (a) Live broadcast tail. Best-effort; `recv()` yields the next filter-matching
/// event, or a `Lagged`/`Closed` signal. Carries no durable cursor.
pub struct LiveSubscription {
    rx: broadcast::Receiver<Arc<Event>>,
    filter: EventFilter,
}

impl LiveSubscription {
    /// Match a live broadcast event against the filter. `since` is intentionally
    /// ignored on the live path (round-5: the live feed is not history-scoped).
    fn matches_live(&self, ev: &Event) -> bool {
        if let Some(prefix) = &self.filter.event_type_prefix {
            if !ev.event_type.starts_with(prefix) {
                return false;
            }
        }
        if let Some(a) = &self.filter.agent_id {
            if &ev.agent_id != a {
                return false;
            }
        }
        if let Some(r) = &self.filter.run_id {
            if ev.run_id.as_deref() != Some(r.as_str()) {
                return false;
            }
        }
        if let Some(t) = &self.filter.trace_id {
            if &ev.trace_id != t {
                return false;
            }
        }
        true
    }

    /// Await the next filter-matching live event. Non-matching events are skipped
    /// internally. `Lagged`/`Closed` are surfaced.
    pub async fn recv(&mut self) -> ReadNext {
        loop {
            match self.rx.recv().await {
                Ok(ev) => {
                    if self.matches_live(&ev) {
                        return ReadNext::Event(ev);
                    }
                    // non-match → keep pulling
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    return ReadNext::Lagged { skipped: n }
                }
                Err(broadcast::error::RecvError::Closed) => return ReadNext::Closed,
            }
        }
    }
}

/// (b) Durable resume stream — a `rowid`-ordered DB-tail over the `events` table.
/// `recv()` yields the next committed event with `rowid > last` that matches the
/// filter, in rowid order (replay backlog then live tail). Gap-free over committed
/// rows; every item carries a durable cursor (its own `id`).
///
/// Fetches are strictly rowid-contiguous (no SQL filters); the filter is applied
/// in Rust while `last_rowid` advances over EVERY scanned row — so a
/// sparse/never-matching filter can never cause the tail to re-scan the same range
/// (round-6 audit fix). Cost note (§3.8): `resume(None, …)` starts just before the
/// first IN-RETENTION row (round-12 fix — it does NOT cold-scan pre-retention
/// history in the never-pruned table); a resume-from-cursor is cheaper still. Uses
/// a DEDICATED read pool isolated from the writer pool, so tailing never starves
/// the `db_indexer` write path.
pub struct ResumeStream {
    pool: Arc<Pool<SqliteConnectionManager>>,
    last_rowid: i64,
    filter: RowFilter,
    buffer: VecDeque<ReadEvent>,
}

impl ResumeStream {
    /// Await the next matching event in the durable tail. Drains the current
    /// batch's matches before issuing the next `rowid`-range fetch; when caught up
    /// (no more rows) it sleeps [`RESUME_TAIL_POLL`] and re-polls (a live tail —
    /// bound with `tokio::time::timeout` to detect "no more, for now"). Only DB
    /// errors terminate it.
    pub async fn recv(&mut self) -> Result<Option<ReadEvent>, ReadApiError> {
        loop {
            if let Some(ev) = self.buffer.pop_front() {
                return Ok(Some(ev));
            }
            let got_rows = self.fetch_batch().await?;
            if self.buffer.is_empty() && !got_rows {
                // Genuinely caught up (no rows beyond last_rowid) — poll.
                tokio::time::sleep(RESUME_TAIL_POLL).await;
            }
            // If got_rows but all were filtered out, last_rowid already advanced
            // past them (no rescan); loop refetches the next range immediately.
        }
    }

    /// Fetch the next rowid-contiguous batch (rowid > last, no SQL filters,
    /// ORDER BY rowid ASC, LIMIT `RESUME_BATCH`); advance `last_rowid` to the batch
    /// max ALWAYS, and push filter-matching events into `buffer`. Returns whether
    /// the batch contained any rows.
    async fn fetch_batch(&mut self) -> Result<bool, ReadApiError> {
        let pool = self.pool.clone();
        let last = self.last_rowid;
        let rows =
            tokio::task::spawn_blocking(move || -> Result<Vec<(i64, Event)>, ReadApiError> {
                let conn = pool.get().map_err(|e| ReadApiError::Db(e.to_string()))?;
                let sql = format!(
                    "SELECT {SELECT_COLS} FROM events WHERE rowid > ?1 ORDER BY rowid ASC LIMIT ?2"
                );
                let mut stmt = conn
                    .prepare_cached(&sql)
                    .map_err(|e| ReadApiError::Db(e.to_string()))?;
                let mapped = stmt
                    .query_map(rusqlite::params![last, RESUME_BATCH as i64], row_to_event)
                    .map_err(|e| ReadApiError::Db(e.to_string()))?;
                let mut out = Vec::new();
                for r in mapped {
                    out.push(r.map_err(|e| ReadApiError::Db(e.to_string()))?);
                }
                Ok(out)
            })
            .await
            .map_err(|e| ReadApiError::Db(e.to_string()))??;

        let got_rows = !rows.is_empty();
        for (rowid, event) in rows {
            self.last_rowid = self.last_rowid.max(rowid);
            if self.filter.matches(&event) {
                self.buffer.push_back(ReadEvent {
                    cursor: ReadCursor(event.id.clone()),
                    event: Arc::new(event),
                });
            }
        }
        Ok(got_rows)
    }
}

//! 5 `HostFunctionHandler` impls for the `agent-memory` WIT interface
//! (MODULE-011 §1.3.1 + `runtime/wit/advance.wit`). Slice B.
//!
//! WIT result encoding:
//! - `remember` returns `result<memory-id, memory-error>` — non-unit OK arm →
//!   `Val::Result(Ok(Some(Box::new(Val::String(id)))))`.
//! - `recall` / `recall-at` return `result<list<memory-entry>, memory-error>` —
//!   non-unit OK arm with a list payload.
//! - `forget` / `rollback-memory` return `result<_, memory-error>` — UNIT OK
//!   arm → `Val::Result(Ok(None))`. NEVER `Some(payload)` (Wasmtime 43 rejects
//!   `Some` for a unit OK arm).
//! - Errors always lower as `Val::Result(Err(Some(Box::new(memory_error))))`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use advance_runtime::host_registry::{HostCallContext, HostCallError, HostFunctionHandler};
use advance_shared_types::traits::{EventBusEmit, RememberContentPolicy, RememberDecision};
use uuid::Uuid;
use wasmtime::component::Val;

use crate::clock::{Clock, SystemClock};
use crate::events;

use crate::knowledge::{MemoryEntry, MemoryStatus, MemoryType};
use crate::l6::cursor::L6CursorStore;
use crate::rollback::MemoryGitRestore;
use crate::store::{ForgetError, MemoryStore};
use crate::wit_error::{wit_memory_error_to_val, WitMemoryError};

/// DoS bounds enforced at every WIT-host-fn entry BEFORE allocating the Val
/// conversion. Mirrors the cap-fs MAX_PATH_BYTES / MAX_READ_BYTES pattern.
/// Round-13 adversarial-fix #2: previously every string + list parameter was
/// unbounded, allowing a guest to allocate arbitrary host RAM per call.

/// 1 MiB content cap on `remember(content)`. Above this, the handler rejects
/// before mutating the store. Generous for natural-language memory entries;
/// stricter than the underlying schema (`MemoryEntry.content: String` is
/// unbounded) precisely because the WIT boundary is the trust boundary.
pub const MAX_CONTENT_BYTES: usize = 1024 * 1024;

/// Per-tag max length (256 bytes). Matches typical CONTRACT-001 spec-string
/// caps in MODULE-001.
pub const MAX_TAG_BYTES: usize = 256;

/// Max tags per `remember` call (256). Bounds the `Vec<Val::String>`
/// expansion AND the persistent `MemoryEntry.tags` Vec size.
pub const MAX_TAGS_COUNT: usize = 256;

/// MODULE-005-AC-29 producer-boundary scan admission control: the maximum number of
/// CONCURRENT policy scans (each runs on a tokio blocking thread). A burst of large
/// `remember()` calls beyond this bound FAILS OPEN — the scan is skipped and the write
/// proceeds — rather than saturating the shared blocking pool. Availability of the write
/// path outranks best-effort enforcement (a producer-boundary heuristic, not a security
/// boundary). Only consulted when a policy is wired (`None` path never touches it).
const MAX_CONCURRENT_SCANS: usize = 8;

/// 64 KiB cap on `recall(query)` + `recall-at(query)`. Bounds the
/// `to_lowercase()` allocation per call.
pub const MAX_QUERY_BYTES: usize = 64 * 1024;

/// 64-byte cap on `recall-at(timestamp)` / `rollback-memory(timestamp)` —
/// well above any RFC3339-ish format (`YYYY-MM-DDTHH:MM:SS.sss±HH:MM` is
/// 29 chars).
pub const MAX_TIMESTAMP_BYTES: usize = 64;

/// Cap recall result size at 1024 entries per call. `limit == 0` is also
/// mapped to this cap (round-13 adversarial-fix #3 — previously `0` resolved
/// to `usize::MAX`, returning the entire bucket cloned).
pub const MAX_RECALL_LIMIT: u32 = 1024;

/// Loosely validate that a timestamp string starts with `YYYY-MM-DDT`. Slice
/// B is deliberately lenient (no full RFC3339 parser, no chrono dep), but a
/// minimal shape check protects against accidental empty / wildcard inputs
/// from a guest that would cause `recall-at` / `rollback-memory` to
/// pathologically lex-compare against unrelated `created_at` strings.
fn validate_timestamp_shape(ts: &str) -> Result<(), WitMemoryError> {
    if ts.len() < 11 || ts.len() > MAX_TIMESTAMP_BYTES {
        return Err(WitMemoryError::StorageError(format!(
            "timestamp length {} outside [11, {}]",
            ts.len(),
            MAX_TIMESTAMP_BYTES
        )));
    }
    let bytes = ts.as_bytes();
    // YYYY-MM-DDT prefix check (positions 0-3 digits, 4 dash, 5-6 digits, 7 dash, 8-9 digits, 10 T).
    let valid_prefix = bytes[0].is_ascii_digit()
        && bytes[1].is_ascii_digit()
        && bytes[2].is_ascii_digit()
        && bytes[3].is_ascii_digit()
        && bytes[4] == b'-'
        && bytes[5].is_ascii_digit()
        && bytes[6].is_ascii_digit()
        && bytes[7] == b'-'
        && bytes[8].is_ascii_digit()
        && bytes[9].is_ascii_digit()
        && bytes[10] == b'T';
    if !valid_prefix {
        return Err(WitMemoryError::StorageError(format!(
            "timestamp '{ts}' does not match YYYY-MM-DDT… shape"
        )));
    }
    Ok(())
}

/// Format a [`Clock`]'s `now()` as a SECOND-granularity `Z`-form RFC3339 string
/// for [`MemoryEntry::created_at`] (slice m011-memory-persist, AC-42).
///
/// Uses `to_rfc3339_opts(Secs, true)` → e.g. `2026-06-06T08:59:43Z`. Two format
/// decisions, both forced by the fact that `created_at` is compared
/// **lexicographically** (raw string) in `recall_at`/`rollback`
/// (`store.rs::recall_at`/`rollback`):
/// 1. **`Z` form, not `+00:00`** (the `true` arg): bare `to_rfc3339()` emits
///    `+00:00`, which would mis-order against the `Z`-form timestamps used
///    everywhere else.
/// 2. **SECOND granularity, not millis** (`Secs`): every `created_at` in the
///    `knowledge.jsonl` schema is second-granularity `Z` (knowledge.rs examples
///    `2026-03-23T10:00:00Z`, all store.rs/test fixtures, the mechanical-digest
///    stub). A millis form (`…43.123Z`) is NOT lexicographically monotonic
///    against a second-granularity bound (`…43Z`), because `'.'` (0x2E) sorts
///    before `'Z'` (0x5A) — so `…43.123Z` < `…43Z`, mis-classifying a
///    same-second entry at a same-second `recall_at`/`rollback` boundary.
///    Matching the schema's second granularity keeps the lexical compare
///    order-preserving for all `created_at`↔`created_at` comparisons.
///
/// No new `chrono` dep — uses the `advance_shared_types::chrono` re-export.
///
/// Slice m011-mem-product: delegates to the shared
/// [`crate::clock::clock_now_rfc3339_z`] helper (byte-identical to the prior
/// inline body) so the remember-handler and the mechanical-digest fallback
/// emit the IDENTICAL `created_at` form.
fn created_at_now(clock: &dyn Clock) -> String {
    crate::clock::clock_now_rfc3339_z(clock)
}

fn ok_payload(payload: Val) -> Vec<Val> {
    vec![Val::Result(Ok(Some(Box::new(payload))))]
}

fn ok_unit() -> Vec<Val> {
    vec![Val::Result(Ok(None))]
}

fn err_variant(err: &WitMemoryError) -> Vec<Val> {
    vec![Val::Result(Err(Some(Box::new(wit_memory_error_to_val(
        err,
    )))))]
}

fn entry_to_val(e: &MemoryEntry) -> Val {
    Val::Record(vec![
        ("id".to_string(), Val::String(e.id.clone())),
        ("content".to_string(), Val::String(e.content.clone())),
        (
            "tags".to_string(),
            Val::List(e.tags.iter().cloned().map(Val::String).collect()),
        ),
        ("created-at".to_string(), Val::String(e.created_at.clone())),
        ("score".to_string(), Val::Option(None)),
        (
            "type".to_string(),
            Val::Option(Some(Box::new(Val::String(memory_type_to_string(
                &e.entry_type,
            ))))),
        ),
        (
            "status".to_string(),
            Val::Option(Some(Box::new(Val::String(memory_status_to_string(
                &e.status,
            ))))),
        ),
        (
            "task-origin".to_string(),
            match &e.task_origin {
                Some(s) => Val::Option(Some(Box::new(Val::String(s.clone())))),
                None => Val::Option(None),
            },
        ),
    ])
}

fn memory_type_to_string(t: &MemoryType) -> String {
    match t {
        MemoryType::Fact => "fact".into(),
        MemoryType::UserPreference => "user-preference".into(),
    }
}

fn memory_status_to_string(s: &MemoryStatus) -> String {
    match s {
        MemoryStatus::Active => "active".into(),
        MemoryStatus::Contested => "contested".into(),
        MemoryStatus::Orphaned => "orphaned".into(),
        MemoryStatus::Superseded => "superseded".into(),
        MemoryStatus::Forgotten => "forgotten".into(),
    }
}

pub struct RememberHandler {
    store: Arc<MemoryStore>,
    event_bus: Arc<dyn EventBusEmit + Send + Sync>,
    /// Wall-clock source for `created_at` (slice m011-memory-persist, AC-42).
    /// Defaults to [`SystemClock`] via [`RememberHandler::new`] (so production
    /// — incl. the unchanged `register_agent_memory` call sites — gets real
    /// time with no signature change); tests inject a `MutableClock` via
    /// [`RememberHandler::with_clock`] for deterministic timestamps.
    clock: Arc<dyn Clock>,
    /// MODULE-005-AC-29 producer-boundary policy (CONTRACT-214). `None` (the
    /// default via [`RememberHandler::new`] / [`RememberHandler::with_clock`],
    /// and the legacy `register_agent_memory` / `_with_git` registrations) makes
    /// the `remember()` path byte-identical to the pre-guard behaviour. When
    /// `Some`, `call()` runs `check_content` on a blocking thread before building
    /// the entry and rejects raw file-resident bytes. See `register_agent_memory_with_git_and_policy`.
    policy: Option<Arc<dyn RememberContentPolicy>>,
    /// Admission control for the producer-boundary scan ([`MAX_CONCURRENT_SCANS`]
    /// permits). Bounds how many scans run concurrently on the tokio blocking pool so a
    /// burst of large `remember()` calls cannot starve it; over the bound the scan is
    /// skipped (fail-open). Never consulted when `policy` is `None`.
    scan_permits: Arc<tokio::sync::Semaphore>,
}

impl RememberHandler {
    /// Construct with the real [`SystemClock`] and NO producer-boundary policy.
    /// Signature UNCHANGED from the pre-AC-42 2-arg form — `register_agent_memory`
    /// + its call sites compile untouched; `policy = None` keeps the write path
    /// byte-identical.
    pub fn new(store: Arc<MemoryStore>, event_bus: Arc<dyn EventBusEmit + Send + Sync>) -> Self {
        Self {
            store,
            event_bus,
            clock: Arc::new(SystemClock),
            policy: None,
            scan_permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SCANS)),
        }
    }

    /// Construct with an injected [`Clock`] (test seam — deterministic
    /// `created_at` via `MutableClock`). `policy = None` (byte-identical).
    pub fn with_clock(
        store: Arc<MemoryStore>,
        event_bus: Arc<dyn EventBusEmit + Send + Sync>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            store,
            event_bus,
            clock,
            policy: None,
            scan_permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SCANS)),
        }
    }

    /// Construct with a producer-boundary policy (MODULE-005-AC-29 / CONTRACT-214).
    /// Uses the real [`SystemClock`]. Threaded in by
    /// [`crate::host_fn::register_agent_memory_with_git_and_policy`]; production
    /// supplies `Some(cap_lifecycle::WorkspaceFileResidentPolicy)`.
    pub fn with_policy(
        store: Arc<MemoryStore>,
        event_bus: Arc<dyn EventBusEmit + Send + Sync>,
        policy: Option<Arc<dyn RememberContentPolicy>>,
    ) -> Self {
        Self {
            store,
            event_bus,
            clock: Arc::new(SystemClock),
            policy,
            scan_permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SCANS)),
        }
    }
}

impl HostFunctionHandler for RememberHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let store = Arc::clone(&self.store);
        let bus = Arc::clone(&self.event_bus);
        let clock = Arc::clone(&self.clock);
        // Pre-clone the optional producer-boundary policy into an owned local before
        // `Box::pin` — the returned future is `'static`, so the async body may not
        // borrow through `self` (identical to store/bus/clock above). `None` ⇒ no clone.
        let policy = self.policy.clone();
        let scan_permits = Arc::clone(&self.scan_permits);
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for agent-memory.remember, got {results_len}"
                )));
            }
            let (content, tags) = match params.as_slice() {
                [Val::String(c), Val::List(t)] => {
                    // Round-13 adversarial-fix #2: bound EVERY guest-controlled
                    // allocation BEFORE any clone() lands in the host heap.
                    if c.len() > MAX_CONTENT_BYTES {
                        return Ok(err_variant(&WitMemoryError::LimitExceeded(format!(
                            "remember: content size {} exceeds MAX_CONTENT_BYTES ({})",
                            c.len(),
                            MAX_CONTENT_BYTES
                        ))));
                    }
                    if t.len() > MAX_TAGS_COUNT {
                        return Ok(err_variant(&WitMemoryError::LimitExceeded(format!(
                            "remember: tags count {} exceeds MAX_TAGS_COUNT ({})",
                            t.len(),
                            MAX_TAGS_COUNT
                        ))));
                    }
                    let mut tags = Vec::with_capacity(t.len());
                    for v in t {
                        match v {
                            Val::String(s) => {
                                if s.len() > MAX_TAG_BYTES {
                                    return Ok(err_variant(&WitMemoryError::LimitExceeded(
                                        format!(
                                            "remember: tag length {} exceeds MAX_TAG_BYTES ({})",
                                            s.len(),
                                            MAX_TAG_BYTES
                                        ),
                                    )));
                                }
                                tags.push(s.clone());
                            }
                            _ => {
                                return Ok(err_variant(&WitMemoryError::StorageError(
                                    "remember: tags list contained non-string element".into(),
                                )));
                            }
                        }
                    }
                    (c.clone(), tags)
                }
                _ => {
                    return Ok(err_variant(&WitMemoryError::StorageError(
                        "remember: expected (string, list<string>) params".into(),
                    )));
                }
            };
            // MODULE-005-AC-29 producer-boundary guard (CONTRACT-214). When a policy
            // is wired, reject `remember()` content detected as raw file-resident bytes
            // BEFORE building the event or inserting — so a rejected call emits no
            // `memory.remember` and writes nothing. The concrete policy does bounded
            // blocking FS I/O, so it runs on a blocking thread (off the async reactor);
            // a policy panic (`JoinError`) FAILS OPEN (Allow). `None` (default / legacy
            // registration) skips this whole block — byte-identical to the pre-guard path.
            if let Some(p) = &policy {
                // Admission control: only run the scan if a scan permit is free. Over
                // MAX_CONCURRENT_SCANS concurrent scans, `try_acquire_owned` errors and we
                // FAIL OPEN (skip the scan, allow the write) rather than queueing onto the
                // saturated blocking pool. The permit is held across the scan and released
                // when `_permit` drops at the end of this block.
                if let Ok(_permit) = Arc::clone(&scan_permits).try_acquire_owned() {
                    let p = Arc::clone(p);
                    let agent = ctx.agent_id.clone();
                    let content_for_policy = content.clone();
                    let decision = tokio::task::spawn_blocking(move || {
                        p.check_content(&agent, &content_for_policy)
                    })
                    .await
                    .unwrap_or(RememberDecision::Allow);
                    if let RememberDecision::Reject(reason) = decision {
                        return Ok(err_variant(&WitMemoryError::StorageError(reason)));
                    }
                }
            }
            // Build the bounded `memory.remember` event NOW (holds only a
            // ≤64-char preview + tags, NOT the full content) so it can be
            // emitted on the success arm without re-borrowing the
            // entry-consumed `content`. Emission is success-scoped.
            let remember_ev = events::memory_remember_event(&ctx, &content, &tags);
            let entry = MemoryEntry {
                id: Uuid::new_v4().to_string(),
                agent_id: ctx.agent_id.clone(),
                entry_type: MemoryType::Fact,
                content,
                tags,
                created_at: created_at_now(clock.as_ref()),
                task_origin: None,
                is_active: true,
                superseded_by: None,
                status: MemoryStatus::Active,
                supersession_reason: None,
                cluster_id: None,
                sources: vec![],
            };
            match store.insert(&ctx.agent_id, entry) {
                Ok(id) => {
                    bus.emit(remember_ev);
                    Ok(ok_payload(Val::String(id)))
                }
                Err(e) => Ok(err_variant(&e.into())),
            }
        })
    }
}

pub struct RecallHandler {
    store: Arc<MemoryStore>,
    event_bus: Arc<dyn EventBusEmit + Send + Sync>,
}

impl RecallHandler {
    pub fn new(store: Arc<MemoryStore>, event_bus: Arc<dyn EventBusEmit + Send + Sync>) -> Self {
        Self { store, event_bus }
    }
}

impl HostFunctionHandler for RecallHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let store = Arc::clone(&self.store);
        let bus = Arc::clone(&self.event_bus);
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for agent-memory.recall, got {results_len}"
                )));
            }
            let (query, limit) = match params.as_slice() {
                [Val::String(q), Val::U32(n)] => (q.clone(), *n),
                _ => {
                    return Ok(err_variant(&WitMemoryError::StorageError(
                        "recall: expected (string, u32) params".into(),
                    )));
                }
            };
            if query.len() > MAX_QUERY_BYTES {
                return Ok(err_variant(&WitMemoryError::LimitExceeded(format!(
                    "recall: query length {} exceeds MAX_QUERY_BYTES ({})",
                    query.len(),
                    MAX_QUERY_BYTES
                ))));
            }
            // Round-13 adversarial-fix #3: cap recall page size. limit == 0 was
            // previously resolving to usize::MAX in the store, allowing a guest
            // to request the entire bucket cloned per call.
            let capped = if limit == 0 || limit > MAX_RECALL_LIMIT {
                MAX_RECALL_LIMIT
            } else {
                limit
            };
            let hits = store.recall(&ctx.agent_id, &query, capped);
            let list = Val::List(hits.iter().map(entry_to_val).collect());
            bus.emit(events::memory_recall_event(&ctx, &query, hits.len()));
            Ok(ok_payload(list))
        })
    }
}

pub struct ForgetHandler {
    store: Arc<MemoryStore>,
    event_bus: Arc<dyn EventBusEmit + Send + Sync>,
}

impl ForgetHandler {
    pub fn new(store: Arc<MemoryStore>, event_bus: Arc<dyn EventBusEmit + Send + Sync>) -> Self {
        Self { store, event_bus }
    }
}

impl HostFunctionHandler for ForgetHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let store = Arc::clone(&self.store);
        let bus = Arc::clone(&self.event_bus);
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for agent-memory.forget, got {results_len}"
                )));
            }
            let id = match params.as_slice() {
                [Val::String(s)] => s.clone(),
                _ => {
                    return Ok(err_variant(&WitMemoryError::StorageError(
                        "forget: expected (string) param".into(),
                    )));
                }
            };
            match store.forget(&ctx.agent_id, &id) {
                Ok(()) => {
                    bus.emit(events::memory_forget_event(&ctx, &id));
                    Ok(ok_unit())
                }
                Err(ForgetError::NotFound(msg)) => Ok(err_variant(&WitMemoryError::NotFound(msg))),
                Err(ForgetError::Invalid(msg)) => {
                    Ok(err_variant(&WitMemoryError::StorageError(msg)))
                }
            }
        })
    }
}

pub struct RecallAtHandler {
    store: Arc<MemoryStore>,
    event_bus: Arc<dyn EventBusEmit + Send + Sync>,
}

impl RecallAtHandler {
    pub fn new(store: Arc<MemoryStore>, event_bus: Arc<dyn EventBusEmit + Send + Sync>) -> Self {
        Self { store, event_bus }
    }
}

impl HostFunctionHandler for RecallAtHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let store = Arc::clone(&self.store);
        let bus = Arc::clone(&self.event_bus);
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for agent-memory.recall-at, got {results_len}"
                )));
            }
            let (query, ts, limit) = match params.as_slice() {
                [Val::String(q), Val::String(t), Val::U32(n)] => (q.clone(), t.clone(), *n),
                _ => {
                    return Ok(err_variant(&WitMemoryError::StorageError(
                        "recall-at: expected (string, string, u32) params".into(),
                    )));
                }
            };
            if query.len() > MAX_QUERY_BYTES {
                return Ok(err_variant(&WitMemoryError::LimitExceeded(format!(
                    "recall-at: query length {} exceeds MAX_QUERY_BYTES ({})",
                    query.len(),
                    MAX_QUERY_BYTES
                ))));
            }
            if let Err(e) = validate_timestamp_shape(&ts) {
                return Ok(err_variant(&e));
            }
            let capped = if limit == 0 || limit > MAX_RECALL_LIMIT {
                MAX_RECALL_LIMIT
            } else {
                limit
            };
            let hits = store.recall_at(&ctx.agent_id, &query, &ts, capped);
            let list = Val::List(hits.iter().map(entry_to_val).collect());
            bus.emit(events::memory_recall_at_event(
                &ctx,
                &query,
                &ts,
                hits.len(),
            ));
            Ok(ok_payload(list))
        })
    }
}

pub struct RollbackMemoryHandler {
    store: Arc<MemoryStore>,
    event_bus: Arc<dyn EventBusEmit + Send + Sync>,
    /// AC-18 cap-memory-half (slice G, m011-slice-g): on the rollback-memory
    /// WIT success arm, reset the L6 cursor to literal initial state per
    /// AC-18 §1.4 wording. See [`L6CursorStore::reset_to_epoch`].
    cursor_store: Arc<L6CursorStore>,
    /// rollback-memory slice (2026-06-12): the AC-18 git half — the
    /// dependency-inverted [`MemoryGitRestore`] seam restoring
    /// `_knowledge_map.yaml` + `syntheses/*.md` from history (knowledge.jsonl
    /// is the store's in-process job; see the trait rustdoc for the
    /// split-brain-avoiding division). `None` (the legacy `new()`) skips the
    /// git half — pre-slice behavior, byte-identical.
    git_restore: Option<Arc<dyn MemoryGitRestore>>,
}

impl RollbackMemoryHandler {
    pub fn new(
        store: Arc<MemoryStore>,
        event_bus: Arc<dyn EventBusEmit + Send + Sync>,
        cursor_store: Arc<L6CursorStore>,
    ) -> Self {
        Self {
            store,
            event_bus,
            cursor_store,
            git_restore: None,
        }
    }

    /// rollback-memory slice: additive constructor wiring the git-restore
    /// seam (the composition root injects the MODULE-003-backed adapter).
    pub fn new_with_git_restore(
        store: Arc<MemoryStore>,
        event_bus: Arc<dyn EventBusEmit + Send + Sync>,
        cursor_store: Arc<L6CursorStore>,
        git_restore: Option<Arc<dyn MemoryGitRestore>>,
    ) -> Self {
        Self {
            store,
            event_bus,
            cursor_store,
            git_restore,
        }
    }
}

impl HostFunctionHandler for RollbackMemoryHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let store = Arc::clone(&self.store);
        let bus = Arc::clone(&self.event_bus);
        let cursor_store = Arc::clone(&self.cursor_store);
        let git_restore = self.git_restore.clone();
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for agent-memory.rollback-memory, got {results_len}"
                )));
            }
            let ts = match params.as_slice() {
                [Val::String(t)] => t.clone(),
                _ => {
                    return Ok(err_variant(&WitMemoryError::StorageError(
                        "rollback-memory: expected (string) param".into(),
                    )));
                }
            };
            // Round-13 adversarial-fix #1: previously the rollback host fn
            // accepted any guest-supplied string (including "9999..." or "~"
            // which lex-sorts above all ISO-8601 dates) and used it directly
            // for the lex-compare in MemoryStore::rollback, wiping the entire
            // bucket. Now reject malformed timestamps at the boundary.
            if let Err(e) = validate_timestamp_shape(&ts) {
                return Ok(err_variant(&e));
            }
            // Adversarial-round F3 fix (2026-06-13): the prefix-only shape
            // gate is NOT enough for rollback — the store half lex-compares
            // (which its rustdoc requires to be Z-form) while the git half
            // strictly parses RFC3339; an offset-form ("...+09:00") or
            // suffix-garbage timestamp would split the two halves onto
            // DIFFERENT instants, or mutate-then-error deterministically.
            // Require full canonical Z-form RFC3339 BEFORE any mutation so
            // both halves act on the same instant (rollback-only tightening;
            // the read-only recall-at keeps the historic shape gate).
            {
                use advance_shared_types::chrono::DateTime;
                let parses = DateTime::parse_from_rfc3339(&ts).is_ok();
                if !parses || !ts.ends_with('Z') {
                    return Ok(err_variant(&WitMemoryError::StorageError(format!(
                        "rollback-memory: timestamp must be canonical Z-form \
                         RFC3339 (e.g. 2026-06-13T00:00:00Z); got shape \
                         len={}",
                        ts.len()
                    ))));
                }
            }
            match store.rollback(&ctx.agent_id, &ts) {
                Ok(entries_deactivated) => {
                    // rollback-memory slice ordering (the adjudicated
                    // split-brain-avoiding sequence):
                    //   1. store mutation FIRST (in-process drop + the store's
                    //      own knowledge.jsonl persist — cache and file stay
                    //      consistent by construction; landed above);
                    //   2. git half SECOND — restore the no-runtime-cache
                    //      files (_knowledge_map.yaml + syntheses/*.md) as of
                    //      the timestamp via the injected seam. A git failure
                    //      surfaces as storage-error: the in-process half has
                    //      ALREADY landed (documented non-atomicity — the call
                    //      is retryable: a re-run re-drops nothing and retries
                    //      the restore);
                    //   3. cursor reset (epoch/0/0, NEVER from history);
                    //   4. observability emit LAST — records the completed
                    //      effect.
                    if let Some(git) = git_restore {
                        if let Err(e) = git.restore_at(ctx.agent_id.clone(), ts.clone()).await {
                            // Adversarial-round F11 fix (2026-06-13): the
                            // store half's destructive drop ALREADY landed —
                            // the audit event must record it even on the
                            // git-half failure path (a retry re-drops
                            // nothing and would emit entries_deactivated=0,
                            // permanently losing the count from the event
                            // stream). Emit BEFORE returning the error; the
                            // error return still signals the partial state
                            // to the guest (retryable, see seam rustdoc).
                            bus.emit(events::memory_rollback_event(
                                &ctx,
                                &ts,
                                entries_deactivated,
                            ));
                            return Ok(err_variant(&WitMemoryError::StorageError(format!(
                                "rollback-memory: git restore failed after the in-process \
                                 half landed (retryable): {e}"
                            ))));
                        }
                    }
                    cursor_store.reset_to_epoch(&ctx.agent_id);
                    bus.emit(events::memory_rollback_event(
                        &ctx,
                        &ts,
                        entries_deactivated,
                    ));
                    Ok(ok_unit())
                }
                Err(e) => Ok(err_variant(&e.into())),
            }
        })
    }
}

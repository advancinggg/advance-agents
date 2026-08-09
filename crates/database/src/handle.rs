use std::path::Path;
use std::sync::Arc;

use r2d2::{Pool, PooledConnection as R2d2PooledConn};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};

use crate::error::DbError;
use crate::schema::{apply as apply_migrations, SCHEMA_VERSION};
use crate::vec_adapter::register_sqlite_vec_extension;
use crate::{default_tunables_provider, embedding_to_blob, now_text, TunablesProvider};

const ID_SEPARATOR: char = '\u{1F}';

fn content_row_id(agent_id: &str, file_path: &str) -> String {
    format!("{agent_id}{ID_SEPARATOR}{file_path}")
}

fn meta_row_id(agent_id: &str, directory: &str, entry_name: &str) -> String {
    format!("{agent_id}{ID_SEPARATOR}{directory}{ID_SEPARATOR}{entry_name}")
}

/// Wave-20 Lane `search`: the `memory_index` row-id, agent-namespaced exactly like
/// [`content_row_id`] so the same memory doc ingested under multiple query aliases
/// (the prod `[bare, colon]` set) yields DISTINCT PK rows (no `memory_index.id`
/// collision) — each queryable under its own `agent_id` form.
fn memory_row_id(agent_id: &str, bare_id: &str) -> String {
    format!("{agent_id}{ID_SEPARATOR}{bare_id}")
}

/// Wave-20 Lane `search` — additive memory write-side ingest helper.
///
/// The missing counterpart of [`SqliteIndexHandle::upsert_content_index`] for the
/// `memory_index` + `memory_vec` surface (the trait exposes content / meta / task /
/// turn upserts but no memory upsert — memory rows were previously only bulk-written
/// by `rebuild.rs::scan_knowledge_jsonl`). It is a FREE fn over `&dyn
/// SqliteIndexHandle` (reusing the trait's existing pub `get_conn`), NOT a trait
/// method, so the CONTRACT-030 `SqliteIndexHandle` trait surface is UNCHANGED
/// (`modified_contracts: []`).
///
/// `bare_id` is the un-namespaced memory entry id; the helper validates the bare
/// components (mirroring `upsert_content_index`'s `validate_id_component`), composes
/// the agent-namespaced composite via [`memory_row_id`], and stores it RAW (the
/// composite legitimately contains the `\u{1F}` separator, so it is NOT itself
/// re-validated). `type` is fixed to `"fact"` to satisfy the `type TEXT NOT NULL`
/// schema constraint (recall does not filter on `type`); `is_active=1` /
/// `status='active'` / RFC-3339 `created_at` are set so the row passes recall's
/// `COALESCE(is_active,1)=1` + status + `parse_ts` gates. The embedding (when
/// present) is dim-checked against [`crate::DEFAULT_EMBEDDING_DIM`] — the `&dyn`
/// trait exposes no live `Tunables`, and the `*_vec` tables are fixed `float[768]`.
/// Idempotent: `ON CONFLICT(id) DO UPDATE` refreshes content + re-links the vec.
pub fn upsert_memory_index_row(
    handle: &dyn SqliteIndexHandle,
    agent_id: &str,
    bare_id: &str,
    content: &str,
    embedding: Option<&[f32]>,
) -> Result<(), DbError> {
    validate_agent_id_nonempty(agent_id)?;
    validate_id_component("agent_id", agent_id)?;
    validate_id_component("memory_id", bare_id)?;
    if let Some(e) = embedding {
        validate_embedding(e, crate::DEFAULT_EMBEDDING_DIM)?;
    }
    let id = memory_row_id(agent_id, bare_id);
    let now = now_text();
    let mut conn = handle.get_conn()?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    // `embedding BLOB` column stays NULL (embeddings live in memory_vec only,
    // mirroring `scan_knowledge_jsonl`). ON CONFLICT preserves the rowid (so the
    // memory_vec re-link below stays valid) and makes a re-ingest fully overwrite
    // the prior row's RECALL-relevant state: it refreshes `content`, and
    // REACTIVATES the row (`is_active=1`, `status='active'`, clearing any prior
    // `superseded_by`/`supersession_reason`) so a previously forgotten/superseded
    // id does NOT stay filtered out of recall after re-ingest (adversarial r10).
    // `created_at` is PRESERVED on conflict (not stomped with `now()`), keeping the
    // original provenance — recall orders by similarity, not by created_at.
    tx.execute(
        "INSERT INTO memory_index(id, agent_id, type, content, tags, embedding, created_at, \
           task_origin, superseded_by, is_active, status, supersession_reason, sources, \
           access_count, last_accessed) \
         VALUES (?1, ?2, 'fact', ?3, NULL, NULL, ?4, NULL, NULL, 1, 'active', NULL, NULL, 0, NULL) \
         ON CONFLICT(id) DO UPDATE SET \
           content = excluded.content, \
           is_active = 1, \
           status = 'active', \
           superseded_by = NULL, \
           supersession_reason = NULL",
        params![id, agent_id, content, now],
    )?;

    let rowid: i64 = tx.query_row(
        "SELECT rowid FROM memory_index WHERE id = ?1",
        params![id],
        |r| r.get(0),
    )?;

    // The `memory_vec` row ALWAYS reflects the current embedding: replace it when
    // `Some`, and DELETE any stale vec when `None` (adversarial r10 — otherwise a
    // content-only re-ingest could leave an old vector disagreeing with the new
    // content; a row with no vec is simply unrecallable, the consistent semantics).
    tx.execute("DELETE FROM memory_vec WHERE rowid = ?1", params![rowid])?;
    if let Some(emb) = embedding {
        tx.execute(
            "INSERT INTO memory_vec(rowid, embedding) VALUES (?1, ?2)",
            params![rowid, embedding_to_blob(emb)],
        )?;
    }

    tx.commit()?;
    Ok(())
}

/// Slice G: parameterized on `expected_dim` so the live snapshot value
/// from `Tunables` flows through. Callers in production pass
/// `self.current_tunables().embedding_dim`; unit tests pass a literal.
pub(crate) fn validate_embedding(emb: &[f32], expected_dim: usize) -> Result<(), DbError> {
    if emb.len() != expected_dim {
        return Err(DbError::InvalidConfig(format!(
            "embedding dim {} != expected {}",
            emb.len(),
            expected_dim
        )));
    }
    // Round-13 adversarial closure: reject NaN / ±Inf to prevent ranking
    // corruption — sqlite-vec's KNN distance with NaN produces non-deterministic
    // ordering and can contaminate top-K reads. Pre-flight rejection BEFORE
    // any SQL keeps the *_vec tables clean.
    if !emb.iter().all(|f| f.is_finite()) {
        return Err(DbError::InvalidConfig(
            "embedding components must all be finite (no NaN or ±Inf)".to_string(),
        ));
    }
    Ok(())
}

/// Validate that a caller-supplied `last_modified` string parses as RFC 3339
/// (the format every read path in this crate expects via
/// `recall.rs::parse_ts` / `recall.rs::ts_to_text`). Round-13 adversarial
/// closure: a trusted-but-buggy caller writing `Some("garbage")` would not
/// fail at write time but would later poison recall reads when the row is
/// returned (parse_ts errors out). Pre-flight syntactic check keeps the
/// write/read invariant aligned. None passes through unchanged (NULL on
/// INSERT / preserve-existing on UPDATE per the COALESCE semantic).
fn validate_last_modified(last_modified: Option<&str>) -> Result<(), DbError> {
    if let Some(s) = last_modified {
        chrono::DateTime::parse_from_rfc3339(s)
            .map_err(|e| DbError::InvalidConfig(format!("last_modified must be RFC 3339: {e}")))?;
    }
    Ok(())
}

/// Reject C0 control chars (U+0000..=U+001F) and U+007F (DEL) in any id
/// component. Slice H adversarial R1 W5 closure: the rebuild scanner uses
/// `rebuild.rs::id_component_safe` to reject the same range; the incremental
/// write surface must align so cap-memory writes that succeed here aren't
/// silently dropped by the next startup rebuild. This is also a log-injection
/// defense (control chars in agent_id flowing into MODULE-019 logs).
///
/// Trust boundary on this crate is process-internal trusted code; this is
/// defense-in-depth for in-process callers — NOT a security boundary against
/// external input. U+001F (the row-id separator byte) is included in the
/// C0 range and continues to be rejected.
fn validate_id_component(label: &str, component: &str) -> Result<(), DbError> {
    if component
        .chars()
        .any(|c| (c as u32) < 0x20 || c == '\u{7F}')
    {
        return Err(DbError::InvalidConfig(format!(
            "{label} must not contain C0 control chars (U+0000..=U+001F) or U+007F"
        )));
    }
    Ok(())
}

/// Reject empty / whitespace-only id-component string. Rationale:
/// `recall.rs::validate_agent_id` rejects empty/whitespace `agent_id` on the
/// read path, so writing rows with such an id-component would silently produce
/// orphan rows (writable but unreachable through the public Recall API or
/// task/turn lookup) — weakening AC-13's triple-consistency invariant.
/// Round-7 audit closure (agent_id) + Slice H adversarial R1 W4 closure
/// (task_id): keep the write/read surfaces aligned on what counts as a
/// valid id component.
fn validate_id_nonempty(label: &str, value: &str) -> Result<(), DbError> {
    if value.trim().is_empty() {
        return Err(DbError::InvalidConfig(format!(
            "{label} must not be empty or whitespace-only"
        )));
    }
    Ok(())
}

/// Back-compat wrapper for Slice E callers. Forwards to `validate_id_nonempty`
/// with the `agent_id` label.
fn validate_agent_id_nonempty(agent_id: &str) -> Result<(), DbError> {
    validate_id_nonempty("agent_id", agent_id)
}

pub type PooledConnection = R2d2PooledConn<SqliteConnectionManager>;

/// CONTRACT-030 — runtime SQLite handle.
///
/// **Trust boundary**: callers MUST be process-internal trusted code.
/// `db_path` and `pool_size` arguments to constructors flow into
/// `SqliteConnectionManager` and the connection pool with only minimal
/// validation (URI flag stripped, `:memory:` literal rejected, pool_size > 0).
/// This crate does NOT defend against an attacker who can write the SQLite
/// file at the supplied path before construction — caller is responsible for
/// path-isolation (e.g. `<workspace>/.runtime/index.db` per Decision 4 + the
/// `.runtime/` git-ignore set in `crates/git/src/repo.rs`). `schema.rs::apply`
/// adds a defense-in-depth `PRAGMA user_version` check that rejects unknown
/// non-zero versions, but a sophisticated forgery (matching version + matching
/// table names) still requires shape-validation at the consumer level.
pub trait SqliteIndexHandle: Send + Sync {
    fn get_conn(&self) -> Result<PooledConnection, DbError>;

    /// Returns the **runtime's expected** schema version (compile-time constant
    /// `SCHEMA_VERSION`). This is NOT a query against the database file. The
    /// on-disk version is set to this value at the end of `run_migrations()`,
    /// inside the same transaction as the DDL — so after a successful
    /// `run_migrations()`, on-disk and in-memory versions agree.
    fn schema_version(&self) -> u32;

    fn run_migrations(&self) -> Result<(), DbError>;

    // ──────────────────────────────────────────────────────────────────
    // Slice E — incremental write surface (CONTRACT-030 expansion).
    //
    // Each method runs as a single `TransactionBehavior::Immediate`
    // transaction over the primary `*_index` row + sibling FTS5/vec0
    // virtual tables. UPSERT preserves rowid across updates; FTS5/vec0
    // alignment with the primary table is maintained by DELETE+INSERT
    // with the bound rowid (FTS5 has no `ON CONFLICT`).
    // ──────────────────────────────────────────────────────────────────

    /// Upsert a content_index row + matching content_fts/content_vec rows.
    ///
    /// `embedding=None` leaves content_vec untouched (two-stage write —
    /// the post-processor fills it via a follow-up upsert with
    /// `embedding=Some`). When `Some`, validated against `EMBEDDING_DIM = 768`
    /// AND finite-ness (rejects NaN / ±Inf) BEFORE any SQL.
    ///
    /// `last_modified` is an RFC 3339 string and is parse-checked at
    /// pre-flight (round-13 adversarial closure: malformed strings would
    /// otherwise poison the read path's `parse_ts` and break recall).
    /// None on UPDATE preserves the existing column value (COALESCE
    /// semantic — lets a "preview-only refresh" not stomp the disk
    /// timestamp). None on INSERT writes NULL.
    ///
    /// `preview` is stored as bound — including the empty string "". This
    /// differs from the rebuild scanner's policy at `rebuild.rs::scan_content_files`,
    /// which writes `NULL` for empty previews. Slice E's contract is "store
    /// what the caller provided"; callers wanting the NULL-empty convention
    /// must filter on their side.
    ///
    /// `agent_id` MUST be non-empty and not whitespace-only (matches the
    /// read-side contract enforced by `recall.rs::validate_agent_id` —
    /// otherwise the row would be writable but unreachable through Recall).
    /// `agent_id` and `file_path` MUST NOT contain the row-id separator byte
    /// `\u{1F}` (U+001F INFORMATION SEPARATOR ONE) — pre-flight rejected
    /// with `DbError::InvalidConfig` (defense-in-depth: prevents accidental
    /// cross-key collision on the composite `id` column).
    fn upsert_content_index(
        &self,
        agent_id: &str,
        file_path: &str,
        preview: &str,
        embedding: Option<&[f32]>,
        last_modified: Option<&str>,
    ) -> Result<(), DbError>;

    /// Upsert a meta_index row + matching meta_vec row.
    ///
    /// `tags` is a JSON-encoded array string (matches Slice D rebuild
    /// slice's `scan_meta_yaml` encoding via `serde_json::to_string`).
    /// Callers must produce a JSON-shape string, NOT comma-separated values.
    ///
    /// `embedding=None` leaves meta_vec untouched. When `Some`, validated
    /// against `EMBEDDING_DIM = 768` AND finite-ness (rejects NaN / ±Inf)
    /// BEFORE any SQL. The parent table's `embedding BLOB` column is always
    /// NULL — embeddings live in `meta_vec` only.
    ///
    /// `agent_id` MUST be non-empty and not whitespace-only.
    /// `agent_id` / `directory` / `entry_name` MUST NOT contain the row-id
    /// separator byte `\u{1F}` — pre-flight rejected with
    /// `DbError::InvalidConfig`.
    fn upsert_meta_index(
        &self,
        agent_id: &str,
        directory: &str,
        entry_name: &str,
        description: Option<&str>,
        tags: Option<&str>,
        embedding: Option<&[f32]>,
    ) -> Result<(), DbError>;

    /// Remove a content_index row and its content_fts / content_vec siblings.
    /// Idempotent: removing a row that does not exist returns `Ok(())`.
    ///
    /// Same input contract as `upsert_content_index`: `agent_id` MUST be
    /// non-empty + non-whitespace, and neither `agent_id` nor `file_path`
    /// may contain `\u{1F}` — pre-flight rejected with `DbError::InvalidConfig`.
    fn delete_content_index_row(&self, agent_id: &str, file_path: &str) -> Result<(), DbError>;

    /// Remove a meta_index row and its meta_vec sibling.
    /// Idempotent: removing a row that does not exist returns `Ok(())`.
    ///
    /// Same input contract as `upsert_meta_index`: `agent_id` MUST be
    /// non-empty + non-whitespace, and none of `agent_id` / `directory` /
    /// `entry_name` may contain `\u{1F}`.
    fn delete_meta_index_row(
        &self,
        agent_id: &str,
        directory: &str,
        entry_name: &str,
    ) -> Result<(), DbError>;

    // ──────────────────────────────────────────────────────────────────
    // Slice H — task_index + turn_index incremental write surface
    // (m004-slice-h, 2026-05-24). Joint M004+M011 closure of M004-AC-10
    // (task_index sync per turn) + M004-AC-11 (turn_index per-turn writes
    // + reference_count sync-back per M011 §3.6 hard requirement).
    // Provides the M004-side write surface the future cap-memory rusqlite
    // adapter delegates to.
    // ──────────────────────────────────────────────────────────────────

    /// Upsert a task_index row + matching task_vec row.
    ///
    /// `task_id` is the single-column PRIMARY KEY (PRD §11.3.3 "tasks span
    /// agents"). Cross-agent calls writing the same `task_id` overwrite the
    /// prior row's `agent_id` + `title` + (COALESCE-merged) optional fields
    /// — INTENTIONAL design matching cap-memory `SqliteIndex::upsert_task`
    /// seam semantics.
    ///
    /// **CROSS-AGENT ATTRIBUTE-LEAK WARNING** (Slice H adversarial R1 W1):
    /// COALESCE preserves prior author's `brief` / `status` / `last_turn_at` /
    /// `turns_total` / task_vec embedding when the new caller passes `None`.
    /// Concretely: if agent-A writes `(task_id="t", brief="A's secret",
    /// embedding=A_emb)`, then agent-B writes `(task_id="t", title="B",
    /// brief=None, embedding=None)` — the resulting row has `agent_id="B"`
    /// but `brief` and task_vec still carry A's content. The read path
    /// filters task rows by `agent_id` (recall.rs, unified_search.rs) so
    /// agent B's recall now returns a task hit carrying A's data. Within
    /// PRD §11.3.3's "tasks span agents" trust model this is by design,
    /// but callers wanting to clear sensitive prior-author content MUST
    /// pass `Some("")` (or appropriate zero-Some) — NOT `None` — for each
    /// optional field. The cap-memory rusqlite adapter (deferred) must
    /// document this contract for its `upsert_task` callers.
    ///
    /// `title` is required (`NOT NULL`) and ALWAYS-OVERWRITES on conflict.
    /// `brief` / `status` / `last_turn_at` / `turns_total` preserve via
    /// `COALESCE` on UPDATE (`None` keeps existing). `last_turn_at` is RFC
    /// 3339 string; parse-checked at pre-flight.
    ///
    /// `embedding=None` leaves task_vec untouched. `Some` is validated
    /// (dim + finite-ness) BEFORE any SQL. Primary table's `embedding BLOB`
    /// column stays NULL — embeddings live in `task_vec` only.
    ///
    /// `updated_at` is always-overwrite (every successful call refreshes it).
    ///
    /// `agent_id` MUST be non-empty / not whitespace-only. `agent_id` /
    /// `task_id` MUST NOT contain `\u{1F}`.
    fn upsert_task_index(
        &self,
        agent_id: &str,
        task_id: &str,
        title: &str,
        brief: Option<&str>,
        status: Option<&str>,
        last_turn_at: Option<&str>,
        turns_total: Option<i64>,
        embedding: Option<&[f32]>,
    ) -> Result<(), DbError>;

    /// Upsert a turn_index row + matching turn_vec row.
    ///
    /// `id` is `"{agent_id}\u{1F}{task_id}\u{1F}turn-{turn}"` —
    /// 3-component agent-prefixed (matches cap-memory `SqliteIndex`
    /// `(agent_id, task_id, turn)` seam key). This format also flows
    /// through `rebuild.rs::scan_turn_index_yaml`. Cross-agent isolation
    /// is structural — distinct `agent_id` values produce distinct ids.
    ///
    /// `timestamp` and `digest` are required (`NOT NULL`). `timestamp` is
    /// RFC 3339 string; parse-checked at pre-flight. `digest` MUST be
    /// non-empty (Slice H adversarial R1 W3 closure — aligns with the
    /// rebuild scanner's `scan_turn_index_yaml` empty-digest rejection).
    /// `turn` MUST be non-zero (Slice H adversarial R1 W2 closure —
    /// aligns with `scan_turn_index_yaml` turn-zero rejection).
    ///
    /// `reference_count` is PRESERVED ON CONFLICT per M011 §3.6 hard
    /// requirement: INSERT binds `0`; the UPDATE clause OMITS the column
    /// (and OMITS `agent_id` / `task_id` / `turn` which are pinned by the
    /// id PK). Callers wanting to increment reference_count MUST use
    /// [`bump_turn_reference`].
    ///
    /// `embedding=None` leaves turn_vec untouched. `Some` is validated
    /// (dim + finite-ness) BEFORE any SQL.
    ///
    /// Note: cap-memory's `TurnIndexRow.updated_at` field has no
    /// destination column on M004 `turn_index` (the table lacks
    /// `updated_at`, unlike content/meta/memory/task indexes). The
    /// cap-memory rusqlite adapter MUST drop this field on the M004 call.
    ///
    /// `agent_id` MUST be non-empty / not whitespace-only. `agent_id` /
    /// `task_id` MUST NOT contain `\u{1F}`.
    #[allow(clippy::too_many_arguments)]
    fn upsert_turn_index(
        &self,
        agent_id: &str,
        task_id: &str,
        turn: u32,
        timestamp: &str,
        digest: &str,
        importance: Option<&str>,
        has_user_instruction: Option<bool>,
        has_user_correction: Option<bool>,
        has_tool_use: Option<bool>,
        has_decision: Option<bool>,
        embedding: Option<&[f32]>,
        tokens_digest: Option<i64>,
        tokens_l0_processed: Option<i64>,
    ) -> Result<(), DbError>;

    /// Atomically increment `reference_count` on the turn_index row with
    /// id `"{agent_id}\u{1F}{task_id}\u{1F}turn-{turn}"`. Single SQL
    /// UPDATE — SQLite's per-statement auto-commit handles concurrent
    /// callers race-free without an explicit Immediate-tx wrapper (avoids
    /// two extra round-trips on the post-processor hot path).
    ///
    /// Returns `Ok(true)` if a row was bumped, `Ok(false)` if no matching
    /// row exists (idempotent missing-row — matches `delete_*_index_row`).
    ///
    /// Does NOT touch `embedding` (AC-31 invariant: "embedding is NOT
    /// re-computed on reference_count bump" per PRD §8.4) or
    /// `last_accessed` (runtime stat owned by the recall read path).
    ///
    /// Agent isolation is structural via the 3-component id PK.
    ///
    /// `agent_id` MUST be non-empty / not whitespace-only. `agent_id` /
    /// `task_id` MUST NOT contain `\u{1F}`.
    fn bump_turn_reference(
        &self,
        agent_id: &str,
        task_id: &str,
        turn: u32,
    ) -> Result<bool, DbError>;
}

#[derive(Debug)]
struct PragmaCustomizer {
    /// Slice G: snapshotted at pool-build time from `Tunables::wal_mode`.
    /// `true` → `PRAGMA journal_mode = WAL`; `false` → `PRAGMA journal_mode = MEMORY`.
    /// The PragmaCustomizer is per-pool, NOT per-checkout — flipping
    /// `wal_mode` via hot-reload is snapshot-observable in `host.config()`
    /// but does not re-pragma live connections. Documented honestly in
    /// MODULE-001 §2.10 + MODULE-004 §2.10.
    wal_mode: bool,
}

impl PragmaCustomizer {
    fn new(wal_mode: bool) -> Self {
        Self { wal_mode }
    }
}

impl r2d2::CustomizeConnection<Connection, rusqlite::Error> for PragmaCustomizer {
    fn on_acquire(&self, conn: &mut Connection) -> Result<(), rusqlite::Error> {
        // PRAGMA journal_mode is database-level + persistent in the file
        // header; re-issuing it on every acquire is a no-op for established
        // WAL databases. For `:memory:` connections (the `new_in_memory()`
        // test path), SQLite silently rejects WAL and stays in `memory` mode
        // without raising an error — production crash-recovery semantics do
        // NOT apply to in-memory tests, but capability tests (T20) still pass
        // because vec0 + FTS5 work regardless of journal_mode.
        // PRAGMA synchronous = NORMAL + busy_timeout = 5000 are per-connection.
        // PRAGMA case_sensitive_like = 1: round-13 (adversarial, slice F)
        // finding — SQLite's default LIKE is ASCII-case-insensitive, which
        // would let descent SQL (`c.file_path LIKE 'dir/%' ESCAPE '\'`) leak
        // across case-distinct sibling directories on case-sensitive
        // filesystems (Linux). Setting case-sensitive globally is safe for
        // this crate: schema.rs's startup migration LIKE check already uses
        // `LOWER(...)` on both data and pattern, and descent is the only
        // production LIKE callsite. Per-connection PRAGMA (set on every
        // acquire) — same lifetime semantics as PRAGMA synchronous /
        // busy_timeout below.
        let journal_mode = if self.wal_mode { "WAL" } else { "MEMORY" };
        let pragmas = format!(
            "PRAGMA journal_mode = {journal_mode}; \
             PRAGMA synchronous = NORMAL; \
             PRAGMA busy_timeout = 5000; \
             PRAGMA case_sensitive_like = 1;"
        );
        conn.execute_batch(&pragmas)?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct R2d2SqliteIndexHandle {
    pool: Arc<Pool<SqliteConnectionManager>>,
    /// Slice G: live tunables provider. Per-call reads via
    /// `self.tunables.current()` give consumer paths (validate_embedding,
    /// recall_blocking, descend_into_dirs, embed_or_skip) access to the
    /// current snapshot. Plain `Arc<dyn>` (no Mutex) preserves the
    /// `#[derive(Clone)]` above; per the read-through-snapshot design,
    /// the inner provider itself reads through to the watcher's
    /// `RwLock<Arc<RuntimeConfig>>`.
    tunables: Arc<dyn TunablesProvider>,
}

impl std::fmt::Debug for R2d2SqliteIndexHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("R2d2SqliteIndexHandle")
            .field("tunables", &self.tunables.current())
            .finish_non_exhaustive()
    }
}

impl R2d2SqliteIndexHandle {
    /// Construct a file-backed handle with default tunables. `db_path` MUST be
    /// a real filesystem path — passing `Path::new(":memory:")` or any other
    /// SQLite URI here builds a connection-per-pool-slot **file** literally
    /// named `:memory:`, NOT a memory database. For in-memory operation, use
    /// `new_in_memory()`. For production wiring with a live config snapshot,
    /// use `with_tunables(...)`.
    pub fn new(db_path: &Path, pool_size: u32) -> Result<Self, DbError> {
        Self::with_tunables(db_path, pool_size, default_tunables_provider())
    }

    /// Slice G: construct a handle threading a live `TunablesProvider`.
    /// `wal_mode` is read ONCE at pool build and snapshotted into
    /// `PragmaCustomizer`; subsequent hot-reloads of `wal_mode` are
    /// snapshot-observable but do not re-pragma live connections. The
    /// `embedding_dim` snapshot is read per-call via `self.tunables.current()`
    /// inside upsert validation, so dim hot-reloads are behaviorally enforced.
    pub fn with_tunables(
        db_path: &Path,
        pool_size: u32,
        tunables: Arc<dyn TunablesProvider>,
    ) -> Result<Self, DbError> {
        if pool_size == 0 {
            return Err(DbError::InvalidConfig(
                "pool_size must be at least 1".to_string(),
            ));
        }
        if db_path == Path::new(":memory:") {
            return Err(DbError::InvalidConfig(
                "db_path == \":memory:\" — call R2d2SqliteIndexHandle::new_in_memory() \
                 instead; SqliteConnectionManager::file(\":memory:\") creates a literal \
                 file with that name, not a memory database"
                    .to_string(),
            ));
        }
        register_sqlite_vec_extension()?;
        // Explicitly DISABLE SQLITE_OPEN_URI so caller-supplied path inputs cannot
        // be reinterpreted as SQLite URI strings (e.g. `file::memory:?cache=shared`,
        // `file:/tmp/x?mode=memory` — both would otherwise bypass the file-storage
        // assumption of `new()`). rusqlite's default flag set is
        // SQLITE_OPEN_READ_WRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NO_MUTEX |
        // SQLITE_OPEN_URI; we strip the URI bit only, preserving the rest.
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let initial_wal_mode = tunables.current().wal_mode;
        let manager = SqliteConnectionManager::file(db_path).with_flags(flags);
        let pool = Pool::builder()
            .max_size(pool_size)
            .connection_customizer(Box::new(PragmaCustomizer::new(initial_wal_mode)))
            .build(manager)?;
        let handle = Self {
            pool: Arc::new(pool),
            tunables,
        };
        handle.run_migrations()?;
        Ok(handle)
    }

    pub fn new_in_memory() -> Result<Self, DbError> {
        let tunables = default_tunables_provider();
        register_sqlite_vec_extension()?;
        let initial_wal_mode = tunables.current().wal_mode;
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::builder()
            .max_size(1)
            .connection_customizer(Box::new(PragmaCustomizer::new(initial_wal_mode)))
            .build(manager)?;
        let handle = Self {
            pool: Arc::new(pool),
            tunables,
        };
        handle.run_migrations()?;
        Ok(handle)
    }

    /// Slice G helper: returns the live `Tunables` snapshot via the held
    /// provider. Used by the upsert paths (validate_embedding) and by
    /// `R2d2RecallImpl` consumers that need to plumb the dim through.
    pub fn current_tunables(&self) -> crate::Tunables {
        self.tunables.current()
    }
}

impl SqliteIndexHandle for R2d2SqliteIndexHandle {
    fn get_conn(&self) -> Result<PooledConnection, DbError> {
        self.pool.get().map_err(DbError::from)
    }

    fn schema_version(&self) -> u32 {
        SCHEMA_VERSION
    }

    fn run_migrations(&self) -> Result<(), DbError> {
        let mut conn = self.get_conn()?;
        apply_migrations(&mut conn)?;
        Ok(())
    }

    fn upsert_content_index(
        &self,
        agent_id: &str,
        file_path: &str,
        preview: &str,
        embedding: Option<&[f32]>,
        last_modified: Option<&str>,
    ) -> Result<(), DbError> {
        validate_agent_id_nonempty(agent_id)?;
        validate_id_component("agent_id", agent_id)?;
        validate_id_component("file_path", file_path)?;
        validate_last_modified(last_modified)?;
        if let Some(e) = embedding {
            validate_embedding(e, self.current_tunables().embedding_dim)?;
        }
        let id = content_row_id(agent_id, file_path);
        let mut conn = self.get_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = now_text();

        // INSERT ... ON CONFLICT(id) DO UPDATE preserves rowid across updates
        // (SQLite UPSERT contract for ≥ 3.24). On INSERT with last_modified=None
        // the bound NULL goes straight in. On UPDATE, COALESCE preserves the
        // existing value when the caller passes None — the "preview-only
        // refresh" case where the disk mtime hasn't changed.
        tx.execute(
            "INSERT INTO content_index(id, agent_id, file_path, content_preview, last_modified, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT(id) DO UPDATE SET \
               content_preview = excluded.content_preview, \
               last_modified = COALESCE(excluded.last_modified, content_index.last_modified), \
               updated_at = excluded.updated_at",
            params![id, agent_id, file_path, preview, last_modified, now],
        )?;

        let rowid: i64 = tx.query_row(
            "SELECT rowid FROM content_index WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )?;

        // FTS5 has no ON CONFLICT; DELETE+INSERT with bound rowid replaces
        // atomically within the open transaction. content_fts.tags is unused
        // (tags live on meta_index); keep empty for forward compat.
        tx.execute("DELETE FROM content_fts WHERE rowid = ?1", params![rowid])?;
        tx.execute(
            "INSERT INTO content_fts(rowid, file_path, content_preview, tags) VALUES (?1, ?2, ?3, ?4)",
            params![rowid, file_path, preview, ""],
        )?;

        if let Some(emb) = embedding {
            tx.execute("DELETE FROM content_vec WHERE rowid = ?1", params![rowid])?;
            tx.execute(
                "INSERT INTO content_vec(rowid, embedding) VALUES (?1, ?2)",
                params![rowid, embedding_to_blob(emb)],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    fn upsert_meta_index(
        &self,
        agent_id: &str,
        directory: &str,
        entry_name: &str,
        description: Option<&str>,
        tags: Option<&str>,
        embedding: Option<&[f32]>,
    ) -> Result<(), DbError> {
        validate_agent_id_nonempty(agent_id)?;
        validate_id_component("agent_id", agent_id)?;
        validate_id_component("directory", directory)?;
        validate_id_component("entry_name", entry_name)?;
        if let Some(e) = embedding {
            validate_embedding(e, self.current_tunables().embedding_dim)?;
        }
        let id = meta_row_id(agent_id, directory, entry_name);
        let mut conn = self.get_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = now_text();

        // `embedding BLOB` column on meta_index is always NULL — embeddings live
        // in meta_vec only. Omitting the column from the INSERT list lets it
        // default to NULL (no DEFAULT clause in schema.rs:25).
        tx.execute(
            "INSERT INTO meta_index(id, agent_id, directory, entry_name, description, tags, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
             ON CONFLICT(id) DO UPDATE SET \
               description = excluded.description, \
               tags = excluded.tags, \
               updated_at = excluded.updated_at",
            params![id, agent_id, directory, entry_name, description, tags, now],
        )?;

        let rowid: i64 = tx.query_row(
            "SELECT rowid FROM meta_index WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )?;

        if let Some(emb) = embedding {
            tx.execute("DELETE FROM meta_vec WHERE rowid = ?1", params![rowid])?;
            tx.execute(
                "INSERT INTO meta_vec(rowid, embedding) VALUES (?1, ?2)",
                params![rowid, embedding_to_blob(emb)],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    fn delete_content_index_row(&self, agent_id: &str, file_path: &str) -> Result<(), DbError> {
        validate_agent_id_nonempty(agent_id)?;
        validate_id_component("agent_id", agent_id)?;
        validate_id_component("file_path", file_path)?;
        let id = content_row_id(agent_id, file_path);
        let mut conn = self.get_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let rowid_opt: Option<i64> = tx
            .query_row(
                "SELECT rowid FROM content_index WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?;

        if let Some(rowid) = rowid_opt {
            tx.execute("DELETE FROM content_vec WHERE rowid = ?1", params![rowid])?;
            tx.execute("DELETE FROM content_fts WHERE rowid = ?1", params![rowid])?;
            tx.execute("DELETE FROM content_index WHERE rowid = ?1", params![rowid])?;
        }

        tx.commit()?;
        Ok(())
    }

    fn delete_meta_index_row(
        &self,
        agent_id: &str,
        directory: &str,
        entry_name: &str,
    ) -> Result<(), DbError> {
        validate_agent_id_nonempty(agent_id)?;
        validate_id_component("agent_id", agent_id)?;
        validate_id_component("directory", directory)?;
        validate_id_component("entry_name", entry_name)?;
        let id = meta_row_id(agent_id, directory, entry_name);
        let mut conn = self.get_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let rowid_opt: Option<i64> = tx
            .query_row(
                "SELECT rowid FROM meta_index WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?;

        if let Some(rowid) = rowid_opt {
            tx.execute("DELETE FROM meta_vec WHERE rowid = ?1", params![rowid])?;
            tx.execute("DELETE FROM meta_index WHERE rowid = ?1", params![rowid])?;
        }

        tx.commit()?;
        Ok(())
    }

    fn upsert_task_index(
        &self,
        agent_id: &str,
        task_id: &str,
        title: &str,
        brief: Option<&str>,
        status: Option<&str>,
        last_turn_at: Option<&str>,
        turns_total: Option<i64>,
        embedding: Option<&[f32]>,
    ) -> Result<(), DbError> {
        validate_id_nonempty("agent_id", agent_id)?;
        validate_id_nonempty("task_id", task_id)?;
        validate_id_component("agent_id", agent_id)?;
        validate_id_component("task_id", task_id)?;
        validate_last_modified(last_turn_at)?;
        if let Some(e) = embedding {
            validate_embedding(e, self.current_tunables().embedding_dim)?;
        }
        let mut conn = self.get_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = now_text();

        // task_id is the single-column PK (PRD §11.3.3 "tasks span agents").
        // Cross-agent calls overwrite agent_id + title; optional fields use
        // COALESCE to preserve existing on None. updated_at always refreshes.
        tx.execute(
            "INSERT INTO task_index(task_id, agent_id, title, brief, status, \
                                     last_turn_at, turns_total, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
             ON CONFLICT(task_id) DO UPDATE SET \
               agent_id = excluded.agent_id, \
               title = excluded.title, \
               brief = COALESCE(excluded.brief, task_index.brief), \
               status = COALESCE(excluded.status, task_index.status), \
               last_turn_at = COALESCE(excluded.last_turn_at, task_index.last_turn_at), \
               turns_total = COALESCE(excluded.turns_total, task_index.turns_total), \
               updated_at = excluded.updated_at",
            params![
                task_id,
                agent_id,
                title,
                brief,
                status,
                last_turn_at,
                turns_total,
                now
            ],
        )?;

        let rowid: i64 = tx.query_row(
            "SELECT rowid FROM task_index WHERE task_id = ?1",
            params![task_id],
            |r| r.get(0),
        )?;

        if let Some(emb) = embedding {
            tx.execute("DELETE FROM task_vec WHERE rowid = ?1", params![rowid])?;
            tx.execute(
                "INSERT INTO task_vec(rowid, embedding) VALUES (?1, ?2)",
                params![rowid, embedding_to_blob(emb)],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    fn upsert_turn_index(
        &self,
        agent_id: &str,
        task_id: &str,
        turn: u32,
        timestamp: &str,
        digest: &str,
        importance: Option<&str>,
        has_user_instruction: Option<bool>,
        has_user_correction: Option<bool>,
        has_tool_use: Option<bool>,
        has_decision: Option<bool>,
        embedding: Option<&[f32]>,
        tokens_digest: Option<i64>,
        tokens_l0_processed: Option<i64>,
    ) -> Result<(), DbError> {
        validate_id_nonempty("agent_id", agent_id)?;
        validate_id_nonempty("task_id", task_id)?;
        validate_id_component("agent_id", agent_id)?;
        validate_id_component("task_id", task_id)?;
        // Slice H adversarial R1 W2 closure: align with scan_turn_index_yaml's
        // `entry.turn == 0` rejection so the incremental write surface cannot
        // produce rows the next startup rebuild would silently drop.
        if turn == 0 {
            return Err(DbError::InvalidConfig("turn must be non-zero".to_string()));
        }
        // Slice H adversarial R1 W3 closure: align with scan_turn_index_yaml's
        // empty-digest rejection.
        if digest.is_empty() {
            return Err(DbError::InvalidConfig(
                "digest must be non-empty".to_string(),
            ));
        }
        // timestamp is required (schema NOT NULL); inline RFC 3339 parse-check
        // with the right field label.
        chrono::DateTime::parse_from_rfc3339(timestamp)
            .map_err(|e| DbError::InvalidConfig(format!("timestamp must be RFC 3339: {e}")))?;
        if let Some(e) = embedding {
            validate_embedding(e, self.current_tunables().embedding_dim)?;
        }
        let id = format!("{agent_id}{ID_SEPARATOR}{task_id}{ID_SEPARATOR}turn-{turn}");
        let mut conn = self.get_conn()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        // reference_count: bind 0 on INSERT, OMIT on UPDATE (M011 §3.6
        // hard requirement — only bump_turn_reference mutates the counter).
        // agent_id / task_id / turn also OMITTED from UPDATE — pinned by
        // the 3-component id PK.
        tx.execute(
            "INSERT INTO turn_index(id, agent_id, task_id, turn, timestamp, digest, \
                                     importance, reference_count, has_user_instruction, \
                                     has_user_correction, has_tool_use, has_decision, \
                                     tokens_digest, tokens_l0_processed) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, ?9, ?10, ?11, ?12, ?13) \
             ON CONFLICT(id) DO UPDATE SET \
               timestamp = excluded.timestamp, \
               digest = excluded.digest, \
               importance = COALESCE(excluded.importance, turn_index.importance), \
               has_user_instruction = COALESCE(excluded.has_user_instruction, turn_index.has_user_instruction), \
               has_user_correction = COALESCE(excluded.has_user_correction, turn_index.has_user_correction), \
               has_tool_use = COALESCE(excluded.has_tool_use, turn_index.has_tool_use), \
               has_decision = COALESCE(excluded.has_decision, turn_index.has_decision), \
               tokens_digest = COALESCE(excluded.tokens_digest, turn_index.tokens_digest), \
               tokens_l0_processed = COALESCE(excluded.tokens_l0_processed, turn_index.tokens_l0_processed)",
            params![
                id, agent_id, task_id, turn as i64, timestamp, digest, importance,
                has_user_instruction, has_user_correction, has_tool_use, has_decision,
                tokens_digest, tokens_l0_processed
            ],
        )?;

        let rowid: i64 = tx.query_row(
            "SELECT rowid FROM turn_index WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )?;

        if let Some(emb) = embedding {
            tx.execute("DELETE FROM turn_vec WHERE rowid = ?1", params![rowid])?;
            tx.execute(
                "INSERT INTO turn_vec(rowid, embedding) VALUES (?1, ?2)",
                params![rowid, embedding_to_blob(emb)],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    fn bump_turn_reference(
        &self,
        agent_id: &str,
        task_id: &str,
        turn: u32,
    ) -> Result<bool, DbError> {
        validate_id_nonempty("agent_id", agent_id)?;
        validate_id_nonempty("task_id", task_id)?;
        validate_id_component("agent_id", agent_id)?;
        validate_id_component("task_id", task_id)?;
        let id = format!("{agent_id}{ID_SEPARATOR}{task_id}{ID_SEPARATOR}turn-{turn}");
        let conn = self.get_conn()?;
        // Single-statement atomic UPDATE. SQLite's per-statement auto-commit
        // + 5000ms busy_timeout handle concurrent callers race-free without
        // an explicit Immediate-tx wrapper. Agent isolation is structural
        // via the 3-component id PK.
        let changed = conn.execute(
            "UPDATE turn_index SET reference_count = reference_count + 1 WHERE id = ?1",
            params![id],
        )?;
        Ok(changed > 0)
    }
}

//! 9-step post-processor pipeline implementing CONTRACT-103
//! `PostProcessorHook` from `advance-shared-types`. MODULE-011 §1.3.5.
//!
//! Slice B wires the `Components` bundle (extractor / reconciler / store /
//! cooldown / clock) into Step 2 (cooldown-gated `BatchExtractor` call with
//! mechanical-digest fallback) and Step 5 (`Reconciler::reconcile` →
//! `MemoryStore::apply_action`). `PostProcessor::new()` keeps slice A's
//! trace-only default (`components: None`) so the canonical-9-step trace
//! contract holds for both slice A baseline tests and slice B new tests.
//!
//! Real `.meta.yaml` write-back (Step 3), file-dedup via SQLite (Step 4),
//! persistent jsonl append (Step 6), summary.yaml + turn-index.yaml on-disk
//! write (Step 7), SQLite index upserts (Step 8), and L6 hot-path evaluation
//! (Step 9) are `waived_scope` for slice B and remain trace-only stubs.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use advance_runtime::host_registry::HostRegistry;
use advance_shared_types::mailbox::{ActionResult, Message};
use advance_shared_types::memory::{PostProcessorError, PostProcessorHook};
use advance_shared_types::token_estimate::tokens_from_bytes_u32;
use advance_shared_types::traits::EventBusEmit;
use advance_shared_types::turn_log::{TurnTranscriptSource, TURN_LOG_FILENAME};
use async_trait::async_trait;
use uuid::Uuid;

use std::time::Duration;

use crate::clock::Clock;
use crate::cooldown::FailureCooldown;
use crate::embedder::{Embedder, EmbedderError, StubEmbedder};
use crate::embedding_upkeep::{
    EmbeddingUpkeep, Standing, VectorRow, CATCH_UP_TIME, VECTORS_PER_TURN_END,
};
use crate::extractor::{
    BatchExtractor, BatchExtractorError, DescriptionUpdate, Extraction, ExtractionContext,
};
use crate::knowledge::{MemoryEntry, MemorySource, MemoryStatus, MemoryType};
use crate::l6::cursor::L6CursorStore;
use crate::l6::emit::L6Emitter;
use crate::l6::lease::{LeaseDecision, LeaseStore};
use crate::l6::trigger::{L6TriggerEvaluator, L6TriggerState};
use crate::reconcile::{MemoryAction, Reconciler, SimilarityIndex};
use crate::sqlite_index::{
    InMemorySqliteIndex, IndexUnavailable, MemoryIndexRow, SqliteIndex, TaskIndexRow, TurnIndexRow,
    RECENT_TURN_WINDOW,
};
use crate::store::MemoryStore;
use crate::summary::{Summary, SummaryMeta};
use crate::task_storage::{TASK_SUMMARY_FILENAME, TASK_TURN_INDEX_FILENAME};
use crate::turn_index::{
    apply_turn_digest, GitAssociation, Importance, LogOffset, TurnEntry, TurnIndex, TurnIndexMeta,
};
use crate::turn_log::{
    append_turn_log_known, bump_references, fill_turn_features, prompt_from_payload, KnownLogs,
    LoggedTurn, FAILED_TURN_NOTE,
};

/// 9 canonical step labels — verbatim from MODULE-011 §1.3.5.
const STEP_1: &str = "Step 1: Collect changes";
const STEP_2: &str = "Step 2: Batch LLM call (or fallback)";
const STEP_3: &str = "Step 3: Write-back descriptions (update .meta.yaml)";
const STEP_4: &str = "Step 4: File dedup check";
const STEP_5: &str = "Step 5: Memory reconciliation";
const STEP_6: &str = "Step 6: Write knowledge.jsonl";
const STEP_7: &str = "Step 7: Update summary.yaml + turn-index.yaml";
const STEP_8: &str = "Step 8: Update SQLite indexes";
const STEP_9: &str = "Step 9: Evaluate L6 conditions";

pub const CANONICAL_STEPS: [&str; 9] = [
    STEP_1, STEP_2, STEP_3, STEP_4, STEP_5, STEP_6, STEP_7, STEP_8, STEP_9,
];

/// SAT-D Step-3 DoS bound: max changed-file descriptions indexed per turn. The
/// `ex.descriptions` vector is LLM-produced; each entry drives a file read + an
/// LLM/VLM round-trip + a `.meta.yaml` write, so the per-turn fan-out is capped
/// defensively. Matches the cli `EXTRACTION_SCHEMA` `maxItems` (64) bound.
pub const MAX_INDEXED_DESCRIPTIONS_PER_TURN: usize = 64;

/// Slice satC-l6 (SAT-C) — in-process L6 dispatch seam. After Step-9 emits
/// `memory.l6_consolidation_due` (lease `Acquired`), the post-processor invokes
/// this to run the L6 consolidation runnable on the LIVE turn — a DIRECT
/// in-process call, because the MODULE-019 EventBus exposes no public native
/// `subscribe`/receiver API, so L6 cannot be started by subscribing to the
/// trigger event. The concrete impl lives at the cli composition root
/// (`L6DispatchAdapter`), which owns the `L6Runnable` + the `component.error`
/// emit-on-failure (kept OUT of cap-memory so cap-memory keeps NO dependency on
/// `advance-scheduler`, which owns `emit_component_error`). `Components.l6_handler
/// == None` preserves the pre-SAT-C behaviour (Step-9 emits `consolidation_due`
/// only, no dispatch). Returns `true` iff the consolidation completed
/// successfully — Step-9 calls `mark_l6_ran` only on `true`, leaving a failed
/// run to retry on the next trigger (SYS-AC-216 shape). See §3.8 note 19.
#[async_trait]
pub trait L6Dispatch: Send + Sync {
    async fn dispatch(&self, agent_id: &str, lease_token: &str) -> bool;
}

/// One indexed file description produced by [`DescriptionIndexer`]: the
/// NORMALIZED workspace-relative path the impl actually resolved (so the
/// caller's `FileRef.vpath` + idempotency key are alias-stable — `./a.png`,
/// `a.png`, `dir//a.png` collapse to one key) plus the produced description.
#[derive(Clone, Debug)]
pub struct IndexedDescription {
    pub vpath: String,
    pub description: String,
}

/// SAT-D: Step-3 per-changed-file description-indexing seam. cap-memory has
/// ZERO cap-llm/cap-fs dep, so the impl lives at the cli composition root
/// (`VlmDescriptionIndexer`). Given a changed file's (raw, possibly aliased,
/// LLM-produced/UNTRUSTED) path, the impl confines+normalizes it, resolves
/// bytes+MIME, routes by MIME — text→LLM (CONTRACT-081 `chat`),
/// image/pdf→VLM (CONTRACT-082 `extract_description`), binary/unknown→no-index
/// — writes the description back to the file's `.meta.yaml` (CONTRACT-010/012
/// `MetaMaintainer::update_entry_meta`), and returns the normalized vpath +
/// description. `None` ⇒ rejected/private/hidden path, binary/unknown MIME,
/// empty output, or a soft failure (NEVER fatal to the turn). `Components.
/// description_indexer == None` keeps Step-3 a documented no-op (pre-SAT-D
/// behaviour, preserving the 9-step trace + the AC-44 trace-only guard).
#[async_trait]
pub trait DescriptionIndexer: Send + Sync {
    async fn index_description(&self, agent_id: &str, path: &str) -> Option<IndexedDescription>;
}

/// Cross-collaborator wiring bundle. The `store` field is shared by reference
/// between this PostProcessor (writes via Step 5) and the `agent-memory` WIT
/// host handlers (reads via `recall`/`recall-at`; writes via `remember`/
/// `forget`/`rollback-memory`). Production wiring is responsible for
/// constructing one `Components` bundle and passing the SAME
/// `Arc<MemoryStore>` to BOTH `PostProcessor::with_components` and
/// `Components::register_agent_memory` — the convenience method below
/// enforces this by construction.
///
/// **Send + Sync auto-trait note**: Rust does NOT propagate `Send + Sync` from
/// a trait's super-bounds onto a `dyn Trait` use-site; every `dyn Trait` field
/// below MUST spell `+ Send + Sync` explicitly. `Arc<dyn PostProcessorHook>`
/// in the scheduler wiring requires the entire field chain to be `Send + Sync`.
///
/// **Clone but NOT Default**: `Arc<dyn Trait>` is Clone (via Arc's blanket
/// Clone impl), so `derive(Clone)` works. `Default` is NOT derivable because
/// `Arc<dyn BatchExtractor + Send + Sync>` has no `Default`. `Debug` is also
/// manually impl'd, redacting trait-object fields (mirrors L6RunnableSpec).
#[derive(Clone)]
pub struct Components {
    pub extractor: Arc<dyn BatchExtractor + Send + Sync>,
    pub reconciler: Arc<Reconciler<dyn SimilarityIndex + Send + Sync>>,
    pub store: Arc<MemoryStore>,
    pub cooldown: Arc<FailureCooldown>,
    pub clock: Arc<dyn Clock + Send + Sync>,
    // ── Slice C: L6 Step 9 wiring ──
    pub trigger: Arc<L6TriggerEvaluator>,
    pub lease: Arc<dyn LeaseStore + Send + Sync>,
    pub l6_emitter: Arc<dyn L6Emitter + Send + Sync>,
    pub l6_trigger_state: Arc<Mutex<L6TriggerState>>,
    // ── Slice D: MODULE-019 EventBus (CONTRACT-180, consumed) for the
    // agent-memory WIT handlers' `memory.*` emission (Seam A). Spelled
    // `+ Send + Sync` to match the in-file `dyn Trait` convention. ──
    pub event_bus: Arc<dyn EventBusEmit + Send + Sync>,
    // ── Slice F: SQLite-index + Embedder seams (cap-memory-internal; NOT in
    // shared-types / NOT in ARCHITECTURE §6.1). Drives 4 public `sync_*` /
    // `bump_turn_reference` methods. Slice satB-postproc calls the `sync_*`
    // methods from `PostProcessor::run` Step 8 (when a tasks root is configured);
    // tests also drive these seams directly. See MODULE-011 §3.6 / §3.8 note 12. ──
    pub sqlite_index: Arc<dyn SqliteIndex + Send + Sync>,
    pub embedder: Arc<dyn Embedder + Send + Sync>,
    // ── The pacing of vector catch-up (embedding again a text that did not
    // change): rests after a failed request or a model change. Process memory;
    // clones of this bundle share it. See `embedding_upkeep`. ──
    pub embedding_upkeep: Arc<EmbeddingUpkeep>,
    // ── Slice G (m011-slice-g): L6 cursor store shared between Step-5a flush
    // (via `L6Runnable.cursor_store`) and WIT `rollback-memory` reset (via
    // `RollbackMemoryHandler.cursor_store`). See AC-18 cap-memory-half closure
    // in §3.8 note 13 + the cursor-store-sharing HARD REQUIREMENT in §3.6. ──
    pub cursor_store: Arc<L6CursorStore>,
    // ── The directory that holds the task directories (PRD §11.2:
    // `<workspace>/.agent/tasks/active`). Step 0 logs the turn to
    // `<tasks_root>/{task_id}/llm-turns.jsonl`; Step 7 writes `summary.yaml` and
    // `turn-index.yaml` beside it. `None` (the default for `with_l6_defaults` /
    // `wired`) keeps Steps 0/7/8 on the trace-only path so the rootless in-memory
    // test suite is unaffected; the composition root sets it via `with_tasks_root`. ──
    pub tasks_root: Option<PathBuf>,
    // ── The agent's workspace root, the root a tool call's `path` is relative
    // to: Step 7 records the git blob id of each file the turn read under it
    // (`read_file_versions`). `None` ⇒ no version is recorded. ──
    pub workspace_root: Option<PathBuf>,
    // ── The host's record of the turn that just ran (the LLM gateway), which
    // Step 0 takes and logs. `None` ⇒ the log holds the inbound message only. ──
    pub transcript_source: Option<Arc<dyn TurnTranscriptSource>>,
    // ── Slice satB-postproc (SAT-B): the BARE cap id the post-processor writes
    // under (store/index/file ops). `run()` receives the COLON messaging id
    // (`agent:root`) but the shared `MemoryStore`/WIT handlers key the write
    // bucket by the bare cap id (`root`); the two id grammars are
    // incompatible, so the composition root supplies the bare id here. `None`
    // ⇒ writes use the `run()` agent_id verbatim (preserves every existing test). ──
    pub write_agent_id: Option<String>,
    // ── Slice satC-l6 (SAT-C): optional in-process L6 dispatch handler invoked
    // at Step-9 (after emit_consolidation_due). `None` ⇒ pre-SAT-C behaviour
    // (emit only). The cli composition root sets it via `with_l6_handler`. See
    // the `L6Dispatch` trait doc above + §3.8 note 19. ──
    pub l6_handler: Option<Arc<dyn L6Dispatch>>,
    // ── Slice satD-vlm (SAT-D): optional Step-3 VLM/LLM description-indexing
    // seam. `None` ⇒ Step-3 stays a documented no-op (pre-SAT-D behaviour). The
    // cli composition root sets it via `with_description_indexer`. BARE `dyn`
    // (no explicit `+ Send + Sync`): `DescriptionIndexer: Send + Sync` supertrait
    // makes the use-site `Send+Sync`, exactly like `l6_handler` above. See the
    // `DescriptionIndexer` trait doc + §3.8 note 20. ──
    pub description_indexer: Option<Arc<dyn DescriptionIndexer>>,
}

impl std::fmt::Debug for Components {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // All fields are redacted via placeholder strings to avoid PII /
        // bearer-secret / internal-state leakage on `format!("{c:?}")` /
        // `tracing::debug!(c)` / panic-message paths. Mirrors the slice-D
        // round-16/17 defensive-Debug pattern (the `L6CompletedPayload`
        // manual Debug redaction at l6/emit.rs) — extended by slice-F
        // adversarial round 2 to cover the pre-existing struct fields
        // (`store`, `cooldown`, `trigger`, `l6_trigger_state`) whose
        // derived/default Debug would have surfaced internal state.
        // Defense-in-depth scoping note (adversarial round 4 correction):
        // `MemoryStore`'s own manual `Debug` (store.rs:615) currently emits
        // only per-agent entry counts (NOT `MemoryEntry.content`), so the
        // immediate PII surface on `store` was already contained at the
        // owner-type layer — this redaction is the second gate against a
        // future regression of `MemoryStore::Debug` reintroducing the
        // per-entry detail.
        f.debug_struct("Components")
            .field("extractor", &"<BatchExtractor>")
            .field("reconciler", &"<Reconciler>")
            .field("store", &"<MemoryStore>")
            .field("cooldown", &"<FailureCooldown>")
            .field("clock", &"<Clock>")
            .field("trigger", &"<L6TriggerEvaluator>")
            .field("lease", &"<LeaseStore>")
            .field("l6_emitter", &"<L6Emitter>")
            .field("l6_trigger_state", &"<L6TriggerState>")
            .field("event_bus", &"<EventBusEmit>")
            .field("sqlite_index", &"<SqliteIndex>")
            .field("embedder", &"<Embedder>")
            .field("embedding_upkeep", &"<EmbeddingUpkeep>")
            .field("cursor_store", &"<L6CursorStore>")
            .field("tasks_root", &self.tasks_root)
            .field("workspace_root", &self.workspace_root)
            .field(
                "transcript_source",
                &self
                    .transcript_source
                    .as_ref()
                    .map(|_| "<TurnTranscriptSource>"),
            )
            .field("write_agent_id", &"<redacted>")
            .field(
                "l6_handler",
                &self.l6_handler.as_ref().map(|_| "<L6Dispatch>"),
            )
            .field(
                "description_indexer",
                &self
                    .description_indexer
                    .as_ref()
                    .map(|_| "<DescriptionIndexer>"),
            )
            .finish()
    }
}

impl Components {
    /// Convenience: register the 5 `agent-memory` WIT host handlers against
    /// `registry`, using `self.store` as the shared backing store. Eliminates
    /// the "documentary contract" risk that the WIT-side store and the
    /// post-processor store could be wired to different Arc instances.
    pub fn register_agent_memory(&self, registry: &dyn HostRegistry) {
        crate::host_fn::register_agent_memory(
            registry,
            Arc::clone(&self.store),
            Arc::clone(&self.event_bus),
            Arc::clone(&self.cursor_store),
        );
    }

    /// Slice C — construct a `Components` with the 4 L6 fields filled by
    /// throwaway in-memory defaults (`L6TriggerEvaluator::new()`,
    /// `InMemoryLeaseStore`, `InMemoryEmitter`, empty `L6TriggerState`). Lets
    /// Slice B call sites (which used `Components { extractor, reconciler,
    /// store, cooldown, clock }` struct-literal init) construct without the
    /// new fields and with NO observable behavioral change for the Slice B
    /// suite. Note: with the default `L6TriggerState` (`last_l6_at == None`)
    /// Step 9's trigger DOES fire (the `HoursSinceLast` condition treats
    /// "never run" as ∞ elapsed), so `begin_acquire`/`confirm_acquire`/
    /// `emit_consolidation_due` execute — but the three default sinks are
    /// (1) `lease = `[`InMemoryLeaseStore`] (an in-process lease state
    /// machine — `confirm_acquire` succeeds against the just-`begin_acquire`-d
    /// token, no real persistence); (2) `l6_emitter = `[`InMemoryEmitter`]
    /// (Step-9 `emit_consolidation_due` lands in its internal
    /// `Mutex<Vec<...>>`, not on any real bus — the slice-B/C contract reads
    /// L6 emits from this capture); (3) `event_bus = `[`NoopEventBus`] (the
    /// WIT-handler Seam-A bus, which DISCARDS every `memory.*` handler emit —
    /// tests assert nothing on it). The canonical `Step 9` trace label is
    /// pushed BEFORE the trigger check, so the Slice B 9-step trace contract
    /// and every Slice B assertion are preserved. The `lease` + `l6_emitter`
    /// + `event_bus` fields are all `pub` and therefore publicly accessible
    /// (the prior "not exposed to the caller" framing was inaccurate — the
    /// "throwaway" property is the in-process / no-real-bus emit destinations
    /// just enumerated, NOT field privacy).
    ///
    /// # Lease-store sharing (round-17 adversarial-fix cross-reference)
    ///
    /// This constructor shares the same lease-store-sharing HARD REQUIREMENT
    /// as [`Components::wired`]: the deferred cap-memory runtime-assembly
    /// slice (§3.8 note 10) MUST pass `c.lease.clone()` to [`L6Runnable::new`]
    /// (NOT a separately-constructed `LeaseStore`) — Step-9 `confirm_acquire`
    /// (via `c.lease`) and Step-6 `release` (via the runnable's own `lease`)
    /// MUST observe the same lease state, else `L6Error::LeaseLost` on every
    /// run. In current usage `with_l6_defaults` is the Slice-B/C test stub
    /// (NoopEventBus destination), so the footgun is not exploited; it is
    /// disclosed here for parity with [`Components::wired`]'s doc-comment so
    /// a future integrator reaching for `with_l6_defaults` outside a test
    /// gets the same warning. See §3.6 "L6 lease-store sharing" Known-Gap.
    ///
    /// # Cursor-store sharing (slice G; HARD REQUIREMENT)
    ///
    /// Symmetric to the lease-store-sharing requirement above: this constructor
    /// mints a fresh [`L6CursorStore`] and stores it in the public
    /// [`Components::cursor_store`] field, while [`L6Runnable::new`] takes an
    /// independent `cursor_store: Arc<L6CursorStore>` argument. The deferred
    /// cap-memory runtime-assembly slice (§3.8 note 10) MUST pass
    /// `c.cursor_store.clone()` to `L6Runnable::new`'s `cursor_store` argument
    /// — L6 Step-5a's `cursor_store.flush(...)` (called via the runnable's
    /// `cursor_store`) and the WIT `RollbackMemoryHandler::call`'s
    /// `cursor_store.reset_to_epoch(...)` (called via `Components.cursor_store`)
    /// MUST observe **the same cursor state**. Wiring two distinct
    /// `L6CursorStore`s silently breaks the loop: Step-5a flushes store-A's
    /// watermark while `rollback-memory` resets store-B → L6 reads the stale
    /// watermark, never sees the rollback's reset → the next L6 run uses the
    /// old cursor instead of restarting from epoch/0/0 (violates AC-18).
    /// See §3.6 "L6 cursor-store sharing between Components and L6Runnable"
    /// Known-Gap row.
    ///
    /// [`L6CursorStore`]: crate::l6::cursor::L6CursorStore
    ///
    /// [`NoopEventBus`]: crate::events::NoopEventBus
    /// [`InMemoryLeaseStore`]: crate::l6::lease::InMemoryLeaseStore
    /// [`InMemoryEmitter`]: crate::l6::emit::InMemoryEmitter
    /// [`Components::wired`]: Components::wired
    /// [`L6Runnable::new`]: crate::l6::runnable::L6Runnable::new
    pub fn with_l6_defaults(
        extractor: Arc<dyn BatchExtractor + Send + Sync>,
        reconciler: Arc<Reconciler<dyn SimilarityIndex + Send + Sync>>,
        store: Arc<MemoryStore>,
        cooldown: Arc<FailureCooldown>,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> Self {
        Self {
            extractor,
            reconciler,
            store,
            cooldown,
            clock,
            trigger: Arc::new(L6TriggerEvaluator::new()),
            lease: Arc::new(crate::l6::lease::InMemoryLeaseStore::new()),
            l6_emitter: Arc::new(crate::l6::emit::InMemoryEmitter::new()),
            l6_trigger_state: Arc::new(Mutex::new(L6TriggerState::default())),
            // Slice D: no-op default keeps Slice B/C pipeline contracts
            // intact (those tests assert nothing on handler emits, and L6
            // capture goes through the `InMemoryEmitter` above, NOT this bus).
            event_bus: Arc::new(crate::events::NoopEventBus),
            // Slice F: SQLite-index + Embedder seam defaults (in-memory).
            // Signature UNCHANGED — body-only default-injection preserves
            // every existing `with_l6_defaults(...)` call site.
            sqlite_index: Arc::new(InMemorySqliteIndex::default()),
            embedder: Arc::new(StubEmbedder),
            embedding_upkeep: Arc::new(EmbeddingUpkeep::new()),
            // Slice G (m011-slice-g): L6 cursor store seam default.
            // Signature UNCHANGED — body-only default-injection (slice-F
            // precedent). Future runtime-assembly slice MUST share this Arc
            // with L6Runnable::new's `cursor_store` arg — see the
            // "Cursor-store sharing" rustdoc block on this method.
            cursor_store: Arc::new(L6CursorStore::new()),
            // Slice satB-postproc: write-path seam defaults. Body-only injection
            // (slice-F/G precedent) — signature UNCHANGED. `None` ⇒ trace-only
            // Steps 7/8 + run()-agent_id writes (rootless tests unaffected).
            tasks_root: None,
            workspace_root: None,
            transcript_source: None,
            write_agent_id: None,
            // Slice satC-l6 (SAT-C): no in-process L6 dispatch by default
            // (Step-9 emits consolidation_due only) — body-only injection,
            // signature UNCHANGED. The cli composition root attaches a handler
            // via `with_l6_handler`.
            l6_handler: None,
            // SAT-D: Step-3 stays a no-op by default; cli attaches via
            // `with_description_indexer`. Body-only injection, signature UNCHANGED.
            description_indexer: None,
        }
    }

    /// Slice D — production-shaped constructor. Like [`with_l6_defaults`] but
    /// wires the supplied MODULE-019 `event_bus` for the WIT handlers (Seam A)
    /// AND uses it to back a real [`EventBusL6Emitter`] for the L6 Step-9 /
    /// Step-5c path (Seam B — the §3.6 line-923 "L6Emitter→M019 EventBus"
    /// production-wiring closure under the already-`passed` AC-15). The other
    /// L6 seams keep their in-memory defaults (still deferred per §3.6).
    ///
    /// # Lease-store sharing (round-16 adversarial fix; HARD REQUIREMENT)
    ///
    /// This constructor mints a fresh [`InMemoryLeaseStore`] and stores it in
    /// the public [`Components::lease`] field. The deferred cap-memory
    /// runtime-assembly slice (§3.8 note 10) MUST pass `c.lease.clone()` to
    /// [`L6Runnable::new`]'s `lease` argument — Step-9's `confirm_acquire`
    /// (called via `c.lease`) and Step-6's `release` (called via the
    /// runnable's separate `lease` field) MUST observe **the same lease
    /// state**. Wiring two distinct `LeaseStore`s — fresh InMemory here AND a
    /// separately-constructed store passed to `L6Runnable::new` — silently
    /// breaks the loop: Step-9 confirms in store-A; Step-6 release + the
    /// runnable's lease-loss gate check store-B → `L6Error::LeaseLost` on
    /// every run + the lease in store-A never clears until TTL. See §3.6
    /// "L6 lease-store sharing" Known-Gap row.
    ///
    /// # Cursor-store sharing (slice G; HARD REQUIREMENT)
    ///
    /// Symmetric to the lease-store-sharing requirement above: this constructor
    /// mints a fresh [`L6CursorStore`] and stores it in the public
    /// [`Components::cursor_store`] field, while [`L6Runnable::new`] takes an
    /// independent `cursor_store: Arc<L6CursorStore>` argument. The deferred
    /// cap-memory runtime-assembly slice (§3.8 note 10) MUST pass
    /// `c.cursor_store.clone()` to `L6Runnable::new`'s `cursor_store` argument
    /// — L6 Step-5a's `cursor_store.flush(...)` (called via the runnable's
    /// `cursor_store`) and the WIT `RollbackMemoryHandler::call`'s
    /// `cursor_store.reset_to_epoch(...)` (called via `Components.cursor_store`)
    /// MUST observe **the same cursor state**. Wiring two distinct
    /// `L6CursorStore`s silently breaks the loop: Step-5a flushes store-A's
    /// watermark while `rollback-memory` resets store-B → L6 reads the stale
    /// watermark, never sees the rollback's reset → the next L6 run uses the
    /// old cursor instead of restarting from epoch/0/0 (violates AC-18).
    /// See §3.6 "L6 cursor-store sharing between Components and L6Runnable"
    /// Known-Gap row.
    ///
    /// [`L6CursorStore`]: crate::l6::cursor::L6CursorStore
    ///
    /// [`with_l6_defaults`]: Components::with_l6_defaults
    /// [`EventBusL6Emitter`]: crate::l6::emit::EventBusL6Emitter
    /// [`InMemoryLeaseStore`]: crate::l6::lease::InMemoryLeaseStore
    /// [`L6Runnable::new`]: crate::l6::runnable::L6Runnable::new
    pub fn wired(
        extractor: Arc<dyn BatchExtractor + Send + Sync>,
        reconciler: Arc<Reconciler<dyn SimilarityIndex + Send + Sync>>,
        store: Arc<MemoryStore>,
        cooldown: Arc<FailureCooldown>,
        clock: Arc<dyn Clock + Send + Sync>,
        event_bus: Arc<dyn EventBusEmit + Send + Sync>,
    ) -> Self {
        Self {
            extractor,
            reconciler,
            store,
            cooldown,
            clock,
            trigger: Arc::new(L6TriggerEvaluator::new()),
            lease: Arc::new(crate::l6::lease::InMemoryLeaseStore::new()),
            l6_emitter: Arc::new(crate::l6::emit::EventBusL6Emitter::new(Arc::clone(
                &event_bus,
            ))),
            l6_trigger_state: Arc::new(Mutex::new(L6TriggerState::default())),
            event_bus,
            // Slice F: SQLite-index + Embedder seam defaults (in-memory).
            // Signature UNCHANGED — body-only default-injection preserves
            // every existing `wired(...)` call site. Production rusqlite +
            // real embedder adapters are deferred (see MODULE-011 §3.6).
            sqlite_index: Arc::new(InMemorySqliteIndex::default()),
            embedder: Arc::new(StubEmbedder),
            embedding_upkeep: Arc::new(EmbeddingUpkeep::new()),
            // Slice G (m011-slice-g): L6 cursor store seam default.
            // Signature UNCHANGED — body-only default-injection. Future
            // runtime-assembly slice MUST share this Arc with L6Runnable::new's
            // `cursor_store` arg per the # Cursor-store sharing rustdoc above.
            cursor_store: Arc::new(L6CursorStore::new()),
            // Slice satB-postproc: write-path seam defaults (see with_l6_defaults).
            // The composition root sets these via with_tasks_root / with_write_agent_id.
            tasks_root: None,
            workspace_root: None,
            transcript_source: None,
            write_agent_id: None,
            // Slice satC-l6 (SAT-C): no in-process L6 dispatch by default; the
            // cli composition root attaches a handler via `with_l6_handler`.
            l6_handler: None,
            // SAT-D: no Step-3 description indexer by default; cli attaches via
            // `with_description_indexer`.
            description_indexer: None,
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // Slice satB-postproc (SAT-B) — write-path seam builders (consuming).
    // Composition root: `Components::wired(..).with_tasks_root(..).with_sqlite_index(..).with_write_agent_id(..)`.
    // ────────────────────────────────────────────────────────────────────

    /// PRD §11.2: set the directory that holds the task directories
    /// (`<workspace>/.agent/tasks/active`). Step 0 logs each turn to
    /// `<root>/{task_id}/llm-turns.jsonl`; Step 7 writes `summary.yaml` /
    /// `turn-index.yaml` beside it. Absent ⇒ Steps 0/7/8 stay trace-only.
    pub fn with_tasks_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.tasks_root = Some(root.into());
        self
    }

    /// Set the agent's workspace root, which a tool call's `path` is relative to: Step 7
    /// records the git blob id of each file a turn read under it (`read_file_versions`).
    pub fn with_workspace_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.workspace_root = Some(root.into());
        self
    }

    /// Set where Step 0 takes the transcript of the turn that just ran from (the LLM
    /// gateway). Absent ⇒ a turn's log holds its inbound message only.
    pub fn with_transcript_source(mut self, source: Arc<dyn TurnTranscriptSource>) -> Self {
        self.transcript_source = Some(source);
        self
    }

    /// SAT-B (AC-46): swap the (in-memory default) SQLite index for a durable
    /// `RusqliteSqliteIndex`. The composition root degrades to the in-memory
    /// default (this builder is simply not called) if `RusqliteSqliteIndex::open`
    /// fails — see `cli::commands::start::build_live_post_processor`.
    pub fn with_sqlite_index(mut self, idx: Arc<dyn SqliteIndex + Send + Sync>) -> Self {
        self.sqlite_index = idx;
        self
    }

    /// SAT-B (AC-44 / colon-vs-bare fix): set the BARE cap id the post-processor
    /// keys all store/index/file writes under. `run()` receives the COLON
    /// messaging id; this maps it to the bucket `recall` reads.
    pub fn with_write_agent_id(mut self, id: impl Into<String>) -> Self {
        self.write_agent_id = Some(id.into());
        self
    }

    /// Swap the (deterministic 8-dim stub) embedder for a real one — the
    /// composition root installs a CONTRACT-081 `embed()` adapter when an
    /// embedding-capable provider is configured, so `sync_turn_index` /
    /// `sync_task_index` write semantic vectors the context assembler's recall
    /// and task-routing read side can match against (same model, same dim).
    pub fn with_embedder(mut self, embedder: Arc<dyn Embedder + Send + Sync>) -> Self {
        self.embedder = embedder;
        self
    }

    /// The SQLite index this pipeline writes (shared with the context
    /// assembler's read-side adapters so recall sees every turn-end write).
    pub fn sqlite_index(&self) -> Arc<dyn SqliteIndex + Send + Sync> {
        Arc::clone(&self.sqlite_index)
    }

    /// SAT-C (slice satC-l6): attach the in-process L6 dispatch handler invoked
    /// by Step-9 after `emit_consolidation_due`. Consuming builder mirroring the
    /// SAT-B write-path builders. The cli composition root calls this (via
    /// `crate::l6_wiring::attach_l6`) with an adapter wrapping the production
    /// `L6Runnable` + the `component.error` emitter. Absent ⇒ Step-9 emits
    /// `memory.l6_consolidation_due` only (pre-SAT-C behaviour).
    pub fn with_l6_handler(mut self, handler: Arc<dyn L6Dispatch>) -> Self {
        self.l6_handler = Some(handler);
        self
    }

    /// SAT-D: attach the Step-3 VLM/LLM description-indexing seam. `None`
    /// (the default) keeps Step-3 a documented no-op.
    pub fn with_description_indexer(mut self, indexer: Arc<dyn DescriptionIndexer>) -> Self {
        self.description_indexer = Some(indexer);
        self
    }

    // ────────────────────────────────────────────────────────────────────
    // Slice F — SQLite-index + Embedder seam-driving methods (AC-19/24/27/31)
    //
    // Publicly callable: tests construct `TurnEntry` / `Summary` instances
    // and call these methods directly. Slice satB-postproc now also calls them
    // from `PostProcessor::run` Step 8 (`step_8_sqlite_sync`) after Step 7
    // materializes the per-turn `TurnEntry` / `Summary` and resolves the
    // task_id (from `msg.context.task_id`, or an `_agent-<write_id>` fallback),
    // keyed by the bare `write_id`. When no tasks root is configured (the
    // rootless test path), Step 8 stays push-only, so the AC-08 9-step
    // canonical trace is preserved on every branch. See MODULE-011 §3.6 / §3.8 note 12.
    // ────────────────────────────────────────────────────────────────────

    /// Slice F (AC-19, REQ-226): compute the L1 embedding for `digest +
    /// "\n" + collapsed_view` via [`Embedder::embed`], then upsert a
    /// [`TurnIndexRow`] into the [`SqliteIndex`]. `task_id` is derived from
    /// `turn.task_id` (`TurnEntry` already carries it per turn_index.rs:70) —
    /// no separate `task_id` parameter, eliminating the silent-data-divergence
    /// footgun where caller passes a different task_id from the one embedded
    /// in the TurnEntry.
    ///
    /// **Cross-method composition warning** (adversarial round 6 finding):
    /// `reference_count` is copied verbatim from the caller-supplied
    /// `TurnEntry`. If a caller interleaves [`bump_turn_reference`] (which
    /// bumps the stored row's count to `N+k`) with a follow-on
    /// `sync_turn_index` call carrying a stale `turn.reference_count == N`,
    /// the bump is silently clobbered. The §2.11 1-per-agent serialization
    /// makes this not exploitable today — slice satB-postproc's Step 8 calls
    /// `sync_turn_index` / `sync_task_index` / `sync_memory_index` but NOT
    /// `bump_turn_reference`, so it never interleaves the two; any future
    /// caller that DOES interleave MUST establish a call
    /// ordering contract (e.g., always re-load `TurnEntry.reference_count`
    /// from `sqlite_index.get_turn()` before constructing the
    /// `TurnEntry` passed here). See §3.6 row "In-memory `SqliteIndex`
    /// stub get-modify-upsert race posture" surface (3) for the rusqlite
    /// adapter contract.
    pub async fn sync_turn_index(
        &self,
        agent_id: &str,
        turn: &TurnEntry,
    ) -> Result<(), EmbedderError> {
        let text = turn_embedding_text(&turn.digest, &turn.collapsed_view);
        // The vector is stored WITH the model that produced it. The digest row is
        // written in EVERY outcome, so the turn stays listed and countable:
        // - a turn with no text has nothing to embed, and no request is made;
        // - an embedder with nothing to embed with answers an empty vector;
        // - a failed embedding request is reported to the caller AFTER the row is
        //   written (it must not cost the turn its index row).
        // In each case the row carries no new vector; a vector this same digest
        // already has is kept rather than erased, and a later turn end fills the
        // gap in ([`Self::heal_vectors`]).
        let (embedded, failure) = if text.trim().is_empty() {
            ((Vec::new(), None), None)
        } else {
            match self.embedder.embed_recorded(&text).await {
                Ok(embedded) => (embedded, None),
                Err(e) => ((Vec::new(), None), Some(e)),
            }
        };
        // What catch-up is told is about the text that was asked about. Catch-up
        // asks about the same text — the digest, and the view it reads back from
        // the task's `turn-index.yaml` — unless that view cannot be read back.
        let row = VectorRow::Turn {
            task_id: turn.task_id.clone(),
            turn: turn.turn,
        };
        match &failure {
            Some(failure) => self.note_failed_embedding(agent_id, failure, row.clone(), &text),
            None if !embedded.0.is_empty() => self.embedding_upkeep.request_served(agent_id, &row),
            None => {}
        }
        let (embedding, embedding_model) = match embedded {
            (vector, _) if vector.is_empty() => self
                .sqlite_index
                .get_turn(agent_id, &turn.task_id, turn.turn)
                .filter(|prev| prev.digest == turn.digest && !prev.embedding.is_empty())
                .map(|prev| (prev.embedding, prev.embedding_model))
                .unwrap_or((Vec::new(), None)),
            embedded => embedded,
        };
        if !turn.digest.trim().is_empty() {
            // What catch-up asks about for the row is the text just asked about: Step 7
            // wrote the view beside the digest in the task's `turn-index.yaml`.
            self.embedding_upkeep
                .row_written(agent_id, &row, &text, embedding_model.as_deref());
        }
        self.sqlite_index.upsert_turn(TurnIndexRow {
            agent_id: agent_id.to_owned(),
            task_id: turn.task_id.clone(),
            turn: turn.turn,
            digest: turn.digest.clone(),
            embedding,
            embedding_model,
            reference_count: turn.reference_count,
            updated_at: utc_now_string(&*self.clock),
        });
        failure.map_or(Ok(()), Err)
    }

    /// Slice F (AC-27, REQ-230): upsert a [`TaskIndexRow`] from a [`Summary`].
    /// `brief_embedding` is recomputed via [`Embedder::embed`] when
    /// `summary.brief` differs from the previously-stored row's
    /// `brief_snapshot` (string equality — deterministic substitute for
    /// semantic similarity in the absence of a real embedder; see
    /// MODULE-011 §3.8 note 12 (d)): on first-write OR on textual change the
    /// brief is embedded right away. An UNCHANGED brief keeps its stored vector
    /// verbatim, whatever model it is of. When that vector is missing or comes
    /// from another model than the one in use, embedding the brief again is
    /// catch-up, and catch-up is [`Self::heal_vectors`]' — for this task as for
    /// every other task of the agent, whether or not it ever gets another turn.
    ///
    /// **Whose row**: the row is `summary.meta.agent_id`'s own
    /// (`(agent_id, task_id)` — see [`TaskIndexRow`]). Another agent working
    /// under the same task id has its own row, brief and vector; neither turn
    /// end reads or rewrites the other's. `summary.meta.agent_id` is set by the
    /// post-processor from its write id (Step 7), not by a guest.
    ///
    /// **In-memory-stub posture**: like [`bump_turn_reference`], the brief-
    /// change gate spans two lock acquisitions (`get_task` then `upsert_task`).
    /// The post-processor §2.11 serialization (1-per-agent) keeps two turn ends
    /// of one agent from interleaving here. See §3.6 row "In-memory
    /// `SqliteIndex` stub get-modify-upsert race posture".
    pub async fn sync_task_index(&self, summary: &Summary) -> Result<(), EmbedderError> {
        let agent_id = summary.meta.agent_id.as_str();
        let prev = self.sqlite_index.get_task(agent_id, &summary.meta.task_id);
        let brief_changed = prev
            .as_ref()
            .map(|r| r.brief_snapshot != summary.brief)
            .unwrap_or(true);
        let has_text = !summary.brief.trim().is_empty();
        let row = VectorRow::Task {
            task_id: summary.meta.task_id.clone(),
        };
        let mut failure = None;
        let (brief_embedding, brief_embedding_model) = if !brief_changed {
            // The same text: its vector stays, whatever model it is of.
            prev.map(|row| (row.brief_embedding, row.brief_embedding_model))
                .unwrap_or((None, None))
        } else if !has_text {
            // A brief with no text has no vector (and the one of its old text goes).
            (None, None)
        } else {
            match self.embedder.embed_recorded(&summary.brief).await {
                Ok((vector, model)) if !vector.is_empty() => {
                    self.embedding_upkeep.request_served(agent_id, &row);
                    (Some(vector), model)
                }
                // No vector for the new text — nothing to embed with (`Ok` empty), or
                // the request failed (reported after the row is written). The vector
                // of the previous text is dropped, never left standing for a brief it
                // does not describe; a later turn end catches the row up.
                outcome => {
                    failure = outcome.err();
                    if let Some(failure) = &failure {
                        self.note_failed_embedding(agent_id, failure, row.clone(), &summary.brief);
                    }
                    (None, None)
                }
            }
        };
        if has_text {
            self.embedding_upkeep.row_written(
                agent_id,
                &row,
                &summary.brief,
                brief_embedding_model.as_deref(),
            );
        }
        self.sqlite_index.upsert_task(TaskIndexRow {
            task_id: summary.meta.task_id.clone(),
            agent_id: summary.meta.agent_id.clone(),
            last_turn_at: summary.meta.last_turn_at.clone(),
            turns_total: summary.meta.turns_total,
            updated_at: utc_now_string(&*self.clock),
            brief_snapshot: summary.brief.clone(),
            brief_embedding,
            brief_embedding_model,
        });
        failure.map_or(Ok(()), Err)
    }

    /// Give a few of `agent_id`'s rows — task briefs and turn digests — a vector
    /// of the model its queries are made with now, and say how many got one.
    ///
    /// A reader compares stored vectors with a query of the SAME model only. So a
    /// row whose vector is missing (its request failed, or nothing could embed
    /// when it was written), comes from another model (the agent's provider
    /// changed) or from a model nobody recorded (an index written by an older
    /// version) is invisible to recall and to task routing. Nothing else would
    /// ever embed it again: a turn's digest never changes, and a task may never
    /// get another turn. This does, a little per turn end:
    ///
    /// - at most [`VECTORS_PER_TURN_END`] rows per call: the task briefs first,
    ///   then the turn rows, each the most recently written first. Task routing
    ///   compares every message with the briefs of all the agent's tasks, so a
    ///   brief of another model leaves routing short of its task (MODULE-010
    ///   §1.4.2); the briefs are few, one per task, and are caught up first;
    /// - turn rows only among the [`RECENT_TURN_WINDOW`] most recent (what a
    ///   reader scans): the cost of a model change is bounded by the window and
    ///   the number of tasks, never by the length of the history;
    /// - only the vector and its model are written
    ///   ([`SqliteIndex::set_task_brief_embedding`],
    ///   [`SqliteIndex::set_turn_embedding`]), and only while the row still holds
    ///   the text the vector was computed from; the row keeps its place in time;
    /// - paced by [`crate::embedding_upkeep`]: nothing while catch-up rests; a
    ///   text the service refuses is set aside, a text whose request fails while
    ///   the service is answering is put off behind every other row, and either
    ///   way the pass goes on behind it; two failures in a row end the pass and
    ///   start a rest; a pass starts no request once it has run for
    ///   [`CATCH_UP_TIME`], and ends by then in any case — a request still
    ///   unanswered (the gateway's own retries included) is cut off and counts as
    ///   failed — since the agent's next turn waits for the pass; and once nothing
    ///   is left the index is not searched again until a row needs a vector.
    ///
    /// `Err` — why the pass stopped (the index could not be read or written, the
    /// embedder named no model for a vector), or else the first thing that kept a
    /// row from its vector (a request failed, a text was refused); the rows behind
    /// a refused or put-off text were still embedded. An index that cannot be
    /// read never counts as "nothing left": the agent is not settled by it.
    ///
    /// With nothing to embed with ([`Embedder::current_model`] is `None`) it
    /// does nothing. The text embedded is the one [`Self::sync_task_index`] and
    /// [`Self::sync_turn_index`] embed for a new row: a task's brief, a turn's
    /// digest and then its collapsed view. A turn row keeps no view, so the view is
    /// read back from the `turn-index.yaml` of the row's task, where Step 7 wrote it
    /// (MODULE-010 B1). A turn whose view cannot be read back is caught up from its
    /// digest alone (see `TurnViews`).
    pub async fn heal_vectors(&self, agent_id: &str) -> Result<usize, CatchUpError> {
        let Some(model) = self.embedder.current_model() else {
            return Ok(0);
        };
        let upkeep = &self.embedding_upkeep;
        let started = self.clock.now();
        // Asked at every turn end that has a model: this is also where a change of
        // the model is noticed (and starts a rest).
        if !upkeep.may_catch_up(agent_id, &model, started) || upkeep.is_settled(agent_id) {
            return Ok(0);
        }
        // From each table, enough to find a full pass of open rows behind every
        // text kept back.
        let limit = VECTORS_PER_TURN_END + upkeep.kept_back(agent_id);
        let index = self.sqlite_index.as_ref();
        let listed = index
            .list_tasks_not_of_model(agent_id, &model, limit)
            .and_then(|tasks| {
                index
                    .list_turns_not_of_model(agent_id, &model, RECENT_TURN_WINDOW, limit)
                    .map(|turns| (tasks, turns))
            });
        let (tasks, turns) = match listed {
            Ok(listed) => listed,
            Err(e) => {
                // What is left is not known, which is not "nothing is left": the
                // agent stays unsettled, and a failing index is not asked again at
                // every turn end.
                upkeep.rest(agent_id, self.clock.now());
                return Err(e.into());
            }
        };
        let mut open = Vec::new();
        let mut put_off = Vec::new();
        // A turn's vector is computed from its digest and its collapsed view; the row
        // keeps no view, so it is read back from the task's `turn-index.yaml`.
        let mut views = TurnViews::new(self.tasks_root.as_deref(), agent_id);
        for row in tasks
            .into_iter()
            .map(StaleRow::Task)
            .chain(turns.into_iter().map(|row| {
                let view = views.view(&row.task_id, row.turn);
                StaleRow::Turn(row, view)
            }))
        {
            match upkeep.standing(agent_id, &row.key(), &row.text()) {
                Standing::Open => open.push(row),
                Standing::PutOff { place } => put_off.push((place, row)),
                Standing::SetAside => {}
            }
        }
        if open.is_empty() && put_off.is_empty() {
            // Nothing is left but texts the service refused.
            upkeep.settle(agent_id);
            return Ok(0);
        }
        // Open rows: the briefs, then the digests, each the most recently written
        // first. Then the rows put off, the one put off longest ago first.
        open.sort_by(|a, b| {
            a.is_turn()
                .cmp(&b.is_turn())
                .then_with(|| b.updated_at().cmp(a.updated_at()))
        });
        put_off.sort_by_key(|(place, _)| *place);
        let rows = open
            .into_iter()
            .chain(put_off.into_iter().map(|(_, row)| row));
        let mut asked = 0;
        let mut served = 0;
        let mut embedded = 0;
        let mut kept_from_its_vector: Option<CatchUpError> = None;
        // The pass is over by this moment of real time, whatever a request is doing
        // then: the agent's next turn waits for it.
        let deadline = tokio::time::Instant::now() + CATCH_UP_TIME;
        for row in rows.take(VECTORS_PER_TURN_END) {
            let running = self.clock.now().duration_since(started).unwrap_or_default();
            if running >= CATCH_UP_TIME {
                break;
            }
            let text = row.text();
            let answer = match tokio::time::timeout_at(
                deadline,
                self.embedder.embed_recorded(&text),
            )
            .await
            {
                Ok(answer) => answer,
                Err(_out_of_time) => {
                    // Cut off: a failed request, and the end of the pass.
                    asked += 1;
                    upkeep.request_failed(agent_id, row.key(), &text, self.clock.now());
                    kept_from_its_vector.get_or_insert(
                        EmbedderError::Upstream(
                            "no answer within the time a catch-up pass has".into(),
                        )
                        .into(),
                    );
                    break;
                }
            };
            match answer {
                Ok((vector, Some(produced))) if !vector.is_empty() => {
                    asked += 1;
                    served += 1;
                    upkeep.request_served(agent_id, &row.key());
                    match row.store(index, agent_id, &vector, &produced) {
                        Ok(true) => embedded += 1,
                        // The row holds another text by now: its writer embedded that.
                        Ok(false) => {}
                        Err(e) => {
                            upkeep.rest(agent_id, self.clock.now());
                            return Err(e.into());
                        }
                    }
                    if produced != model {
                        // The agent's model moved under this pass. The vector is
                        // stored as what it is; the next turn end sees the change.
                        break;
                    }
                }
                // A vector of a model nobody names cannot be stored as one of the
                // model in use, now or at the next turn end
                // ([`Embedder::current_model`]): the embedder is at fault, and is
                // not asked for the next one.
                Ok((vector, None)) if !vector.is_empty() => {
                    upkeep.rest(agent_id, self.clock.now());
                    return Err(EmbedderError::Upstream(
                        "the embedder named no model for the vector it returned".into(),
                    )
                    .into());
                }
                // Nothing to embed with any more.
                Ok(_) => break,
                // The service answered and refused this text: it is not asked about
                // it again, and the rows behind it are not held up.
                Err(e) if e.is_about_the_text() => {
                    asked += 1;
                    upkeep.set_aside(agent_id, row.key(), &text);
                    kept_from_its_vector.get_or_insert(e.into());
                }
                Err(e) => {
                    asked += 1;
                    let resting =
                        upkeep.request_failed(agent_id, row.key(), &text, self.clock.now());
                    kept_from_its_vector.get_or_insert(e.into());
                    if resting {
                        break;
                    }
                }
            }
        }
        if asked > 0 && served == 0 {
            // Requests were made and no vector came of them. Whatever stands
            // between these texts and their vectors, the next ones are not asked
            // about right away.
            upkeep.rest(agent_id, self.clock.now());
        }
        kept_from_its_vector.map_or(Ok(embedded), Err)
    }

    /// An embedding request for the text `row` of `agent_id` holds failed. A text
    /// the service refused is set aside (catch-up does not ask about it again).
    /// Any other failure goes by what the request before it showed
    /// ([`EmbeddingUpkeep::request_failed`]): the text is put off, or — the
    /// service is failing — catch-up rests.
    fn note_failed_embedding(
        &self,
        agent_id: &str,
        failure: &EmbedderError,
        row: VectorRow,
        text: &str,
    ) {
        if failure.is_about_the_text() {
            self.embedding_upkeep.set_aside(agent_id, row, text);
        } else {
            self.embedding_upkeep
                .request_failed(agent_id, row, text, self.clock.now());
        }
    }

    /// Slice F (AC-24, REQ-159): mirror every entry's [`MemoryStatus`] into a
    /// [`MemoryIndexRow.epistemic_status`] row via [`MemoryStatus::as_str`].
    /// Iterates `self.store.list(agent_id)`. No embedding involvement
    /// (memory_index rows are non-vector). Each row's `updated_at` is
    /// computed independently inside the loop (per-row timestamp, matching
    /// the convention of `sync_turn_index` / `sync_task_index` /
    /// `bump_turn_reference`) so a future delta-since-X query against the
    /// memory_index can distinguish individual row writes within a batch.
    pub fn sync_memory_index(&self, agent_id: &str) {
        for entry in self.store.list(agent_id) {
            self.sqlite_index.upsert_memory(MemoryIndexRow {
                agent_id: agent_id.to_owned(),
                memory_id: entry.id.clone(),
                epistemic_status: entry.status.as_str().to_owned(),
                updated_at: utc_now_string(&*self.clock),
            });
        }
    }

    /// Slice F (AC-31, REQ-230): bump `reference_count` of an existing
    /// [`TurnIndexRow`] WITHOUT recomputing the embedding. Get-modify-upsert
    /// sequence; returns `true` if the row existed and was updated, `false`
    /// if the row was not found (Step 7 — slice satB-postproc — writes it
    /// first via `sync_turn_index` before any reference bump).
    ///
    /// CRITICAL invariant (AC-31 explicit): the in-place row mutation keeps
    /// `embedding` bytes-for-bytes unchanged. T41 asserts this byte-equality
    /// across 3 successive bumps.
    ///
    /// **In-memory-stub posture**: the get-modify-upsert spans two
    /// `InMemorySqliteIndex` lock acquisitions (`get_turn` releases the lock,
    /// then `upsert_turn` re-acquires). Concurrent bumps on the same
    /// `(agent_id, task_id, turn)` row could in principle lose increments. In
    /// production this is structurally prevented: §2.11 Operational Parameters
    /// pins post-processor concurrency to "1 per agent (serialized)" — the
    /// seam callers (post-processor Step 8, wired by slice satB-postproc)
    /// run sequentially within an agent, and cross-agent calls touch
    /// different turn keys. The deferred rusqlite adapter (§3.6) will use
    /// atomic `UPDATE ... SET reference_count = reference_count + 1` so the
    /// race is structurally eliminated there too. See §3.6 row
    /// "In-memory `SqliteIndex` stub get-modify-upsert race posture".
    ///
    /// **Saturating-add silent-overflow posture** (adversarial round 4
    /// finding): `reference_count.saturating_add(1)` clamps at `u32::MAX`
    /// (4,294,967,295). Once a row reaches the cap, further bumps are silent
    /// no-ops on the count while still refreshing `updated_at` — downstream
    /// consumers using `reference_count` for hot-row eviction / LRU /
    /// staleness signals would mis-rank the row. Not reachable under any
    /// realistic workload (4.3B references on a single turn is implausible),
    /// but a misbehaving Step-7-extension that loops on the same turn key
    /// could trip the saturation. The deferred rusqlite adapter SHOULD use
    /// `BIGINT` (i64) for `reference_count` to push the cap out of practical
    /// reach AND surface a warning log on the i64-saturation transition.
    pub fn bump_turn_reference(&self, agent_id: &str, task_id: &str, turn: u32) -> bool {
        if let Some(mut row) = self.sqlite_index.get_turn(agent_id, task_id, turn) {
            row.reference_count = row.reference_count.saturating_add(1);
            row.updated_at = utc_now_string(&*self.clock);
            // The bump makes the row recent again: if its vector is not of the
            // model in use, it is one more row to catch up on.
            if !row.digest.trim().is_empty() {
                self.embedding_upkeep.row_written(
                    agent_id,
                    &VectorRow::Turn {
                        task_id: task_id.to_owned(),
                        turn,
                    },
                    &turn_embedding_text(
                        &row.digest,
                        &TurnViews::new(self.tasks_root.as_deref(), agent_id).view(task_id, turn),
                    ),
                    row.embedding_model.as_deref(),
                );
            }
            // CRITICAL: do NOT recompute embedding here.
            self.sqlite_index.upsert_turn(row);
            true
        } else {
            false
        }
    }
}

/// The text a turn's vector is computed from: its digest, then its collapsed
/// view (PRD §11.3, the L1 layer; Step 7 writes the view since MODULE-010 B1). An
/// index row keeps the digest alone; [`Components::heal_vectors`] reads the view
/// back from the task's `turn-index.yaml` to compute the vector again.
fn turn_embedding_text(digest: &str, collapsed_view: &str) -> String {
    format!("{digest}\n{collapsed_view}")
}

/// Why a pass of [`Components::heal_vectors`] stopped short or left a row out.
#[derive(Debug, thiserror::Error)]
pub enum CatchUpError {
    /// An embedding request failed, or the service refused a text.
    #[error(transparent)]
    Embedding(#[from] EmbedderError),
    /// The index could not be read or written.
    #[error(transparent)]
    Index(#[from] IndexUnavailable),
}

/// A row [`Components::heal_vectors`] found without a vector of the model in use.
enum StaleRow {
    Task(TaskIndexRow),
    /// A turn row, and the collapsed view read back for it ([`TurnViews`]).
    Turn(TurnIndexRow, String),
}

impl StaleRow {
    fn key(&self) -> VectorRow {
        match self {
            StaleRow::Task(row) => VectorRow::Task {
                task_id: row.task_id.clone(),
            },
            StaleRow::Turn(row, _) => VectorRow::Turn {
                task_id: row.task_id.clone(),
                turn: row.turn,
            },
        }
    }

    /// Whether the row is a turn's (else a task's brief).
    fn is_turn(&self) -> bool {
        matches!(self, StaleRow::Turn(..))
    }

    /// When the row was last written.
    fn updated_at(&self) -> &str {
        match self {
            StaleRow::Task(row) => &row.updated_at,
            StaleRow::Turn(row, _) => &row.updated_at,
        }
    }

    /// The text the row's vector is computed from — what the turn end that wrote
    /// the row embedded, as far as the view could be read back.
    fn text(&self) -> String {
        match self {
            StaleRow::Task(row) => row.brief_snapshot.clone(),
            StaleRow::Turn(row, view) => turn_embedding_text(&row.digest, view),
        }
    }

    /// Store `vector` (of `model`) on the row, provided the row still holds the
    /// text the vector was computed from.
    fn store(
        &self,
        index: &(dyn SqliteIndex + Send + Sync),
        agent_id: &str,
        vector: &[f32],
        model: &str,
    ) -> Result<bool, IndexUnavailable> {
        match self {
            StaleRow::Task(row) => index.set_task_brief_embedding(
                agent_id,
                &row.task_id,
                &row.brief_snapshot,
                vector,
                model,
            ),
            StaleRow::Turn(row, _) => index.set_turn_embedding(
                agent_id,
                &row.task_id,
                row.turn,
                &row.digest,
                vector,
                model,
            ),
        }
    }
}

/// The collapsed views of an agent's turns, read back from their tasks'
/// `turn-index.yaml` for [`Components::heal_vectors`]: each task's file once a
/// pass, with the same bounds and checks as Step 7's own read. Nothing is created.
/// A turn whose view cannot be read back has none, and is caught up from its
/// digest alone: with no tasks root, a task id that is not one safe segment, a
/// tasks root or task directory that is missing or a link (the task files a
/// release before MODULE-010 B1 wrote stay where it wrote them), an index entry
/// that is gone or was written for another agent, or a view longer than Step 7
/// writes.
struct TurnViews<'a> {
    tasks_root: Option<&'a Path>,
    agent_id: &'a str,
    read: std::collections::HashMap<String, std::collections::HashMap<u32, String>>,
}

impl<'a> TurnViews<'a> {
    fn new(tasks_root: Option<&'a Path>, agent_id: &'a str) -> Self {
        Self {
            tasks_root,
            agent_id,
            read: std::collections::HashMap::new(),
        }
    }

    /// The collapsed view of `turn` of `task_id`, or an empty one.
    fn view(&mut self, task_id: &str, turn: u32) -> String {
        let (tasks_root, agent_id) = (self.tasks_root, self.agent_id);
        self.read
            .entry(task_id.to_string())
            .or_insert_with(|| read_turn_views(tasks_root, agent_id, task_id))
            .get(&turn)
            .cloned()
            .unwrap_or_default()
    }
}

/// The collapsed views `agent_id`'s turns of `task_id` have in the task's
/// `turn-index.yaml`, by turn ([`TurnViews`]).
fn read_turn_views(
    tasks_root: Option<&Path>,
    agent_id: &str,
    task_id: &str,
) -> std::collections::HashMap<u32, String> {
    let mut views = std::collections::HashMap::new();
    let Some(tasks_root) = tasks_root else {
        return views;
    };
    if sanitize_task_segment(task_id).as_deref() != Some(task_id) {
        return views;
    }
    let real_dir =
        |path: &Path| std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_dir());
    let dir = tasks_root.join(task_id);
    if !real_dir(tasks_root) || !real_dir(&dir) {
        return views;
    }
    match (tasks_root.canonicalize(), dir.canonicalize()) {
        (Ok(root), Ok(canon)) if canon.starts_with(&root) => {}
        _ => return views,
    }
    // The archive's entries first: an entry in both is the index's.
    let archived = crate::task_storage::load_turn_index_archive(
        &dir.join(crate::task_storage::TASK_TURN_INDEX_ARCHIVE_FILENAME),
    );
    for entry in archived
        .into_iter()
        .chain(load_turn_index(&dir.join(TASK_TURN_INDEX_FILENAME)).turns)
    {
        if entry.agent_id == agent_id
            && entry.collapsed_view.len() <= crate::turn_log::MAX_COLLAPSED_VIEW_BYTES
        {
            views.insert(entry.turn, entry.collapsed_view);
        }
    }
    views
}

/// Slice F private helper: ISO-8601 UTC timestamp routed through the
/// caller-supplied [`Clock`].
///
/// Round-2 adversarial fix: routes through the existing `Clock` injection
/// seam (`clock.rs:11-13`) instead of bypassing it via a direct
/// `chrono::Utc::now()` call. This restores: (a) deterministic-timestamp
/// testing for all 4 slice-F seam methods (tests inject a `MutableClock` and
/// drive the timestamps deterministically); (b) per-row timestamp
/// auditability via the same injection point used by `FailureCooldown` and
/// the rest of cap-memory; (c) chaos-test resilience against wall-clock
/// jumps. The Clock trait stays unchanged (still only `fn now(&self) ->
/// SystemTime`); this helper formats the SystemTime into RFC 3339 via the
/// existing `advance_shared_types::chrono` re-export (same path used by
/// slice-D `events.rs`).
///
/// **Clock-impl contract for chrono-range safety** (adversarial round 5
/// finding): `chrono::DateTime::<Utc>::from(SystemTime)` panics on values
/// outside chrono's representable range (`SystemTime` near `u64::MAX`
/// seconds beyond UNIX_EPOCH, or before the earliest representable
/// timestamp). Implementations of [`Clock`] supplied to `Components.clock`
/// MUST return `SystemTime` values within `[chrono::DateTime::<Utc>::MIN,
/// chrono::DateTime::<Utc>::MAX]` — practically, any plausible production
/// timestamp (`SystemClock`) or test fixture (`MutableClock` started near
/// `UNIX_EPOCH`) satisfies this trivially. The contract is documented to
/// guard against future adversarial / chaos-test `Clock` impls that might
/// return wildly out-of-range values; the alternative defensive bounded-
/// check inside `utc_now_string` itself was considered and deferred
/// (overkill for the slice-F in-memory-stub posture; the production
/// rusqlite adapter will encode timestamps via SQL `TEXT`/`INTEGER` with
/// its own range validation).
fn utc_now_string(clock: &dyn Clock) -> String {
    let system_time = clock.now();
    let datetime: advance_shared_types::chrono::DateTime<advance_shared_types::chrono::Utc> =
        system_time.into();
    datetime.to_rfc3339()
}

// ────────────────────────────────────────────────────────────────────────
// Slice satB-postproc (SAT-B) — Step-7 on-disk writeback helpers.
// ────────────────────────────────────────────────────────────────────────

/// SAT-B (AC-45 / R12): max bytes for an existing `summary.yaml` /
/// `turn-index.yaml` read back at Step 7. A tampered/oversize workspace file is
/// REFUSED before deserialization (DoS guard) and the step starts from a fresh
/// in-memory default. 1 MiB matches the `crates/database/src/rebuild.rs`
/// `MAX_YAML_BYTES` convention for the same artifact class (cross-crate reuse
/// unavailable — cap-memory has no `advance-database` dep). Net-new:
/// `persistence::read_line_capped` is line-oriented (knowledge.jsonl), not a
/// whole-file YAML cap.
pub const MAX_TASK_YAML_BYTES: u64 = 1024 * 1024;

/// SAT-B: map an embedder failure (Step-8 `sync_*` seam) into the post-processor
/// error type. Orphan-safe (mirrors the `From<ForgetError>` precedent in
/// store.rs): `EmbedderError` is cap-memory-local. With the default
/// `StubEmbedder` this never fires; it exists so a future real-embedder adapter
/// composes via `?` in Step 8.
impl From<EmbedderError> for PostProcessorError {
    fn from(e: EmbedderError) -> Self {
        PostProcessorError::StorageError(e.to_string())
    }
}

/// A vector catch-up that stopped short (Step 8) is reported the same way.
impl From<CatchUpError> for PostProcessorError {
    fn from(e: CatchUpError) -> Self {
        PostProcessorError::StorageError(e.to_string())
    }
}

/// The per-agent DEFAULT task partition Step 7 writes under when the inbound
/// message carries no `task_id` (`_agent-{write_id}`). The context assembler's
/// history readers use the SAME derivation so a turn with no task id reads back
/// the history the previous no-task-id turns wrote. `None` when `write_id` is
/// not a safe path segment (Step 7 then skips the write as well).
pub fn default_task_partition(write_id: &str) -> Option<String> {
    sanitize_task_segment(write_id).map(|s| format!("_agent-{s}"))
}

/// Whether `task_id` is an agent's default partition ([`default_task_partition`]): the turns
/// no task was settled for. It is no task: routing never chooses it, and it is no related
/// task. Its turns are recalled as other tasks' turns are.
pub fn is_default_task_partition(task_id: &str) -> bool {
    task_id.starts_with("_agent-")
}

/// SAT-B (AC-45 / D4): validate a guest-controllable task-id path SEGMENT.
/// Returns `Some(clean)` only for a single safe path component; rejects empty,
/// `.`/`..`, a leading `.`, any `/`/`\`/NUL, or an absolute/multi-component
/// form. A rejected value is NEVER silently redirected — Step 7 skips the write.
pub(crate) fn sanitize_task_segment(raw: &str) -> Option<String> {
    if raw.is_empty()
        || raw == "."
        || raw == ".."
        || raw.starts_with('.')
        || raw.contains('/')
        || raw.contains('\\')
        || raw.contains('\0')
    {
        return None;
    }
    // Belt-and-suspenders: a clean value must parse to exactly ONE Normal path
    // component (rejects absolute/root/parent/prefix forms the string checks miss).
    let mut comps = Path::new(raw).components();
    match (comps.next(), comps.next()) {
        (Some(std::path::Component::Normal(_)), None) => Some(raw.to_string()),
        _ => None,
    }
}

/// SAT-B (AC-45 / D4 / W3): compose `<tasks_root>/{task_id}` and confine it
/// under `tasks_root` against symlink escape. `task_id` MUST already be sanitized
/// (single safe segment). Creates the dirs (so the atomic writes land), rejects a
/// symlinked tasks root or task dir, and asserts the canonicalized dir stays under
/// the canonicalized `tasks_root`. Returns `None` (write skipped) on any breach.
///
/// Residual TOCTOU: a check-then-write window remains; full elimination needs
/// `openat`/`O_NOFOLLOW` descriptor-relative I/O — out of scope for a single
/// sanitized segment under the agent's own `.agent/tasks/active` (documented at the gate).
fn confined_task_dir(tasks_root: &Path, task_id: &str) -> Option<PathBuf> {
    // Audit r7: reject a pre-planted symlinked root BEFORE create_dir_all (else
    // `create_dir_all` would mkdir through it). The canonical `starts_with` check
    // below is the backstop for any deeper symlink; a concurrent post-canonicalize
    // parent swap remains the documented TOCTOU residual.
    if std::fs::symlink_metadata(tasks_root)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        eprintln!("cap-memory post-processor: refusing symlinked tasks root {tasks_root:?}; skipping write");
        return None;
    }
    if let Err(e) = std::fs::create_dir_all(tasks_root) {
        eprintln!("cap-memory post-processor: create tasks root {tasks_root:?} failed: {e}");
        return None;
    }
    let dir = tasks_root.join(task_id);
    // Reject a pre-existing symlinked task dir outright.
    if let Ok(meta) = std::fs::symlink_metadata(&dir) {
        if meta.file_type().is_symlink() {
            eprintln!("cap-memory post-processor: refusing symlinked task dir {dir:?}");
            return None;
        }
    }
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("cap-memory post-processor: create task dir {dir:?} failed: {e}");
        return None;
    }
    // Canonical confinement: the realpath of the task dir MUST stay under the
    // realpath of the tasks root (catches any symlink in the chain that escapes).
    let (Ok(canon_root), Ok(canon_dir)) = (tasks_root.canonicalize(), dir.canonicalize()) else {
        eprintln!("cap-memory post-processor: canonicalize failed for {dir:?}; skipping write");
        return None;
    };
    if !canon_dir.starts_with(&canon_root) {
        eprintln!(
            "cap-memory post-processor: task dir {canon_dir:?} escapes the tasks root {canon_root:?}; skipping write"
        );
        return None;
    }
    Some(dir)
}

/// The task a turn is written under, resolved THREE-WAY from `msg.context.task_id`
/// (D3 / Codex W2): absent ⇒ the agent's default partition `_agent-{write_id}`;
/// present + valid ⇒ it; present + malicious ⇒ `None` (the write is SKIPPED, never
/// silently redirected under `_agent-*`).
fn resolve_task_id(write_id: &str, msg: &Message) -> Option<String> {
    match msg.context.as_ref().and_then(|c| c.task_id.clone()) {
        None => {
            let partition = default_task_partition(write_id);
            if partition.is_none() {
                eprintln!(
                    "cap-memory post-processor: write_id {write_id:?} unsanitizable for a default task partition; skipping on-disk write"
                );
            }
            partition
        }
        Some(raw) => {
            let safe = sanitize_task_segment(&raw);
            if safe.is_none() {
                eprintln!(
                    "cap-memory post-processor: rejecting malicious task_id {raw:?} (NOT redirected); skipping on-disk write"
                );
            }
            safe
        }
    }
}

/// The YAML of `index`, and the oldest turn entries it no longer holds: while it is larger
/// than three quarters of [`MAX_TASK_YAML_BYTES`] (the cap the next turn's read applies; the
/// rest is room for the turns to come), its oldest tenth moves out. Without this, an index past
/// the cap would read back as empty and the next turn would overwrite it. The caller appends
/// what moved out to the task's turn-index archive
/// ([`crate::task_storage::TASK_TURN_INDEX_ARCHIVE_FILENAME`]), so the index and its archive
/// hold every entry between them; turn numbers carry on from the newest entry.
fn turn_index_yaml(index: &mut TurnIndex) -> Result<(String, Vec<TurnEntry>), PostProcessorError> {
    let mut moved_out = Vec::new();
    loop {
        let yaml = serde_yml::to_string(&*index).map_err(|e| {
            PostProcessorError::StorageError(format!("serialize turn-index.yaml: {e}"))
        })?;
        if yaml.len() as u64 <= MAX_TASK_YAML_BYTES / 4 * 3 || index.turns.len() <= 1 {
            return Ok((yaml, moved_out));
        }
        let excess = (index.turns.len() / 10).max(1);
        moved_out.extend(index.turns.drain(..excess));
    }
}

/// What Step 7 wrote, for Step 8: the task summary, the new turn entry, and the older
/// turns that gained a reference (7b.iv).
#[derive(Debug)]
struct TurnArtifacts {
    summary: Summary,
    entry: TurnEntry,
    referenced: Vec<u32>,
}

/// SAT-B (AC-45 / R12): read a YAML file with the [`MAX_TASK_YAML_BYTES`] size
/// cap. `None` on missing / oversize / unreadable — the caller starts fresh.
fn read_capped_yaml(path: &Path) -> Option<String> {
    // SAT-B audit r6 (symlink read-DoS fix): reject a symlinked yaml LEAF (so a
    // `turn-index.yaml -> /dev/zero` or outside-file symlink can't be followed),
    // and read through a `take(MAX+1)` bound so even a swapped / special file is
    // capped — `metadata().len()` of a special file like `/dev/zero` is 0 and
    // would pass a len-only check, then `read_to_string` would read unbounded.
    use std::io::Read as _;
    let lm = std::fs::symlink_metadata(path).ok()?;
    // Reject ANY non-regular leaf (audit r7): a symlink (escape), a FIFO / socket /
    // device (`File::open` + `read_to_string` on a writer-less FIFO would BLOCK and
    // hang the per-agent live turn), or a directory. Only a real regular file is read.
    if !lm.file_type().is_file() {
        eprintln!(
            "cap-memory post-processor: refusing non-regular yaml leaf {path:?}; starting fresh"
        );
        return None;
    }
    let f = std::fs::File::open(path).ok()?;
    let mut s = String::new();
    if f.take(MAX_TASK_YAML_BYTES + 1)
        .read_to_string(&mut s)
        .is_err()
    {
        eprintln!("cap-memory post-processor: read {path:?} failed/non-utf8; starting fresh");
        return None;
    }
    if s.len() as u64 > MAX_TASK_YAML_BYTES {
        eprintln!(
            "cap-memory post-processor: {path:?} exceeds {MAX_TASK_YAML_BYTES}-byte cap; starting fresh"
        );
        return None;
    }
    Some(s)
}

fn empty_turn_index() -> TurnIndex {
    TurnIndex {
        meta: TurnIndexMeta {
            last_epoch_turn: 0,
            last_epoch_at: String::new(),
        },
        turns: Vec::new(),
        epochs: Vec::new(),
    }
}

/// Load an existing `turn-index.yaml` (bounded + `validate_invariants`-checked)
/// or a fresh empty index. Oversize / parse-error / failed invariants ⇒ fresh
/// (logged) — a tampered workspace file cannot DoS or corrupt the live turn.
fn load_turn_index(path: &Path) -> TurnIndex {
    let Some(s) = read_capped_yaml(path) else {
        return empty_turn_index();
    };
    match serde_yml::from_str::<TurnIndex>(&s) {
        Ok(ti) => match ti.validate_invariants() {
            Ok(()) => ti,
            Err(e) => {
                eprintln!(
                    "cap-memory post-processor: {path:?} failed validate_invariants ({e}); starting fresh"
                );
                empty_turn_index()
            }
        },
        Err(e) => {
            eprintln!("cap-memory post-processor: {path:?} parse error ({e}); starting fresh");
            empty_turn_index()
        }
    }
}

fn default_summary() -> Summary {
    Summary {
        meta: SummaryMeta::default(),
        brief: String::new(),
        key_decisions: Vec::new(),
        findings: Vec::new(),
        open_questions: Vec::new(),
        current_state: String::new(),
        errors_and_corrections: Vec::new(),
        workflow: String::new(),
    }
}

/// Load an existing `summary.yaml` (bounded) or a fresh default.
fn load_summary(path: &Path) -> Summary {
    read_capped_yaml(path)
        .and_then(|s| serde_yml::from_str::<Summary>(&s).ok())
        .unwrap_or_else(default_summary)
}

/// Skeleton concrete impl of [`PostProcessorHook`]. Records each step's
/// execution into an `Arc<Mutex<Vec<String>>>` trace; the `components` field
/// is `None` for slice A trace-only default and `Some(...)` when wired for
/// real LLM extraction + reconciliation.
#[derive(Clone, Debug, Default)]
pub struct PostProcessor {
    trace: Arc<Mutex<Vec<String>>>,
    summary_calls: Arc<Mutex<u64>>,
    turn_index_calls: Arc<Mutex<u64>>,
    components: Option<Components>,
    /// What Step 0's last append left of each turn log ([`KnownLogs`]).
    known_logs: Arc<KnownLogs>,
}

impl PostProcessor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_components(components: Components) -> Self {
        Self {
            trace: Arc::new(Mutex::new(Vec::new())),
            summary_calls: Arc::new(Mutex::new(0)),
            turn_index_calls: Arc::new(Mutex::new(0)),
            components: Some(components),
            known_logs: Arc::default(),
        }
    }

    pub fn trace_snapshot(&self) -> Vec<String> {
        self.trace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn summary_calls(&self) -> u64 {
        *self
            .summary_calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn turn_index_calls(&self) -> u64 {
        *self
            .turn_index_calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn push(&self, label: &'static str) {
        self.trace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(label.to_string());
    }

    async fn step_1_collect_changes(
        &self,
        _agent_id: &str,
        _msg: &Message,
        _result: &ActionResult,
    ) -> Result<(), PostProcessorError> {
        self.push(STEP_1);
        Ok(())
    }

    /// Step 2: cooldown-gated batch LLM extraction with mechanical-digest
    /// fallback on `BatchExtractorError::LlmFailure`. Returns the extraction
    /// as a per-run local (NOT stored on `&self` — `PostProcessor` is shared
    /// via `Arc<dyn PostProcessorHook>` and concurrent run() calls must not
    /// alias). Trace label is pushed BEFORE any early-return so the canonical
    /// 9-step contract holds across all branches.
    async fn step_2_batch_llm_call(
        &self,
        agent_id: &str,
        msg: &Message,
        result: &ActionResult,
    ) -> Result<Option<Extraction>, PostProcessorError> {
        self.push(STEP_2);
        let Some(components) = &self.components else {
            return Ok(None);
        };
        let now = components.clock.now();
        if components.cooldown.is_cooling_down(agent_id, now) {
            // Cooldown active — skip the LLM call but still run the fallback
            // so Step 5 has consistent input. AC-09 partial-degrade contract.
            return Ok(Some(mechanical_digest_fallback(
                agent_id,
                msg,
                result,
                &*components.clock,
            )));
        }
        let ctx = ExtractionContext {
            agent_id,
            msg,
            result,
        };
        match components.extractor.extract(&ctx).await {
            Ok(extraction) => Ok(Some(extraction)),
            Err(BatchExtractorError::LlmFailure(_)) => {
                components.cooldown.record_failure(agent_id, now);
                Ok(Some(mechanical_digest_fallback(
                    agent_id,
                    msg,
                    result,
                    &*components.clock,
                )))
            }
            Err(BatchExtractorError::Invalid(e)) => Err(PostProcessorError::Invalid(e)),
        }
    }

    /// Step 3 (SAT-D): VLM/LLM description writeback + store-routing.
    /// `write_id` is the BARE cap-id bucket `recall` reads (resolved by `run`,
    /// same as Steps 5/7/8). With no `description_indexer` seam (the default)
    /// this is a documented no-op — the canonical writeback is the CLI
    /// `VlmDescriptionIndexer` (cap-memory has no cap-fs/cap-llm dep), so the
    /// `.meta.yaml` writeback (072/066) + MIME routing (071/217) happen inside
    /// the seam; here we route the returned description into the STORE so
    /// `MemoryStore::recall` surfaces it (073). See §3.8 note 20.
    async fn step_3_writeback_descriptions(
        &self,
        write_id: &str,
        extraction: Option<&Extraction>,
    ) -> Result<(), PostProcessorError> {
        self.push(STEP_3);
        let (Some(ex), Some(c)) = (extraction, &self.components) else {
            return Ok(());
        };
        let Some(indexer) = &c.description_indexer else {
            return Ok(()); // no seam ⇒ no-op (back-compat / AC-44 trace-only)
        };
        // DoS bound: `ex.descriptions` is LLM-produced. Each iteration does a
        // file read + an LLM/VLM round-trip + a `.meta.yaml` write, so cap the
        // per-turn fan-out defensively (the production cli extractor's schema
        // already bounds it to ≤64, but Step-3 must not trust that). Excess is
        // skipped + logged, never failing the turn.
        let total = ex.descriptions.len();
        if total > MAX_INDEXED_DESCRIPTIONS_PER_TURN {
            eprintln!(
                "cap-memory post-processor Step 3: capping description indexing at \
                 {MAX_INDEXED_DESCRIPTIONS_PER_TURN} of {total} (excess skipped)"
            );
        }
        for d in ex
            .descriptions
            .iter()
            .take(MAX_INDEXED_DESCRIPTIONS_PER_TURN)
        {
            let Some(idx) = indexer.index_description(write_id, &d.path).await else {
                continue; // rejected/private path, binary MIME, empty, or soft failure
            };
            // (vpath,content)-keyed idempotency on the NORMALIZED vpath
            // (alias-stable): skip only if an active entry already has this exact
            // content AND a FileRef source for the SAME vpath — avoids duplicate
            // accumulation on re-index of an unchanged file WITHOUT suppressing a
            // distinct file that happens to share a description.
            let dup = c
                .store
                .recall(write_id, &idx.description, 0)
                .iter()
                .any(|e| {
                    e.content == idx.description
                    && e.sources.iter().any(|s| {
                        matches!(s, MemorySource::FileRef { vpath, .. } if *vpath == idx.vpath)
                    })
                });
            if dup {
                continue;
            }
            let entry =
                build_file_description_entry(write_id, &idx.vpath, &idx.description, &*c.clock);
            // DIRECT insert (NOT reconcile): a file-description is per-file and
            // must not be content-similarity-superseded by a DIFFERENT file's
            // similar description. Best-effort — a per-file insert error (cap /
            // invariant) is logged and skipped, never failing the turn (and NOT
            // pushed to the trace: the canonical 9-step contract must hold).
            if let Err(e) = c.store.insert(write_id, entry) {
                eprintln!(
                    "cap-memory post-processor Step 3: description index insert skipped ({e:?})"
                );
            }
            // SYS-AC-073: the description is now recall-able via MemoryEntry.content.
        }
        Ok(())
    }

    async fn step_4_fs_dedup(
        &self,
        _agent_id: &str,
        _extraction: Option<&Extraction>,
    ) -> Result<(), PostProcessorError> {
        self.push(STEP_4);
        // SQLite content_index lookup deferred (waived_scope: MODULE-004 wiring).
        Ok(())
    }

    /// Step 5: reconciliation. For each `knowledge` entry, NORMALIZE its
    /// `agent_id` to the resolved `write_id` (the BARE cap-id write bucket —
    /// `MemoryStore::apply_action` rejects an entry whose `agent_id != caller`),
    /// then `Reconciler::reconcile` → `MemoryStore::apply_action` (Insert /
    /// Supersede / Skip). SAT-B: when `write_agent_id` is unset, `write_id ==`
    /// the `run()` agent_id, so the normalize is a no-op vs the pre-SAT-B
    /// behaviour (AC-10/AC-11 unaffected). `&ex.knowledge` is an immutable
    /// borrow, so each entry is cloned before its `agent_id` is set. A tag the
    /// model chose that reads as the store's provenance tag
    /// ([`crate::store::FROM_AGENT_TAG_PREFIX`], which only a hand-over sets) is
    /// dropped first, and the entry kept: the store would refuse the entry with
    /// it, and this step would end the turn's post-processing there.
    async fn step_5_memory_reconciliation(
        &self,
        write_id: &str,
        extraction: Option<&Extraction>,
    ) -> Result<(), PostProcessorError> {
        self.push(STEP_5);
        let (Some(ex), Some(components)) = (extraction, &self.components) else {
            return Ok(());
        };
        for entry in &ex.knowledge {
            let mut e = entry.clone();
            e.agent_id = write_id.to_string();
            e.tags.retain(|tag| {
                let reserved = crate::store::reads_as_handed_over(tag);
                if reserved {
                    eprintln!(
                        "cap-memory post-processor: dropping the tag {tag:?} of extracted entry \
                         {}: it reads as the provenance tag only a hand-over sets",
                        entry.id
                    );
                }
                !reserved
            });
            let action = components.reconciler.reconcile(write_id, &e);
            // SAT-C (068): inspect the action BEFORE it is moved into
            // `apply_action`, then increment the L6 ">=20 new entries"
            // watermark only for a real materialized row (Insert or Supersede,
            // NOT Skip) — both add a knowledge row / represent knowledge change.
            // Recorded only after `apply_action` succeeds (a cap-rejected Insert
            // `?`-returns before the increment). See §3.8 note 19(e).
            let counts_new = matches!(
                action,
                MemoryAction::Insert(_) | MemoryAction::Supersede { .. }
            );
            components.store.apply_action(write_id, action)?;
            if counts_new {
                components
                    .l6_trigger_state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .record_new_entry();
            }
        }
        Ok(())
    }

    async fn step_6_write_knowledge_jsonl(
        &self,
        _agent_id: &str,
        _extraction: Option<&Extraction>,
    ) -> Result<(), PostProcessorError> {
        self.push(STEP_6);
        // SAT-B: intentional no-op. The persistent `MemoryStore` (when opened
        // via `MemoryStore::open`) already owns `knowledge.jsonl` — Step 5's
        // `apply_action`/`insert` atomically append/rewrite it. A Step-6 append
        // here would DOUBLE-WRITE. SYS-AC-066's knowledge.jsonl half is delivered
        // by Step 5; Step 6 stays a no-op by design (see MODULE-011 §3.6).
        Ok(())
    }

    /// Step 7 (SAT-B / AC-45; PRD §11.4 7a/7b): when Step 0 logged the turn under a
    /// task directory, materialize a per-turn `Summary` + `TurnEntry` and atomically
    /// write `summary.yaml` + `turn-index.yaml` under `<tasks_root>/{task_id}/`. The
    /// entry locates the turn in the log and carries the features derived from it
    /// ([`fill_turn_features`]); the older turns it refers to gain a reference (7b.iv).
    /// The in-memory `summary_calls` / `turn_index_calls` counters are ALWAYS bumped
    /// (the slice-F pipeline-counter tests rely on this), independent of fs writes.
    /// Returns the materialized artifacts for Step 8 (or `None` when trace-only / no
    /// tasks root / a refused task id).
    async fn step_7_update_summary_and_turn_index(
        &self,
        write_id: &str,
        msg: &Message,
        extraction: Option<&Extraction>,
        logged: Option<&LoggedTurn>,
    ) -> Result<Option<TurnArtifacts>, PostProcessorError> {
        self.push(STEP_7);
        self.update_summary_inner();
        self.update_turn_index_inner();

        let Some(components) = &self.components else {
            return Ok(None);
        };
        // Step 0 resolved the task and its directory; without a tasks root, or for a
        // task id it refused, there is nothing to write.
        let Some(logged) = logged else {
            return Ok(None);
        };
        let Some(ex) = extraction else {
            return Ok(None);
        };
        let task_id = logged.task_id.clone();
        let turn_index_path = logged.task_dir.join(TASK_TURN_INDEX_FILENAME);
        let summary_path = logged.task_dir.join(TASK_SUMMARY_FILENAME);
        let ts = utc_now_string(&*components.clock);

        // ── turn-index.yaml (append one TurnEntry) ──
        let mut turn_index = load_turn_index(&turn_index_path);
        let mut entry = TurnEntry {
            turn: logged.turn,
            timestamp: ts.clone(),
            agent_id: write_id.to_string(),
            task_id: task_id.clone(),
            log_offset: LogOffset {
                start_line: 0,
                end_line: 0,
            },
            has_user_instruction: false,
            has_user_correction: false,
            has_tool_use: false,
            has_decision: false,
            importance: Importance::Normal,
            // digest + git fields filled by `apply_turn_digest`, the rest by
            // `fill_turn_features` below.
            digest: String::new(),
            collapsed_view: String::new(),
            git_commit: String::new(),
            git_diff_summary: String::new(),
            git_checkpoints: Vec::new(),
            reference_count: 0,
            content_identifiers: Vec::new(),
            read_file_versions: Vec::new(),
            tokens_digest: 0,
            tokens_collapse_excerpt: 0,
            tokens_l0_processed: 0,
        };
        // The gated path always has `Some(extraction)` (step_2 returns
        // `Ok(Some(..))` whenever components is Some — real or mechanical
        // fallback). `apply_turn_digest` sets the REAL digest (from the
        // extraction, or a deterministic mechanical fallback) + empty git fields.
        apply_turn_digest(&mut entry, ex, &GitAssociation::none());
        fill_turn_features(
            &mut entry,
            logged,
            msg,
            components.workspace_root.as_deref(),
        );
        entry.tokens_digest = tokens_from_bytes_u32(entry.digest.len());
        // 7b.iv: the older turns this turn refers to gain a reference.
        let referenced = bump_references(&mut turn_index.turns, &entry, &logged.prompt);
        turn_index.turns.push(entry.clone());
        let (mut ti_yaml, moved_out) = turn_index_yaml(&mut turn_index)?;
        if !moved_out.is_empty() {
            // The entries go to the archive before the index is written without them: a
            // failure in between leaves an entry in both, never in neither. When the archive
            // cannot take them, the index keeps them while it still reads back whole; past its
            // read cap they are dropped, and stderr says so.
            let archive = turn_index_path
                .with_file_name(crate::task_storage::TASK_TURN_INDEX_ARCHIVE_FILENAME);
            if let Err(e) = crate::task_storage::append_turn_index_archive(&archive, &moved_out) {
                eprintln!(
                    "cap-memory post-processor Step 7: archiving {} index entries of task {task_id:?} failed: {e}",
                    moved_out.len()
                );
                let dropped = moved_out.len();
                let mut whole = turn_index.clone();
                let mut turns = moved_out;
                turns.append(&mut whole.turns);
                whole.turns = turns;
                match serde_yml::to_string(&whole) {
                    Ok(yaml) if yaml.len() as u64 <= MAX_TASK_YAML_BYTES => ti_yaml = yaml,
                    _ => eprintln!(
                        "cap-memory post-processor Step 7: the index of task {task_id:?} cannot keep \
                         them under its {MAX_TASK_YAML_BYTES}-byte read cap; its {dropped} oldest \
                         entries are dropped"
                    ),
                }
            }
        }
        crate::persistence::atomic_write(&turn_index_path, ti_yaml.as_bytes())
            .map_err(|e| PostProcessorError::StorageError(e.to_string()))?;

        // ── summary.yaml (update _meta cursors) ──
        let mut summary = load_summary(&summary_path);
        summary.meta.task_id = task_id.clone();
        summary.meta.agent_id = write_id.to_string();
        if summary.meta.title.is_empty() {
            // Non-empty title — the DB rebuild scanner skips empty-title summaries.
            summary.meta.title = format!("Task {task_id}");
        }
        summary.meta.turns_total = summary.meta.turns_total.saturating_add(1);
        summary.meta.last_turn_at = ts.clone();
        summary.meta.last_updated = ts;

        // ── summary.yaml L4 brief (SYS-J-03 / SYS-AC-008) ──
        // Populate the rolling task brief from THIS turn's digest (`entry.digest` =
        // `build_turn_digest(ex)`, already computed by `apply_turn_digest` above). Gated on
        // the AC-28 brief-tier cadence helper `should_update_brief` (>= 3 turns since the
        // last refresh, or a Notable/Critical importance override) so the wired producer
        // MATCHES the speced + already-passed (AC-28/REQ-229) cadence. ALSO bootstrap the
        // brief on the first digest-producing turn (empty brief) so the L4 reader is not
        // starved before turn 3 — the cadence governs refresh frequency, not the initial
        // population. `last_brief_update` advances ONLY on an actual refresh (correct
        // `should_update_brief` cursor semantics). `entry.importance` is `Importance::Normal`
        // in Step-7 (importance derivation is a separate deferred slice), so only the cadence
        // / bootstrap legs are active here. Surfacing a non-empty brief lets the L4 reader
        // return it and the assembler render the `# Task Summary` section (skip-on-empty).
        let current_turn = summary.meta.turns_total;
        if !entry.digest.trim().is_empty()
            && (summary.brief.trim().is_empty()
                || summary.should_update_brief(current_turn, entry.importance))
        {
            summary.brief = entry.digest.clone();
            summary.meta.last_brief_update = current_turn;
        }

        let s_yaml = serde_yml::to_string(&summary).map_err(|e| {
            PostProcessorError::StorageError(format!("serialize summary.yaml: {e}"))
        })?;
        crate::persistence::atomic_write(&summary_path, s_yaml.as_bytes())
            .map_err(|e| PostProcessorError::StorageError(e.to_string()))?;

        Ok(Some(TurnArtifacts {
            summary,
            entry,
            referenced,
        }))
    }

    /// Step 0 (PRD §11.4 precondition — the turn log is on disk as soon as
    /// `handle-message` returns): log the turn to `<tasks_root>/{task_id}/
    /// llm-turns.jsonl` — the inbound message, then what the host recorded of the turn
    /// ([`TurnTranscriptSource`]), one line per message with its L0 annotation — and
    /// note the lines it occupies. The transcript is taken first, whatever happens
    /// next, so it can never be logged as another turn's. `None` when trace-only, with
    /// no tasks root, or for a task id Step 7 would refuse; a failed append is logged
    /// and leaves the turn's range `0..=0`. (No trace label: the 9-step trace contract
    /// is the PRD's Steps 1–9.)
    ///
    /// `failed`: the turn failed (`PostProcessorHook::turn_failed`). Its messages are logged,
    /// then [`FAILED_TURN_NOTE`], and nothing else is done with it.
    fn step_0_log_turn(&self, write_id: &str, msg: &Message, failed: bool) -> Option<LoggedTurn> {
        let components = self.components.as_ref()?;
        let transcript = components
            .transcript_source
            .as_ref()
            .map(|source| source.take_turn_transcript(write_id))
            .unwrap_or_default();
        let tasks_root = components.tasks_root.as_ref()?;
        let task_id = resolve_task_id(write_id, msg)?;
        let task_dir = confined_task_dir(tasks_root, &task_id)?;
        let next_indexed = load_turn_index(&task_dir.join(TASK_TURN_INDEX_FILENAME))
            .turns
            .last()
            .map(|t| t.turn.saturating_add(1))
            .unwrap_or(1);
        let mut logged = LoggedTurn::new(
            task_id,
            task_dir,
            next_indexed,
            prompt_from_payload(&msg.payload),
            transcript,
        );
        if failed {
            logged
                .messages
                .push(advance_shared_types::turn_log::TranscriptMessage::new(
                    "system",
                    FAILED_TURN_NOTE,
                ));
            logged
                .marks
                .push(advance_shared_types::turn_log::L0Mark::Keep);
        }
        let ts = utc_now_string(&*components.clock);
        let log = logged.task_dir.join(TURN_LOG_FILENAME);
        match append_turn_log_known(
            &self.known_logs,
            &log,
            next_indexed,
            &ts,
            &logged.messages,
            &logged.marks,
        ) {
            Ok((turn, range)) => {
                logged.turn = turn;
                logged.log_offset = range;
            }
            Err(e) => eprintln!(
                "cap-memory post-processor Step 0: logging turn {next_indexed} of task {:?} failed: {e}",
                logged.task_id
            ),
        }
        Some(logged)
    }

    fn update_summary_inner(&self) {
        let mut guard = self
            .summary_calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = guard.saturating_add(1);
    }

    fn update_turn_index_inner(&self) {
        let mut guard = self
            .turn_index_calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = guard.saturating_add(1);
    }

    /// Step 8 (SAT-B / AC-45/46): drive the SQLite sync seams from within `run`
    /// using the Step-7 artifacts, keyed by the bare `write_id`. With the
    /// default `StubEmbedder` these are infallible. A real embedder's
    /// `EmbedderError` (a failed embedding request) maps to `StorageError` (the
    /// `From` impl) and is returned only AFTER all three syncs ran: the turn row,
    /// the task row and the memory rows are written either way, the failed vector
    /// is simply absent. Last, a few older rows whose vector a query cannot use
    /// are embedded again ([`Components::heal_vectors`]) — after this turn's own
    /// rows, so they never wait on it. No Step-7 artifacts (trace-only /
    /// skipped) ⇒ push-only (preserves tests).
    async fn step_8_sqlite_sync(
        &self,
        write_id: &str,
        artifacts: Option<&TurnArtifacts>,
    ) -> Result<(), PostProcessorError> {
        self.push(STEP_8);
        let (Some(components), Some(artifacts)) = (&self.components, artifacts) else {
            return Ok(());
        };
        let turn_synced = components.sync_turn_index(write_id, &artifacts.entry).await;
        // 7b.iv → Step 8: the rows of the older turns that gained a reference.
        for turn in &artifacts.referenced {
            components.bump_turn_reference(write_id, &artifacts.entry.task_id, *turn);
        }
        let task_synced = components.sync_task_index(&artifacts.summary).await;
        components.sync_memory_index(write_id);
        let caught_up = components.heal_vectors(write_id).await;
        turn_synced?;
        task_synced?;
        caught_up?;
        Ok(())
    }

    /// Step 9 — L6 hot-path evaluation (AC-12). Pushes the canonical label
    /// BEFORE any early-return (Slice B 9-step contract). Trigger-fires →
    /// observable two-phase `begin_acquire` then `confirm_acquire` → emit
    /// `memory.l6_consolidation_due`. `AlreadyHeld` (another L6 in flight) →
    /// skip silently.
    async fn step_9_evaluate_l6(&self, agent_id: &str) -> Result<(), PostProcessorError> {
        self.push(STEP_9);
        let Some(c) = &self.components else {
            return Ok(());
        };
        let now = c.clock.now();
        let input = c
            .l6_trigger_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .to_input(now);
        if !c.trigger.should_trigger(&input).fired {
            return Ok(());
        }
        let ttl = Duration::from_secs(600);
        if let LeaseDecision::Acquired { token } = c.lease.begin_acquire(agent_id, now, ttl) {
            c.lease.confirm_acquire(agent_id, &token);
            // Slice D: pass the live lease token as PRD §15.4 `lease_id`.
            // The lease two-phase ORDERING (begin→confirm→emit) is
            // pre-existing slice-C / AC-13-`passed` behaviour and is
            // intentionally NOT changed here (MODULE-011 §3.8 note 8).
            c.l6_emitter.emit_consolidation_due(agent_id, &token);
            // SAT-C: dispatch into the L6 consolidation runnable on the LIVE
            // turn — a DIRECT in-process call (the EventBus exposes no native
            // subscribe). On success, mark the trigger as run so the next turn
            // does NOT re-consolidate (the default `last_l6_at==None`
            // HoursSinceLast leg would otherwise fire every turn); the lease is
            // held to its TTL (the Ok path does not release it), giving
            // single-flight (215 shape). On failure the adapter has already
            // emitted `component.error` and the runnable's Err-arm released the
            // lease, so `mark_l6_ran` is SKIPPED and the next trigger retries
            // (216 shape). See §3.8 note 19.
            if let Some(handler) = &c.l6_handler {
                if handler.dispatch(agent_id, &token).await {
                    c.l6_trigger_state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .mark_l6_ran(now);
                }
            }
        }
        Ok(())
    }

    fn reset_observers(&self) {
        self.trace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        *self
            .summary_calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = 0;
        *self
            .turn_index_calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = 0;
    }
}

/// Mechanical-digest fallback used by Step 2 when the LLM call fails OR the
/// cooldown window is active. Synthesizes a minimal `Extraction` (no LLM call)
/// satisfying `MemoryEntry::validate_invariants` by construction.
///
/// Round-13 adversarial-fix #9: the fallback content used to embed
/// `msg.payload.len()` and `result.actions.len()` — a side-channel that
/// disclosed sensitive payload sizes (e.g. PII document byte count) into the
/// persistent memory store, retrievable via `recall("mechanical-digest")`.
/// The content is now an opaque marker; observability of the failure path
/// belongs on MODULE-019 EventBus, not in the memory content.
///
/// Slice m011-mem-product: `created_at` now comes from the injected
/// [`crate::clock::Clock`] via the shared [`crate::clock::clock_now_rfc3339_z`]
/// helper (the SAME second-granularity `Z`-form the remember-handler uses),
/// replacing the hardcoded `"1970-01-01T00:00:00Z"` (the AC-42 follow-up
/// mechanical-digest half — see §3.6 `created_at` row / §3.8 note 16(c)). The
/// `Extraction.digest` is `None` here: the degraded path has no LLM-derived
/// turn digest, so AC-38's `build_turn_digest` synthesizes a mechanical
/// single-sentence digest downstream (T50-c).
fn mechanical_digest_fallback(
    agent_id: &str,
    _msg: &Message,
    _result: &ActionResult,
    clock: &dyn crate::clock::Clock,
) -> Extraction {
    let entry = MemoryEntry {
        id: Uuid::new_v4().to_string(),
        agent_id: agent_id.to_string(),
        entry_type: MemoryType::Fact,
        content: "mechanical-digest fallback (LLM unavailable)".to_string(),
        tags: vec!["mechanical-digest".into(), "fallback".into()],
        created_at: crate::clock::clock_now_rfc3339_z(clock),
        task_origin: None,
        is_active: true,
        superseded_by: None,
        status: MemoryStatus::Active,
        supersession_reason: None,
        cluster_id: None,
        sources: vec![],
    };
    Extraction {
        descriptions: Vec::<DescriptionUpdate>::new(),
        knowledge: vec![entry],
        digest: None,
    }
}

/// SAT-D Step-3: build a file-description `MemoryEntry` for the store so the
/// description is recall-able (073). `content` is the (already 4 KiB-bounded)
/// description; the `FileRef` source carries the NORMALIZED `vpath`. Provenance
/// (`commit_ish`/`blob_id`) is best-effort working-tree (the changed file may be
/// uncommitted mid-turn; recall keys on `content` only) — precise git-blob
/// staleness for VLM entries is a documented §3.6/§3.8 follow-up. `FileRef`'s
/// `validate_invariants` checks only `line_range` ordering, so the sentinels
/// pass. `agent_id` is set to `write_id` so `store.insert`'s caller-id check
/// passes and the entry lands in the bucket `recall(write_id, …)` reads.
fn build_file_description_entry(
    write_id: &str,
    vpath: &str,
    description: &str,
    clock: &dyn crate::clock::Clock,
) -> MemoryEntry {
    MemoryEntry {
        id: Uuid::new_v4().to_string(),
        agent_id: write_id.to_string(),
        entry_type: MemoryType::Fact,
        content: description.to_string(),
        tags: vec!["file-description".into()],
        created_at: crate::clock::clock_now_rfc3339_z(clock),
        task_origin: None,
        is_active: true,
        superseded_by: None,
        status: MemoryStatus::Active,
        supersession_reason: None,
        cluster_id: None,
        sources: vec![MemorySource::FileRef {
            agent_id: write_id.to_string(),
            vpath: vpath.to_string(),
            commit_ish: "working-tree".to_string(),
            blob_id: String::new(),
            line_range: None,
        }],
    }
}

/// Compatibility shim — production callers can synthesize a "now" SystemTime
/// without depending on `SystemTime::now()` directly (useful in tests).
#[allow(dead_code)]
fn now() -> SystemTime {
    SystemTime::now()
}

#[async_trait]
impl PostProcessorHook for PostProcessor {
    async fn run(
        &self,
        agent_id: &str,
        msg: &Message,
        result: &ActionResult,
    ) -> Result<(), PostProcessorError> {
        self.reset_observers();
        // SAT-B: resolve the BARE write id (colon-msg-id → bare-cap-id bucket fix).
        // A `None` override ⇒ write_id == the run() agent_id (preserves every
        // existing test where the id is already consistent).
        let write_id = self
            .components
            .as_ref()
            .and_then(|c| c.write_agent_id.as_deref())
            .unwrap_or(agent_id);
        let logged = self.step_0_log_turn(write_id, msg, false);
        self.step_1_collect_changes(agent_id, msg, result).await?;
        let extraction = self.step_2_batch_llm_call(agent_id, msg, result).await?;
        self.step_3_writeback_descriptions(write_id, extraction.as_ref())
            .await?;
        self.step_4_fs_dedup(write_id, extraction.as_ref()).await?;
        self.step_5_memory_reconciliation(write_id, extraction.as_ref())
            .await?;
        self.step_6_write_knowledge_jsonl(write_id, extraction.as_ref())
            .await?;
        let artifacts = self
            .step_7_update_summary_and_turn_index(
                write_id,
                msg,
                extraction.as_ref(),
                logged.as_ref(),
            )
            .await?;
        // Step 8 fails only on an embedding request (its rows are written either
        // way). Step 9 does not read the vector index, so that failure is reported
        // after Step 9 ran — it must not also cost the turn its L6 evaluation.
        let index_synced = self.step_8_sqlite_sync(write_id, artifacts.as_ref()).await;
        // Step 9 uses the BARE `write_id`, NOT the run() messaging agent_id
        // (SAT-C / audit r1 fix): now that Step-9 DISPATCHES into the L6
        // runnable, the runnable lists/commits the agent's MEMORY bucket — which
        // Steps 5/7/8 wrote under `write_id` (`root`), not the colon
        // messaging id (`agent:root`). Dispatching under the colon id would
        // consolidate an empty/wrong bucket while emitting l6_completed +
        // marking-ran. The lease/emit are also keyed by `write_id` so the
        // runnable's lease-loss gate (which sees `write_id`) stays consistent.
        // (When `write_agent_id` is unset, `write_id == agent_id`, so the
        // pre-SAT-C single-id behaviour + every existing test is preserved.)
        self.step_9_evaluate_l6(write_id).await?;
        index_synced
    }

    /// MODULE-011 Step 0 for a turn that failed (D3: every turn is logged): what the host
    /// recorded of it, then [`FAILED_TURN_NOTE`]. Steps 1–9 do not run, so it gets no digest
    /// and no index entry; the next turn is numbered after it.
    async fn turn_failed(&self, agent_id: &str, msg: &Message) {
        let write_id = self
            .components
            .as_ref()
            .and_then(|c| c.write_agent_id.as_deref())
            .unwrap_or(agent_id);
        let _ = self.step_0_log_turn(write_id, msg, true);
    }
}

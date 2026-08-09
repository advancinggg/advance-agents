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
use advance_shared_types::traits::EventBusEmit;
use async_trait::async_trait;
use uuid::Uuid;

use std::time::Duration;

use crate::clock::Clock;
use crate::cooldown::FailureCooldown;
use crate::embedder::{Embedder, EmbedderError, StubEmbedder};
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
    InMemorySqliteIndex, MemoryIndexRow, SqliteIndex, TaskIndexRow, TurnIndexRow,
};
use crate::store::MemoryStore;
use crate::summary::{Summary, SummaryMeta};
use crate::task_storage::{TASK_SUMMARY_FILENAME, TASK_TURN_INDEX_FILENAME};
use crate::turn_index::{
    apply_turn_digest, GitAssociation, Importance, LogOffset, TurnEntry, TurnIndex, TurnIndexMeta,
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
    // methods from `PostProcessor::run` Step 8 (when an fs_root is configured);
    // tests also drive these seams directly. See MODULE-011 §3.6 / §3.8 note 12. ──
    pub sqlite_index: Arc<dyn SqliteIndex + Send + Sync>,
    pub embedder: Arc<dyn Embedder + Send + Sync>,
    // ── Slice G (m011-slice-g): L6 cursor store shared between Step-5a flush
    // (via `L6Runnable.cursor_store`) and WIT `rollback-memory` reset (via
    // `RollbackMemoryHandler.cursor_store`). See AC-18 cap-memory-half closure
    // in §3.8 note 13 + the cursor-store-sharing HARD REQUIREMENT in §3.6. ──
    pub cursor_store: Arc<L6CursorStore>,
    // ── Slice satB-postproc (SAT-B): the cap-memory memory root
    // (= `<workspace>/.agent/memory`) for Step-7 on-disk writeback. `None`
    // (the default for `with_l6_defaults` / `wired`) keeps Steps 7/8 on the
    // trace-only path so the rootless in-memory test suite is unaffected; the
    // composition root sets it via `with_fs_root`. ──
    pub fs_root: Option<PathBuf>,
    // ── Slice satB-postproc (SAT-B): the BARE cap id the post-processor writes
    // under (store/index/file ops). `run()` receives the COLON messaging id
    // (`agent:default`) but the shared `MemoryStore`/WIT handlers key the write
    // bucket by the bare cap id (`default-agent`); the two id grammars are
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
            .field("cursor_store", &"<L6CursorStore>")
            .field("fs_root", &self.fs_root)
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
            // Slice G (m011-slice-g): L6 cursor store seam default.
            // Signature UNCHANGED — body-only default-injection (slice-F
            // precedent). Future runtime-assembly slice MUST share this Arc
            // with L6Runnable::new's `cursor_store` arg — see the
            // "Cursor-store sharing" rustdoc block on this method.
            cursor_store: Arc::new(L6CursorStore::new()),
            // Slice satB-postproc: write-path seam defaults. Body-only injection
            // (slice-F/G precedent) — signature UNCHANGED. `None` ⇒ trace-only
            // Steps 7/8 + run()-agent_id writes (rootless tests unaffected).
            fs_root: None,
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
            // Slice G (m011-slice-g): L6 cursor store seam default.
            // Signature UNCHANGED — body-only default-injection. Future
            // runtime-assembly slice MUST share this Arc with L6Runnable::new's
            // `cursor_store` arg per the # Cursor-store sharing rustdoc above.
            cursor_store: Arc::new(L6CursorStore::new()),
            // Slice satB-postproc: write-path seam defaults (see with_l6_defaults).
            // The composition root sets these via with_fs_root / with_write_agent_id.
            fs_root: None,
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
    // Composition root: `Components::wired(..).with_fs_root(..).with_sqlite_index(..).with_write_agent_id(..)`.
    // ────────────────────────────────────────────────────────────────────

    /// SAT-B (AC-45): set the cap-memory memory root (`<workspace>/.agent/memory`)
    /// that Step 7 writes `summary.yaml` / `turn-index.yaml` under
    /// (`<fs_root>/tasks/{task_id}/`). Absent ⇒ Steps 7/8 stay trace-only.
    pub fn with_fs_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.fs_root = Some(root.into());
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
    // keyed by the bare `write_id`. When no `fs_root` is configured (the
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
        let text = format!("{}\n{}", turn.digest, turn.collapsed_view);
        let embedding = self.embedder.embed(&text).await?;
        self.sqlite_index.upsert_turn(TurnIndexRow {
            agent_id: agent_id.to_owned(),
            task_id: turn.task_id.clone(),
            turn: turn.turn,
            digest: turn.digest.clone(),
            embedding,
            reference_count: turn.reference_count,
            updated_at: utc_now_string(&*self.clock),
        });
        Ok(())
    }

    /// Slice F (AC-27, REQ-230): upsert a [`TaskIndexRow`] from a [`Summary`].
    /// `brief_embedding` is recomputed via [`Embedder::embed`] ONLY if
    /// `summary.brief` differs from the previously-stored row's
    /// `brief_snapshot` (string equality — deterministic substitute for
    /// semantic similarity in the absence of a real embedder; see
    /// MODULE-011 §3.8 note 12 (d)). On first-write OR on textual change the
    /// embedding is recomputed; on no-change the previously-stored embedding
    /// is preserved verbatim (Option<Vec<f32>> clone).
    ///
    /// **In-memory-stub posture**: like [`bump_turn_reference`], the brief-
    /// change gate spans two lock acquisitions (`get_task` then `upsert_task`).
    /// Concurrent `sync_task_index` calls for the same `task_id` could
    /// theoretically clobber each other's brief snapshot. In production the
    /// post-processor §2.11 serialization (1-per-agent) eliminates this for
    /// per-agent tasks; cross-agent task sharing (PRD §11.3.3 — tasks span
    /// agents) is the responsibility of the deferred rusqlite adapter which
    /// will use SQL `INSERT ON CONFLICT` / `UPSERT` semantics. See §3.6 row
    /// "In-memory `SqliteIndex` stub get-modify-upsert race posture".
    ///
    /// **Tenant-scoping**: `summary.meta.agent_id` is stored verbatim into
    /// the row but the task table is keyed by `task_id` alone (per PRD
    /// §11.3.3 — tasks span agents). `list_tasks_for_agent` filters by
    /// `agent_id` for convenience. The deferred runtime-assembly slice MUST
    /// ensure `summary.meta.agent_id` is populated by the trusted agent-loop
    /// driver (not by guest-controlled WIT calls) before this method is
    /// reachable — see §3.6 row "Task-table `agent_id` filtering vs
    /// tenant-isolation posture".
    pub async fn sync_task_index(&self, summary: &Summary) -> Result<(), EmbedderError> {
        let prev = self.sqlite_index.get_task(&summary.meta.task_id);
        let brief_changed = prev
            .as_ref()
            .map(|r| r.brief_snapshot != summary.brief)
            .unwrap_or(true);
        let brief_embedding = if brief_changed {
            Some(self.embedder.embed(&summary.brief).await?)
        } else {
            prev.as_ref().and_then(|r| r.brief_embedding.clone())
        };
        self.sqlite_index.upsert_task(TaskIndexRow {
            task_id: summary.meta.task_id.clone(),
            agent_id: summary.meta.agent_id.clone(),
            last_turn_at: summary.meta.last_turn_at.clone(),
            turns_total: summary.meta.turns_total,
            updated_at: utc_now_string(&*self.clock),
            brief_snapshot: summary.brief.clone(),
            brief_embedding,
        });
        Ok(())
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
            // CRITICAL: do NOT recompute embedding here.
            self.sqlite_index.upsert_turn(row);
            true
        } else {
            false
        }
    }
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

/// SAT-B (AC-45 / D4): validate a guest-controllable task-id path SEGMENT.
/// Returns `Some(clean)` only for a single safe path component; rejects empty,
/// `.`/`..`, a leading `.`, any `/`/`\`/NUL, or an absolute/multi-component
/// form. A rejected value is NEVER silently redirected — Step 7 skips the write.
fn sanitize_task_segment(raw: &str) -> Option<String> {
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

/// SAT-B (AC-45 / D4 / W3): compose `<fs_root>/tasks/{task_id}` and confine it
/// under `fs_root` against symlink escape. `task_id` MUST already be sanitized
/// (single safe segment). Creates the dir (so the atomic write lands), rejects a
/// symlinked task dir, and asserts the canonicalized dir stays under the
/// canonicalized `fs_root`. Returns `None` (write skipped) on any breach.
///
/// Residual TOCTOU: a check-then-write window remains; full elimination needs
/// `openat`/`O_NOFOLLOW` descriptor-relative I/O — out of scope for a single
/// sanitized segment under the agent's own `.agent/memory` (documented at the gate).
fn confined_task_dir(fs_root: &Path, task_id: &str) -> Option<PathBuf> {
    let tasks = fs_root.join("tasks");
    // Audit r7: reject a pre-planted `tasks` PARENT symlink BEFORE create_dir_all
    // (else `create_dir_all` would mkdir through it, outside fs_root). The
    // canonical `starts_with` check below is the backstop for any deeper symlink;
    // a concurrent post-canonicalize parent swap remains the documented TOCTOU
    // residual (full closure needs descriptor-relative openat/mkdirat — out of scope).
    if std::fs::symlink_metadata(&tasks)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        eprintln!("cap-memory post-processor: refusing symlinked `tasks` parent {tasks:?}; skipping write");
        return None;
    }
    if let Err(e) = std::fs::create_dir_all(&tasks) {
        eprintln!("cap-memory post-processor: create tasks dir {tasks:?} failed: {e}");
        return None;
    }
    let dir = tasks.join(task_id);
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
    // realpath of fs_root (catches any symlink in the chain that escapes).
    let (Ok(canon_root), Ok(canon_dir)) = (fs_root.canonicalize(), dir.canonicalize()) else {
        eprintln!("cap-memory post-processor: canonicalize failed for {dir:?}; skipping write");
        return None;
    };
    if !canon_dir.starts_with(&canon_root) {
        eprintln!(
            "cap-memory post-processor: task dir {canon_dir:?} escapes fs_root {canon_root:?}; skipping write"
        );
        return None;
    }
    Some(dir)
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
    /// borrow, so each entry is cloned before its `agent_id` is set.
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

    /// Step 7 (SAT-B / AC-45): when an `fs_root` is configured, materialize a
    /// per-turn `Summary` + `TurnEntry` and atomically write `summary.yaml` +
    /// `turn-index.yaml` under `<fs_root>/tasks/{task_id}/`. The in-memory
    /// `summary_calls` / `turn_index_calls` counters are ALWAYS bumped (the
    /// slice-F pipeline-counter tests rely on this), independent of fs writes.
    /// task_id is resolved THREE-WAY from `msg.context.task_id`: absent ⇒ derive
    /// `_agent-{write_id}`; present + valid ⇒ use it; present + malicious ⇒ SKIP
    /// the write (never redirect). Returns the materialized artifacts for Step 8
    /// (or `None` when trace-only / no fs_root / skipped task_id).
    async fn step_7_update_summary_and_turn_index(
        &self,
        write_id: &str,
        msg: &Message,
        extraction: Option<&Extraction>,
    ) -> Result<Option<(Summary, TurnEntry)>, PostProcessorError> {
        self.push(STEP_7);
        self.update_summary_inner();
        self.update_turn_index_inner();

        let Some(components) = &self.components else {
            return Ok(None);
        };
        let Some(fs_root) = components.fs_root.as_ref() else {
            return Ok(None);
        };
        let Some(ex) = extraction else {
            return Ok(None);
        };

        // THREE-WAY task_id resolution (D3 / Codex W2): distinguish true absence
        // (derive a per-agent default partition) from a present-but-malicious
        // value (SKIP — never silently redirect under `_agent-*`).
        let task_id = match msg.context.as_ref().and_then(|c| c.task_id.clone()) {
            None => match sanitize_task_segment(write_id) {
                Some(s) => format!("_agent-{s}"),
                None => {
                    eprintln!(
                        "cap-memory post-processor Step 7: write_id {write_id:?} unsanitizable for a default task partition; skipping on-disk write"
                    );
                    return Ok(None);
                }
            },
            Some(raw) => match sanitize_task_segment(&raw) {
                Some(safe) => safe,
                None => {
                    eprintln!(
                        "cap-memory post-processor Step 7: rejecting malicious task_id {raw:?} (NOT redirected); skipping on-disk write"
                    );
                    return Ok(None);
                }
            },
        };

        let Some(task_dir) = confined_task_dir(fs_root, &task_id) else {
            return Ok(None);
        };
        let turn_index_path = task_dir.join(TASK_TURN_INDEX_FILENAME);
        let summary_path = task_dir.join(TASK_SUMMARY_FILENAME);
        let ts = utc_now_string(&*components.clock);

        // ── turn-index.yaml (append one TurnEntry) ──
        let mut turn_index = load_turn_index(&turn_index_path);
        let next_turn = turn_index
            .turns
            .last()
            .map(|t| t.turn.saturating_add(1))
            .unwrap_or(1);
        let mut entry = TurnEntry {
            turn: next_turn,
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
            // digest + git fields filled by `apply_turn_digest` below.
            digest: String::new(),
            collapsed_view: String::new(),
            git_commit: String::new(),
            git_diff_summary: String::new(),
            git_checkpoints: Vec::new(),
            reference_count: 0,
            // Honest empty/zero stubs for the deferred-posture fields (no producer
            // from the 4 inputs — slice-A "schema scaffold, fields deferred" posture).
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
        turn_index.turns.push(entry.clone());
        let ti_yaml = serde_yml::to_string(&turn_index).map_err(|e| {
            PostProcessorError::StorageError(format!("serialize turn-index.yaml: {e}"))
        })?;
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

        Ok(Some((summary, entry)))
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
    /// default `StubEmbedder` these are infallible; a future real-embedder
    /// `EmbedderError` maps to `StorageError` via `?` (the `From` impl). No
    /// Step-7 artifacts (trace-only / skipped) ⇒ push-only (preserves tests).
    async fn step_8_sqlite_sync(
        &self,
        write_id: &str,
        artifacts: Option<&(Summary, TurnEntry)>,
    ) -> Result<(), PostProcessorError> {
        self.push(STEP_8);
        let (Some(components), Some((summary, turn_entry))) = (&self.components, artifacts) else {
            return Ok(());
        };
        components.sync_turn_index(write_id, turn_entry).await?;
        components.sync_task_index(summary).await?;
        components.sync_memory_index(write_id);
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
        self.step_1_collect_changes(agent_id, msg, result).await?;
        let extraction = self.step_2_batch_llm_call(agent_id, msg, result).await?;
        // SAT-B: resolve the BARE write id (colon-msg-id → bare-cap-id bucket fix).
        // A `None` override ⇒ write_id == the run() agent_id (preserves every
        // existing test where the id is already consistent).
        let write_id = self
            .components
            .as_ref()
            .and_then(|c| c.write_agent_id.as_deref())
            .unwrap_or(agent_id);
        self.step_3_writeback_descriptions(write_id, extraction.as_ref())
            .await?;
        self.step_4_fs_dedup(write_id, extraction.as_ref()).await?;
        self.step_5_memory_reconciliation(write_id, extraction.as_ref())
            .await?;
        self.step_6_write_knowledge_jsonl(write_id, extraction.as_ref())
            .await?;
        let artifacts = self
            .step_7_update_summary_and_turn_index(write_id, msg, extraction.as_ref())
            .await?;
        self.step_8_sqlite_sync(write_id, artifacts.as_ref())
            .await?;
        // Step 9 uses the BARE `write_id`, NOT the run() messaging agent_id
        // (SAT-C / audit r1 fix): now that Step-9 DISPATCHES into the L6
        // runnable, the runnable lists/commits the agent's MEMORY bucket — which
        // Steps 5/7/8 wrote under `write_id` (`default-agent`), not the colon
        // messaging id (`agent:default`). Dispatching under the colon id would
        // consolidate an empty/wrong bucket while emitting l6_completed +
        // marking-ran. The lease/emit are also keyed by `write_id` so the
        // runnable's lease-loss gate (which sees `write_id`) stays consistent.
        // (When `write_agent_id` is unset, `write_id == agent_id`, so the
        // pre-SAT-C single-id behaviour + every existing test is preserved.)
        self.step_9_evaluate_l6(write_id).await?;
        Ok(())
    }
}

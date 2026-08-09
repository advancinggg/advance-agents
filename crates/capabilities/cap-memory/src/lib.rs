//! cap-memory — MODULE-011 memory-system.
//!
//! Core surfaces:
//! - `agent-memory` WIT host bindings (5 host fns: `remember` / `recall` /
//!   `forget` / `recall-at` / `rollback-memory`) registered via
//!   [`host_fn::register_agent_memory`] under capability `"memory"` /
//!   namespace `"advance:runtime/agent-memory@0.1.0"`.
//! - Memory write/read main flow: [`store::MemoryStore`] (in-memory `new()` /
//!   persistent `open()` over per-agent `knowledge.jsonl`; both
//!   **retention-bounded** — see `store.rs` / MODULE-011 §2.7) +
//!   [`reconcile::Reconciler`] with the deterministic four-branch `MemoryAction`
//!   algebra (`Insert` / `Skip` / `Supersede{Refinement}` / `Supersede{Merge}`).
//! - LLM extraction pipeline: post-processor Step 2 via the internal
//!   [`extractor::BatchExtractor`] trait + [`cooldown::FailureCooldown`], with a
//!   mechanical-digest fallback on `LlmFailure` (AC-09 partial degrade).
//! - L6 cross-task consolidation ([`l6`]), the `SqliteIndex` seam
//!   ([`sqlite_index`] in-memory stub + [`sqlite_index_rusqlite`] durable), and
//!   skill-candidate production ([`skill_candidate`]).
//!
//! The internal traits [`extractor::BatchExtractor`] /
//! [`reconcile::SimilarityIndex`] / [`clock::Clock`] stay INSIDE this crate —
//! NOT promoted to `shared-types`. ARCHITECTURE.md §6.1 contract registry is
//! unchanged (CONTRACT-100 already declared).

pub mod clock;
pub mod cooldown;
pub mod embedder;
pub mod events;
pub mod extractor;
pub mod host_fn;
pub mod knowledge;
pub mod l6;
pub mod persistence;
pub mod post_processor;
pub mod reconcile;
pub mod rollback;
pub mod search_ingest;
pub mod skill_candidate;
pub mod sqlite_index;
pub mod sqlite_index_rusqlite;
pub mod store;
pub mod summary;
pub mod task_storage;
pub mod turn_index;
pub mod wit_error;
pub mod wit_impl;

pub use clock::{clock_now_rfc3339_z, Clock, MutableClock, SystemClock};
pub use cooldown::{FailureCooldown, DEFAULT_COOLDOWN_SECS};
pub use embedder::{Embedder, EmbedderError, StubEmbedder, STUB_EMBEDDING_DIM};
pub use events::{
    l6_completed_event, l6_consolidation_due_event, memory_forget_event, memory_recall_at_event,
    memory_recall_event, memory_remember_event, memory_rollback_event, noop_bus, preview,
    NoopEventBus, MEMORY_FORGET, MEMORY_L6_COMPLETED, MEMORY_L6_CONSOLIDATION_DUE, MEMORY_RECALL,
    MEMORY_RECALL_AT, MEMORY_REMEMBER, MEMORY_ROLLBACK,
};
pub use extractor::{
    BatchExtractor, BatchExtractorError, DescriptionUpdate, Extraction, ExtractionContext,
    StubBatchExtractor,
};
pub use host_fn::{
    register_agent_memory, register_agent_memory_with_git,
    register_agent_memory_with_git_and_policy, CAPABILITY, NAMESPACE,
};
pub use knowledge::{
    Freshness, LineRange, MemoryEntry, MemoryError, MemorySource, MemoryStatus, MemoryType,
    SupersessionReason,
};
pub use l6::{
    compute_health_snapshot, list_contested, list_orphaned, list_partial_stale, should_synthesize,
    BatchIdSource, ClusterAssignment, ClusterClassification, ComponentFinished, EventBusL6Emitter,
    FailingCommitter, FileBlobResolver, FixedBatchIdSource, InMemoryCommitter, InMemoryEmitter,
    InMemoryLeaseStore, InMemoryStalenessProbe, KnowledgeMap, KnowledgeMapError,
    KnowledgeMapTaskSynthesis, KnowledgeMapTopic, L6ClassificationInput, L6ClassificationOutput,
    L6Classifier, L6ClusterBuilder, L6CommitError, L6Committer, L6CompletedPayload, L6CursorStore,
    L6Delta, L6Emitter, L6Runnable, L6TriggerEvaluator, L6TriggerInput, L6TriggerState,
    L6TriggerThresholds, LeaseDecision, LeaseState, LeaseStore, ResolverStalenessProbe,
    SkillHealthFile, SkillHealthWriteError, SkillHealthWriter, SkillHealthYamlEntry,
    StaleDetectionReport, StaleStateSnapshot, StalenessJudgment, StalenessProbe, StubL6Classifier,
    StubSynthesisGenerator, Synthesis, SynthesisGate, SynthesisGateResult, SynthesisGenerator,
    SynthesisInput, TaskRef, TriggerCond, TriggerOutcome, UuidBatchIdSource, L6_CANONICAL_STEPS,
    SKILL_HEALTH_FILENAME,
};
pub use persistence::{
    KnowledgeJsonlStore, PersistError, DEFAULT_MAX_INACTIVE_BYTES_PER_AGENT,
    DEFAULT_MAX_INACTIVE_PER_AGENT, KNOWLEDGE_JSONL_FILENAME, MAX_LINE_BYTES,
};
pub use post_processor::{
    Components, DescriptionIndexer, IndexedDescription, L6Dispatch, PostProcessor,
};
pub use reconcile::{
    InMemorySimilarityIndex, MemoryAction, Reconciler, SimilarityIndex, DEFAULT_THRESHOLD,
};
pub use rollback::{MemoryGitRestore, ROLLBACK_GIT_PATHS};
pub use search_ingest::{memory_search_docs, MemorySearchDoc};
pub use skill_candidate::{
    compute_candidate_id, Resolution, SkillCandidate, SkillCandidateError, SkillCandidateEvent,
    SkillCandidateStore, SKILL_CANDIDATES_FILENAME,
};
pub use sqlite_index::{
    InMemorySqliteIndex, MemoryIndexRow, SqliteIndex, TaskIndexRow, TurnIndexRow,
    MAX_INDEX_ROWS_PER_TABLE,
};
pub use sqlite_index_rusqlite::{RusqliteSqliteIndex, SqliteIndexError};
pub use store::{
    ForgetError, L6JournalEntry, L6JournalField, MemoryId, MemoryStore,
    DEFAULT_MAX_ACTIVE_PER_AGENT, MAX_ENTRY_BYTES,
};
pub use summary::{Confidence, Correction, Finding, KeyDecision, Summary, SummaryMeta};
pub use task_storage::{
    TASK_DECOMPOSITION_FILENAME, TASK_LLM_TURNS_FILENAME, TASK_STORAGE_DIR_TEMPLATE,
    TASK_STORAGE_FILES, TASK_STORAGE_OPTIONAL_FILES, TASK_STORAGE_REQUIRED_FILES,
    TASK_SUMMARY_FILENAME, TASK_TURN_INDEX_FILENAME,
};
pub use turn_index::{
    apply_turn_digest, build_turn_digest, CorrectionDrift, Epoch, GitAssociation, Importance,
    LogOffset, PreferenceSignal, ReadFileVersion, RecurringPattern, TurnEntry, TurnIndex,
    TurnIndexMeta, MECHANICAL_TURN_DIGEST,
};
pub use wit_error::{wit_memory_error_to_val, WitMemoryError};

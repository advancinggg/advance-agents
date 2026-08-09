//! MODULE-010 context-engine — Slices A + B.
//!
//! **Slice A** delivered: [`ContextAssemblerImpl`] (CONTRACT-090) 4-tier
//! scaffolding with Tier 2 AC-18 unified `# Available Tools` view, the
//! [`WarningQueue`] inject_tier3_warning storage, the Slice-A local
//! [`HostFnInventoryReader`], two cache-breakpoint markers (AC-05), and
//! AC-01 statelessness (no provider crate dep).
//!
//! **Slice B** adds:
//! - [`unified_search`] — AC-02 coordinator (`UnifiedSearchCoordinator`):
//!   embedding precompute + §1.3.1 cross-task turn filter over
//!   [`ports::UnifiedSearchPort`].
//! - [`task_router`] — AC-03/04 CONTRACT-091 `TaskRouter`: semantic routing,
//!   finite-value hardening (`embed` fail / non-finite → `EmbeddingFailed`,
//!   not `NewTask`), `auto:` exclusion, ambiguity tie-break by `last_turn_at`
//!   (`Some` precedes `None`) → light-LLM fallback. `TaskRoutingDecision` /
//!   `ContextError` are §1.3.2-named-but-upstream-undefined (locally
//!   materialized — see MODULE-010 §3.6 B2).
//! - [`l0_compress`] — AC-07 pure 3-step compression over
//!   `L0Entry { turn_id }`.
//! - [`knowledge_map`] — AC-16 Tier 1b ⑨ section with the 3 spec caps +
//!   documented deterministic drop-order.
//! - [`tier1`] — Tier 1a sanitized AGENTS.md identity slot + Tier 1b
//!   knowledge-map slot.
//! - [`tier2_delegates`] — AC-19 Tier 2 ⑬ "Available Delegates"
//!   (`AgentKind::Sub` only).
//! - [`ports`] — the 6 crate-local async dependency-inversion ports + data
//!   carriers (Slice-A `HostFnInventoryReader` precedent; see MODULE-010
//!   §3.6 / §3.8).
//!
//! **Slice C** adds:
//! - [`retention_rerank`] — REQ-238 AC-10/11 retention-rerank adapter:
//!   `rerank_by_retention` over the crate-local `RetentionScorer`
//!   **CONTRACT-031 `Recall::retention_score` stand-in** (no local formula —
//!   the weights stay owned by MODULE-004 §1.4.3; query-time, no cached
//!   aggregate; explicit finite/non-finite partition). Exported +
//!   code-audit-tested but NOT wired into `assemble()`'s live history feed
//!   (`LlmMessage` has no retention metadata — Slice-B `UnifiedSearchCoordinator`
//!   non-wired precedent; user-accepted scope 2026-05-18; MODULE-010 §3.6
//!   Slice-C (d)/(f)).
//! - [`tier3`] — REQ-239 AC-09 4-mode progressive loading:
//!   `select_progressive_mode` (§1.3.5 bands) + `recent_l0_turns` (5/3/1/0) +
//!   `model_context_window` (fail-safe-small `8_192` default, no test-only
//!   entries) + `response_reserve` + `bound_tier3_turns`, live-wired into
//!   [`assembler`]'s Tier-3 mode-select.
//!
//! Every **Slice-B-introduced untrusted description / identity / capability
//! string** entering the assembled prompt — AGENTS.md identity (Tier 1a),
//! knowledge-map topics/syntheses (Tier 1b), Tier 2 tool-view names/args/
//! descriptions (AC-18), Delegate name + capability summaries (Tier 2 ⑬,
//! AC-19) — is routed through the single shared `pub(crate)`
//! `tier2::sanitize_description` Trojan-Source defense (no divergent
//! sanitizer copy). **Scope boundary (honest)**: Tier 3 user/assistant turn
//! content (`AssemblyContext.turn_buffer` and `AssemblyContext.prompt`) is
//! NOT sanitized — it is the LLM's own conversation history / current user
//! query, treated as in-scope content rather than rendered metadata.
//! Sanitizing it would risk destroying semantic content (legitimate code
//! snippets containing literals that look like sentinels, BiDi-bearing
//! natural-language text the user intentionally included, etc.). A future
//! slice may add source-aware sanitization at the user-message ingress if
//! the threat model requires it; until then, prompt-injection at the Tier-3
//! user-message layer is out of MODULE-010's defense scope (it belongs to
//! the channel / transport layer that produced the message).
//!
//! AC-01 statelessness is still enforced by the crate's deliberate absence of
//! any provider crate dep — `tests/stateless.rs::cargo_manifest_excludes_provider_crates`
//! greps `Cargo.toml`. The 6 Slice-B ports are pure-trait deps; no provider /
//! HTTP / TLS crate is added.

pub mod assembler;
pub mod boundary_marker;
pub mod corpus_ingest;
pub mod inventory;
pub mod knowledge_map;
pub mod knowledge_map_reader;
pub mod l0_compress;
pub mod ports;
pub mod processing_pipeline;
pub mod recall_embedding;
pub mod recall_section;
pub mod retention_rerank;
pub mod sanitize;
pub mod staleness;
pub mod task_router;
pub mod tier1;
pub mod tier2;
pub mod tier2_decomposition;
pub mod tier2_delegates;
pub mod tier2_skills;
pub mod tier3;
pub mod turn_embed;
pub mod unified_search;
pub mod vector_search;
pub mod warning_queue;

pub use assembler::{ContextAssemblerImpl, INPUT_VALIDATION_PREFIX};
pub use inventory::{HostFnEntry, HostFnInventoryReader};
pub use knowledge_map::{
    build_knowledge_map_section, KNOWLEDGE_MAP_MAX_TOKENS, MAX_TASK_SYNTHESES, MAX_TOPICS,
};
pub use l0_compress::{l0_compress, L0Action, L0Entry, L0Kind};
pub use ports::{
    AgentIdentityReader, ContentHit, DecompositionReader, EmbeddingPort, KnowledgeMap,
    KnowledgeMapReader, KnowledgeTopic, LightLlmFallbackPort, MemoryHit, PortError,
    SkillSummaryEntry, SkillSummaryReader, SubtaskView, TaskHit, TaskIndexPort, TaskSynthesis,
    TurnHit, UnifiedSearchPort, UnifiedSearchResult,
};
// Slice D — new ports + carriers (AC-06 / AC-08 / AC-17).
pub use ports::{
    BlobId, CheckedTurn, DigestOnlyView, EpochSummary, GitBlobReader, GlobalMemoryRecord,
    L2DigestReader, L3EpochReader, L4TaskSummaryReader, L5SynthesisReader, L6ConsolidationReader,
    MultiLevelContextDigest, StalenessVerdict, SynthesisView, TaskSummaryView, Tier45ContextRecord,
    TurnCollapsedView, TurnDigestForEmbed, TurnIndexEntry, TurnIndexSqliteWriter,
    TurnIndexYamlWriter, TurnReadFileVersions, TurnView, VectorHit, VectorIndexReader,
};
// Slice D — new module public surfaces.
pub use boundary_marker::layer2_wrap;
pub use processing_pipeline::{coordinate_processing, MultiLevelReaders, ProcessingError};
pub use retention_rerank::{rerank_by_retention, RerankItem, RetentionScorer, TurnDigestView};
pub use sanitize::{attach_flags_to_record, layer1_flag};
pub use staleness::{check_and_demote, is_turn_stale, StalenessCheckError, MAX_TRACKED_PATHS};
pub use task_router::{
    ContextError, TaskRouter, TaskRoutingDecision, AMBIGUITY_GAP, TASK_MATCH_THRESHOLD,
};
pub use tier1::{build_tier1a, build_tier1b};
pub use tier2::{assemble_unified, format_available_tools_section, UnifiedToolRecord};
pub use tier2_decomposition::format_active_decomposition_section;
pub use tier2_delegates::{
    format_available_delegates_section, format_available_delegates_section_with_aliases,
};
pub use tier2_skills::{format_available_skills_section, SKILL_BUDGET_TOKENS_DEFAULT};
pub use tier3::{
    bound_tier3_turns, model_context_window, recent_l0_turns, response_reserve,
    select_progressive_mode, ProgressiveMode, COMPACT_MIN, MEDIUM_MIN, RETENTION_HIGH_THRESHOLD,
    RETENTION_LOW_THRESHOLD, SMALL_MODEL_WINDOW, WIDE_MIN,
};
pub use turn_embed::{
    index_turn_end, MAX_EMBED_SOURCE_BYTES, OVERSIZE_PREFIX, SQLITE_WRITER_PREFIX,
    YAML_WRITER_PREFIX,
};
pub use unified_search::UnifiedSearchCoordinator;
pub use warning_queue::WarningQueue;

// Data-port pre-build (2026-06-08) — dep-light REAL implementations of the
// unified_search / vector-index / task-index / knowledge-map ports over a
// caller-supplied data seam (cap-memory data-load + cap-llm embedding adapter
// are B1's downstream wiring; see MODULE-010 §3.6). Only genuinely-new symbols
// are re-exported here — the port traits + result/carrier types are already
// re-exported from `ports` above.
pub use knowledge_map_reader::{KnowledgeRecord, ProjectingKnowledgeMap};
pub use vector_search::{
    cosine_similarity, AgentSearchCorpus, CosineTaskIndex, CosineVectorIndex, IndexedTask,
    IndexedTurn, IndexedVector, RankingUnifiedSearch, DEFAULT_MAX_RESULTS,
};

// Wave-13 Lane C (2026-06-23) — the read-path recall mechanism (MODULE-010 §3.8
// Wave-13 Lane C): a real deterministic embedding, the corpus-populate
// primitive, and the omit-when-empty recall renderer. `format_recall_section`
// stays `pub(crate)` (consumed only by `assemble()`), so it is NOT re-exported.
pub use corpus_ingest::{build_agent_search_corpus, CorpusDoc, CorpusDocKind};
pub use recall_embedding::{HashingEmbedding, RECALL_EMBEDDING_DIM_DEFAULT};

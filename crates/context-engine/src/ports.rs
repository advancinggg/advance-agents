//! Slice-B crate-local async dependency-inversion ports + data carriers.
//!
//! Same pattern + rationale as the Slice-A `HostFnInventoryReader`
//! (`crate::inventory`): the surfaces these ports stand in for
//! (CONTRACT-032/031 MODULE-004 search/task-index, CONTRACT-081 MODULE-009
//! `embed`, CONTRACT-101 MODULE-011 `MemoryStoreReader`, AGENTS.md FS read)
//! are NOT yet hoisted into `crates/shared-types`. Depending on the concrete
//! `advance-database` / `advance-cap-llm` crates would break the
//! inverted-dependency discipline and (for cap-llm) trip
//! `tests/stateless.rs::cargo_manifest_excludes_provider_crates` (AC-01
//! dep-light posture). So Slice B mirrors them as crate-local `#[async_trait]`
//! ports; a future cross-module wire-up slice promotes each (or folds it into
//! the eventual hoisted CONTRACT). See MODULE-010 §3.6 / §3.8.
//!
//! Carrier honesty categories (MODULE-010 §3.8 Slice-B sub-section):
//! - **(A)** [`UnifiedSearchResult`] / [`TaskHit`] / [`TurnHit`] /
//!   [`ContentHit`] / [`MemoryHit`] mirror EXISTING canonical
//!   `crates/database` structs with one enumerated divergence:
//!   `last_turn_at: Option<SystemTime>` vs canonical `Option<DateTime<Utc>>`
//!   (Option preserved; `SystemTime` keeps the crate dep-light, matching the
//!   `AgentState.last_handle_message_at: Option<SystemTime>` precedent).
//! - **(B1)** [`KnowledgeMap`] / [`KnowledgeTopic`] / [`TaskSynthesis`] have
//!   NO upstream struct anywhere (`KnowledgeMap` is only a bare return type on
//!   CONTRACT-101 `MemoryStoreReader::read_knowledge_map`). Materialized here
//!   from MODULE-010's OWN §1.3.3⑨ + §2.11 field-level spec.
//!
//! All ports are `Send + Sync` read-only async traits. `agent_id` is NOT
//! whitelist-validated *inside* the port impls — every Slice-B in-crate
//! caller (`assembler.rs::assemble`, `task_router::route_task`,
//! `unified_search::UnifiedSearchCoordinator::unified_search`,
//! `tier2_delegates::format_available_delegates_section`) validates per
//! CONTRACT-090 invariant 4 BEFORE invoking any port. Direct workspace
//! consumers that bypass these wrappers and call port impls themselves are
//! responsible for the same validation (the trait surface is read-only and
//! does not constrain its `agent_id` parameter at the type level).

use std::time::SystemTime;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Generic port-level failure. The ports stand in for I/O surfaces (SQLite,
/// LLM gateway, FS); a single opaque string error mirrors the
/// `DbError`/`LlmError`/`AssemblyError` pattern without coupling to any
/// concrete upstream error enum. Operator-facing — same PII exclusion rule as
/// `AssemblyError` payloads (no user content / secrets).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortError(pub String);

impl std::fmt::Display for PortError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for PortError {}

// ─────────────────────────────────────────────────────────────────────────
// Category (A) carriers — mirror existing crates/database canonical shapes.
// Divergence (enumerated, MODULE-010 §3.6): last_turn_at/timestamp are
// Option<SystemTime>/SystemTime here vs canonical Option<DateTime<Utc>>/
// DateTime<Utc> in crates/database/src/{score,unified_search}.rs.
// ─────────────────────────────────────────────────────────────────────────

/// One ranked task hit. Mirrors `crates/database/src/score.rs::TaskHit`
/// (`task_id`, `similarity`, `last_turn_at`). The routing decision (top-1
/// threshold, tie-break) is owned by [`crate::task_router`] (CONTRACT-091),
/// NOT by the producing primitive.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TaskHit {
    pub task_id: String,
    pub similarity: f32,
    /// `None` carries tie-break semantics: `Some(t)` precedes `None`
    /// (mirrors upstream `rank_task_rows` "newer first; None goes after Some").
    pub last_turn_at: Option<SystemTime>,
    /// Producer-supplied text (the task brief) rendered in `# Recalled Context`
    /// so the model sees what the task was about, not only its id. Untrusted;
    /// the renderer byte-caps + sanitizes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
}

/// One cross-task turn hit. Mirrors
/// `crates/database/src/unified_search.rs::TurnHit` (all 4 fields incl. `id`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TurnHit {
    pub id: String,
    pub task_id: String,
    pub similarity: f32,
    pub timestamp: SystemTime,
    /// Producer-supplied text (the turn digest) rendered in `# Related Turns` (⑯).
    /// Untrusted; the renderer byte-caps + sanitizes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    /// The turn's number in its task, when the producer knows it: ⑯ can then load
    /// the turn whole ([`RecentTurnsReader::read_turns`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn: Option<u64>,
    /// The turn's PRD §11.3.4 retention score at this read, when the producer can
    /// score it. ⑯ keeps a scored turn by its score (§11.3.5); an unscored one is
    /// loaded as its digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<f32>,
}

/// One content-index hit. Minimal mirror — only the fields Slice B needs for
/// source separation (AC-02). Adjusted-score ranking is owned by MODULE-004.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ContentHit {
    pub id: String,
    pub adjusted_score: f32,
    /// Producer-supplied preview rendered in `# Recalled Context`. Untrusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
}

/// One memory-index hit (with epistemic boost folded into `adjusted_score` by
/// the producer). Minimal mirror — source-separation only.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemoryHit {
    pub id: String,
    pub adjusted_score: f32,
    /// Producer-supplied memory text rendered in `# Recalled Context`. Untrusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
}

/// Source-separated unified search result. Mirrors
/// `crates/database/src/unified_search.rs::UnifiedSearchResult`. The 4 typed
/// fields ARE the "source separation" the AC-02 criterion requires.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct UnifiedSearchResult {
    pub tasks: Vec<TaskHit>,
    /// Per §1.3.1 this is **cross-task only** (`task_id != current`). The
    /// CONTRACT-032 producer applies NO such filter; the
    /// [`crate::unified_search`] coordinator owns enforcing it.
    pub turns: Vec<TurnHit>,
    pub contents: Vec<ContentHit>,
    pub memories: Vec<MemoryHit>,
}

// ─────────────────────────────────────────────────────────────────────────
// Category (B1) carriers — NO upstream struct exists. Derived from
// MODULE-010's own §1.3.3⑨ ("_knowledge_map.yaml topics + task_syntheses,
// hard limit 500 tokens") + §2.11 (max 10 topics / 5 task_syntheses).
// ─────────────────────────────────────────────────────────────────────────

/// One knowledge-map topic. `body` is untrusted (MODULE-011-authored from
/// agent turns) — [`crate::knowledge_map`] sanitizes it before rendering.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KnowledgeTopic {
    pub name: String,
    pub body: String,
}

/// One per-task synthesis (L5). `body` is untrusted, sanitized at render.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TaskSynthesis {
    pub task_id: String,
    pub body: String,
}

/// `_knowledge_map.yaml` projection. **No canonical upstream struct exists**
/// (CONTRACT-101 `read_knowledge_map` only names `Option<KnowledgeMap>` as a
/// bare return type). Field set is materialized from MODULE-010 §1.3.3⑨.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct KnowledgeMap {
    pub topics: Vec<KnowledgeTopic>,
    pub task_syntheses: Vec<TaskSynthesis>,
}

// ─────────────────────────────────────────────────────────────────────────
// The 6 ports.
// ─────────────────────────────────────────────────────────────────────────

/// Stands in for CONTRACT-032 `UnifiedSearch` (MODULE-004; canonical async
/// trait in `crates/database/src/unified_search.rs`). The coordinator
/// pre-computes `query_embedding` via [`EmbeddingPort`] before calling this
/// (MODULE-004 does not call `embed()` on the read path).
#[async_trait]
pub trait UnifiedSearchPort: Send + Sync {
    async fn search(
        &self,
        agent_id: &str,
        query: &str,
        query_embedding: &[f32],
    ) -> Result<UnifiedSearchResult, PortError>;

    /// [`Self::search`] for a turn that runs in `current_task_id` (`None`: in no task, that is
    /// in the agent's default partition): PRD §11.3.1 recalls other tasks' turns and briefs
    /// ("task_id != 当前 task"). A port that can leave the task out before it cuts its lists
    /// overrides this, so the task's own turns and its brief take no place in them (for a turn
    /// in no task, the default partition's); the default runs [`Self::search`], and the
    /// coordinator drops the task's entries from what it returns.
    async fn search_other_tasks(
        &self,
        agent_id: &str,
        query: &str,
        query_embedding: &[f32],
        _current_task_id: Option<&str>,
    ) -> Result<UnifiedSearchResult, PortError> {
        self.search(agent_id, query, query_embedding).await
    }

    /// PRD §11.3.5 "同 Task 较早历史": the turns of `task_id` (an empty id: the agent's
    /// default partition) the query recalls — the semantic and the keyword candidates,
    /// up to `limit` of each — with their retention scores. `None`: the port does not
    /// search a task's turns (the default), and its earlier turns come from the L2
    /// reader as they are.
    async fn search_task_turns(
        &self,
        _agent_id: &str,
        _task_id: &str,
        _query: &str,
        _query_embedding: &[f32],
        _limit: usize,
    ) -> Result<Option<Vec<TurnHit>>, PortError> {
        Ok(None)
    }
}

/// Stands in for CONTRACT-031/032 task-index top-N-by-similarity (MODULE-004).
/// Returns hits sorted by `similarity` desc (the routing decision is owned by
/// [`crate::task_router`]).
#[async_trait]
pub trait TaskIndexPort: Send + Sync {
    async fn top_n_by_similarity(
        &self,
        agent_id: &str,
        query_embedding: &[f32],
        n: usize,
    ) -> Result<Vec<TaskHit>, PortError>;

    /// The agent's current task: the task its latest turn ran in, as the one of its tasks
    /// with the latest `last_turn_at`. A default partition and a task of the `auto:`
    /// namespace are never the current task. `None` when the agent has none, or the index
    /// cannot say (the default). A turn routing cannot settle runs in it (MODULE-010
    /// §1.4.2).
    async fn current_task(&self, agent_id: &str) -> Result<Option<String>, PortError> {
        let _ = agent_id;
        Ok(None)
    }
}

/// Stands in for CONTRACT-081 `embed()` (MODULE-009 cap-llm).
#[async_trait]
pub trait EmbeddingPort: Send + Sync {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, PortError>;
}

/// Stands in for CONTRACT-081 light-model completion (MODULE-009). Used ONLY
/// as the residual tie-break in [`crate::task_router`] when ≥2 candidates
/// share the same `last_turn_at`. Returns the chosen `task_id`.
#[async_trait]
pub trait LightLlmFallbackPort: Send + Sync {
    async fn pick_one(&self, query: &str, candidates: &[String]) -> Result<String, PortError>;
}

/// Deliberate one-of-five-method narrowing of CONTRACT-101
/// `MemoryStoreReader` (the full surface is
/// `read_knowledge`/`read_summary`/`read_turn_index`/`read_knowledge_map`/
/// `read_synthesis`). Slice B needs only `read_knowledge_map`. NOT a faithful
/// mirror — a narrowed seam (MODULE-010 §3.6 B1).
#[async_trait]
pub trait KnowledgeMapReader: Send + Sync {
    async fn read_knowledge_map(&self, agent_id: &str) -> Option<KnowledgeMap>;
}

/// Stands in for the AGENTS.md identity read (MODULE-002 FS / MODULE-011).
/// Returns the identity document body, or `None` when the agent has no
/// AGENTS.md. The returned text is **untrusted** (agent-authored) — the
/// Tier 1a builder sanitizes it before injection.
#[async_trait]
pub trait AgentIdentityReader: Send + Sync {
    async fn agents_md_summary(&self, agent_id: &str) -> Option<String>;
    /// Read `{workspace}/.agent/AGENTS.md` for a Child roster entry.
    /// Default is `None` so stubs / frozen builders stay byte-identical.
    async fn agents_md_for_workspace(&self, workspace: &std::path::Path) -> Option<String> {
        let _ = workspace;
        None
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Slice D — 9 new ports + carriers for AC-06 / AC-08 / AC-17.
//
// AC-12 (context.assembled event) and AC-13/14 (prompt-injection layer 1/2)
// consume the CANONICAL shared-types contracts directly — CONTRACT-180
// `EventBusEmit` + `Event`, CONTRACT-114 `PromptInjectionHelpers` +
// `InjectionFlag` + `TrustLevel` — so they add NO new port here (MODULE-010
// §3.8 Slice-D). Only surfaces with no canonical shared-types hoist get a
// crate-local port below.
//
// Carrier honesty (MODULE-010 §3.6 Slice-D):
// - The 5 L2–L6 readers + the L1 `VectorIndexReader` are (B1) narrowings of
//   CONTRACT-101 `MemoryStoreReader` surfaces (L1–L6 owned by MODULE-011).
// - `GitBlobReader` is (B1) with NO upstream §6.1 CONTRACT for git-blob-by-path
//   (CONTRACT-051 is MailboxDispatcher M006; M003 owns commit-queue/rollback/
//   checkpoint, none blob-by-path). Materialized from §1.3.4's narrative.
// - The two turn-index writers are (B1) write-side stand-ins for CONTRACT-030
//   (SQLite turn_index) + CONTRACT-101 (turn-index.yaml).
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use advance_shared_types::security_validator::InjectionFlag;

use crate::l0_compress::L0Action;

// ─── (B1) data carriers ───

/// A git blob hash (hex). Newtype so the staleness comparison can't confuse a
/// blob id with an arbitrary string. No upstream struct (the git-blob-by-path
/// surface is undefined in §6.1 — MODULE-010 §3.6 Slice-D (e)).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobId(pub String);

/// The `read_file_versions[*].blob_id` map a turn-index.yaml entry records
/// (§1.3.4). `BTreeMap` for deterministic iteration order.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnReadFileVersions {
    pub entries: BTreeMap<PathBuf, BlobId>,
}

/// L2 turn digest carrier (one-sentence summary + the L0-collapsed view text).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TurnDigestForEmbed {
    pub turn_id: u64,
    pub digest: String,
    pub collapsed_view: String,
}

/// The L0-collapsed view of a turn (the §1.3.4 in-TurnBuffer collapse output as
/// rendered text). Thin newtype carried into the AC-17 embed pipeline input.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TurnCollapsedView(pub String);

/// L3 epoch summary carrier.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EpochSummary {
    pub epoch_id: String,
    pub summary: String,
}

/// L4 task-summary carrier.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TaskSummaryView {
    pub task_id: String,
    pub summary: String,
}

/// L5 cross-task synthesis carrier.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SynthesisView {
    pub task_id: String,
    pub body: String,
}

/// L6 consolidated / global-memory record carrier.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GlobalMemoryRecord {
    pub id: String,
    pub body: String,
}

/// L1 vector-index hit (id + similarity score). Mirror of MODULE-004's
/// turn-index hit shape, minimal for AC-06 coordination.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VectorHit {
    pub id: String,
    pub score: f32,
}

/// The L1 turn-index entry written by the AC-17 turn-end pipeline. Carries the
/// embedding generated from `digest + collapsed_view` (matching the rebuild
/// embed-source format). Written to BOTH the SQLite virtual table and the
/// turn-index.yaml L1 layer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TurnIndexEntry {
    pub id: String,
    pub turn_id: u64,
    pub digest: String,
    pub collapsed_view: String,
    pub embedding: Vec<f32>,
}

/// The aggregated output of the AC-06 6-level coordinator. One field per level
/// (L0 in-module via `l0_compress`; L1–L6 via the reader ports below).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MultiLevelContextDigest {
    pub l0: Vec<L0Action>,
    pub l1: Vec<VectorHit>,
    pub l2: Vec<TurnDigestForEmbed>,
    pub l3: Option<EpochSummary>,
    pub l4: Option<TaskSummaryView>,
    pub l5: Vec<SynthesisView>,
    pub l6: Vec<GlobalMemoryRecord>,
}

/// The L4/L5 context record AC-13's layer-1 sanitizer projects flags onto. Uses
/// the CANONICAL shared-types [`InjectionFlag`] (no local rematerialization).
/// The live L4/L5 ingress producer is a future slice (MODULE-010 §3.6 Slice-D
/// (c)); this carrier is the receiver-side shape the adapter targets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tier45ContextRecord {
    pub content: String,
    pub flags: Vec<InjectionFlag>,
}

/// A full turn view handed to the AC-08 staleness check. `read_file_versions`
/// is the recorded blob map; `collapsed_view` is dropped on demotion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnView {
    pub turn_id: u64,
    pub digest: String,
    pub collapsed_view: String,
    pub read_file_versions: TurnReadFileVersions,
}

/// A turn demoted to digest-only (the §1.3.4 "stale turns demoted to digest
/// only" form). `collapsed_view` is intentionally absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestOnlyView {
    pub turn_id: u64,
    pub digest: String,
}

/// The result of an AC-08 staleness check + demotion. (B2 — spec-named via
/// §1.3.4 but undefined upstream.)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckedTurn {
    /// All tracked blobs match the current tree — the turn is fresh.
    Fresh(TurnView),
    /// At least one tracked blob diverged (or a tracked path is gone) — the
    /// turn is demoted to digest-only.
    DemotedToDigest(DigestOnlyView),
}

/// The pure staleness verdict over a blob comparison (no demotion applied).
/// (B2 — spec-named via §1.3.4 but undefined upstream.)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StalenessVerdict {
    /// Every tracked `(path, blob_id)` matches the current tree.
    Fresh,
    /// One or more tracked paths diverged or are missing from the current tree.
    Stale { diverged: Vec<PathBuf> },
}

// ─── (B1) the 9 Slice-D ports ───

/// AC-06 L1 read-side — vector-index lookup (stands in for the read side of
/// CONTRACT-030 turn_index / CONTRACT-101 turn-index.yaml L1 layer). NEW port,
/// NOT a reuse of [`KnowledgeMapReader`].
#[async_trait]
pub trait VectorIndexReader: Send + Sync {
    async fn lookup(
        &self,
        agent_id: &str,
        query_embedding: &[f32],
    ) -> Result<Vec<VectorHit>, PortError>;
}

/// AC-06 L2 — turn digests for a task (narrowing of CONTRACT-101
/// `MemoryStoreReader::read_turn_index`'s L2 slice).
#[async_trait]
pub trait L2DigestReader: Send + Sync {
    async fn read_digests(
        &self,
        agent_id: &str,
        task_id: &str,
    ) -> Result<Vec<TurnDigestForEmbed>, PortError>;
}

/// AC-06 L3 — epoch summary for a task (no `MemoryStoreReader` method; B1
/// locally materialized surface).
#[async_trait]
pub trait L3EpochReader: Send + Sync {
    async fn read_epoch(
        &self,
        agent_id: &str,
        task_id: &str,
    ) -> Result<Option<EpochSummary>, PortError>;
}

/// AC-06 L4 — task summary (narrowing of CONTRACT-101
/// `MemoryStoreReader::read_summary`).
#[async_trait]
pub trait L4TaskSummaryReader: Send + Sync {
    async fn read_task_summary(
        &self,
        agent_id: &str,
        task_id: &str,
    ) -> Result<Option<TaskSummaryView>, PortError>;
}

/// AC-06 L5 — cross-task syntheses (narrowing of CONTRACT-101
/// `MemoryStoreReader::read_synthesis`).
#[async_trait]
pub trait L5SynthesisReader: Send + Sync {
    async fn read_syntheses(
        &self,
        agent_id: &str,
        task_id: &str,
    ) -> Result<Vec<SynthesisView>, PortError>;
}

/// AC-06 L6 — consolidated / global memory (narrowing of CONTRACT-101
/// `MemoryStoreReader::read_knowledge`).
#[async_trait]
pub trait L6ConsolidationReader: Send + Sync {
    async fn read_global_memory(
        &self,
        agent_id: &str,
    ) -> Result<Vec<GlobalMemoryRecord>, PortError>;
}

/// ⑯ — one recent turn of the agent's task, as its turn log holds it (PRD §11.3.5 "同 Task
/// 近期窗口"). The assembler loads it whole — L0-processed: what a later step of the same turn
/// superseded or made stale is shortened (PRD §11.3.3) — or, when a file it read has changed
/// since or it does not fit, as its digest.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecentTurn {
    pub turn_id: u64,
    /// When the turn ran (UTC, RFC 3339).
    pub timestamp: String,
    pub digest: String,
    /// The files the turn read, at the versions it read (PRD §11.2.1 `read_file_versions`).
    pub read_file_versions: TurnReadFileVersions,
    /// The turn's messages as logged, oldest first; empty when the log holds none of them.
    pub messages: Vec<advance_shared_types::turn_log::TranscriptMessage>,
    /// The L0 mark of each message, index for index.
    pub marks: Vec<advance_shared_types::turn_log::L0Mark>,
}

/// ⑯ — the last turns of a task (PRD §11.3.5): up to `count`, oldest first. An empty `task_id`
/// is the agent's default task. A reader error degrades to no recent turns (§2.8).
#[async_trait]
pub trait RecentTurnsReader: Send + Sync {
    async fn read_recent_turns(
        &self,
        agent_id: &str,
        task_id: &str,
        count: usize,
    ) -> Result<Vec<RecentTurn>, PortError>;

    /// The turns of `task_id` numbered in `turns` (an empty id: the agent's default
    /// partition), oldest first; a turn the reader cannot find is left out. ⑯ loads a
    /// task's earlier turn, or another task's turn, whole with it. Default: none (such
    /// a turn is loaded as its digest).
    async fn read_turns(
        &self,
        _agent_id: &str,
        _task_id: &str,
        _turns: &[u64],
    ) -> Result<Vec<RecentTurn>, PortError> {
        Ok(Vec::new())
    }
}

/// The reader of an agent without a turn log: no recent turns.
pub struct NoRecentTurns;

#[async_trait]
impl RecentTurnsReader for NoRecentTurns {
    async fn read_recent_turns(
        &self,
        _agent_id: &str,
        _task_id: &str,
        _count: usize,
    ) -> Result<Vec<RecentTurn>, PortError> {
        Ok(Vec::new())
    }
}

/// AC-08 — current git blob id by path. **B1: no upstream §6.1 CONTRACT.**
/// `Ok(None)` means the path no longer exists in the current working tree
/// (genuine staleness); `Err` is an I/O / lookup failure that the staleness
/// check propagates fail-CLOSED (NOT silently treated as stale).
#[async_trait]
pub trait GitBlobReader: Send + Sync {
    async fn current_blob(&self, path: &Path) -> Result<Option<BlobId>, PortError>;
}

/// AC-17 — write the turn-index entry to the SQLite `turn_index` virtual table
/// (CONTRACT-030 write-side stand-in).
#[async_trait]
pub trait TurnIndexSqliteWriter: Send + Sync {
    async fn write_turn_index_sqlite(&self, entry: &TurnIndexEntry) -> Result<(), PortError>;
}

/// AC-17 — write the turn-index entry to the `turn-index.yaml` L1 layer
/// (CONTRACT-101 write-side stand-in). Distinct port from the SQLite writer so
/// the §1.4 "writes to BOTH" conjunction is verifiable at the M010 caller
/// boundary (the pipeline calls both, once each, per turn).
#[async_trait]
pub trait TurnIndexYamlWriter: Send + Sync {
    async fn write_turn_index_yaml(&self, entry: &TurnIndexEntry) -> Result<(), PortError>;
}

// ═══════════════════════════════════════════════════════════════════════════
// Slice V1-c — Skill L0 summary reader (AC-15 / REQ-264).
//
// Feeds the Tier-2 ⑩ `# Available Skills` section. Same B1 local-port
// convention as `AgentIdentityReader` / `KnowledgeMapReader`: the production
// surface (reading the agent's visible skills + their SKILL.md summaries) is
// not yet hoisted into shared-types, so MODULE-010 reads via this crate-local
// async port. The summary text is produced by cap-skills `extract_skill_summary`
// (first paragraph, ≤ 100 tokens); this port carries the already-extracted
// summary. No `shared-types` change (MODULE-017 prompt directive: prefer
// context-engine-local types for L0 injection).
// ═══════════════════════════════════════════════════════════════════════════

/// One visible skill's L0 summary entry. Category-(B1) carrier — no upstream
/// struct; materialized from MODULE-017 §1.4 AC-27 + PRD §12.4.4.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SkillSummaryEntry {
    /// Skill name (the `.agent/skills/{name}/` directory name).
    pub name: String,
    /// First-paragraph SKILL.md summary, already ≤ 100 tokens (cap-skills
    /// `extract_skill_summary`).
    pub summary: String,
    /// Injection priority — higher is kept first when the aggregate exceeds the
    /// budget cap (AC-27 "truncate lowest-scoring first"). **Production
    /// semantics**: recency / last-used-derived (supplied by the reader impl).
    /// **This slice**: caller/test-supplied — the production recency source is
    /// deferred (no recency field on shared-types `SkillInfo`; MODULE-010 §3.6
    /// (Slice V1-c) + MODULE-017 §3.6 (K-a)).
    pub score: f32,
}

/// AC-15 — per-agent visible-skill L0 summaries for the Tier-2 ⑩
/// `# Available Skills` section. Read-only; `agent_id` is whitelist-validated
/// by the caller (`assembler.rs::assemble`) before invocation, per the
/// CONTRACT-090 invariant-4 convention shared by every port in this module.
#[async_trait]
pub trait SkillSummaryReader: Send + Sync {
    async fn list_skill_summaries(&self, agent_id: &str) -> Vec<SkillSummaryEntry>;
}

/// One active subtask for the Tier-2 ⑭ "Active Task Decomposition" section
/// (Wave-12 Lane C). A read-only (B1) projection of MODULE-005's `SubtaskState`
/// (cap-lifecycle). `status` is a **stringified** kebab tag (`pending` /
/// `in-progress` / `completed` / `failed` / `skipped`) so context-engine does NOT
/// import `cap_lifecycle::SubtaskStatus` — the cli adapter stringifies it at the
/// boundary, preserving the AC-01 dep-light posture (the `tests/stateless.rs`
/// provider-crate-exclusion guard). The fields are **untrusted** (agent-authored
/// titles) — `format_active_decomposition_section` sanitizes them before injection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubtaskView {
    /// The subtask id (`st-{uuid}` shape from MODULE-005).
    pub subtask_id: String,
    /// The subtask title (untrusted; sanitized at render).
    pub title: String,
    /// Kebab status tag, already stringified at the cli boundary
    /// (`cap_lifecycle::events::status_tag`).
    pub status: String,
}

/// The active task's non-orphaned subtasks for the Tier-2 ⑭ "Active Task
/// Decomposition" section (Wave-12 Lane C). Read-only; the cli adapter
/// (`CapDecompositionReader`) bridges to MODULE-005's `DefaultDecompositionStore`,
/// resolves the owner via a bare-first agent-id alias set, and filters to
/// non-orphaned subtasks. `agent_id` is whitelist-validated by the caller
/// (`assembler.rs::assemble`) before invocation (CONTRACT-090 invariant 4); `task_id`
/// is the active task (`None` ⇒ no active decomposition ⇒ empty `Vec`). Implementations
/// MUST be fail-soft (return `Vec::new()` on any read error) so assembly never aborts.
#[async_trait]
pub trait DecompositionReader: Send + Sync {
    async fn read_active_subtasks(&self, agent_id: &str, task_id: Option<&str>)
        -> Vec<SubtaskView>;
}

// ═══════════════════════════════════════════════════════════════════════════
// Runtime info — Tier 1a ②/③ (architecture / security model) + Tier 1b ⑦/⑧
// (capability config / mode state / runtime info).
// ═══════════════════════════════════════════════════════════════════════════

/// The runtime facts the Tier 1a `# Runtime Architecture` / `# Security Model`
/// and the Tier 1b `# Runtime State` sections render. Category-(B1) carrier —
/// no upstream struct; the composition root fills it from what it already
/// knows (declared capabilities, workspace, resolved model, agent-tree kind).
/// Every string is **untrusted** at render (sanitized + byte-capped).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeInfoView {
    /// Runtime crate version (e.g. `0.1.40`).
    pub runtime_version: String,
    /// `root` | `child` | `sub` (lower-case tag), when the tree knows the agent.
    pub agent_kind: Option<String>,
    /// Parent handle for a non-root agent.
    pub parent_agent: Option<String>,
    /// Display form of the agent workspace (never an absolute host path on the
    /// client side; the composition root decides what to show).
    pub workspace: Option<String>,
    /// Declared capability names (`.agent/config.yaml`), sorted at render.
    pub capabilities: Vec<String>,
    /// Serving mode: `serve` (POST /msg), `channels`, `auto`, …
    pub mode: Option<String>,
    /// The provider entry id the turn's model resolves to.
    pub llm_provider: Option<String>,
    /// The resolved model id fed to `AssemblyContext.model`.
    pub llm_model: Option<String>,
    /// Persistent memory (cap-memory) is wired for this agent.
    pub memory_enabled: bool,
    /// Skills reader is wired for this agent.
    pub skills_enabled: bool,
    /// A real embedding provider backs semantic recall / task routing.
    pub embedding_enabled: bool,
}

/// Tier 1a/1b runtime-info source. Read-only; `None` ⇒ the three runtime
/// sections are omitted (byte-identical to the pre-runtime-info prompt).
#[async_trait]
pub trait RuntimeInfoReader: Send + Sync {
    async fn runtime_info(&self, agent_id: &str) -> Option<RuntimeInfoView>;
}

// ═══════════════════════════════════════════════════════════════════════════
// Assembly report — the per-turn inspection record the composition root
// exposes through the Client API (`GET /client/agents/{id}/context`).
// ═══════════════════════════════════════════════════════════════════════════

/// One assembled message, attributed to its tier. `tokens` uses the same
/// estimator as `TierTokenCounts`, so the per-tier sums match.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssemblySection {
    /// `1a` | `1b` | `2` | `3`.
    pub tier: String,
    /// The section heading (`# Agent Identity`, …) or a role-derived label
    /// (`history turn`, `warning`, `user prompt`, `cache breakpoint`).
    pub label: String,
    pub role: String,
    pub tokens: u32,
    pub bytes: u32,
}

/// Recall hit counts for one assembly.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssemblyRecallReport {
    /// A query embedding was requested (non-blank prompt + embedding port).
    pub attempted: bool,
    pub tasks: u32,
    pub turns: u32,
    pub contents: u32,
    pub memories: u32,
}

/// History / multi-level digest usage for one assembly.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssemblyHistoryReport {
    /// `AssemblyContext.turn_buffer` entries received.
    pub turn_buffer_in: u32,
    /// Entries kept after L0 compression + progressive-mode bounding.
    pub turn_buffer_kept: u32,
    /// Entries L0 dropped (superseded / invalidated) or collapsed to a skeleton.
    pub l0_compressed: u32,
    pub l2_digests: u32,
    pub l3_epoch: bool,
    pub l4_task_summary: bool,
    /// ⑭ L5: briefs of other tasks the message resembles (PRD §11.3.1, at most 3).
    pub l5_related_briefs: u32,
    /// ⑭ task syntheses shown with the task summary.
    pub task_syntheses: u32,
    /// ⑯ recent turns of the task loaded whole (L0-processed).
    pub recent_turns: u32,
    /// ⑯ recent turns loaded as their digest: a file they read has changed since, they did
    /// not fit, or the mode loads digests only.
    pub recent_turn_digests: u32,
    /// ⑯ earlier turns of the task the message recalls, loaded whole (PRD §11.3.5).
    pub earlier_turns: u32,
    /// ⑯ earlier turns of the task the message recalls, loaded as their digest.
    pub earlier_turn_digests: u32,
    /// ⑯ turns of other tasks the message recalls, loaded whole.
    pub related_turns: u32,
    /// ⑯ turns of other tasks the message recalls, loaded as their digest.
    pub related_turn_digests: u32,
}

/// The model an agent chats on, and the context window its provider entry gives for it
/// (MODULE-010 D5, PRD §11.3.5 `llm_gateway.get_context_window()`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatModelWindow {
    /// The provider entry the agent chats on.
    pub provider_id: String,
    /// The model id that entry is sent for the agent's own requests that name none: the
    /// model its `llm:` policy names, else the entry's default. Empty when neither exists.
    pub model: String,
    /// The window the entry gives for `model`, and where it comes from.
    pub declared: Option<(u32, WindowSource)>,
}

/// Where the window an assembly budgets with comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowSource {
    /// The chat entry's `model-context-windows` figure for the model.
    Provider,
    /// The context window of the chat entry's catalog profile.
    Profile,
    /// The model family's published window (`tier3::family_context_window`).
    Family,
    /// No source knows the model: the fail-safe-small window.
    Fallback,
    /// The composition root's fixed window (`with_model_context_window`).
    Override,
}

impl WindowSource {
    pub fn as_str(self) -> &'static str {
        match self {
            WindowSource::Provider => "provider",
            WindowSource::Profile => "profile",
            WindowSource::Family => "family",
            WindowSource::Fallback => "fallback",
            WindowSource::Override => "override",
        }
    }
}

/// Reads, at every assembly, the model the assembler's agent chats on, from the live
/// provider config and the agent's live `llm:` policy. `None` = the agent has no chat entry
/// yet (one free to chat on several entries before any served it): the assembly falls back
/// to the composition root's model.
pub type ChatModelSource = std::sync::Arc<dyn Fn() -> Option<ChatModelWindow> + Send + Sync>;

/// The full per-turn assembly report. Emitted once per successful `assemble()`
/// through [`AssemblyReportSink`] AFTER the result is built.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AssemblyReport {
    pub agent_id: String,
    pub task_id: Option<String>,
    pub message_id: String,
    pub trace_id: Option<String>,
    pub model: String,
    /// The provider entry `model` is on; `None` when the agent has no chat entry yet.
    #[serde(default)]
    pub model_provider: Option<String>,
    pub model_context_window: u32,
    /// Where `model_context_window` comes from: `provider` | `profile` | `family` |
    /// `fallback` | `override` ([`WindowSource`]).
    #[serde(default)]
    pub model_window_source: String,
    pub response_reserve: u32,
    pub budget_tokens: u32,
    /// `tier1a + tier1b + tier2 + tier3`.
    pub used_tokens: u32,
    /// `budget_tokens - used_tokens` (saturating).
    pub remaining_tokens: u32,
    /// `wide` | `medium` | `compact` | `extreme`.
    pub progressive_mode: String,
    /// The budget-overflow guard produced the degraded (identity + prompt) set.
    pub degraded: bool,
    pub tier1a_tokens: u32,
    pub tier1b_tokens: u32,
    pub tier2_tokens: u32,
    pub tier3_tokens: u32,
    pub sections: Vec<AssemblySection>,
    pub routing_method: String,
    pub routing_confidence: f32,
    pub is_new_task: bool,
    pub recall: AssemblyRecallReport,
    pub history: AssemblyHistoryReport,
    pub prompt_bytes: u32,
    pub warnings: u32,
}

/// Sink for [`AssemblyReport`]s. Sync + non-blocking (the implementer stores
/// the latest report per agent; never does I/O on the turn path).
pub trait AssemblyReportSink: Send + Sync {
    fn record(&self, report: AssemblyReport);
}

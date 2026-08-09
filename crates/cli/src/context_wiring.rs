//! Backbone Step 2 (2026-06-07) — composition-root wiring for the real
//! [`ContextAssemblerImpl`] (MODULE-010, CONTRACT-090).
//!
//! `ContextAssemblerImpl::new` takes 19 dependency ports. Until the backbone
//! slice its only callers were crate-internal test fixtures ("no workspace consumer").
//! This module supplies the production adapters/stubs and a single
//! [`build_context_assembler`] entry that the cli composition root + the
//! system-acceptance harness both call.
//!
//! **Dep-light discipline**: the adapters live HERE (in the cli, the top of the
//! dep graph), NOT in `context-engine` — context-engine deliberately depends on
//! nothing but `shared-types` (its `tests/stateless.rs` guard forbids provider
//! crates), so any adapter that wraps a provider must live downstream.
//!
//! **Port reality for THIS slice** (see MODULE-001/009/010 §3.6/§3.7):
//! - CALLER-SUPPLIED (real-able): `event_bus`, `callable_inventory`,
//!   `host_fn_inventory`, `agent_tree`. PRODUCTION (start.rs) passes REAL
//!   `event_bus` + `host_fn_inventory` (a `HostRegistry` capability-probe) + the
//!   REAL `agent_tree` snapshot (SAT-A; the cap-lifecycle spawn host-fns record
//!   `Sub` nodes into it — 011), and STILL STUBS `callable_inventory` (empty,
//!   lands in a later slice). The HARNESS passes a real `event_bus` (CapturingBus)
//!   + a populated `callable_inventory` (wasm+mcp) + a populated `host_fn_inventory`
//!   so SYS-AC-010's `# Available Tools` merge is witnessable. NOTE: Wave-12 BRIDGED
//!   the colon/bare keying — `assemble()` matches `# Available Delegates` against the
//!   agent-id alias set `[cap_agent_id, msg_agent_id]` (passed by start.rs via
//!   `build_with_all_ports`'s `query_aliases`), so a real product-spawned Sub now
//!   surfaces BY NAME (SYS-AC-011 stays DEFERRED only for the empty-caps WIT spawn
//!   cap-lift gap — the "with capability summaries" clause).
//! - HERMETIC STUBS (always, both prod + harness): `embedding`, `task_index`,
//!   `light_llm`, `unified_search`, `agent_identity`. These feed the routing /
//!   recall tiers that SYS-AC-008/009 (explicitly §3-deferred) require; stubbing
//!   them keeps `assemble()` hermetic (no `/v1/embeddings` round-trip on the
//!   witness turn) and the assembler degrades gracefully (MODULE-010 §2.8).
//!   (`knowledge_map` + the L2/L3/L4 history readers became REAL in the B1 /
//!   SAT-A slices — see MODULE-010 §3.6 — so this list is the original
//!   backbone-Step-2 reality, kept for context.)
//! - CALLER-SUPPLIED (skills-J26 satellite, 2026-06-20): `skill_summary` is the
//!   real [`DiskSkillSummaryReader`] in production when the agent declares the
//!   `skills` capability (root threaded via `WiringHandles.skills_root`);
//!   `StubSkillSummary` otherwise. So `# Available Skills` is no longer always
//!   omitted in production.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;

use advance_context_engine::ports::{
    AgentIdentityReader, DecompositionReader, EpochSummary, GlobalMemoryRecord, KnowledgeMap,
    KnowledgeMapReader, L2DigestReader, L3EpochReader, L4TaskSummaryReader, L5SynthesisReader,
    L6ConsolidationReader, LightLlmFallbackPort, PortError, SkillSummaryEntry, SkillSummaryReader,
    SubtaskView, SynthesisView, TaskHit, TaskIndexPort, TaskSummaryView, TurnDigestForEmbed,
    UnifiedSearchPort, UnifiedSearchResult, VectorHit, VectorIndexReader,
};
// Re-exported (not just `use`) so downstream test crates that don't depend on
// `advance-context-engine` directly (e.g. system-acceptance) can call
// `GatewayEmbedding::embed` through the trait.
pub use advance_context_engine::ports::EmbeddingPort;
// Wave-20 Lane `search`: re-exported alongside EmbeddingPort so the system-acceptance
// harness (deps cli, not context-engine) can impl EmbeddingPort for its FixtureEmbedding.
pub use advance_context_engine::ports::PortError as CePortError;
// B1 backbone (2026-06-09): the dep-light REAL port impls pre-built in
// context-engine (context-ports satellite) that the cli adapters feed with
// cap-memory data. context-engine stays read-only (these are reused, not edited).
use advance_context_engine::{
    build_agent_search_corpus, AgentSearchCorpus, ContextAssemblerImpl, CorpusDoc, CorpusDocKind,
    CosineTaskIndex, HostFnEntry, HostFnInventoryReader, IndexedTask, KnowledgeRecord,
    ProjectingKnowledgeMap, RankingUnifiedSearch,
};
// Wave-20 Lane `search`: the MODULE-004 dense+sparse read path + its cross-crate
// adapter. Only the non-hit types are imported (TaskHit/ContentHit/etc. collide
// with the context-engine carriers already in scope; the adapter maps between them).
use crate::dual_recall::R2d2UnifiedSearchAdapter;
use advance_database::{
    upsert_memory_index_row, R2d2SqliteIndexHandle, R2d2UnifiedSearchImpl, SqliteIndexHandle,
};
// Wave-16 Lane 2: re-exported (like `EmbeddingPort`) so the system-acceptance harness
// (which deps on cli, not context-engine) can construct the recall embedder for the
// `with_recall_corpus` axis.
pub use advance_context_engine::HashingEmbedding;
// Wave-12 Lane C: the decomposition store + its read trait + the status-tag
// stringifier, for the `CapDecompositionReader` adapter (the cli is the top of the
// dep graph — it may depend on cap-lifecycle; context-engine stays dep-light by
// taking only the `DecompositionReader` trait object + the stringified `SubtaskView`).
use cap_lifecycle::events::status_tag;
use cap_lifecycle::{DecompositionStore, DefaultDecompositionStore};
use cap_llm::{LlmGateway, LlmGatewayInternal};
use cap_memory::summary::Summary;
use cap_memory::turn_index::TurnIndex;
use cap_memory::{memory_search_docs, MemoryStore, MemoryType};
// skills-J26 reader satellite (2026-06-20): the real production `SkillSummaryReader`
// reuses cap-skills' first-paragraph summary extractor unchanged. The READ itself is
// a local bounded directory walk (NOT cap-skills `list_active`, which is unbounded /
// FIFO-unsafe on the hot turn path — ADVERSARIAL-r9 W1/W2).
use advance_runtime::host_registry::HostRegistry;
use advance_shared_types::agent_tree::{
    AgentKind, AgentTreeReader, AgentTreeSnapshot, AgentTreeSnapshotData, Capability,
};
use advance_shared_types::capability::{McpToolEntry, ToolEntry};
use advance_shared_types::context::ContextAssembler;
use advance_shared_types::traits::{CallableInventoryReader, EventBusEmit};
use cap_skills::extract_skill_summary;
// Wave-16 Lane 2: reuse the TOCTOU-hardened file-safety helpers (made `pub(crate)`
// in `vlm_indexer`) for the recall corpus's workspace-content walk — no duplication.
use crate::vlm_indexer::{confine, read_capped_bytes};

// ─────────────────────────────────────────────────────────────────────────
// Hermetic stub ports (the 7 data ports — empty/None/safe-default).
// ─────────────────────────────────────────────────────────────────────────

/// AGENTS.md identity reader — production stub (no AGENTS.md read this slice →
/// Tier-1a identity slot empty). A real FS-backed reader is a follow-up.
struct StubAgentIdentity;
#[async_trait]
impl AgentIdentityReader for StubAgentIdentity {
    async fn agents_md_summary(&self, _agent_id: &str) -> Option<String> {
        None
    }
}

/// Knowledge-map reader — stub returning `None` → Tier-1b knowledge section
/// empty (the persistent MemoryStore feed is a Step-3 concern).
struct StubKnowledgeMap;
#[async_trait]
impl KnowledgeMapReader for StubKnowledgeMap {
    async fn read_knowledge_map(&self, _agent_id: &str) -> Option<KnowledgeMap> {
        None
    }
}

/// Embedding port — hermetic stub: a fixed zero vector (never a real
/// `/v1/embeddings` round-trip on the witness turn). The downstream
/// task_index/unified_search stubs return empty, so the embedding value is
/// inert; routing degrades to `NewTask`.
struct StubEmbedding;
#[async_trait]
impl EmbeddingPort for StubEmbedding {
    async fn embed(&self, _text: &str) -> Result<Vec<f32>, PortError> {
        Ok(vec![0.0; 16])
    }
}

/// Real `EmbeddingPort` wrapping cap-llm's `LlmGateway::embed` (`/v1/embeddings`).
///
/// **B1 backbone (2026-06-09): built + tested, but NOT injected into the live
/// assembler this slice.** `assemble()` runs `TaskRouter` whenever
/// `ctx.task_id.is_none()`, and the router calls `embed()` BEFORE the task
/// index — so a live `GatewayEmbedding` would force a real `/v1/embeddings`
/// round-trip on every turn (breaking the hermetic witness the existing
/// [`StubEmbedding`] preserves) for ZERO benefit: the task index is empty (no
/// embeddings indexed yet) so routing degrades to `NewTask` regardless. This
/// adapter goes live in the future slice that populates a real embedding index.
/// See MODULE-010 §3.6 (B1 backbone row).
pub struct GatewayEmbedding {
    gateway: Arc<LlmGateway>,
}
impl GatewayEmbedding {
    pub fn new(gateway: Arc<LlmGateway>) -> Self {
        Self { gateway }
    }
}
#[async_trait]
impl EmbeddingPort for GatewayEmbedding {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, PortError> {
        // `embed` is a `LlmGatewayInternal` trait method (CONTRACT-081), not an
        // inherent method — the trait import above brings it into scope.
        self.gateway
            .embed(text)
            .await
            .map_err(|e| PortError(e.to_string()))
    }
}

/// Task-index port — hermetic stub: no candidates.
struct StubTaskIndex;
#[async_trait]
impl TaskIndexPort for StubTaskIndex {
    async fn top_n_by_similarity(
        &self,
        _agent_id: &str,
        _query_embedding: &[f32],
        _n: usize,
    ) -> Result<Vec<TaskHit>, PortError> {
        Ok(Vec::new())
    }
}

/// Light-LLM tie-break fallback — stub returning the first candidate (the
/// tie-break is only reached with ≥2 candidates sharing a timestamp, which the
/// empty task_index never produces).
struct StubLightLlm;
#[async_trait]
impl LightLlmFallbackPort for StubLightLlm {
    async fn pick_one(&self, _query: &str, candidates: &[String]) -> Result<String, PortError> {
        Ok(candidates.first().cloned().unwrap_or_default())
    }
}

/// Unified-search port — hermetic stub: empty source-separated result.
struct StubUnifiedSearch;
#[async_trait]
impl UnifiedSearchPort for StubUnifiedSearch {
    async fn search(
        &self,
        _agent_id: &str,
        _query: &str,
        _query_embedding: &[f32],
    ) -> Result<UnifiedSearchResult, PortError> {
        Ok(UnifiedSearchResult::default())
    }
}

/// Skill-summary reader — stub returning no visible skills (Tier-2 ⑩ omitted).
struct StubSkillSummary;
#[async_trait]
impl SkillSummaryReader for StubSkillSummary {
    async fn list_skill_summaries(&self, _agent_id: &str) -> Vec<SkillSummaryEntry> {
        Vec::new()
    }
}

/// skills-J26 reader satellite (2026-06-20) — the REAL production
/// `SkillSummaryReader` (the live counterpart to [`StubSkillSummary`]). Reads the
/// agent's on-disk activated skills (`<skills_agent_root>/.agent/skills/{name}/`)
/// via a BOUNDED directory walk → [`extract_skill_summary`] (first paragraph,
/// ≤100 tok) → [`SkillSummaryEntry`].
///
/// **Root coincidence (load-bearing)**: `skills_agent_root` is the SAME value the
/// cap-skills WIT provider is rooted at — `<workspace>/.agent` — single-sourced in
/// `wiring.rs` and threaded here via `WiringHandles.skills_root`. The cap-skills
/// provider's `DiskSkillStorage` (the `activate-skill` WRITE path) appends
/// `.agent/skills`, so the physical dir is `<workspace>/.agent/.agent/skills`; this
/// reader walks that SAME dir, seeing exactly the skills the agent activated. Each
/// skill dir holds `SKILL.md` (content) + `.meta.yaml` (the `skill_id` / `version`
/// the writer recorded).
///
/// **Bounded read (ADVERSARIAL-r9 hardening — W1/W2)**: this runs on EVERY
/// `assemble()` (the hot turn path), so it deliberately does NOT use cap-skills
/// `DiskSkillStorage::list_active()`, which `read_to_string`s every active skill's
/// files with NO size cap and NO regular-file / symlink guard — a turn-path
/// FIFO-hang / unbounded-alloc hazard. Instead it (a) caps the active-skill COUNT at
/// [`MAX_VISIBLE_SKILLS`]; (b) reads each file via [`read_regular_capped`] — a
/// `symlink_metadata` STAT-BEFORE-OPEN that rejects a symlink / FIFO / dir / socket /
/// oversize BEFORE any blocking `open` (so a planted non-regular file is skipped,
/// never followed or hung on) + a `take(MAX_SKILL_READ_BYTES)` bounded read; (c)
/// rejects a skill entry that is not a real subdirectory (`DirEntry::file_type` does
/// not follow symlinks, so a symlink-to-dir is skipped); (d) cross-checks
/// `meta.skill_id == dir name` (the corruption / tampering guard cap-skills'
/// `read_active` applies). The downstream formatter additionally score-truncates the
/// RENDERED section to `min(skill_budget_tokens, ⌊budget·0.05⌋, 10K)` — that bounds
/// the PROMPT, not the I/O, which is why the count cap above bounds the read itself.
/// **Residual (disclosed)**: a host-side TOCTOU race that swaps a path to a
/// FIFO/symlink between the stat and the open (tiny window; `<ws>/.agent` is the
/// agent's OWN 0700 dir — outside the guest threat model: the guest writes skills
/// only via the validated `activate-skill` host-fn, ≤50 KiB regular files, and has
/// no mkfifo/symlink primitive). Same disclosed residual class as the sibling
/// `CapMemoryHistoryReader` ([`read_capped_under`]).
///
/// **Score**: `score = version as f32` (the active skill's `.meta.yaml` version) — a
/// deterministic revision-maturity proxy, NOT true recency/last-used (no recency
/// field exists on `SkillBlob` / `shared-types SkillInfo`). A freshly-activated v1
/// skill therefore scores LOWEST and is truncated FIRST under the aggregate budget —
/// the inverse of AC-27's recency intent, disclosed (MODULE-010 §3.6 Slice-V1-c).
/// The real recency-derived source + the e2e SYS-AC-078/079/081 flip are a
/// documented harvest hand-off.
///
/// **Single-agent**: rooted at one agent's `.agent`, so `agent_id` is ignored (the
/// on-disk skills dir IS this agent's — same single-agent model as
/// `SingleAgentSkillStoreProvider`). Any error → the skill is skipped / empty `Vec`
/// (fail-soft, byte-identical to [`StubSkillSummary`]; the formatter omits
/// `# Available Skills` when empty). The formatter independently sanitizes
/// (Trojan-Source) + re-bounds each summary token count, so untrusted SKILL.md
/// content is defended downstream.
pub struct DiskSkillSummaryReader {
    skills_agent_root: PathBuf,
}

impl DiskSkillSummaryReader {
    /// `skills_agent_root` is the cap-skills provider root (`<workspace>/.agent`),
    /// NOT the literal skills dir — the cap-skills layout appends `.agent/skills`.
    pub fn new(skills_agent_root: PathBuf) -> Self {
        Self { skills_agent_root }
    }
}

/// Upper bound on active skills read per turn (ADVERSARIAL-r9 W2). Far above the
/// formatter's budget capacity (it truncates the rendered section to
/// `min(skill_budget_tokens, ⌊budget·0.05⌋, 10K)` tokens — at most a few hundred
/// short lines), so it never affects normal operation; it bounds the per-turn O(N)
/// file I/O for a pathological active set.
const MAX_VISIBLE_SKILLS: usize = 256;

/// Per-file read cap for a skill's `SKILL.md` / `.meta.yaml` (ADVERSARIAL-r9 W1).
/// ≥ the cap-skills `MAX_CONTENT_LEN` (50_000-byte) write cap, with headroom, so a
/// legitimately-activated skill is never truncated while a non-guest-planted
/// oversized file cannot bloat the turn.
const MAX_SKILL_READ_BYTES: u64 = 96 * 1024;

/// Read a REGULAR file ≤ `max_bytes`, rejecting symlink / FIFO / dir / socket /
/// device / oversize via a `symlink_metadata` STAT-BEFORE-OPEN (lstat: does NOT
/// follow a symlink and does NOT open — so a planted symlink or named pipe is
/// rejected without a symlink-follow or a blocking `open`). `None` on any hazard.
/// (ADVERSARIAL-r9 W1; the SAT-D "stat-before-open" pattern. Residual: a host-side
/// TOCTOU race-swap to a FIFO between the stat and the open — disclosed on
/// [`DiskSkillSummaryReader`], the same residual class as [`read_capped_under`].)
fn read_regular_capped(path: &Path, max_bytes: u64) -> Option<String> {
    use std::io::Read;
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() || meta.len() > max_bytes {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    let mut buf = String::new();
    file.take(max_bytes).read_to_string(&mut buf).ok()?;
    Some(buf)
}

#[async_trait]
impl SkillSummaryReader for DiskSkillSummaryReader {
    async fn list_skill_summaries(&self, _agent_id: &str) -> Vec<SkillSummaryEntry> {
        let skills_root = self.skills_agent_root.join(".agent/skills");
        let entries = match std::fs::read_dir(&skills_root) {
            Ok(e) => e,
            // Absent / unreadable skills dir → no visible skills (≡ StubSkillSummary).
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        for entry in entries.flatten() {
            if out.len() >= MAX_VISIBLE_SKILLS {
                break; // count bound (W2)
            }
            // Only a real subdirectory is a skill dir. `DirEntry::file_type` does NOT
            // follow symlinks, so a symlink-to-dir planted as a skill entry is skipped.
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let Some(skill_id) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let dir = entry.path();
            // Stat-before-open bounded reads of SKILL.md + .meta.yaml (W1).
            let Some(content) = read_regular_capped(&dir.join("SKILL.md"), MAX_SKILL_READ_BYTES)
            else {
                continue;
            };
            let Some(meta_raw) = read_regular_capped(&dir.join(".meta.yaml"), MAX_SKILL_READ_BYTES)
            else {
                continue;
            };
            let Ok(meta) = serde_yml::from_str::<serde_yml::Value>(&meta_raw) else {
                continue; // unparseable meta → skip (corruption-skip, ≡ list_active)
            };
            // Cross-check meta.skill_id == dir name (cap-skills `read_active` guard:
            // reject a corrupt/tampered meta whose embedded id ≠ the path key).
            if meta.get("skill_id").and_then(|v| v.as_str()) != Some(skill_id.as_str()) {
                continue;
            }
            // Score = the active skill's recorded version (deterministic proxy).
            let version = meta.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
            out.push(SkillSummaryEntry {
                name: skill_id,
                summary: extract_skill_summary(&content),
                score: version as f32,
            });
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Real-able ports the caller supplies (with reusable production constructors).
// ─────────────────────────────────────────────────────────────────────────

/// Empty `AgentTreeSnapshot` — the no-`fs`-capability fallback (without `fs` no
/// `agent_tree_snapshot` is built). An fs agent instead gets the REAL shared
/// `AgentTreeStore` snapshot via the pub `WiringHandles.agent_tree_snapshot` field
/// (wired into the assembler in `start.rs`), into which the spawn host-fns now
/// record `Sub` nodes (011). Wave-12 BRIDGED the colon/bare keying — `assemble()`
/// matches `# Available Delegates` against the agent-id alias set, so a real
/// product-spawned Sub now surfaces by NAME (SYS-AC-011 stays DEFERRED only for the
/// empty-caps WIT spawn cap-lift gap). Returns no nodes / no relations.
pub struct EmptyAgentTree;
impl AgentTreeReader for EmptyAgentTree {
    fn parent_of(&self, _agent_id: &str) -> Option<String> {
        None
    }
    fn children_of(&self, _agent_id: &str) -> Vec<String> {
        Vec::new()
    }
    fn siblings_of(&self, _agent_id: &str) -> Vec<String> {
        Vec::new()
    }
    fn agent_exists(&self, _agent_id: &str) -> bool {
        false
    }
    fn agent_kind(&self, _agent_id: &str) -> Option<AgentKind> {
        None
    }
    fn capabilities(&self, _agent_id: &str) -> Vec<Capability> {
        Vec::new()
    }
}
impl AgentTreeSnapshot for EmptyAgentTree {
    fn snapshot(&self) -> AgentTreeSnapshotData {
        AgentTreeSnapshotData {
            nodes: Vec::new(),
            parent_of: std::collections::HashMap::new(),
            children_of: std::collections::HashMap::new(),
            peer_slug_map: std::collections::HashMap::new(),
            revision: 0,
        }
    }
}

/// Empty `CallableInventoryReader` — production default (no wasm/mcp tools
/// surfaced until cap-tools/cap-mcp inventory wiring lands in Step-3). The
/// harness passes a populated `cap_tools::CallableInventory` instead.
pub struct EmptyCallableInventory;
impl CallableInventoryReader for EmptyCallableInventory {
    fn list_wasm_tools(&self, _agent_id: &str) -> Vec<ToolEntry> {
        Vec::new()
    }
    fn list_mcp_tools(&self, _agent_id: &str) -> Vec<McpToolEntry> {
        Vec::new()
    }
}

/// A `HostFnInventoryReader` backed by a fixed list of [`HostFnEntry`] — usable
/// by both production (built from a [`HostRegistry`] capability-probe via
/// [`host_fns_from_registry`]) and the harness (a hand-built list). Returns the
/// same list for every agent (per-agent grant filtering is a future concern).
pub struct FixedHostFnInventory {
    entries: Vec<HostFnEntry>,
}
impl FixedHostFnInventory {
    pub fn new(entries: Vec<HostFnEntry>) -> Self {
        Self { entries }
    }

    /// Build from bare host-fn names (description/schema empty). Lets downstream
    /// callers (e.g. the system-acceptance harness) construct a host-fn inventory
    /// without importing `HostFnEntry` directly.
    pub fn from_names(names: &[&str]) -> Self {
        Self {
            entries: names
                .iter()
                .map(|n| HostFnEntry {
                    name: (*n).to_string(),
                    description: String::new(),
                    params_schema: serde_json::Value::Null,
                })
                .collect(),
        }
    }
}
impl HostFnInventoryReader for FixedHostFnInventory {
    fn list_host_fns(&self, _agent_id: &str) -> Vec<HostFnEntry> {
        self.entries.clone()
    }
}

/// Build a `HostFnEntry` list by PROBING a [`HostRegistry`] for a fixed
/// capability allowlist (the registry has no generic enumerate — only
/// `lookup(cap)`). Each registered spec under a probed capability becomes a
/// `HostFnEntry { name, description: "", params_schema: null }` (the registry
/// carries no description/schema). De-duplicated by name. Production wiring.
pub fn host_fns_from_registry(registry: &dyn HostRegistry, caps: &[&str]) -> Vec<HostFnEntry> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for cap in caps {
        for spec in registry.lookup(cap) {
            if seen.insert(spec.name.clone()) {
                out.push(HostFnEntry {
                    name: spec.name,
                    description: String::new(),
                    params_schema: serde_json::Value::Null,
                });
            }
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────
// Stage-C SAT-A — the 6 L1-L6 reader ports (12th–17th `ContextAssemblerImpl::new`
// deps). L2/L3 read the agent's `turn-index.yaml`, L4 the `summary.yaml` (the
// cap-memory task artifacts SAT-B's PostProcessor writes); L1/L5/L6 are inert
// this slice (no embedding index / distinct synthesis surface / Tier-1b overlap
// — MODULE-010 §3.8 Stage-C SAT-A). All file reads are task_id-path-validated,
// size-capped, and reject records whose embedded agent/task ids mismatch.
// ─────────────────────────────────────────────────────────────────────────

/// Empty L1 vector reader — inert this slice (`MemoryEntry` carries no embedding;
/// no persistent embedding index exists). Used in BOTH the all-stub path and the
/// real history path's L1 slot.
struct StubVectorIndex;
#[async_trait]
impl VectorIndexReader for StubVectorIndex {
    async fn lookup(&self, _agent_id: &str, _q: &[f32]) -> Result<Vec<VectorHit>, PortError> {
        Ok(Vec::new())
    }
}

/// Empty L2 reader — all-stub path (no history files).
struct StubL2Digest;
#[async_trait]
impl L2DigestReader for StubL2Digest {
    async fn read_digests(
        &self,
        _agent_id: &str,
        _task_id: &str,
    ) -> Result<Vec<TurnDigestForEmbed>, PortError> {
        Ok(Vec::new())
    }
}

/// Empty L3 reader — all-stub path.
struct StubL3Epoch;
#[async_trait]
impl L3EpochReader for StubL3Epoch {
    async fn read_epoch(
        &self,
        _agent_id: &str,
        _task_id: &str,
    ) -> Result<Option<EpochSummary>, PortError> {
        Ok(None)
    }
}

/// Empty L4 reader — all-stub path.
struct StubL4TaskSummary;
#[async_trait]
impl L4TaskSummaryReader for StubL4TaskSummary {
    async fn read_task_summary(
        &self,
        _agent_id: &str,
        _task_id: &str,
    ) -> Result<Option<TaskSummaryView>, PortError> {
        Ok(None)
    }
}

/// Empty L5 reader — inert this slice (cross-task syntheses live in a distinct
/// `syntheses/*.md` / `Synthesis` surface, NOT `summary.yaml`).
struct StubL5Synthesis;
#[async_trait]
impl L5SynthesisReader for StubL5Synthesis {
    async fn read_syntheses(
        &self,
        _agent_id: &str,
        _task_id: &str,
    ) -> Result<Vec<SynthesisView>, PortError> {
        Ok(Vec::new())
    }
}

/// Empty L6 reader — inert this slice (`MemoryStore.recall` overlaps the Tier-1b
/// knowledge map; surfacing it here would duplicate `Fact` content in the prompt).
struct StubL6Consolidation;
#[async_trait]
impl L6ConsolidationReader for StubL6Consolidation {
    async fn read_global_memory(
        &self,
        _agent_id: &str,
    ) -> Result<Vec<GlobalMemoryRecord>, PortError> {
        Ok(Vec::new())
    }
}

/// Max bytes for a single cap-memory history artifact (`turn-index.yaml` /
/// `summary.yaml`) read before serde parse — both carriers' docstrings require
/// the caller to cap input size (YAML-bomb / allocation-DoS defense). 2 MiB is
/// generous for a per-task index (a `TurnEntry` is ~a few hundred bytes; 2 MiB
/// ≈ thousands of turns) while tightly bounding the per-turn parse cost
/// (adversarial-r9 W1 — the read runs on every turn with a task_id).
///
/// **Known per-turn cost (deferred optimization, adversarial-r9 W1)**: L2
/// (`read_digests`) and L3 (`read_epoch`) each independently parse
/// `turn-index.yaml`, so the coordinator parses it TWICE per turn (+ once for
/// `summary.yaml`), synchronously via `std::fs` in the async turn path. Bounded
/// by this cap; a future optimization can share a single parse across L2/L3
/// (per-pass memo keyed by task_id, with freshness handling) and/or move the
/// blocking read to `spawn_blocking`.
const MAX_HISTORY_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Reject a `task_id` that is unsafe to substitute into the
/// `{memory_root}/tasks/{task_id}/…` path: empty, over-long, containing a path
/// separator / `..` traversal sequence / control char, or any non-slug char.
fn is_safe_task_id(task_id: &str) -> bool {
    !task_id.is_empty()
        && task_id.len() <= 256
        && !task_id.contains("..")
        && task_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Read a history artifact as a `String`, fail-closed on every hazard:
/// - **symlink escape**: `canonicalize` resolves all symlinks (in the file AND
///   its parent dirs); the resolved path MUST stay under the canonical
///   `root` (the agent's own memory dir), else `None` — so a symlink planted
///   under `tasks/{task_id}/` cannot redirect the read outside the root.
///   (Within-root redirection is additionally caught by the embedded
///   agent/task-id checks.)
/// - **oversize**: reject if the open file's length `> max_bytes`.
/// - **TOCTOU grow/swap**: the read itself is bounded by `take(max_bytes)`, so a
///   file that grew past the cap after the length check is read-truncated (and
///   a mid-char cut fails the UTF-8 decode → `None`), never an unbounded alloc.
/// Any error → `None` (the reader then yields empty, degrading gracefully).
///
/// **Residual TOCTOU (disclosed, defense-in-depth-only)**: this canonicalizes
/// then reopens by pathname, so a concurrent swap of a path component to a
/// symlink between `canonicalize` and `File::open` could still be followed (the
/// classic check-then-open race). It is NOT a practical escalation here: the
/// caller already validated `task_id` (no traversal), `root` is the agent's own
/// 0700 `.agent/memory` (same trust domain), and any followed file must STILL
/// deserialize as a `deny_unknown_fields` `TurnIndex`/`Summary` AND pass the
/// embedded agent/task-id check — so a redirected read yields content only if
/// the target is itself valid history YAML bearing this agent's own ids. The
/// race-free fix is `openat2(RESOLVE_NO_SYMLINKS)` (Linux) with a fallback
/// (cap-fs / MODULE-001 §3.7 precedent), tracked as a future hardening.
fn read_capped_under(root: &Path, path: &Path, max_bytes: u64) -> Option<String> {
    use std::io::Read;
    let canon_root = std::fs::canonicalize(root).ok()?;
    let canon = std::fs::canonicalize(path).ok()?; // resolves symlinks; None if missing
    if !canon.starts_with(&canon_root) {
        return None;
    }
    let file = std::fs::File::open(&canon).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > max_bytes {
        return None;
    }
    let mut buf = String::new();
    file.take(max_bytes).read_to_string(&mut buf).ok()?;
    Some(buf)
}

/// Real cap-memory-backed L2/L3/L4 reader over the agent's persisted task
/// artifacts (`{memory_root}/tasks/{task_id}/{turn-index,summary}.yaml`). Bound
/// at construction to the agent's memory root + its query-alias set ({bare cap
/// write-id, colon routing-id}); the `task_id` is supplied per read (the reader
/// trait arg). Production content is SAT-B-gated (SAT-B's PostProcessor writes
/// these files); absent / oversize / invalid / id-mismatched → empty.
///
/// **Cross-AGENT isolation (enforced here)**: the per-agent `memory_root` + the
/// `agent_matches` embedded-id check confine every read to the REQUESTING
/// agent's OWN tasks — a sender cannot make this reader surface another agent's
/// history.
///
/// **Turn→task authorization (cross-module HAND-OFF — adversarial-r9 C1,
/// user-accepted 2026-06-16)**: this reader reads whatever `task_id` the turn's
/// `AssemblyContext` carries (sourced from `MessageContext.task_id`). It does
/// NOT — and cannot — verify that the inbound turn was AUTHORIZED to reference
/// that task; the reader has no authz model, and reading the requested task's
/// context IS the assembler's contract. A guest can set an arbitrary `task_id`
/// via the `notify-agent` WIT host-fn (MODULE-006 messaging), which would steer
/// the RECEIVING agent to fold one of its OWN (still same-agent) tasks' history
/// into the turn — an intra-agent cross-task confused-deputy. Authorizing which
/// `task_id` a sender may set is the MESSAGING/SCHEDULER layer's responsibility
/// (MODULE-006 `notify-agent` admission / MODULE-014 turn routing), NOT this
/// reader's. Tracked as a cross-module hand-off for that owner. (In the current
/// daemon all INBOUND paths set `context: None` → `task_id` empty → this reader
/// is inert; only `notify-agent` activates it.)
pub struct CapMemoryHistoryReader {
    memory_root: PathBuf,
    query_aliases: Vec<String>,
}

impl CapMemoryHistoryReader {
    pub fn new(memory_root: PathBuf, query_aliases: Vec<String>) -> Self {
        Self {
            memory_root,
            query_aliases,
        }
    }

    /// Cross-agent check: the record's embedded `agent_id` must be one of the
    /// query aliases. **Fail-CLOSED** — an empty alias set matches NOTHING (a
    /// misconfigured reader yields no content rather than leaking any agent's
    /// history). Production always supplies a non-empty alias set ({bare cap
    /// write-id, colon routing-id}).
    fn agent_matches(&self, embedded: &str) -> bool {
        !self.query_aliases.is_empty() && self.query_aliases.iter().any(|a| a == embedded)
    }

    /// Build the per-task dir, rejecting an unsafe `task_id` (path-traversal).
    fn task_dir(&self, task_id: &str) -> Option<PathBuf> {
        if !is_safe_task_id(task_id) {
            return None;
        }
        Some(self.memory_root.join("tasks").join(task_id))
    }

    fn load_turn_index(&self, task_id: &str) -> Option<TurnIndex> {
        let path = self.task_dir(task_id)?.join("turn-index.yaml");
        let raw = read_capped_under(&self.memory_root, &path, MAX_HISTORY_FILE_BYTES)?;
        serde_yml::from_str::<TurnIndex>(&raw).ok()
    }

    fn load_summary(&self, task_id: &str) -> Option<Summary> {
        let path = self.task_dir(task_id)?.join("summary.yaml");
        let raw = read_capped_under(&self.memory_root, &path, MAX_HISTORY_FILE_BYTES)?;
        serde_yml::from_str::<Summary>(&raw).ok()
    }
}

#[async_trait]
impl L2DigestReader for CapMemoryHistoryReader {
    async fn read_digests(
        &self,
        _agent_id: &str,
        task_id: &str,
    ) -> Result<Vec<TurnDigestForEmbed>, PortError> {
        let Some(index) = self.load_turn_index(task_id) else {
            return Ok(Vec::new());
        };
        // `TurnEntry` carries both ids — reject any turn whose embedded
        // task_id ≠ requested OR whose agent_id is not an alias (cross-task /
        // cross-agent history-injection defense).
        let out = index
            .turns
            .into_iter()
            .filter(|t| t.task_id == task_id && self.agent_matches(&t.agent_id))
            .map(|t| TurnDigestForEmbed {
                turn_id: t.turn as u64,
                digest: t.digest,
                collapsed_view: t.collapsed_view,
            })
            .collect();
        Ok(out)
    }
}

#[async_trait]
impl L3EpochReader for CapMemoryHistoryReader {
    async fn read_epoch(
        &self,
        _agent_id: &str,
        task_id: &str,
    ) -> Result<Option<EpochSummary>, PortError> {
        let Some(index) = self.load_turn_index(task_id) else {
            return Ok(None);
        };
        // `Epoch` / `TurnIndexMeta` carry no ids — only surface an epoch if the
        // file genuinely belongs to this task (≥1 turn matches the requested
        // task + an alias), tying L3's validity to the same per-turn check L2
        // applies (the validated task-scoped path is the primary defense).
        let belongs = index
            .turns
            .iter()
            .any(|t| t.task_id == task_id && self.agent_matches(&t.agent_id));
        if !belongs {
            return Ok(None);
        }
        Ok(index.epochs.into_iter().next_back().map(|e| EpochSummary {
            epoch_id: e.id,
            summary: e.summary,
        }))
    }
}

#[async_trait]
impl L4TaskSummaryReader for CapMemoryHistoryReader {
    async fn read_task_summary(
        &self,
        _agent_id: &str,
        task_id: &str,
    ) -> Result<Option<TaskSummaryView>, PortError> {
        let Some(summary) = self.load_summary(task_id) else {
            return Ok(None);
        };
        // `Summary.meta` carries both ids — reject a mismatched/stale file.
        if summary.meta.task_id != task_id || !self.agent_matches(&summary.meta.agent_id) {
            return Ok(None);
        }
        Ok(Some(TaskSummaryView {
            task_id: summary.meta.task_id,
            summary: summary.brief,
        }))
    }
}

/// Construct the [`ContextAssemblerImpl`] from all 19 ports (the 8 real-able +
/// the 3 always-stub + the 6 L-reader ports + the Stage-C SAT-E
/// `PromptInjectionHelpers` + the Wave-12 Lane C `DecompositionReader`). The
/// single place the 19-arg constructor is called;
/// every public builder funnels through here. The concrete CONTRACT-114
/// `DefaultPromptInjectionHelpers` is constructed HERE (cli already deps
/// cap-http) — context-engine stays dep-light (it takes only the trait-object
/// port).
#[allow(clippy::too_many_arguments)]
/// Wave-12 Lane C — the production [`DecompositionReader`] adapter. Bridges the
/// context-engine port to MODULE-005's [`DefaultDecompositionStore`] (the SAME store
/// instance the decomposition host-fns record into, shared via `wire_capabilities`).
///
/// **Bare-first owner resolution (the colon/bare keying fix)**: `DefaultDecompositionStore::get`
/// validates the caller as a registered `AgentTreeStore` node and REJECTS colon-shaped
/// ids (owner ids are `[A-Za-z0-9_-]`). The assembler passes `ctx.agent_id` (the colon
/// msg-id `agent:default` in production), so this adapter tries its construction-time
/// alias set `{bare cap write-id, colon routing-id}` BARE-FIRST until one resolves —
/// fixing the residual the 011 delegates section left open (where the colon key never
/// matched the bare-recorded nodes). Filters to NON-orphaned subtasks and stringifies
/// the status at this boundary (`status_tag`) so context-engine never imports
/// `cap_lifecycle::SubtaskStatus`. Fail-soft: no `task_id` / store error / no task →
/// empty `Vec` (assembly never aborts).
pub struct CapDecompositionReader {
    store: Arc<DefaultDecompositionStore>,
    /// `{bare cap write-id, colon routing-id}` — MUST be bare-first (the bare cap-id
    /// is the registered owner; colon ids are rejected by the store).
    query_aliases: Vec<String>,
}

impl CapDecompositionReader {
    pub fn new(store: Arc<DefaultDecompositionStore>, query_aliases: Vec<String>) -> Self {
        Self {
            store,
            query_aliases,
        }
    }
}

#[async_trait]
impl DecompositionReader for CapDecompositionReader {
    async fn read_active_subtasks(
        &self,
        _agent_id: &str,
        task_id: Option<&str>,
    ) -> Vec<SubtaskView> {
        let Some(task_id) = task_id else {
            return Vec::new(); // no active task ⇒ no decomposition section
        };
        // Bare-first owner resolution (see struct doc): the store's `get` rejects
        // colon ids as owners, so try each alias until one resolves to a real owner.
        for alias in &self.query_aliases {
            match self.store.get(alias, task_id) {
                Ok(Some(state)) => {
                    return state
                        .subtasks
                        .into_iter()
                        .filter(|s| !s.orphaned)
                        .map(|s| SubtaskView {
                            subtask_id: s.subtask_id,
                            title: s.title,
                            status: status_tag(s.status).to_string(),
                        })
                        .collect();
                }
                // Valid owner, but no such task — the task is owner-scoped, so no
                // other alias can hold it. Stop with empty.
                Ok(None) => return Vec::new(),
                // Non-owner alias (PermissionDenied) or io error — try the next
                // alias; fail-soft to empty if none resolve.
                Err(_) => continue,
            }
        }
        Vec::new()
    }
}

/// Wave-12 Lane C — the no-op [`DecompositionReader`] fallback (mirrors
/// [`EmptyAgentTree`]). Used on every path with no decomposition store (no
/// fs/messaging capability, or the back-compat builders) ⇒ no Tier-2 ⑭ section.
pub struct EmptyDecomposition;

#[async_trait]
impl DecompositionReader for EmptyDecomposition {
    async fn read_active_subtasks(
        &self,
        _agent_id: &str,
        _task_id: Option<&str>,
    ) -> Vec<SubtaskView> {
        Vec::new()
    }
}

fn build_with_all_ports(
    event_bus: Arc<dyn EventBusEmit>,
    callable_inventory: Arc<dyn CallableInventoryReader>,
    host_fn_inventory: Arc<dyn HostFnInventoryReader>,
    agent_tree: Arc<dyn AgentTreeSnapshot>,
    embedding: Arc<dyn EmbeddingPort>,
    knowledge_map: Arc<dyn KnowledgeMapReader>,
    unified_search: Arc<dyn UnifiedSearchPort>,
    task_index: Arc<dyn TaskIndexPort>,
    l1_vector: Arc<dyn VectorIndexReader>,
    l2_digest: Arc<dyn L2DigestReader>,
    l3_epoch: Arc<dyn L3EpochReader>,
    l4_summary: Arc<dyn L4TaskSummaryReader>,
    l5_synthesis: Arc<dyn L5SynthesisReader>,
    l6_consolidation: Arc<dyn L6ConsolidationReader>,
    // skills-J26 reader satellite: the 11th port. Was a hardcoded
    // `Arc::new(StubSkillSummary)`; now caller-supplied so production can inject
    // the real `DiskSkillSummaryReader` (every back-compat path passes the stub).
    skill_summary: Arc<dyn SkillSummaryReader>,
    // Wave-12 Lane A: the agent-id alias set ({bare cap-id, colon msg-id}) `assemble()`
    // uses to match ⑬ delegates `node.parent` AND drain the Tier-3 WarningQueue
    // (SYS-AC-011 + SYS-AC-122). `&[]` on the hermetic / back-compat paths
    // (single-`ctx.agent_id` behaviour); the per-agent builders pass the
    // production `[cap_agent_id (bare), msg_agent_id (colon)]`.
    query_aliases: &[String],
    // Wave-12 Lane C: the 19th ContextAssembler port. Caller-supplied so production
    // injects the real `CapDecompositionReader` and every back-compat path passes
    // `EmptyDecomposition` (⇒ no Tier-2 ⑭ section ⇒ byte-identical).
    decomposition: Arc<dyn DecompositionReader>,
) -> Arc<dyn ContextAssembler> {
    Arc::new(
        ContextAssemblerImpl::new(
            callable_inventory,
            host_fn_inventory,
            Arc::new(StubAgentIdentity),
            knowledge_map,
            agent_tree,
            embedding,
            task_index,
            Arc::new(StubLightLlm),
            unified_search,
            event_bus,
            skill_summary,
            l1_vector,
            l2_digest,
            l3_epoch,
            l4_summary,
            l5_synthesis,
            l6_consolidation,
            // Stage-C SAT-E: 18th port — the concrete CONTRACT-114 helper. cap-http
            // is a cli dep (the only crate where it's allowed); context-engine takes
            // the trait object only (dep-light, AC-01).
            Arc::new(cap_http::DefaultPromptInjectionHelpers::default()),
            // Wave-12 Lane C: 19th port — the decomposition reader (real
            // `CapDecompositionReader` in production, `EmptyDecomposition` on every
            // back-compat path).
            decomposition,
        )
        .with_agent_id_aliases(query_aliases.to_vec()),
    )
}

// ─────────────────────────────────────────────────────────────────────────
// The single composition entry.
// ─────────────────────────────────────────────────────────────────────────

/// Assemble the real [`ContextAssemblerImpl`] from the 4 caller-supplied
/// "real-able" ports + the 7 hermetic stubs. The caller decides how real the
/// tool/tree ports are (production passes [`EmptyCallableInventory`] /
/// [`EmptyAgentTree`] / an empty [`FixedHostFnInventory`]; the harness passes
/// populated ones to witness SYS-AC-010).
pub fn build_context_assembler(
    event_bus: Arc<dyn EventBusEmit>,
    callable_inventory: Arc<dyn CallableInventoryReader>,
    host_fn_inventory: Arc<dyn HostFnInventoryReader>,
    agent_tree: Arc<dyn AgentTreeSnapshot>,
) -> Arc<dyn ContextAssembler> {
    // Back-compat: all 7 data ports hermetic-stub (the pre-B1 behaviour).
    build_context_assembler_with_providers(
        event_bus,
        callable_inventory,
        host_fn_inventory,
        agent_tree,
        Arc::new(StubEmbedding),
        Arc::new(StubKnowledgeMap),
        Arc::new(StubUnifiedSearch),
        Arc::new(StubTaskIndex),
    )
}

/// B1 backbone (2026-06-09): assemble the real [`ContextAssemblerImpl`] with the
/// 4 caller-supplied "real-able" ports PLUS the 4 data ports this slice can make
/// real (`embedding` / `knowledge_map` / `unified_search` / `task_index`). The
/// remaining 3 data ports (`agent_identity` / `light_llm` / `skill_summary`)
/// stay hermetic stubs. `build_context_assembler` delegates here with all-stub
/// data ports; `build_context_assembler_for_agent` supplies the real ones.
#[allow(clippy::too_many_arguments)]
pub fn build_context_assembler_with_providers(
    event_bus: Arc<dyn EventBusEmit>,
    callable_inventory: Arc<dyn CallableInventoryReader>,
    host_fn_inventory: Arc<dyn HostFnInventoryReader>,
    agent_tree: Arc<dyn AgentTreeSnapshot>,
    embedding: Arc<dyn EmbeddingPort>,
    knowledge_map: Arc<dyn KnowledgeMapReader>,
    unified_search: Arc<dyn UnifiedSearchPort>,
    task_index: Arc<dyn TaskIndexPort>,
) -> Arc<dyn ContextAssembler> {
    // The 6 L-reader ports are all-stub here (back-compat: the all-stub path +
    // the harness's `build_context_assembler` route through this). The real
    // L2/L3/L4 history readers are wired by
    // `build_context_assembler_for_agent_with_history`.
    build_with_all_ports(
        event_bus,
        callable_inventory,
        host_fn_inventory,
        agent_tree,
        embedding,
        knowledge_map,
        unified_search,
        task_index,
        Arc::new(StubVectorIndex),
        Arc::new(StubL2Digest),
        Arc::new(StubL3Epoch),
        Arc::new(StubL4TaskSummary),
        Arc::new(StubL5Synthesis),
        Arc::new(StubL6Consolidation),
        // Back-compat: no skills root on this path → no `# Available Skills`.
        Arc::new(StubSkillSummary),
        &[], // Wave-12 Lane A: no alias bridge on the bare/back-compat path (single-id)
        // Wave-12 Lane C: no decomposition on this back-compat path → no Tier-2 ⑭
        // section (byte-identical to pre-Wave-12).
        Arc::new(EmptyDecomposition),
    )
}

// ─────────────────────────────────────────────────────────────────────────
// B1 backbone — real cap-memory-backed data ports + the agent-level entry.
// ─────────────────────────────────────────────────────────────────────────

/// Upper bound on active entries pulled into the boot-time knowledge snapshot per
/// alias. The Tier-1b renderer caps the rendered section at `MAX_TOPICS` (10
/// topics) / 500 tokens (`context-engine::knowledge_map`), so this is set well
/// above that for token-truncation headroom while bounding the per-boot clone
/// (folds AUDIT-r4 Codex Warning — `recall(.., 0)` unbounded amplification).
const KNOWLEDGE_RECALL_LIMIT: u32 = 64;

/// Project the agent's ACTIVE knowledge into [`KnowledgeRecord`]s. Uses
/// `MemoryStore::recall(write_agent_id, "", KNOWLEDGE_RECALL_LIMIT)` (NOT `list`) so
/// the inactive forgotten/superseded tail is excluded (`recall` filters
/// `is_active`; an empty query substring-matches all active). Reads the SINGLE
/// `write_agent_id` bucket — the id cap-memory writes under — NEVER a union across
/// aliases (the alias/colon-id split is handled on the QUERY side by
/// [`real_knowledge_map_reader`]'s keying, not by widening the READ; folds
/// ADVERSARIAL-r7 W3). Topic `name` = first tag, else the entry type; `body` = the
/// entry content.
fn load_knowledge_records(store: &MemoryStore, write_agent_id: &str) -> Vec<KnowledgeRecord> {
    // Read ONLY the agent's own write bucket (folds ADVERSARIAL-r7 W3: reading
    // every alias + unioning could merge a distinct colon-id bucket into the bare
    // agent's prompt; cap-memory writes under ONE id — the bare cap write-id — so
    // we read exactly that one bucket, never a union). BOUNDED recall (NOT `limit
    // 0` — folds AUDIT-r4: the Tier-1b renderer keeps ≤ MAX_TOPICS(10)/500 tokens,
    // so `KNOWLEDGE_RECALL_LIMIT` headroom bounds the per-build projection clone).
    // `recall` (NOT `list`) filters `is_active`, so forgotten/superseded never leak.
    store
        .recall(write_agent_id, "", KNOWLEDGE_RECALL_LIMIT)
        .into_iter()
        .map(|entry| {
            let name = entry
                .tags
                .first()
                .cloned()
                .unwrap_or_else(|| memory_type_label(&entry.entry_type).to_string());
            KnowledgeRecord::Topic {
                name,
                body: entry.content,
            }
        })
        .collect()
}

fn memory_type_label(t: &MemoryType) -> &'static str {
    match t {
        MemoryType::Fact => "fact",
        MemoryType::UserPreference => "user-preference",
    }
}

/// Build a real [`KnowledgeMapReader`] over the agent's OWN write-bucket records,
/// keyed under the explicit `query_aliases` set ({bare cap write-id, colon
/// assembler routing-id}) so the assembler hits the same records whichever id it
/// queries (folds the prod colon/bare key-split). Records are read from
/// `write_agent_id` ONLY (folds ADVERSARIAL-r7 W3 — no cross-bucket union), then
/// projected under every query alias. Empty records → the reader yields `None`
/// (≡ stub). The projection is a build-time snapshot (MODULE-010 §3.6 B1 row).
fn real_knowledge_map_reader(
    store: &MemoryStore,
    write_agent_id: &str,
    query_aliases: &[String],
) -> Arc<dyn KnowledgeMapReader> {
    let records = load_knowledge_records(store, write_agent_id);
    let mut map: HashMap<String, Vec<KnowledgeRecord>> = HashMap::new();
    for alias in query_aliases {
        map.insert(alias.clone(), records.clone());
    }
    Arc::new(ProjectingKnowledgeMap::new(map))
}

/// Real `UnifiedSearchPort` over the agent corpus, alias-keyed. **Fed an EMPTY
/// corpus this slice** (no persistent embedding index exists — `MemoryEntry`
/// carries no embedding), so it returns empty results = byte-identical-behavior
/// to [`StubUnifiedSearch`]; ready for a future slice that populates embeddings.
fn real_unified_search(aliases: &[String]) -> Arc<dyn UnifiedSearchPort> {
    let mut corpora: HashMap<String, AgentSearchCorpus> = HashMap::new();
    for alias in aliases {
        corpora.insert(alias.clone(), AgentSearchCorpus::default());
    }
    Arc::new(RankingUnifiedSearch::new(corpora))
}

/// Real `TaskIndexPort`, alias-keyed. **Empty rows this slice** (see
/// [`real_unified_search`]) → byte-identical-behavior to [`StubTaskIndex`]
/// (router degrades to `NewTask`).
fn real_task_index(aliases: &[String]) -> Arc<dyn TaskIndexPort> {
    let mut rows: HashMap<String, Vec<IndexedTask>> = HashMap::new();
    for alias in aliases {
        rows.insert(alias.clone(), Vec::new());
    }
    Arc::new(CosineTaskIndex::new(rows))
}

/// The agent-level composition entry both production (`start.rs`) and the
/// system-acceptance harness call. When `memory` is `Some` (the agent declared
/// the memory capability — the gate is the store's presence, owned by the single
/// composition root that opened it), the knowledge/search/task ports are made
/// REAL over **the SHARED registered `MemoryStore`** (the SAME `Arc` the WIT
/// handlers use — NOT a second `open()`; folds ADVERSARIAL-r7 W1/W2 + Claude-W:
/// no second hydration of the active set, no dual-handle corruption hazard, no
/// new `.agent/memory` open surface). `None` → the all-stub path, byte-identical
/// to pre-B1 (so `.agent/memory` content can never reach a no-memory-cap agent's
/// prompt). The `embedding` slot stays [`StubEmbedding`] regardless (hermeticity
/// — see [`GatewayEmbedding`]). `write_agent_id` = the bare cap id cap-memory
/// writes under (the ONLY bucket read); `query_aliases` = the id(s) the assembler
/// may query with ({bare write-id, colon routing-id} in prod; a single id in the
/// harness) — the projection is keyed under all of them so the colon-id query hits.
pub fn build_context_assembler_for_agent(
    event_bus: Arc<dyn EventBusEmit>,
    callable_inventory: Arc<dyn CallableInventoryReader>,
    host_fn_inventory: Arc<dyn HostFnInventoryReader>,
    agent_tree: Arc<dyn AgentTreeSnapshot>,
    memory: Option<Arc<MemoryStore>>,
    write_agent_id: &str,
    query_aliases: &[String],
) -> Arc<dyn ContextAssembler> {
    // Delegates to the history-aware builder with NO memory_root → the L2/L3/L4
    // file readers stay inert. The system-acceptance harness (which calls this
    // FROZEN signature) + any non-history caller keep their exact prior
    // behaviour; the real history readers are wired only by
    // `build_context_assembler_for_agent_with_history` (start.rs).
    build_context_assembler_for_agent_with_history(
        event_bus,
        callable_inventory,
        host_fn_inventory,
        agent_tree,
        memory,
        write_agent_id,
        query_aliases,
        None,
    )
}

/// Stage-C SAT-A — the history-aware agent-level entry. Identical to
/// [`build_context_assembler_for_agent`] PLUS the `memory_root` that activates the
/// real cap-memory-backed L2/L3/L4 history readers (`turn-index.yaml` /
/// `summary.yaml` under `{memory_root}/tasks/{task_id}/`).
///
/// **FROZEN 8-arg signature** (the system-acceptance harness + `cli/tests/` call
/// this form). skills-J26 satellite: this now delegates to
/// [`build_context_assembler_for_agent_with_skills`] with `skills_agent_root: None`
/// → [`StubSkillSummary`] → byte-identical to its pre-satellite behaviour.
#[allow(clippy::too_many_arguments)]
pub fn build_context_assembler_for_agent_with_history(
    event_bus: Arc<dyn EventBusEmit>,
    callable_inventory: Arc<dyn CallableInventoryReader>,
    host_fn_inventory: Arc<dyn HostFnInventoryReader>,
    agent_tree: Arc<dyn AgentTreeSnapshot>,
    memory: Option<Arc<MemoryStore>>,
    write_agent_id: &str,
    query_aliases: &[String],
    memory_root: Option<&Path>,
) -> Arc<dyn ContextAssembler> {
    build_context_assembler_for_agent_with_skills(
        event_bus,
        callable_inventory,
        host_fn_inventory,
        agent_tree,
        memory,
        write_agent_id,
        query_aliases,
        memory_root,
        None, // no skills root → StubSkillSummary (byte-identical to pre-satellite)
    )
}

/// skills-J26 reader satellite (2026-06-20) — the production agent-level entry that
/// `start.rs` calls. Identical to [`build_context_assembler_for_agent_with_history`]
/// PLUS `skills_agent_root`, which activates the real on-disk
/// [`DiskSkillSummaryReader`] for the Tier-2 ⑩ `# Available Skills` section.
///
/// **`skills_agent_root` gating (independent of memory):** skills ⊥ memory. `Some`
/// (production: `WiringHandles.skills_root` = `<workspace>/.agent`, set iff the
/// agent declared the `skills` capability) → the real reader over the agent's
/// activated skills; `None` → [`StubSkillSummary`] (no section). The reader is
/// active in BOTH the `memory: Some` and `memory: None` arms, so a skills-but-no-
/// memory agent still surfaces its skills. `memory_root` keeps its own
/// memory-capability gate (the L2/L3/L4 history readers), unchanged. The
/// `embedding` slot stays [`StubEmbedding`] regardless (hermeticity).
/// Wave-12 Lane C — the production agent-level entry that `start.rs` calls. It is
/// [`build_context_assembler_for_agent_with_skills`] PLUS the Tier-2 ⑭
/// `DecompositionReader` (real `CapDecompositionReader` in production).
/// `_with_skills` is now a THIN WRAPPER that delegates here with
/// `EmptyDecomposition`, so the real memory/skills/history wiring lives in ONE body
/// (no divergent copies) and every frozen `_with_skills` caller (system-acceptance
/// harness, `spawn_wiring_011`) compiles + behaves byte-identically.
#[allow(clippy::too_many_arguments)]
pub fn build_context_assembler_for_agent_with_decomposition(
    event_bus: Arc<dyn EventBusEmit>,
    callable_inventory: Arc<dyn CallableInventoryReader>,
    host_fn_inventory: Arc<dyn HostFnInventoryReader>,
    agent_tree: Arc<dyn AgentTreeSnapshot>,
    memory: Option<Arc<MemoryStore>>,
    write_agent_id: &str,
    query_aliases: &[String],
    memory_root: Option<&Path>,
    skills_agent_root: Option<&Path>,
    decomposition: Arc<dyn DecompositionReader>,
) -> Arc<dyn ContextAssembler> {
    // The skill-summary reader is INDEPENDENT of the memory capability. `Some` →
    // the real DiskSkillSummaryReader over the agent's on-disk activated skills;
    // `None` → StubSkillSummary (byte-identical to pre-satellite, in BOTH arms).
    let skill_summary: Arc<dyn SkillSummaryReader> = match skills_agent_root {
        Some(root) => Arc::new(DiskSkillSummaryReader::new(root.to_path_buf())),
        None => Arc::new(StubSkillSummary),
    };
    match memory {
        Some(store) => {
            // Real L2/L3/L4 history readers ONLY when a memory_root is supplied
            // (capability already gated by this `Some` arm). The SAME reader Arc
            // backs all three trait slots.
            let (l2, l3, l4): (
                Arc<dyn L2DigestReader>,
                Arc<dyn L3EpochReader>,
                Arc<dyn L4TaskSummaryReader>,
            ) = match memory_root {
                Some(root) => {
                    let reader = Arc::new(CapMemoryHistoryReader::new(
                        root.to_path_buf(),
                        query_aliases.to_vec(),
                    ));
                    (reader.clone(), reader.clone(), reader)
                }
                None => (
                    Arc::new(StubL2Digest),
                    Arc::new(StubL3Epoch),
                    Arc::new(StubL4TaskSummary),
                ),
            };
            build_with_all_ports(
                event_bus,
                callable_inventory,
                host_fn_inventory,
                agent_tree,
                Arc::new(StubEmbedding), // hermeticity: GatewayEmbedding built but not live
                real_knowledge_map_reader(&store, write_agent_id, query_aliases),
                real_unified_search(query_aliases),
                real_task_index(query_aliases),
                Arc::new(StubVectorIndex), // L1 inert (no embedding index)
                l2,
                l3,
                l4,
                Arc::new(StubL5Synthesis), // L5 inert (distinct synthesis surface)
                Arc::new(StubL6Consolidation), // L6 inert (Tier-1b overlap)
                skill_summary,
                query_aliases, // Wave-12 Lane A: colon/bare alias bridge (⑬ + Tier-3)
                decomposition,
            )
        }
        // No-memory path: the all-stub data ports (byte-identical to
        // `build_context_assembler`'s port set), PLUS the (real-or-stub)
        // skill_summary so a skills-but-no-memory agent still surfaces skills.
        None => build_with_all_ports(
            event_bus,
            callable_inventory,
            host_fn_inventory,
            agent_tree,
            Arc::new(StubEmbedding),
            Arc::new(StubKnowledgeMap),
            Arc::new(StubUnifiedSearch),
            Arc::new(StubTaskIndex),
            Arc::new(StubVectorIndex),
            Arc::new(StubL2Digest),
            Arc::new(StubL3Epoch),
            Arc::new(StubL4TaskSummary),
            Arc::new(StubL5Synthesis),
            Arc::new(StubL6Consolidation),
            skill_summary,
            query_aliases, // Wave-12 Lane A: colon/bare alias bridge (⑬ + Tier-3)
            decomposition,
        ),
    }
}

/// skills-J26 reader satellite (2026-06-20) — the agent-level entry whose 9-arg
/// signature is FROZEN (called by the system-acceptance harness + `spawn_wiring_011`
/// + the `_with_history` chain). Wave-12 Lane C: now a thin wrapper that delegates to
/// [`build_context_assembler_for_agent_with_decomposition`] with
/// [`EmptyDecomposition`] — so the single shared body owns the real
/// memory/skills/history wiring AND this signature stays byte-identical (⇒ no
/// Tier-2 ⑭ section ⇒ assembled output byte-identical to pre-Wave-12). Production
/// (`start.rs`) calls `_with_decomposition` directly with the real reader.
#[allow(clippy::too_many_arguments)]
pub fn build_context_assembler_for_agent_with_skills(
    event_bus: Arc<dyn EventBusEmit>,
    callable_inventory: Arc<dyn CallableInventoryReader>,
    host_fn_inventory: Arc<dyn HostFnInventoryReader>,
    agent_tree: Arc<dyn AgentTreeSnapshot>,
    memory: Option<Arc<MemoryStore>>,
    write_agent_id: &str,
    query_aliases: &[String],
    memory_root: Option<&Path>,
    skills_agent_root: Option<&Path>,
) -> Arc<dyn ContextAssembler> {
    build_context_assembler_for_agent_with_decomposition(
        event_bus,
        callable_inventory,
        host_fn_inventory,
        agent_tree,
        memory,
        write_agent_id,
        query_aliases,
        memory_root,
        skills_agent_root,
        Arc::new(EmptyDecomposition),
    )
}

// ─────────────────────────────────────────────────────────────────────────
// Wave-16 Lane 2 — deep-content recall: populate the unified-search corpus from
// local memory + workspace files (the FIRST production caller of the Wave-13
// `build_agent_search_corpus` / `memory_search_docs` / `HashingEmbedding`
// primitives). DORMANT in production boot (`start.rs` keeps the empty-corpus
// `_with_decomposition` path → byte-identical); opted into by the
// system-acceptance `with_recall_corpus` axis to witness SYS-AC-005.
// ─────────────────────────────────────────────────────────────────────────

/// Max NON-EMPTY active memory docs ingested into the recall corpus (the active
/// set is already retention-bounded; this is defense-in-depth).
const MAX_RECALL_MEMORY_DOCS: u32 = 256;
/// Max workspace-content files ingested into the recall corpus.
const MAX_RECALL_FILES: usize = 256;
/// A file larger than this is SKIPPED entirely (fail-closed; never partially indexed).
const MAX_RECALL_FILE_BYTES: u64 = 64 * 1024;
/// Hard bound on the TOTAL directory-entries examined by the workspace walk (DoS
/// guard): caps both the wall-clock cost AND the candidate-path accumulation BEFORE
/// the `MAX_RECALL_FILES` output cap, so a pathological workspace cannot consume
/// unbounded time/memory on the (currently dormant) recall ingest path. 16× the
/// file cap — ample headroom to discover `MAX_RECALL_FILES` text files amid binaries.
const MAX_RECALL_SCAN_ENTRIES: usize = MAX_RECALL_FILES * 16;

/// Walk `workspace_root` and collect bounded, TOCTOU-safe text-file content docs.
/// Prunes hidden + `.git`/`.agent`/`.advance`/`target`/`node_modules` dirs during
/// descent; each candidate is re-validated through the `pub(crate)` `vlm_indexer`
/// [`confine`] (canonicalize + confine-under-root + symlink/hidden reject) and read
/// via [`read_capped_bytes`] (lstat-reject-non-regular + `O_NOFOLLOW`/`O_NONBLOCK`
/// + fd re-check). Non-UTF-8 / NUL-bearing (binary) / empty-after-trim files are
/// skipped. Deterministic (sorted) order; the `CorpusDoc::content` id is the
/// canonical workspace-relative `vpath` (provenance-stable, agent-independent).
fn walk_workspace_content_docs(workspace_root: &Path) -> Vec<CorpusDoc> {
    fn is_pruned_dir(name: &str) -> bool {
        name.starts_with('.') || name == "target" || name == "node_modules"
    }

    // 1. Enumerate candidate workspace-relative paths (dir-pruning, symlink-skipping),
    //    HARD-BOUNDED by `MAX_RECALL_SCAN_ENTRIES` total entries examined so neither the
    //    `rels` accumulation nor the `dirs` queue can grow unbounded on a pathological tree.
    let mut rels: Vec<String> = Vec::new();
    let mut dirs: Vec<PathBuf> = vec![workspace_root.to_path_buf()];
    let mut scanned: usize = 0;
    'walk: while let Some(dir) = dirs.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            scanned += 1;
            if scanned > MAX_RECALL_SCAN_ENTRIES {
                break 'walk; // DoS guard: bound total entries examined (+ rels/dirs growth)
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if is_pruned_dir(&name) {
                continue;
            }
            // `file_type()` is an lstat (does NOT follow symlinks): a symlink is
            // neither `is_dir` nor `is_file` here, so it is skipped (and `confine`
            // + `read_capped_bytes` reject it again downstream).
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if ft.is_dir() {
                dirs.push(path);
            } else if ft.is_file() {
                if let Ok(rel) = path.strip_prefix(workspace_root) {
                    if let Some(s) = rel.to_str() {
                        rels.push(s.to_string());
                    }
                }
            }
        }
    }
    rels.sort();
    rels.dedup();

    // 2. Confine + read + decode each, bounded by MAX_RECALL_FILES.
    let mut out: Vec<CorpusDoc> = Vec::new();
    for rel in rels {
        if out.len() >= MAX_RECALL_FILES {
            break;
        }
        let Some((abs, vpath)) = confine(workspace_root, &rel) else {
            continue; // hidden / symlink-escape / traversal / missing
        };
        let Some(bytes) = read_capped_bytes(&abs, MAX_RECALL_FILE_BYTES) else {
            continue; // non-regular / oversize / swapped-leaf
        };
        let Ok(text) = String::from_utf8(bytes) else {
            continue; // non-UTF-8 (binary)
        };
        if text.contains('\0') || text.trim().is_empty() {
            continue; // NUL-bearing (binary) or blank → un-rankable
        }
        out.push(CorpusDoc::content(vpath, text));
    }
    out
}

/// Build a POPULATED `UnifiedSearchPort` for the agent: ingest the agent's active
/// memory entries (`memory_search_docs`, exact-id `recall(write_agent_id,…)`) +
/// the workspace file content into [`CorpusDoc`]s, embed via `embedder`
/// ([`build_agent_search_corpus`]), and key the resulting [`AgentSearchCorpus`]
/// under EVERY alias (so the assembler's `unified_search(&ctx.agent_id, …)` —
/// which `RankingUnifiedSearch` looks up by EXACT key — hits regardless of which
/// alias form `assemble()` passes). The caller threads the SAME `embedder` Arc
/// into the assembler's `embedding` port so the query embedding is symmetric with
/// the corpus embeddings.
pub async fn build_recall_unified_search(
    memory: &MemoryStore,
    workspace_root: &Path,
    write_agent_id: &str,
    query_aliases: &[String],
    embedder: &dyn EmbeddingPort,
) -> Arc<dyn UnifiedSearchPort> {
    let mut docs: Vec<CorpusDoc> =
        memory_search_docs(memory, write_agent_id, MAX_RECALL_MEMORY_DOCS)
            .into_iter()
            .map(|d| CorpusDoc::memory(d.id, d.text))
            .collect();
    docs.extend(walk_workspace_content_docs(workspace_root));

    let corpus = build_agent_search_corpus(&docs, embedder).await;
    let mut corpora: HashMap<String, AgentSearchCorpus> = HashMap::new();
    for alias in query_aliases {
        corpora.insert(alias.clone(), corpus.clone());
    }
    Arc::new(RankingUnifiedSearch::new(corpora))
}

/// Wave-20 Lane `search` — the DUAL-PATH (dense + sparse FTS5) production recall
/// builder. Unlike [`build_recall_unified_search`] (dense-only `RankingUnifiedSearch`,
/// which ignores the query text), this populates a real in-memory SQLite index that
/// the MODULE-004 `R2d2UnifiedSearchImpl` queries with BOTH `vec_distance_cosine`
/// (dense) and `content_fts MATCH` (sparse BM25), bridged to the assembler's
/// `UnifiedSearchPort` by [`R2d2UnifiedSearchAdapter`]. This is what witnesses
/// SYS-AC-009.
///
/// Ingests the SAME corpus as `build_recall_unified_search` (the Wave-16 path:
/// `memory_search_docs` + `walk_workspace_content_docs`) under EACH query alias —
/// content via the `upsert_content_index` trait method (→ content_index + content_fts
/// + content_vec) and memory via the additive `database::upsert_memory_index_row`
/// (→ memory_index + memory_vec). Ingesting under the literal query-alias `agent_id`
/// sidesteps the colon/bare keying seam (R2d2 filters `WHERE agent_id = ?`). The
/// `embedder` MUST be 768-dim (the vec0 tables are fixed `float[768]`); a smaller-dim
/// embedder (e.g. the production `StubEmbedding`'s 16) fails `validate_embedding`, so
/// every row is skipped → empty index → empty recall = byte-identical to the dormant
/// `real_unified_search` path (this is what keeps the default boot DORMANT).
pub async fn build_dual_recall_unified_search(
    memory: &MemoryStore,
    workspace_root: &Path,
    write_agent_id: &str,
    query_aliases: &[String],
    embedder: &dyn EmbeddingPort,
) -> Arc<dyn UnifiedSearchPort> {
    // Per-kind fan-out cap for the R2d2 read path (the impl further caps at its
    // internal DEFAULT_FAN_OUT_LIMIT=50; any value ≥ the corpus size is fine).
    const DUAL_RECALL_FAN_OUT: u32 = 50;

    // In-memory SQLite index: 768-dim default tunables, migrations applied, a
    // single pooled connection (max_size=1) so the ingest writes and the recall
    // reads share ONE in-memory DB. No file I/O (avoids the volume-TCC hazard).
    let handle = match R2d2SqliteIndexHandle::new_in_memory() {
        Ok(h) => h,
        // Fail-safe: a handle/migration failure must NOT abort boot — fall back to
        // the empty-recall stub (byte-identical to the dormant path).
        Err(_) => return Arc::new(StubUnifiedSearch),
    };

    let mut docs: Vec<CorpusDoc> =
        memory_search_docs(memory, write_agent_id, MAX_RECALL_MEMORY_DOCS)
            .into_iter()
            .map(|d| CorpusDoc::memory(d.id, d.text))
            .collect();
    docs.extend(walk_workspace_content_docs(workspace_root));

    for doc in &docs {
        if doc.text.trim().is_empty() {
            continue;
        }
        let emb = match embedder.embed(&doc.text).await {
            Ok(v) if !v.is_empty() && v.iter().all(|x| x.is_finite()) => v,
            // Embed error / empty / non-finite → skip (defensive; matches
            // `build_agent_search_corpus`).
            _ => continue,
        };
        for alias in query_aliases {
            // BEST-EFFORT, FAIL-CLOSED contract (adversarial r10): a single rejected
            // row (a wrong-dim embedder on the dormant production path; an id with a
            // C0/separator byte; a transient SQLite fault) is OMITTED from the index
            // rather than aborting the whole ingest — a corpus-build hiccup must never
            // bring down `advance start`. This is fail-CLOSED, not fail-open: an
            // omitted row simply does not appear in recall (it can never inject a
            // spurious hit), so the SYS-AC-009 witness's presence assertions fail loud
            // if an expected row were dropped. The corpus is the agent's OWN workspace
            // + memory (its own trust boundary). No logger is wired on this dormant
            // boot path; a future production-ON lane that adds a config gate should
            // also thread a partial-index telemetry sink here.
            let _ = match doc.kind {
                CorpusDocKind::Content => {
                    handle.upsert_content_index(alias, &doc.id, &doc.text, Some(&emb), None)
                }
                CorpusDocKind::Memory => {
                    upsert_memory_index_row(&handle, alias, &doc.id, &doc.text, Some(&emb))
                }
            };
        }
    }

    let search = R2d2UnifiedSearchImpl::new(handle, DUAL_RECALL_FAN_OUT);
    Arc::new(R2d2UnifiedSearchAdapter::new(Arc::new(search)))
}

/// Recall-axis assembler builder: identical to the no-history port set of
/// [`build_context_assembler_for_agent_with_decomposition`] EXCEPT it threads the
/// caller-supplied populated `unified_search` + the real `embedding` (e.g.
/// `HashingEmbedding`) instead of `real_unified_search` (empty corpus) +
/// [`StubEmbedding`]. Every other tier port stays stub, so the only memory-derived
/// section is the Tier-3 `# Recalled Context`. Additive: the production boot path
/// (`build_context_assembler_for_agent_with_decomposition`) is untouched + stays
/// DORMANT (empty corpus → `format_recall_section`→None → byte-identical prompt).
#[allow(clippy::too_many_arguments)]
pub fn build_context_assembler_for_agent_with_recall(
    event_bus: Arc<dyn EventBusEmit>,
    callable_inventory: Arc<dyn CallableInventoryReader>,
    host_fn_inventory: Arc<dyn HostFnInventoryReader>,
    agent_tree: Arc<dyn AgentTreeSnapshot>,
    query_aliases: &[String],
    unified_search: Arc<dyn UnifiedSearchPort>,
    embedding: Arc<dyn EmbeddingPort>,
) -> Arc<dyn ContextAssembler> {
    build_with_all_ports(
        event_bus,
        callable_inventory,
        host_fn_inventory,
        agent_tree,
        embedding,                  // the REAL query embedder (symmetric with the corpus)
        Arc::new(StubKnowledgeMap), // Tier-1b inert → recall is the only memory-derived section
        unified_search,             // the POPULATED RankingUnifiedSearch
        Arc::new(StubTaskIndex),
        Arc::new(StubVectorIndex),
        Arc::new(StubL2Digest),
        Arc::new(StubL3Epoch),
        Arc::new(StubL4TaskSummary),
        Arc::new(StubL5Synthesis),
        Arc::new(StubL6Consolidation),
        Arc::new(StubSkillSummary),
        query_aliases,
        Arc::new(EmptyDecomposition),
    )
}

// ─────────────────────────────────────────────────────────────────────────
// B1 backbone — unit tests for the real cap-memory-backed adapters.
// ─────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use cap_memory::{MemoryEntry, MemoryStatus, MemoryType};

    fn fact(id: &str, agent: &str, content: &str) -> MemoryEntry {
        MemoryEntry {
            id: id.into(),
            agent_id: agent.into(),
            entry_type: MemoryType::Fact,
            content: content.into(),
            tags: vec![],
            created_at: "2026-01-01T00:00:00Z".into(),
            task_origin: None,
            is_active: true,
            superseded_by: None,
            status: MemoryStatus::Active,
            supersession_reason: None,
            cluster_id: None,
            sources: vec![],
        }
    }

    /// `load_knowledge_records` projects ACTIVE entries (via `recall`, not
    /// `list`) and EXCLUDES a forgotten one — no forgotten content leaks into
    /// the knowledge map.
    #[test]
    fn knowledge_loader_projects_active_recall() {
        let store = MemoryStore::new();
        let agent = "agent:a";
        store
            .insert(agent, fact("k1", agent, "Rust is memory-safe"))
            .unwrap();
        store
            .insert(agent, fact("k2", agent, "the build is green"))
            .unwrap();
        store
            .insert(agent, fact("k3", agent, "this fact will be forgotten"))
            .unwrap();
        store.forget(agent, "k3").unwrap();

        let records = load_knowledge_records(&store, agent);
        let bodies: Vec<&str> = records
            .iter()
            .map(|r| match r {
                KnowledgeRecord::Topic { body, .. } => body.as_str(),
                KnowledgeRecord::Synthesis { body, .. } => body.as_str(),
            })
            .collect();
        assert_eq!(
            records.len(),
            2,
            "only the 2 active entries project; got {bodies:?}"
        );
        assert!(bodies.contains(&"Rust is memory-safe"));
        assert!(bodies.contains(&"the build is green"));
        assert!(
            !bodies.iter().any(|b| b.contains("forgotten")),
            "the forgotten entry must NOT leak (recall is is_active-filtered, list is not)"
        );

        // Empty store → no records → the reader yields None (≡ StubKnowledgeMap).
        let empty = MemoryStore::new();
        assert!(load_knowledge_records(&empty, "agent:none").is_empty());

        // Reading is scoped to the ONE write bucket — an entry under a DIFFERENT
        // id is NOT unioned in (folds ADVERSARIAL-r7 W3).
        let other = MemoryStore::new();
        other
            .insert(
                "agent:other",
                fact("x1", "agent:other", "secret from another bucket"),
            )
            .unwrap();
        assert!(
            load_knowledge_records(&other, agent).is_empty(),
            "reading write_agent_id={agent} must NOT pull records from a different bucket"
        );
    }

    /// The reader is keyed under the explicit alias set {bare write-id, colon
    /// routing-id}, so an entry WRITTEN under the bare id is found when the
    /// assembler QUERIES under the colon id (the prod key-split that would
    /// otherwise silently empty Tier 1b).
    #[tokio::test]
    async fn knowledge_loader_alias_keying() {
        let store = MemoryStore::new();
        let bare = "default-agent";
        let colon = "agent:default";
        store
            .insert(bare, fact("k1", bare, "wired knowledge body"))
            .unwrap();

        // write_agent_id = bare (the bucket cap-memory wrote under); query under both.
        let reader =
            real_knowledge_map_reader(&store, bare, &[bare.to_string(), colon.to_string()]);
        // Query under the COLON id (what `assemble()` passes in production).
        let km = reader
            .read_knowledge_map(colon)
            .await
            .expect("entry written under the bare id is reachable under the colon alias");
        assert!(
            km.topics.iter().any(|t| t.body == "wired knowledge body"),
            "the bare-written record projects under the colon-id query"
        );
    }

    /// The unified-search + task-index adapters are real impls but fed an EMPTY
    /// corpus this slice → byte-identical-behavior to the stubs (empty result /
    /// no task hit → router degrades to NewTask). Hermetic: no embedding needed.
    #[tokio::test]
    async fn corpus_ports_inert_this_slice() {
        let aliases = vec!["agent:a".to_string(), "default-agent".to_string()];
        let q = vec![0.1_f32, 0.2, 0.3];

        let search = real_unified_search(&aliases);
        let res = search.search("agent:a", "anything", &q).await.unwrap();
        assert!(
            res.tasks.is_empty()
                && res.turns.is_empty()
                && res.contents.is_empty()
                && res.memories.is_empty(),
            "empty corpus → empty source-separated result (inert, ready for a future index slice)"
        );

        let tasks = real_task_index(&aliases);
        let hits = tasks.top_n_by_similarity("agent:a", &q, 5).await.unwrap();
        assert!(
            hits.is_empty(),
            "empty task rows → no hits → router → NewTask"
        );
    }

    /// Wave-16 Lane 2 — `build_recall_unified_search` POPULATES the corpus from
    /// local memory + workspace files: a query returns hits in BOTH `memories`
    /// (the seeded entry) AND `contents` (a workspace text file), keyed under
    /// EVERY alias; hidden (`.agent/…`) + binary (invalid-UTF-8) files are excluded
    /// by the TOCTOU-safe walk.
    #[tokio::test]
    async fn recall_unified_search_populates_from_memory_and_files() {
        let store = MemoryStore::new();
        store
            .insert(
                "agent:t",
                fact("m1", "agent:t", "the deploy script runs cargo build"),
            )
            .unwrap();

        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("notes.md"),
            b"local recall content about rsync mirrors",
        )
        .unwrap();
        // Hidden control dir → pruned/confined out (never read).
        std::fs::create_dir(dir.path().join(".agent")).unwrap();
        std::fs::write(dir.path().join(".agent/secret.txt"), b"private secret").unwrap();
        // Binary (invalid UTF-8) → skipped.
        std::fs::write(dir.path().join("blob.bin"), [0x00u8, 0x9f, 0x92, 0x96]).unwrap();
        // Empty/whitespace → skipped (un-rankable).
        std::fs::write(dir.path().join("blank.txt"), b"   \n\t").unwrap();

        let embedder = HashingEmbedding::default();
        let aliases = vec!["agent:t".to_string(), "t".to_string()];
        let search =
            build_recall_unified_search(&store, dir.path(), "agent:t", &aliases, &embedder).await;

        // A non-zero query embedding (same 16-dim embedder); RankingUnifiedSearch
        // has no min-score threshold so every non-empty corpus doc surfaces.
        let q = embedder.embed_text("how does the deploy work");
        let res = search
            .search("agent:t", "how does the deploy work", &q)
            .await
            .unwrap();

        assert!(
            res.memories.iter().any(|m| m.id == "m1"),
            "seeded memory entry in ## Memory"
        );
        assert!(
            res.contents.iter().any(|c| c.id == "notes.md"),
            "workspace text file in ## Files; got {:?}",
            res.contents.iter().map(|c| &c.id).collect::<Vec<_>>()
        );
        assert!(
            !res.contents
                .iter()
                .any(|c| c.id.contains("secret") || c.id.contains(".agent")),
            "hidden/.agent file MUST be excluded"
        );
        assert!(
            !res.contents.iter().any(|c| c.id == "blob.bin"),
            "binary file MUST be excluded"
        );
        assert!(
            !res.contents.iter().any(|c| c.id == "blank.txt"),
            "blank file MUST be excluded"
        );

        // Keyed under the BARE alias too (the colon/bare bridge).
        let res_bare = search
            .search("t", "how does the deploy work", &q)
            .await
            .unwrap();
        assert!(
            res_bare.memories.iter().any(|m| m.id == "m1"),
            "corpus keyed under every alias"
        );
    }

    // ── skills-J26 reader satellite — DiskSkillSummaryReader unit tests ──

    // The tests still WRITE skills through the cap-skills `DiskSkillStorage`
    // (proving write/read coincidence); the production reader no longer uses it.
    use cap_skills::persistence::{DiskSkillStorage, SkillBlob, SkillStorage};
    use cap_skills::{Provenance, TrustLevel};

    /// Materialize an active skill on disk at the SAME root the cap-skills WIT
    /// provider uses (`<workspace>/.agent`), so the write path and the reader's
    /// read path coincide exactly (the load-bearing root invariant). The blob's
    /// `content` lands at `<root>/.agent/skills/{id}/SKILL.md`.
    async fn write_skill(
        skills_agent_root: &std::path::Path,
        id: &str,
        version: u32,
        content: &str,
    ) {
        let storage = DiskSkillStorage::with_default_writer(skills_agent_root.to_path_buf());
        storage
            .write_active(&SkillBlob {
                skill_id: id.to_string(),
                version,
                content: content.to_string(),
                tags: vec![],
                provenance: Provenance::AgentCreated,
                trust_level: TrustLevel::Untrusted,
            })
            .await
            .expect("write_active");
    }

    /// RDR-1 — the reader projects a skill written via cap-skills `DiskSkillStorage`
    /// at the SAME `<workspace>/.agent` root: name == skill_id, summary == the
    /// first-paragraph extract, score == version. Validates the reader's read-path
    /// against the writer's write-path at a shared root.
    #[tokio::test]
    async fn rdr1_reader_projects_on_disk_skill_at_shared_root() {
        let tmp = tempfile::tempdir().unwrap();
        // Canonicalize to defuse the macOS /var → /private/var symlink so the
        // write-root and read-root canonicalize identically (matches the wiring
        // test-harness pattern).
        let workspace = std::fs::canonicalize(tmp.path()).unwrap();
        let root = workspace.join(".agent");

        let md = "---\nname: alpha\n---\n# Alpha\n\nThe alpha skill greets the user by name.\n\nMore detail below.\n";
        write_skill(&root, "alpha", 2, md).await;

        let reader = DiskSkillSummaryReader::new(root.clone());
        let entries = reader.list_skill_summaries("agent:ignored").await;
        assert_eq!(entries.len(), 1, "exactly one visible skill");
        let e = &entries[0];
        assert_eq!(e.name, "alpha", "name == skill_id");
        assert_eq!(
            e.summary, "The alpha skill greets the user by name.",
            "summary == first-paragraph extract (frontmatter + heading skipped)"
        );
        assert_eq!(e.score, 2.0_f32, "score == version as f32");
    }

    /// RDR-2 — a root with no `.agent/.agent/skills` dir → empty Vec (graceful
    /// degrade, byte-identical to `StubSkillSummary`).
    #[tokio::test]
    async fn rdr2_missing_skills_dir_yields_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = std::fs::canonicalize(tmp.path()).unwrap();
        // Nothing written — no skills dir exists.
        let reader = DiskSkillSummaryReader::new(workspace.join(".agent"));
        let entries = reader.list_skill_summaries("agent:a").await;
        assert!(
            entries.is_empty(),
            "no skills dir → empty (≡ StubSkillSummary)"
        );
    }

    /// RDR-3 — two skills at distinct SMALL versions carry distinct `score ==
    /// version` (the deterministic signal the SYS-AC-081 harvest asserts
    /// version-ordered truncation against; small versions keep `u32→f32` exact).
    #[tokio::test]
    async fn rdr3_score_reflects_version() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = std::fs::canonicalize(tmp.path()).unwrap();
        let root = workspace.join(".agent");
        write_skill(&root, "low", 1, "Low skill summary paragraph.\n").await;
        write_skill(&root, "high", 3, "High skill summary paragraph.\n").await;

        let reader = DiskSkillSummaryReader::new(root);
        let entries = reader.list_skill_summaries("agent:a").await;
        assert_eq!(entries.len(), 2);
        let high = entries
            .iter()
            .find(|e| e.name == "high")
            .expect("high present");
        let low = entries
            .iter()
            .find(|e| e.name == "low")
            .expect("low present");
        assert_eq!(high.score, 3.0_f32);
        assert_eq!(low.score, 1.0_f32);
        assert!(
            high.score > low.score,
            "higher version → higher score (kept first under truncation)"
        );
    }
}

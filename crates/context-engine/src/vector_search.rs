//! Data-port pre-build (2026-06-08) — dep-light REAL implementations of the
//! `UnifiedSearchPort` / `VectorIndexReader` / `TaskIndexPort` ports over a
//! **caller-supplied in-memory data seam**.
//!
//! These are production (non-stub) implementations of three EXISTING
//! crate-local ports (`crate::ports`). They run REAL cosine-similarity ranking
//! and source separation over data the caller loads in — they do NOT depend on
//! `advance-cap-memory` / `advance-cap-llm` (the AC-01 stateless guard
//! `tests/stateless.rs::cargo_manifest_excludes_provider_crates` forbids
//! provider crates; the inverted-dependency discipline of MODULE-010 §3.6
//! "(Slice B) 6 crate-local async ports" forbids coupling to the concrete
//! store/provider crates). The cap-memory data-load + the cap-llm
//! `EmbeddingPort` are the DOWNSTREAM B1 wiring (MODULE-010 §3.6 data-port
//! pre-build rows) — this slice ships the ranking/projection LOGIC + crate
//! tests; B1 loads cap-memory rows into [`AgentSearchCorpus`] and swaps the
//! `cli/context_wiring.rs` hermetic stubs for these impls.
//!
//! **Honesty (MODULE-010 §3.6):** for `contents`/`memories`, the
//! [`crate::ports::ContentHit`]/[`crate::ports::MemoryHit`] `adjusted_score`
//! field is populated with the RAW cosine as a dep-light placeholder — the
//! real epistemic-status-boosted `adjusted_score` is owned by MODULE-004 and
//! is folded in upstream by B1's loader (or the eventual hoisted CONTRACT-032
//! producer). Tasks/turns carry true cosine `similarity`.
//!
//! **`agent_id` validation:** per the `crate::ports` lib-doc convention,
//! `agent_id` is NOT whitelist-validated inside the port impls — every in-tree
//! caller validates per CONTRACT-090 invariant 4 before invoking. Here
//! `agent_id` is purely a corpus lookup key (unknown agent → empty result).

use std::collections::HashMap;
use std::time::SystemTime;

use async_trait::async_trait;

use crate::ports::{
    ContentHit, MemoryHit, PortError, TaskHit, TaskIndexPort, TurnHit, UnifiedSearchPort,
    UnifiedSearchResult, VectorHit, VectorIndexReader,
};
use crate::task_router::time_key;

/// Default per-kind result cap. Defense-in-depth so a pathological corpus
/// cannot emit an unbounded `Vec` into the prompt pipeline. The corpus is also
/// upstream-bounded (cap-memory retention caps) when B1 loads it. Override via
/// the `with_max_results*` setters.
pub const DEFAULT_MAX_RESULTS: usize = 256;

/// Cosine similarity over two equal-length finite vectors.
///
/// Returns `None` (the item is SKIPPED before ranking — never ranked with a
/// garbage score) on any of: dimension mismatch, empty input, a zero-norm
/// vector (cosine is undefined — would divide by zero → NaN), or any
/// non-finite (`NaN`/`±∞`) component or intermediate sum. This mirrors the
/// crate's existing finite-value hardening (`task_router` / `unified_search`).
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> Option<f32> {
    if a.is_empty() || a.len() != b.len() {
        return None;
    }
    let mut dot = 0.0_f32;
    let mut norm_a = 0.0_f32;
    let mut norm_b = 0.0_f32;
    for (x, y) in a.iter().zip(b.iter()) {
        if !x.is_finite() || !y.is_finite() {
            return None;
        }
        dot += x * y;
        norm_a += x * x;
        norm_b += y * y;
    }
    // A finite-input vector can still overflow its squared-norm / dot sum to
    // ±∞ (→ NaN); reject that rather than rank on a garbage score.
    if !dot.is_finite() || !norm_a.is_finite() || !norm_b.is_finite() {
        return None;
    }
    if norm_a <= 0.0 || norm_b <= 0.0 {
        return None; // zero-norm → cosine undefined
    }
    let denom = norm_a.sqrt() * norm_b.sqrt();
    if !denom.is_finite() || denom <= 0.0 {
        return None;
    }
    let cos = dot / denom;
    if cos.is_finite() {
        Some(cos)
    } else {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Caller-supplied input carriers (dep-light; B1's loader fills these from
// cap-memory rows). Each carries the embedding the ranker scores against.
// ─────────────────────────────────────────────────────────────────────────

/// One indexed `(id, embedding)` row (used for the content/memory corpora and
/// the [`CosineVectorIndex`]).
#[derive(Clone, Debug, PartialEq)]
pub struct IndexedVector {
    pub id: String,
    pub embedding: Vec<f32>,
}

/// One indexed task row. `last_turn_at` carries the `TaskHit` tie-break
/// semantics (`Some` precedes `None`, newer first).
#[derive(Clone, Debug, PartialEq)]
pub struct IndexedTask {
    pub task_id: String,
    pub embedding: Vec<f32>,
    pub last_turn_at: Option<SystemTime>,
}

/// One indexed cross-task turn row.
#[derive(Clone, Debug, PartialEq)]
pub struct IndexedTurn {
    pub id: String,
    pub task_id: String,
    pub embedding: Vec<f32>,
    pub timestamp: SystemTime,
}

/// Per-agent search corpus — the 4 source-separated kinds the unified search
/// ranks over. B1 loads cap-memory's task-index / turn-index / content /
/// memory rows into this.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AgentSearchCorpus {
    pub tasks: Vec<IndexedTask>,
    pub turns: Vec<IndexedTurn>,
    pub contents: Vec<IndexedVector>,
    pub memories: Vec<IndexedVector>,
}

// ─────────────────────────────────────────────────────────────────────────
// RankingUnifiedSearch — real `UnifiedSearchPort`.
// ─────────────────────────────────────────────────────────────────────────

/// Real `UnifiedSearchPort`: cosine-ranks the agent's [`AgentSearchCorpus`]
/// and source-separates into the 4 typed [`UnifiedSearchResult`] fields. The
/// `query` text is unused (the embedding is the ranking signal); the
/// coordinator (`crate::unified_search`) owns the cross-task turn filter, so
/// this port returns all ranked turns.
pub struct RankingUnifiedSearch {
    corpora: HashMap<String, AgentSearchCorpus>,
    max_results_per_kind: usize,
}

impl RankingUnifiedSearch {
    pub fn new(corpora: HashMap<String, AgentSearchCorpus>) -> Self {
        Self {
            corpora,
            max_results_per_kind: DEFAULT_MAX_RESULTS,
        }
    }

    pub fn with_max_results_per_kind(mut self, cap: usize) -> Self {
        self.max_results_per_kind = cap;
        self
    }
}

#[async_trait]
impl UnifiedSearchPort for RankingUnifiedSearch {
    async fn search(
        &self,
        agent_id: &str,
        _query: &str,
        query_embedding: &[f32],
    ) -> Result<UnifiedSearchResult, PortError> {
        let Some(corpus) = self.corpora.get(agent_id) else {
            return Ok(UnifiedSearchResult::default());
        };

        let mut tasks: Vec<TaskHit> = corpus
            .tasks
            .iter()
            .filter_map(|t| {
                cosine_similarity(query_embedding, &t.embedding).map(|s| TaskHit {
                    task_id: t.task_id.clone(),
                    similarity: s,
                    last_turn_at: t.last_turn_at,
                })
            })
            .collect();
        // score desc → last_turn_at (Some>None, newer first) → task_id asc.
        tasks.sort_by(|a, b| {
            b.similarity
                .total_cmp(&a.similarity)
                .then_with(|| time_key(&b.last_turn_at).cmp(&time_key(&a.last_turn_at)))
                .then_with(|| a.task_id.cmp(&b.task_id))
        });
        tasks.truncate(self.max_results_per_kind);

        let mut turns: Vec<TurnHit> = corpus
            .turns
            .iter()
            .filter_map(|t| {
                cosine_similarity(query_embedding, &t.embedding).map(|s| TurnHit {
                    id: t.id.clone(),
                    task_id: t.task_id.clone(),
                    similarity: s,
                    timestamp: t.timestamp,
                })
            })
            .collect();
        // score desc → timestamp desc (newer first) → id asc.
        turns.sort_by(|a, b| {
            b.similarity
                .total_cmp(&a.similarity)
                .then_with(|| b.timestamp.cmp(&a.timestamp))
                .then_with(|| a.id.cmp(&b.id))
        });
        turns.truncate(self.max_results_per_kind);

        let contents = rank_vectors(&corpus.contents, query_embedding, self.max_results_per_kind)
            .into_iter()
            .map(|(id, score)| ContentHit {
                id,
                adjusted_score: score,
            })
            .collect();

        let memories = rank_vectors(&corpus.memories, query_embedding, self.max_results_per_kind)
            .into_iter()
            .map(|(id, score)| MemoryHit {
                id,
                adjusted_score: score,
            })
            .collect();

        Ok(UnifiedSearchResult {
            tasks,
            turns,
            contents,
            memories,
        })
    }
}

/// Shared `(id, embedding)` cosine ranker: score desc → id asc, capped. Used
/// for contents/memories (and mirrored by [`CosineVectorIndex`]).
fn rank_vectors(rows: &[IndexedVector], query: &[f32], cap: usize) -> Vec<(String, f32)> {
    let mut hits: Vec<(String, f32)> = rows
        .iter()
        .filter_map(|r| cosine_similarity(query, &r.embedding).map(|s| (r.id.clone(), s)))
        .collect();
    hits.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    hits.truncate(cap);
    hits
}

// ─────────────────────────────────────────────────────────────────────────
// CosineVectorIndex — real `VectorIndexReader` (AC-06 L1 read-side).
// ─────────────────────────────────────────────────────────────────────────

/// Real `VectorIndexReader`: ranks the FULL agent corpus by cosine desc and
/// truncates at `max_results`. The trait's `lookup` takes NO `n` argument — so
/// "N" is the impl-owned cap, never caller-supplied (cf. [`CosineTaskIndex`]).
pub struct CosineVectorIndex {
    rows: HashMap<String, Vec<IndexedVector>>,
    max_results: usize,
}

impl CosineVectorIndex {
    pub fn new(rows: HashMap<String, Vec<IndexedVector>>) -> Self {
        Self {
            rows,
            max_results: DEFAULT_MAX_RESULTS,
        }
    }

    pub fn with_max_results(mut self, cap: usize) -> Self {
        self.max_results = cap;
        self
    }
}

#[async_trait]
impl VectorIndexReader for CosineVectorIndex {
    async fn lookup(
        &self,
        agent_id: &str,
        query_embedding: &[f32],
    ) -> Result<Vec<VectorHit>, PortError> {
        let Some(rows) = self.rows.get(agent_id) else {
            return Ok(Vec::new());
        };
        let hits = rank_vectors(rows, query_embedding, self.max_results)
            .into_iter()
            .map(|(id, score)| VectorHit { id, score })
            .collect();
        Ok(hits)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// CosineTaskIndex — real `TaskIndexPort`.
// ─────────────────────────────────────────────────────────────────────────

/// Real `TaskIndexPort`: cosine top-`n` over the agent's task rows, sorted
/// score desc with the `task_router::time_key` tie-break (`Some` precedes
/// `None`, newer first), then `task_id` asc for full determinism. Honors the
/// caller-supplied `n`.
pub struct CosineTaskIndex {
    rows: HashMap<String, Vec<IndexedTask>>,
}

impl CosineTaskIndex {
    pub fn new(rows: HashMap<String, Vec<IndexedTask>>) -> Self {
        Self { rows }
    }
}

#[async_trait]
impl TaskIndexPort for CosineTaskIndex {
    async fn top_n_by_similarity(
        &self,
        agent_id: &str,
        query_embedding: &[f32],
        n: usize,
    ) -> Result<Vec<TaskHit>, PortError> {
        let Some(rows) = self.rows.get(agent_id) else {
            return Ok(Vec::new());
        };
        let mut hits: Vec<TaskHit> = rows
            .iter()
            .filter_map(|t| {
                cosine_similarity(query_embedding, &t.embedding).map(|s| TaskHit {
                    task_id: t.task_id.clone(),
                    similarity: s,
                    last_turn_at: t.last_turn_at,
                })
            })
            .collect();
        hits.sort_by(|a, b| {
            b.similarity
                .total_cmp(&a.similarity)
                .then_with(|| time_key(&b.last_turn_at).cmp(&time_key(&a.last_turn_at)))
                .then_with(|| a.task_id.cmp(&b.task_id))
        });
        hits.truncate(n);
        Ok(hits)
    }
}

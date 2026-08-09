//! Slice-C retention-rerank adapter (REQ-238 — AC-10 / AC-11).
//!
//! The retention-score **formula** (`0.20×recency + 0.15×type +
//! 0.25×reference + 0.25×importance + 0.15×user_intent`) is owned by
//! MODULE-004 §1.4.3 and exported on CONTRACT-031
//! `Recall::retention_score(&TurnDigest, DateTime<Utc>) -> f32`. That export
//! is itself **pure over the caller-supplied digest** — it does NOT re-read
//! the `turn_index.reference_count` column; that read happens upstream where
//! MODULE-004 builds the `TurnDigest`. MODULE-010 is the **rerank consumer**
//! only (joint REQ-155; §1.3.6 "MODULE-010 does **not** reimplement the
//! formula").
//!
//! Because the crate is deliberately dep-light (AC-01: no `advance-database`
//! dep, no `chrono`; `Cargo.toml` is out of this slice's boundary), MODULE-010
//! consumes the primitive **via a crate-local dependency-inversion stand-in**
//! [`RetentionScorer`] — the exact Slice-A `inventory::HostFnInventoryReader`
//! + Slice-B `ports.rs` precedent (those crate-local stand-ins consumed
//! CONTRACT-031/032 MODULE-004 surfaces and passed their ACs). This file
//! contains **no retention formula** (AC-10: no local reimplementation —
//! verified mechanically by `tests/retention_rerank.rs::t_no_local_formula`).
//!
//! The adapter is **exported + unit/code-audit-tested but NOT wired into
//! `assemble()`'s live history feed** — `LlmMessage{role,content}` carries no
//! retention metadata, so a meaningful live rerank needs the deferred
//! digest/turn-typed history-load surface (MODULE-010 §3.6 Slice-C (d)/(f)).
//! Exact Slice-B `UnifiedSearchCoordinator` non-wired precedent (passed
//! AC-02). User-accepted scope (2026-05-18, "Accept non-wired adapter").

use std::time::SystemTime;

/// Crate-local **category-(A)** mirror of canonical
/// `crates/database/src/score.rs::TurnDigest` — the one input the MODULE-004
/// CONTRACT-031 `retention_score` primitive scores. Field-for-field identical
/// to the canonical struct **except** the single sanctioned divergence
/// `timestamp: SystemTime` (and the [`RetentionScorer::retention_score`]
/// `now: SystemTime` parameter) vs canonical `DateTime<Utc>` — the same
/// category-(A) `SystemTime` choice Slice-B made for `TaskHit.last_turn_at`
/// (keeps the crate `chrono`-free; MODULE-010 §3.6 Slice-C (b)).
///
/// `reference_count` is carried identically to canonical `TurnDigest`;
/// MODULE-010 does NOT own or refresh that column (it is MODULE-004 upstream
/// per §1.4.3:384-388). Each rerank call passes the current per-call digest
/// (carrying the current `reference_count` value) so the score is recomputed
/// per call, never cached (AC-11).
#[derive(Clone, Debug, PartialEq)]
pub struct TurnDigestView {
    /// `turn_index` row timestamp. `SystemTime` (not `DateTime<Utc>`) — the
    /// category-(A) divergence; keeps the crate `chrono`-free.
    pub timestamp: SystemTime,
    /// `turn_index.importance` enum: `"critical"` | `"notable"` | anything
    /// else is the `"normal"` baseline. Owned/scored by MODULE-004.
    pub importance: String,
    /// `turn_index.reference_count`: number of later turns referencing this
    /// one (sync-back updated by MODULE-004's post-processor). Carried as a
    /// digest field exactly as canonical `TurnDigest` does.
    pub reference_count: u32,
    pub has_user_instruction: bool,
    pub has_user_correction: bool,
    pub has_tool_use: bool,
    pub has_decision: bool,
}

/// Crate-local **dependency-inversion stand-in for CONTRACT-031
/// `Recall::retention_score`** (MODULE-004, formula owner §1.4.3). Sync — the
/// MODULE-004 export is a sync `fn`. `Send + Sync` for the same trait-object
/// posture as the Slice-B ports.
///
/// MODULE-010 consumes the retention primitive **only through this trait** —
/// it does NOT reimplement the weighted-sum formula (AC-10) and does NOT link
/// `advance-database` (AC-01 dep-light posture; the trait stands in for the
/// not-yet-hoisted CONTRACT-031 surface, MODULE-010 §3.6 Slice-C (a)).
pub trait RetentionScorer: Send + Sync {
    /// Return MODULE-004's retention score for `turn` evaluated at `now`.
    /// Implementations forward to MODULE-004's CONTRACT-031 export; this
    /// crate never computes the score itself.
    fn retention_score(&self, turn: &TurnDigestView, now: SystemTime) -> f32;
}

/// One rerank candidate: an opaque `payload` paired with the `digest` the
/// retention score is computed from. Generic so the adapter reranks any
/// turn-bearing item (e.g. a `TurnHit`) by its digest without coupling to a
/// concrete hit type.
#[derive(Clone, Debug, PartialEq)]
pub struct RerankItem<T> {
    pub payload: T,
    pub digest: TurnDigestView,
}

impl<T> RerankItem<T> {
    pub fn new(payload: T, digest: TurnDigestView) -> Self {
        Self { payload, digest }
    }
}

/// Rerank `items` by MODULE-004's retention score, descending (most-retained
/// first). Progressive-load rerank consumer for AC-10 / AC-11.
///
/// **Query-time, no cached aggregate (AC-11)**: `scorer.retention_score` is
/// invoked exactly once per item on **every** call — the aggregate score is
/// never memoized or pre-stored. Calling this twice over the same items
/// re-invokes the scorer `2 × items.len()` times (locked by
/// `tests/retention_rerank.rs` MODULE-010-T15).
///
/// **No formula here (AC-10)**: scoring is entirely delegated to the injected
/// [`RetentionScorer`] (the CONTRACT-031 stand-in); this function only orders.
///
/// **NaN/non-finite handling (defense-in-depth)**: a naive descending
/// `f32::total_cmp` is WRONG — IEEE-754 totalOrder ranks `+NaN` as the
/// *greatest* value, so a poisoned `+NaN` score would sort to the FRONT
/// (fail-open). Instead this **partitions**: items whose score `is_finite()`
/// are sorted descending by `f32::total_cmp` (stable); items with a
/// non-finite score (NaN / ±∞) are appended **after** every finite item with
/// their relative input order preserved (deterministic lowest priority).
/// MODULE-004 already finite-guards upstream; this is consumer-side
/// defense-in-depth so the rerank never fail-opens.
pub fn rerank_by_retention<T>(
    items: Vec<RerankItem<T>>,
    scorer: &dyn RetentionScorer,
    now: SystemTime,
) -> Vec<RerankItem<T>> {
    // Score once per item, this call (no caching — AC-11).
    let scored: Vec<(f32, RerankItem<T>)> = items
        .into_iter()
        .map(|item| {
            let score = scorer.retention_score(&item.digest, now);
            (score, item)
        })
        .collect();

    // Partition finite vs non-finite, each preserving input order.
    let (mut finite, non_finite): (Vec<(f32, RerankItem<T>)>, Vec<(f32, RerankItem<T>)>) =
        scored.into_iter().partition(|(s, _)| s.is_finite());

    // Stable descending sort of the finite scores (`sort_by` is stable;
    // `b.total_cmp(a)` => descending). Non-finite already in input order.
    finite.sort_by(|a, b| b.0.total_cmp(&a.0));

    finite
        .into_iter()
        .chain(non_finite)
        .map(|(_, item)| item)
        .collect()
}

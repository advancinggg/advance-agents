//! Pure-math scoring primitives for MODULE-004 recall and routing.
//!
//! Implements the three scoring models from PRD §8.5 (REQ-155 parent + REQ-156,
//! REQ-157, REQ-158, REQ-159 sub-requirements):
//!
//! 1. [`compute_adjusted_score`] — content/memory ranking score with sigmoid
//!    hotness, 7-day half-life decay, and an epistemic boost for memory rows
//!    (REQ-156/157/158/159; AC-06 + AC-07).
//! 2. [`retention_score`] — query-time turn-rerank score over five weighted
//!    terms (recency, type, reference count, importance, user intent)
//!    (REQ-155; AC-15).
//! 3. [`task_semantic_similarity`] / [`rank_task_rows`] — task-routing
//!    primitives over `task_index` embeddings, returning ranked [`TaskHit`]
//!    rows with `last_turn_at` as the secondary sort key (REQ-155; AC-16).
//!
//! Slice B ships these primitives with **zero database I/O, zero async, and
//! no trait implementations**. The CONTRACT-031 (`Recall`) and CONTRACT-032
//! (`UnifiedSearch`) trait method bodies that wrap these helpers shipped in
//! Slice C (m004-slice-c) and live in `recall.rs` / `unified_search.rs`.
//!
//! Per-source field-mapping rustdoc (forward contract for the recall slice;
//! see [`SearchResult`]):
//!
//! - [`Source::Content`]: `last_modified ← content_index.last_modified`
//!   (nullable; recall row-mapper falls back to `last_accessed` if Some, else
//!   epoch); `last_accessed ← content_index.last_accessed`; `access_count ←
//!   content_index.access_count` (nullable per SQLite default; row-mapper
//!   coerces NULL → 0u32 to match the schema's `INTEGER DEFAULT 0`); `status =
//!   None`; `created_at` proxied from `last_modified` (no created_at column).
//! - [`Source::Memory`]: `last_modified ← memory_index.created_at` (memory
//!   rows are created once and never modified post-creation; supersession is
//!   recorded via `superseded_by` + a NEW row); `last_accessed ←
//!   memory_index.last_accessed`; `access_count ← memory_index.access_count`
//!   (NULL → 0u32 same as content); `status ← memory_index.status` (values
//!   `active|contested|orphaned|superseded|forgotten`); `created_at ←
//!   memory_index.created_at`.
//! - [`Source::Memory`] is the only variant for which the epistemic boost
//!   branch fires (PRD §8.5.2b).
//! - [`Source::Meta`]: NOT scored by [`compute_adjusted_score`] per PRD §8.5.3
//!   table-role mapping. The recall pipeline never constructs a
//!   [`SearchResult`] with `Source::Meta` for the score function — meta hits
//!   emit `parent_score` (50/50 directory aggregation) which is passed in to
//!   the score function for content/memory hits. The variant exists for
//!   completeness; if a future revision needs to score meta rows, the
//!   canonical mapping is `last_modified ← meta_index.updated_at`,
//!   `last_accessed = None` (no column), `access_count = 0` (no column),
//!   `status = None`, `created_at` proxied from `updated_at`.
//!
//! NaN-input invariant: callers SHOULD pre-validate embedding vectors against
//! NaN/Inf components, but `score.rs` provides defense-in-depth against
//! reaching the public API. With NaN inputs, [`cosine`] returns NaN (the
//! zero-magnitude guard does NOT catch NaN since `NaN == 0.0` is false in
//! IEEE 754); [`cosine`] also returns NaN on length mismatch (R27 hardening,
//! replacing the previous panic-on-mismatch contract).
//! [`rank_task_rows`] FILTERS NaN-similarity rows AND dim-mismatch rows out
//! of the candidate set entirely (R23 + R25 hardening), so they never
//! appear in output regardless of input position, `limit`, or
//! `last_turn_at` tiebreaks. For Slice B, the only caller is the future
//! recall slice, which sources embeddings from MODULE-009 CONTRACT-081
//! `embed()` — that pipeline remains the primary defense; the score-module
//! filters are defense-in-depth fallbacks.
//!
//! Clock-skew invariant (post-R21): both [`compute_adjusted_score`] (decay)
//! and [`retention_score`] (recency) clamp their decay/recency factors at 1.0
//! via `.min(1.0)`, so future-dated reference timestamps no longer produce
//! +Inf scores via the `exp(positive)` path. Combined with the saturating
//! `timestamp_millis()` arithmetic (no chrono Sub panic on extreme dates) and
//! the final `is_finite()` guard (NaN demotion), the score functions are
//! bounded for any input the recall slice may legitimately or accidentally
//! feed. Slice B's primitives now fail closed for clock-skew + corrupt-input
//! adversarial paths; the recall slice retains the responsibility to
//! pre-validate ingestion timestamps for accurate ranking semantics.

use chrono::{DateTime, Utc};

/// Origin table of a search hit. Used by [`compute_adjusted_score`] to gate
/// the epistemic boost branch (only [`Source::Memory`] hits are boosted).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// `content_index` hit (file content).
    Content,
    /// `meta_index` hit (directory description). Not scored by
    /// [`compute_adjusted_score`] per PRD §8.5.3.
    Meta,
    /// `memory_index` hit (knowledge / user-preference entry).
    Memory,
}

/// In-memory normalization of a recall result row. The recall slice
/// constructs this from per-table queries against `content_index` /
/// `memory_index`; see the module-level rustdoc for the per-source field
/// mapping.
#[derive(Clone, Debug)]
pub struct SearchResult {
    /// Per-row similarity score. For dense hits this is the sqlite-vec
    /// cosine similarity; for sparse hits this is the FTS5 rank converted
    /// to a [0,1] score by the recall pipeline.
    pub self_score: f32,
    /// Number of times this row has been returned by a recall call. Stored
    /// in `content_index.access_count` / `memory_index.access_count`
    /// (`INTEGER DEFAULT 0`; nullable, NULL → 0).
    pub access_count: u32,
    /// Latest content modification timestamp. Populated per the per-source
    /// mapping (module rustdoc): `content_index.last_modified` for Content,
    /// `memory_index.created_at` for Memory.
    pub last_modified: DateTime<Utc>,
    /// Latest access timestamp. None when the row has never been recalled
    /// or when the source schema has no `last_accessed` column.
    pub last_accessed: Option<DateTime<Utc>>,
    /// Origin table.
    pub source: Source,
    /// `memory_index.status` for [`Source::Memory`]; None for other sources.
    /// Recognized values: `"active"`, `"contested"`, `"orphaned"`,
    /// `"superseded"`, `"forgotten"` (per PRD §8.2 / MODULE-004 §1.4.1).
    pub status: Option<String>,
    /// Row-creation timestamp. For Memory this is `memory_index.created_at`;
    /// for Content this is proxied from `last_modified` (the schema has no
    /// content_index.created_at column).
    pub created_at: DateTime<Utc>,
}

/// One row of `turn_index` rendered for [`retention_score`] computation. The
/// fields below mirror the §1.4.1 schema columns (see MODULE-004
/// §1.4.1 lines 148-166).
#[derive(Clone, Debug)]
pub struct TurnDigest {
    pub timestamp: DateTime<Utc>,
    /// `turn_index.importance` enum: `"critical"` | `"notable"` | anything
    /// else is treated as the `"normal"` baseline (0.3 weight in the score).
    pub importance: String,
    /// `turn_index.reference_count`: number of later turns that reference
    /// this one (sync-back updated by the post-processor).
    pub reference_count: u32,
    pub has_user_instruction: bool,
    pub has_user_correction: bool,
    pub has_tool_use: bool,
    pub has_decision: bool,
}

/// One row of `task_index` for [`task_semantic_similarity`] /
/// [`rank_task_rows`].
#[derive(Clone, Debug)]
pub struct TaskIndexRow {
    pub task_id: String,
    /// `task_index.embedding` decoded from the `BLOB` column. Length must
    /// match the query embedding (asserted by [`cosine`]).
    pub embedding: Vec<f32>,
    /// `task_index.last_turn_at` — used as the secondary sort key in
    /// [`rank_task_rows`] (newer first; None goes after Some).
    pub last_turn_at: Option<DateTime<Utc>>,
}

/// One ranked task hit produced by [`rank_task_rows`]. Consumer is MODULE-010
/// CONTRACT-091 `TaskRouter` (the routing decision — top-1 threshold,
/// tie-break rules — is owned by MODULE-010, not this primitive).
#[derive(Clone, Debug)]
pub struct TaskHit {
    pub task_id: String,
    pub similarity: f32,
    pub last_turn_at: Option<DateTime<Utc>>,
}

/// PRD §8.5.1 — `adjusted_score = base × hotness × decay`, optionally times an
/// epistemic boost for memory hits (PRD §8.5.2b). Implements REQ-155 + REQ-156
/// + REQ-157 + REQ-158 (AC-06) and REQ-159 (AC-07).
///
/// - `base = self_score × 0.5 + parent_score × 0.5` (50/50 propagation —
///   `parent_score` is computed by the recall slice via meta_index directory
///   aggregation per AC-05; Slice B accepts it as an injected parameter).
/// - `hotness = 0.1 + 0.9 × sigmoid(access_count/10 − 3)` (REQ-157; floor
///   0.1, ceiling 1.0 as access_count → ∞; equals 0.55 at access_count = 30,
///   matching MODULE-004-T04).
/// - `decay = 0.1 + 0.9 × exp(−days_since × 0.693 / 7)` (REQ-158; 7-day
///   half-life, floor 0.1; equals 0.55 at days_since = 7, matching
///   MODULE-004-T05).
///   - Spec §1.4.3 line 232 writes `last_active = result.last_modified.max(
///     result.last_accessed)` as shorthand. Since `last_accessed` is
///     `Option<DateTime<Utc>>`, the literal expression does not typecheck;
///     we resolve via `.map_or(last_modified, |la| last_modified.max(la))`
///     (None falls back to last_modified, Some(t) takes the later of the two).
///   - Decay is **clamped at 1.0** via `.min(1.0)` (R21 hardening): for
///     valid (past) inputs decay ∈ [0.1, 1.0]; for future-timestamp inputs
///     (clock skew on rebuild) the unchecked `exp(positive)` would otherwise
///     explode toward +Inf and dominate the ranking — the clamp closes that
///     attack vector while preserving spec semantics for valid inputs.
/// - Memory boost (REQ-159, AC-07): `Source::Memory` rows multiply by 3.0 if
///   `status ∈ {"contested", "orphaned"}`, by 1.5 if `status == "active"`
///   AND `now - max(last_accessed.unwrap_or(created_at), created_at) > 30
///   days`, else 1.0. Non-memory sources skip the boost branch.
pub fn compute_adjusted_score(result: &SearchResult, parent_score: f32, now: DateTime<Utc>) -> f32 {
    // Adversarial R29 hardening: enforce the documented "Source::Meta is
    // NOT scored" contract at runtime. Per the module-level rustdoc + PRD
    // §8.5.3 table-role mapping, meta_index hits emit `parent_score` (50/50
    // directory aggregation) but are NOT themselves scored by
    // compute_adjusted_score. Pre-R29 the function only special-cased
    // Source::Memory for the boost branch — Source::Meta inputs were
    // silently scored as Source::Content equivalents, allowing a buggy or
    // adversarial caller to rank meta_index rows directly. The R29 guard
    // returns 0.0 for Meta inputs, making the contract self-enforcing.
    if result.source == Source::Meta {
        return 0.0;
    }

    // Adversarial R23 hardening: clamp self_score and parent_score to [0, 1]
    // before computing base. Pre-R23 the function trusted callers to provide
    // similarities already in [0, 1] per the recall slice's row-mapper
    // convention, but a corrupt directory aggregate or FTS5-rank-to-score
    // mapping could produce a finite-but-huge value (e.g., 1e30) that
    // bypasses the existing is_finite() guard and propagates through
    // base × hotness × decay to yield a finite score that dominates
    // legitimate rows. The clamp keeps base bounded in [0, 1] (and
    // therefore the final score in [0, 3.0] including the boost), so a
    // corrupted upstream score can no longer rank-poison. NaN inputs
    // propagate through `clamp` (Rust's f32::clamp returns NaN if the
    // value is NaN), so the final is_finite() guard still demotes them.
    let self_score = result.self_score.clamp(0.0, 1.0);
    let parent = parent_score.clamp(0.0, 1.0);
    let base = self_score * 0.5 + parent * 0.5;

    // Hotness — sigmoid(access_count/10 − 3) scaled to [0.1, 1.0].
    let x = (result.access_count as f32) / 10.0 - 3.0;
    let hotness = 0.1 + 0.9 / (1.0 + (-x).exp());

    // Decay — 7-day half-life with 0.1 floor. last_active = max of the two
    // timestamps, with None last_accessed falling back to last_modified.
    let last_active = result
        .last_accessed
        .map_or(result.last_modified, |la| result.last_modified.max(la));
    // PRD §8.5.1 specifies continuous-time decay; derive fractional days
    // from millisecond elapsed time rather than truncating to whole days.
    // Earlier whole-day `num_days()` form bucketed 0d-23h59m as days=0 etc.
    // (§1.4.3 spec aligned to continuous-time per audit round 18.)
    //
    // Adversarial R21 hardening: use `timestamp_millis().saturating_sub(...)`
    // instead of `chrono::Duration` arithmetic on `now - last_active`. The
    // chrono `Sub` impl panics when the result exceeds Duration::MIN/MAX
    // (~±292 years); a corrupt or attacker-injected DB timestamp at chrono's
    // MIN_UTC/MAX_UTC sentinels would otherwise abort the recall worker.
    // saturating_sub on i64 millis cannot panic and saturates at i64 bounds
    // (~±290 million years — well past any sensible value).
    let elapsed_ms_decay = now
        .timestamp_millis()
        .saturating_sub(last_active.timestamp_millis());
    let days_since = elapsed_ms_decay as f32 / 86_400_000.0;
    // Clamp decay at 1.0: for valid (past) inputs decay ∈ [0.1, 1.0]; for
    // future-timestamp inputs (clock skew / corruption) the unchecked exp()
    // would explode toward +Inf and dominate the ranking. The clamp
    // preserves spec semantics for valid inputs and removes the rank-poison
    // attack vector (Adversarial R21 — "future timestamp → +Inf score" path).
    let decay = (0.1 + 0.9 * (-days_since * 0.693 / 7.0).exp()).min(1.0);

    let score = base * hotness * decay;

    let final_score = if result.source == Source::Memory {
        let aging_ref = result
            .last_accessed
            .unwrap_or(result.created_at)
            .max(result.created_at);
        // Same saturating millisecond delta as the decay branch above.
        let elapsed_ms_aging = now
            .timestamp_millis()
            .saturating_sub(aging_ref.timestamp_millis());
        let days = elapsed_ms_aging as f32 / 86_400_000.0;
        let boost = match result.status.as_deref() {
            Some("contested") | Some("orphaned") => 3.0,
            Some("active") if days > 30.0 => 1.5,
            _ => 1.0,
        };
        score * boost
    } else {
        score
    };

    // Final-output finite guard (Adversarial R21): if any input was NaN/Inf
    // and propagated through the multiplications, return 0.0 rather than
    // poisoning downstream rankings. Recall slice's row-mapper validation
    // remains the primary defense; this is in-depth fallback.
    if final_score.is_finite() {
        final_score
    } else {
        0.0
    }
}

/// PRD §8.5 / §11.3.4 — query-time `turn_index` rerank score over five
/// weighted terms. Implements REQ-155 (AC-15).
///
/// `0.20 × recency + 0.15 × type_score + 0.25 × reference + 0.25 ×
/// importance + 0.15 × user_intent`
///
/// - `recency = exp(-0.05 × hours_ago)` (decay slope per spec).
/// - `type_score`: 1.0 if `has_user_instruction`, else 0.8 if `has_decision`,
///   else 0.5 if `has_tool_use`, else 0.3 baseline (the `.max()` chain in the
///   spec accumulates the highest qualifying value).
/// - `reference = sigmoid(0.3 × (reference_count − 5))` (saturating at 1 for
///   high reference counts).
/// - `importance`: 1.0 / 0.6 / 0.3 for `"critical"` / `"notable"` / else.
/// - `user_intent`: 1.0 if `has_user_correction`, else 0.0.
pub fn retention_score(turn: &TurnDigest, now: DateTime<Utc>) -> f32 {
    // PRD §8.5 specifies continuous-time recency decay (`exp(-0.05 *
    // hours_ago)` with hours_ago as a fractional value), so derive
    // hours_ago from the millisecond elapsed rather than truncating to
    // whole hours. The earlier whole-hour `num_hours()` form bucketed
    // 0m-59m as recency=1.0 and 1h-1h59m as 0.951, which deviated from
    // the PRD curve at sub-hour granularity (§1.4.3 spec aligned to
    // continuous-time per audit round 16).
    //
    // Adversarial R21 hardening: use `timestamp_millis().saturating_sub(...)`
    // instead of `chrono::Duration` arithmetic to avoid the chrono Sub
    // panic on extreme timestamps. Recency clamp at 1.0 prevents
    // future-timestamp injection from producing +Inf via exp(positive).
    let elapsed_ms = now
        .timestamp_millis()
        .saturating_sub(turn.timestamp.timestamp_millis());
    let hours_ago = elapsed_ms as f32 / 3_600_000.0;
    let recency = (-0.05 * hours_ago).exp().min(1.0);

    let type_score = {
        let mut s = 0.3_f32;
        if turn.has_user_instruction {
            s = s.max(1.0);
        }
        if turn.has_decision {
            s = s.max(0.8);
        }
        if turn.has_tool_use {
            s = s.max(0.5);
        }
        s
    };

    let reference = 1.0 / (1.0 + (-0.3 * (turn.reference_count as f32 - 5.0)).exp());

    let importance = match turn.importance.as_str() {
        "critical" => 1.0,
        "notable" => 0.6,
        _ => 0.3,
    };
    let user_intent = if turn.has_user_correction { 1.0 } else { 0.0 };

    let score = 0.20 * recency
        + 0.15 * type_score
        + 0.25 * reference
        + 0.25 * importance
        + 0.15 * user_intent;

    // Final-output finite guard (Adversarial R21): NaN/Inf inputs cannot
    // produce a useful score; default to 0.0 rather than rank-poison.
    if score.is_finite() {
        score
    } else {
        0.0
    }
}

/// Cosine similarity between two equal-length f32 vectors. Returns
/// [`f32::NAN`] for any pathological input (length mismatch OR
/// zero-magnitude vector); finite cosine otherwise. The calling
/// `rank_task_rows` filter and any future Recall trait wrapper drop NaN
/// rows from the candidate set, closing all known fail-open routing
/// vectors at this primitive level.
///
/// **Adversarial R27+R31 hardening**: this function originally panicked
/// via `assert_eq!` on length mismatch (precondition contract). R27
/// replaced the panic with a NaN return so `rank_task_rows`'s R25 NaN
/// filter could drop dim-mismatch rows. R31 extends NaN return to the
/// zero-magnitude case as well — pre-R31, `cosine([0,0], [1,0])`
/// returned `0.0` to avoid division-by-zero, but a zero query embedding
/// (model corruption, BLOB truncation) made every candidate tie at 0.0
/// and ordering collapsed to `last_turn_at`, letting a forged "newest"
/// row win top-1 despite no semantic match. R31's NaN return makes
/// zero-magnitude rows invisible alongside dim-mismatch and NaN-input
/// rows. The recall slice should still pre-validate at row-mapping time;
/// this NaN-on-pathology contract is defense-in-depth.
///
/// Mathematically, cosine of zero vectors is undefined; returning NaN is
/// a more honest signal than the 0.0 sentinel, and matches the rest of
/// the slice's "filter NaN" defense pattern.
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return f32::NAN;
    }
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let mag_a = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let mag_b = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if mag_a == 0.0 || mag_b == 0.0 {
        return f32::NAN;
    }
    dot / (mag_a * mag_b)
}

/// PRD §8.5 / §11.3.1 — pure cosine similarity between a query embedding
/// and a single `task_index` row. Forwards to [`cosine`].
pub fn task_semantic_similarity(query_emb: &[f32], task_row: &TaskIndexRow) -> f32 {
    cosine(query_emb, &task_row.embedding)
}

/// Rank `task_index` rows by [`task_semantic_similarity`] DESC with
/// `last_turn_at` DESC as the secondary sort key. Truncates to the top
/// `limit` hits. Implements REQ-155 (AC-16) — the consumer-side routing
/// decision (top-1 threshold, light-LLM fallback) is owned by MODULE-010
/// CONTRACT-091 `TaskRouter`.
///
/// Tiebreak details: rows with equal `similarity` are ordered by
/// `last_turn_at` DESC (newer first); `Some(t)` precedes `None`; full ties
/// (equal similarity AND equal-or-both-None last_turn_at) preserve input
/// order via stable sort.
///
/// NaN-similarity defense (R25): NaN-similarity rows are filtered out of
/// the candidate set entirely (alongside dim-mismatch rows), so they never
/// appear in the output regardless of `limit` or `last_turn_at`. R12 had
/// demoted NaN rows to last via an explicit is_nan() comparator, but that
/// left two reachable adversarial paths: (a) when `limit` exceeded the
/// number of valid candidates, NaN rows filled trailing top-k slots; (b)
/// when the query embedding was NaN-tainted, all rows produced NaN cosine
/// and ordering collapsed to `last_turn_at` only — a forged "newest"
/// NaN-row could win top-1. The filter closes both paths. The recall
/// slice should still pre-validate embeddings via MODULE-009 CONTRACT-081
/// `embed()`; this is defense-in-depth.
pub fn rank_task_rows(query_emb: &[f32], rows: &[TaskIndexRow], limit: usize) -> Vec<TaskHit> {
    // Adversarial R21+R23 hardening: per-row dimension validation.
    // `cosine` panics on length mismatch by design (precondition
    // contract), but a single corrupt embedding BLOB or a
    // model-dimension drift race in the recall slice would
    // otherwise abort the entire ranking call (DoS surface).
    //
    // R21 demoted mismatched rows to similarity=0.0, but R23 found that
    // the secondary `last_turn_at` tiebreak could let a tampered recent
    // row sneak into top-k by tying with legitimate cosine=0.0 rows.
    // R23 fix: FILTER mismatched-dim rows out of the candidate set
    // entirely (they can never appear in the output, regardless of
    // last_turn_at), closing the silent fail-open vector. The recall
    // slice should still pre-validate at row-mapping time and surface
    // DbError::Corruption; this filter is a defense-in-depth fallback.
    // R25 hardening: filter NaN-similarity rows in addition to dim-mismatch
    // rows. Pre-R25, NaN rows were sorted to the end (R12 demote behavior),
    // but two adversarial paths remained: (a) when `limit > valid_count`,
    // NaN rows filled the trailing top-k slots; (b) when the QUERY embedding
    // is NaN-tainted (or all candidate rows produce NaN cosine), ordering
    // collapsed to `last_turn_at` only — a forged "newest" NaN-tainted row
    // could win top-1. Filtering NaN-similarity at the same boundary as
    // dim-mismatch closes both paths: NaN-tainted rows simply disappear
    // from the output, regardless of limit.
    let mut hits: Vec<TaskHit> = rows
        .iter()
        .filter(|r| query_emb.len() == r.embedding.len())
        .filter_map(|r| {
            let similarity = task_semantic_similarity(query_emb, r);
            if similarity.is_nan() {
                None
            } else {
                Some(TaskHit {
                    task_id: r.task_id.clone(),
                    similarity,
                    last_turn_at: r.last_turn_at,
                })
            }
        })
        .collect();

    // After R25 NaN filter, the comparator no longer needs the is_nan()
    // branches — all hits have finite similarity. Kept simple
    // partial_cmp(...).unwrap_or(Equal) for any future float-ordering
    // edge case (e.g., -0.0 vs 0.0; partial_cmp returns Equal here, so
    // unwrap_or is purely defensive).
    hits.sort_by(|a, b| {
        b.similarity
            .partial_cmp(&a.similarity)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| match (a.last_turn_at, b.last_turn_at) {
                (Some(a_ts), Some(b_ts)) => b_ts.cmp(&a_ts),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            })
    });

    hits.truncate(limit);
    hits
}

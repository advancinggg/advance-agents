//! Unit tests for the score module — Slice B (m004-slice-b).
//! Covers MODULE-004 §3.3 T04, T05, T06, T15, T16 (in-scope ACs: AC-06, AC-07,
//! AC-15, AC-16). All tests are pure-math against in-memory inputs; no DB,
//! no async, no `Utc::now()`.

use advance_database::score::*;
use chrono::{DateTime, Duration, TimeZone, Utc};

/// Construct a `DateTime<Utc>` at midnight on the given date. Avoids
/// `Utc::now()` and the `clock` chrono feature.
fn t(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0)
        .single()
        .unwrap()
}

fn approx(actual: f32, expected: f32, tol: f32) -> bool {
    (actual - expected).abs() < tol
}

// ---------------------------------------------------------------------------
// MODULE-004-T04 — AC-06 — hotness sigmoid at access_count = 30
// ---------------------------------------------------------------------------

#[test]
fn t04_hotness_sigmoid_at_30_accesses() {
    // x = 30/10 - 3 = 0; sigmoid(0) = 0.5; hotness = 0.1 + 0.9·0.5 = 0.55.
    // Isolate hotness contribution: base = 1.0 (self_score=1, parent=1),
    // decay = 1.0 (last_modified == now → days=0).
    let now = t(2026, 5, 1);
    let result = SearchResult {
        self_score: 1.0,
        access_count: 30,
        last_modified: now,
        last_accessed: None,
        source: Source::Content,
        status: None,
        created_at: now,
    };
    let score = compute_adjusted_score(&result, 1.0, now);
    assert!(approx(score, 0.55, 0.01), "expected ~0.55, got {}", score);

    // Boundary: access_count = 0 → x = -3, sigmoid(-3) ≈ 0.0474, hotness ≈ 0.143.
    let cold = SearchResult {
        access_count: 0,
        ..result.clone()
    };
    let score = compute_adjusted_score(&cold, 1.0, now);
    assert!(
        approx(score, 0.143, 0.01),
        "cold hotness ≈ 0.143, got {}",
        score
    );

    // Boundary: very high access_count → hotness → 1.0.
    let hot = SearchResult {
        access_count: 1000,
        ..result.clone()
    };
    let score = compute_adjusted_score(&hot, 1.0, now);
    assert!(approx(score, 1.0, 0.01), "hot hotness → 1.0, got {}", score);
}

// ---------------------------------------------------------------------------
// MODULE-004-T05 — AC-06 — decay 7-day half-life + decay floor
// ---------------------------------------------------------------------------

#[test]
fn t05_decay_7_day_half_life() {
    // days_since = 7 → exp(-0.693) ≈ 0.5 → decay = 0.55.
    let now = t(2026, 5, 8);
    let mod_time = t(2026, 5, 1); // 7 days earlier
    let row = SearchResult {
        self_score: 1.0,
        access_count: 30, // hotness = 0.55 (T04 baseline)
        last_modified: mod_time,
        last_accessed: None,
        source: Source::Content,
        status: None,
        created_at: mod_time,
    };
    let score = compute_adjusted_score(&row, 1.0, now);
    // base × hotness × decay = 1.0 × 0.55 × 0.55 = 0.3025.
    assert!(
        approx(score, 0.3025, 0.01),
        "expected ~0.3025, got {}",
        score
    );

    // days_since = 0 → decay = 1.0 → score = base × hotness = 0.55.
    let row_today = SearchResult {
        last_modified: now,
        created_at: now,
        ..row.clone()
    };
    let score = compute_adjusted_score(&row_today, 1.0, now);
    assert!(approx(score, 0.55, 0.01));

    // Very stale (years ago) → decay → 0.1 floor → score = 0.55 × 0.1 = 0.055.
    let stale = SearchResult {
        last_modified: t(2020, 1, 1),
        created_at: t(2020, 1, 1),
        ..row.clone()
    };
    let score = compute_adjusted_score(&stale, 1.0, now);
    assert!(
        approx(score, 0.055, 0.01),
        "decay floor 0.1 → score ≈ 0.055, got {}",
        score
    );
}

// ---------------------------------------------------------------------------
// MODULE-004-T06 — AC-07 — epistemic boost (contested / orphaned / aging /
// recent / non-memory)
// ---------------------------------------------------------------------------

#[test]
fn t06_epistemic_boost() {
    let now = t(2026, 5, 1);
    let mem_contested = SearchResult {
        self_score: 1.0,
        access_count: 30, // hotness 0.55
        last_modified: now,
        last_accessed: None,
        source: Source::Memory,
        status: Some("contested".to_string()),
        created_at: now,
    };
    // base 1.0, hotness 0.55, decay 1.0, boost 3.0 → 1.65.
    let score = compute_adjusted_score(&mem_contested, 1.0, now);
    assert!(
        approx(score, 1.65, 0.01),
        "contested ×3 → 1.65, got {}",
        score
    );

    // Orphaned also ×3.
    let mem_orphaned = SearchResult {
        status: Some("orphaned".to_string()),
        ..mem_contested.clone()
    };
    let s = compute_adjusted_score(&mem_orphaned, 1.0, now);
    assert!(approx(s, 1.65, 0.01), "orphaned ×3 → 1.65, got {}", s);

    // Aging active (created >30d ago) → ×1.5.
    let now_aging = t(2026, 6, 5); // 35 days after created_at
    let mem_aging = SearchResult {
        self_score: 1.0,
        access_count: 30,
        last_modified: now_aging,
        last_accessed: None,
        source: Source::Memory,
        status: Some("active".to_string()),
        created_at: t(2026, 5, 1),
    };
    let s = compute_adjusted_score(&mem_aging, 1.0, now_aging);
    // base 1.0, hotness 0.55, decay 1.0, boost 1.5 → 0.825.
    assert!(
        approx(s, 0.825, 0.01),
        "aging active ×1.5 → 0.825, got {}",
        s
    );

    // Recent active (≤30d) → ×1.0 (no boost).
    let mem_recent = SearchResult {
        self_score: 1.0,
        access_count: 30,
        last_modified: now,
        last_accessed: None,
        source: Source::Memory,
        status: Some("active".to_string()),
        created_at: t(2026, 4, 25), // 6 days old at 2026-05-01
    };
    let s = compute_adjusted_score(&mem_recent, 1.0, now);
    assert!(
        approx(s, 0.55, 0.01),
        "recent active ×1.0 → 0.55, got {}",
        s
    );

    // Non-memory source — boost branch is skipped even with status=contested.
    let content_status = SearchResult {
        source: Source::Content,
        status: Some("contested".to_string()),
        ..mem_contested.clone()
    };
    let s = compute_adjusted_score(&content_status, 1.0, now);
    assert!(
        approx(s, 0.55, 0.01),
        "non-memory ignores status → 0.55, got {}",
        s
    );

    // Memory with no status (None) → ×1.0.
    let mem_no_status = SearchResult {
        status: None,
        ..mem_contested.clone()
    };
    let s = compute_adjusted_score(&mem_no_status, 1.0, now);
    assert!(approx(s, 0.55, 0.01), "memory no status → 0.55, got {}", s);

    // Memory with superseded status (not in boost set) → ×1.0.
    let mem_superseded = SearchResult {
        status: Some("superseded".to_string()),
        ..mem_contested.clone()
    };
    let s = compute_adjusted_score(&mem_superseded, 1.0, now);
    assert!(approx(s, 0.55, 0.01), "memory superseded → 0.55, got {}", s);
}

// ---------------------------------------------------------------------------
// MODULE-004-T15 — AC-15 — retention_score weight terms
// ---------------------------------------------------------------------------

#[test]
fn t15_retention_score_weight_terms() {
    let now = t(2026, 5, 1);

    // Baseline: hours_ago=0 (recency=1), normal importance (0.3), reference_count=5
    // (sigmoid(0)=0.5), no type bits (0.3 baseline), no user correction (0.0).
    // 0.20·1 + 0.15·0.3 + 0.25·0.5 + 0.25·0.3 + 0.15·0 = 0.20 + 0.045 + 0.125
    // + 0.075 + 0 = 0.445.
    let baseline = TurnDigest {
        timestamp: now,
        importance: "normal".to_string(),
        reference_count: 5,
        has_user_instruction: false,
        has_user_correction: false,
        has_tool_use: false,
        has_decision: false,
    };
    assert!(
        approx(retention_score(&baseline, now), 0.445, 0.001),
        "baseline retention = 0.445"
    );

    // Recency-only: hours_ago=20 → recency = exp(-1.0) ≈ 0.36788.
    let recent = TurnDigest {
        timestamp: now - Duration::hours(20),
        ..baseline.clone()
    };
    let expected = 0.20 * 0.367_879_4 + 0.15 * 0.3 + 0.25 * 0.5 + 0.25 * 0.3 + 0.0;
    assert!(approx(retention_score(&recent, now), expected, 0.001));

    // Type variation — has_user_instruction promotes type_score to 1.0.
    let user_inst = TurnDigest {
        has_user_instruction: true,
        ..baseline.clone()
    };
    let expected = 0.20 * 1.0 + 0.15 * 1.0 + 0.25 * 0.5 + 0.25 * 0.3 + 0.0;
    assert!(approx(retention_score(&user_inst, now), expected, 0.001));

    // Type variation — has_decision promotes type_score to 0.8.
    let dec = TurnDigest {
        has_decision: true,
        ..baseline.clone()
    };
    let expected = 0.20 * 1.0 + 0.15 * 0.8 + 0.25 * 0.5 + 0.25 * 0.3 + 0.0;
    assert!(approx(retention_score(&dec, now), expected, 0.001));

    // Type variation — has_tool_use promotes type_score to 0.5.
    let tu = TurnDigest {
        has_tool_use: true,
        ..baseline.clone()
    };
    let expected = 0.20 * 1.0 + 0.15 * 0.5 + 0.25 * 0.5 + 0.25 * 0.3 + 0.0;
    assert!(approx(retention_score(&tu, now), expected, 0.001));

    // Reference variation — reference_count=15 → sigmoid(3) ≈ 0.95257.
    let ref_high = TurnDigest {
        reference_count: 15,
        ..baseline.clone()
    };
    let expected = 0.20 * 1.0 + 0.15 * 0.3 + 0.25 * 0.952_574_1 + 0.25 * 0.3 + 0.0;
    assert!(approx(retention_score(&ref_high, now), expected, 0.001));

    // Importance: critical → 1.0.
    let crit = TurnDigest {
        importance: "critical".to_string(),
        ..baseline.clone()
    };
    let expected = 0.20 * 1.0 + 0.15 * 0.3 + 0.25 * 0.5 + 0.25 * 1.0 + 0.0;
    assert!(approx(retention_score(&crit, now), expected, 0.001));

    // Importance: notable → 0.6.
    let nota = TurnDigest {
        importance: "notable".to_string(),
        ..baseline.clone()
    };
    let expected = 0.20 * 1.0 + 0.15 * 0.3 + 0.25 * 0.5 + 0.25 * 0.6 + 0.0;
    assert!(approx(retention_score(&nota, now), expected, 0.001));

    // User intent — has_user_correction → 1.0.
    let corr = TurnDigest {
        has_user_correction: true,
        ..baseline.clone()
    };
    let expected = 0.20 * 1.0 + 0.15 * 0.3 + 0.25 * 0.5 + 0.25 * 0.3 + 0.15 * 1.0;
    assert!(approx(retention_score(&corr, now), expected, 0.001));

    // Multi-bit type interaction — has_user_instruction wins over has_decision.
    let multi = TurnDigest {
        has_user_instruction: true,
        has_decision: true,
        has_tool_use: true,
        ..baseline.clone()
    };
    let expected = 0.20 * 1.0 + 0.15 * 1.0 + 0.25 * 0.5 + 0.25 * 0.3 + 0.0;
    assert!(approx(retention_score(&multi, now), expected, 0.001));
}

// ---------------------------------------------------------------------------
// MODULE-004-T16 — AC-16 — rank_task_rows + cosine helper edges
// ---------------------------------------------------------------------------

#[test]
fn t16_rank_task_rows_sort_with_tiebreak() {
    let now = t(2026, 5, 1);
    let q = vec![1.0_f32, 0.0, 0.0];
    let rows = vec![
        TaskIndexRow {
            task_id: "T1".to_string(),
            embedding: vec![1.0, 0.0, 0.0], // cos = 1.0
            last_turn_at: Some(now - Duration::hours(1)),
        },
        TaskIndexRow {
            task_id: "T2".to_string(),
            embedding: vec![0.5, 0.5, 0.0], // cos ≈ 0.707
            last_turn_at: Some(now - Duration::hours(2)),
        },
        TaskIndexRow {
            task_id: "T3".to_string(),
            embedding: vec![0.0, 1.0, 0.0], // cos = 0.0
            last_turn_at: None,
        },
        TaskIndexRow {
            task_id: "T4".to_string(),
            embedding: vec![1.0, 0.0, 0.0], // cos = 1.0 (tied with T1, T5)
            last_turn_at: Some(now - Duration::hours(3)),
        },
        TaskIndexRow {
            task_id: "T5".to_string(),
            embedding: vec![1.0, 0.0, 0.0], // cos = 1.0 — newest
            last_turn_at: Some(now - Duration::minutes(30)),
        },
    ];

    // Top-5: ties resolved by last_turn_at DESC; None goes after Some.
    let hits = rank_task_rows(&q, &rows, 5);
    assert_eq!(hits.len(), 5);
    let order: Vec<&str> = hits.iter().map(|h| h.task_id.as_str()).collect();
    assert_eq!(
        order,
        vec!["T5", "T1", "T4", "T2", "T3"],
        "expected newest-first ties then by similarity, got {:?}",
        order
    );

    // Limit truncation.
    let top2 = rank_task_rows(&q, &rows, 2);
    assert_eq!(top2.len(), 2);
    assert_eq!(top2[0].task_id, "T5");
    assert_eq!(top2[1].task_id, "T1");

    // Limit larger than rows: returns all rows, no panic.
    let top10 = rank_task_rows(&q, &rows, 10);
    assert_eq!(top10.len(), 5);

    // Empty rows: returns empty vec, no panic.
    let empty: Vec<TaskIndexRow> = vec![];
    let none = rank_task_rows(&q, &empty, 5);
    assert!(none.is_empty());

    // None vs Some tiebreak: None goes after Some when similarities tie.
    let pair = vec![
        TaskIndexRow {
            task_id: "A".to_string(),
            embedding: vec![1.0, 0.0, 0.0],
            last_turn_at: None,
        },
        TaskIndexRow {
            task_id: "B".to_string(),
            embedding: vec![1.0, 0.0, 0.0],
            last_turn_at: Some(now - Duration::days(100)), // very old, but Some
        },
    ];
    let hits = rank_task_rows(&q, &pair, 2);
    assert_eq!(
        hits[0].task_id, "B",
        "Some(any) precedes None on similarity tie"
    );
    assert_eq!(hits[1].task_id, "A");

    // Cosine helper sanity (post-R31: zero-magnitude → NaN, not 0.0):
    assert!(
        approx(cosine(&[1.0, 0.0], &[1.0, 0.0]), 1.0, 0.001),
        "identity"
    );
    assert!(
        approx(cosine(&[1.0, 0.0], &[0.0, 1.0]), 0.0, 0.001),
        "orthogonal"
    );
    assert!(
        approx(cosine(&[1.0, 0.0], &[-1.0, 0.0]), -1.0, 0.001),
        "anti-parallel"
    );
    assert!(
        cosine(&[0.0, 0.0], &[1.0, 0.0]).is_nan(),
        "zero vector → NaN (R31)"
    );
    assert!(
        cosine(&[1.0, 0.0], &[0.0, 0.0]).is_nan(),
        "zero rhs → NaN (R31)"
    );

    // task_semantic_similarity is just a cosine wrapper.
    let row = TaskIndexRow {
        task_id: "X".to_string(),
        embedding: vec![1.0, 0.0, 0.0],
        last_turn_at: None,
    };
    assert!(approx(task_semantic_similarity(&q, &row), 1.0, 0.001));
}

#[test]
fn r31_zero_magnitude_embeddings_filtered_out() {
    // R31 hardening: zero-magnitude embeddings (corrupt model output, BLOB
    // truncation, or attacker-injected zero vectors) used to return
    // similarity=0.0 from cosine. That allowed every candidate to tie at
    // 0.0 when the query was zero-magnitude, collapsing ordering to
    // last_turn_at — a forged "newest" task could then win top-1 despite
    // no semantic match. R31 changes cosine to return NaN on zero
    // magnitude, so rank_task_rows's NaN filter (R25) drops these rows
    // entirely.
    let now = t(2026, 5, 1);
    let zero_q = vec![0.0_f32, 0.0, 0.0];

    let valid = TaskIndexRow {
        task_id: "VALID".to_string(),
        embedding: vec![1.0, 0.0, 0.0],
        last_turn_at: Some(now - Duration::hours(10)),
    };
    let attacker = TaskIndexRow {
        task_id: "ATTACKER".to_string(),
        embedding: vec![0.5, 0.5, 0.0],
        last_turn_at: Some(now), // newest — would win pre-R31 via tiebreak
    };

    // Pre-R31: cosine(zero_q, valid) = 0.0 = cosine(zero_q, attacker), tied.
    // attacker wins top-1 by last_turn_at. POST-R31: both NaN, both filtered, empty.
    let hits = rank_task_rows(&zero_q, &[valid.clone(), attacker.clone()], 5);
    assert!(
        hits.is_empty(),
        "zero query → no rows; closes routing fail-open"
    );

    // Symmetric case: legitimate query, a corrupt zero-vector candidate row.
    let q = vec![1.0_f32, 0.0, 0.0];
    let zero_row = TaskIndexRow {
        task_id: "CORRUPT_ZERO".to_string(),
        embedding: vec![0.0, 0.0, 0.0],
        last_turn_at: Some(now), // recent — would have appeared in top-k pre-R31
    };
    let hits = rank_task_rows(&q, &[valid.clone(), zero_row], 5);
    assert_eq!(hits.len(), 1, "zero-mag candidate filtered out");
    assert_eq!(hits[0].task_id, "VALID");
}

#[test]
fn t16_nan_similarity_filtered_out() {
    // Adversarial R25 hardening: rank_task_rows must FILTER NaN-similarity
    // rows out of the candidate set (not just demote to last).
    // Pre-R25 (R12 fix): NaN rows demoted to last via is_nan() comparator —
    // worked for ordering but two adversarial paths remained:
    //   (a) limit > valid_count → NaN rows fill trailing top-k slots
    //   (b) query is NaN-tainted → all cosines NaN → ordering collapses to
    //       last_turn_at; forged "newest" row wins top-1
    // R25 fix: filter NaN-similarity rows entirely, same boundary as
    // dim-mismatch (R23). They never appear in output.
    let now = t(2026, 5, 1);
    let q = vec![1.0_f32, 0.0, 0.0];

    // Build a row whose embedding produces NaN cosine.
    let nan_row = TaskIndexRow {
        task_id: "NAN".to_string(),
        embedding: vec![f32::NAN, 0.0, 0.0],
        last_turn_at: Some(now), // newest — but should be FILTERED, not used as tiebreak winner
    };
    let valid_high = TaskIndexRow {
        task_id: "HIGH".to_string(),
        embedding: vec![1.0, 0.0, 0.0], // cos = 1.0
        last_turn_at: Some(now - Duration::hours(10)),
    };
    let valid_low = TaskIndexRow {
        task_id: "LOW".to_string(),
        embedding: vec![0.0, 1.0, 0.0], // cos = 0.0
        last_turn_at: Some(now - Duration::hours(20)),
    };

    // NaN row in different input positions: always filtered; output has only valid rows.
    for rows in &[
        vec![nan_row.clone(), valid_high.clone(), valid_low.clone()], // NaN first
        vec![valid_high.clone(), nan_row.clone(), valid_low.clone()], // NaN middle
        vec![valid_high.clone(), valid_low.clone(), nan_row.clone()], // NaN last
    ] {
        let hits = rank_task_rows(&q, rows, 3);
        assert_eq!(
            hits.len(),
            2,
            "NaN row filtered, only 2 valid rows in output"
        );
        let order: Vec<&str> = hits.iter().map(|h| h.task_id.as_str()).collect();
        assert_eq!(order, vec!["HIGH", "LOW"]);
    }

    // Multiple NaN rows + one valid: only valid row appears.
    let nan2 = TaskIndexRow {
        task_id: "NAN2".to_string(),
        embedding: vec![f32::NAN, f32::NAN, 0.0],
        last_turn_at: None,
    };
    let rows = vec![nan_row.clone(), valid_high.clone(), nan2.clone()];
    let hits = rank_task_rows(&q, &rows, 3);
    assert_eq!(hits.len(), 1, "only HIGH survives — NaN rows filtered");
    assert_eq!(hits[0].task_id, "HIGH");

    // Closure of fail-open via NaN-tainted query: query w/ NaN component
    // yields NaN cosine for every row; filter empties the output, no row
    // can win top-1 by last_turn_at fallback.
    let q_nan = vec![f32::NAN, 0.0, 0.0];
    let valid_rows = vec![valid_high.clone(), valid_low.clone()];
    let hits = rank_task_rows(&q_nan, &valid_rows, 5);
    assert!(
        hits.is_empty(),
        "NaN-tainted query → no rows in output (no fail-open)"
    );
}

#[test]
fn r27_cosine_returns_nan_on_length_mismatch() {
    // R27 hardening: cosine returns NaN on length mismatch instead of
    // panicking. The NaN propagates up through task_semantic_similarity to
    // rank_task_rows, where the R25 NaN filter drops the row entirely. This
    // closes the panic-on-mismatch DoS surface for any caller that uses
    // cosine / task_semantic_similarity directly without pre-validation.
    let result = cosine(&[1.0, 0.0], &[1.0, 0.0, 0.0]);
    assert!(
        result.is_nan(),
        "expected NaN on length mismatch, got {}",
        result
    );

    // Empty-vs-non-empty also returns NaN.
    let result = cosine(&[], &[1.0, 0.0]);
    assert!(result.is_nan());

    // task_semantic_similarity propagates the NaN.
    let row = TaskIndexRow {
        task_id: "X".to_string(),
        embedding: vec![1.0, 0.0], // 2-dim
        last_turn_at: None,
    };
    let q = vec![1.0_f32, 0.0, 0.0]; // 3-dim
    let result = task_semantic_similarity(&q, &row);
    assert!(
        result.is_nan(),
        "task_semantic_similarity inherits cosine NaN"
    );
}

// ---------------------------------------------------------------------------
// Adversarial R21 hardening tests
// ---------------------------------------------------------------------------

#[test]
fn r21_compute_adjusted_score_finite_under_extreme_timestamps() {
    // chrono::DateTime::MIN_UTC / MAX_UTC sentinels would have panicked the
    // pre-R21 implementation via chrono::Duration overflow on `now - last_active`.
    // The saturating_sub on timestamp_millis eliminates the panic; the .min(1.0)
    // decay clamp + finite guard prevent +Inf rank-poison.
    let now = t(2026, 5, 1);

    // Far-future last_modified (would have produced +Inf decay pre-R21).
    let r_future = SearchResult {
        self_score: 1.0,
        access_count: 30,
        last_modified: t(9999, 12, 31), // ~7973 years in the future
        last_accessed: None,
        source: Source::Content,
        status: None,
        created_at: t(9999, 12, 31),
    };
    let s = compute_adjusted_score(&r_future, 1.0, now);
    assert!(
        s.is_finite(),
        "score must be finite for future timestamps, got {}",
        s
    );
    // Decay clamped at 1.0; base 1.0 × hotness 0.55 × decay 1.0 = 0.55.
    assert!(
        approx(s, 0.55, 0.01),
        "decay clamp at 1.0 → score 0.55, got {}",
        s
    );

    // chrono MIN_UTC last_modified (would have panicked pre-R21).
    let r_ancient = SearchResult {
        self_score: 1.0,
        access_count: 30,
        last_modified: chrono::DateTime::<Utc>::MIN_UTC,
        last_accessed: None,
        source: Source::Content,
        status: None,
        created_at: chrono::DateTime::<Utc>::MIN_UTC,
    };
    let s = compute_adjusted_score(&r_ancient, 1.0, now);
    assert!(
        s.is_finite(),
        "score must be finite for MIN_UTC timestamps, got {}",
        s
    );
    // Very stale → decay floor 0.1; base 1.0 × hotness 0.55 × decay 0.1 = 0.055.
    assert!(
        approx(s, 0.055, 0.01),
        "decay floor 0.1 → score ≈ 0.055, got {}",
        s
    );
}

#[test]
fn r21_compute_adjusted_score_nan_input_demoted_to_zero() {
    // NaN in self_score / parent_score would propagate through base × hotness × decay
    // pre-R21. The final `is_finite()` guard now demotes NaN-tainted scores to 0.0.
    let now = t(2026, 5, 1);
    let r = SearchResult {
        self_score: f32::NAN,
        access_count: 30,
        last_modified: now,
        last_accessed: None,
        source: Source::Content,
        status: None,
        created_at: now,
    };
    let s = compute_adjusted_score(&r, 1.0, now);
    assert_eq!(s, 0.0, "NaN self_score → score 0.0 (finite guard)");

    // NaN parent_score also demoted.
    let r_clean = SearchResult {
        self_score: 1.0,
        ..r.clone()
    };
    let s = compute_adjusted_score(&r_clean, f32::NAN, now);
    assert_eq!(s, 0.0, "NaN parent_score → score 0.0");
}

#[test]
fn r21_retention_score_finite_under_extreme_timestamps() {
    // Pre-R21 used chrono::Duration arithmetic which panics at MIN_UTC, plus
    // unclamped recency could produce +Inf for far-future timestamps.
    let now = t(2026, 5, 1);

    let turn_future = TurnDigest {
        timestamp: t(9999, 12, 31),
        importance: "normal".to_string(),
        reference_count: 5,
        has_user_instruction: false,
        has_user_correction: false,
        has_tool_use: false,
        has_decision: false,
    };
    let s = retention_score(&turn_future, now);
    assert!(
        s.is_finite(),
        "retention must be finite for future timestamps"
    );
    // recency clamped at 1.0 → baseline 0.445.
    assert!(
        approx(s, 0.445, 0.01),
        "recency clamp at 1.0 → 0.445, got {}",
        s
    );

    let turn_ancient = TurnDigest {
        timestamp: chrono::DateTime::<Utc>::MIN_UTC,
        ..turn_future.clone()
    };
    let s = retention_score(&turn_ancient, now);
    assert!(
        s.is_finite(),
        "retention must be finite for MIN_UTC timestamps"
    );
    // Very stale → recency = exp(-large) ≈ 0; rest stays.
    // Score ≈ 0.20*0 + 0.15*0.3 + 0.25*0.5 + 0.25*0.3 + 0 = 0.245.
    assert!(approx(s, 0.245, 0.001), "stale recency → 0.245, got {}", s);
}

#[test]
fn r23_rank_task_rows_dim_mismatch_filtered_out() {
    // Pre-R21: corrupt-dim row would panic the entire ranking call.
    // R21 fix: demote to similarity=0.0 (sorted to bottom).
    // R23 fix: FILTER mismatched rows out of the candidate set entirely
    // (closes silent fail-open via last_turn_at tiebreak — a tampered row
    // with recent timestamp could otherwise sneak into top-k by tying with
    // legitimate cos=0.0 rows).
    let now = t(2026, 5, 1);
    let q = vec![1.0_f32, 0.0, 0.0];
    let rows = vec![
        TaskIndexRow {
            task_id: "GOOD".to_string(),
            embedding: vec![1.0, 0.0, 0.0], // 3-dim, matches q → cos=1.0
            last_turn_at: Some(now),
        },
        TaskIndexRow {
            task_id: "WRONG_DIM".to_string(),
            embedding: vec![1.0, 0.0], // 2-dim, mismatched → FILTERED
            last_turn_at: Some(now),
        },
        TaskIndexRow {
            task_id: "ALSO_WRONG".to_string(),
            embedding: vec![1.0, 0.0, 0.0, 0.0], // 4-dim, mismatched → FILTERED
            last_turn_at: Some(now),
        },
        TaskIndexRow {
            task_id: "ZERO".to_string(),
            embedding: vec![0.0, 1.0, 0.0], // 3-dim, cos=0
            last_turn_at: Some(now),
        },
    ];

    // Only valid-dim rows appear in output; mismatched rows are filtered out.
    let hits = rank_task_rows(&q, &rows, 4);
    assert_eq!(hits.len(), 2, "only 2 valid-dim rows survive filter");
    let order: Vec<&str> = hits.iter().map(|h| h.task_id.as_str()).collect();
    assert_eq!(order, vec!["GOOD", "ZERO"]);

    // Confirm cos values are correct (no NaN, no NEG_INF leakage from filter).
    assert!(approx(hits[0].similarity, 1.0, 0.001));
    assert!(approx(hits[1].similarity, 0.0, 0.001));

    // Even with limit=4, only 2 valid rows returned (no padding from corrupt rows).
    let limited = rank_task_rows(&q, &rows, 1);
    assert_eq!(limited.len(), 1);
    assert_eq!(limited[0].task_id, "GOOD");
}

#[test]
fn r29_compute_adjusted_score_meta_returns_zero() {
    // R29 hardening: Source::Meta is NOT scored per PRD §8.5.3 table-role
    // mapping; meta_index hits only emit parent_score for content/memory
    // ranking, never get scored themselves. Pre-R29 the function silently
    // scored Meta as Content-equivalent (skipping only the Memory boost).
    // R29 adds an explicit Source::Meta → 0.0 guard at function entry.
    let now = t(2026, 5, 1);
    let r_meta = SearchResult {
        self_score: 1.0,
        access_count: 30,
        last_modified: now,
        last_accessed: None,
        source: Source::Meta,
        status: None,
        created_at: now,
    };
    assert_eq!(
        compute_adjusted_score(&r_meta, 1.0, now),
        0.0,
        "Source::Meta returns 0.0 unconditionally"
    );

    // Sanity: the same row but Source::Content scores normally.
    let r_content = SearchResult {
        source: Source::Content,
        ..r_meta.clone()
    };
    let s = compute_adjusted_score(&r_content, 1.0, now);
    assert!(approx(s, 0.55, 0.01), "Source::Content scores normally");
}

#[test]
fn r23_compute_adjusted_score_input_clamp_caps_finite_huge() {
    // Pre-R23, finite-but-huge self_score / parent_score (e.g., 1e30 from a
    // corrupted upstream FTS5 rank-to-score mapping) bypassed the is_finite()
    // guard and propagated through base × hotness × decay to yield a finite
    // score that dominated legitimate rows. The R23 input clamp to [0, 1]
    // bounds base in [0, 1] and the final score in [0, 3.0] (with boost).
    let now = t(2026, 5, 1);
    let r = SearchResult {
        self_score: 1e30, // Adversarial: huge finite, would have bypassed is_finite()
        access_count: 30,
        last_modified: now,
        last_accessed: None,
        source: Source::Content,
        status: None,
        created_at: now,
    };
    let s = compute_adjusted_score(&r, 1.0, now);
    // After clamp(0,1): self=1.0, parent=1.0 → base=1.0; hotness=0.55, decay=1.0;
    // score = 1.0 * 0.55 * 1.0 = 0.55. Bounded.
    assert!(
        s.is_finite() && s <= 3.0,
        "score must be bounded, got {}",
        s
    );
    assert!(
        approx(s, 0.55, 0.01),
        "huge self_score clamps to 1.0, score={}",
        s
    );

    // Negative inputs also clamped (corrupted to negative similarity by upstream pipeline bug).
    let r_neg = SearchResult {
        self_score: -1e10,
        ..r.clone()
    };
    let s = compute_adjusted_score(&r_neg, -1e10, now);
    // After clamp(0,1): both 0.0 → base=0.0 → score=0.0.
    assert_eq!(s, 0.0, "negative inputs clamp to 0.0");

    // Huge parent_score also clamped.
    let r_clean = SearchResult {
        self_score: 1.0,
        ..r
    };
    let s = compute_adjusted_score(&r_clean, 1e30, now);
    assert!(
        approx(s, 0.55, 0.01),
        "huge parent_score clamps to 1.0, score={}",
        s
    );
}

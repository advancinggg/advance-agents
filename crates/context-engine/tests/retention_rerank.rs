//! Slice-C AC-10 / AC-11 (REQ-238) — retention-rerank adapter.
//!
//! - **MODULE-010-T14** (Integration, AC-10): consumption via the
//!   CONTRACT-031 stand-in — rerank uses the injected scorer's returned value
//!   verbatim, never recomputes.
//! - **t_no_local_formula** (Code, AC-10): the canonical MODULE-004
//!   `score.rs:303-354` retention-formula token-forms are ABSENT from
//!   `retention_rerank.rs` + `tier3.rs` + `assembler.rs` (no local
//!   reimplementation).
//! - **MODULE-010-T15** (Code, AC-11): query-time, no cached/pre-stored
//!   aggregate — two rerank calls over the same items ⇒ exactly `2×N` scorer
//!   invocations.
//! - **t_rerank_nan_sinks** (Unit, AC-11): non-finite scores deterministically
//!   sort AFTER all finite (explicit partition, not naive `total_cmp`).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

use advance_context_engine::{rerank_by_retention, RerankItem, RetentionScorer, TurnDigestView};

fn dig() -> TurnDigestView {
    TurnDigestView {
        timestamp: SystemTime::UNIX_EPOCH,
        importance: "normal".into(),
        reference_count: 0,
        has_user_instruction: false,
        has_user_correction: false,
        has_tool_use: false,
        has_decision: false,
    }
}

fn item(id: &str) -> RerankItem<String> {
    RerankItem::new(id.to_string(), dig())
}

// ── MODULE-010-T14 — consumption via the CONTRACT-031 stand-in ────────────

/// Fake `RetentionScorer` = the injected CONTRACT-031 `Recall::retention_score`
/// stand-in (standard DI test methodology, same as the Slice-B `Null*`/`Mock*`
/// port doubles). The injected score is **deliberately NON-monotone in
/// `reference_count`** (the highest `reference_count` maps to the *lowest*
/// score): the only ordering that reproduces the asserted result is consuming
/// THIS returned `f32` verbatim — sorting by `reference_count` (or any other
/// field-monotone local computation) yields a different order. This makes T14
/// uniquely discriminating for verbatim stand-in-value consumption.
struct FixtureScorer;
impl RetentionScorer for FixtureScorer {
    fn retention_score(&self, turn: &TurnDigestView, _now: SystemTime) -> f32 {
        // Arbitrary injected value — NOT the MODULE-004 formula, and NOT
        // monotone in reference_count (rc=9 → 0.10, the lowest). MODULE-010
        // must order by exactly this, proving it neither recomputes a formula
        // nor sorts by a digest field.
        match turn.reference_count {
            5 => 0.90, // "a"
            1 => 0.30, // "b"
            9 => 0.10, // "c"  ← highest reference_count, LOWEST score
            3 => 0.60, // "d"
            _ => 0.0,
        }
    }
}

fn item_rc(id: &str, rc: u32) -> RerankItem<String> {
    let mut d = dig();
    d.reference_count = rc;
    RerankItem::new(id.to_string(), d)
}

#[test]
fn module_010_t14_consumes_stand_in_value_verbatim() {
    // Injected scores (non-monotone in reference_count): a=0.90, b=0.30,
    // c=0.10, d=0.60. reference_count-descending = [c,a,d,b];
    // reference_count-ascending = [b,d,a,c]; input/payload order = [a,b,c,d]
    // — ALL differ from the scorer-value-descending order asserted below, so
    // the assertion holds ONLY if MODULE-010 consumed the returned f32
    // verbatim (not a recomputed formula, not a digest-field sort).
    let items = vec![
        item_rc("a", 5),
        item_rc("b", 1),
        item_rc("c", 9),
        item_rc("d", 3),
    ];
    let out = rerank_by_retention(items, &FixtureScorer, SystemTime::UNIX_EPOCH);
    let order: Vec<&str> = out.iter().map(|i| i.payload.as_str()).collect();
    // Descending by the injected stand-in value (0.90 > 0.60 > 0.30 > 0.10)
    // — MODULE-010 used the returned value verbatim.
    assert_eq!(order, vec!["a", "d", "b", "c"]);
}

// ── t_no_local_formula — no local formula reimplementation (AC-10) ────────

#[test]
fn t_no_local_formula() {
    let sources = [
        (
            "retention_rerank.rs",
            include_str!("../src/retention_rerank.rs"),
        ),
        ("tier3.rs", include_str!("../src/tier3.rs")),
        ("assembler.rs", include_str!("../src/assembler.rs")),
    ];
    // The ACTUAL canonical token-forms from crates/database/src/score.rs:303-354
    // (the retention_score body). If any appears here, MODULE-010 has locally
    // reimplemented the MODULE-004-owned formula → AC-10 violation.
    let forbidden = [
        "-0.05 * hours_ago",
        "reference_count as f32 - 5.0",
        "\"critical\" => 1.0",
        "0.20 * recency",
        "0.25 * reference",
    ];
    for (name, src) in sources {
        for f in forbidden {
            assert!(
                !src.contains(f),
                "{name} contains canonical retention-formula token `{f}` — \
                 MODULE-010 must NOT reimplement the MODULE-004 formula (AC-10)"
            );
        }
    }
}

// ── MODULE-010-T15 — query-time, no cached aggregate (AC-11) ──────────────

struct CountingScorer {
    calls: AtomicUsize,
}
impl RetentionScorer for CountingScorer {
    fn retention_score(&self, _turn: &TurnDigestView, _now: SystemTime) -> f32 {
        self.calls.fetch_add(1, Ordering::SeqCst);
        1.0
    }
}

#[test]
fn module_010_t15_query_time_no_cached_aggregate() {
    let scorer = CountingScorer {
        calls: AtomicUsize::new(0),
    };
    let mk = || vec![item("a"), item("b"), item("c")]; // N = 3
    let now = SystemTime::UNIX_EPOCH;

    let _ = rerank_by_retention(mk(), &scorer, now);
    assert_eq!(
        scorer.calls.load(Ordering::SeqCst),
        3,
        "first call scores N"
    );

    let _ = rerank_by_retention(mk(), &scorer, now);
    assert_eq!(
        scorer.calls.load(Ordering::SeqCst),
        6,
        "second rerank over the same items re-invokes the stand-in (2×N) — \
         no cached/pre-stored aggregate retention_score (AC-11)"
    );
}

// ── t_rerank_nan_sinks — non-finite determinism (AC-11 defense) ───────────

/// Returns a per-payload score so the test can inject NaN / +∞ / finite.
struct MapScorer;
impl RetentionScorer for MapScorer {
    fn retention_score(&self, turn: &TurnDigestView, _now: SystemTime) -> f32 {
        match turn.reference_count {
            0 => f32::NAN,
            1 => 0.7,
            2 => f32::INFINITY,
            3 => 0.2,
            4 => 0.9,
            _ => 0.0,
        }
    }
}

#[test]
fn t_rerank_nan_sinks() {
    // payload → reference_count selects the injected score:
    //  nan1=NaN, hi=0.9, mid=0.7, inf1=+inf, lo=0.2
    let items = vec![
        item_rc("nan1", 0),
        item_rc("hi", 4),
        item_rc("mid", 1),
        item_rc("inf1", 2),
        item_rc("lo", 3),
    ];
    let out = rerank_by_retention(items, &MapScorer, SystemTime::UNIX_EPOCH);
    let order: Vec<&str> = out.iter().map(|i| i.payload.as_str()).collect();
    // Finite first, descending (hi 0.9, mid 0.7, lo 0.2); then non-finite
    // AFTER all finite, in input order (nan1 before inf1). A naive
    // descending `f32::total_cmp` would WRONGLY float +inf/+NaN to the top.
    assert_eq!(order, vec!["hi", "mid", "lo", "nan1", "inf1"]);
}

//! Integration tests for MODULE-004 Slice F — recursive search descent
//! (PRD §8.3.4 second half; closes REQ-154).
//!
//! Verifies AC-20 (descent surface) and AC-20b (recursion gate + chain
//! bound) via `R2d2SqliteIndexHandle::new_in_memory()` round-trips.
//! T-descent-07 (depth=0 short-circuit) lives inline in
//! `recall.rs::tests` because it exercises the private
//! `recursive_descent_step` symbol directly.

mod common;

use advance_database::{R2d2RecallImpl, R2d2SqliteIndexHandle, Recall, Source};
use chrono::{DateTime, Utc};

use common::{emb_with_sim, one_hot, seed_content, seed_meta};

fn fixed_ts(secs: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
}

fn handle() -> R2d2SqliteIndexHandle {
    R2d2SqliteIndexHandle::new_in_memory().expect("in-memory handle")
}

fn impl_for(handle: R2d2SqliteIndexHandle) -> R2d2RecallImpl<R2d2SqliteIndexHandle> {
    R2d2RecallImpl::new(handle)
}

// =============================================================================
// MODULE-004-T-descent-01 (AC-20): pure-descent surfaces low-self-sim row
// =============================================================================

#[tokio::test(flavor = "current_thread")]
async fn t_descent_01_pure_descent_surfaces_low_sim_row() {
    let h = handle();
    // Meta hit at dir_a (sim 1.0 vs query one_hot(0)).
    seed_meta(
        &h,
        "m_dir_a",
        "agent1",
        "dir_a",
        "research directory",
        &emb_with_sim(1.0),
    )
    .expect("seed meta");
    // Content row at dir_a/file.md with sim 0.1 — global dense filter
    // (>= 0.3) excludes it; preview text without query keyword so FTS does
    // not match either. Descent must be the only path that surfaces it.
    seed_content(
        &h,
        "c1",
        "agent1",
        "dir_a/file.md",
        "lorem ipsum body",
        &emb_with_sim(0.1),
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed content");

    let recall = impl_for(h);
    let results = recall
        .recall("agent1", "xyz", &one_hot(0), 10)
        .await
        .expect("recall ok");

    assert_eq!(results.len(), 1, "descent must surface c1 once");
    let r = &results[0];
    assert_eq!(r.id, "c1");
    assert_eq!(r.source, Source::Content);
    assert!(
        (r.similarity - 0.1).abs() < 1e-5,
        "sim ≈ 0.1 (descent SQL value)"
    );
    assert!(
        (r.parent_score - 1.0).abs() < 1e-5,
        "parent_score ≈ 1.0 (single-level ancestor walk via parent_score_for_path)"
    );
    assert!(r.adjusted_score > 0.0, "adjusted_score is positive");
}

// =============================================================================
// MODULE-004-T-descent-02 (AC-20b): 2-level descent + immediate-child enumeration
// =============================================================================

#[tokio::test(flavor = "current_thread")]
async fn t_descent_02_two_level_descent_via_immediate_child() {
    let h = handle();
    // Meta hits at `a` AND `a/b` (both sim 1.0).
    seed_meta(&h, "m_a", "agent1", "a", "a desc", &emb_with_sim(1.0)).expect("seed meta a");
    seed_meta(&h, "m_a_b", "agent1", "a/b", "a/b desc", &emb_with_sim(1.0)).expect("seed meta a/b");
    // Content at a/b/leaf.md, sim 0.1, no FTS keyword.
    seed_content(
        &h,
        "c1",
        "agent1",
        "a/b/leaf.md",
        "lorem ipsum body",
        &emb_with_sim(0.1),
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed content");

    let recall = impl_for(h);
    let results = recall
        .recall("agent1", "xyz", &one_hot(0), 10)
        .await
        .expect("recall ok");

    // Either driver iteration order produces same final result via shared
    // visited (a-first walks a → a/b discovering c1; a/b-first finds c1
    // directly then visited blocks the a chain's recursion).
    assert_eq!(results.len(), 1, "shared visited dedups across siblings");
    let r = &results[0];
    assert_eq!(r.id, "c1");
    assert_eq!(r.source, Source::Content);
    assert!((r.similarity - 0.1).abs() < 1e-5);
    // Ancestor walk: file at a/b/leaf.md, ancestors [a/b (1.0), a (1.0)],
    // bottom-up fold p=1.0 → 1.0*0.5 + 1.0*0.5 = 1.0 → parent_score = 1.0.
    assert!((r.parent_score - 1.0).abs() < 1e-5);
}

// =============================================================================
// MODULE-004-T-descent-03 (AC-20b): 3-level descent within depth cap
// =============================================================================

#[tokio::test(flavor = "current_thread")]
async fn t_descent_03_three_level_descent_within_cap() {
    let h = handle();
    // Meta hits at a, a/b, a/b/c (all sim 1.0).
    for (id, dir) in &[("m_a", "a"), ("m_a_b", "a/b"), ("m_a_b_c", "a/b/c")] {
        seed_meta(&h, id, "agent1", dir, "desc", &emb_with_sim(1.0)).expect("seed meta");
    }
    seed_content(
        &h,
        "c1",
        "agent1",
        "a/b/c/leaf.md",
        "lorem ipsum body",
        &emb_with_sim(0.1),
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed content");

    let recall = impl_for(h);
    let results = recall
        .recall("agent1", "xyz", &one_hot(0), 10)
        .await
        .expect("recall ok");

    // Chain rooted at the shallowest entry walks a → a/b → a/b/c discovering
    // c1 via direct-children SQL at a/b/c. Subsequent driver iterations of
    // a/b and a/b/c early-return via visited check.
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, "c1");
    assert!((results[0].similarity - 0.1).abs() < 1e-5);
}

// =============================================================================
// MODULE-004-T-descent-04 (AC-20): dedup with global hit
// =============================================================================

#[tokio::test(flavor = "current_thread")]
async fn t_descent_04_dedup_with_global_hit() {
    let h = handle();
    seed_meta(&h, "m_dir_a", "agent1", "dir_a", "desc", &emb_with_sim(1.0)).expect("seed meta");
    // sim 1.0 — global dense returns c1; descent ALSO finds c1.
    seed_content(
        &h,
        "c1",
        "agent1",
        "dir_a/file.md",
        "lorem ipsum body",
        &emb_with_sim(1.0),
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed content");

    let recall = impl_for(h);
    let results = recall
        .recall("agent1", "xyz", &one_hot(0), 10)
        .await
        .expect("recall ok");

    assert_eq!(results.len(), 1, "dedup keeps c1 exactly once");
    assert_eq!(results[0].id, "c1");
    assert!((results[0].similarity - 1.0).abs() < 1e-5);
}

// =============================================================================
// MODULE-004-T-descent-04b (AC-20): low-sim sibling visibility under no-suppression
// =============================================================================

#[tokio::test(flavor = "current_thread")]
async fn t_descent_04b_low_sim_sibling_visible_under_no_suppression() {
    let h = handle();
    seed_meta(&h, "m_dir_a", "agent1", "dir_a", "desc", &emb_with_sim(1.0)).expect("seed meta");
    // c1 sim 1.0 (global-dense match)
    seed_content(
        &h,
        "c1",
        "agent1",
        "dir_a/file.md",
        "lorem ipsum body",
        &emb_with_sim(1.0),
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed c1");
    // c2 sim 0.1 (only descent can surface it)
    seed_content(
        &h,
        "c2",
        "agent1",
        "dir_a/other.md",
        "different body",
        &emb_with_sim(0.1),
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed c2");

    let recall = impl_for(h);
    let results = recall
        .recall("agent1", "xyz", &one_hot(0), 10)
        .await
        .expect("recall ok");

    assert_eq!(results.len(), 2, "descent surfaces low-sim sibling c2");
    let ids: Vec<&str> = results.iter().map(|r| r.id.as_str()).collect();
    assert!(ids.contains(&"c1"), "c1 in results (global dense)");
    assert!(
        ids.contains(&"c2"),
        "c2 in results (descent — verifies no-suppression)"
    );
    let c1 = results.iter().find(|r| r.id == "c1").unwrap();
    let c2 = results.iter().find(|r| r.id == "c2").unwrap();
    assert!((c1.similarity - 1.0).abs() < 1e-5);
    assert!((c2.similarity - 0.1).abs() < 1e-5);
}

// =============================================================================
// MODULE-004-T-descent-04c (AC-20): case-sensitive descent (round-13 adversarial)
// =============================================================================
//
// SQLite's default LIKE is ASCII-case-insensitive; on case-sensitive filesystems
// (Linux) this would let descent SQL `LIKE 'Research/%'` match files under
// `research/`. Slice F sets `PRAGMA case_sensitive_like = 1` per pooled
// connection (handle.rs PragmaCustomizer) to defend against this.

#[tokio::test(flavor = "current_thread")]
async fn t_descent_04c_case_sensitive_descent() {
    let h = handle();
    // Meta hit at "Research" (capital R, sim 1.0).
    seed_meta(
        &h,
        "m_Research",
        "agent1",
        "Research",
        "desc",
        &emb_with_sim(1.0),
    )
    .expect("seed meta Research");
    // Content row under DIFFERENT-CASE sibling "research/leak.md" (sim 0.1
    // — global dense filters it). With case-insensitive LIKE this would
    // be picked up by descent's pattern `Research/%` and leak into recall
    // results; with case-sensitive LIKE it must stay invisible.
    seed_content(
        &h,
        "c_leak",
        "agent1",
        "research/leak.md",
        "lorem ipsum body",
        &emb_with_sim(0.1),
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed content");

    let recall = impl_for(h);
    let results = recall
        .recall("agent1", "xyz", &one_hot(0), 10)
        .await
        .expect("recall ok");

    assert!(
        results.is_empty(),
        "case-sensitive LIKE must NOT surface lower-case sibling under upper-case meta dir"
    );
}

// =============================================================================
// MODULE-004-T-descent-04d (AC-20): LIKE wildcard escape (round-9 audit defense)
// =============================================================================
//
// POSIX-legal directory names containing `%` or `_` would, without LIKE
// pattern escaping, match cross-directory siblings via wildcard expansion.
// Slice F's `escape_like` helper + `LIKE ?N ESCAPE '\\'` clause defends.

#[tokio::test(flavor = "current_thread")]
async fn t_descent_04d_like_wildcard_escape() {
    let h = handle();
    // Meta hit at literal "100%" dir (sim 1.0).
    seed_meta(&h, "m_pct", "agent1", "100%", "desc", &emb_with_sim(1.0)).expect("seed meta 100%");
    // Content row under sibling "100abc/leak.md" — without escape, descent's
    // pattern `100%/%` would match this via wildcard expansion (sim 0.1
    // → global dense filters it; descent must NOT pick it up).
    seed_content(
        &h,
        "c_leak",
        "agent1",
        "100abc/leak.md",
        "lorem ipsum body",
        &emb_with_sim(0.1),
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed content");
    // Legitimate child of "100%" dir (sim 0.1 — only descent should surface).
    seed_content(
        &h,
        "c_legit",
        "agent1",
        "100%/note.md",
        "lorem ipsum body",
        &emb_with_sim(0.1),
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed content");

    let recall = impl_for(h);
    let results = recall
        .recall("agent1", "xyz", &one_hot(0), 10)
        .await
        .expect("recall ok");

    let ids: Vec<&str> = results.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(
        results.len(),
        1,
        "descent must surface ONLY the legitimate child"
    );
    assert_eq!(
        ids,
        vec!["c_legit"],
        "wildcard `%` in dir name must be treated as literal"
    );
}

// =============================================================================
// MODULE-004-T-descent-04e (AC-20): cross-agent isolation (round-13 defense)
// =============================================================================
//
// Descent SQL binds `agent_id = ?2` exactly — verify a regression test pins
// the cross-agent isolation invariant against accidental future drops.

#[tokio::test(flavor = "current_thread")]
async fn t_descent_04e_cross_agent_isolation() {
    let h = handle();
    // Agent A has a meta hit at dir_x.
    seed_meta(
        &h,
        "m_A_dir_x",
        "agentA",
        "dir_x",
        "A desc",
        &emb_with_sim(1.0),
    )
    .expect("seed meta A");
    // Agent B has content under the SAME dir_x (would be surfaced by descent
    // if agent_id binding accidentally dropped).
    seed_content(
        &h,
        "c_B_secret",
        "agentB",
        "dir_x/secret.md",
        "lorem ipsum body",
        &emb_with_sim(0.1),
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed B content");
    // Agent A's own content (descent must surface this).
    seed_content(
        &h,
        "c_A_own",
        "agentA",
        "dir_x/own.md",
        "lorem ipsum body",
        &emb_with_sim(0.1),
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed A content");

    let recall = impl_for(h);
    let results = recall
        .recall("agentA", "xyz", &one_hot(0), 10)
        .await
        .expect("recall ok");

    let ids: Vec<&str> = results.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(
        results.len(),
        1,
        "agentA recall must NOT see agentB content"
    );
    assert_eq!(ids, vec!["c_A_own"]);
}

// =============================================================================
// MODULE-004-T-descent-05 (AC-20): below-threshold suppression at meta filter
// =============================================================================

#[tokio::test(flavor = "current_thread")]
async fn t_descent_05_below_threshold_suppression() {
    let h = handle();
    // Meta sim 0.2 — meta_scores SQL filter (>= 0.3) excludes this entry,
    // so meta_scores is empty after the dense routing scan.
    seed_meta(
        &h,
        "m_dir_a_lowsim",
        "agent1",
        "dir_a",
        "desc",
        &emb_with_sim(0.2),
    )
    .expect("seed meta");
    seed_content(
        &h,
        "c1",
        "agent1",
        "dir_a/file.md",
        "lorem ipsum body",
        &emb_with_sim(0.1),
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed content");

    let recall = impl_for(h);
    let results = recall
        .recall("agent1", "xyz", &one_hot(0), 10)
        .await
        .expect("recall ok");

    assert!(
        results.is_empty(),
        "descent does not trigger when meta_scores empty"
    );
}

// =============================================================================
// MODULE-004-T-descent-06 (AC-20): MAX_DESCENT_FANOUT cap binds at 50
// =============================================================================

#[tokio::test(flavor = "current_thread")]
async fn t_descent_06_max_descent_fanout_cap_binds() {
    let h = handle();
    seed_meta(&h, "m_dir_a", "agent1", "dir_a", "desc", &emb_with_sim(1.0)).expect("seed meta");
    // 75 content rows, all sim 0.1 (below DENSE_THRESHOLD so global dense
    // returns 0). Descent's SQL has LIMIT MAX_DESCENT_FANOUT (=50) so the
    // discovered set is capped at 50.
    for n in 0..75 {
        let id = format!("c{n:02}");
        let path = format!("dir_a/file_{n:02}.md");
        seed_content(
            &h,
            &id,
            "agent1",
            &path,
            "lorem ipsum body",
            &emb_with_sim(0.1),
            0,
            fixed_ts(1_700_000_000),
        )
        .expect("seed content");
    }

    let recall = impl_for(h);
    let results = recall
        .recall("agent1", "xyz", &one_hot(0), 100)
        .await
        .expect("recall ok");

    // limit=100 doesn't bind; descent's MAX_DESCENT_FANOUT=50 does.
    // Count-only assertion since all 75 rows have identical sim 0.1 and
    // SQLite's ORDER BY tie-break is undefined.
    assert_eq!(results.len(), 50, "MAX_DESCENT_FANOUT=50 cap binds");
}

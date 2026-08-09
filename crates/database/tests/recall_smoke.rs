//! Integration tests for MODULE-004 Slice C — CONTRACT-031 `Recall` +
//! CONTRACT-032 `UnifiedSearch`. Verifies AC-03/04/05/12/17 via
//! `R2d2SqliteIndexHandle::new_in_memory()` round-trips.

mod common;

use advance_database::{
    DbError, R2d2RecallImpl, R2d2SqliteIndexHandle, R2d2UnifiedSearchImpl, Recall, Source,
    SqliteIndexHandle, UnifiedSearch,
};
use chrono::{DateTime, Utc};

use common::{
    now_utc, one_hot, read_content_access, read_memory_access, seed_content, seed_memory,
    seed_meta, seed_task, seed_turn, zero_emb,
};

/// Construct a 768-dim unit vector that produces a specific target similarity
/// `target_sim ∈ [0, 1]` against the query `one_hot(0)` under the recall
/// pipeline's `(1 - vec_distance_cosine / 2.0)` mapping (= `(1 + cos)/2`).
///
/// Solves `cos = 2*target_sim - 1`, places that as v[0], and fills v[1] to
/// keep the vector unit-length so cosine == cos exactly.
fn emb_with_sim(target_sim: f32) -> Vec<f32> {
    let cos = (2.0 * target_sim - 1.0).clamp(-1.0, 1.0);
    let mut v = vec![0.0_f32; 768];
    v[0] = cos;
    v[1] = (1.0 - cos * cos).sqrt();
    v
}

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
// AC-04 — Dual-path merge dedupe (T02 / T02b / T18a / T18b)
// =============================================================================

#[tokio::test(flavor = "current_thread")]
async fn t02_dual_path_dedupe_returns_row_once() {
    let h = handle();
    // Single content row that matches BOTH dense (one_hot(0)) and sparse
    // (FTS5 MATCH "apple") paths.
    seed_content(
        &h,
        "c1",
        "agent1",
        "dir/a.md",
        "apple cake recipe",
        &one_hot(0),
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed");

    let recall = impl_for(h);
    let results = recall
        .recall("agent1", "apple", &one_hot(0), 10)
        .await
        .expect("recall");

    let ids: Vec<&str> = results.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, vec!["c1"], "dual-path merge must deduplicate by id");
}

#[tokio::test(flavor = "current_thread")]
async fn t02b_dense_only_sparse_only_dual_path() {
    let h = handle();
    // c_dense_only: dense match (one_hot(0)) but NOT sparse (no `apple` token).
    seed_content(
        &h,
        "c_dense",
        "agent1",
        "dir/d.md",
        "watermelon",
        &one_hot(0),
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed");
    // c_sparse_only: sparse match (`apple`) but orthogonal embedding (one_hot(5)).
    seed_content(
        &h,
        "c_sparse",
        "agent1",
        "dir/s.md",
        "apple jam",
        &one_hot(5),
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed");
    // c_both: matches both paths.
    seed_content(
        &h,
        "c_both",
        "agent1",
        "dir/b.md",
        "apple cake",
        &one_hot(0),
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed");

    let recall = impl_for(h);
    let results = recall
        .recall("agent1", "apple", &one_hot(0), 10)
        .await
        .expect("recall");

    let ids: std::collections::HashSet<&str> = results.iter().map(|r| r.id.as_str()).collect();
    assert!(ids.contains("c_dense"), "dense-only row missing");
    assert!(ids.contains("c_sparse"), "sparse-only row missing");
    assert!(ids.contains("c_both"), "dual-path row missing");
    assert_eq!(ids.len(), 3, "expected 3 distinct ids; got {:?}", ids);

    let both_row = results.iter().find(|r| r.id == "c_both").unwrap();
    assert!(both_row.similarity.is_finite());
    assert!(both_row.similarity > 0.0);
}

// =============================================================================
// Wave-20 Lane `search` — additive `upsert_memory_index_row` write-side helper.
// Proves a memory row written by the helper round-trips through REAL recall
// (dense leg) with the agent-namespaced composite id.
// =============================================================================

#[tokio::test(flavor = "current_thread")]
async fn t_upsert_memory_index_row_roundtrips_through_recall() {
    let h = handle();
    advance_database::upsert_memory_index_row(
        &h,
        "agent1",
        "mem-1",
        "the deploy uses rsync",
        Some(&one_hot(0)),
    )
    .expect("upsert memory row");

    let recall = impl_for(h);
    // Memory is dense-only (no memory_fts) — the query text is irrelevant; the
    // one_hot(0) embedding matches the ingested one_hot(0) (sim 1.0 >= threshold).
    let results = recall
        .recall("agent1", "deploy", &one_hot(0), 10)
        .await
        .expect("recall");

    let mem = results
        .iter()
        .find(|r| r.source == Source::Memory)
        .expect("memory hit must be present");
    assert_eq!(
        mem.id, "agent1\u{1F}mem-1",
        "memory_index.id must be the agent-namespaced composite (memory_row_id)"
    );
    assert_eq!(
        mem.content_full.as_deref(),
        Some("the deploy uses rsync"),
        "recalled memory content must round-trip"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn t_upsert_memory_index_row_multi_alias_no_pk_collision() {
    // W1/I4 fix: the SAME bare memory id ingested under two distinct aliases
    // (the prod `[bare, colon]` query-alias set) must yield TWO distinct
    // memory_index PK rows, each recallable under its own agent_id.
    let h = handle();
    for alias in ["agent", "agent:run-7"] {
        advance_database::upsert_memory_index_row(
            &h,
            alias,
            "mem-9",
            "shared insight",
            Some(&one_hot(0)),
        )
        .expect("upsert under alias");
    }
    let recall = impl_for(h);
    for alias in ["agent", "agent:run-7"] {
        let results = recall
            .recall(alias, "x", &one_hot(0), 10)
            .await
            .expect("recall");
        let mem = results
            .iter()
            .find(|r| r.source == Source::Memory)
            .unwrap_or_else(|| panic!("memory hit missing under alias {alias:?}"));
        assert_eq!(mem.id, format!("{alias}\u{1F}mem-9"));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn t18a_cross_agent_isolation() {
    let h = handle();
    // Both agents have semantically-identical content; ids are globally unique
    // (TEXT PRIMARY KEY enforces this).
    seed_content(
        &h,
        "row-a",
        "A",
        "shared.md",
        "shared content",
        &one_hot(0),
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed A");
    seed_content(
        &h,
        "row-b",
        "B",
        "shared.md",
        "shared content",
        &one_hot(0),
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed B");

    let recall = impl_for(h);
    let results = recall
        .recall("A", "shared", &one_hot(0), 10)
        .await
        .expect("recall");

    let ids: Vec<&str> = results.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["row-a"],
        "agent_id filter must exclude other agents"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn t18b_empty_embedding_rejected() {
    let h = handle();
    let recall = impl_for(h);
    let r = recall.recall("agent1", "anything", &[], 10).await;
    assert!(matches!(r, Err(DbError::InvalidConfig(_))));
}

#[tokio::test(flavor = "current_thread")]
async fn t18c_recall_at_unsupported() {
    let h = handle();
    let recall = impl_for(h);
    let r = recall
        .recall_at("agent1", "q", &one_hot(0), "2026-01-01T00:00:00Z", 10)
        .await;
    assert!(matches!(r, Err(DbError::Unsupported(_))));
}

// =============================================================================
// AC-05 — Directory aggregation + recursive 50/50 propagation (T03b/T03c/T03d)
// =============================================================================

#[tokio::test(flavor = "current_thread")]
async fn t03b_single_level_propagation() {
    let h = handle();
    // file at dir_a/file.md with self_score derived from cosine match.
    // We arrange the content embedding to give cosine ≈ 0.4 against the query.
    // Easiest: make content embedding orthogonal to query and rely on FTS-rank-only?
    // Simpler approach: use one_hot(0) for query AND content, then control via
    // last_modified / access_count instead. Here we use one_hot(0) for both
    // (cosine = 1.0) and verify only that propagation routes the meta hit through.
    seed_content(
        &h,
        "c1",
        "agent1",
        "dir_a/file.md",
        "doc body",
        &one_hot(0),
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed content");
    // meta hit on dir_a — also one_hot(0) for cosine = 1.0.
    seed_meta(
        &h,
        "m_dir_a",
        "agent1",
        "dir_a",
        "directory description",
        &one_hot(0),
    )
    .expect("seed meta");

    let recall = impl_for(h);
    let results = recall
        .recall("agent1", "doc", &one_hot(0), 10)
        .await
        .expect("recall");

    let r = results
        .iter()
        .find(|r| r.id == "c1")
        .expect("c1 in results");
    assert_eq!(r.source, Source::Content);
    // parent_score should be ≈ 1.0 (single-level, exact dir match, cosine=1).
    assert!(
        (r.parent_score - 1.0).abs() < 0.01,
        "parent_score = {}",
        r.parent_score
    );
}

#[tokio::test(flavor = "current_thread")]
async fn t03c_three_level_recursive_50_50() {
    let h = handle();
    // file at dir_a/dir_b/dir_c/leaf.md with meta hits at three ancestor
    // levels yielding actual *similarities* 0.7, 0.5, 0.3 (after the
    // sqlite-vec `(1+cos)/2` transform). `emb_with_sim(t)` constructs an
    // embedding whose post-transform similarity against `one_hot(0)` is t.
    let q = one_hot(0);

    seed_content(
        &h,
        "leaf",
        "agent1",
        "dir_a/dir_b/dir_c/leaf.md",
        "leaf doc",
        &emb_with_sim(1.0),
        0,
        now_utc(),
    )
    .expect("seed leaf");
    seed_meta(
        &h,
        "m_a",
        "agent1",
        "dir_a",
        "dir_a desc",
        &emb_with_sim(0.7),
    )
    .expect("seed m_a");
    seed_meta(
        &h,
        "m_ab",
        "agent1",
        "dir_a/dir_b",
        "dir_a/dir_b",
        &emb_with_sim(0.5),
    )
    .expect("seed m_ab");
    seed_meta(
        &h,
        "m_abc",
        "agent1",
        "dir_a/dir_b/dir_c",
        "dir_a/dir_b/dir_c",
        &emb_with_sim(0.3),
    )
    .expect("seed m_abc");

    let recall = impl_for(h);
    let results = recall
        .recall("agent1", "leaf", &q, 10)
        .await
        .expect("recall");

    let r = results
        .iter()
        .find(|r| r.id == "leaf")
        .expect("leaf in results");
    // bottom-up: p=0.7 → p=0.5*0.5+0.7*0.5=0.6 → p=0.3*0.5+0.6*0.5=0.45
    let expected = 0.45_f32;
    assert!(
        (r.parent_score - expected).abs() < 0.02,
        "parent_score = {} expected ≈ {}",
        r.parent_score,
        expected
    );
}

#[tokio::test(flavor = "current_thread")]
async fn t03d_depth_limit_excludes_too_deep_ancestors() {
    let h = handle();
    let q = one_hot(0);
    // file at a/b/c/d/leaf.md. RECALL_MAX_DEPTH = 3 → walked closest-first:
    // [a/b/c/d, a/b/c, a/b]. `a` is at depth 4 — must be excluded.
    // Use sim=0.4 for `a/b/c/d` (passes 0.3 threshold). Use sim=0.9 for `a/`
    // (would dominate if not excluded).
    seed_content(
        &h,
        "leaf2",
        "agent1",
        "a/b/c/d/leaf.md",
        "leaf",
        &emb_with_sim(1.0),
        0,
        now_utc(),
    )
    .expect("seed leaf2");
    seed_meta(&h, "m_a", "agent1", "a", "root", &emb_with_sim(0.9)).expect("seed m_a");
    seed_meta(
        &h,
        "m_abcd",
        "agent1",
        "a/b/c/d",
        "deepest",
        &emb_with_sim(0.4),
    )
    .expect("seed m_abcd");

    let recall = impl_for(h);
    let results = recall
        .recall("agent1", "leaf", &q, 10)
        .await
        .expect("recall");

    let r = results
        .iter()
        .find(|r| r.id == "leaf2")
        .expect("leaf2 in results");
    // ancestors closest-first: [0.4, 0.0, 0.0]; bottom-up:
    //   p = 0.0 → p = 0.0*0.5 + 0.0*0.5 = 0 → p = 0.4*0.5 + 0*0.5 = 0.2
    let expected = 0.2_f32;
    assert!(
        (r.parent_score - expected).abs() < 0.02,
        "parent_score = {} expected ≈ {} (a/ at depth 4 must be excluded)",
        r.parent_score,
        expected
    );
}

// =============================================================================
// AC-12 — FTS5 MATCH OR semantics (T11 / T11b / T11c)
// =============================================================================

#[tokio::test(flavor = "current_thread")]
async fn t11_fts5_or_returns_either() {
    let h = handle();
    // c1 contains apple, c2 contains banana, c3 contains both.
    // Use anti-aligned embeddings (target sim = 0.0) so dense path filters
    // them out and only FTS5 matches drive results.
    let low = emb_with_sim(0.0);
    seed_content(
        &h,
        "c1",
        "agent1",
        "f1.md",
        "apple cake",
        &low,
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed");
    seed_content(
        &h,
        "c2",
        "agent1",
        "f2.md",
        "banana bread",
        &low,
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed");
    seed_content(
        &h,
        "c3",
        "agent1",
        "f3.md",
        "apple banana",
        &low,
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed");

    let recall = impl_for(h);
    // Query "apple banana" → keywords ["apple", "banana"] → MATCH "apple" OR "banana".
    let q = one_hot(0);
    let results = recall
        .recall("agent1", "apple banana", &q, 10)
        .await
        .expect("recall");

    let ids: std::collections::HashSet<&str> = results.iter().map(|r| r.id.as_str()).collect();
    assert!(ids.contains("c1"));
    assert!(ids.contains("c2"));
    assert!(ids.contains("c3"));
}

#[tokio::test(flavor = "current_thread")]
async fn t11c_multi_keyword_query_or_semantics() {
    // Round-10 finding W1 fix: T11c was documented in §3.3 but no test
    // covered the multi-keyword OR-expansion behavior.
    let h = handle();
    let low = emb_with_sim(0.0);
    seed_content(
        &h,
        "c1",
        "agent1",
        "f1.md",
        "apple cake",
        &low,
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed");
    seed_content(
        &h,
        "c2",
        "agent1",
        "f2.md",
        "banana bread",
        &low,
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed");
    seed_content(
        &h,
        "c3",
        "agent1",
        "f3.md",
        "apple banana",
        &low,
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed");

    let recall = impl_for(h);
    let q = one_hot(0);
    // Multi-keyword "apple cake" → keywords ["apple", "cake"] → MATCH "apple" OR "cake".
    // Both c1 (apple cake) and c3 (apple banana) contain `apple`; c1 also has `cake`.
    // c2 (banana bread) has neither.
    let results = recall
        .recall("agent1", "apple cake", &q, 10)
        .await
        .expect("recall");
    let ids: std::collections::HashSet<&str> = results.iter().map(|r| r.id.as_str()).collect();
    assert!(ids.contains("c1"), "c1 has both apple AND cake");
    assert!(ids.contains("c3"), "c3 has apple");
    assert!(!ids.contains("c2"), "c2 has neither apple nor cake");
}

#[tokio::test(flavor = "current_thread")]
async fn t11b_single_keyword_excludes_non_matching() {
    let h = handle();
    let low = emb_with_sim(0.0);
    seed_content(
        &h,
        "c1",
        "agent1",
        "f1.md",
        "apple cake",
        &low,
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed");
    seed_content(
        &h,
        "c2",
        "agent1",
        "f2.md",
        "banana bread",
        &low,
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed");
    seed_content(
        &h,
        "c3",
        "agent1",
        "f3.md",
        "apple banana",
        &low,
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed");

    let recall = impl_for(h);
    let q = one_hot(0);
    let results = recall
        .recall("agent1", "apple", &q, 10)
        .await
        .expect("recall");
    let ids: std::collections::HashSet<&str> = results.iter().map(|r| r.id.as_str()).collect();
    assert!(ids.contains("c1"), "c1 has apple");
    assert!(ids.contains("c3"), "c3 has apple");
    assert!(!ids.contains("c2"), "c2 does NOT have apple");
}

// =============================================================================
// AC-03 — Recall touches only content/memory/meta tables (T13)
// =============================================================================

#[tokio::test(flavor = "current_thread")]
async fn t13_recall_does_not_return_task_or_turn_rows() {
    let h = handle();
    let q = one_hot(0);

    // Content + memory rows (recall SHOULD return these).
    seed_content(
        &h,
        "c1",
        "agent1",
        "doc.md",
        "apple cake",
        &q,
        0,
        fixed_ts(1_700_000_000),
    )
    .expect("seed c");
    seed_memory(&h, "m1", "agent1", "remember apple", &q, None, 0).expect("seed m");

    // Task + turn rows with the SAME embedding — these would surface in recall
    // results if recall mistakenly queried task_index / turn_index.
    seed_task(
        &h,
        "t1",
        "agent1",
        "task title apple",
        &q,
        Some(fixed_ts(1_700_000_000)),
    )
    .expect("seed t");
    seed_turn(
        &h,
        "tr1",
        "agent1",
        "t1",
        1,
        "digest",
        &q,
        fixed_ts(1_700_000_000),
    )
    .expect("seed tr");

    let recall = impl_for(h);
    let results = recall
        .recall("agent1", "apple", &q, 10)
        .await
        .expect("recall");

    let sources: Vec<Source> = results.iter().map(|r| r.source.clone()).collect();
    let ids: Vec<&str> = results.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(
        results.len(),
        2,
        "expected 2 hits (content + memory); got ids {:?}",
        ids
    );
    for s in &sources {
        assert!(
            matches!(s, Source::Content | Source::Memory),
            "source = {:?} must be Content or Memory only",
            s
        );
    }
    assert!(ids.contains(&"c1"));
    assert!(ids.contains(&"m1"));
    assert!(!ids.contains(&"t1"));
    assert!(!ids.contains(&"tr1"));
}

#[test]
fn t13_static_audit_recall_blocking_does_not_touch_task_or_turn() {
    // Static defense-in-depth: brace-counter parse the body of `fn recall_blocking`
    // in `src/recall.rs` and assert no `task_index|task_vec|turn_index|turn_vec`
    // literal appears inside.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/recall.rs");
    let src = std::fs::read_to_string(&path).expect("read recall.rs");

    let body = extract_fn_body(&src, "fn recall_blocking")
        .expect("could not locate fn recall_blocking body");

    for forbidden in &["task_index", "task_vec", "turn_index", "turn_vec"] {
        assert!(
            !body.contains(forbidden),
            "AC-03 violation: `recall_blocking` body contains forbidden token {:?}",
            forbidden
        );
    }
}

/// Brace-counter parser: locate the `fn recall_blocking` line, find its
/// opening `{`, then walk forward tracking depth while skipping string
/// literals (regular, byte, raw, raw byte, c-string, raw c-string), char
/// literals, byte char literals, line comments, and nested block comments.
fn extract_fn_body<'a>(src: &'a str, fn_header: &str) -> Option<&'a str> {
    let header_pos = src.find(fn_header)?;
    // find first `{` after the header
    let open = src[header_pos..].find('{')?;
    let body_start = header_pos + open + 1;

    let bytes = src.as_bytes();
    let mut i = body_start;
    let mut depth: i32 = 1;

    while i < bytes.len() && depth > 0 {
        let b = bytes[i];

        // line comment
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // nested block comment
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            let mut bdepth: i32 = 1;
            i += 2;
            while i < bytes.len() && bdepth > 0 {
                if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
                    bdepth += 1;
                    i += 2;
                } else if bytes[i] == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                    bdepth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            continue;
        }

        // raw string forms: r"..."; r#"..."#; b similarly; cr/c similarly.
        // Detect prefix at position i.
        if let Some((prefix_len, hash_count)) = raw_string_prefix(&bytes[i..]) {
            // find closing `"` followed by hash_count `#`s
            i += prefix_len;
            let close_marker = (0..hash_count).map(|_| b'#').collect::<Vec<_>>();
            'raw: while i < bytes.len() {
                if bytes[i] == b'"' {
                    let mut k = i + 1;
                    let mut ok = true;
                    for &h in &close_marker {
                        if k >= bytes.len() || bytes[k] != h {
                            ok = false;
                            break;
                        }
                        k += 1;
                    }
                    if ok {
                        i = k;
                        break 'raw;
                    }
                }
                i += 1;
            }
            continue;
        }

        // regular / byte / c string: " or b" or c"
        let str_prefix = match (b, bytes.get(i + 1).copied()) {
            (b'"', _) => Some(1),
            (b'b', Some(b'"')) => Some(2),
            (b'c', Some(b'"')) => Some(2),
            _ => None,
        };
        if let Some(plen) = str_prefix {
            i += plen;
            while i < bytes.len() {
                let c = bytes[i];
                if c == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                if c == b'"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }

        // char / byte char literal: '...' (also lifetime fallback)
        if b == b'\'' || (b == b'b' && bytes.get(i + 1).copied() == Some(b'\'')) {
            let start = if b == b'b' { i + 2 } else { i + 1 };
            // peek up to 4 chars for closing '
            let mut k = start;
            let mut found = false;
            while k < bytes.len() && k - start < 6 {
                if bytes[k] == b'\\' && k + 1 < bytes.len() {
                    k += 2;
                    continue;
                }
                if bytes[k] == b'\'' {
                    found = true;
                    break;
                }
                k += 1;
            }
            if found {
                i = k + 1;
                continue;
            }
            // lifetime token: just consume the leading '
            i += 1;
            continue;
        }

        // brace tracking
        if b == b'{' {
            depth += 1;
        } else if b == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(&src[body_start..i]);
            }
        }
        i += 1;
    }

    None
}

fn raw_string_prefix(s: &[u8]) -> Option<(usize, usize)> {
    // Detect r"... | r#"... | b... | br"... | br#"... | c"... | cr"... | cr#"...
    // Returns (prefix_byte_count, hash_count). Match the longest valid prefix.
    let mut i = 0;
    let mut hash_count = 0;
    let mut start_chars = String::new();

    // Optional b or c prefix
    let with_b = s.get(0).copied() == Some(b'b');
    let with_c = s.get(0).copied() == Some(b'c');
    if with_b {
        start_chars.push('b');
        i += 1;
    } else if with_c {
        start_chars.push('c');
        i += 1;
    }
    if s.get(i).copied() != Some(b'r') {
        return None;
    }
    i += 1;
    while s.get(i).copied() == Some(b'#') {
        hash_count += 1;
        i += 1;
    }
    if s.get(i).copied() != Some(b'"') {
        return None;
    }
    i += 1; // consume opening "
    Some((i, hash_count))
}

// =============================================================================
// AC-17 — Post-recall access update (T17 / T17b / T17c)
// =============================================================================

#[tokio::test(flavor = "current_thread")]
async fn t17_post_recall_increments_access_count_and_sets_last_accessed() {
    let h = handle();
    seed_content(
        &h,
        "c1",
        "agent1",
        "f.md",
        "apple cake",
        &one_hot(0),
        5,
        fixed_ts(1_700_000_000),
    )
    .expect("seed");

    let h_for_read = h.clone();
    let recall = impl_for(h);
    let results = recall
        .recall("agent1", "apple", &one_hot(0), 10)
        .await
        .expect("recall");

    // Returned access_count should be post-update value (= 6).
    let r = results.iter().find(|r| r.id == "c1").unwrap();
    assert_eq!(r.access_count, 6);
    assert!(r.last_accessed.is_some());

    // Persisted row reflects the same.
    let (count, ts) = read_content_access(&h_for_read, "c1").expect("read");
    assert_eq!(count, 6);
    assert!(ts.is_some());
}

#[tokio::test(flavor = "current_thread")]
async fn t17b_successive_recalls_each_increment() {
    let h = handle();
    seed_content(
        &h,
        "c1",
        "agent1",
        "f.md",
        "apple cake",
        &one_hot(0),
        5,
        fixed_ts(1_700_000_000),
    )
    .expect("seed");

    let h_for_read = h.clone();
    let recall = impl_for(h);
    let _ = recall
        .recall("agent1", "apple", &one_hot(0), 10)
        .await
        .expect("recall1");
    let (count1, ts1) = read_content_access(&h_for_read, "c1").expect("read1");
    let _ = recall
        .recall("agent1", "apple", &one_hot(0), 10)
        .await
        .expect("recall2");
    let (count2, ts2) = read_content_access(&h_for_read, "c1").expect("read2");

    assert_eq!(count1, 6);
    assert_eq!(count2, 7);
    assert!(ts1.is_some() && ts2.is_some());
    assert!(
        ts2.unwrap() >= ts1.unwrap(),
        "ts2 {} should be >= ts1 {}",
        ts2.unwrap(),
        ts1.unwrap()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn t17c_memory_row_access_update() {
    let h = handle();
    seed_memory(
        &h,
        "m1",
        "agent1",
        "remember apple",
        &one_hot(0),
        Some("active"),
        3,
    )
    .expect("seed");

    let h_for_read = h.clone();
    let recall = impl_for(h);
    let results = recall
        .recall("agent1", "apple", &one_hot(0), 10)
        .await
        .expect("recall");
    assert!(results.iter().any(|r| r.id == "m1"));

    let (count, ts) = read_memory_access(&h_for_read, "m1").expect("read");
    assert_eq!(count, 4);
    assert!(ts.is_some());
}

// =============================================================================
// orthogonal control — query with no hits returns empty (no panic, no UPDATE error)
// =============================================================================

#[tokio::test(flavor = "current_thread")]
async fn empty_corpus_returns_empty() {
    let h = handle();
    let recall = impl_for(h);
    let results = recall
        .recall("agent1", "anything", &one_hot(0), 10)
        .await
        .expect("recall");
    assert!(results.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn zero_query_embedding_now_rejected() {
    // Round-10 finding W11 fix: zero-magnitude embeddings produce undefined
    // cosine semantics. Slice C now fails closed at validation.
    let h = handle();
    let recall = impl_for(h);
    let r = recall.recall("agent1", "apple", &zero_emb(), 10).await;
    assert!(matches!(r, Err(DbError::InvalidConfig(_))));
}

#[tokio::test(flavor = "current_thread")]
async fn empty_agent_id_rejected() {
    // Round-10 finding W3 fix: agent_id non-empty validation now enforced.
    let h = handle();
    let recall = impl_for(h);
    let r = recall.recall("", "apple", &one_hot(0), 10).await;
    assert!(matches!(r, Err(DbError::InvalidConfig(_))));
    let r = recall.recall("   ", "apple", &one_hot(0), 10).await;
    assert!(matches!(r, Err(DbError::InvalidConfig(_))));
}

#[tokio::test(flavor = "current_thread")]
async fn oversized_query_rejected() {
    // Round-15 (adversarial Info finding) defense-in-depth: query.len() >
    // MAX_QUERY_BYTES (4096) is rejected before extract_keywords scans it.
    let h = handle();
    let recall = impl_for(h);
    let big = "a".repeat(8192);
    let r = recall.recall("agent1", &big, &one_hot(0), 10).await;
    assert!(matches!(r, Err(DbError::InvalidConfig(_))));
}

// =============================================================================
// AC-04 — recall_blocking handles NULL last_modified + NULL access_count rows
// =============================================================================
//
// Round-10 finding W6 + W10 fix: schema permits NULL on these columns; recall
// must not abort on legal NULLs. The post-recall UPDATE uses COALESCE so NULL
// access_count is treated as 0 before incrementing.

#[tokio::test(flavor = "current_thread")]
async fn null_last_modified_does_not_crash_recall() {
    let h = handle();
    // Insert a content row directly with NULL last_modified — bypasses the
    // common::seed_content helper to exercise the NULL fallback path.
    {
        let mut conn = h.get_conn().expect("conn");
        let tx = conn.transaction().expect("tx");
        tx.execute(
            "INSERT INTO content_index(id, agent_id, file_path, content_preview, access_count, \
             last_accessed, last_modified, updated_at) \
             VALUES ('c1','agent1','f.md','apple',5,NULL,NULL,'2026-01-01T00:00:00.000Z')",
            [],
        )
        .expect("insert content_index");
        let rowid = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO content_fts(rowid, file_path, content_preview, tags) VALUES (?1,'f.md','apple','')",
            [rowid],
        ).expect("insert content_fts");
        let blob = common::embedding_to_blob(&one_hot(0));
        tx.execute(
            "INSERT INTO content_vec(rowid, embedding) VALUES (?1, ?2)",
            rusqlite::params![rowid, blob],
        )
        .expect("insert content_vec");
        tx.commit().expect("commit");
    }

    let h_for_read = h.clone();
    let recall = impl_for(h);
    let results = recall
        .recall("agent1", "apple", &one_hot(0), 10)
        .await
        .expect("recall");
    assert!(results.iter().any(|r| r.id == "c1"));

    // Post-recall access_count was NULL, COALESCE(NULL, 0) + 1 == 1.
    let (count, ts) = read_content_access(&h_for_read, "c1").expect("read");
    // Pre-row had access_count=5 (literal), so post = 6. NULL test runs separately below.
    assert_eq!(count, 6);
    assert!(ts.is_some());
}

#[tokio::test(flavor = "current_thread")]
async fn null_access_count_promotes_to_one_via_coalesce() {
    let h = handle();
    // NULL access_count + recall → COALESCE(NULL, 0) + 1 = 1 (NOT NULL).
    {
        let mut conn = h.get_conn().expect("conn");
        let tx = conn.transaction().expect("tx");
        tx.execute(
            "INSERT INTO content_index(id, agent_id, file_path, content_preview, access_count, \
             last_accessed, last_modified, updated_at) \
             VALUES ('c2','agent1','g.md','banana',NULL,NULL,'2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z')",
            [],
        ).expect("insert content_index");
        let rowid = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO content_fts(rowid, file_path, content_preview, tags) VALUES (?1,'g.md','banana','')",
            [rowid],
        ).expect("insert content_fts");
        let blob = common::embedding_to_blob(&one_hot(0));
        tx.execute(
            "INSERT INTO content_vec(rowid, embedding) VALUES (?1, ?2)",
            rusqlite::params![rowid, blob],
        )
        .expect("insert content_vec");
        tx.commit().expect("commit");
    }

    let h_for_read = h.clone();
    let recall = impl_for(h);
    let _ = recall
        .recall("agent1", "banana", &one_hot(0), 10)
        .await
        .expect("recall");

    let (count, ts) = read_content_access(&h_for_read, "c2").expect("read");
    assert_eq!(
        count, 1,
        "COALESCE(NULL, 0) + 1 must produce 1 (was: NULL stays NULL bug)"
    );
    assert!(ts.is_some());
}

// =============================================================================
// CONTRACT-032 UnifiedSearch — fan-out smoke test (round-10 finding W9)
// =============================================================================

#[tokio::test(flavor = "current_thread")]
async fn unified_search_fans_out_over_all_surfaces() {
    let h = handle();
    let q = one_hot(0);
    let now = fixed_ts(1_700_000_000);

    seed_content(&h, "c1", "agent1", "doc.md", "apple cake", &q, 0, now).expect("seed c");
    seed_memory(&h, "m1", "agent1", "remember apple", &q, None, 0).expect("seed m");
    seed_task(&h, "t1", "agent1", "apple task title", &q, Some(now)).expect("seed t");
    seed_turn(&h, "tr1", "agent1", "t1", 1, "apple digest", &q, now).expect("seed tr");

    let unified = R2d2UnifiedSearchImpl::new(h.clone(), 10);
    let result = unified.search("agent1", "apple", &q).await.expect("search");

    assert_eq!(
        result.contents.len(),
        1,
        "exactly 1 content hit; got {:?}",
        result.contents.iter().map(|h| &h.id).collect::<Vec<_>>()
    );
    assert_eq!(result.memories.len(), 1, "exactly 1 memory hit");
    assert_eq!(result.tasks.len(), 1, "exactly 1 task hit");
    assert_eq!(result.turns.len(), 1, "exactly 1 turn hit");

    assert_eq!(result.contents[0].id, "c1");
    assert_eq!(result.memories[0].id, "m1");
    assert_eq!(result.memories[0].content, "remember apple");
    assert_eq!(result.tasks[0].task_id, "t1");
    assert_eq!(result.turns[0].id, "tr1");
}

#[tokio::test(flavor = "current_thread")]
async fn limit_zero_returns_empty_no_mutation() {
    // Round-11 finding (Codex W1): limit == 0 must return empty Vec
    // without mutating access stats. Prior `.max(1)` coercion was a silent
    // contract change.
    let h = handle();
    seed_content(
        &h,
        "c1",
        "agent1",
        "f.md",
        "apple",
        &one_hot(0),
        5,
        fixed_ts(1_700_000_000),
    )
    .expect("seed");
    let h_for_read = h.clone();
    let recall = impl_for(h);
    let results = recall
        .recall("agent1", "apple", &one_hot(0), 0)
        .await
        .expect("recall");
    assert!(results.is_empty(), "limit=0 must return empty");
    let (count, _) = read_content_access(&h_for_read, "c1").expect("read");
    assert_eq!(count, 5, "access_count must NOT have been incremented");
}

#[tokio::test(flavor = "current_thread")]
async fn memory_recall_filters_superseded_and_forgotten() {
    // Round-11 finding C1 (Codex Diff): memory_index.is_active filter required
    // by PRD §11.3.2. Status superseded / forgotten must NOT be returned.
    let h = handle();
    let q = one_hot(0);
    seed_memory(
        &h,
        "m_active",
        "agent1",
        "active fact",
        &q,
        Some("active"),
        0,
    )
    .expect("seed active");
    seed_memory(
        &h,
        "m_contested",
        "agent1",
        "contested fact",
        &q,
        Some("contested"),
        0,
    )
    .expect("seed contested");
    seed_memory(
        &h,
        "m_orphaned",
        "agent1",
        "orphaned fact",
        &q,
        Some("orphaned"),
        0,
    )
    .expect("seed orphaned");
    seed_memory(
        &h,
        "m_superseded",
        "agent1",
        "old fact",
        &q,
        Some("superseded"),
        0,
    )
    .expect("seed superseded");
    seed_memory(
        &h,
        "m_forgotten",
        "agent1",
        "lost fact",
        &q,
        Some("forgotten"),
        0,
    )
    .expect("seed forgotten");

    let recall = impl_for(h);
    let results = recall
        .recall("agent1", "fact", &q, 100)
        .await
        .expect("recall");
    let ids: std::collections::HashSet<&str> = results.iter().map(|r| r.id.as_str()).collect();

    assert!(ids.contains("m_active"), "active rows must be recalled");
    assert!(
        ids.contains("m_contested"),
        "contested rows must be recalled"
    );
    assert!(ids.contains("m_orphaned"), "orphaned rows must be recalled");
    assert!(
        !ids.contains("m_superseded"),
        "superseded rows must be filtered"
    );
    assert!(
        !ids.contains("m_forgotten"),
        "forgotten rows must be filtered"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn memory_recall_filters_inactive_via_is_active_flag() {
    let h = handle();
    let q = one_hot(0);
    // Seed an explicitly is_active=0 memory row by direct SQL.
    {
        let mut conn = h.get_conn().expect("conn");
        let tx = conn.transaction().expect("tx");
        tx.execute(
            "INSERT INTO memory_index(id, agent_id, type, content, tags, embedding, created_at, \
             task_origin, superseded_by, is_active, status, supersession_reason, sources, \
             access_count, last_accessed) \
             VALUES ('m_inactive','agent1','fact','inactive fact',NULL,NULL,'2026-01-01T00:00:00.000Z',\
                     NULL,NULL,0,'active',NULL,NULL,0,NULL)",
            [],
        ).expect("insert memory_index");
        let rowid = tx.last_insert_rowid();
        let blob = common::embedding_to_blob(&q);
        tx.execute(
            "INSERT INTO memory_vec(rowid, embedding) VALUES (?1, ?2)",
            rusqlite::params![rowid, blob],
        )
        .expect("insert memory_vec");
        tx.commit().expect("commit");
    }
    seed_memory(
        &h,
        "m_active",
        "agent1",
        "active fact",
        &q,
        Some("active"),
        0,
    )
    .expect("seed active");

    let recall = impl_for(h);
    let results = recall
        .recall("agent1", "fact", &q, 100)
        .await
        .expect("recall");
    let ids: std::collections::HashSet<&str> = results.iter().map(|r| r.id.as_str()).collect();
    assert!(ids.contains("m_active"));
    assert!(
        !ids.contains("m_inactive"),
        "is_active=0 rows must be filtered"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn unified_search_limit_zero_returns_empty() {
    let h = handle();
    let unified = R2d2UnifiedSearchImpl::new(h, 0);
    let result = unified
        .search("agent1", "q", &one_hot(0))
        .await
        .expect("search");
    assert!(result.contents.is_empty());
    assert!(result.memories.is_empty());
    assert!(result.tasks.is_empty());
    assert!(result.turns.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn unified_search_validates_inputs() {
    let h = handle();
    let unified = R2d2UnifiedSearchImpl::new(h, 10);
    let r = unified.search("", "q", &one_hot(0)).await;
    assert!(matches!(r, Err(DbError::InvalidConfig(_))));
    let r = unified.search("agent1", "q", &[]).await;
    assert!(matches!(r, Err(DbError::InvalidConfig(_))));
    let r = unified.search("agent1", "q", &zero_emb()).await;
    assert!(matches!(r, Err(DbError::InvalidConfig(_))));
}

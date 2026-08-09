//! Crate tests for the dep-light data-port real implementations
//! (`vector_search`): `cosine_similarity`, `RankingUnifiedSearch`,
//! `CosineVectorIndex`, `CosineTaskIndex`. Proves REAL ranked content directly
//! AND through the existing `UnifiedSearchCoordinator` / `TaskRouter` surfaces.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use advance_context_engine::{
    cosine_similarity, AgentSearchCorpus, CosineTaskIndex, CosineVectorIndex, EmbeddingPort,
    IndexedTask, IndexedTurn, IndexedVector, LightLlmFallbackPort, PortError, RankingUnifiedSearch,
    TaskIndexPort, TaskRouter, TaskRoutingDecision, UnifiedSearchCoordinator, UnifiedSearchPort,
    UnifiedSearchResult, VectorIndexReader,
};
use async_trait::async_trait;

// ─── cosine_similarity (Unit) ───

#[test]
fn cosine_identical_is_one() {
    let v = vec![1.0, 2.0, 3.0];
    let c = cosine_similarity(&v, &v).unwrap();
    assert!((c - 1.0).abs() < 1e-6, "identical → 1.0, got {c}");
}

#[test]
fn cosine_orthogonal_is_zero() {
    let c = cosine_similarity(&[1.0, 0.0], &[0.0, 1.0]).unwrap();
    assert!(c.abs() < 1e-6, "orthogonal → 0.0, got {c}");
}

#[test]
fn cosine_opposite_is_neg_one() {
    let c = cosine_similarity(&[1.0, 0.0], &[-1.0, 0.0]).unwrap();
    assert!((c + 1.0).abs() < 1e-6, "opposite → -1.0, got {c}");
}

#[test]
fn cosine_dim_mismatch_is_none() {
    assert_eq!(cosine_similarity(&[1.0, 2.0], &[1.0]), None);
}

#[test]
fn cosine_zero_norm_is_none() {
    assert_eq!(cosine_similarity(&[0.0, 0.0], &[1.0, 2.0]), None);
    assert_eq!(cosine_similarity(&[1.0, 2.0], &[0.0, 0.0]), None);
}

#[test]
fn cosine_non_finite_is_none() {
    assert_eq!(cosine_similarity(&[f32::NAN, 1.0], &[1.0, 2.0]), None);
    assert_eq!(cosine_similarity(&[f32::INFINITY, 1.0], &[1.0, 2.0]), None);
    assert_eq!(
        cosine_similarity(&[1.0, 1.0], &[f32::NEG_INFINITY, 2.0]),
        None
    );
    let empty: &[f32] = &[];
    assert_eq!(cosine_similarity(empty, empty), None);
}

// ─── RankingUnifiedSearch (Integration) ───

fn corpus_one_agent() -> RankingUnifiedSearch {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
    let mut m = HashMap::new();
    m.insert(
        "agent-1".to_string(),
        AgentSearchCorpus {
            tasks: vec![
                IndexedTask {
                    task_id: "task-a".into(),
                    embedding: vec![1.0, 0.0],
                    last_turn_at: Some(now),
                },
                IndexedTask {
                    task_id: "task-b".into(),
                    embedding: vec![0.0, 1.0],
                    last_turn_at: None,
                },
            ],
            turns: vec![
                IndexedTurn {
                    id: "turn-1".into(),
                    task_id: "task-a".into(),
                    embedding: vec![1.0, 0.0],
                    timestamp: now,
                },
                IndexedTurn {
                    id: "turn-2".into(),
                    task_id: "task-b".into(),
                    embedding: vec![0.0, 1.0],
                    timestamp: now,
                },
            ],
            contents: vec![IndexedVector {
                id: "c1".into(),
                embedding: vec![1.0, 0.0],
            }],
            memories: vec![IndexedVector {
                id: "m1".into(),
                embedding: vec![1.0, 0.0],
            }],
        },
    );
    RankingUnifiedSearch::new(m)
}

#[tokio::test]
async fn unified_search_ranks_and_source_separates() {
    let s = corpus_one_agent();
    let r = s.search("agent-1", "q", &[1.0, 0.0]).await.unwrap();
    // Source separation: all 4 kinds populated.
    assert_eq!(r.tasks.len(), 2);
    assert_eq!(r.turns.len(), 2);
    assert_eq!(r.contents.len(), 1);
    assert_eq!(r.memories.len(), 1);
    // Ranking: the [1,0]-aligned task ranks above the orthogonal one.
    assert_eq!(r.tasks[0].task_id, "task-a");
    assert!(r.tasks[0].similarity > r.tasks[1].similarity);
    assert_eq!(r.turns[0].id, "turn-1");
    assert_eq!(r.contents[0].id, "c1");
    assert_eq!(r.memories[0].id, "m1");
}

#[tokio::test]
async fn unified_search_unknown_agent_is_empty() {
    let s = corpus_one_agent();
    let r = s.search("nope", "q", &[1.0, 0.0]).await.unwrap();
    assert_eq!(r, UnifiedSearchResult::default());
}

#[tokio::test]
async fn unified_search_skips_non_finite_and_mismatched_items() {
    // Poisoned rows in ALL FOUR kinds — the identical filter_map(cosine ..)
    // skip path must drop them everywhere, leaving only the clean row per kind.
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
    let mut m = HashMap::new();
    m.insert(
        "agent-1".to_string(),
        AgentSearchCorpus {
            tasks: vec![
                IndexedTask {
                    task_id: "task-good".into(),
                    embedding: vec![1.0, 0.0],
                    last_turn_at: None,
                },
                IndexedTask {
                    task_id: "task-nan".into(),
                    embedding: vec![f32::NAN, 0.0],
                    last_turn_at: None,
                },
                IndexedTask {
                    task_id: "task-mismatch".into(),
                    embedding: vec![1.0, 0.0, 0.0],
                    last_turn_at: None,
                },
            ],
            turns: vec![
                IndexedTurn {
                    id: "turn-good".into(),
                    task_id: "x".into(),
                    embedding: vec![1.0, 0.0],
                    timestamp: now,
                },
                IndexedTurn {
                    id: "turn-inf".into(),
                    task_id: "x".into(),
                    embedding: vec![f32::INFINITY, 0.0],
                    timestamp: now,
                },
            ],
            contents: vec![
                IndexedVector {
                    id: "good".into(),
                    embedding: vec![1.0, 0.0],
                },
                IndexedVector {
                    id: "naninf".into(),
                    embedding: vec![f32::NAN, 0.0],
                },
                IndexedVector {
                    id: "mismatch".into(),
                    embedding: vec![1.0, 0.0, 0.0],
                },
            ],
            memories: vec![
                IndexedVector {
                    id: "mem-good".into(),
                    embedding: vec![1.0, 0.0],
                },
                IndexedVector {
                    id: "mem-zero".into(),
                    embedding: vec![0.0, 0.0], // zero-norm → skipped
                },
            ],
        },
    );
    let s = RankingUnifiedSearch::new(m);
    let r = s.search("agent-1", "q", &[1.0, 0.0]).await.unwrap();
    assert_eq!(r.tasks.len(), 1, "non-finite + dim-mismatch tasks skipped");
    assert_eq!(r.tasks[0].task_id, "task-good");
    assert_eq!(r.turns.len(), 1, "non-finite turns skipped");
    assert_eq!(r.turns[0].id, "turn-good");
    assert_eq!(
        r.contents.len(),
        1,
        "non-finite + dim-mismatch contents skipped"
    );
    assert_eq!(r.contents[0].id, "good");
    assert_eq!(r.memories.len(), 1, "zero-norm memories skipped");
    assert_eq!(r.memories[0].id, "mem-good");
}

#[tokio::test]
async fn unified_search_equal_scores_tie_break_by_id() {
    let mut m = HashMap::new();
    m.insert(
        "agent-1".to_string(),
        AgentSearchCorpus {
            contents: vec![
                IndexedVector {
                    id: "zeta".into(),
                    embedding: vec![1.0, 0.0],
                },
                IndexedVector {
                    id: "alpha".into(),
                    embedding: vec![1.0, 0.0],
                },
            ],
            ..Default::default()
        },
    );
    let s = RankingUnifiedSearch::new(m);
    let r = s.search("agent-1", "q", &[1.0, 0.0]).await.unwrap();
    // Equal cosine → deterministic id-ascending tie-break.
    assert_eq!(r.contents[0].id, "alpha");
    assert_eq!(r.contents[1].id, "zeta");
}

#[tokio::test]
async fn unified_search_is_deterministic() {
    let s = corpus_one_agent();
    let q = vec![0.7, 0.7];
    let r1 = s.search("agent-1", "q", &q).await.unwrap();
    let r2 = s.search("agent-1", "q", &q).await.unwrap();
    assert_eq!(r1, r2, "same input → byte-identical output");
}

#[tokio::test]
async fn unified_search_respects_result_cap() {
    let mut m = HashMap::new();
    let contents: Vec<IndexedVector> = (0..10)
        .map(|i| IndexedVector {
            id: format!("c{i:02}"),
            embedding: vec![1.0, 0.0],
        })
        .collect();
    m.insert(
        "a".to_string(),
        AgentSearchCorpus {
            contents,
            ..Default::default()
        },
    );
    let s = RankingUnifiedSearch::new(m).with_max_results_per_kind(3);
    let r = s.search("a", "q", &[1.0, 0.0]).await.unwrap();
    assert_eq!(r.contents.len(), 3, "per-kind cap respected");
}

// ─── CosineVectorIndex (Unit/Integration) ───

#[tokio::test]
async fn vector_index_ranks_desc_and_caps() {
    let mut m = HashMap::new();
    m.insert(
        "a".to_string(),
        vec![
            IndexedVector {
                id: "near".into(),
                embedding: vec![1.0, 0.0],
            },
            IndexedVector {
                id: "far".into(),
                embedding: vec![0.0, 1.0],
            },
            IndexedVector {
                id: "mid".into(),
                embedding: vec![1.0, 1.0],
            },
        ],
    );
    let idx = CosineVectorIndex::new(m).with_max_results(2);
    let hits = idx.lookup("a", &[1.0, 0.0]).await.unwrap();
    assert_eq!(
        hits.len(),
        2,
        "rank-all then truncate at internal cap (no caller n)"
    );
    assert_eq!(hits[0].id, "near"); // cos 1.0
    assert!(hits[0].score >= hits[1].score);
}

#[tokio::test]
async fn vector_index_unknown_agent_empty() {
    let idx = CosineVectorIndex::new(HashMap::new());
    assert!(idx.lookup("nope", &[1.0]).await.unwrap().is_empty());
}

// ─── CosineTaskIndex (Unit) ───

#[tokio::test]
async fn task_index_respects_n_and_orders_desc() {
    let mut m = HashMap::new();
    m.insert(
        "a".to_string(),
        vec![
            IndexedTask {
                task_id: "t-near".into(),
                embedding: vec![1.0, 0.0],
                last_turn_at: None,
            },
            IndexedTask {
                task_id: "t-mid".into(),
                embedding: vec![1.0, 1.0],
                last_turn_at: None,
            },
            IndexedTask {
                task_id: "t-far".into(),
                embedding: vec![0.0, 1.0],
                last_turn_at: None,
            },
        ],
    );
    let idx = CosineTaskIndex::new(m);
    let hits = idx.top_n_by_similarity("a", &[1.0, 0.0], 2).await.unwrap();
    assert_eq!(hits.len(), 2, "honors caller n");
    assert_eq!(hits[0].task_id, "t-near");
    assert!(hits[0].similarity >= hits[1].similarity);
}

#[tokio::test]
async fn task_index_tie_break_some_before_none_newer_first() {
    let early = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let late = SystemTime::UNIX_EPOCH + Duration::from_secs(200);
    let mut m = HashMap::new();
    m.insert(
        "a".to_string(),
        vec![
            IndexedTask {
                task_id: "none".into(),
                embedding: vec![1.0, 0.0],
                last_turn_at: None,
            },
            IndexedTask {
                task_id: "early".into(),
                embedding: vec![1.0, 0.0],
                last_turn_at: Some(early),
            },
            IndexedTask {
                task_id: "late".into(),
                embedding: vec![1.0, 0.0],
                last_turn_at: Some(late),
            },
        ],
    );
    let idx = CosineTaskIndex::new(m);
    let hits = idx.top_n_by_similarity("a", &[1.0, 0.0], 3).await.unwrap();
    // Equal cosine → tie-break: newest Some > older Some > None.
    assert_eq!(hits[0].task_id, "late");
    assert_eq!(hits[1].task_id, "early");
    assert_eq!(hits[2].task_id, "none");
}

// ─── Integration through the existing surfaces ───

struct FixedEmbed(Vec<f32>);
#[async_trait]
impl EmbeddingPort for FixedEmbed {
    async fn embed(&self, _text: &str) -> Result<Vec<f32>, PortError> {
        Ok(self.0.clone())
    }
}

/// A light-LLM double that must NEVER be reached in the unambiguous routing
/// tests (returns an error so a stray call fails the test loudly).
struct UnreachableLlm;
#[async_trait]
impl LightLlmFallbackPort for UnreachableLlm {
    async fn pick_one(&self, _query: &str, _candidates: &[String]) -> Result<String, PortError> {
        Err(PortError(
            "light-llm tie-break should not be reached".into(),
        ))
    }
}

#[tokio::test]
async fn coordinator_returns_real_hits_and_drops_current_task_turns() {
    let s = corpus_one_agent(); // turns: turn-1 (task-a), turn-2 (task-b)
    let coord = UnifiedSearchCoordinator::new(Arc::new(FixedEmbed(vec![1.0, 0.0])), Arc::new(s));
    // current_task = task-a → the coordinator drops turn-1 (same task), keeps turn-2.
    let r = coord
        .unified_search("agent-1", "query", Some("task-a"))
        .await
        .unwrap();
    assert!(
        r.turns.iter().all(|t| t.task_id != "task-a"),
        "coordinator drops current-task turns"
    );
    assert!(r.turns.iter().any(|t| t.id == "turn-2"));
    assert!(!r.tasks.is_empty(), "real ranked task hits flow through");
}

#[tokio::test]
async fn task_router_routes_existing_for_matching_query() {
    // Orthonormal basis so cosines are exact: query [1,0,0] matches task-x at
    // cos 1.0 and task-y at cos 0.0 → top1−top2 = 1.0 ≥ AMBIGUITY_GAP (0.1),
    // so the unambiguous branch fires (light-LLM never reached).
    let early = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let mut m = HashMap::new();
    m.insert(
        "agent-1".to_string(),
        vec![
            IndexedTask {
                task_id: "task-x".into(),
                embedding: vec![1.0, 0.0, 0.0],
                last_turn_at: Some(early),
            },
            IndexedTask {
                task_id: "task-y".into(),
                embedding: vec![0.0, 1.0, 0.0],
                last_turn_at: None,
            },
        ],
    );
    let router = TaskRouter::new(
        Arc::new(FixedEmbed(vec![1.0, 0.0, 0.0])),
        Arc::new(CosineTaskIndex::new(m)),
        Arc::new(UnreachableLlm),
    );
    let decision = router.route_task("agent-1", "match x").await.unwrap();
    assert_eq!(
        decision,
        TaskRoutingDecision::Existing("task-x".to_string())
    );
}

#[tokio::test]
async fn task_router_routes_new_for_non_matching_query() {
    // Query orthogonal to the only task → cos 0.0 < TASK_MATCH_THRESHOLD (0.5).
    let mut m = HashMap::new();
    m.insert(
        "agent-1".to_string(),
        vec![IndexedTask {
            task_id: "task-x".into(),
            embedding: vec![1.0, 0.0, 0.0],
            last_turn_at: None,
        }],
    );
    let router = TaskRouter::new(
        Arc::new(FixedEmbed(vec![0.0, 0.0, 1.0])),
        Arc::new(CosineTaskIndex::new(m)),
        Arc::new(UnreachableLlm),
    );
    let decision = router.route_task("agent-1", "no match").await.unwrap();
    assert_eq!(decision, TaskRoutingDecision::NewTask);
}

// ─── Defense-in-depth / determinism hardening (test-coverage closure) ───

#[test]
fn cosine_finite_inputs_overflowing_norm_is_none() {
    // Large-but-finite components: each passes the per-component is_finite gate,
    // but the squared-norm / dot accumulation overflows f32 to +inf → the
    // post-accumulation finite guard rejects it (no NaN escapes into ranking).
    let big = vec![f32::MAX, f32::MAX];
    assert_eq!(cosine_similarity(&big, &big), None);
}

#[tokio::test]
async fn unified_search_tasks_tie_break_some_before_none_newer_first() {
    // Equal cosine across all three tasks → the RankingUnifiedSearch.tasks sort
    // path's own time_key tie-break must order: newest Some > older Some > None.
    let early = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let late = SystemTime::UNIX_EPOCH + Duration::from_secs(200);
    let mut m = HashMap::new();
    m.insert(
        "a".to_string(),
        AgentSearchCorpus {
            tasks: vec![
                IndexedTask {
                    task_id: "none".into(),
                    embedding: vec![1.0, 0.0],
                    last_turn_at: None,
                },
                IndexedTask {
                    task_id: "early".into(),
                    embedding: vec![1.0, 0.0],
                    last_turn_at: Some(early),
                },
                IndexedTask {
                    task_id: "late".into(),
                    embedding: vec![1.0, 0.0],
                    last_turn_at: Some(late),
                },
            ],
            ..Default::default()
        },
    );
    let s = RankingUnifiedSearch::new(m);
    let r = s.search("a", "q", &[1.0, 0.0]).await.unwrap();
    let order: Vec<String> = r.tasks.iter().map(|t| t.task_id.clone()).collect();
    assert_eq!(order, vec!["late", "early", "none"]);
}

#[tokio::test]
async fn unified_search_default_cap_bounds_results() {
    // No with_max_results* override → the DEFAULT_MAX_RESULTS cap bounds a
    // pathological corpus (300 > 256).
    let contents: Vec<IndexedVector> = (0..300)
        .map(|i| IndexedVector {
            id: format!("c{i:03}"),
            embedding: vec![1.0, 0.0],
        })
        .collect();
    let mut m = HashMap::new();
    m.insert(
        "a".to_string(),
        AgentSearchCorpus {
            contents,
            ..Default::default()
        },
    );
    let s = RankingUnifiedSearch::new(m);
    let r = s.search("a", "q", &[1.0, 0.0]).await.unwrap();
    assert_eq!(
        r.contents.len(),
        advance_context_engine::DEFAULT_MAX_RESULTS
    );
}

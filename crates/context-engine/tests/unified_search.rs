//! AC-02 — unified_search coordinator (T02: source separation +
//! §1.3.1 cross-task turn filter + EmbeddingFailed mapping).

use std::sync::Arc;
use std::time::SystemTime;

use advance_context_engine::{
    ContentHit, EmbeddingPort, MemoryHit, PortError, TaskHit, TurnHit, UnifiedSearchCoordinator,
    UnifiedSearchPort, UnifiedSearchResult,
};
use advance_shared_types::context::AssemblyError;
use async_trait::async_trait;

struct Embed(Result<Vec<f32>, PortError>);
#[async_trait]
impl EmbeddingPort for Embed {
    async fn embed(&self, _t: &str) -> Result<Vec<f32>, PortError> {
        self.0.clone()
    }
}

/// Returns 1 task + 1 SAME-task turn + 1 CROSS-task turn + 1 content +
/// 1 memory. The coordinator must drop the same-task turn.
struct Search;
#[async_trait]
impl UnifiedSearchPort for Search {
    async fn search(
        &self,
        _a: &str,
        _q: &str,
        _e: &[f32],
    ) -> Result<UnifiedSearchResult, PortError> {
        Ok(UnifiedSearchResult {
            tasks: vec![TaskHit {
                task_id: "task-1".into(),
                similarity: 0.8,
                last_turn_at: Some(SystemTime::UNIX_EPOCH),
            }],
            turns: vec![
                TurnHit {
                    id: "turn-same".into(),
                    task_id: "task-current".into(),
                    similarity: 0.7,
                    timestamp: SystemTime::UNIX_EPOCH,
                },
                TurnHit {
                    id: "turn-cross".into(),
                    task_id: "task-other".into(),
                    similarity: 0.6,
                    timestamp: SystemTime::UNIX_EPOCH,
                },
            ],
            contents: vec![ContentHit {
                id: "content-1".into(),
                adjusted_score: 0.5,
            }],
            memories: vec![MemoryHit {
                id: "memory-1".into(),
                adjusted_score: 0.4,
            }],
        })
    }
}

/// T02 — all 4 source lists populated + typed-separate; the same-task turn
/// is dropped (§1.3.1 cross-task invariant), the cross-task turn survives.
#[tokio::test]
async fn t02_source_separation_and_cross_task_filter() {
    let coord =
        UnifiedSearchCoordinator::new(Arc::new(Embed(Ok(vec![0.1, 0.2]))), Arc::new(Search));
    let r = coord
        .unified_search("agent-1", "q", Some("task-current"))
        .await
        .expect("search ok");

    assert_eq!(r.tasks.len(), 1, "task source populated");
    assert_eq!(r.contents.len(), 1, "content source populated");
    assert_eq!(r.memories.len(), 1, "memory source populated");
    assert_eq!(r.turns.len(), 1, "same-task turn dropped, cross-task kept");
    assert_eq!(r.turns[0].id, "turn-cross");
    assert_eq!(r.turns[0].task_id, "task-other");
    // typed-separate: each list carries its own hit type (compile-time
    // guaranteed by the struct; assert the ids did not cross-contaminate).
    assert_eq!(r.tasks[0].task_id, "task-1");
    assert_eq!(r.contents[0].id, "content-1");
    assert_eq!(r.memories[0].id, "memory-1");
}

/// With no current task, NO turn is dropped — assert by id (not just count)
/// so the test witnesses the filter genuinely did not fire.
#[tokio::test]
async fn no_current_task_keeps_all_turns() {
    let coord = UnifiedSearchCoordinator::new(Arc::new(Embed(Ok(vec![0.1]))), Arc::new(Search));
    let r = coord.unified_search("agent-1", "q", None).await.unwrap();
    assert_eq!(r.turns.len(), 2, "no current task → no cross-task drop");
    let ids: Vec<&str> = r.turns.iter().map(|t| t.id.as_str()).collect();
    assert!(
        ids.contains(&"turn-same"),
        "turn-same retained when no current task"
    );
    assert!(
        ids.contains(&"turn-cross"),
        "turn-cross retained when no current task"
    );
}

/// Embed failure maps to `AssemblyError::EmbeddingFailed` (§2.8 contract).
#[tokio::test]
async fn embed_failure_maps_to_embedding_failed() {
    let coord = UnifiedSearchCoordinator::new(
        Arc::new(Embed(Err(PortError("gateway down".into())))),
        Arc::new(Search),
    );
    match coord.unified_search("agent-1", "q", None).await {
        Err(AssemblyError::EmbeddingFailed(_)) => {}
        other => panic!("expected EmbeddingFailed, got {other:?}"),
    }
}

/// Round-10 Warning 3 regression lock: an invalid `agent_id` passed to the
/// pub coordinator is rejected with the INPUT_VALIDATION-prefixed
/// `MemoryStoreFailure` payload (defensive whitelist guard at the pub fn).
#[tokio::test]
async fn invalid_agent_id_rejected_with_input_validation_prefix() {
    use advance_context_engine::INPUT_VALIDATION_PREFIX;
    let coord = UnifiedSearchCoordinator::new(Arc::new(Embed(Ok(vec![0.1]))), Arc::new(Search));
    for bad in &["../etc", ";DROP", "with space", "\u{0000}NUL", ""] {
        match coord.unified_search(bad, "q", None).await {
            Err(AssemblyError::MemoryStoreFailure(msg)) => {
                assert!(
                    msg.starts_with(INPUT_VALIDATION_PREFIX),
                    "expected INPUT_VALIDATION-prefixed payload, got {msg:?} for bad={bad:?}"
                );
            }
            other => panic!("expected MemoryStoreFailure for bad={bad:?}, got {other:?}"),
        }
    }
}

/// A non-finite query embedding also maps to `EmbeddingFailed` (same
/// finite-value discipline as TaskRouter).
#[tokio::test]
async fn non_finite_embedding_maps_to_embedding_failed() {
    let coord = UnifiedSearchCoordinator::new(
        Arc::new(Embed(Ok(vec![1.0, f32::INFINITY]))),
        Arc::new(Search),
    );
    match coord.unified_search("agent-1", "q", None).await {
        Err(AssemblyError::EmbeddingFailed(_)) => {}
        other => panic!("expected EmbeddingFailed, got {other:?}"),
    }
}

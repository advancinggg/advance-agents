//! AC-03 / AC-04 — TaskRouter (T03 semantic / T04 auto-exclude /
//! T05 last_turn_at tie-break / T05b LLM-fallback / T-router-embedfail).

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use advance_context_engine::{
    ContextError, EmbeddingPort, LightLlmFallbackPort, PortError, TaskHit, TaskIndexPort,
    TaskRouter, TaskRoutingDecision,
};
use async_trait::async_trait;

// ─── Configurable mocks ───

struct Embed(Result<Vec<f32>, PortError>);
#[async_trait]
impl EmbeddingPort for Embed {
    async fn embed(&self, _t: &str) -> Result<Vec<f32>, PortError> {
        self.0.clone()
    }
}

struct Index(Vec<TaskHit>);
#[async_trait]
impl TaskIndexPort for Index {
    async fn top_n_by_similarity(
        &self,
        _a: &str,
        _q: &[f32],
        _n: usize,
    ) -> Result<Vec<TaskHit>, PortError> {
        Ok(self.0.clone())
    }
}

struct Llm(String);
#[async_trait]
impl LightLlmFallbackPort for Llm {
    async fn pick_one(&self, _q: &str, _c: &[String]) -> Result<String, PortError> {
        Ok(self.0.clone())
    }
}

struct LlmUnreachable;
#[async_trait]
impl LightLlmFallbackPort for LlmUnreachable {
    async fn pick_one(&self, _q: &str, _c: &[String]) -> Result<String, PortError> {
        panic!("light-LLM fallback must NOT be called in this scenario");
    }
}

fn hit(id: &str, sim: f32, lta: Option<SystemTime>) -> TaskHit {
    TaskHit {
        task_id: id.into(),
        similarity: sim,
        last_turn_at: lta,
    }
}

fn router(
    embed: impl EmbeddingPort + 'static,
    index: impl TaskIndexPort + 'static,
    llm: impl LightLlmFallbackPort + 'static,
) -> TaskRouter {
    TaskRouter::new(Arc::new(embed), Arc::new(index), Arc::new(llm))
}

const Q_EMB: [f32; 3] = [0.1, 0.2, 0.3];

/// T03 — semantic similarity routing (NOT adjusted_score): a clear top hit
/// well above threshold routes to it.
#[tokio::test]
async fn t03_routes_to_top_semantic_hit() {
    let r = router(
        Embed(Ok(Q_EMB.to_vec())),
        Index(vec![hit("task-a", 0.9, None), hit("task-b", 0.3, None)]),
        LlmUnreachable,
    );
    let d = r.route_task("agent-1", "do the thing").await.unwrap();
    assert_eq!(d, TaskRoutingDecision::Existing("task-a".into()));
}

/// T04 — the `auto:` namespace is excluded even when it is the top hit.
#[tokio::test]
async fn t04_excludes_auto_namespace() {
    let r = router(
        Embed(Ok(Q_EMB.to_vec())),
        Index(vec![
            hit("auto:tmp-123", 0.9, None),
            hit("task-real", 0.6, None),
        ]),
        LlmUnreachable,
    );
    let d = r.route_task("agent-1", "q").await.unwrap();
    assert_eq!(d, TaskRoutingDecision::Existing("task-real".into()));
}

/// T05 — ambiguity (gap < 0.1) tie-broken by `last_turn_at`; newer wins;
/// `Some` precedes `None`; light-LLM NOT called.
#[tokio::test]
async fn t05_tie_break_by_last_turn_at_newer_wins() {
    let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
    let new = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let r = router(
        Embed(Ok(Q_EMB.to_vec())),
        Index(vec![
            hit("task-old", 0.85, Some(old)),
            hit("task-new", 0.86, Some(new)),
        ]),
        LlmUnreachable,
    );
    let d = r.route_task("agent-1", "q").await.unwrap();
    assert_eq!(d, TaskRoutingDecision::Existing("task-new".into()));
}

/// T05 corollary — `Some` precedes `None`: a candidate WITH a timestamp beats
/// an equally-similar candidate with `None`, even though both are in the
/// ambiguity window.
#[tokio::test]
async fn t05_some_precedes_none() {
    let t = SystemTime::UNIX_EPOCH + Duration::from_secs(500);
    let r = router(
        Embed(Ok(Q_EMB.to_vec())),
        Index(vec![
            hit("task-none", 0.86, None),
            hit("task-some", 0.86, Some(t)),
        ]),
        LlmUnreachable,
    );
    let d = r.route_task("agent-1", "q").await.unwrap();
    assert_eq!(d, TaskRoutingDecision::Existing("task-some".into()));
}

/// T05b — residual tie (identical `last_turn_at`) → light-LLM fallback
/// actually fires and its chosen id is returned.
#[tokio::test]
async fn t05b_residual_tie_invokes_llm_fallback() {
    let same = SystemTime::UNIX_EPOCH + Duration::from_secs(42);
    let r = router(
        Embed(Ok(Q_EMB.to_vec())),
        Index(vec![
            hit("task-x", 0.86, Some(same)),
            hit("task-y", 0.86, Some(same)),
        ]),
        Llm("task-y".into()),
    );
    let d = r.route_task("agent-1", "q").await.unwrap();
    assert_eq!(d, TaskRoutingDecision::Existing("task-y".into()));
}

/// The ONLY legitimate NewTask path: no confident match (all below
/// threshold) — NOT an error mask.
#[tokio::test]
async fn no_confident_match_is_new_task() {
    let r = router(
        Embed(Ok(Q_EMB.to_vec())),
        Index(vec![hit("task-a", 0.2, None)]),
        LlmUnreachable,
    );
    let d = r.route_task("agent-1", "q").await.unwrap();
    assert_eq!(d, TaskRoutingDecision::NewTask);
}

/// Round-10 Warning 3 regression lock: an invalid `agent_id` passed
/// directly to `route_task` returns `Ok(NewTask)` (safe degraded default —
/// no panic, no propagation of an unvalidated id into the index port).
#[tokio::test]
async fn invalid_agent_id_returns_new_task_safe_default() {
    let r = router(
        Embed(Ok(Q_EMB.to_vec())),
        Index(vec![hit("task-a", 0.9, None)]),
        LlmUnreachable,
    );
    for bad in &["../etc", ";DROP", "with space", "\u{0000}NUL", ""] {
        let d = r
            .route_task(bad, "q")
            .await
            .expect("never panics on bad id");
        assert_eq!(
            d,
            TaskRoutingDecision::NewTask,
            "invalid agent_id must safely degrade to NewTask: bad={bad:?}"
        );
    }
}

/// T-router-embedfail (a) — a hard `embed()` error propagates as
/// `EmbeddingFailed`, NOT `NewTask`.
#[tokio::test]
async fn t_router_embedfail_hard_error() {
    let r = router(
        Embed(Err(PortError("gateway down".into()))),
        Index(vec![hit("task-a", 0.9, None)]),
        LlmUnreachable,
    );
    match r.route_task("agent-1", "q").await {
        Err(ContextError::EmbeddingFailed(_)) => {}
        other => panic!("expected EmbeddingFailed, got {other:?}"),
    }
}

/// T-router-embedfail (b) — a successful embed returning a NaN (or empty)
/// vector is ALSO `EmbeddingFailed`, NOT `NewTask` (the `NaN<threshold`
/// fail-open footgun is closed).
#[tokio::test]
async fn t_router_embedfail_non_finite_vector_is_not_new_task() {
    let r = router(
        Embed(Ok(vec![0.1, f32::NAN, 0.3])),
        Index(vec![hit("task-a", 0.9, None)]),
        LlmUnreachable,
    );
    match r.route_task("agent-1", "q").await {
        Err(ContextError::EmbeddingFailed(_)) => {}
        other => panic!("NaN query embedding must be EmbeddingFailed, got {other:?}"),
    }

    let r_empty = router(
        Embed(Ok(vec![])),
        Index(vec![hit("task-a", 0.9, None)]),
        LlmUnreachable,
    );
    match r_empty.route_task("agent-1", "q").await {
        Err(ContextError::EmbeddingFailed(_)) => {}
        other => panic!("empty query embedding must be EmbeddingFailed, got {other:?}"),
    }
}

/// T-router-embedfail (c) — a hit with non-finite similarity is dropped; a
/// finite lower hit is chosen instead of the poisoned one.
#[tokio::test]
async fn t_router_embedfail_non_finite_hit_similarity_skipped() {
    let r = router(
        Embed(Ok(Q_EMB.to_vec())),
        Index(vec![
            hit("task-poison", f32::NAN, None),
            hit("task-good", 0.7, None),
        ]),
        LlmUnreachable,
    );
    let d = r.route_task("agent-1", "q").await.unwrap();
    assert_eq!(d, TaskRoutingDecision::Existing("task-good".into()));
}

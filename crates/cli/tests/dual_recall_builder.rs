//! Wave-20 Lane `search` — isolated cli-layer coverage of `build_dual_recall_unified_search`
//! (the SYS-AC-009 dual-path builder), independent of the e2e SUT. Proves the corpus
//! walk → per-alias SQLite ingest → `R2d2UnifiedSearchImpl` → `R2d2UnifiedSearchAdapter`
//! path returns a dense-only doc + a sparse-only doc through the
//! `context_engine::UnifiedSearchPort`, and exercises the W1 memory-id multi-alias
//! namespacing (which the single-alias e2e witness never hits).

use std::sync::Arc;

use advance_cli::context_wiring::{build_dual_recall_unified_search, CePortError, EmbeddingPort};
use advance_context_engine::ports::UnifiedSearchPort;
use advance_database::DEFAULT_EMBEDDING_DIM;
use cap_memory::{
    MemoryEntry, MemoryStatus, MemoryStore, MemoryType, DEFAULT_MAX_ACTIVE_PER_AGENT,
};

/// Same controlled geometry as the system-acceptance `FixtureEmbedding`: text with the
/// `SPARSEMARK` marker → anti-correlated `[-1,0,..]` (dense similarity 0.0 < threshold ⇒
/// dense-EXCLUDED, surfaces only via `content_fts MATCH`); everything else → `[1,0,..]`.
struct FixtureEmbedding;

#[async_trait::async_trait]
impl EmbeddingPort for FixtureEmbedding {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, CePortError> {
        let mut v = vec![0.0_f32; DEFAULT_EMBEDDING_DIM];
        v[0] = if text.contains("SPARSEMARK") {
            -1.0
        } else {
            1.0
        };
        Ok(v)
    }
}

fn fact(agent_id: &str, id: &str, content: &str) -> MemoryEntry {
    MemoryEntry {
        id: id.into(),
        agent_id: agent_id.into(),
        entry_type: MemoryType::Fact,
        content: content.into(),
        tags: vec![],
        created_at: "2026-01-01T00:00:00Z".into(),
        task_origin: None,
        is_active: true,
        superseded_by: None,
        status: MemoryStatus::Active,
        supersession_reason: None,
        cluster_id: None,
        sources: vec![],
    }
}

/// Run the built port for `query` and return (content ids, memory ids). The query is
/// embedded with the SAME FixtureEmbedding (symmetric dense geometry).
async fn ids_of(
    search: &Arc<dyn UnifiedSearchPort>,
    agent_id: &str,
    query: &str,
) -> (Vec<String>, Vec<String>) {
    let q = FixtureEmbedding.embed(query).await.expect("embed query");
    let r = search.search(agent_id, query, &q).await.expect("search");
    (
        r.contents.iter().map(|c| c.id.clone()).collect(),
        r.memories.iter().map(|m| m.id.clone()).collect(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn build_dual_recall_returns_dense_and_sparse_through_port() {
    let agent = "agent:alpha";
    let ws = tempfile::tempdir().expect("ws tempdir");
    std::fs::write(ws.path().join("dense.md"), b"DENSEMARK quokka platypus").unwrap();
    std::fs::write(
        ws.path().join("sparse.md"),
        b"SPARSEMARK zubernockle widget",
    )
    .unwrap();
    let memdir = tempfile::tempdir().expect("mem tempdir");
    let store = MemoryStore::open(memdir.path(), DEFAULT_MAX_ACTIVE_PER_AGENT).expect("store");
    store
        .insert(agent, fact(agent, "mem-1", "the deploy uses rsync"))
        .expect("insert");

    let search = build_dual_recall_unified_search(
        &store,
        ws.path(),
        agent,
        &[agent.to_string()],
        &FixtureEmbedding,
    )
    .await;

    // Keyword query "zubernockle widget": dense.md via the dense leg (cosine; FTS-misses
    // the keyword), sparse.md via the sparse FTS5 leg (dense-excluded by e_anti), memory
    // via the dense leg → all three reach the port result.
    let (contents, memories) = ids_of(&search, agent, "zubernockle widget").await;
    assert!(
        contents.iter().any(|id| id.contains("dense.md")),
        "dense.md (dense leg) missing: {contents:?}"
    );
    assert!(
        contents.iter().any(|id| id.contains("sparse.md")),
        "sparse.md (sparse FTS5 leg) missing: {contents:?}"
    );
    assert!(
        memories.iter().any(|id| id.contains("mem-1")),
        "memory dense hit missing: {memories:?}"
    );

    // No-keyword query "quokka platypus": sparse.md drops (dense-excluded + FTS-miss),
    // dense.md stays → the FTS sparse leg is load-bearing.
    let (contents2, _) = ids_of(&search, agent, "quokka platypus").await;
    assert!(
        contents2.iter().any(|id| id.contains("dense.md")),
        "dense.md must remain under a different query: {contents2:?}"
    );
    assert!(
        !contents2.iter().any(|id| id.contains("sparse.md")),
        "sparse.md must drop without its keyword (FTS leg load-bearing): {contents2:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn build_dual_recall_multi_alias_each_alias_recalls() {
    // W1: ingest the SAME corpus under the prod `[bare, colon]` query-alias set; each alias
    // must independently recall the docs (proves the alias-namespaced content_row_id +
    // memory_row_id avoid a single-row collision — the cli builder's per-alias ingest loop).
    let bare = "alpha";
    let colon = "alpha:run-7";
    let ws = tempfile::tempdir().expect("ws tempdir");
    std::fs::write(ws.path().join("dense.md"), b"DENSEMARK quokka").unwrap();
    let memdir = tempfile::tempdir().expect("mem tempdir");
    let store = MemoryStore::open(memdir.path(), DEFAULT_MAX_ACTIVE_PER_AGENT).expect("store");
    // memory_search_docs reads under write_agent_id = bare; the builder then keys the row
    // under BOTH aliases.
    store
        .insert(bare, fact(bare, "mem-9", "shared insight"))
        .expect("insert");

    let search = build_dual_recall_unified_search(
        &store,
        ws.path(),
        bare,
        &[bare.to_string(), colon.to_string()],
        &FixtureEmbedding,
    )
    .await;

    for alias in [bare, colon] {
        let (contents, memories) = ids_of(&search, alias, "quokka").await;
        assert!(
            contents.iter().any(|id| id.contains("dense.md")),
            "alias {alias}: dense.md missing: {contents:?}"
        );
        assert!(
            memories.iter().any(|id| id.contains("mem-9")),
            "alias {alias}: memory missing: {memories:?}"
        );
    }
}

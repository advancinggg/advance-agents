//! Wave-20 Lane `search` — the cross-crate adapter bridging MODULE-004's
//! dense+sparse `database::UnifiedSearch` (CONTRACT-032 `R2d2UnifiedSearchImpl`:
//! dense `vec_distance_cosine` + sparse `content_fts MATCH` BM25, merged) to
//! MODULE-010's `context_engine::UnifiedSearchPort` (the assembler's recall read
//! port).
//!
//! These are two DIFFERENT traits in two DIFFERENT crates with DIFFERENT result
//! types — there is no shared port, so the dense-only `RankingUnifiedSearch` (the
//! only existing `UnifiedSearchPort` producer) can never witness the sparse leg.
//! context-engine must stay provider-crate-free (the AC-01 stateless guard forbids
//! depending on `advance-database`), so the bridge lives HERE, in the cli
//! composition root (the cli-spine ADR's sanctioned home; cli already deps both
//! crates). The adapter impls the EXISTING `UnifiedSearchPort` and adds no new
//! contract surface — `modified_contracts: []`.

use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;

use advance_context_engine::ports::{
    ContentHit, MemoryHit, PortError, TaskHit, TurnHit, UnifiedSearchPort, UnifiedSearchResult,
};

/// Wraps any `database::UnifiedSearch` and exposes it as a
/// `context_engine::UnifiedSearchPort`, mapping the source-separated result types
/// (db's rich hits → ce's slim `{id, adjusted_score}` carriers; `DateTime<Utc>` →
/// `SystemTime`) and `DbError` → `PortError`.
pub struct R2d2UnifiedSearchAdapter {
    inner: Arc<dyn advance_database::UnifiedSearch>,
}

impl R2d2UnifiedSearchAdapter {
    pub fn new(inner: Arc<dyn advance_database::UnifiedSearch>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl UnifiedSearchPort for R2d2UnifiedSearchAdapter {
    async fn search(
        &self,
        agent_id: &str,
        query: &str,
        query_embedding: &[f32],
    ) -> Result<UnifiedSearchResult, PortError> {
        let db = self
            .inner
            .search(agent_id, query, query_embedding)
            .await
            // PortError is operator-facing (same boundary as AssemblyError). DbError's
            // Display carries dim / config / sqlite-status labels and MAY echo the
            // agent's OWN query tokens — never recalled row content (dropped by the
            // result mapping below) and never a cross-tenant secret. Bounded to
            // operator-facing logs within the agent's own trust boundary (adv r10).
            .map_err(|e| PortError(e.to_string()))?;
        Ok(map_result(db))
    }
}

fn map_result(db: advance_database::UnifiedSearchResult) -> UnifiedSearchResult {
    UnifiedSearchResult {
        tasks: db.tasks.into_iter().map(map_task).collect(),
        turns: db.turns.into_iter().map(map_turn).collect(),
        contents: db.contents.into_iter().map(map_content).collect(),
        memories: db.memories.into_iter().map(map_memory).collect(),
    }
}

fn map_task(t: advance_database::TaskHit) -> TaskHit {
    TaskHit {
        task_id: t.task_id,
        similarity: t.similarity,
        last_turn_at: t.last_turn_at.map(SystemTime::from),
    }
}

fn map_turn(t: advance_database::TurnHit) -> TurnHit {
    TurnHit {
        id: t.id,
        task_id: t.task_id,
        similarity: t.similarity,
        timestamp: SystemTime::from(t.timestamp),
    }
}

fn map_content(c: advance_database::ContentHit) -> ContentHit {
    // ce::ContentHit is the slim source-separation carrier — only id + score reach
    // the prompt (the file_path / preview / access_count are MODULE-004-internal).
    ContentHit {
        id: c.id,
        adjusted_score: c.adjusted_score,
    }
}

fn map_memory(m: advance_database::MemoryHit) -> MemoryHit {
    MemoryHit {
        id: m.id,
        adjusted_score: m.adjusted_score,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use advance_shared_types::chrono::{DateTime, Utc};

    #[test]
    fn maps_db_result_to_ce_result_all_four_arms() {
        let ts = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let db = advance_database::UnifiedSearchResult {
            tasks: vec![advance_database::TaskHit {
                task_id: "t1".into(),
                similarity: 0.5,
                last_turn_at: Some(ts),
            }],
            turns: vec![advance_database::TurnHit {
                id: "turn1".into(),
                task_id: "t9".into(),
                similarity: 0.4,
                timestamp: ts,
            }],
            contents: vec![advance_database::ContentHit {
                id: "c1".into(),
                file_path: "dir/a.md".into(),
                content_preview: Some("preview".into()),
                similarity: 0.9,
                adjusted_score: 0.91,
                access_count: 2,
            }],
            memories: vec![advance_database::MemoryHit {
                id: "m1".into(),
                content: "x".into(),
                similarity: 0.8,
                adjusted_score: 0.88,
                status: None,
            }],
        };

        let ce = map_result(db);

        assert_eq!(ce.tasks.len(), 1);
        assert_eq!(ce.tasks[0].task_id, "t1");
        assert_eq!(ce.tasks[0].similarity, 0.5);
        assert_eq!(ce.tasks[0].last_turn_at, Some(SystemTime::from(ts)));
        assert_eq!(ce.turns[0].id, "turn1");
        assert_eq!(ce.turns[0].task_id, "t9");
        assert_eq!(ce.turns[0].timestamp, SystemTime::from(ts));
        // ce slim carriers keep only id + adjusted_score.
        assert_eq!(ce.contents[0].id, "c1");
        assert_eq!(ce.contents[0].adjusted_score, 0.91);
        assert_eq!(ce.memories[0].id, "m1");
        assert_eq!(ce.memories[0].adjusted_score, 0.88);
    }
}

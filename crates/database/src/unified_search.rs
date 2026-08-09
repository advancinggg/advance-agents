//! CONTRACT-032 `UnifiedSearch` trait + `R2d2UnifiedSearchImpl` for MODULE-004
//! Slice C. Fan-out search over recall + task semantic similarity + turn dense
//! search; consumed by MODULE-010's unified_search coordinator.
//!
//! `search()` is allowed to touch task_index / turn_index — AC-03's "recall
//! searches X only" applies to `Recall::recall()`, not the entire trait surface.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::embedding_to_blob;
use crate::error::DbError;
use crate::handle::SqliteIndexHandle;
use crate::recall::{
    parse_ts, validate_agent_id, validate_query, validate_query_embedding, R2d2RecallImpl, Recall,
    RecallResult,
};
use crate::score::{Source, TaskHit};
use crate::TunablesProvider;

// Round-10 finding W3 fix: route validation through recall.rs's helpers so
// the two trait surfaces share a single source of truth. Constants used in
// SQL bindings stay local for clarity.
const DENSE_THRESHOLD: f32 = 0.3;
const DEFAULT_FAN_OUT_LIMIT: u32 = 50;

/// CONTRACT-032 `UnifiedSearch` trait.
#[async_trait]
pub trait UnifiedSearch: Send + Sync {
    async fn search(
        &self,
        agent_id: &str,
        query: &str,
        query_embedding: &[f32],
    ) -> Result<UnifiedSearchResult, DbError>;
}

#[derive(Clone, Debug)]
pub struct UnifiedSearchResult {
    pub tasks: Vec<TaskHit>,
    pub turns: Vec<TurnHit>,
    pub contents: Vec<ContentHit>,
    pub memories: Vec<MemoryHit>,
}

#[derive(Clone, Debug)]
pub struct TurnHit {
    pub id: String,
    pub task_id: String,
    pub similarity: f32,
    pub timestamp: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct ContentHit {
    pub id: String,
    pub file_path: String,
    pub content_preview: Option<String>,
    pub similarity: f32,
    pub adjusted_score: f32,
    pub access_count: u32,
}

#[derive(Clone, Debug)]
pub struct MemoryHit {
    pub id: String,
    pub content: String,
    pub similarity: f32,
    pub adjusted_score: f32,
    pub status: Option<String>,
}

pub struct R2d2UnifiedSearchImpl<H: SqliteIndexHandle> {
    recall: R2d2RecallImpl<H>,
    handle: H,
    default_limit: u32,
}

impl<H: SqliteIndexHandle + Clone> R2d2UnifiedSearchImpl<H> {
    pub fn new(handle: H, default_limit: u32) -> Self {
        Self {
            recall: R2d2RecallImpl::new(handle.clone()),
            handle,
            default_limit,
        }
    }

    /// Slice G: production wiring with a live `TunablesProvider`. The
    /// inner recall is constructed via `with_tunables` so unified_search
    /// reads the dim through `recall.current_embedding_dim()` per call —
    /// single-owner model (no dual tunables field on this struct).
    pub fn with_tunables(
        handle: H,
        default_limit: u32,
        tunables: Arc<dyn TunablesProvider>,
    ) -> Self {
        Self {
            recall: R2d2RecallImpl::with_tunables(handle.clone(), tunables),
            handle,
            default_limit,
        }
    }
}

#[async_trait]
impl<H> UnifiedSearch for R2d2UnifiedSearchImpl<H>
where
    H: SqliteIndexHandle + Clone + 'static,
{
    async fn search(
        &self,
        agent_id: &str,
        query: &str,
        query_embedding: &[f32],
    ) -> Result<UnifiedSearchResult, DbError> {
        validate_agent_id(agent_id)?;
        validate_query(query)?;
        // Slice G: read dim through inner recall's tunables (single-owner)
        validate_query_embedding(query_embedding, self.recall.current_embedding_dim())?;

        let limit = self.default_limit.min(DEFAULT_FAN_OUT_LIMIT);
        if limit == 0 {
            return Ok(UnifiedSearchResult {
                tasks: Vec::new(),
                turns: Vec::new(),
                contents: Vec::new(),
                memories: Vec::new(),
            });
        }
        let recall_results = self
            .recall
            .recall(agent_id, query, query_embedding, limit)
            .await?;
        let tasks = self
            .recall
            .task_semantic_similarity(agent_id, query_embedding, limit)
            .await?;

        let turns = {
            let handle = self.handle.clone();
            let agent_id = agent_id.to_string();
            let q_blob = embedding_to_blob(query_embedding);
            let limit_i64 = limit as i64;
            tokio::task::spawn_blocking(move || -> Result<Vec<TurnHit>, DbError> {
                let conn = handle.get_conn()?;
                let mut stmt = conn.prepare(
                    "SELECT t.id, t.task_id, t.timestamp, \
                            (1.0 - vec_distance_cosine(tv.embedding, ?1) / 2.0) AS similarity \
                     FROM turn_index t JOIN turn_vec tv ON tv.rowid = t.rowid \
                     WHERE t.agent_id = ?2 AND similarity >= ?3 \
                     ORDER BY similarity DESC LIMIT ?4",
                )?;
                let iter = stmt.query_map(
                    rusqlite::params![&q_blob, &agent_id, DENSE_THRESHOLD as f64, limit_i64],
                    |row| -> rusqlite::Result<TurnHit> {
                        let id: String = row.get(0)?;
                        let task_id: String = row.get(1)?;
                        let ts_str: String = row.get(2)?;
                        let similarity: f64 = row.get(3)?;
                        Ok(TurnHit {
                            id,
                            task_id,
                            similarity: similarity as f32,
                            timestamp: parse_ts(2, &ts_str)?,
                        })
                    },
                )?;
                iter.collect::<Result<Vec<_>, _>>().map_err(DbError::from)
            })
            .await
            .map_err(|e| DbError::Internal(format!("unified_search task panic: {e}")))??
        };

        // Partition recall results into contents + memories by Source enum.
        let mut contents = Vec::new();
        let mut memories = Vec::new();
        for r in recall_results.into_iter() {
            match r.source {
                Source::Content => contents.push(into_content_hit(r)),
                Source::Memory => memories.push(into_memory_hit(r)),
                Source::Meta => {
                    // Recall does not return Source::Meta — defensive skip.
                }
            }
        }

        Ok(UnifiedSearchResult {
            tasks,
            turns,
            contents,
            memories,
        })
    }
}

fn into_content_hit(r: RecallResult) -> ContentHit {
    ContentHit {
        id: r.id,
        file_path: r.file_path.unwrap_or_default(),
        content_preview: r.content_preview,
        similarity: r.similarity,
        adjusted_score: r.adjusted_score,
        access_count: r.access_count,
    }
}

fn into_memory_hit(r: RecallResult) -> MemoryHit {
    MemoryHit {
        id: r.id,
        content: r.content_full.unwrap_or_default(),
        similarity: r.similarity,
        adjusted_score: r.adjusted_score,
        status: r.status,
    }
}

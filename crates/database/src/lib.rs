#![deny(unsafe_code)]

pub mod error;
pub mod fts_adapter;
pub mod handle;
pub mod rebuild;
pub mod recall;
mod schema;
pub mod score;
pub mod unified_search;
mod vec_adapter;

pub use error::DbError;
pub use handle::{
    upsert_memory_index_row, PooledConnection, R2d2SqliteIndexHandle, SqliteIndexHandle,
};
pub use rebuild::{Embedder, EmbedderError, IndexRebuild, R2d2IndexRebuildImpl, RebuildReport};
pub use recall::{R2d2RecallImpl, Recall, RecallResult};
pub use score::{
    compute_adjusted_score, cosine, rank_task_rows, retention_score, task_semantic_similarity,
    SearchResult, Source, TaskHit, TaskIndexRow, TurnDigest,
};
pub use unified_search::{
    ContentHit, MemoryHit, R2d2UnifiedSearchImpl, TurnHit, UnifiedSearch, UnifiedSearchResult,
};

use std::sync::Arc;

// ──────────────────────────────────────────────────────────────────────
// Tunables — runtime-tunable knobs (Slice G) that consumers read per call
// instead of compile-time constants. Bridges `RuntimeConfig.database.*`
// (CONTRACT-003) to the database read/write paths so AC-19 hot-reloads
// have observable behavioral effects.
// ──────────────────────────────────────────────────────────────────────

pub const DEFAULT_EMBEDDING_DIM: usize = 768;
pub const DEFAULT_RECALL_MAX_DEPTH: u32 = 3;
pub const DEFAULT_WAL_MODE: bool = true;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tunables {
    pub embedding_dim: usize,
    pub recall_max_depth: u32,
    pub wal_mode: bool,
}

impl Default for Tunables {
    fn default() -> Self {
        Self {
            embedding_dim: DEFAULT_EMBEDDING_DIM,
            recall_max_depth: DEFAULT_RECALL_MAX_DEPTH,
            wal_mode: DEFAULT_WAL_MODE,
        }
    }
}

pub trait TunablesProvider: Send + Sync + std::fmt::Debug {
    fn current(&self) -> Tunables;
}

#[derive(Debug, Clone)]
pub struct StaticTunablesProvider(Tunables);

impl StaticTunablesProvider {
    pub fn new(t: Tunables) -> Self {
        Self(t)
    }
}

impl Default for StaticTunablesProvider {
    fn default() -> Self {
        Self(Tunables::default())
    }
}

impl TunablesProvider for StaticTunablesProvider {
    fn current(&self) -> Tunables {
        self.0
    }
}

pub(crate) fn default_tunables_provider() -> Arc<dyn TunablesProvider> {
    Arc::new(StaticTunablesProvider::default())
}

// ──────────────────────────────────────────────────────────────────────
// Crate-internal shared helpers (hoisted in m004-slice-e from rebuild.rs +
// recall.rs to give the production crate a single source of truth)
// ──────────────────────────────────────────────────────────────────────

/// Schema-required embedding dimension for all `*_vec` virtual tables
/// (`vec0(embedding float[768])` per schema.rs). Slice G: production paths
/// no longer reference this directly — they read from `Tunables`. Retained
/// so unit tests can express the "default" value as a literal where
/// plumbing a provider would be noisy.
#[allow(dead_code)]
pub(crate) const EMBEDDING_DIM: usize = DEFAULT_EMBEDDING_DIM;

/// "Now" as an RFC 3339 millisecond-precision UTC string. Used by every
/// `*_index` row's `updated_at` / `last_accessed` writer in this crate.
pub(crate) fn now_text() -> String {
    let dt: chrono::DateTime<chrono::Utc> = std::time::SystemTime::now().into();
    dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Encode a `&[f32]` embedding as raw little-endian bytes for sqlite-vec
/// `BLOB` column binding.
pub(crate) fn embedding_to_blob(e: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(e.len() * 4);
    for f in e {
        out.extend_from_slice(&f.to_le_bytes());
    }
    out
}

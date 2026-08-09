use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DbError {
    #[error("connection-pool error: {0}")]
    Pool(#[from] r2d2::Error),

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("schema-mismatch: stored user_version {stored}, expected {expected}")]
    SchemaMismatch { stored: u32, expected: u32 },

    /// Unsupported operation — currently surfaces from `Recall::recall_at`
    /// pending the historical-version slice (depends on MODULE-003 git
    /// versions). Callers MUST pattern-match this variant when calling
    /// `recall_at` and either skip or fall back.
    #[error("unsupported operation: {0}")]
    Unsupported(String),

    /// Executor-level failure inside the recall pipeline — typically a
    /// `tokio::task::JoinError` from `spawn_blocking` (panic / cancellation).
    /// Distinct from `InvalidConfig` so operators are not misled into
    /// suspecting a caller-supplied config error when the cause is a worker
    /// panic. Slice D extends usage to: (a) `Embedder::embed` failure during
    /// rebuild (mapped here so MODULE-004 has no compile-time edge to
    /// cap-llm); (b) embed-result dimension mismatch vs schema; (c)
    /// `std::io::Error` opening a directory the rebuild scanner expects
    /// to exist.
    #[error("internal error: {0}")]
    Internal(String),
}

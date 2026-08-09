use thiserror::Error;

#[derive(Debug, Error)]
pub enum EventBusError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("sqlite error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("connection pool error: {0}")]
    Pool(#[from] r2d2::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error(
        "events.db user_version is unrecognized — refusing to operate on a file not authored by this crate"
    )]
    MigrationVersionMismatch,

    #[error(
        "events.db has user_version=0 but an observability table already exists — refusing to overwrite a pre-seeded table"
    )]
    PreexistingTable,

    #[error(
        "events.db column shape does not match (expected: {expected}, got: {got}) — refusing to operate on a forged file"
    )]
    InvalidColumnShape { expected: String, got: String },

    #[error(
        "event field exceeds size limit ({field}: {actual} bytes > {limit}) — Implementer Invariant 2 enforcement"
    )]
    OversizeEventField {
        field: &'static str,
        actual: usize,
        limit: usize,
    },

    #[error("refusing to follow symlink at JSONL output path: {path}")]
    SymlinkAtOutputPath { path: String },

    /// Slice m019-B: the merged axum HTTP+WS server failed to bind to its TCP
    /// listener. `addr` is the requested socket; `source` is the underlying io::Error.
    #[error("event-bus HTTP/WebSocket server failed to bind {addr}: {source}")]
    BindFailed {
        addr: String,
        #[source]
        source: std::io::Error,
    },

    /// Slice m019-B: a background writer / stats / server task panicked.
    /// Surfaced via `EventBus::shutdown()`'s join-set drain.
    #[error("event-bus background task '{name}' panicked: {message}")]
    BackgroundTaskPanicked { name: &'static str, message: String },
}

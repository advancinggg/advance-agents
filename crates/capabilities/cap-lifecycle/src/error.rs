//! Slice-A error types for cap-lifecycle.

#[derive(Debug, thiserror::Error)]
pub enum SpawnError {
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("agent already exists: {0}")]
    AlreadyExists(String),
    #[error("parent not found: {0}")]
    ParentNotFound(String),
    #[error("path traversal rejected: {0}")]
    PathTraversal(String),
    #[error("workspace I/O failure: {0}")]
    WorkspaceIoFailure(String),
    #[error("tree state invalid: {0}")]
    TreeStateInvalid(String),
    #[error("subset violation: {0}")]
    SubsetViolation(String),
}

#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("I/O failure: {0}")]
    IoFailure(String),
    #[error("invalid rollback target: {0}")]
    InvalidTarget(String),
    #[error("rollback gate: {0}")]
    RollbackGate(String),
    /// Slice C — terminate cascade's `tree.remove` failed (first error
    /// propagates; NO retry — the top-down freeze already made the subtree
    /// stable, so this signals an unexpected I/O or invariant fault, not a
    /// recoverable race).
    #[error("cascade partial: {0}")]
    CascadePartial(String),
}

/// Slice C — task-decomposition protocol errors (MODULE-005 §2.8).
///
/// The 7 leading variants map 1:1 onto the PRD §9.5 frozen
/// `decomposition-error` WIT variant set (domain failures, typed-lowered).
/// `ParseError` / `IoFailure` / `InvalidConfig` are infrastructure failures
/// with NO neutral `decomposition-error` WIT home — the WIT layer lowers
/// them to a `HostCallError::HandlerError` host trap (truthful "could not
/// complete, non-domain" signal; never a false typed domain claim). See
/// MODULE-005 §2.8 3-category error-lowering taxonomy.
#[derive(Debug, thiserror::Error)]
pub enum DecompositionError {
    #[error("task not found: {0}")]
    TaskNotFound(String),
    #[error("subtask not found: {0}")]
    SubtaskNotFound(String),
    #[error("duplicate title: {0}")]
    DuplicateTitle(String),
    #[error("duplicate existing-id: {0}")]
    DuplicateExistingId(String),
    #[error("dependency cycle: {0}")]
    DependencyCycle(String),
    #[error("unresolved dependency: {0}")]
    UnresolvedDependency(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("I/O failure: {0}")]
    IoFailure(String),
    #[error("invalid config: {0}")]
    InvalidConfig(String),
}

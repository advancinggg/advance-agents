//! MODULE-018 §2.8 error taxonomy — Slice A: 10 variants; Slice B adds 7
//! (total 17); Slice C adds 1 (`ConstraintViolation`, total 18); Slice D adds
//! 3 (`GitCloneFailed`, `TarballExtractFailed`, `RegistryFetchFailed`, total 21)
//! for the non-Local install source surface.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum PackError {
    #[error("invalid pack.yaml: {0}")]
    InvalidManifest(String),

    #[error("runtime-version mismatch: required {required}, current {current}")]
    RuntimeVersionMismatch { required: String, current: String },

    #[error("checksum mismatch for {0}: expected {1}, got {2}")]
    ChecksumMismatch(String, String, String),

    #[error("admin rejected install")]
    AdminRejected,

    #[error("unversioned FQ ref: {0} (must be {{pack}}@{{version}}/{{component}})")]
    UnversionedRef(String),

    #[error("pack not found: {0}@{1}")]
    PackNotFound(String, String),

    #[error("component not found in pack {pack}@{version}: {component}")]
    ComponentNotFound {
        pack: String,
        version: String,
        component: String,
    },

    #[error(
        "ambiguous bare-name FQ ref in pack {pack}@{version}: {component} found in {kinds:?}; \
         use prefixed form `{{pack}}@{{version}}/{{kind-dir}}/{{name}}` to disambiguate"
    )]
    AmbiguousComponent {
        pack: String,
        version: String,
        component: String,
        kinds: Vec<crate::registry::ComponentKind>,
    },

    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("not yet implemented: {0}")]
    NotImplemented(&'static str),

    // ─────────────────────────────────────────────────────────────
    // Slice B additions (§2.8 update)
    #[error("dependency not found: {name} (version_req {version_req})")]
    DependencyNotFound { name: String, version_req: String },

    #[error("dependency {name} version mismatch: required {required}, resolver returned {found}")]
    DependencyVersionMismatch {
        name: String,
        required: String,
        found: String,
    },

    /// `path` is the dep-loop in DFS order (root NOT included). For cycle A→B→A
    /// where A is the root install, `path` renders as `["B", "A", "B"]`.
    #[error("dependency cycle detected: {}", .path.join(" → "))]
    DependencyCycle { path: Vec<String> },

    #[error("dependency depth exceeded max {max_depth} at {name}")]
    DependencyDepthExceeded { max_depth: usize, name: String },

    #[error("invalid workflow: {0}")]
    InvalidWorkflow(String),

    #[error("missing secret: {key}")]
    MissingSecret { key: String },

    #[error("materialize target missing in pack provides: kind={kind}, name={name}")]
    MaterializeMissingProvide { kind: String, name: String },

    // ─────────────────────────────────────────────────────────────
    // Slice C addition (§2.8 18th variant) — REQ-073 constraint surface
    // for `resolve_pack_component` and `apply_preset`. The reason string
    // names the specific gate that failed (component-type mismatch,
    // trigger present, binary/behavior-ref absent, FQ ref kind wrong,
    // target_agent_id validation, etc.).
    #[error("constraint violation: {reason}")]
    ConstraintViolation { reason: String },

    // ─────────────────────────────────────────────────────────────
    // Slice D additions (§2.8 19/20/21 variants) — non-Local install
    // source fetch failures (git+/tarball/registry).
    /// git+ subprocess `git clone --depth 1 [--branch <ref>] -- <url> <dest>`
    /// returned non-zero status, or `tokio::time::timeout` fired, or git
    /// binary not found in PATH. `reason` carries a short diagnostic
    /// (git's stderr first line, "wall-clock timeout", "git binary not
    /// found in PATH", etc.).
    #[error("git clone failed for {url}: {reason}")]
    GitCloneFailed { url: String, reason: String },

    /// Tarball untar rejected an entry (`..` traversal, absolute path, null
    /// byte, backslash, non-UTF-8, type ∉ {Regular, Directory}) OR exceeded
    /// total/per-entry/entry-count cap.
    #[error("tarball extract failed at {}: {reason}", path.display())]
    TarballExtractFailed { path: PathBuf, reason: String },

    /// `RegistryClient::fetch_tarball` timeout (wraps `tokio::time::timeout`)
    /// OR explicit client-returned error wrapped here for diagnostic clarity.
    /// Distinguishes registry-specific failures from generic `GitCloneFailed`.
    #[error("registry fetch failed for {name}@{version}: {reason}")]
    RegistryFetchFailed {
        name: String,
        version: String,
        reason: String,
    },
}

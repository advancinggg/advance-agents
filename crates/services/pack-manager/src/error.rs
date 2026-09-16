//! MODULE-018 §2.8 error taxonomy — Slice A: 10 variants; Slice B adds 7
//! (total 17); Slice C adds 1 (`ConstraintViolation`, total 18); Slice D adds
//! 3 (`GitCloneFailed`, `TarballExtractFailed`, `RegistryFetchFailed`, total 21)
//! for the non-Local install source surface. PACK-GAP-CLOSURE lane P1 adds 3
//! (`AlreadyInstalled`, `DependentsExist`, `UnknownRequiredCapability`, total 24)
//! for the reinstall / uninstall / capability-catalog surface; lane P3 adds 1
//! (`SignatureInvalid`, total 25) for the signed-manifest surface and redacts
//! URL userinfo in `GitCloneFailed`'s Display; lane P2 adds 1
//! (`WorkflowStepFailed`, total 26) for the workflow-compensation surface.

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
    /// (or, for a commit-SHA pin, the `init` / `remote add` / `fetch --depth 1
    /// origin <sha>` / `checkout FETCH_HEAD` sequence) returned non-zero status,
    /// or `tokio::time::timeout` fired, or git binary not found in PATH.
    /// `reason` carries a short diagnostic (git's stderr first line,
    /// "wall-clock timeout", "git binary not found in PATH", etc.).
    ///
    /// PACK-GAP-CLOSURE P3 (§4.2): the Display form passes `url` through
    /// [`crate::source::redact_userinfo`], so a credential-bearing URL
    /// (`https://user:token@host/…`) never reaches a log or a terminal in
    /// clear text. The raw field is kept for programmatic callers.
    #[error("git clone failed for {}: {reason}", crate::source::redact_userinfo(.url))]
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

    // ─────────────────────────────────────────────────────────────
    // PACK-GAP-CLOSURE P1 additions (§2.2 / §2.4) — variants 22/23/24.
    /// Step ③ (after manifest parse, BEFORE checksum verification and admin
    /// approval): `packs_dir/{name}@{version}` already exists on disk OR
    /// `.meta.yaml` already carries the key. Judged from DISK state (not the
    /// in-memory registry) so a fresh `Installer` over an existing packs dir
    /// refuses a reinstall without ever prompting the admin. Recovery path:
    /// [`Installer::uninstall`](crate::Installer::uninstall) then install.
    #[error("pack {name}@{version} is already installed")]
    AlreadyInstalled { name: String, version: String },

    /// `uninstall` refused: other installed packs declare a `dependencies:`
    /// entry that this exact `{name}@{version}` satisfies. `dependents` is the
    /// sorted `"{name}@{version}"` list of those packs — uninstall them first.
    #[error("cannot uninstall {name}@{version}: still required by {}", .dependents.join(", "))]
    DependentsExist {
        name: String,
        version: String,
        dependents: Vec<String>,
    },

    /// Step ④ (`CatalogCheckedApproval`): `required-capabilities` names one or
    /// more capabilities absent from the composition root's capability catalog.
    /// Surfaced BEFORE the inner approval strategy runs, so an admin is never
    /// prompted to approve a capability the runtime cannot provide.
    #[error("pack {pack} declares unknown required-capabilities: {}", .unknown.join(", "))]
    UnknownRequiredCapability { pack: String, unknown: Vec<String> },

    // ─────────────────────────────────────────────────────────────
    // PACK-GAP-CLOSURE P3 addition (§4.1) — variant 25.
    /// Step ③b: the pack ships a `pack.sig` that is malformed (not the
    /// `alg: ed25519` / `public-key` / `signature` YAML shape, bad hex, a
    /// non-canonical key or signature) OR whose signature does not verify over
    /// the exact `pack.yaml` bytes. Raised REGARDLESS of the configured trust
    /// roots: a pack that claims a signature it cannot back is refused outright,
    /// whereas a valid signature from an unknown key merely counts as unsigned.
    #[error("signature verification failed for pack {pack}: {reason}")]
    SignatureInvalid { pack: String, reason: String },

    // ─────────────────────────────────────────────────────────────
    // PACK-GAP-CLOSURE P2 addition (§3.5) — variant 26.
    /// `WorkflowApplier::apply`: step `i` failed AFTER at least one earlier step
    /// had already executed. Every earlier successful `spawn-child` /
    /// `submit-component` was compensated in reverse order (`terminate_child` /
    /// `withdraw_component` on the executor) BEFORE this error was returned;
    /// `register-mcp-server` has no compensation (it only returns an id).
    ///
    /// - `step` — `"step[{i}]:{type}"` of the failing step.
    /// - `source` — the failing step's own error (validation or executor).
    /// - `compensated` — compensations that succeeded, in execution (reverse)
    ///   order: `"spawn-child:{target_path}"` / `"submit-component:{ref}"`.
    /// - `compensation_failures` — compensations that themselves failed, as
    ///   `"{label}: {error}"`; never swallowed. A non-empty list means the
    ///   admin must reconcile the named resources by hand.
    ///
    /// A failure at the FIRST executed step (nothing to undo) surfaces the raw
    /// step error unchanged, so pre-P2 callers matching `InvalidWorkflow` /
    /// `MissingSecret` on single-step templates are unaffected.
    #[error(
        "workflow {step} failed: {source} (compensated: [{}]; compensation failures: [{}])",
        .compensated.join(", "),
        .compensation_failures.join("; ")
    )]
    WorkflowStepFailed {
        step: String,
        #[source]
        source: Box<PackError>,
        compensated: Vec<String>,
        compensation_failures: Vec<String>,
    },
}

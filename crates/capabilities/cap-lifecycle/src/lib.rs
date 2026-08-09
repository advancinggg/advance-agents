//! cap-lifecycle — MODULE-005 Slice A foundation.
//!
//! Slice A is library-only and **synchronous** (no async runtime / no tokio /
//! no cap-fs / no cap-grant deps). The crate provides:
//!
//! - [`AgentTreeStore`] — concrete impl of BOTH [`AgentTreeReader`] AND
//!   [`AgentTreeSnapshot`] (the supertrait bound `AgentTreeSnapshot: AgentTreeReader`
//!   forces both impls on the same type). Canonicalizes every
//!   `AgentNode.workspace_path` on insert + enforces workspace_root containment.
//!   The direct `AgentTreeReader` methods on the live store use fresh per-call
//!   read-locks (best-effort); for per-turn consistency, see [`SnapshotReader`]
//!   below.
//! - [`SnapshotReader`] — per-turn [`AgentTreeReader`] over a captured
//!   [`AgentTreeSnapshotData`]. Recommended pattern for CONTRACT-040
//!   Implementer Invariant 2 ("per-turn read consistency").
//! - [`Spawner`] trait + [`DefaultSpawner`] — sync spawn-child + spawn-sub.
//!   Workspace_root is owned and canonicalized by [`AgentTreeStore::new`];
//!   `DefaultSpawner::new` only injects the SubsetGate and inherits the tree's
//!   workspace_root via [`AgentTreeStore::workspace_root`]. Rejects Sub-as-parent
//!   per MODULE-005 §1.2.
//! - [`SpawnerSubsetGate`] trait — dependency-inverted subset-gate seam.
//!   Slice A shipped the trait only; tests in this crate's `tests/`
//!   directory define their own local `AlwaysOkGate` / `AlwaysFailGate`
//!   impls. **Slice E (m013-slice-e, 2026-05-23) ships the production
//!   [`CapGrantSubsetAdapter`]** wrapping cap-grant's Capability-first
//!   `validate_capability_subset` entry; the projection from
//!   `[shared_types::Capability]` to the cap-grant internal model is
//!   fail-closed by design (per-family param-key whitelist; rejects
//!   unrecognized keys, non-object params, non-scalar values, identity-
//!   destroying CSV elements, non-integer numbers).
//! - [`SubsetCheckedComponentSubmit`] — Slice E Rust-API wrapper around
//!   any `ComponentSubmitGate` + `SpawnerSubsetGate` that performs the
//!   subset check BEFORE delegating; closes the M005-AC-06 submit-component
//!   enforcement point at the cap-lifecycle library layer. WIT-level
//!   submit-component continues to pass `Vec::new()` capabilities until
//!   `advance.wit`'s submit-component signature lifts capabilities in a
//!   future slice.
//! - [`init_child_workspace`] — `.agent/` skeleton materializer.
//! - [`atomic_write`] — sync write-tmp + rename (≤ 64 KiB).
//! - Errors: [`SpawnError`], [`LifecycleError`].
//!
//! # Consistency note
//!
//! Per shared-types Implementer Invariant 2, [`AgentTreeReader`] consumers
//! should call [`AgentTreeSnapshot::snapshot`] ONCE per logical turn and
//! pass the resulting [`AgentTreeSnapshotData`] around (or wrap it in
//! [`SnapshotReader::new`]). Per-call reader methods on the live
//! [`AgentTreeStore`] take fresh read-locks and may not be mutually
//! consistent across concurrent writers.
//!
//! # TOCTOU acknowledgment
//!
//! Slice A uses lexical path validation + post-materialization symlink
//! detection. It does NOT use `openat2 + RESOLVE_NO_SYMLINKS`. A workspace-
//! local race attacker who can plant symlinks between validate and write may
//! redirect output. Slice A's threat model assumes a non-adversarial caller
//! (first-party tests + Slice B WIT host layer). Full openat2 hardening is
//! a Slice B/C work item.
//!
//! [`AgentTreeReader`]: advance_shared_types::agent_tree::AgentTreeReader
//! [`AgentTreeSnapshot`]: advance_shared_types::agent_tree::AgentTreeSnapshot
//! [`AgentTreeSnapshotData`]: advance_shared_types::agent_tree::AgentTreeSnapshotData

#![forbid(unsafe_code)]

pub mod atomic;
pub mod auto_bootstrap;
pub mod cap_grant_adapter;
pub mod cascade_adapters;
pub mod checkpoint;
pub mod component_submit;
pub mod decomposition;
pub mod error;
/// Decomposition observability event builders (`task.decomposed` /
/// `task.subtask_updated`); consumed by `wit_impl` dispatch.
pub mod events;
pub mod identifier;
/// Pack-sourced `TemplateResolver` (sat/pack-template-bridge, 2026-06-15):
/// resolves a pack-installed agent-template via `PackRegistry` into a
/// `TemplateContent` for `apply_template`.
pub mod pack_template_resolver;
pub mod producer_boundary;
pub mod rollback;
pub mod spawn;
pub mod sqlite_agent_stats_reader;
pub mod stats;
mod template_data;
pub mod templates;
pub mod terminate;
pub mod tree;
pub mod wit_impl;
pub mod workspace;

// Narrow explicit re-exports — no wildcard `pub use`.
pub use atomic::{atomic_write, MAX_BYTES};
pub use auto_bootstrap::{
    apply_auto_bootstrap, parse_auto_bootstrap, BootstrapEnsure, BootstrapEntry, BootstrapError,
    BootstrapEvent, BootstrapKind, BootstrapReport, MAX_BOOTSTRAP_ENTRIES,
    MAX_BOOTSTRAP_INPUT_BYTES,
};
pub use cap_grant_adapter::{CapGrantSubsetAdapter, SubsetCheckedComponentSubmit};
pub use cascade_adapters::{
    FsMemoryArchiver, FsWorkspaceCleanup, GrantRevokeCascade, MailboxFlushCascade,
    RunManagerCascade,
};
pub use checkpoint::{
    CheckpointController, CheckpointEntry, DefaultCheckpointController, NamedCheckpointGate,
};
pub use component_submit::{
    admit_runnable_binary, ComponentId, ComponentInfo, ComponentState, ComponentSubmitConfig,
    ComponentSubmitConfigV2, ComponentSubmitGate,
};
pub use decomposition::{
    DecompositionPlan, DecompositionReceipt, DecompositionState, DecompositionStore,
    DecompositionStrategy, DefaultDecompositionStore, DelegationTarget, SubtaskIdMapping,
    SubtaskSpec, SubtaskState, SubtaskStatus, MAX_DECOMPOSITION_DOC_BYTES,
    MAX_DECOMPOSITION_SUBTASKS, MAX_SUBTASK_PROMPT_BYTES, MAX_SUBTASK_TITLE_BYTES,
    MAX_TASK_ID_BYTES,
};
pub use error::{DecompositionError, LifecycleError, SpawnError};
pub use identifier::{is_workspace_hidden_name, sub_uuid_v4, validate_agent_id, MAX_AGENT_ID_LEN};
pub use sqlite_agent_stats_reader::SqliteAgentStatsReader;
pub use stats::{AgentStats, AgentStatsReader, DefaultStatsController, StatsController};
pub use terminate::{
    DefaultTerminateController, GrantCascadeRevoke, LoopCascade, MailboxCascade, MemoryArchiver,
    RunCascade, TerminateController, WorkspaceCleanup,
};
pub use wit_impl::{
    register_agent_component_submit, register_agent_decomposition, register_agent_lifecycle,
    register_agent_spawn, AgentLifecycleBundle, AGENT_LIFECYCLE_CAPABILITY,
    AGENT_LIFECYCLE_NAMESPACE,
};
// sat/pack-template-bridge (2026-06-15): pack-sourced TemplateResolver.
pub use pack_template_resolver::PackTemplateResolver;
pub use producer_boundary::WorkspaceFileResidentPolicy;
pub use rollback::{
    DefaultRollbackController, RollbackController, RollbackModeSpec, RollbackTargetSpec,
    WorkspaceRollbackGate,
};
pub use spawn::{
    DefaultSpawner, SpawnChildConfig, SpawnObserver, SpawnSubConfig, Spawner, SpawnerSubsetGate,
};
pub use templates::{
    apply_template, BuiltinTemplateRegistry, TemplateContent, TemplateError, TemplateResolver,
    TemplateSkillEntry, MAX_MANIFEST_YAML_ALIASES, MAX_MANIFEST_YAML_ANCHORS, MAX_TEMPLATE_SKILLS,
    MAX_TEMPLATE_TOTAL_BYTES,
};
pub use tree::{AgentTreeStore, SnapshotReader, MAX_AGENTS_PER_STORE};
pub use workspace::{
    init_child_workspace, init_child_workspace_files, resolve_under_parent, symlink_check,
    MAX_INIT_FILES, MAX_INIT_FILE_BYTES, MAX_INIT_TOTAL_BYTES, MAX_PATH_DEPTH,
};

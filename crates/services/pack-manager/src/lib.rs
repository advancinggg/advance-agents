//! advance-pack-manager — MODULE-018 pack-system.
//!
//! Slice A ships the foundation skeleton; Slice B extends with recursive deps,
//! admin approval prompt, workflow applier, and 5 concrete materializer methods.
//!
//! - pack.yaml manifest parser ([`PackManifest`]) + semver-range validation;
//!   pack.yaml integrity is enforced via step ④ admin approval review of
//!   `required-capabilities` + `trust-level` (signed-manifest scheme deferred to
//!   Slice C)
//! - 8-step install orchestrator ([`Installer`]) with [`InstallTraceSink`] audit
//!   hook. Slice B: recursive dependency install via [`DependencyResolver`] seam
//!   (Local-source deps; non-Local still `NotImplemented`).
//! - [`PackRegistry`] trait + [`InMemoryPackRegistry`] in-memory implementation
//!   with async no-arg `rescan()` populating from on-disk `.meta.yaml` via
//!   atomic read-build-swap. Slice B adds `find_installed_satisfying` helper
//!   for recursive-dep dedup.
//! - [`MaterializeAction`] trait + [`DefaultMaterializer`] concrete impl. Slice C
//!   shipped all 10 §19.3 materializer methods; the AC-17 slice (m018-rescap) adds
//!   the 11th, [`register_resource_capability`](MaterializeAction::register_resource_capability)
//!   — the register-not-copy REGISTRATION surface for the `resource-capabilities`
//!   category (validate `capability.yaml`, return a content-derived
//!   [`ResourceCapabilityId`]; nothing copied to workspaces).
//! - [`InteractiveApproval`] stdin-driven [`ApprovalStrategy`] for the admin
//!   approval prompt (Slice B AC-07). Short-circuits on empty
//!   `required-capabilities`.
//! - [`WorkflowApplier`] static driver for workflow templates (Slice B AC-10).
//!   Drives 3 step types through [`WorkflowExecutor`] seam; resolves
//!   `secret-refs` through [`SecretStore`] seam.
//! - [`PackError`] taxonomy (26 variants — Slice D added `GitCloneFailed`,
//!   `TarballExtractFailed`, `RegistryFetchFailed` for the non-Local install
//!   source surface; Slice C added `ConstraintViolation`; Pack lane P1
//!   added `AlreadyInstalled`, `DependentsExist`, `UnknownRequiredCapability`;
//!   P3 added `SignatureInvalid`; P2 added `WorkflowStepFailed`).
//! - Pack lane P1 (the internal pack gap-closure plan §2): [`Installer::new`]
//!   builder + [`NoopTraceSink`]; disk-truth `AlreadyInstalled` at step ③ (before
//!   checksum / approval); [`Installer::uninstall`] with `DependentsExist`
//!   refusal; a cross-process install lock ([`INSTALL_LOCK_FILENAME`]) held
//!   across steps ③→⑧; [`PackRegistry::provides`] enumeration; and the
//!   [`CatalogCheckedApproval`] decorator validating `required-capabilities`
//!   against a [`CapabilityCatalog`].
//! - [`RegistryClient`] async seam (Slice D AC-05) for `registry:name@version`
//!   source dispatch; ships `MockRegistryClient` test helper following the
//!   `RecordingTraceSink` visibility precedent. The production HTTPS client
//!   (`HttpsRegistryClient`) lives in the cli composition root
//!   (Pack lane P3); `list_versions` is a default method here.
//! - Pack lane P3 (the internal pack gap-closure plan §4): signed manifests
//!   ([`signature`] — `pack.sig` ed25519 over `pack.yaml`, `Installer::with_trust_roots`,
//!   `PackError::SignatureInvalid`, unsigned `trusted` claims downgraded and
//!   surfaced through [`ApprovalContext`]); git commit-SHA pins + slash refs +
//!   userinfo redaction ([`redact_userinfo`]); and the fd-relative
//!   [`fetch::copy_dir_no_symlinks_observed`] copy that closes the source-side
//!   symlink-swap TOCTOU window.
//! - Pack lane P2 (the internal pack gap-closure plan §3): workflow
//!   compensation (`WorkflowExecutor::{terminate_child, withdraw_component}` +
//!   `PackError::WorkflowStepFailed`); the `mcp-servers/{name}.yaml` schema
//!   ([`mcp_server_manifest`]); the STRUCTURED meta-schema extension merge
//!   ([`meta_schema_merge`]); `materialize_channel_adapter` explicitly
//!   unsupported; and [`resource_capability_tool_names`] for the cli's
//!   pack-tool exposure reconciliation. The pack → subsystem bridges themselves
//!   (skills / presets / mcp / meta-schema / memory-seeds) and the production
//!   `WorkflowExecutor` / `SecretStore` / `DependencyResolver` implementations
//!   live in the cli composition root (`pack_bridges`, `pack_production`).

pub mod admin;
pub mod catalog;
pub(crate) mod component_manifest;
pub mod deps;
pub mod error;
pub mod fetch;
pub mod install;
pub(crate) mod layout;
pub mod manifest;
pub mod materialize;
pub mod materialize_impl;
pub mod mcp_server_manifest;
pub mod meta;
pub mod meta_schema_merge;
pub mod registry;
pub mod registry_client;
pub mod signature;
pub mod source;
pub mod verify;
pub mod workflow;

pub use admin::InteractiveApproval;
pub use catalog::{CapabilityCatalog, CatalogCheckedApproval, StaticCapabilityCatalog};
pub use component_manifest::{resource_capability_id, resource_capability_tool_names};
pub use deps::DependencyResolver;
pub use error::PackError;
pub use fetch::FetchContext;
pub use install::{
    ApprovalContext, ApprovalStrategy, AutoApprove, AutoReject, InstallStep, InstallTraceSink,
    Installer, NoopTraceSink, PackInstallReport, PackUninstallReport, RecordingTraceSink,
    RejectUnlessTrivial, DEFAULT_FETCH_TIMEOUT, INSTALL_LOCK_FILENAME,
    PACK_REGISTRY_RELOADED_EVENT, PACK_UNINSTALLED_EVENT,
};
pub use manifest::{
    ChecksumAlgo, PackChecksums, PackDependency, PackManifest, PackProvides, TrustLevel,
};
pub use materialize::{
    GrantId, MaterializeAction, McpServerId, ResourceCapabilityId, WorkflowContext, WorkflowReport,
};
pub use materialize_impl::DefaultMaterializer;
pub use mcp_server_manifest::{
    parse_mcp_server_manifest, parse_mcp_server_manifest_str, McpServerManifest, McpTransportDecl,
    MAX_MCP_SERVER_YAML_BYTES,
};
pub use meta::{MetaIndex, MetaPackEntry, MetaScope};
pub use meta_schema_merge::{
    merge_meta_schema_extension_file, merge_meta_schema_extension_file_with, MetaSchemaMergeError,
    MetaSchemaMergeReport, MAX_META_SCHEMA_YAML_BYTES,
};
pub use registry::{
    path_for_kind, ComponentKind, ComponentManifest, InMemoryPackRegistry, NamespaceResolver,
    PackComponentResolution, PackMetadata, PackProvideEntry, PackRegistry, PackResolution,
};
pub use registry_client::{MockRegistryClient, RegistryClient};
pub use signature::{verify_pack_signature, PACK_SIG_FILENAME};
pub use source::{is_commit_sha, parse_source, redact_userinfo, SourceRef};
pub use workflow::{
    SecretStore, SecretValue, TriggerEventBody, WorkflowApplier, WorkflowExecutor, WorkflowStep,
    WorkflowTemplate, WorkflowTrigger,
};

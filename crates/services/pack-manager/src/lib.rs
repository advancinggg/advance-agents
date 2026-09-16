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
//! - [`PackError`] taxonomy (24 variants — Slice D added `GitCloneFailed`,
//!   `TarballExtractFailed`, `RegistryFetchFailed` for the non-Local install
//!   source surface; Slice C added `ConstraintViolation`; PACK-GAP-CLOSURE P1
//!   added `AlreadyInstalled`, `DependentsExist`, `UnknownRequiredCapability`).
//! - PACK-GAP-CLOSURE P1 (docs/plans/PACK-GAP-CLOSURE.md §2): [`Installer::new`]
//!   builder + [`NoopTraceSink`]; disk-truth `AlreadyInstalled` at step ③ (before
//!   checksum / approval); [`Installer::uninstall`] with `DependentsExist`
//!   refusal; a cross-process install lock ([`INSTALL_LOCK_FILENAME`]) held
//!   across steps ③→⑧; [`PackRegistry::provides`] enumeration; and the
//!   [`CatalogCheckedApproval`] decorator validating `required-capabilities`
//!   against a [`CapabilityCatalog`].
//! - [`RegistryClient`] async seam (Slice D AC-05) for `registry:name@version`
//!   source dispatch; production HTTPS endpoint deferred to Slice D+; ships
//!   `MockRegistryClient` test helper following the `RecordingTraceSink`
//!   visibility precedent.

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
pub mod meta;
pub mod registry;
pub mod registry_client;
pub mod source;
pub mod verify;
pub mod workflow;

pub use admin::InteractiveApproval;
pub use catalog::{CapabilityCatalog, CatalogCheckedApproval, StaticCapabilityCatalog};
pub use component_manifest::resource_capability_id;
pub use deps::DependencyResolver;
pub use error::PackError;
pub use fetch::FetchContext;
pub use install::{
    ApprovalStrategy, AutoApprove, AutoReject, InstallStep, InstallTraceSink, Installer,
    NoopTraceSink, PackInstallReport, PackUninstallReport, RecordingTraceSink, RejectUnlessTrivial,
    DEFAULT_FETCH_TIMEOUT, INSTALL_LOCK_FILENAME, PACK_REGISTRY_RELOADED_EVENT,
    PACK_UNINSTALLED_EVENT,
};
pub use manifest::{
    ChecksumAlgo, PackChecksums, PackDependency, PackManifest, PackProvides, TrustLevel,
};
pub use materialize::{
    GrantId, MaterializeAction, McpServerId, ResourceCapabilityId, WorkflowContext, WorkflowReport,
};
pub use materialize_impl::DefaultMaterializer;
pub use meta::{MetaIndex, MetaPackEntry, MetaScope};
pub use registry::{
    path_for_kind, ComponentKind, ComponentManifest, InMemoryPackRegistry, NamespaceResolver,
    PackComponentResolution, PackMetadata, PackProvideEntry, PackRegistry, PackResolution,
};
pub use registry_client::{MockRegistryClient, RegistryClient};
pub use source::{parse_source, SourceRef};
pub use workflow::{
    SecretStore, SecretValue, TriggerEventBody, WorkflowApplier, WorkflowExecutor, WorkflowStep,
    WorkflowTemplate, WorkflowTrigger,
};

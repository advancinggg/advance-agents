//! PACK-GAP-CLOSURE P1 (§2.8) — composition-root wiring of the MODULE-018 pack
//! system for `advance start`.
//!
//! [`build_pack_wiring`] yields ONE [`InMemoryPackRegistry`] rescanned from the
//! workspace packs dir (`RuntimeConfig.pack.packs_dir` joined onto the workspace
//! root by `wiring.rs`), and over it:
//!
//! - the [`ChainedTemplateResolver`] — runtime built-ins for bare names
//!   (`researcher`), the [`PackTemplateResolver`] for pack FQ refs
//!   (`{pack}@{ver}/agent-templates/{name}`). Every production spawner
//!   (config-tree materialization, the guest `spawn-child` spawner, the
//!   client-api agents admin adapter) shares this ONE resolver, replacing the
//!   three bare `BuiltinTemplateRegistry::new()` sites the gap audit found.
//! - the [`PackEvaluatorResolver`] — auto-loop evaluator FQ refs
//!   (`{pack}@{ver}/components/{name}`), installed on the production auto-loop
//!   driver by `auto_wiring::install_auto_loop_integration_with_evaluator`.
//! - a [`DefaultMaterializer`] over the registry (the 11 CONTRACT-171
//!   materializer methods). PACK-GAP-CLOSURE P2 (§3.4, #10): its
//!   `WorkflowExecutor` / `SecretStore` seams are the one-shot
//!   [`LateBoundWorkflowExecutor`] / [`LateBoundSecretStore`] slots — the
//!   production `SchedulerWorkflowExecutor` (spawner + scheduler submit API)
//!   and `CapSecretsSecretStore` are built LATER in `wiring.rs` (they depend on
//!   the template resolver / master key this wiring provides) and bound into
//!   the slots; until then every leg fails closed (`NotImplemented` / no
//!   secret), never silently succeeding. [`PackWiring::mcp_entries`] is where a
//!   workflow's `register-mcp-server` entries are retained for the MCP client.
//!
//! Boot semantics (fail-closed): a missing `packs_dir` is created (empty
//! registry — a fresh `advance init` workspace boots); an existing one is
//! rescanned and ANY rescan failure aborts boot (a corrupt `.meta.yaml` or a
//! tampered installed pack must not be silently ignored). A `packs_dir` that is
//! a symlink or a file is refused.
//!
//! The daemon path is READ-ONLY over the packs dir: installs go through
//! `advance pack install` (`commands/pack.rs`), which runs the `Installer`
//! against the same directory under the cross-process install lock. A running
//! daemon sees a new pack after restart (rescan-on-boot); live rescan is a
//! later lane.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_pack_manager::{DefaultMaterializer, InMemoryPackRegistry, PackError, PackRegistry};
use advance_shared_types::traits::EventBusEmit;
use cap_lifecycle::pack_template_resolver::PackTemplateResolver;
use cap_lifecycle::templates::{
    BuiltinTemplateRegistry, TemplateContent, TemplateError, TemplateResolver,
};

use crate::auto_wiring::PackEvaluatorResolver;
use crate::pack_bridges::InMemoryMcpEntrySink;
use crate::pack_production::{LateBoundSecretStore, LateBoundWorkflowExecutor};

/// Boot-time pack wiring failure. Every variant aborts `advance start`.
#[derive(Debug)]
pub enum PackWiringError {
    /// `packs_dir` exists but is not a real directory (symlink / regular file).
    NotADirectory(PathBuf),
    /// Creating a missing `packs_dir` (or probing it) failed.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// The registry rescan failed (corrupt `.meta.yaml`, tampered pack, …).
    Rescan(PackError),
}

impl std::fmt::Display for PackWiringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackWiringError::NotADirectory(p) => {
                write!(f, "packs dir is not a real directory: {p:?}")
            }
            PackWiringError::Io { path, source } => {
                write!(f, "packs dir {path:?}: {source}")
            }
            PackWiringError::Rescan(e) => write!(f, "pack registry rescan failed: {e}"),
        }
    }
}

impl std::error::Error for PackWiringError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PackWiringError::Io { source, .. } => Some(source),
            PackWiringError::Rescan(e) => Some(e),
            PackWiringError::NotADirectory(_) => None,
        }
    }
}

/// The composed pack-system handles. All fields are shared handles (`Arc`), so
/// the struct is cheap to clone into `WiringHandles`.
#[derive(Clone)]
pub struct PackWiring {
    /// The packs dir the registry was rescanned from (already joined onto the
    /// workspace root).
    pub packs_dir: PathBuf,
    /// The ONE production pack registry (rescanned at boot).
    pub registry: Arc<InMemoryPackRegistry>,
    /// Built-ins ∪ pack FQ refs — see [`ChainedTemplateResolver`].
    pub template_resolver: Arc<dyn TemplateResolver>,
    /// Auto-loop evaluator FQ-ref resolver over `registry`.
    pub evaluator_resolver: Arc<PackEvaluatorResolver>,
    /// CONTRACT-171 materializer over `registry`, composed over
    /// `workflow_executor` + `secret_store`.
    pub materializer: Arc<DefaultMaterializer>,
    /// P2 (§3.4): the materializer's `WorkflowExecutor` slot. `wiring.rs` binds
    /// the production `SchedulerWorkflowExecutor` once the spawner and the
    /// scheduler submit API exist; unbound → every workflow leg is
    /// `NotImplemented`.
    pub workflow_executor: Arc<LateBoundWorkflowExecutor>,
    /// P2 (§3.4): the materializer's `SecretStore` slot. `wiring.rs` binds the
    /// cap-secrets-backed store once the master key is loaded; unbound → every
    /// `secret-refs` lookup is `MissingSecret`.
    pub secret_store: Arc<LateBoundSecretStore>,
    /// P2 (§3.1): entries a workflow's `register-mcp-server` produced (trust +
    /// secrets already applied), retained for the MCP client wiring to drain
    /// into a `McpServersConfig`.
    pub mcp_entries: Arc<InMemoryMcpEntrySink>,
    /// Reserved for an in-daemon `Installer`: the bus pack lifecycle events
    /// (`pack.registry_reloaded` / `pack.uninstalled`) would go to. The
    /// read-only registry/resolvers built here emit nothing.
    pub event_bus: Option<Arc<dyn EventBusEmit>>,
}

/// Build the pack wiring over `packs_dir` (see module docs for the boot
/// semantics). `event_bus` is retained on the returned [`PackWiring`] for a
/// future in-daemon installer; it is not used by the boot-time rescan.
pub async fn build_pack_wiring(
    packs_dir: &Path,
    event_bus: Option<Arc<dyn EventBusEmit>>,
) -> Result<PackWiring, PackWiringError> {
    match std::fs::symlink_metadata(packs_dir) {
        // `symlink_metadata` does not follow: a symlinked packs dir reports as a
        // symlink (not a dir) and is refused, never followed.
        Ok(md) if md.is_dir() => {}
        Ok(_) => return Err(PackWiringError::NotADirectory(packs_dir.to_path_buf())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(packs_dir).map_err(|source| PackWiringError::Io {
                path: packs_dir.to_path_buf(),
                source,
            })?;
        }
        Err(source) => {
            return Err(PackWiringError::Io {
                path: packs_dir.to_path_buf(),
                source,
            });
        }
    }
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.to_path_buf()));
    registry.rescan().await.map_err(PackWiringError::Rescan)?;
    let dyn_registry: Arc<dyn PackRegistry> = registry.clone();
    let template_resolver: Arc<dyn TemplateResolver> = Arc::new(ChainedTemplateResolver::new(
        Arc::new(BuiltinTemplateRegistry::new()),
        Arc::new(PackTemplateResolver::new(dyn_registry.clone())),
    ));
    let evaluator_resolver = Arc::new(PackEvaluatorResolver::new(dyn_registry.clone()));
    let workflow_executor = Arc::new(LateBoundWorkflowExecutor::new());
    let secret_store = Arc::new(LateBoundSecretStore::new());
    let materializer = Arc::new(DefaultMaterializer::new(
        dyn_registry,
        Arc::clone(&workflow_executor) as Arc<dyn advance_pack_manager::WorkflowExecutor>,
        Arc::clone(&secret_store) as Arc<dyn advance_pack_manager::SecretStore>,
    ));
    Ok(PackWiring {
        packs_dir: packs_dir.to_path_buf(),
        registry,
        template_resolver,
        evaluator_resolver,
        materializer,
        workflow_executor,
        secret_store,
        mcp_entries: Arc::new(InMemoryMcpEntrySink::new()),
        event_bus,
    })
}

/// [`TemplateResolver`] chaining the runtime built-ins with a pack resolver.
///
/// Routing is by reference SHAPE, not by trial: a ref containing both `@` and
/// `/` is a pack FQ ref (`{pack}@{version}/…`) and goes to the pack half — its
/// error (e.g. `NotFound` for an uninstalled pack) surfaces verbatim; anything
/// else is a bare built-in name. `list()` is the concatenation
/// built-ins ++ pack FQ refs (every listed ref resolves through the same chain).
pub struct ChainedTemplateResolver {
    builtin: Arc<dyn TemplateResolver>,
    pack: Arc<dyn TemplateResolver>,
}

impl ChainedTemplateResolver {
    pub fn new(builtin: Arc<dyn TemplateResolver>, pack: Arc<dyn TemplateResolver>) -> Self {
        Self { builtin, pack }
    }

    /// `{pack}@{version}/{component…}` shape → pack half.
    pub fn is_pack_ref(template_ref: &str) -> bool {
        template_ref.contains('@') && template_ref.contains('/')
    }
}

impl TemplateResolver for ChainedTemplateResolver {
    fn resolve(&self, template_ref: &str) -> Result<TemplateContent, TemplateError> {
        if Self::is_pack_ref(template_ref) {
            self.pack.resolve(template_ref)
        } else {
            self.builtin.resolve(template_ref)
        }
    }

    fn list(&self) -> Vec<String> {
        let mut out = self.builtin.list();
        out.extend(self.pack.list());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use advance_pack_manager::{SecretStore, WorkflowExecutor};

    struct Pack;
    impl TemplateResolver for Pack {
        fn resolve(&self, r: &str) -> Result<TemplateContent, TemplateError> {
            Err(TemplateError::NotFound(format!("pack:{r}")))
        }
        fn list(&self) -> Vec<String> {
            vec!["p@1.0.0/agent-templates/t".into()]
        }
    }

    #[test]
    fn pack_ref_shape_needs_both_at_and_slash() {
        assert!(ChainedTemplateResolver::is_pack_ref(
            "p@1.0.0/agent-templates/t"
        ));
        assert!(!ChainedTemplateResolver::is_pack_ref("researcher"));
        assert!(!ChainedTemplateResolver::is_pack_ref("p@1.0.0"));
        assert!(!ChainedTemplateResolver::is_pack_ref("a/b"));
    }

    #[test]
    fn bare_names_never_reach_the_pack_half() {
        let chain =
            ChainedTemplateResolver::new(Arc::new(BuiltinTemplateRegistry::new()), Arc::new(Pack));
        let err = chain.resolve("definitely-not-a-builtin").unwrap_err();
        assert!(
            !format!("{err:?}").contains("pack:"),
            "bare name must be answered by the built-in half: {err:?}"
        );
    }

    #[tokio::test]
    async fn unbound_slots_fail_closed_at_boot() {
        let tmp = tempfile::TempDir::new().unwrap();
        let wiring = build_pack_wiring(&tmp.path().join("packs"), None)
            .await
            .unwrap();
        assert!(!wiring.workflow_executor.is_bound());
        assert!(!wiring.secret_store.is_bound());
        assert!(matches!(
            wiring
                .workflow_executor
                .spawn_child("t", Path::new("x"), &BTreeMap::new()),
            Err(PackError::NotImplemented(_))
        ));
        assert!(matches!(
            wiring
                .workflow_executor
                .register_mcp_server("c", &BTreeMap::new()),
            Err(PackError::NotImplemented(_))
        ));
        assert!(wiring.secret_store.get("anything").is_none());
        assert!(wiring.mcp_entries.is_empty());
    }
}

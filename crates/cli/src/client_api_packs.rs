//! CLI-served `PackAdminProvider` (CONTRACT-190 packs family) over the ONE production pack
//! registry (`PackWiring.registry`) and an `Installer` built from `RuntimeConfig.pack`.
//!
//! Same rules as `advance pack install|list|uninstall` (commands/pack.rs), minus stdin: the
//! request's `accepted_capabilities` IS the operator's approval decision
//! ([`AcceptedCapabilitiesApproval`]), wrapped in the same `CatalogCheckedApproval` over
//! `KNOWN_CAPABILITIES` ∪ installed resource-capability ids, with the same trust roots and
//! registry client. Installs and uninstalls rescan the shared registry, so the live runtime
//! (template resolver, evaluator resolver, tool exposure) sees the change without a restart.
//!
//! `ClientApi::handle()` is SYNC and may run on a tokio worker (the transport wraps it in
//! `spawn_blocking`); the installer is async. Each call therefore runs on an OWNED
//! current-thread runtime on a scoped OS thread — never `Handle::block_on` (workspace clippy
//! disallows it; it panics on a worker).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use advance_client_api::packs::{
    ClientPackDetail, ClientPackInstallRequest, ClientPackInstallResult, ClientPackProvide,
    ClientPackSummary, ClientPackUninstallResult,
};
use advance_client_api::{PackAdminProvider, ProviderError};
use advance_pack_manager::{
    ApprovalStrategy, CatalogCheckedApproval, ComponentKind, InMemoryPackRegistry, Installer,
    PackError, PackManifest, PackRegistry, TrustLevel,
};
use advance_runtime::config::PackConfig;
use async_trait::async_trait;

use crate::commands::pack::build_capability_catalog;
use crate::pack_registry_client::HttpsRegistryClient;

/// Approves a manifest iff every `required-capabilities` entry was accepted by the request.
/// A manifest with no requirements is approved without any list (the CLI's AC-07 short-circuit).
pub struct AcceptedCapabilitiesApproval {
    accepted: Vec<String>,
}

impl AcceptedCapabilitiesApproval {
    pub fn new(accepted: Vec<String>) -> Self {
        Self { accepted }
    }
}

#[async_trait]
impl ApprovalStrategy for AcceptedCapabilitiesApproval {
    async fn approve(&self, manifest: &PackManifest) -> Result<bool, PackError> {
        Ok(manifest
            .required_capabilities
            .iter()
            .all(|cap| self.accepted.iter().any(|a| a == cap)))
    }
}

/// The production `PackAdminProvider`.
pub struct WiredPackAdminProvider {
    registry: Arc<InMemoryPackRegistry>,
    packs_dir: PathBuf,
    config: PackConfig,
    runtime_version: String,
}

impl WiredPackAdminProvider {
    pub fn new(
        registry: Arc<InMemoryPackRegistry>,
        packs_dir: PathBuf,
        config: PackConfig,
        runtime_version: impl Into<String>,
    ) -> Self {
        Self {
            registry,
            packs_dir,
            config,
            runtime_version: runtime_version.into(),
        }
    }

    /// Run an async pack-manager call on an owned current-thread runtime (see module docs).
    fn block_on<F>(fut: F) -> Result<F::Output, ProviderError>
    where
        F: std::future::Future + Send,
        F::Output: Send,
    {
        std::thread::scope(|s| {
            s.spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| {
                        ProviderError::Unavailable(format!(
                            "pack call: failed to build the owned runtime: {e}"
                        ))
                    })?;
                Ok(runtime.block_on(fut))
            })
            .join()
            .map_err(|_| ProviderError::Unavailable("pack call panicked".into()))?
        })
    }

    fn installer(&self, approval: Arc<dyn ApprovalStrategy>) -> Result<Installer, ProviderError> {
        let catalog = build_capability_catalog(&self.registry).map_err(|e| {
            ProviderError::Unavailable(format!("cannot build the capability catalog: {e}"))
        })?;
        let approval = Arc::new(CatalogCheckedApproval::new(approval, Arc::new(catalog)));
        let fetch_timeout = Duration::from_secs(self.config.fetch_timeout_sec);
        let mut installer = Installer::new(
            self.packs_dir.clone(),
            Arc::clone(&self.registry),
            self.runtime_version.clone(),
            approval,
        )
        .with_fetch_timeout(fetch_timeout)
        .with_trust_roots(self.config.trust_roots.clone());
        if let Some(url) = &self.config.registry_url {
            let client = HttpsRegistryClient::new(url, fetch_timeout).map_err(|e| {
                ProviderError::Unavailable(format!("cannot build the registry client: {e}"))
            })?;
            installer = installer.with_registry_client(Arc::new(client));
        }
        Ok(installer)
    }
}

fn trust_str(level: TrustLevel) -> &'static str {
    match level {
        TrustLevel::Trusted => "trusted",
        TrustLevel::Untrusted => "untrusted",
    }
}

fn kind_str(kind: ComponentKind) -> &'static str {
    match kind {
        ComponentKind::Binary => "behavior-binaries",
        ComponentKind::AgentTemplate => "agent-templates",
        ComponentKind::Skill => "skills",
        ComponentKind::RunnableComponent => "components",
        ComponentKind::ChannelAdapter => "channel-adapters",
        ComponentKind::McpServer => "mcp-servers",
        ComponentKind::Preset => "presets",
        ComponentKind::Workflow => "workflows",
        ComponentKind::MemorySeed => "memory-seeds",
        ComponentKind::MetaSchemaExtension => "meta-schema-extensions",
        ComponentKind::ResourceCapability => "resource-capabilities",
    }
}

fn summary_of(meta: &advance_pack_manager::PackMetadata) -> ClientPackSummary {
    ClientPackSummary {
        name: meta.name.clone(),
        version: meta.version.clone(),
        trust_level: trust_str(meta.trust_level).to_string(),
        signed_by: meta.signed_by.clone(),
        required_capabilities: meta.required_capabilities.clone(),
    }
}

/// Project a `PackError` onto the client-safe variant set (see the trait docs).
pub fn map_pack_error(error: PackError) -> ProviderError {
    match error {
        PackError::AlreadyInstalled { name, version } => {
            ProviderError::AlreadyExists(format!("{name}@{version} is already installed"))
        }
        PackError::PackNotFound(name, version) => {
            ProviderError::NotFound(format!("{name}@{version} is not installed"))
        }
        PackError::DependentsExist {
            name,
            version,
            dependents,
        } => ProviderError::InvalidState(format!(
            "{name}@{version} is required by {}",
            dependents.join(", ")
        )),
        PackError::AdminRejected => ProviderError::Forbidden(
            "the pack requires capabilities the request did not accept".into(),
        ),
        PackError::UnknownRequiredCapability { pack, unknown } => {
            ProviderError::InvalidRequest(format!(
                "{pack} requires unknown capabilities: {}",
                unknown.join(", ")
            ))
        }
        PackError::InvalidManifest(_)
        | PackError::RuntimeVersionMismatch { .. }
        | PackError::ChecksumMismatch(..)
        | PackError::UnversionedRef(_)
        | PackError::ComponentNotFound { .. }
        | PackError::AmbiguousComponent { .. }
        | PackError::DependencyNotFound { .. }
        | PackError::DependencyVersionMismatch { .. }
        | PackError::DependencyCycle { .. }
        | PackError::DependencyDepthExceeded { .. }
        | PackError::ConstraintViolation { .. }
        | PackError::SignatureInvalid { .. } => ProviderError::InvalidRequest(error.to_string()),
        other => ProviderError::Unavailable(other.to_string()),
    }
}

impl PackAdminProvider for WiredPackAdminProvider {
    fn list_packs(&self) -> Result<Vec<ClientPackSummary>, ProviderError> {
        let mut packs: Vec<ClientPackSummary> = self
            .registry
            .list_installed()
            .iter()
            .map(summary_of)
            .collect();
        packs.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));
        Ok(packs)
    }

    fn get_pack(&self, name: &str, version: &str) -> Result<ClientPackDetail, ProviderError> {
        let meta = self
            .registry
            .list_installed()
            .into_iter()
            .find(|m| m.name == name && m.version == version)
            .ok_or_else(|| ProviderError::NotFound(format!("{name}@{version} is not installed")))?;
        let provides = self
            .registry
            .provides(name, version)
            .unwrap_or_default()
            .into_iter()
            .map(|p| ClientPackProvide {
                kind: kind_str(p.kind).to_string(),
                name: p.name,
            })
            .collect();
        Ok(ClientPackDetail {
            summary: summary_of(&meta),
            provides,
        })
    }

    fn install_pack(
        &self,
        request: &ClientPackInstallRequest,
    ) -> Result<ClientPackInstallResult, ProviderError> {
        let installer = self.installer(Arc::new(AcceptedCapabilitiesApproval::new(
            request.accepted_capabilities.clone(),
        )))?;
        let source = request.source.clone();
        let report = Self::block_on(async move { installer.install(&source).await })?
            .map_err(map_pack_error)?;
        let install_path = report
            .install_path
            .strip_prefix(&self.packs_dir)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| format!("{}@{}", report.name, report.version));
        Ok(ClientPackInstallResult {
            name: report.name,
            version: report.version,
            install_path,
        })
    }

    fn uninstall_pack(
        &self,
        name: &str,
        version: &str,
    ) -> Result<ClientPackUninstallResult, ProviderError> {
        // Uninstall never consults the approval strategy; the accepted set is irrelevant.
        let installer = self.installer(Arc::new(AcceptedCapabilitiesApproval::new(vec![])))?;
        let (name, version) = (name.to_string(), version.to_string());
        let report = Self::block_on(async move { installer.uninstall(&name, &version).await })?
            .map_err(map_pack_error)?;
        Ok(ClientPackUninstallResult {
            name: report.name,
            version: report.version,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_projection_variants() {
        assert!(matches!(
            map_pack_error(PackError::AlreadyInstalled {
                name: "a".into(),
                version: "1.0.0".into()
            }),
            ProviderError::AlreadyExists(_)
        ));
        assert!(matches!(
            map_pack_error(PackError::PackNotFound("a".into(), "1.0.0".into())),
            ProviderError::NotFound(_)
        ));
        assert!(matches!(
            map_pack_error(PackError::DependentsExist {
                name: "a".into(),
                version: "1.0.0".into(),
                dependents: vec!["b@1.0.0".into()]
            }),
            ProviderError::InvalidState(_)
        ));
        assert!(matches!(
            map_pack_error(PackError::AdminRejected),
            ProviderError::Forbidden(_)
        ));
        assert!(matches!(
            map_pack_error(PackError::InvalidManifest("x".into())),
            ProviderError::InvalidRequest(_)
        ));
        assert!(matches!(
            map_pack_error(PackError::NotImplemented("x")),
            ProviderError::Unavailable(_)
        ));
    }
}

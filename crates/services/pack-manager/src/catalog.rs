//! PACK-GAP-CLOSURE P1 (§2.4) — `required-capabilities` validated against a
//! capability catalog, as an [`ApprovalStrategy`] **decorator** (so `Installer`
//! gains no field).
//!
//! `CatalogCheckedApproval` runs at step ④: every entry of the manifest's
//! `required-capabilities` is looked up in the [`CapabilityCatalog`]; any
//! unknown name fails the install with
//! [`PackError::UnknownRequiredCapability`] BEFORE the inner strategy (and thus
//! before any interactive prompt) runs. An empty `required-capabilities` list
//! never consults the catalog, preserving the AC-07 short-circuit semantics of
//! the inner strategies.
//!
//! The composition root builds the catalog from the runtime's known capability
//! names plus the ids of every installed pack's resource-capabilities (see
//! `crates/cli/src/commands/pack.rs`).

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;

use crate::error::PackError;
use crate::install::{ApprovalContext, ApprovalStrategy};
use crate::manifest::PackManifest;

/// Answers "is this capability name something the runtime can provide?".
pub trait CapabilityCatalog: Send + Sync {
    fn is_known(&self, cap: &str) -> bool;
}

/// Fixed-set [`CapabilityCatalog`].
#[derive(Debug, Clone, Default)]
pub struct StaticCapabilityCatalog {
    caps: BTreeSet<String>,
}

impl StaticCapabilityCatalog {
    pub fn new(caps: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            caps: caps.into_iter().map(Into::into).collect(),
        }
    }

    /// Sorted view of the catalog (diagnostics / tests).
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.caps.iter().map(String::as_str)
    }
}

impl CapabilityCatalog for StaticCapabilityCatalog {
    fn is_known(&self, cap: &str) -> bool {
        self.caps.contains(cap)
    }
}

/// [`ApprovalStrategy`] decorator: catalog check first, then delegate.
pub struct CatalogCheckedApproval {
    inner: Arc<dyn ApprovalStrategy>,
    catalog: Arc<dyn CapabilityCatalog>,
}

impl CatalogCheckedApproval {
    pub fn new(inner: Arc<dyn ApprovalStrategy>, catalog: Arc<dyn CapabilityCatalog>) -> Self {
        Self { inner, catalog }
    }

    /// The catalog gate: `Err(UnknownRequiredCapability)` naming every unknown
    /// requirement (manifest order, de-duplicated), `Ok(())` otherwise.
    fn check(&self, manifest: &PackManifest) -> Result<(), PackError> {
        // Order-preserving, de-duplicated list of the unknown names so the error
        // text reads in manifest order and never repeats an entry.
        let mut seen = BTreeSet::new();
        let unknown: Vec<String> = manifest
            .required_capabilities
            .iter()
            .filter(|c| !self.catalog.is_known(c))
            .filter(|c| seen.insert((*c).clone()))
            .cloned()
            .collect();
        if !unknown.is_empty() {
            return Err(PackError::UnknownRequiredCapability {
                pack: manifest.name.clone(),
                unknown,
            });
        }
        Ok(())
    }
}

#[async_trait]
impl ApprovalStrategy for CatalogCheckedApproval {
    async fn approve(&self, manifest: &PackManifest) -> Result<bool, PackError> {
        self.check(manifest)?;
        self.inner.approve(manifest).await
    }

    /// PACK-GAP-CLOSURE P3: the signature context is forwarded verbatim so an
    /// interactive inner strategy can show the downgrade / signer.
    async fn approve_with_context(
        &self,
        manifest: &PackManifest,
        ctx: &ApprovalContext,
    ) -> Result<bool, PackError> {
        self.check(manifest)?;
        self.inner.approve_with_context(manifest, ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::{AutoApprove, AutoReject};

    fn manifest(required: &[&str]) -> PackManifest {
        let mut yaml = String::from(
            "name: foo\nversion: 1.0.0\nruntime-version: \">=0.1.0\"\nprovides: {}\nchecksums:\n  algo: sha256\n  files: {}\n",
        );
        if !required.is_empty() {
            yaml.push_str("required-capabilities:\n");
            for r in required {
                yaml.push_str(&format!("  - {r}\n"));
            }
        }
        PackManifest::from_yaml(&yaml).unwrap()
    }

    #[tokio::test]
    async fn unknown_names_are_reported_in_manifest_order_without_duplicates() {
        let approval = CatalogCheckedApproval::new(
            Arc::new(AutoApprove),
            Arc::new(StaticCapabilityCatalog::new(["fs"])),
        );
        let err = approval
            .approve(&manifest(&["teleport", "fs", "warp", "teleport"]))
            .await
            .unwrap_err();
        match err {
            PackError::UnknownRequiredCapability { pack, unknown } => {
                assert_eq!(pack, "foo");
                assert_eq!(unknown, vec!["teleport".to_string(), "warp".to_string()]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn known_names_delegate_to_inner_verdict() {
        let catalog = Arc::new(StaticCapabilityCatalog::new(["fs", "llm"]));
        let yes = CatalogCheckedApproval::new(Arc::new(AutoApprove), catalog.clone());
        assert!(yes.approve(&manifest(&["fs", "llm"])).await.unwrap());
        let no = CatalogCheckedApproval::new(Arc::new(AutoReject), catalog);
        assert!(!no.approve(&manifest(&["fs"])).await.unwrap());
    }

    #[tokio::test]
    async fn context_is_forwarded_to_the_inner_strategy() {
        struct Capture(std::sync::Mutex<Option<ApprovalContext>>);
        #[async_trait]
        impl ApprovalStrategy for Capture {
            async fn approve(&self, _: &PackManifest) -> Result<bool, PackError> {
                Ok(false)
            }
            async fn approve_with_context(
                &self,
                _: &PackManifest,
                ctx: &ApprovalContext,
            ) -> Result<bool, PackError> {
                *self.0.lock().unwrap() = Some(ctx.clone());
                Ok(true)
            }
        }
        let inner = Arc::new(Capture(std::sync::Mutex::new(None)));
        let approval = CatalogCheckedApproval::new(
            inner.clone(),
            Arc::new(StaticCapabilityCatalog::new(["fs"])),
        );
        let ctx = ApprovalContext {
            signed_by: Some("ab".repeat(32)),
            trust_downgraded: false,
        };
        assert!(approval
            .approve_with_context(&manifest(&["fs"]), &ctx)
            .await
            .unwrap());
        assert_eq!(inner.0.lock().unwrap().as_ref(), Some(&ctx));
        // The catalog gate still runs first.
        assert!(matches!(
            approval
                .approve_with_context(&manifest(&["warp"]), &ctx)
                .await,
            Err(PackError::UnknownRequiredCapability { .. })
        ));
    }

    #[tokio::test]
    async fn empty_requirements_never_consult_the_catalog() {
        struct Panicking;
        impl CapabilityCatalog for Panicking {
            fn is_known(&self, _: &str) -> bool {
                panic!("catalog must not be consulted for an empty requirement list")
            }
        }
        let approval = CatalogCheckedApproval::new(Arc::new(AutoApprove), Arc::new(Panicking));
        assert!(approval.approve(&manifest(&[])).await.unwrap());
    }
}

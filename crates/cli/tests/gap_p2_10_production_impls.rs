#![cfg(feature = "gap-p2")]
//! GAP-10 (P2) — production implementations of the pack-manager seams.
//! See docs/plans/PACK-GAP-CLOSURE.md §3.4. `SchedulerWorkflowExecutor` is covered by the
//! compensation contract (pack-manager gap_p2_04) + system journeys, not here.

use std::path::Path;
use std::sync::Arc;

use advance_cli::pack_production::{
    ClosureSecretStore, LocalDirDependencyResolver, RegistryDependencyResolver,
};
use advance_pack_manager::{DependencyResolver, PackError, RegistryClient, SecretStore, SourceRef};
use async_trait::async_trait;

#[test]
fn pi_01_closure_secret_store_exposes_only_present_keys() {
    let store = ClosureSecretStore::new(|k| (k == "a").then(|| "secret-a".to_string()));
    assert_eq!(
        store.get("a").map(|v| v.expose_secret().to_string()),
        Some("secret-a".into())
    );
    assert!(store.get("b").is_none());
}

fn mk(root: &Path, name: &str, version: &str) {
    let d = root.join(format!("{name}@{version}"));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(
        d.join("pack.yaml"),
        format!("name: {name}\nversion: {version}\n"),
    )
    .unwrap();
}

#[tokio::test]
async fn pi_02_local_dir_resolver_picks_highest_satisfying_version() {
    let tmp = tempfile::TempDir::new().unwrap();
    for v in ["1.0.0", "1.2.0", "2.0.0", "1.3.0-beta.1"] {
        mk(tmp.path(), "a", v);
    }
    let r = LocalDirDependencyResolver::new(tmp.path().to_path_buf());
    let src = r
        .resolve("a", &semver::VersionReq::parse("^1.0").unwrap())
        .await
        .unwrap();
    assert_eq!(
        src,
        SourceRef::Local(tmp.path().join("a@1.2.0")),
        "pre-release excluded, 2.0.0 out of range"
    );
    let err = r
        .resolve("a", &semver::VersionReq::parse("^3").unwrap())
        .await
        .unwrap_err();
    assert!(
        matches!(err, PackError::DependencyNotFound { .. }),
        "{err:?}"
    );
    let err = r
        .resolve("zzz", &semver::VersionReq::parse("*").unwrap())
        .await
        .unwrap_err();
    assert!(
        matches!(err, PackError::DependencyNotFound { .. }),
        "{err:?}"
    );
}

struct FakeRegistry;
#[async_trait]
impl RegistryClient for FakeRegistry {
    async fn fetch_tarball(
        &self,
        _n: &str,
        _v: &str,
        _d: &Path,
    ) -> Result<std::path::PathBuf, PackError> {
        Err(PackError::NotImplemented("not needed here"))
    }
    async fn list_versions(&self, name: &str) -> Result<Vec<semver::Version>, PackError> {
        if name != "a" {
            return Ok(vec![]);
        }
        Ok(["1.0.0", "1.4.0", "2.1.0"]
            .iter()
            .map(|v| semver::Version::parse(v).unwrap())
            .collect())
    }
}

#[tokio::test]
async fn pi_03_registry_resolver_uses_list_versions() {
    let r = RegistryDependencyResolver::new(Arc::new(FakeRegistry));
    let src = r
        .resolve("a", &semver::VersionReq::parse(">=1.2, <2").unwrap())
        .await
        .unwrap();
    assert_eq!(
        src,
        SourceRef::Registry {
            name: "a".into(),
            version: "1.4.0".into()
        }
    );
    assert!(matches!(
        r.resolve("b", &semver::VersionReq::parse("*").unwrap())
            .await,
        Err(PackError::DependencyNotFound { .. })
    ));
}

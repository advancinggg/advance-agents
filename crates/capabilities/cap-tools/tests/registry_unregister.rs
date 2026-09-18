//! `LazyToolRegistry::unregister_binary` / `is_registered` — an installed pack's skill tool
//! leaves the registry on uninstall and comes back on reinstall.

use cap_tools::{LazyRegistryConfig, LazyToolRegistry, ToolError, ToolRegistry};

#[tokio::test]
async fn a_registered_binary_can_be_removed_and_registered_again() {
    let registry = LazyToolRegistry::new(LazyRegistryConfig::default());
    registry
        .register_binary("skill::agenda", b"not-yet-loaded".to_vec())
        .await;
    assert!(registry.is_registered("skill::agenda").await);
    assert!(registry
        .list()
        .await
        .iter()
        .any(|t| t.id == "skill::agenda"));

    assert!(registry.unregister_binary("skill::agenda").await);
    assert!(!registry.is_registered("skill::agenda").await);
    assert!(!registry
        .list()
        .await
        .iter()
        .any(|t| t.id == "skill::agenda"));
    assert!(matches!(
        registry
            .invoke("skill::agenda", "detach-occurrence", b"{}")
            .await,
        Err(ToolError::NotFound(_))
    ));
    assert!(
        !registry.unregister_binary("skill::agenda").await,
        "removing twice reports nothing was registered"
    );

    registry
        .register_binary("skill::agenda", b"again".to_vec())
        .await;
    assert!(registry.is_registered("skill::agenda").await);
}

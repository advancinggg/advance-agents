use super::*;
use crate::test_support::{
    fixture_runtime_config, MockEventBusEmit, MockHttpSecurityChain, MockRuntimeConfigProvider,
};

#[test]
fn module_001_ac31_vlm_catalog_getter_returns_the_shared_arc() {
    let catalog = Arc::new(crate::catalog::ModelProfileCatalog::new());
    let vlm = LlmGatewayVlm::new(
        Arc::new(MockRuntimeConfigProvider::new(fixture_runtime_config())),
        Arc::new(MockHttpSecurityChain::default()),
        Arc::new(MockEventBusEmit::default()),
        "test-agent".into(),
    )
    .with_shared_catalog(Arc::clone(&catalog));
    assert!(Arc::ptr_eq(&vlm.catalog(), &catalog));
}

//! The production `tool-invoke` host fn holds a `CompositeToolRegistry`, not the lazy
//! registry itself. The caller identity must survive the wrapper: an identity-bearing host
//! tool (the `data` tool) refuses the anonymous path, so a dropped `agent_id` would make every
//! agent call fail.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cap_tools::web::{CompositeToolRegistry, HostToolRegistry};
use cap_tools::{
    HostTool, LazyRegistryConfig, LazyToolRegistry, MethodInfo, ToolDescription, ToolError,
    ToolRegistry,
};

/// Records who called; refuses anonymous calls like the `data` tool does.
struct WhoCalls {
    seen: Mutex<Vec<String>>,
}

#[async_trait]
impl HostTool for WhoCalls {
    fn describe(&self) -> ToolDescription {
        ToolDescription {
            description: "records the caller".into(),
            methods: vec![MethodInfo {
                name: "ping".into(),
                description: None,
                input_schema: None,
                output_schema: None,
                idempotent: Some(true),
            }],
        }
    }

    async fn execute(&self, _method: &str, _params: &[u8]) -> Result<Vec<u8>, ToolError> {
        Err(ToolError::PermissionDenied("anonymous".into()))
    }

    async fn execute_as(
        &self,
        agent_id: &str,
        _method: &str,
        _params: &[u8],
    ) -> Result<Vec<u8>, ToolError> {
        self.seen.lock().unwrap().push(agent_id.to_string());
        Ok(b"{}".to_vec())
    }
}

#[tokio::test]
async fn the_composite_registry_forwards_the_caller_identity() {
    let wasm = Arc::new(LazyToolRegistry::new(LazyRegistryConfig::default()));
    let tool = Arc::new(WhoCalls {
        seen: Mutex::new(Vec::new()),
    });
    wasm.register_host("who", tool.clone()).await.unwrap();
    let composite: Arc<dyn ToolRegistry> = Arc::new(CompositeToolRegistry {
        host: Arc::new(HostToolRegistry::new()),
        wasm,
    });

    composite
        .invoke_as("alice", "who", "ping", b"{}")
        .await
        .expect("identity-bearing call succeeds through the composite");
    assert_eq!(*tool.seen.lock().unwrap(), vec!["alice".to_string()]);
    assert!(matches!(
        composite.invoke("who", "ping", b"{}").await,
        Err(ToolError::PermissionDenied(_))
    ));
}

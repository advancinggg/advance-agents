//! GAP-05 (P2, registry half) — host-native tools in `LazyToolRegistry`.
//! Tool WASMs only link WASI; a store-backed
//! tool must be host code, registered under the same id namespace and subject to the same
//! fail-closed result cap.

use std::sync::Arc;

use cap_tools::{
    HostTool, LazyRegistryConfig, LazyToolRegistry, MethodInfo, ToolDescription, ToolError,
    ToolRegistry,
};

struct Echo;

#[async_trait::async_trait]
impl HostTool for Echo {
    fn describe(&self) -> ToolDescription {
        ToolDescription {
            description: "echoes its params".into(),
            methods: vec![MethodInfo {
                name: "echo".into(),
                description: Some("returns params verbatim".into()),
                input_schema: None,
                output_schema: None,
                idempotent: Some(true),
            }],
        }
    }
    async fn execute(&self, method: &str, params: &[u8]) -> Result<Vec<u8>, ToolError> {
        match method {
            "echo" => Ok(params.to_vec()),
            other => Err(ToolError::MethodNotFound(other.to_string())),
        }
    }
}

fn registry(max_result_bytes: usize) -> LazyToolRegistry {
    LazyToolRegistry::new(LazyRegistryConfig {
        max_result_bytes,
        ..LazyRegistryConfig::default()
    })
}

#[tokio::test]
async fn ht_01_register_list_invoke() {
    let reg = registry(64);
    reg.register_host("echo", Arc::new(Echo)).await.unwrap();
    let listed = reg.list().await;
    let info = listed
        .iter()
        .find(|t| t.id == "echo")
        .expect("host tool listed alongside WASM tools");
    assert_eq!(info.methods.len(), 1);
    assert_eq!(info.methods[0].name, "echo");
    assert_eq!(reg.invoke("echo", "echo", b"hi").await.unwrap(), b"hi");
}

#[tokio::test]
async fn ht_02_result_cap_is_fail_closed_for_host_tools_too() {
    let reg = registry(8);
    reg.register_host("echo", Arc::new(Echo)).await.unwrap();
    assert_eq!(
        reg.invoke("echo", "echo", b"12345678").await.unwrap().len(),
        8
    );
    let err = reg.invoke("echo", "echo", b"123456789").await.unwrap_err();
    assert!(
        matches!(err, ToolError::OutputValidationFailed(_)),
        "over-cap result must fail closed, got {err:?}"
    );
}

#[tokio::test]
async fn ht_03_duplicate_id_and_unknown_method_are_rejected() {
    let reg = registry(64);
    reg.register_host("echo", Arc::new(Echo)).await.unwrap();
    let err = reg
        .register_host("echo", Arc::new(Echo))
        .await
        .expect_err("second registration under the same id");
    assert!(matches!(err, ToolError::InvocationFailed(_)), "{err:?}");
    let err = reg.invoke("echo", "nope", b"").await.unwrap_err();
    assert!(matches!(err, ToolError::MethodNotFound(_)), "{err:?}");
    let err = reg.invoke("ghost", "echo", b"").await.unwrap_err();
    assert!(matches!(err, ToolError::NotFound(_)), "{err:?}");
}

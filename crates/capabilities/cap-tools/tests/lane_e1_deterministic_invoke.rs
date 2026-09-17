//! Lane E1 — caller identity for host tools + deterministic tool invocation
//! (lane E1). `data` needs the calling agent; `data.apply` needs a
//! reducer whose clock and randomness the host controls.

use std::sync::{Arc, Mutex};

use advance_runtime::component_loader::{ComponentRuntime, ToolEngineHandle};
use advance_runtime::config::WasmConfig;
use cap_tools::{
    DeterministicCtx, HostTool, LazyRegistryConfig, LazyToolRegistry, MethodInfo, ToolDescription,
    ToolError, ToolRegistry,
};
use chrono::{DateTime, Utc};

/// A tool whose single method `now` returns the WASI wall clock as RFC 3339 text
/// (source under `fixtures/clock_tool`, committed like `echo_tool.component.wasm`).
const CLOCK_TOOL_WASM: &[u8] = include_bytes!("fixtures/clock_tool.component.wasm");

struct WhoAmI {
    seen: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl HostTool for WhoAmI {
    fn describe(&self) -> ToolDescription {
        ToolDescription {
            description: "returns the calling agent".into(),
            methods: vec![MethodInfo {
                name: "who".into(),
                description: None,
                input_schema: None,
                output_schema: None,
                idempotent: Some(true),
            }],
        }
    }
    async fn execute(&self, _method: &str, _params: &[u8]) -> Result<Vec<u8>, ToolError> {
        Err(ToolError::PermissionDenied(
            "identity-bearing tool refuses anonymous invocation".into(),
        ))
    }
    async fn execute_as(
        &self,
        agent_id: &str,
        method: &str,
        _params: &[u8],
    ) -> Result<Vec<u8>, ToolError> {
        match method {
            "who" => {
                self.seen.lock().unwrap().push(agent_id.to_string());
                Ok(agent_id.as_bytes().to_vec())
            }
            other => Err(ToolError::MethodNotFound(other.to_string())),
        }
    }
}

fn tool_engine() -> ToolEngineHandle {
    let cfg = WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    };
    ComponentRuntime::new(&cfg)
        .expect("construct ComponentRuntime")
        .tool_engine_handle()
}

#[tokio::test]
async fn e1_invoke_as_delivers_the_calling_agent_to_host_tools() {
    let reg = LazyToolRegistry::new(LazyRegistryConfig::default());
    let tool = Arc::new(WhoAmI {
        seen: Mutex::new(vec![]),
    });
    reg.register_host("whoami", tool.clone()).await.unwrap();

    let out = reg
        .invoke_as("alice", "whoami", "who", b"{}")
        .await
        .unwrap();
    assert_eq!(out, b"alice");
    assert_eq!(*tool.seen.lock().unwrap(), vec!["alice".to_string()]);

    let err = reg.invoke("whoami", "who", b"{}").await.unwrap_err();
    assert!(
        matches!(err, ToolError::PermissionDenied(_)),
        "the identity-less path reaches `execute`, which this tool refuses: {err:?}"
    );
}

#[tokio::test]
async fn e1_invoke_deterministic_freezes_the_wall_clock() {
    let reg = LazyToolRegistry::new_with_engine(LazyRegistryConfig::default(), tool_engine());
    reg.register_binary("clock", CLOCK_TOOL_WASM.to_vec()).await;

    let frozen: DateTime<Utc> = "2026-09-17T08:00:00Z".parse().unwrap();
    let ctx = || DeterministicCtx {
        now: frozen,
        seed: 7,
    };
    let first = reg
        .invoke_deterministic("clock", "now", b"{}", ctx())
        .await
        .expect("deterministic invoke");
    let second = reg
        .invoke_deterministic("clock", "now", b"{}", ctx())
        .await
        .unwrap();
    assert_eq!(first, second, "same ctx, same bytes");
    assert_eq!(
        String::from_utf8(first).unwrap().trim(),
        "2026-09-17T08:00:00Z",
        "the guest's wall clock IS the injected now"
    );

    let real = reg.invoke("clock", "now", b"{}").await.unwrap();
    assert_ne!(
        String::from_utf8(real).unwrap().trim(),
        "2026-09-17T08:00:00Z",
        "the ordinary path keeps the system clock"
    );
}

//! MODULE-017 Slice F — `agent-tools` observability emit integration tests
//! (T75-T79). Drives the real `AgentToolsInvokeHandler` / `AgentToolsListHandler`
//! through the `HostFunctionHandler::call` boundary with a `RecordingEmitter`.

mod common;

use std::sync::Arc;

use advance_runtime::host_registry::{
    HostCallContext, HostFunctionHandler, HostRegistry, InMemoryHostRegistry,
};
use async_trait::async_trait;
use cap_tools::{
    register_agent_tools, AgentToolsInvokeHandler, AgentToolsListHandler, MethodInfo, ToolError,
    ToolInfo, ToolInstance, ToolRegistry,
};
use wasmtime::component::Val;

use common::{NoopEmitter, NoopGuard, RecordingEmitter};

fn ctx() -> HostCallContext {
    HostCallContext {
        agent_id: "agent-1".into(),
        trace_id: "trace-1".into(),
        turn_id: None,
        capability: "tools".into(),
        function: "advance:runtime/agent-tools::tool-invoke".into(),
        run_id: Some("run-9".into()),
        iteration: None,
    }
}

/// Registry that returns Ok bytes for "echo" / errors otherwise — used by T76.
struct OkRegistry;

#[async_trait]
impl ToolRegistry for OkRegistry {
    async fn load(&self, _: &str) -> Result<ToolInstance, ToolError> {
        Err(ToolError::NotFound("unused".into()))
    }
    async fn invoke(&self, tool_id: &str, _: &str, params: &[u8]) -> Result<Vec<u8>, ToolError> {
        if tool_id == "echo" {
            Ok(params.to_vec())
        } else {
            Err(ToolError::NotFound(tool_id.into()))
        }
    }
    async fn list(&self) -> Vec<ToolInfo> {
        vec![ToolInfo {
            id: "echo".into(),
            description: "echo".into(),
            methods: vec![MethodInfo {
                name: "say".into(),
                description: None,
                input_schema: None,
                output_schema: None,
                idempotent: Some(true),
            }],
        }]
    }
    async fn evict_lru(&self) {}
}

// Empty registry: all invokes miss with NotFound.
struct EmptyRegistry;

#[async_trait]
impl ToolRegistry for EmptyRegistry {
    async fn load(&self, id: &str) -> Result<ToolInstance, ToolError> {
        Err(ToolError::NotFound(id.into()))
    }
    async fn invoke(&self, id: &str, _: &str, _: &[u8]) -> Result<Vec<u8>, ToolError> {
        Err(ToolError::NotFound(id.into()))
    }
    async fn list(&self) -> Vec<ToolInfo> {
        Vec::new()
    }
    async fn evict_lru(&self) {}
}

// MODULE-017-T75 — invoke against empty registry → tool.invoke THEN tool.error.
#[tokio::test]
async fn t75_invoke_emits_invoke_then_error() {
    let rec = Arc::new(RecordingEmitter::default());
    let handler = AgentToolsInvokeHandler {
        tools: Arc::new(EmptyRegistry),
        emitter: rec.clone(),
        repetition_guard: Arc::new(NoopGuard),
    };
    let params = vec![
        Val::String("nope".into()),
        Val::String("m".into()),
        Val::List(vec![Val::U8(1)]),
    ];
    handler.call(ctx(), params, 1).await.unwrap();
    assert_eq!(rec.types(), vec!["tool.invoke", "tool.error"]);
    let evs = rec.snapshot();
    assert_eq!(evs[0].payload["tool_id"], "nope");
    assert_eq!(evs[0].payload["method"], "m");
    assert_eq!(evs[1].payload["error_type"], "not-found");
    // Envelope plumbs agent_id / trace_id / run_id from HostCallContext.
    assert_eq!(evs[0].agent_id, "agent-1");
    assert_eq!(evs[0].trace_id, "trace-1");
    assert_eq!(evs[0].run_id.as_deref(), Some("run-9"));
}

// MODULE-017-T76 — successful invoke → tool.invoke THEN tool.result(result_size).
#[tokio::test]
async fn t76_invoke_emits_invoke_then_result() {
    let rec = Arc::new(RecordingEmitter::default());
    let handler = AgentToolsInvokeHandler {
        tools: Arc::new(OkRegistry),
        emitter: rec.clone(),
        repetition_guard: Arc::new(NoopGuard),
    };
    let params = vec![
        Val::String("echo".into()),
        Val::String("say".into()),
        Val::List(vec![Val::U8(1), Val::U8(2), Val::U8(3)]),
    ];
    handler.call(ctx(), params, 1).await.unwrap();
    assert_eq!(rec.types(), vec!["tool.invoke", "tool.result"]);
    let evs = rec.snapshot();
    assert_eq!(evs[1].payload["tool_id"], "echo");
    assert_eq!(evs[1].payload["result_size"], 3);
    assert!(evs[1].duration_ms.is_some());
}

// MODULE-017-T77 — list-tools → tool.invoke + tool.result with sentinel,
// 2 events regardless of entry count.
#[tokio::test]
async fn t77_list_emits_invoke_then_result_sentinel() {
    let rec = Arc::new(RecordingEmitter::default());
    let handler = AgentToolsListHandler {
        tools: Arc::new(OkRegistry),
        emitter: rec.clone(),
    };
    handler.call(ctx(), vec![], 1).await.unwrap();
    assert_eq!(rec.types(), vec!["tool.invoke", "tool.result"]);
    let evs = rec.snapshot();
    assert_eq!(evs[0].payload["tool_id"], "");
    assert_eq!(evs[0].payload["method"], "list-tools");
    assert_eq!(evs[1].payload["method"], "list-tools");
    assert_eq!(evs[1].payload["result_size"], 1);

    // Empty registry → still exactly 2 events, result_size 0.
    let rec0 = Arc::new(RecordingEmitter::default());
    let handler0 = AgentToolsListHandler {
        tools: Arc::new(EmptyRegistry),
        emitter: rec0.clone(),
    };
    handler0.call(ctx(), vec![], 1).await.unwrap();
    assert_eq!(rec0.types(), vec!["tool.invoke", "tool.result"]);
    assert_eq!(rec0.snapshot()[1].payload["result_size"], 0);
}

// MODULE-017-T78 — decode failure → tool.error only (no preceding tool.invoke).
#[tokio::test]
async fn t78_decode_failure_emits_error_only() {
    let rec = Arc::new(RecordingEmitter::default());
    let handler = AgentToolsInvokeHandler {
        tools: Arc::new(EmptyRegistry),
        emitter: rec.clone(),
        repetition_guard: Arc::new(NoopGuard),
    };
    // Only 2 Vals — decode requires 3 → InputValidationFailed before any call.
    let params = vec![Val::String("t".into()), Val::String("m".into())];
    handler.call(ctx(), params, 1).await.unwrap();
    assert_eq!(rec.types(), vec!["tool.error"]);
    assert_eq!(
        rec.snapshot()[0].payload["error_type"],
        "input-validation-failed"
    );
}

// Supplementary — register_agent_tools wires both handlers with the emitter arg
// (NoopEmitter) without panicking; 2 specs registered.
#[test]
fn register_with_emitter_smoke() {
    let registry: Arc<dyn HostRegistry> = Arc::new(InMemoryHostRegistry::new());
    let tools: Arc<dyn ToolRegistry> = Arc::new(EmptyRegistry);
    register_agent_tools(&*registry, tools, Arc::new(NoopEmitter));
    assert_eq!(registry.lookup("tools").len(), 2);
}

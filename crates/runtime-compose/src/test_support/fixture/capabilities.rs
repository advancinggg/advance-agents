//! Capability / host-function / native-tool knobs on the fixture extension.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::api::async_trait;
use crate::api::{
    CapParams, ComposeCx, GrantDecision, HostCallContext, HostCallError, HostFunctionHandler,
    HostTool, MethodInfo, ToolDescription, ToolError, Val,
};

use super::FixtureRecord;

pub const PROBE_CAPABILITY: &str = "fixture.probe";
pub const PROBE_NAMESPACE: &str = "fixture:probe/host@0.1.0";
pub const PROBE_FUNCTION: &str = "call";
pub const ECHO_TOOL: &str = "fixture.echo";

#[derive(Clone)]
pub struct FixtureHostFn {
    pub capability: &'static str,
    pub namespace: &'static str,
    pub name: &'static str,
}

#[derive(Clone)]
pub struct FixtureTool {
    pub id: &'static str,
}

#[derive(Clone, Default)]
pub struct FixtureSpec {
    pub capabilities: &'static [&'static str],
    pub host_functions: Vec<FixtureHostFn>,
    pub tools: Vec<FixtureTool>,
}

impl FixtureSpec {
    /// capabilities `[fixture.probe]`; host function `fixture.probe` →
    /// `fixture:probe/host@0.1.0::call` (no PanicAnswer: the function returns
    /// `result<string, string>`, so the automatic in-band answer applies);
    /// tool `fixture.echo`.
    pub fn standard() -> Self {
        Self {
            capabilities: &[PROBE_CAPABILITY],
            host_functions: vec![FixtureHostFn {
                capability: PROBE_CAPABILITY,
                namespace: PROBE_NAMESPACE,
                name: PROBE_FUNCTION,
            }],
            tools: vec![FixtureTool { id: ECHO_TOOL }],
        }
    }
}

pub struct ProbeHandler {
    pub(crate) record: Arc<FixtureRecord>,
    pub(crate) cx: ComposeCx,
}

impl HostFunctionHandler for ProbeHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        self.record.host_calls.fetch_add(1, Ordering::SeqCst);
        let input = match params.as_slice() {
            [Val::String(s)] => s.clone(),
            _ => String::new(),
        };
        if input == "panic-sync" {
            panic!("fixture host function panic (sync)");
        }
        if let Some(cap) = input.strip_prefix("grant:") {
            let decision = self.cx.grants().check(cap, &CapParams::empty());
            let d = match decision {
                GrantDecision::Allow => "allow",
                GrantDecision::Deny(_) => "deny",
            };
            let agent = ctx.agent_id;
            let reply = format!("probe:grant:{cap}={d} agent={agent}");
            return Box::pin(async move {
                Ok(vec![Val::Result(Ok(Some(Box::new(Val::String(reply)))))])
            });
        }
        Box::pin(async move {
            if input == "panic" {
                panic!("fixture host function panic");
            }
            Ok(vec![Val::Result(Ok(Some(Box::new(Val::String(format!(
                "probe:{input}"
            ))))))])
        })
    }
}

pub struct EchoTool {
    pub(crate) record: Arc<FixtureRecord>,
}

#[async_trait]
impl HostTool for EchoTool {
    fn describe(&self) -> ToolDescription {
        ToolDescription {
            description: "fixture echo".into(),
            methods: vec![
                MethodInfo {
                    name: "echo".into(),
                    description: None,
                    input_schema: None,
                    output_schema: None,
                    idempotent: None,
                },
                MethodInfo {
                    name: "panic".into(),
                    description: None,
                    input_schema: None,
                    output_schema: None,
                    idempotent: None,
                },
            ],
        }
    }

    async fn execute(&self, method: &str, params: &[u8]) -> Result<Vec<u8>, ToolError> {
        self.record.tool_calls.fetch_add(1, Ordering::SeqCst);
        match method {
            "echo" => Ok(params.to_vec()),
            "panic" => panic!("fixture tool panic"),
            other => Err(ToolError::MethodNotFound(other.to_string())),
        }
    }
}

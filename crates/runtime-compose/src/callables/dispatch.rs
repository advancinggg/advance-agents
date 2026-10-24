//! Layer 3 dispatcher: model-facing name → Layer 2 execution object.

use std::sync::{Arc, RwLock};
use std::time::Instant;

use advance_runtime::callable_registry::{
    CallableDefinition, CallableError, CallableOutcome, CallableRegistry, CallableSource,
    CallableSpec,
};
use advance_runtime::circuit_breaker::CircuitBreakerBus;
use advance_runtime::host_registry::HostCallContext;
use advance_shared_types::capability::{CapParams, GrantDecision, McpToolEntry, ToolEntry};
use advance_shared_types::event::Event;
use advance_shared_types::repetition::{RepetitionDecision, ToolCallSignature};
use advance_shared_types::traits::{
    CallableInventoryReader, EventBusEmit, GrantCheck, RepetitionGuardCheck,
};
use cap_llm::ToolDefinition;
use cap_mcp::McpGate;
use cap_tools::{normalize_callable_name, ToolRegistry};
use serde_json::Value;

use super::catalog::{project_for_caps, ProjectedCatalog};

/// Same function id `invoke-mcp-tool` presents to GrantCheck (ADR D9-a / V5).
pub const INVOKE_MCP_TOOL_FUNCTION: &str = "advance:runtime/mcp-client@0.1.0::invoke-mcp-tool";

/// Same function id `tool-invoke` presents to GrantCheck.
pub const TOOL_INVOKE_FUNCTION: &str = "advance:runtime/agent-tools@0.1.0::tool-invoke";

/// Byte cap on callable results (harness-result-caps: head+tail, fail-open).
const RESULT_CAP_BYTES: usize = 32 * 1024;

/// Per-agent declared-capability lookup (L0).
pub trait AgentCapsLookup: Send + Sync {
    fn capabilities(&self, agent_id: &str) -> Vec<String>;
}

/// Fixed cap set for every agent (root daemon / tests).
pub struct StaticCaps(pub Vec<String>);

impl AgentCapsLookup for StaticCaps {
    fn capabilities(&self, _agent_id: &str) -> Vec<String> {
        self.0.clone()
    }
}

/// Tree-backed lookup with a declared-cap fallback (root daemon / children).
pub struct TreeCapsLookup {
    tree: Option<Arc<dyn advance_shared_types::agent_tree::AgentTreeSnapshot>>,
    fallback: Vec<String>,
}

impl TreeCapsLookup {
    pub fn new(
        tree: Option<Arc<dyn advance_shared_types::agent_tree::AgentTreeSnapshot>>,
        fallback: Vec<String>,
    ) -> Self {
        Self { tree, fallback }
    }
}

impl AgentCapsLookup for TreeCapsLookup {
    fn capabilities(&self, agent_id: &str) -> Vec<String> {
        if let Some(tree) = &self.tree {
            let caps = tree.capabilities(agent_id);
            if !caps.is_empty() {
                return caps
                    .into_iter()
                    .map(|c| c.id.as_str().to_string())
                    .collect();
            }
        }
        self.fallback.clone()
    }
}

/// GrantCheck arguments `invoke-mcp-tool` and `invoke-callable("<server>__<tool>")`
/// both pass (ADR D9-a).
pub fn mcp_invoke_grant_parts(server: &str, tool: &str) -> (&'static str, &'static str, CapParams) {
    (
        "mcp",
        INVOKE_MCP_TOOL_FUNCTION,
        CapParams::new(serde_json::json!({ "servers": server, "tool-patterns": tool })),
    )
}

struct McpDispatch {
    client: Arc<cap_mcp::McpClient>,
    gate: McpGate,
}

/// Process-global Layer 3 dispatcher. WASM/MCP inventories late-bind because
/// the tool registry is created after the LLM gateway.
pub struct CallableDispatcher {
    host: Arc<dyn CallableRegistry>,
    caps: Arc<dyn AgentCapsLookup>,
    grant: Arc<dyn GrantCheck>,
    breaker: Arc<dyn CircuitBreakerBus>,
    repetition: RwLock<Arc<dyn RepetitionGuardCheck>>,
    events: Arc<dyn EventBusEmit>,
    inventory: RwLock<Option<Arc<dyn CallableInventoryReader>>>,
    wasm: RwLock<Option<Arc<dyn ToolRegistry>>>,
    mcp: RwLock<Option<McpDispatch>>,
    gateway: RwLock<Option<Arc<cap_llm::LlmGateway>>>,
}

impl CallableDispatcher {
    pub fn new(
        host: Arc<dyn CallableRegistry>,
        caps: Arc<dyn AgentCapsLookup>,
        grant: Arc<dyn GrantCheck>,
        breaker: Arc<dyn CircuitBreakerBus>,
        repetition: Arc<dyn RepetitionGuardCheck>,
        events: Arc<dyn EventBusEmit>,
    ) -> Self {
        Self {
            host,
            caps,
            grant,
            breaker,
            repetition: RwLock::new(repetition),
            events,
            inventory: RwLock::new(None),
            wasm: RwLock::new(None),
            mcp: RwLock::new(None),
            gateway: RwLock::new(None),
        }
    }

    pub fn bind_inventory(&self, inventory: Arc<dyn CallableInventoryReader>) {
        *self.inventory.write().unwrap_or_else(|e| e.into_inner()) = Some(inventory);
    }

    pub fn bind_wasm(&self, registry: Arc<dyn ToolRegistry>) {
        *self.wasm.write().unwrap_or_else(|e| e.into_inner()) = Some(registry);
    }

    pub fn bind_mcp(&self, client: Arc<cap_mcp::McpClient>, gate: McpGate) {
        *self.mcp.write().unwrap_or_else(|e| e.into_inner()) = Some(McpDispatch { client, gate });
    }

    pub fn bind_repetition(&self, guard: Arc<dyn RepetitionGuardCheck>) {
        *self.repetition.write().unwrap_or_else(|e| e.into_inner()) = guard;
    }

    pub fn bind_gateway(&self, gateway: Arc<cap_llm::LlmGateway>) {
        *self.gateway.write().unwrap_or_else(|e| e.into_inner()) = Some(gateway);
    }

    pub fn project(&self, agent_id: &str) -> ProjectedCatalog {
        let caps = self.caps.capabilities(agent_id);
        let host = self.host.list_for_capabilities(&caps);
        let (wasm, mcp) = self.inventories(agent_id, &caps);
        project_for_caps(host, wasm, mcp, &caps)
    }

    pub fn list(&self, agent_id: &str) -> Result<Vec<CallableDefinition>, CallableError> {
        Ok(self.project(agent_id).entries)
    }

    pub async fn invoke(
        &self,
        ctx: HostCallContext,
        call_id: String,
        name: String,
        arguments: String,
    ) -> Result<CallableOutcome, CallableError> {
        let started = Instant::now();
        let catalog_name = normalize_callable_name(&name);
        let projected = self.project(&ctx.agent_id);
        let entry = projected
            .entries
            .iter()
            .find(|e| e.name == catalog_name || e.name == name)
            .cloned()
            .ok_or_else(|| CallableError::NotFound(name.clone()))?;

        let args = parse_arguments(&arguments)?;
        validate_schema(&entry.parameters, &args)?;

        let result = match entry.source {
            CallableSource::HostFn => {
                let spec = self
                    .host
                    .lookup(&entry.name)
                    .ok_or_else(|| CallableError::NotFound(entry.name.clone()))?;
                self.invoke_host_fn(&ctx, spec, call_id.clone(), args).await
            }
            CallableSource::WasmTool => {
                self.invoke_wasm(&ctx, &entry.name, call_id.clone(), &arguments)
                    .await
            }
            CallableSource::McpTool => {
                self.invoke_mcp(&ctx, &entry.name, call_id.clone(), arguments.as_bytes())
                    .await
            }
        };

        let duration_ms = started.elapsed().as_millis() as u64;
        let is_error = match &result {
            Ok(o) => o.is_error,
            Err(_) => true,
        };
        self.events.emit(Event::observability(
            "callable.invoked",
            ctx.agent_id.clone(),
            serde_json::json!({
                "call_id": call_id,
                "name": entry.name,
                "source": entry.source.as_wit_name(),
                "is_error": is_error,
            }),
            Some(duration_ms),
        ));

        if let Ok(outcome) = &result {
            if let (Some(gw), Some(turn_id)) = (
                self.gateway
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone(),
                ctx.turn_id.as_deref(),
            ) {
                gw.record_tool_result(
                    &ctx.agent_id,
                    turn_id,
                    &outcome.call_id,
                    &entry.name,
                    &outcome.content,
                );
            }
        }
        result
    }

    fn inventories(&self, agent_id: &str, caps: &[String]) -> (Vec<ToolEntry>, Vec<McpToolEntry>) {
        let inv = self
            .inventory
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let wasm = if caps.iter().any(|c| c == "tools") {
            inv.as_ref()
                .map(|i| i.list_wasm_tools(agent_id))
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let mcp = if caps.iter().any(|c| c == "mcp") {
            inv.as_ref()
                .map(|i| i.list_mcp_tools(agent_id))
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        (wasm, mcp)
    }

    async fn invoke_host_fn(
        &self,
        ctx: &HostCallContext,
        spec: CallableSpec,
        call_id: String,
        args: Value,
    ) -> Result<CallableOutcome, CallableError> {
        match self.grant.check(
            &ctx.agent_id,
            &spec.capability,
            &spec.original_function,
            &CapParams::empty(),
        ) {
            GrantDecision::Allow => {}
            GrantDecision::Deny(reason) => return Err(CallableError::PermissionDenied(reason)),
        }
        if let Some(reason) = self.breaker.is_open_capability(&spec.capability) {
            return Err(CallableError::Internal(format!(
                "circuit-breaker: {reason}"
            )));
        }
        let sig = ToolCallSignature {
            tool_id: spec.name.clone(),
            method: "invoke".into(),
            params_hash: params_signature_hash(args.to_string().as_bytes()),
        };
        let guard = self
            .repetition
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let RepetitionDecision::Terminate(reason) = guard.record_tool_call(&ctx.agent_id, sig) {
            return Err(CallableError::RepetitionTerminated(reason));
        }
        let inner_ctx = HostCallContext {
            agent_id: ctx.agent_id.clone(),
            trace_id: ctx.trace_id.clone(),
            turn_id: ctx.turn_id.clone(),
            capability: spec.capability.clone(),
            function: spec.original_function.clone(),
            run_id: ctx.run_id.clone(),
            iteration: ctx.iteration,
        };
        spec.handler.call(inner_ctx, call_id, args).await
    }

    async fn invoke_wasm(
        &self,
        ctx: &HostCallContext,
        name: &str,
        call_id: String,
        arguments: &str,
    ) -> Result<CallableOutcome, CallableError> {
        match self.grant.check(
            &ctx.agent_id,
            "tools",
            TOOL_INVOKE_FUNCTION,
            &CapParams::empty(),
        ) {
            GrantDecision::Allow => {}
            GrantDecision::Deny(reason) => return Err(CallableError::PermissionDenied(reason)),
        }
        let (tool_id, method) = split_method_name(name);
        let wasm = self
            .wasm
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or_else(|| CallableError::NotFound(name.to_string()))?;
        match wasm
            .invoke_as(&ctx.agent_id, &tool_id, &method, arguments.as_bytes())
            .await
        {
            Ok(bytes) => Ok(CallableOutcome {
                call_id,
                content: cap_result(String::from_utf8_lossy(&bytes).into_owned()),
                is_error: false,
            }),
            Err(err) => Ok(CallableOutcome {
                call_id,
                content: cap_result(err.to_string()),
                is_error: true,
            }),
        }
    }

    async fn invoke_mcp(
        &self,
        ctx: &HostCallContext,
        name: &str,
        call_id: String,
        arguments: &[u8],
    ) -> Result<CallableOutcome, CallableError> {
        let (server, tool) = split_method_name(name);
        let (client, gate) = {
            let mcp = self.mcp.read().unwrap_or_else(|e| e.into_inner());
            let mcp = mcp
                .as_ref()
                .ok_or_else(|| CallableError::NotFound(name.to_string()))?;
            (Arc::clone(&mcp.client), mcp.gate.clone())
        };
        // Same GrantCheck as invoke-mcp-tool (V5 / D9-a).
        if let Err(denied) =
            gate.check_tool(&ctx.agent_id, INVOKE_MCP_TOOL_FUNCTION, &server, &tool)
        {
            return Err(CallableError::PermissionDenied(denied.to_string()));
        }
        match client
            .invoke_tool(Some(&ctx.agent_id), &server, &tool, arguments)
            .await
        {
            Ok(bytes) => {
                let is_error = mcp_tool_failed(&bytes);
                Ok(CallableOutcome {
                    call_id,
                    content: cap_result(String::from_utf8_lossy(&bytes).into_owned()),
                    is_error,
                })
            }
            Err(err) => Ok(CallableOutcome {
                call_id,
                content: cap_result(err.to_string()),
                is_error: true,
            }),
        }
    }
}

impl cap_llm::CallableCatalogPort for CallableDispatcher {
    fn list_for_agent(&self, agent_id: &str) -> Vec<ToolDefinition> {
        self.project(agent_id)
            .entries
            .into_iter()
            .map(|e| ToolDefinition {
                name: e.name,
                description: e.description,
                parameters: e.parameters,
            })
            .collect()
    }
}

fn parse_arguments(arguments: &str) -> Result<Value, CallableError> {
    let value: Value = serde_json::from_str(arguments)
        .map_err(|e| CallableError::InvalidArguments(e.to_string()))?;
    if !value.is_object() {
        return Err(CallableError::InvalidArguments(
            "arguments must be a JSON object".into(),
        ));
    }
    Ok(value)
}

fn validate_schema(schema: &Value, args: &Value) -> Result<(), CallableError> {
    if schema.is_null() {
        return Ok(());
    }
    let compiled = jsonschema::JSONSchema::compile(schema)
        .map_err(|e| CallableError::InvalidArguments(format!("callable schema: {e}")))?;
    if let Err(errors) = compiled.validate(args) {
        let detail = errors
            .map(|e| e.to_string())
            .next()
            .unwrap_or_else(|| "arguments do not match callable schema".into());
        return Err(CallableError::InvalidArguments(detail));
    }
    Ok(())
}

fn split_method_name(name: &str) -> (String, String) {
    match name.rsplit_once("__") {
        Some((id, method)) => (id.to_string(), method.to_string()),
        None => (name.to_string(), name.to_string()),
    }
}

fn params_signature_hash(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(PRIME);
    }
    h
}

fn cap_result(s: String) -> String {
    if s.len() <= RESULT_CAP_BYTES {
        return s;
    }
    let head = RESULT_CAP_BYTES / 2;
    let tail = RESULT_CAP_BYTES - head;
    let start = s
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|&i| i <= head)
        .last()
        .unwrap_or(0);
    let end = s.len().saturating_sub(tail);
    let end = s
        .char_indices()
        .map(|(i, _)| i)
        .find(|&i| i >= end)
        .unwrap_or(s.len());
    format!("{}…{} bytes…{}", &s[..start], s.len(), &s[end..])
}

fn mcp_tool_failed(result: &[u8]) -> bool {
    #[derive(serde::Deserialize)]
    struct ToolCallResult {
        #[serde(rename = "isError", default)]
        is_error: Option<bool>,
    }
    let is_object = result.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{');
    is_object
        && serde_json::from_slice::<ToolCallResult>(result)
            .is_ok_and(|parsed| parsed.is_error == Some(true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use advance_runtime::callable_registry::{
        CallableHandler, CallableSpec, InMemoryCallableRegistry,
    };
    use advance_runtime::circuit_breaker::DefaultCircuitBreakerBus;
    use advance_shared_types::repetition::OutputHash;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    struct Allow;
    impl GrantCheck for Allow {
        fn check(
            &self,
            _agent_id: &str,
            _capability: &str,
            _function: &str,
            _params: &CapParams,
        ) -> GrantDecision {
            GrantDecision::Allow
        }
    }

    struct SpyGrant {
        calls: Mutex<Vec<(String, String, String, serde_json::Value)>>,
        inner: Allow,
    }
    impl SpyGrant {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                inner: Allow,
            }
        }
    }
    impl GrantCheck for SpyGrant {
        fn check(
            &self,
            agent_id: &str,
            capability: &str,
            function: &str,
            params: &CapParams,
        ) -> GrantDecision {
            self.calls.lock().unwrap().push((
                agent_id.into(),
                capability.into(),
                function.into(),
                params.as_value().clone(),
            ));
            self.inner.check(agent_id, capability, function, params)
        }
    }

    struct PassRep;
    impl RepetitionGuardCheck for PassRep {
        fn record_tool_call(&self, _: &str, _: ToolCallSignature) -> RepetitionDecision {
            RepetitionDecision::Pass
        }
        fn record_output(&self, _: &str, _: OutputHash) -> RepetitionDecision {
            RepetitionDecision::Pass
        }
    }

    struct NoopBus;
    impl EventBusEmit for NoopBus {
        fn emit(&self, _event: Event) {}
    }

    struct EchoHandler;
    impl CallableHandler for EchoHandler {
        fn call(
            &self,
            _ctx: HostCallContext,
            call_id: String,
            arguments: Value,
        ) -> Pin<Box<dyn Future<Output = Result<CallableOutcome, CallableError>> + Send + 'static>>
        {
            Box::pin(async move {
                Ok(CallableOutcome {
                    call_id,
                    content: arguments.to_string(),
                    is_error: false,
                })
            })
        }
    }

    fn ctx() -> HostCallContext {
        HostCallContext {
            agent_id: "root".into(),
            trace_id: "t".into(),
            turn_id: Some("turn-1".into()),
            capability: "llm".into(),
            function: "advance:runtime/agent-callables@0.1.0::invoke-callable".into(),
            run_id: None,
            iteration: None,
        }
    }

    /// V5 — GrantCheck parts for invoke-callable MCP names match invoke-mcp-tool.
    #[test]
    fn v5_mcp_grantcheck_parts_match_invoke_mcp_tool() {
        let (cap, func, params) = mcp_invoke_grant_parts("github", "search");
        assert_eq!(cap, "mcp");
        assert_eq!(func, INVOKE_MCP_TOOL_FUNCTION);
        assert_eq!(params.as_value()["servers"], "github");
        assert_eq!(params.as_value()["tool-patterns"], "search");
        let spy = SpyGrant::new();
        let _ = spy.check("agent-a", cap, func, &params);
        let calls = spy.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, "mcp");
        assert_eq!(calls[0].2, INVOKE_MCP_TOOL_FUNCTION);
    }

    /// V8 — dotted alias normalizes to `__` catalog name.
    #[tokio::test]
    async fn v8_dotted_alias_dispatches_host_fn() {
        let reg = Arc::new(InMemoryCallableRegistry::new());
        reg.register(CallableSpec {
            capability: "fs".into(),
            name: "data__describe".into(),
            description: "describe".into(),
            parameters: serde_json::json!({"type": "object"}),
            idempotent: true,
            original_function: "advance:runtime/agent-fs@0.1.0::write".into(),
            handler: Arc::new(EchoHandler),
        });
        let disp = CallableDispatcher::new(
            reg,
            Arc::new(StaticCaps(vec!["fs".into()])),
            Arc::new(Allow),
            Arc::new(DefaultCircuitBreakerBus::new()),
            Arc::new(PassRep),
            Arc::new(NoopBus),
        );
        let listed = disp.list("root").unwrap();
        assert!(listed.iter().any(|e| e.name == "data__describe"));
        let out = disp
            .invoke(ctx(), "c1".into(), "data.describe".into(), "{}".into())
            .await
            .unwrap();
        assert!(!out.is_error);
        assert_eq!(out.call_id, "c1");
    }

    #[test]
    fn generate_is_absent_from_catalog() {
        let reg = Arc::new(InMemoryCallableRegistry::new());
        reg.register(CallableSpec {
            capability: "fs".into(),
            name: "write".into(),
            description: "Write a file".into(),
            parameters: serde_json::json!({"type": "object"}),
            idempotent: false,
            original_function: "advance:runtime/agent-fs@0.1.0::write".into(),
            handler: Arc::new(EchoHandler),
        });
        let disp = CallableDispatcher::new(
            reg,
            Arc::new(StaticCaps(vec!["llm".into(), "fs".into()])),
            Arc::new(Allow),
            Arc::new(DefaultCircuitBreakerBus::new()),
            Arc::new(PassRep),
            Arc::new(NoopBus),
        );
        let names: Vec<_> = disp
            .list("root")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, vec!["write"]);
        assert!(!names.iter().any(|n| n == "generate"));
    }
}

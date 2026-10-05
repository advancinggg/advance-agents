//! Doubles for the mcp-client gate and its events: a grant check that records
//! each request and answers by a rule, a grant reader with fixed scopes, an
//! event bus that keeps every event, and a host call context.

use std::sync::{Arc, Mutex};

use advance_runtime::host_registry::{HostCallContext, HostFunctionSpec, HostRegistry};
use advance_shared_types::capability::{CapParams, GrantDecision};
use advance_shared_types::event::Event;
use advance_shared_types::mcp::McpGrantScope;
use advance_shared_types::traits::{EventBusEmit, GrantCheck, McpGrantReader};
use cap_mcp::McpGate;

/// One request a [`RecordingCheck`] was asked: agent, capability, function,
/// params.
pub type Asked = (String, String, String, serde_json::Value);

/// A grant check that records every request and allows those `rule` accepts.
pub struct RecordingCheck {
    rule: Box<dyn Fn(&Asked) -> bool + Send + Sync>,
    asked: Mutex<Vec<Asked>>,
}

impl RecordingCheck {
    pub fn new(rule: impl Fn(&Asked) -> bool + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self {
            rule: Box::new(rule),
            asked: Mutex::new(Vec::new()),
        })
    }

    pub fn allowing_all() -> Arc<Self> {
        Self::new(|_| true)
    }

    pub fn asked(&self) -> Vec<Asked> {
        self.asked.lock().unwrap().clone()
    }
}

impl GrantCheck for RecordingCheck {
    fn check(
        &self,
        agent_id: &str,
        capability: &str,
        function: &str,
        params: &CapParams,
    ) -> GrantDecision {
        let asked = (
            agent_id.to_string(),
            capability.to_string(),
            function.to_string(),
            params.as_value().clone(),
        );
        let allowed = (self.rule)(&asked);
        self.asked.lock().unwrap().push(asked);
        if allowed {
            GrantDecision::Allow
        } else {
            GrantDecision::Deny("refused by the test rule".into())
        }
    }
}

/// A grant reader answering every agent with the same scopes, counting reads.
#[derive(Debug)]
pub struct FixedScopes {
    scopes: Vec<McpGrantScope>,
    reads: Mutex<usize>,
}

impl FixedScopes {
    pub fn new(scopes: Vec<McpGrantScope>) -> Arc<Self> {
        Arc::new(Self {
            scopes,
            reads: Mutex::new(0),
        })
    }

    /// Every server and every tool.
    pub fn unrestricted() -> Arc<Self> {
        Self::new(vec![McpGrantScope::unrestricted()])
    }

    pub fn reads(&self) -> usize {
        *self.reads.lock().unwrap()
    }
}

impl McpGrantReader for FixedScopes {
    fn mcp_grant_scopes(&self, _agent_id: &str) -> Vec<McpGrantScope> {
        *self.reads.lock().unwrap() += 1;
        self.scopes.clone()
    }
}

/// The scope of a grant reaching `servers` (every server when `None`) and,
/// on them, the tools `patterns` match (every tool when `None`).
pub fn scope(servers: Option<&[&str]>, patterns: Option<&[&str]>) -> McpGrantScope {
    let owned = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    McpGrantScope {
        servers: servers.map(owned),
        tool_patterns: patterns.map(owned),
    }
}

/// A gate allowing every call and listing, with no web checker.
pub fn open_gate() -> McpGate {
    McpGate::new(
        RecordingCheck::allowing_all(),
        FixedScopes::unrestricted(),
        None,
    )
}

/// An event bus that keeps every event.
#[derive(Default)]
pub struct CapturingBus {
    events: Mutex<Vec<Event>>,
}

impl CapturingBus {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }

    pub fn types(&self) -> Vec<String> {
        self.events().into_iter().map(|e| e.event_type).collect()
    }
}

impl EventBusEmit for CapturingBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

/// The call context of `agent` calling the mcp-client function `name`.
pub fn ctx(agent: &str, name: &str) -> HostCallContext {
    HostCallContext {
        agent_id: agent.into(),
        trace_id: format!("trace-{name}"),
        turn_id: None,
        capability: "mcp".into(),
        function: format!("advance:runtime/mcp-client@0.1.0::{name}"),
        run_id: Some("run-1".into()),
        iteration: None,
    }
}

/// The registered spec of the mcp-client function `name`.
pub fn spec(registry: &dyn HostRegistry, name: &str) -> HostFunctionSpec {
    registry
        .lookup("mcp")
        .into_iter()
        .find(|spec| spec.name == name)
        .unwrap_or_else(|| panic!("{name} is not registered under `mcp`"))
}

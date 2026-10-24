//! CallableRegistry — sibling of [`HostRegistry`] (ADR 2026-10-24 D3).
//!
//! Host functions are model-facing only when a crate registers a
//! [`CallableSpec`] with a real description and JSON Schema. The registry is
//! the host-fn half of the Layer 3 catalog; WASM and MCP entries are projected
//! at list/dispatch time from their own inventories.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use crate::host_registry::HostCallContext;

/// Maximum distinct callable names a single registry can hold.
pub const MAX_CALLABLES: usize = 1024;

/// Maximum length for capability / name / description strings in a spec.
pub const MAX_CALLABLE_STRING_LEN: usize = 256;

/// Layer 3 source tag (WIT `callable-source`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallableSource {
    HostFn,
    WasmTool,
    McpTool,
}

impl CallableSource {
    pub fn as_wit_name(self) -> &'static str {
        match self {
            Self::HostFn => "host-fn",
            Self::WasmTool => "wasm-tool",
            Self::McpTool => "mcp-tool",
        }
    }
}

/// Dispatcher refusal (WIT `callable-error`). Execution-object failures are
/// [`CallableOutcome`] with `is_error: true`, not this enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallableError {
    NotFound(String),
    PermissionDenied(String),
    InvalidArguments(String),
    RepetitionTerminated(String),
    BudgetExceeded(String),
    Internal(String),
}

impl CallableError {
    pub fn wit_case(&self) -> &'static str {
        match self {
            Self::NotFound(_) => "not-found",
            Self::PermissionDenied(_) => "permission-denied",
            Self::InvalidArguments(_) => "invalid-arguments",
            Self::RepetitionTerminated(_) => "repetition-terminated",
            Self::BudgetExceeded(_) => "budget-exceeded",
            Self::Internal(_) => "internal",
        }
    }

    pub fn payload(&self) -> &str {
        match self {
            Self::NotFound(s)
            | Self::PermissionDenied(s)
            | Self::InvalidArguments(s)
            | Self::RepetitionTerminated(s)
            | Self::BudgetExceeded(s)
            | Self::Internal(s) => s,
        }
    }
}

impl std::fmt::Display for CallableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.wit_case(), self.payload())
    }
}

impl std::error::Error for CallableError {}

/// Successful dispatch (WIT `callable-result`). `is_error` means the execution
/// object reported a failure; the guest still receives `Ok`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallableOutcome {
    pub call_id: String,
    pub content: String,
    pub is_error: bool,
}

/// Catalog entry used by `list-callables`, the native `tools` array, and the
/// Tier-2 `# Available Tools` section. Names are identical across the three
/// by construction.
#[derive(Debug, Clone, PartialEq)]
pub struct CallableDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
    pub source: CallableSource,
    pub idempotent: Option<bool>,
}

/// Async handler for a host-fn callable. Capability crates call their own
/// Rust API here — no WASM `Val` round-trip through the linker.
pub trait CallableHandler: Send + Sync + 'static {
    fn call(
        &self,
        ctx: HostCallContext,
        call_id: String,
        arguments: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<CallableOutcome, CallableError>> + Send + 'static>>;
}

/// Opt-in host-fn catalog spec (ADR 2026-10-24 D3).
pub struct CallableSpec {
    pub capability: String,
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
    pub idempotent: bool,
    /// Original host-fn identity for L1 GrantCheck, e.g.
    /// `advance:runtime/agent-fs@0.1.0::write`.
    pub original_function: String,
    pub handler: Arc<dyn CallableHandler>,
}

impl std::fmt::Debug for CallableSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallableSpec")
            .field("capability", &self.capability)
            .field("name", &self.name)
            .field("idempotent", &self.idempotent)
            .field("original_function", &self.original_function)
            .finish_non_exhaustive()
    }
}

impl Clone for CallableSpec {
    fn clone(&self) -> Self {
        Self {
            capability: self.capability.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
            parameters: self.parameters.clone(),
            idempotent: self.idempotent,
            original_function: self.original_function.clone(),
            handler: Arc::clone(&self.handler),
        }
    }
}

/// CONTRACT-001 sibling: model-facing host-fn catalog.
pub trait CallableRegistry: Send + Sync {
    fn register(&self, spec: CallableSpec);
    fn lookup(&self, name: &str) -> Option<CallableSpec>;
    /// Specs whose `capability` is in `caps`, in insertion order.
    fn list_for_capabilities(&self, caps: &[String]) -> Vec<CallableSpec>;
}

/// Default in-memory registry. Append-only; duplicate names: last register
/// wins at `lookup`, both appear in `list_for_capabilities` until the
/// catalog projector collapses by name (host-fn > wasm > mcp).
pub struct InMemoryCallableRegistry {
    by_name: RwLock<HashMap<String, CallableSpec>>,
    order: RwLock<Vec<String>>,
}

impl Default for InMemoryCallableRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryCallableRegistry {
    pub fn new() -> Self {
        Self {
            by_name: RwLock::new(HashMap::new()),
            order: RwLock::new(Vec::new()),
        }
    }

    pub fn len(&self) -> usize {
        self.by_name.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl CallableRegistry for InMemoryCallableRegistry {
    fn register(&self, spec: CallableSpec) {
        assert!(
            spec.capability.len() <= MAX_CALLABLE_STRING_LEN,
            "callable_registry: capability exceeds MAX_CALLABLE_STRING_LEN"
        );
        assert!(
            spec.name.len() <= MAX_CALLABLE_STRING_LEN,
            "callable_registry: name exceeds MAX_CALLABLE_STRING_LEN"
        );
        assert!(
            !spec.name.is_empty(),
            "callable_registry: name must be non-empty"
        );

        let mut by_name = self.by_name.write().unwrap_or_else(|e| e.into_inner());
        assert!(
            by_name.len() < MAX_CALLABLES || by_name.contains_key(&spec.name),
            "callable_registry: MAX_CALLABLES ({MAX_CALLABLES}) exceeded"
        );
        let is_new = !by_name.contains_key(&spec.name);
        by_name.insert(spec.name.clone(), spec.clone());
        drop(by_name);
        if is_new {
            self.order
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .push(spec.name);
        }
    }

    fn lookup(&self, name: &str) -> Option<CallableSpec> {
        self.by_name
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(name)
            .cloned()
    }

    fn list_for_capabilities(&self, caps: &[String]) -> Vec<CallableSpec> {
        let by_name = self.by_name.read().unwrap_or_else(|e| e.into_inner());
        let order = self.order.read().unwrap_or_else(|e| e.into_inner());
        order
            .iter()
            .filter_map(|n| by_name.get(n))
            .filter(|s| caps.iter().any(|c| c == &s.capability))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Stub;
    impl CallableHandler for Stub {
        fn call(
            &self,
            _ctx: HostCallContext,
            call_id: String,
            _arguments: serde_json::Value,
        ) -> Pin<Box<dyn Future<Output = Result<CallableOutcome, CallableError>> + Send + 'static>>
        {
            Box::pin(async move {
                Ok(CallableOutcome {
                    call_id,
                    content: "ok".into(),
                    is_error: false,
                })
            })
        }
    }

    fn spec(cap: &str, name: &str) -> CallableSpec {
        CallableSpec {
            capability: cap.into(),
            name: name.into(),
            description: format!("{name} callable"),
            parameters: serde_json::json!({"type": "object"}),
            idempotent: false,
            original_function: format!("advance:runtime/agent-{cap}@0.1.0::{name}"),
            handler: Arc::new(Stub),
        }
    }

    #[test]
    fn list_for_capabilities_filters_l0() {
        let reg = InMemoryCallableRegistry::new();
        reg.register(spec("fs", "write"));
        reg.register(spec("memory", "remember"));
        let listed = reg.list_for_capabilities(&["llm".into(), "fs".into()]);
        let names: Vec<_> = listed.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["write"]);
        assert!(reg.lookup("remember").is_some());
    }
}

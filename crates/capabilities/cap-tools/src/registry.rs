//! `ToolRegistry` trait + supporting types per MODULE-017 §2.3 (CONTRACT-163)
//! and PRD §9.8 (canonical WIT shapes).
//!
//! Slice A ships declarations + a stub impl. No WASM, no LRU, no dispatch.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// CONTRACT-163 — runtime-side registry for local / WASM tools.
///
/// Slice A declares this trait but does NOT yet wire host dispatch
/// (planned for the next slice via the same `LinkerInstance::func_new_async`
/// pattern cap-llm uses). Object-safety is required so the host fn can
/// hold a `Box<dyn ToolRegistry>` — verified by the `assert_send_sync`
/// dyn-safety test in `mod tests`.
#[async_trait]
pub trait ToolRegistry: Send + Sync {
    /// Look up (or lazy-load) a tool instance by id. Slice A: always
    /// returns [`ToolError::NotFound`] from [`InMemoryToolRegistry`].
    async fn load(&self, tool_id: &str) -> Result<ToolInstance, ToolError>;

    /// Invoke a method on the named tool. Slice A: always returns
    /// [`ToolError::NotFound`].
    async fn invoke(
        &self,
        tool_id: &str,
        method: &str,
        params: &[u8],
    ) -> Result<Vec<u8>, ToolError>;

    /// Enumerate the currently-loaded tools. Slice A: empty.
    async fn list(&self) -> Vec<ToolInfo>;

    /// Evict the least-recently-used tool from the in-memory cache.
    /// Slice A: no-op.
    async fn evict_lru(&self);
}

/// Stub handle returned from [`ToolRegistry::load`] in later slices.
///
/// `#[non_exhaustive]` so future slices can add e.g. `engine_handle:
/// wasmtime::Instance`, `caps: CapabilitySet` without a breaking-change.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub struct ToolInstance {
    pub tool_id: String,
}

/// WIT ABI record `tool-info` (PRD §9.8 lines 3364-3368).
///
/// **Distinction from [`advance_shared_types::capability::ToolEntry`]
/// (CONTRACT-165 inventory feed)**: `ToolEntry` is the Rust-side
/// context-assembly shape used by MODULE-010 to build the
/// `# Available Tools` view; its `params_schema` field is
/// `serde_json::Value`. `ToolInfo` is the WIT ABI shape returned across
/// the `list-tools` host fn boundary, field-for-field matching PRD §9.8.
/// The two intentionally do NOT merge — Rust-side vs WIT-ABI surfaces
/// have different stability rules.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ToolInfo {
    pub id: String,
    pub description: String,
    pub methods: Vec<MethodInfo>,
}

/// WIT ABI record `method-info` (PRD §9.8 lines 3370-3376).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct MethodInfo {
    pub name: String,
    pub description: Option<String>,
    pub input_schema: Option<String>,
    pub output_schema: Option<String>,
    pub idempotent: Option<bool>,
}

/// WIT ABI record `tool-description` (PRD §9.8 lines 3404-3407).
///
/// Returned from a tool WASM's `describe()` export; the runtime uses
/// this to populate [`ToolInfo`] for the agent-visible `list-tools`
/// view (later slice — Slice A does NOT yet wire describe-dispatch).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ToolDescription {
    pub description: String,
    pub methods: Vec<MethodInfo>,
}

/// WIT ABI variant `tool-error` (PRD §9.8 lines 3378-3385).
///
/// All 6 canonical arms pinned in Slice A so Slice B's host-dispatch
/// wiring is not blocked by a breaking-change to this surface.
#[derive(Clone, Debug, PartialEq, Error)]
pub enum ToolError {
    #[error("tool not found: {0}")]
    NotFound(String),
    #[error("method not found: {0}")]
    MethodNotFound(String),
    #[error("invocation failed: {0}")]
    InvocationFailed(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("input validation failed: {0}")]
    InputValidationFailed(String),
    #[error("output validation failed: {0}")]
    OutputValidationFailed(String),
}

/// Stub [`ToolRegistry`] for Slice A.
///
/// No state, no cache, no WASM. Every lookup misses with
/// [`ToolError::NotFound`]; `list` is empty; `evict_lru` is a no-op.
#[derive(Default, Debug)]
pub struct InMemoryToolRegistry;

impl InMemoryToolRegistry {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ToolRegistry for InMemoryToolRegistry {
    async fn load(&self, tool_id: &str) -> Result<ToolInstance, ToolError> {
        Err(ToolError::NotFound(tool_id.to_string()))
    }

    async fn invoke(
        &self,
        tool_id: &str,
        _method: &str,
        _params: &[u8],
    ) -> Result<Vec<u8>, ToolError> {
        Err(ToolError::NotFound(tool_id.to_string()))
    }

    async fn list(&self) -> Vec<ToolInfo> {
        Vec::new()
    }

    async fn evict_lru(&self) {
        // Slice A: no-op.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SA-10: list() on empty registry returns Vec::new().
    #[tokio::test]
    async fn sa_10_list_empty() {
        let reg = InMemoryToolRegistry::new();
        let tools = reg.list().await;
        assert!(tools.is_empty());
    }

    // SA-11: invoke() unknown returns ToolError::NotFound(tool_id).
    #[tokio::test]
    async fn sa_11_invoke_unknown_returns_not_found() {
        let reg = InMemoryToolRegistry::new();
        let result = reg.invoke("unknown", "m", &[]).await;
        assert_eq!(result, Err(ToolError::NotFound("unknown".to_string())));
    }

    // SA-12: load() unknown returns ToolError::NotFound(tool_id).
    #[tokio::test]
    async fn sa_12_load_unknown_returns_not_found() {
        let reg = InMemoryToolRegistry::new();
        let result = reg.load("unknown").await;
        assert_eq!(result, Err(ToolError::NotFound("unknown".to_string())));
    }

    // SA-13: evict_lru() on empty registry is a no-op (no panic).
    #[tokio::test]
    async fn sa_13_evict_lru_empty_no_op() {
        let reg = InMemoryToolRegistry::new();
        reg.evict_lru().await;
        // No assertion — just confirm no panic.
    }

    // SA-14: dyn-safety + Send + Sync.
    //
    // `assert_send_sync::<Box<dyn ToolRegistry>>()` only type-checks
    // when the trait is dyn-compatible AND the boxed trait object is
    // Send + Sync (i.e., the trait declares `Send + Sync` supertraits).
    // If either property is removed, this test fails to compile.
    #[test]
    fn sa_14_dyn_safety_and_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Box<dyn ToolRegistry>>();
    }

    // SA-18: ToolInfo serde defense — round-trip + wire-format lock + deny_unknown_fields.
    mod sa_18 {
        use super::*;

        fn canonical_tool_info() -> ToolInfo {
            ToolInfo {
                id: "t1".to_string(),
                description: "d".to_string(),
                methods: vec![MethodInfo {
                    name: "m".to_string(),
                    description: None,
                    input_schema: None,
                    output_schema: None,
                    idempotent: None,
                }],
            }
        }

        // SA-18(a): ToolInfo round-trips through serde_json.
        #[test]
        fn sa_18a_tool_info_round_trip() {
            let original = canonical_tool_info();
            let json = serde_json::to_string(&original).expect("serialize");
            let back: ToolInfo = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(original, back);
        }

        // SA-18(b): wire-format lock — exact JSON byte string.
        //
        // Locks the canonical PRD §9.8 wire format: kebab-case field
        // names, null-for-None defaults, struct-field declaration order.
        // Drift here is a regression in the WIT ABI compatibility.
        #[test]
        fn sa_18b_tool_info_wire_format_lock() {
            let info = canonical_tool_info();
            let actual = serde_json::to_string(&info).expect("serialize");
            let expected = r#"{"id":"t1","description":"d","methods":[{"name":"m","description":null,"input-schema":null,"output-schema":null,"idempotent":null}]}"#;
            assert_eq!(actual, expected);
        }

        // SA-18(c): deny_unknown_fields rejects JSON with extra fields.
        #[test]
        fn sa_18c_tool_info_deny_unknown_fields() {
            let json = r#"{"id":"t1","description":"d","methods":[],"extra-field":"oops"}"#;
            let result: Result<ToolInfo, _> = serde_json::from_str(json);
            assert!(
                result.is_err(),
                "expected deny_unknown_fields to reject the extra field, but got: {:?}",
                result
            );
        }
    }
}

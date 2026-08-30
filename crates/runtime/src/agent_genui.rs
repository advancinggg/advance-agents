//! Flag-gated L0 `agent-genui` registration (MODULE-001-AC-29 / T110).
//!
//! Registers a single host function `emit-document` under capability `"genui"`
//! and namespace `advance:runtime/agent-genui@0.1.0`. The handler is a
//! fail-closed loopback: it witnesses that the function is registered and
//! injectable. It does **not** parse A2UI JSON, admit a catalog, evaluate a
//! grant product, emit `genui.*` events, project MODULE-020, or return
//! `Ok(document-id)`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use wasmtime::component::Val;

use crate::host_registry::{
    HostCallContext, HostCallError, HostFunctionHandler, HostFunctionSpec, HostRegistry,
};

const CAPABILITY: &str = "genui";
const NAMESPACE: &str = "advance:runtime/agent-genui@0.1.0";
const NAME: &str = "emit-document";

/// Register the L0 `emit-document` host function.
///
/// Callers (the CLI composition root) pass `RuntimeConfig.genui.max_document_bytes`
/// so the post-lift size bound matches the loaded config. Registration itself
/// is gated by `genui.enabled` at the composition root — this function does
/// not read config.
pub fn register_agent_genui(registry: &dyn HostRegistry, max_document_bytes: usize) {
    registry.register(HostFunctionSpec {
        capability: CAPABILITY.to_string(),
        namespace: NAMESPACE.to_string(),
        name: NAME.to_string(),
        handler: Arc::new(EmitDocumentHandler { max_document_bytes }),
        idempotent: false,
    });
}

struct EmitDocumentHandler {
    max_document_bytes: usize,
}

impl HostFunctionHandler for EmitDocumentHandler {
    fn call(
        &self,
        _ctx: HostCallContext,
        params: Vec<Val>,
        results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let max_document_bytes = self.max_document_bytes;
        Box::pin(async move {
            if results_len != 1 {
                return Err(HostCallError::HandlerError(format!(
                    "expected results_len == 1 for emit-document, got {results_len}"
                )));
            }
            let document_json = match params.as_slice() {
                [Val::String(s)] => s.clone(),
                _ => {
                    return Err(HostCallError::HandlerError(
                        "expected single Val::String parameter".into(),
                    ));
                }
            };
            if document_json.is_empty() {
                return Ok(vec![encode_string_error(
                    "invalid-props",
                    "empty document-json",
                )]);
            }
            if document_json.len() > max_document_bytes {
                return Ok(vec![encode_payloadless_error("document-too-large")]);
            }
            Ok(vec![encode_string_error(
                "surface-unavailable",
                "l0-loopback",
            )])
        })
    }
}

fn encode_payloadless_error(case: &str) -> Val {
    Val::Result(Err(Some(Box::new(Val::Variant(case.to_string(), None)))))
}

fn encode_string_error(case: &str, msg: impl Into<String>) -> Val {
    Val::Result(Err(Some(Box::new(Val::Variant(
        case.to_string(),
        Some(Box::new(Val::String(msg.into()))),
    )))))
}

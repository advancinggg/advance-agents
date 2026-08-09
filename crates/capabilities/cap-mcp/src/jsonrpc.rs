//! JSON-RPC 2.0 wire shapes used over MCP HTTP/SSE transport.
//!
//! MODULE-017 §1.3.5 references "MCP HTTP/SSE transport" without spelling
//! out the on-the-wire JSON-RPC shape — the MCP specification (Anthropic /
//! Model Context Protocol) layers JSON-RPC 2.0 over HTTP. Slice B ships the
//! minimum shapes needed to construct a request and decode a single matched
//! response.

use serde::{Deserialize, Serialize};

/// JSON-RPC 2.0 request envelope.
///
/// The `id` field is monotonic per-transport (managed by [`HttpMcpTransport`]
/// via an `AtomicU64`). `params` carry the method-specific payload encoded
/// as raw JSON.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: serde_json::Value,
    pub id: u64,
}

impl JsonRpcRequest {
    /// Build a JSON-RPC 2.0 request with the canonical `"2.0"` version
    /// string. `params` accepts any `serde_json::Value` payload.
    pub fn new(id: u64, method: impl Into<String>, params: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: method.into(),
            params,
            id,
        }
    }
}

/// JSON-RPC 2.0 response envelope.
///
/// Either `result` or `error` is set; never both. We don't model the
/// success / error split at the type level because the MCP transport
/// inspects `id` and `error` fields and dispatches accordingly.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 error object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip() {
        let req = JsonRpcRequest::new(1, "list-tools", serde_json::json!({}));
        let s = serde_json::to_string(&req).unwrap();
        let back: JsonRpcRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(req, back);
        assert!(s.contains("\"jsonrpc\":\"2.0\""));
    }

    #[test]
    fn response_with_result() {
        let raw = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#;
        let r: JsonRpcResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(r.id, 1);
        assert!(r.result.is_some());
        assert!(r.error.is_none());
    }

    #[test]
    fn response_with_error() {
        let raw = r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32600,"message":"invalid"}}"#;
        let r: JsonRpcResponse = serde_json::from_str(raw).unwrap();
        assert!(r.result.is_none());
        assert_eq!(r.error.as_ref().unwrap().code, -32600);
    }
}

//! JSON-RPC 2.0 wire shapes used by the MCP transports (HTTP/SSE and stdio).
//!
//! The Model Context Protocol layers JSON-RPC 2.0 over each transport. These
//! are the shapes the client sends (requests and notifications) and the
//! response envelope it decodes.

use serde::{Deserialize, Serialize};

/// JSON-RPC 2.0 request envelope.
///
/// The `id` field is monotonic per transport (each transport allocates it from
/// an `AtomicU64`). `params` carry the method-specific payload encoded as raw
/// JSON.
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

/// JSON-RPC 2.0 notification: a message without an `id`, which the receiver
/// never answers (for example `notifications/initialized`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    /// Omitted from the wire when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

impl JsonRpcNotification {
    /// Build a JSON-RPC 2.0 notification with the canonical `"2.0"` version
    /// string.
    pub fn new(method: impl Into<String>, params: Option<serde_json::Value>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: method.into(),
            params,
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
    fn notification_carries_no_id_and_omits_absent_params() {
        let n = JsonRpcNotification::new("notifications/initialized", None);
        let v: serde_json::Value = serde_json::to_value(&n).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
        );
        let with_params =
            JsonRpcNotification::new("notifications/progress", Some(serde_json::json!({"p": 1})));
        let v: serde_json::Value = serde_json::to_value(&with_params).unwrap();
        assert!(v.get("id").is_none());
        assert_eq!(v["params"]["p"], 1);
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

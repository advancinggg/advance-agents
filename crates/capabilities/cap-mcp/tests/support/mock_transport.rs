//! `CountingMockTransport` — a test-only `McpTransport` that captures every
//! invocation and returns scripted responses. Used by `tests/schema.rs` SD-20
//! to assert "rejected before dispatch" (via `call_count() == 0`) and by
//! `tests/client_surface.rs` to drive the 7-method surface without a real
//! network or subprocess.

use std::sync::Mutex;

use async_trait::async_trait;
use cap_mcp::{McpError, McpTransport};

#[derive(Default)]
pub struct CountingMockTransport {
    pub server_id: String,
    scripted: Mutex<Vec<Result<Vec<u8>, McpError>>>,
    captured: Mutex<Vec<(String, serde_json::Value)>>,
}

impl CountingMockTransport {
    pub fn new(server_id: impl Into<String>) -> Self {
        Self {
            server_id: server_id.into(),
            scripted: Mutex::new(Vec::new()),
            captured: Mutex::new(Vec::new()),
        }
    }

    pub fn push_ok(&self, body: serde_json::Value) {
        self.scripted
            .lock()
            .unwrap()
            .push(Ok(serde_json::to_vec(&body).unwrap()));
    }

    // The three accessors below are shared test-support surface: each test binary
    // includes this module and consumes a different subset, so per-binary dead_code
    // would otherwise fire on whichever accessor that binary skips.
    #[allow(dead_code)]
    pub fn push_err(&self, err: McpError) {
        self.scripted.lock().unwrap().push(Err(err));
    }

    #[allow(dead_code)]
    pub fn call_count(&self) -> usize {
        self.captured.lock().unwrap().len()
    }

    #[allow(dead_code)]
    pub fn captured(&self) -> Vec<(String, serde_json::Value)> {
        self.captured.lock().unwrap().clone()
    }
}

#[async_trait]
impl McpTransport for CountingMockTransport {
    async fn invoke(&self, method: &str, params: serde_json::Value) -> Result<Vec<u8>, McpError> {
        self.captured
            .lock()
            .unwrap()
            .push((method.to_string(), params));
        let mut q = self.scripted.lock().unwrap();
        if q.is_empty() {
            return Err(McpError::transport("mock transport: no scripted response"));
        }
        q.remove(0)
    }

    fn server_id(&self) -> &str {
        &self.server_id
    }
}

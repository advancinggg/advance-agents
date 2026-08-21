use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::lazy_registry::LazyToolRegistry;
use crate::registry::{ToolError, ToolInfo, ToolInstance, ToolRegistry};

pub struct HostToolRegistry {
    inner: Mutex<HashMap<String, ToolInfo>>,
}

impl HostToolRegistry {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub async fn register(&self, info: ToolInfo) {
        let mut g = self.inner.lock().await;
        g.insert(info.id.clone(), info);
    }

    pub async fn list(&self) -> Vec<ToolInfo> {
        let g = self.inner.lock().await;
        let mut v: Vec<ToolInfo> = g.values().cloned().collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }

    pub async fn get(&self, id: &str) -> Option<ToolInfo> {
        let g = self.inner.lock().await;
        g.get(id).cloned()
    }
}

impl Default for HostToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

pub struct CompositeToolRegistry {
    pub host: Arc<HostToolRegistry>,
    pub wasm: Arc<LazyToolRegistry>,
}

#[async_trait]
impl ToolRegistry for CompositeToolRegistry {
    async fn load(&self, tool_id: &str) -> Result<ToolInstance, ToolError> {
        if self.host.get(tool_id).await.is_some() {
            return Ok(ToolInstance {
                tool_id: tool_id.to_string(),
            });
        }
        self.wasm.load(tool_id).await
    }

    async fn invoke(
        &self,
        tool_id: &str,
        method: &str,
        params: &[u8],
    ) -> Result<Vec<u8>, ToolError> {
        if self.host.get(tool_id).await.is_some() {
            // Production invoke of web.* is the WebAware handler short-circuit.
            return Err(ToolError::NotFound(tool_id.to_string()));
        }
        self.wasm.invoke(tool_id, method, params).await
    }

    async fn list(&self) -> Vec<ToolInfo> {
        let mut out = self.host.list().await;
        out.extend(self.wasm.list().await);
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    async fn evict_lru(&self) {
        self.wasm.evict_lru().await;
    }
}

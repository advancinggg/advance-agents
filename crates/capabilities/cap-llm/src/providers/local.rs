//! Local-inference adapter (ADR 2026-07-29 gateway seam).
//!
//! Delegates to [`OpenAiAdapter`] — local inference servers (llama.cpp, vLLM,
//! Ollama) overwhelmingly speak the OpenAI-compatible API. The product side
//! wires the actual endpoint + secret via `LlmProviderConfig` with
//! `backend: "local"`.

use advance_shared_types::security_validator::HttpRequest;

use crate::error::LlmError;
use crate::executor::ExecutionOutcome;
use crate::gateway::{ChatMessage, ChatParams};
use crate::provider::ResolvedProvider;
use crate::providers::openai::OpenAiAdapter;
use crate::providers::sse::{SseEvent, SseFrame};
use crate::providers::ProviderAdapter;

pub struct LocalAdapter {
    inner: OpenAiAdapter,
}

impl LocalAdapter {
    pub fn new() -> Self {
        Self {
            inner: OpenAiAdapter,
        }
    }
}

impl ProviderAdapter for LocalAdapter {
    fn build_chat_request(
        &self,
        provider: &ResolvedProvider,
        messages: &[ChatMessage],
        params: &ChatParams,
    ) -> Result<HttpRequest, LlmError> {
        self.inner.build_chat_request(provider, messages, params)
    }

    fn parse_chat_response(&self, status: u16, body: &[u8]) -> Result<ExecutionOutcome, LlmError> {
        self.inner.parse_chat_response(status, body)
    }

    fn build_stream_request(
        &self,
        provider: &ResolvedProvider,
        messages: &[ChatMessage],
        params: &ChatParams,
    ) -> Result<HttpRequest, LlmError> {
        self.inner.build_stream_request(provider, messages, params)
    }

    fn parse_sse_frame(&self, frame: &SseFrame) -> Result<SseEvent, LlmError> {
        self.inner.parse_sse_frame(frame)
    }

    fn build_embed_request(
        &self,
        provider: &ResolvedProvider,
        text: &str,
    ) -> Result<HttpRequest, LlmError> {
        self.inner.build_embed_request(provider, text)
    }

    fn parse_embed_response(&self, status: u16, body: &[u8]) -> Result<Vec<f32>, LlmError> {
        self.inner.parse_embed_response(status, body)
    }

    fn supports_embedding(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use advance_runtime::config::ProviderBackend;
    use std::collections::HashMap;

    fn local_provider() -> ResolvedProvider {
        ResolvedProvider {
            id: "local".into(),
            endpoint: "http://localhost:8080".into(),
            api_key_secret: "local-dummy".into(),
            model: "llama-3.1-8b".into(),
            cost_per_mtoken_in: 0.0,
            cost_per_mtoken_out: 0.0,
            backend: ProviderBackend::Local,
            auth_scheme: None,
        }
    }

    #[test]
    fn t3_select_adapter_local() {
        let adapter = crate::providers::select_adapter(ProviderBackend::Local);
        assert!(!adapter.supports_embedding());
    }

    #[test]
    fn t5_build_chat_request_produces_valid_body() {
        let adapter = LocalAdapter::new();
        let provider = local_provider();
        let messages = vec![ChatMessage {
            role: crate::gateway::ChatRole::User,
            content: "hello".into(),
        }];
        let params = ChatParams::default();
        let req = adapter
            .build_chat_request(&provider, &messages, &params)
            .expect("build_chat_request should succeed");
        assert_eq!(req.url, "http://localhost:8080/v1/chat/completions");
        let body: serde_json::Value =
            serde_json::from_slice(&req.body).expect("body should be valid JSON");
        assert_eq!(body["model"], "llama-3.1-8b");
        assert!(body["messages"].is_array());
    }
}

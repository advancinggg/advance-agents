//! CONTRACT-236 / CONTRACT-238 inference ports (local-endpoint-s1).
//!
//! C236 is the CONTRACT-081 IR: chat / embed / normalized text-delta stream.
//! C238 is the MODULE-012 local transport: hand-off loopback only, no chain.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;

/// Prefix for C238 / sidecar-client failures. Must not equal the cap-llm
/// retry whitelist (`connection refused`, `transport timeout`, …).
pub const LOCAL_TRANSPORT_PREFIX: &str = "local transport:";

/// Prefix for AC-24 typed unsupported-capability errors.
pub const UNSUPPORTED_CAPABILITY_PREFIX: &str = "unsupported capability:";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InferenceMessage {
    pub role: String,
    pub content: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct InferenceTool {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

#[derive(Clone, Debug)]
pub struct InferenceChatRequest {
    pub provider_id: String,
    pub model: String,
    pub messages: Vec<InferenceMessage>,
    pub temperature: Option<f64>,
    pub max_tokens: Option<u32>,
    pub stop_sequences: Option<Vec<String>>,
    pub tools: Option<Vec<InferenceTool>>,
    pub output_schema: Option<String>,
    pub deadline: Instant,
    pub cancel: Arc<AtomicBool>,
}

impl InferenceChatRequest {
    /// Reservation figure for `stream_begin_live` `input_est` (replaces HTTP body len).
    pub fn reservation_bytes(&self) -> u64 {
        let mut n = self.model.len() + self.provider_id.len();
        for m in &self.messages {
            n = n
                .saturating_add(m.role.len())
                .saturating_add(m.content.len());
        }
        if let Some(schema) = &self.output_schema {
            n = n.saturating_add(schema.len());
        }
        if let Some(stop) = &self.stop_sequences {
            for s in stop {
                n = n.saturating_add(s.len());
            }
        }
        if let Some(tools) = &self.tools {
            for t in tools {
                n = n
                    .saturating_add(t.name.len())
                    .saturating_add(t.description.len())
                    .saturating_add(t.parameters.to_string().len());
            }
        }
        n as u64
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct InferenceChatResponse {
    pub text: String,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub finish_reason: String,
}

#[derive(Clone, Debug)]
pub struct InferenceEmbedRequest {
    pub provider_id: String,
    pub model: String,
    pub text: String,
    pub deadline: Instant,
    pub cancel: Arc<AtomicBool>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct InferenceEmbedResponse {
    pub vector: Vec<f32>,
    pub model: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InferenceStreamClass {
    Success,
    Auth,
    NotFound,
    RateLimited,
    Provider5xx,
    Unexpected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InferenceStreamHead {
    pub class: InferenceStreamClass,
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct NormalizedUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_tokens: u64,
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct InferenceTextDelta {
    pub text: String,
    pub usage: Option<NormalizedUsage>,
    pub terminal: bool,
    pub finish_reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InferenceBackendError {
    LocalTransport(String),
    UnsupportedCapability(String),
    ModelNotAvailable(String),
    RateLimited(String),
    ContextTooLong(String),
    Provider(String),
    Unwired,
}

impl InferenceBackendError {
    pub fn local_transport(msg: impl Into<String>) -> Self {
        Self::LocalTransport(msg.into())
    }

    pub fn as_llm_message(&self) -> String {
        match self {
            Self::LocalTransport(s) => format!("{LOCAL_TRANSPORT_PREFIX} {s}"),
            Self::UnsupportedCapability(s) => format!("{UNSUPPORTED_CAPABILITY_PREFIX} {s}"),
            Self::ModelNotAvailable(s) => s.clone(),
            Self::RateLimited(s) => s.clone(),
            Self::ContextTooLong(s) => s.clone(),
            Self::Provider(s) => s.clone(),
            Self::Unwired => format!("{LOCAL_TRANSPORT_PREFIX} not wired"),
        }
    }
}

impl std::fmt::Display for InferenceBackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_llm_message())
    }
}

impl std::error::Error for InferenceBackendError {}

#[async_trait]
pub trait InferenceStream: Send {
    async fn next_chunk(&mut self) -> Option<Result<InferenceTextDelta, InferenceBackendError>>;
    fn cancel(&mut self);
}

#[async_trait]
pub trait InferenceBackendPort: Send + Sync {
    async fn chat(
        &self,
        req: InferenceChatRequest,
    ) -> Result<InferenceChatResponse, InferenceBackendError>;
    async fn embed(
        &self,
        req: InferenceEmbedRequest,
    ) -> Result<InferenceEmbedResponse, InferenceBackendError>;
    async fn start_stream(
        &self,
        req: InferenceChatRequest,
    ) -> Result<(InferenceStreamHead, Box<dyn InferenceStream>), InferenceBackendError>;
    fn is_wired(&self) -> bool;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NotWiredInferenceBackend;

#[async_trait]
impl InferenceBackendPort for NotWiredInferenceBackend {
    async fn chat(
        &self,
        _req: InferenceChatRequest,
    ) -> Result<InferenceChatResponse, InferenceBackendError> {
        Err(InferenceBackendError::Unwired)
    }
    async fn embed(
        &self,
        _req: InferenceEmbedRequest,
    ) -> Result<InferenceEmbedResponse, InferenceBackendError> {
        Err(InferenceBackendError::Unwired)
    }
    async fn start_stream(
        &self,
        _req: InferenceChatRequest,
    ) -> Result<(InferenceStreamHead, Box<dyn InferenceStream>), InferenceBackendError> {
        Err(InferenceBackendError::Unwired)
    }
    fn is_wired(&self) -> bool {
        false
    }
}

/// Sized map: one C236 port per local-class provider id.
#[derive(Clone, Default)]
pub struct InferenceBackendRegistry {
    map: HashMap<String, Arc<dyn InferenceBackendPort>>,
}

impl InferenceBackendRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, id: impl Into<String>, port: Arc<dyn InferenceBackendPort>) {
        self.map.insert(id.into(), port);
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn InferenceBackendPort>> {
        self.map.get(id).cloned()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SidecarHandoff {
    pub pid: u32,
    pub loopback: SocketAddr,
}

impl SidecarHandoff {
    pub fn is_loopback(&self) -> bool {
        match self.loopback.ip() {
            std::net::IpAddr::V4(v4) => v4.is_loopback(),
            std::net::IpAddr::V6(v6) => v6.is_loopback(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LocalHttpRequest {
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub deadline: Instant,
    pub cancel: Arc<AtomicBool>,
}

#[derive(Clone, Debug)]
pub struct LocalHttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct LocalHttpResponseHead {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalTransportError(pub String);

impl LocalTransportError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }

    pub fn as_prefixed(&self) -> String {
        format!("{LOCAL_TRANSPORT_PREFIX} {}", self.0)
    }
}

impl std::fmt::Display for LocalTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_prefixed())
    }
}

impl std::error::Error for LocalTransportError {}

impl From<LocalTransportError> for InferenceBackendError {
    fn from(e: LocalTransportError) -> Self {
        Self::LocalTransport(e.0)
    }
}

#[async_trait]
pub trait LocalBodyStream: Send {
    async fn next_chunk(&mut self) -> Option<Result<Vec<u8>, LocalTransportError>>;
    fn cancel(&mut self);
}

#[async_trait]
pub trait LocalInferenceTransportPolicy: Send + Sync {
    async fn execute(
        &self,
        handoff: &SidecarHandoff,
        request: LocalHttpRequest,
    ) -> Result<LocalHttpResponse, LocalTransportError>;

    async fn execute_streaming(
        &self,
        handoff: &SidecarHandoff,
        request: LocalHttpRequest,
    ) -> Result<(LocalHttpResponseHead, Box<dyn LocalBodyStream>), LocalTransportError>;
}

/// Remaining time until `deadline`, never a second independent clock.
pub fn remaining_until(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

/// Auth header names C238 must strip (no credential injection on the local path).
pub fn is_credential_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "authorization" || n == "x-api-key" || n == "api-key"
}

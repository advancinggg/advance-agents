//! cap-llm — MODULE-009 Slice B-2 — LLM gateway internals.
//!
//! Library crate providing:
//!
//! - [`LlmError`]: 7-variant error type matching MODULE-009 §1.4.1's WIT
//!   `llm-error` discriminants, with `variant_name()` (kebab-case strings
//!   for event-emission paths) and `is_retryable()` (delegates to
//!   [`classify_retryable`]).
//! - [`RetryConfig`] + [`backoff_ms`] + [`backoff_ms_with_fraction`] +
//!   [`classify_retryable`]: retry primitives for the §1.4.2 generate-flow
//!   loop. Slice B-1 added the loop integration; Slice B-2 wires the
//!   gateway, providers, structured-output, cost computation, event emission.
//! - [`ResolvedProvider`] + [`resolve_provider_and_model`]: pure-function
//!   resolver mapping `Option<&str>` model hint onto a (provider, model)
//!   tuple drawn from `RuntimeConfig::llm_providers` (CONTRACT-003).
//! - [`LlmGateway`] + [`LlmGatewayInternal`] (CONTRACT-081 trait surface):
//!   production gateway exposing `chat`, `embed`, and `stream` plus the
//!   non-trait public method `chat_for_run(messages, params, run_id)`
//!   (round-4 C1 — public verification surface for AC-15 RunBudget).
//! - [`ChatMessage`] / [`ChatRole`] / [`ChatParams`] / [`ChatResponse`] /
//!   [`ChatDelta`] / [`ToolDefinition`]: CONTRACT-081 public types.
//! - [`compute_cost`] (cost.rs), [`try_parse_and_validate`]
//!   (structured_output.rs), [`emit_llm_request`] / [`emit_llm_response`] /
//!   [`emit_llm_retry`] / [`emit_llm_error`] (events.rs): leaf utilities.
//! - [`register_agent_llm`] + handlers: registers `agent-llm/{generate,
//!   stream,poll-stream}` HostFunctionSpec entries; all three are implemented —
//!   the generate handler wires the real flow, and the stream/poll-stream
//!   handlers drive the buffered poll-stream lifecycle via a shared
//!   `StreamRegistry` (cap-llm-gaps 2026-06-04). `LlmGateway` also exposes the
//!   public `chat_structured(messages, params, output_schema, run_id)` surface.
//!
//! See MODULE-009 §3.7 Change History for slice context.

pub mod backend_local;
pub mod capability;
pub mod catalog;
pub mod cost;
pub mod error;
pub mod events;
pub mod gateway;
pub mod host_fn;
pub mod preflight;
pub mod provider;
// `providers` is crate-internal: `ProviderAdapter::parse_chat_response`
// returns the `pub(crate)` `ExecutionOutcome`, so the trait surface is
// only meaningful inside cap-llm. Sibling-crate consumption is out of
// scope for Slice B-2 (Slice C may revisit if external adapters need to
// be plugged in).
pub(crate) mod providers;
pub mod retry;
pub mod structured_output;
pub mod vlm;

pub(crate) mod executor;
// WIT poll-stream handle table + delta chunking (cap-llm-gaps 2026-06-04).
// Crate-internal — consumed by host_fn's stream/poll-stream handlers + gateway's
// stream_begin/stream_finish; not part of the CONTRACT-081 public surface.
pub(crate) mod stream;

#[cfg(test)]
mod local_endpoint_tests;

#[cfg(test)]
mod test_support;

pub use backend_local::{
    FailedSpawnBackend, OwnedHandoffSupervisor, ProcessSupervisor, SidecarClient,
    StaticHandoffSupervisor, SupervisedChild,
};
pub use catalog::ModelProfileCatalog;
pub use cost::compute_cost;
pub use error::LlmError;
pub use events::{LLM_ERROR, LLM_REQUEST, LLM_RESPONSE, LLM_RETRY};
pub use gateway::{
    ChatDelta, ChatMessage, ChatParams, ChatResponse, ChatRole, LlmGateway, LlmGatewayInternal,
    ToolDefinition,
};
pub use host_fn::{
    register_agent_llm, register_agent_llm_with_turn_cost, AgentLlmGenerateHandler,
    AgentLlmPollStreamHandler, AgentLlmStreamHandler, AgentStreamReaper, ReapBatch,
};
pub use preflight::{
    chat_preflight, DiscardEventBus, NoopRepetition, PreflightAllowBudget, StaticConfig,
};
pub use provider::{resolve_provider_and_model, ResolvedProvider};
pub use retry::{
    backoff_ms, backoff_ms_with_fraction, classify_retryable, PartialRetry, RetryConfig,
};
pub use structured_output::try_parse_and_validate;
pub use vlm::{dispatch_for_indexing, FileContent, LlmGatewayVlm, VlmExtractor};
// `executor::*` (LlmExecutor / ExecutionOutcome / execute_with_retry / MAX_RETRIES_HARD_CAP)
// stays crate-internal — Slice B-1 ships them as cap-llm internals consumed by gateway.rs;
// not part of CONTRACT-081's `LlmGatewayInternal` public surface, so kept off `pub use`.
// `retry::resolve_retry_config` is crate-internal; `PartialRetry` went pub in the
// small-witness slice (2026-06-11) as the carrier for `LlmGateway::with_retry_overrides`.

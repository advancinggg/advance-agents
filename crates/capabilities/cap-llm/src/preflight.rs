//! First-open generate-path preflight (MODULE-009-AC-31/32).
//!
//! No CONTRACT-243 types. No SecretStore in the signature.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use advance_runtime::config::{RuntimeConfig, RuntimeConfigProvider};
use advance_shared_types::capability::BudgetDecision;
use advance_shared_types::event::Event;
use advance_shared_types::repetition::{OutputHash, RepetitionDecision, ToolCallSignature};
use advance_shared_types::security_validator::HttpSecurityChain;
use advance_shared_types::traits::{EventBusEmit, RepetitionGuardCheck, RunBudget};
use tokio::sync::mpsc;

use crate::gateway::{ChatMessage, ChatParams, ChatRole, LlmGateway, LlmGatewayInternal};
use crate::LlmError;

pub struct PreflightAllowBudget;

impl RunBudget for PreflightAllowBudget {
    fn check(
        &self,
        _run_id: &str,
        _additional_tokens: u64,
        _additional_cost: f64,
    ) -> BudgetDecision {
        BudgetDecision::Allow
    }
    fn commit(&self, _run_id: &str, _tokens: u64, _cost: f64) {}
}

pub struct DiscardEventBus;

impl EventBusEmit for DiscardEventBus {
    fn emit(&self, _event: Event) {}
}

pub struct NoopRepetition;

impl RepetitionGuardCheck for NoopRepetition {
    fn record_tool_call(&self, _agent_id: &str, _sig: ToolCallSignature) -> RepetitionDecision {
        RepetitionDecision::Pass
    }
    fn record_output(&self, _agent_id: &str, _output_hash: OutputHash) -> RepetitionDecision {
        RepetitionDecision::Pass
    }
}

pub struct StaticConfig(pub Arc<RuntimeConfig>);

impl RuntimeConfigProvider for StaticConfig {
    fn current(&self) -> Arc<RuntimeConfig> {
        Arc::clone(&self.0)
    }
    fn subscribe(&self) -> mpsc::Receiver<Arc<RuntimeConfig>> {
        let (_tx, rx) = mpsc::channel(1);
        rx
    }
    fn last_error(&self) -> Option<String> {
        None
    }
}

/// `config.llm_providers` MUST be a one-element list (named provider).
pub async fn chat_preflight(
    config: Arc<dyn RuntimeConfigProvider>,
    chain: Arc<dyn HttpSecurityChain>,
    event_bus: Arc<dyn EventBusEmit>,
    is_cancelled: &AtomicBool,
) -> Result<(), LlmError> {
    if is_cancelled.load(Ordering::SeqCst) {
        return Err(LlmError::ProviderError("cancelled".into()));
    }
    let gateway = LlmGateway::new(
        config,
        chain,
        Arc::new(PreflightAllowBudget),
        event_bus,
        Arc::new(NoopRepetition),
        "default-agent".into(),
    );
    let params = ChatParams {
        model: None,
        temperature: None,
        max_tokens: Some(16),
        stop_sequences: None,
        tools: None,
    };
    let messages = vec![ChatMessage {
        role: ChatRole::User,
        content: "ping".into(),
    }];
    if is_cancelled.load(Ordering::SeqCst) {
        return Err(LlmError::ProviderError("cancelled".into()));
    }
    gateway.chat(messages, params).await?;
    if is_cancelled.load(Ordering::SeqCst) {
        return Err(LlmError::ProviderError("cancelled".into()));
    }
    Ok(())
}

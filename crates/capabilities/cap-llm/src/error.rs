//! LlmError — the seven-variant error type for cap-llm, lowered from the
//! WIT `llm-error` variant in MODULE-009 §1.4.1. Slice A ships the Rust
//! representation; Slice B will add the WIT lowering (`Val`-encoding side)
//! in `wit_impl.rs` once the `agent-llm` interface lands in
//! `crates/runtime/wit/advance.wit`.

use std::fmt;

/// LLM-gateway error variants. Variant names are kebab-case strings matching
/// the WIT discriminants in MODULE-009 §1.4.1.
///
/// Retryability is delegated to [`crate::retry::classify_retryable`] (the
/// AC-06 truth table). Use [`LlmError::is_retryable`] for the question form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LlmError {
    ModelNotAvailable(String),
    RateLimited(String),
    ContextTooLong(String),
    BudgetExceeded(String),
    ProviderError(String),
    StructuredOutputFailed(String),
    RepetitionTerminated(String),
}

impl LlmError {
    /// Stable kebab-case discriminant for event-emission paths and audit
    /// logs. Matches the WIT variant names in §1.4.1.
    pub fn variant_name(&self) -> &'static str {
        match self {
            LlmError::ModelNotAvailable(_) => "model-not-available",
            LlmError::RateLimited(_) => "rate-limited",
            LlmError::ContextTooLong(_) => "context-too-long",
            LlmError::BudgetExceeded(_) => "budget-exceeded",
            LlmError::ProviderError(_) => "provider-error",
            LlmError::StructuredOutputFailed(_) => "structured-output-failed",
            LlmError::RepetitionTerminated(_) => "repetition-terminated",
        }
    }

    /// Returns `true` for variants the transport retry loop should re-attempt.
    /// Delegates to [`crate::retry::classify_retryable`] so there is a single
    /// source of truth (AC-06 + §1.4.4 truth table).
    pub fn is_retryable(&self) -> bool {
        crate::retry::classify_retryable(self)
    }

    fn payload(&self) -> &str {
        match self {
            LlmError::ModelNotAvailable(s)
            | LlmError::RateLimited(s)
            | LlmError::ContextTooLong(s)
            | LlmError::BudgetExceeded(s)
            | LlmError::ProviderError(s)
            | LlmError::StructuredOutputFailed(s)
            | LlmError::RepetitionTerminated(s) => s,
        }
    }
}

impl fmt::Display for LlmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.variant_name(), self.payload())
    }
}

impl std::error::Error for LlmError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_variant_name_kebab_case() {
        assert_eq!(
            LlmError::ModelNotAvailable("x".into()).variant_name(),
            "model-not-available"
        );
        assert_eq!(
            LlmError::RateLimited("x".into()).variant_name(),
            "rate-limited"
        );
        assert_eq!(
            LlmError::ContextTooLong("x".into()).variant_name(),
            "context-too-long"
        );
        assert_eq!(
            LlmError::BudgetExceeded("x".into()).variant_name(),
            "budget-exceeded"
        );
        assert_eq!(
            LlmError::ProviderError("x".into()).variant_name(),
            "provider-error"
        );
        assert_eq!(
            LlmError::StructuredOutputFailed("x".into()).variant_name(),
            "structured-output-failed"
        );
        assert_eq!(
            LlmError::RepetitionTerminated("x".into()).variant_name(),
            "repetition-terminated"
        );
    }

    #[test]
    fn t_is_retryable_via_classify() {
        for err in [
            LlmError::ModelNotAvailable("x".into()),
            LlmError::RateLimited("x".into()),
            LlmError::ContextTooLong("x".into()),
            LlmError::BudgetExceeded("x".into()),
            LlmError::ProviderError("x".into()),
            LlmError::StructuredOutputFailed("x".into()),
            LlmError::RepetitionTerminated("x".into()),
        ] {
            assert_eq!(err.is_retryable(), crate::retry::classify_retryable(&err));
        }
    }

    #[test]
    fn t_display_format() {
        let err = LlmError::RateLimited("anthropic 429".into());
        assert_eq!(format!("{err}"), "rate-limited: anthropic 429");
    }
}

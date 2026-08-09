//! `WitMemoryError` — Rust mirror of the `agent-memory` WIT `memory-error`
//! variant (`runtime/wit/advance.wit` slice-B addition). Slice B has three
//! variants: `not-found(string)` / `storage-error(string)` /
//! `limit-exceeded(string)`. All cap-memory WIT host handlers lower a
//! `Result<_, WitMemoryError>` into a `Val::Result(Err(Some(Box::new(
//! wit_memory_error_to_val(&err)))))` (or `Val::Result(Err(None))` for the
//! parameterless variant — none of slice B's three variants are unit, so the
//! lowering always carries a `Some(payload)`).
//!
//! Internal cap-memory module — NOT promoted to shared-types.

use advance_shared_types::memory::PostProcessorError;
use wasmtime::component::Val;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WitMemoryError {
    NotFound(String),
    StorageError(String),
    LimitExceeded(String),
}

/// Lower a `WitMemoryError` into a `Val::Variant` whose discriminant string
/// matches the WIT case name (kebab-case per the wit declaration). Returns the
/// inner payload Val; the caller wraps it in `Val::Result(Err(Some(Box::new(
/// ...))))`.
pub fn wit_memory_error_to_val(err: &WitMemoryError) -> Val {
    match err {
        WitMemoryError::NotFound(s) => {
            Val::Variant("not-found".into(), Some(Box::new(Val::String(s.clone()))))
        }
        WitMemoryError::StorageError(s) => Val::Variant(
            "storage-error".into(),
            Some(Box::new(Val::String(s.clone()))),
        ),
        WitMemoryError::LimitExceeded(s) => Val::Variant(
            "limit-exceeded".into(),
            Some(Box::new(Val::String(s.clone()))),
        ),
    }
}

impl From<PostProcessorError> for WitMemoryError {
    fn from(e: PostProcessorError) -> Self {
        match e {
            PostProcessorError::LlmFailure(s) => Self::StorageError(s),
            PostProcessorError::StorageError(s) => Self::StorageError(s),
            PostProcessorError::LimitExceeded => {
                Self::LimitExceeded("per-agent memory cap reached".into())
            }
            PostProcessorError::Invalid(s) => Self::StorageError(format!("invalid: {}", s)),
            PostProcessorError::CooldownActive => {
                Self::StorageError("post-processor in cooldown".into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowering_each_variant_carries_payload() {
        let val = wit_memory_error_to_val(&WitMemoryError::NotFound("x".into()));
        match val {
            Val::Variant(name, Some(payload)) => {
                assert_eq!(name, "not-found");
                assert!(matches!(*payload, Val::String(ref s) if s == "x"));
            }
            other => panic!("expected Variant, got {:?}", other),
        }
    }

    #[test]
    fn storage_error_lowers_to_storage_error_variant() {
        let val = wit_memory_error_to_val(&WitMemoryError::StorageError("disk".into()));
        match val {
            Val::Variant(name, _) => assert_eq!(name, "storage-error"),
            other => panic!("expected Variant, got {:?}", other),
        }
    }

    #[test]
    fn limit_exceeded_lowers_to_limit_exceeded_variant() {
        let val = wit_memory_error_to_val(&WitMemoryError::LimitExceeded("cap".into()));
        match val {
            Val::Variant(name, _) => assert_eq!(name, "limit-exceeded"),
            other => panic!("expected Variant, got {:?}", other),
        }
    }

    #[test]
    fn post_processor_error_conversions() {
        let we: WitMemoryError = PostProcessorError::LimitExceeded.into();
        assert!(matches!(we, WitMemoryError::LimitExceeded(_)));
        let we: WitMemoryError = PostProcessorError::Invalid("bad shape".into()).into();
        assert!(matches!(we, WitMemoryError::StorageError(s) if s.contains("bad shape")));
    }
}

//! `BatchExtractor` — internal cap-memory trait for the post-processor's Step 2
//! batch LLM extraction call. NOT promoted to `shared-types` — kept inside the
//! cap-memory crate per the dependency-injection seam pattern (production
//! adapters will wire to MODULE-009 CONTRACT-081 `LlmGatewayInternal::chat` in a
//! later slice).
//!
//! Slice B ships:
//! - The `BatchExtractor` async trait + `Extraction` / `ExtractionContext` / `BatchExtractorError` types.
//! - `StubBatchExtractor` — a test seam with configurable success/failure
//!   response and a `call_count()` observer for the AC-09 cooldown test
//!   ("`BatchExtractor::extract` is not re-called within the cooldown window").

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use advance_shared_types::mailbox::{ActionResult, Message};
use async_trait::async_trait;

use crate::knowledge::MemoryEntry;

/// Borrow bundle handed to the extractor. All three fields share lifetime `'a`;
/// extractor implementations MUST NOT retain them past the async return.
pub struct ExtractionContext<'a> {
    pub agent_id: &'a str,
    pub msg: &'a Message,
    pub result: &'a ActionResult,
}

/// LLM extraction result (or mechanical-digest fallback). `knowledge` carries
/// fully-formed `MemoryEntry` records (each satisfying `validate_invariants`).
/// `descriptions` is collected for Step 3 `.meta.yaml` write-back (waived_scope
/// for slice B — present but ignored by the slice B Step 3 stub).
#[derive(Clone, Debug, Default)]
pub struct Extraction {
    pub descriptions: Vec<DescriptionUpdate>,
    pub knowledge: Vec<MemoryEntry>,
    /// Single-sentence turn digest produced by the BatchExtractor (AC-38,
    /// REQ-227). `Some(..)` on the LLM success path → propagated VERBATIM into
    /// `TurnEntry.digest` by [`crate::turn_index::build_turn_digest`]; `None`
    /// on the mechanical-digest fallback path → `build_turn_digest` synthesizes
    /// a deterministic mechanical digest. Additive `Option` field so every
    /// existing `..Default::default()` construction site stays valid.
    pub digest: Option<String>,
}

#[derive(Clone, Debug)]
pub struct DescriptionUpdate {
    pub path: String,
    pub description: String,
}

#[derive(Clone, Debug)]
pub enum BatchExtractorError {
    /// Light-model LLM call failed after retries. Step 2 records the failure
    /// in `FailureCooldown` and falls through to the mechanical-digest path.
    LlmFailure(String),
    /// Schema validation failed on the extractor's output. Step 2 bubbles
    /// this up as `PostProcessorError::Invalid` (a hard error — distinguish
    /// from `LlmFailure`'s partial-degrade contract).
    Invalid(String),
}

#[async_trait]
pub trait BatchExtractor: Send + Sync {
    async fn extract(&self, ctx: &ExtractionContext<'_>)
        -> Result<Extraction, BatchExtractorError>;
}

/// Test stub for `BatchExtractor`. Constructed via `with_extraction` (returns
/// the configured `Extraction` on every call) or `fail_with` (returns the
/// configured error on every call). Exposes `call_count()` for the AC-09
/// cooldown test's "not re-called inside the cooldown window" assertion.
pub struct StubBatchExtractor {
    response: Mutex<StubResponse>,
    call_count: AtomicU64,
}

enum StubResponse {
    Ok(Extraction),
    Err(BatchExtractorError),
}

impl StubBatchExtractor {
    pub fn with_extraction(extraction: Extraction) -> Self {
        Self {
            response: Mutex::new(StubResponse::Ok(extraction)),
            call_count: AtomicU64::new(0),
        }
    }

    pub fn fail_with(err: BatchExtractorError) -> Self {
        Self {
            response: Mutex::new(StubResponse::Err(err)),
            call_count: AtomicU64::new(0),
        }
    }

    pub fn call_count(&self) -> u64 {
        self.call_count.load(Ordering::SeqCst)
    }

    /// Swap the configured response. Useful for tests that need to verify
    /// recovery after a cooldown window expires.
    pub fn set_response_ok(&self, extraction: Extraction) {
        let mut guard = self
            .response
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = StubResponse::Ok(extraction);
    }
}

#[async_trait]
impl BatchExtractor for StubBatchExtractor {
    async fn extract(
        &self,
        _ctx: &ExtractionContext<'_>,
    ) -> Result<Extraction, BatchExtractorError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        let guard = self
            .response
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &*guard {
            StubResponse::Ok(e) => Ok(e.clone()),
            StubResponse::Err(e) => Err(e.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge::{MemoryEntry, MemoryStatus, MemoryType};
    use advance_shared_types::mailbox::{ActionResult, Message, MessageKind};
    use std::time::SystemTime;

    fn fixture_message() -> Message {
        Message {
            id: "msg-1".into(),
            kind: MessageKind::User,
            from: "user".into(),
            to: "agent".into(),
            payload: vec![1, 2, 3],
            context: None,
            timestamp: SystemTime::UNIX_EPOCH,
            origin: None,
        }
    }

    fn fixture_result() -> ActionResult {
        ActionResult {
            new_state: vec![],
            actions: vec![],
        }
    }

    fn fixture_entry() -> MemoryEntry {
        MemoryEntry {
            id: "id-1".into(),
            agent_id: "agent".into(),
            entry_type: MemoryType::Fact,
            content: "hello".into(),
            tags: vec![],
            created_at: "1970-01-01T00:00:00Z".into(),
            task_origin: None,
            is_active: true,
            superseded_by: None,
            status: MemoryStatus::Active,
            supersession_reason: None,
            cluster_id: None,
            sources: vec![],
        }
    }

    #[tokio::test]
    async fn stub_with_extraction_returns_clone() {
        let extraction = Extraction {
            descriptions: vec![],
            knowledge: vec![fixture_entry()],
            digest: None,
        };
        let stub = StubBatchExtractor::with_extraction(extraction);
        let msg = fixture_message();
        let result = fixture_result();
        let ctx = ExtractionContext {
            agent_id: "agent",
            msg: &msg,
            result: &result,
        };
        let r1 = stub.extract(&ctx).await.expect("first call");
        let r2 = stub.extract(&ctx).await.expect("second call");
        assert_eq!(r1.knowledge.len(), 1);
        assert_eq!(r2.knowledge.len(), 1);
        assert_eq!(stub.call_count(), 2);
    }

    #[tokio::test]
    async fn stub_fail_with_returns_error_each_call() {
        let stub = StubBatchExtractor::fail_with(BatchExtractorError::LlmFailure("boom".into()));
        let msg = fixture_message();
        let result = fixture_result();
        let ctx = ExtractionContext {
            agent_id: "agent",
            msg: &msg,
            result: &result,
        };
        assert!(matches!(
            stub.extract(&ctx).await,
            Err(BatchExtractorError::LlmFailure(_))
        ));
        assert!(matches!(
            stub.extract(&ctx).await,
            Err(BatchExtractorError::LlmFailure(_))
        ));
        assert_eq!(stub.call_count(), 2);
    }
}

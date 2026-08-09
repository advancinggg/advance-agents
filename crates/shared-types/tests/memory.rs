//! Serde + wire-format + compile-check tests for `advance_shared_types::memory`.

use advance_shared_types::memory::{
    KnowledgeHealthSnapshot, L6Context, L6Cursor, L6Error, L6Handler, L6Outcome, L6RunnableSpec,
    PostProcessorError,
};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::SystemTime;

#[test]
fn post_processor_error_round_trip() {
    for e in [
        PostProcessorError::LlmFailure("x".to_string()),
        PostProcessorError::StorageError("s".to_string()),
        PostProcessorError::LimitExceeded,
        PostProcessorError::Invalid("schema".to_string()),
        PostProcessorError::CooldownActive,
    ] {
        let json = serde_json::to_string(&e).unwrap();
        let back: PostProcessorError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);
    }
}

#[test]
fn l6_error_round_trip() {
    for e in [
        L6Error::LlmFailure("x".to_string()),
        L6Error::StorageError("s".to_string()),
        L6Error::LeaseLost,
        L6Error::BudgetExhausted,
        L6Error::GitCommitFailed("g".to_string()),
    ] {
        let json = serde_json::to_string(&e).unwrap();
        let back: L6Error = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);
    }
}

#[test]
fn l6_cursor_round_trip() {
    let c = L6Cursor {
        last_knowledge_id: Some("k1".to_string()),
        last_completed_at: SystemTime::UNIX_EPOCH,
    };
    let json = serde_json::to_string(&c).unwrap();
    let back: L6Cursor = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}

#[test]
fn l6_context_round_trip() {
    let c = L6Context {
        agent_id: "agent:root".to_string(),
        triggered_at: SystemTime::UNIX_EPOCH,
        cursor: None,
        lease_token: "lease-1".to_string(),
    };
    let json = serde_json::to_string(&c).unwrap();
    let back: L6Context = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}

#[test]
fn l6_context_debug_redacts_lease_token() {
    let c = L6Context {
        agent_id: "agent:root".to_string(),
        triggered_at: SystemTime::UNIX_EPOCH,
        cursor: None,
        lease_token: "super-secret-lease-token".to_string(),
    };
    let dbg = format!("{:?}", c);
    assert!(dbg.contains("<redacted>"));
    assert!(!dbg.contains("super-secret-lease-token"));
    assert!(dbg.contains("agent:root"));
}

#[test]
fn knowledge_health_snapshot_round_trip() {
    let s = KnowledgeHealthSnapshot {
        total_active: 100,
        active: 90,
        contested: 5,
        orphaned: 2,
        forgotten: 3,
        superseded: 10,
        partial_stale: 4,
        zero_access_30d: 15,
        clusters_total: 20,
        clusters_contested: 2,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: KnowledgeHealthSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
}

#[test]
fn knowledge_health_snapshot_deny_unknown_fields() {
    let bad = r#"{"total_active":0,"active":0,"contested":0,"orphaned":0,"forgotten":0,"superseded":0,"partial_stale":0,"zero_access_30d":0,"clusters_total":0,"clusters_contested":0,"extra":true}"#;
    let err = serde_json::from_str::<KnowledgeHealthSnapshot>(bad).unwrap_err();
    assert_eq!(err.classify(), serde_json::error::Category::Data);
}

#[test]
fn l6_outcome_round_trip() {
    let o = L6Outcome {
        entries_written: 5,
        syntheses_written: 2,
        knowledge_map_updated: true,
        cluster_deltas: 1,
        health_snapshot: KnowledgeHealthSnapshot {
            total_active: 10,
            active: 9,
            contested: 1,
            orphaned: 0,
            forgotten: 0,
            superseded: 0,
            partial_stale: 0,
            zero_access_30d: 0,
            clusters_total: 3,
            clusters_contested: 1,
        },
    };
    let json = serde_json::to_string(&o).unwrap();
    let back: L6Outcome = serde_json::from_str(&json).unwrap();
    assert_eq!(back, o);
}

// L6RunnableSpec compile-check: Clone + manual Debug + Send + Sync.
// NOT a serde test (Arc<dyn L6Handler> is not serializable per plan §3.2).
struct StubL6Handler;

#[async_trait]
impl L6Handler for StubL6Handler {
    async fn handle(&self, _ctx: L6Context) -> Result<L6Outcome, L6Error> {
        Err(L6Error::BudgetExhausted)
    }
}

#[test]
fn l6_runnable_spec_clone_debug_smoke() {
    let spec = L6RunnableSpec {
        component_id: "cc-memory-l6".to_string(),
        trigger_event: "memory.l6_consolidation_due".to_string(),
        handler: Arc::new(StubL6Handler),
    };
    let cloned = spec.clone();
    assert_eq!(cloned.component_id, spec.component_id);
    let dbg = format!("{:?}", spec);
    // Manual Debug impl redacts handler to "<L6Handler>".
    assert!(dbg.contains("<L6Handler>"));
    assert!(dbg.contains("cc-memory-l6"));
    assert!(dbg.contains("memory.l6_consolidation_due"));
}

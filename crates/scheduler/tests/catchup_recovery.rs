//! AC-08 verification: `catch_up_components` dispatches missed
//! one-shot + missed recurring rows once at restart.
//!
//! Test fixture pre-populates the registry with rows whose
//! `expected_next_fire_at_ms` is in the past; mock `CatchupDispatcher`
//! records each `dispatch_catchup` invocation. Verifies:
//! - one-shot row (interval_ms=None) → dispatched once, expected_next_fire cleared
//! - recurring row (interval_ms=Some(N)) → dispatched once, expected_next_fire rescheduled to now+N
//! - second catch-up pass dispatches 0 (no missed fires after reset)
//! - dispatch failure preserves registry row state

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use advance_scheduler::{
    catch_up_components, CatchupDispatcher, CatchupKind, ComponentId, ComponentRegistry,
    ComponentRegistryRow, ComponentSubmitConfig, HookError,
};
use advance_shared_types::component::ComponentType;

#[derive(Default)]
struct RecordingDispatcher {
    calls: Arc<Mutex<Vec<(ComponentId, CatchupKind)>>>,
    fail_for: Option<String>,
}

impl RecordingDispatcher {
    fn new() -> Self {
        Self::default()
    }

    fn failing_for(id: &str) -> Self {
        Self {
            calls: Default::default(),
            fail_for: Some(id.to_owned()),
        }
    }

    async fn recorded(&self) -> Vec<(ComponentId, CatchupKind)> {
        self.calls.lock().await.clone()
    }
}

#[async_trait]
impl CatchupDispatcher for RecordingDispatcher {
    async fn dispatch_catchup(&self, row: &ComponentRegistryRow) -> Result<(), HookError> {
        if let Some(ref id) = self.fail_for {
            if row.id.as_str() == id {
                return Err(HookError::Failure(format!(
                    "synthetic dispatch failure for {id}"
                )));
            }
        }
        let mut calls = self.calls.lock().await;
        calls.push((
            row.id.clone(),
            match row.interval_ms {
                Some(_) => CatchupKind::RecurringMissed,
                None => CatchupKind::OneShotMissed,
            },
        ));
        Ok(())
    }
}

fn dummy_cfg(id: &str, t: ComponentType) -> ComponentSubmitConfig {
    ComponentSubmitConfig {
        sensitive_params: Vec::new(),
        id: id.into(),
        component_type: t,
        binary: Vec::new(),
        capabilities: Vec::new(),
        output_dir: None,
        trigger: None,
        restart_policy: None,
        delay: None,
        initial_grants: None,
        preset: None,
        retry: None,
    }
}

#[tokio::test]
async fn missed_oneshot_fires_once_and_clears() {
    let tempdir = tempfile::tempdir().unwrap();
    let reg = ComponentRegistry::open_in(tempdir.path(), "components.db")
        .await
        .unwrap();
    // task-b: one-shot, expected_next_fire 1s in past.
    let now = 1_000_000_000_000_i64;
    reg.insert(
        "agent:root",
        &dummy_cfg("task-b", ComponentType::Task),
        None,
    )
    .await
    .unwrap();
    reg.set_expected_next_fire("task-b", Some(now - 1_000))
        .await
        .unwrap();

    let dispatcher = RecordingDispatcher::new();
    let outcomes = catch_up_components(&reg, now, &dispatcher).await.unwrap();

    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].id.as_str(), "task-b");
    assert_eq!(outcomes[0].kind, CatchupKind::OneShotMissed);
    assert!(outcomes[0].dispatched_ok);
    assert!(!outcomes[0].registry_write_failed);

    let calls = dispatcher.recorded().await;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0.as_str(), "task-b");

    // expected_next_fire_at_ms cleared.
    let row = reg.get("task-b").await.unwrap().unwrap();
    assert_eq!(row.expected_next_fire_at_ms, None);
    assert_eq!(row.last_fire_at_ms, Some(now));
}

#[tokio::test]
async fn missed_recurring_fires_once_and_reschedules() {
    let tempdir = tempfile::tempdir().unwrap();
    let reg = ComponentRegistry::open_in(tempdir.path(), "components.db")
        .await
        .unwrap();
    let now = 1_000_000_000_000_i64;
    // cron-a: recurring 5s interval, expected_next_fire 10s in past.
    reg.insert(
        "agent:root",
        &dummy_cfg("cron-a", ComponentType::Cron),
        Some(5_000),
    )
    .await
    .unwrap();
    reg.set_expected_next_fire("cron-a", Some(now - 10_000))
        .await
        .unwrap();

    let dispatcher = RecordingDispatcher::new();
    let outcomes = catch_up_components(&reg, now, &dispatcher).await.unwrap();

    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].id.as_str(), "cron-a");
    assert_eq!(outcomes[0].kind, CatchupKind::RecurringMissed);
    assert!(outcomes[0].dispatched_ok);

    // expected_next_fire_at_ms rescheduled to now + interval.
    let row = reg.get("cron-a").await.unwrap().unwrap();
    assert_eq!(row.expected_next_fire_at_ms, Some(now + 5_000));
    assert_eq!(row.last_fire_at_ms, Some(now));
}

#[tokio::test]
async fn second_pass_no_fires() {
    let tempdir = tempfile::tempdir().unwrap();
    let reg = ComponentRegistry::open_in(tempdir.path(), "components.db")
        .await
        .unwrap();
    let now = 1_000_000_000_000_i64;
    reg.insert(
        "agent:root",
        &dummy_cfg("cron-a", ComponentType::Cron),
        Some(5_000),
    )
    .await
    .unwrap();
    reg.set_expected_next_fire("cron-a", Some(now - 10_000))
        .await
        .unwrap();
    reg.insert(
        "agent:root",
        &dummy_cfg("task-b", ComponentType::Task),
        None,
    )
    .await
    .unwrap();
    reg.set_expected_next_fire("task-b", Some(now - 1_000))
        .await
        .unwrap();

    let dispatcher = RecordingDispatcher::new();
    // First pass: both fire.
    let outcomes = catch_up_components(&reg, now, &dispatcher).await.unwrap();
    assert_eq!(outcomes.len(), 2);

    // Second pass at now+1 ms: cron-a is rescheduled to now+5000 (still future
    // relative to now+1); task-b is cleared. NO new fires.
    let dispatcher2 = RecordingDispatcher::new();
    let outcomes2 = catch_up_components(&reg, now + 1, &dispatcher2)
        .await
        .unwrap();
    assert_eq!(outcomes2.len(), 0);
    let calls2 = dispatcher2.recorded().await;
    assert!(calls2.is_empty());
}

#[tokio::test]
async fn dispatch_failure_preserves_row_state() {
    let tempdir = tempfile::tempdir().unwrap();
    let reg = ComponentRegistry::open_in(tempdir.path(), "components.db")
        .await
        .unwrap();
    let now = 1_000_000_000_000_i64;
    reg.insert(
        "agent:root",
        &dummy_cfg("cron-a", ComponentType::Cron),
        Some(5_000),
    )
    .await
    .unwrap();
    reg.set_expected_next_fire("cron-a", Some(now - 10_000))
        .await
        .unwrap();

    let dispatcher = RecordingDispatcher::failing_for("cron-a");
    let outcomes = catch_up_components(&reg, now, &dispatcher).await.unwrap();

    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].id.as_str(), "cron-a");
    assert!(!outcomes[0].dispatched_ok);
    assert!(outcomes[0].error_message.is_some());

    // Registry row unchanged: expected_next_fire_at_ms still in past;
    // last_fire_at_ms still None.
    let row = reg.get("cron-a").await.unwrap().unwrap();
    assert_eq!(row.expected_next_fire_at_ms, Some(now - 10_000));
    assert_eq!(row.last_fire_at_ms, None);
}

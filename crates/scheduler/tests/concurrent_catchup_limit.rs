//! AC-10 (MODULE-014-AC-10 / REQ-058, T08) verification: expired-task
//! catch-up is limited to `max_concurrent_catchup` (default 3).
//!
//! `TaskRunner::run_expired_catchup` (explicit cap) +
//! `run_expired_catchup_default` (binds `DEFAULT_MAX_CONCURRENT_CATCHUP` =
//! 3) reuse the public `CatchupDispatcher` trait over the SQLite
//! `ComponentRegistry`; `catch_up_components` (AC-08) is untouched. Verified
//! at the helper boundary per the §3.5 "lowest stable boundary" contract
//! (same level as AC-08 fixture-driven `catch_up_components`). Cross-
//! invocation duplicate-dispatch concurrency is the waived Slice-E item;
//! T08.f only exercises SEQUENTIAL invocations.
//!
//! Fixture pattern mirrors `catchup_recovery.rs`: rows are made overdue by
//! `insert` + `set_expected_next_fire(id, Some(past))`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use advance_scheduler::task::TaskRunner;
use advance_scheduler::{
    CatchupDispatcher, ComponentRegistry, ComponentRegistryRow, ComponentSubmitConfig, HookError,
};
use advance_shared_types::component::ComponentType;

const NOW: i64 = 10_000_000;

/// Mock dispatcher: tracks peak concurrent in-flight `dispatch_catchup`
/// calls + a total dispatched count. Held behind `Arc` so the test reads
/// the atomics after `run_expired_catchup` returns.
#[derive(Default)]
struct MaxObservingDispatcher {
    in_flight: AtomicUsize,
    max_observed: AtomicUsize,
    dispatched: AtomicUsize,
}

impl MaxObservingDispatcher {
    fn max(&self) -> usize {
        self.max_observed.load(Ordering::SeqCst)
    }
    fn count(&self) -> usize {
        self.dispatched.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl CatchupDispatcher for MaxObservingDispatcher {
    async fn dispatch_catchup(&self, _row: &ComponentRegistryRow) -> Result<(), HookError> {
        let cur = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_observed.fetch_max(cur, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(30)).await;
        self.dispatched.fetch_add(1, Ordering::SeqCst);
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        Ok(())
    }
}

fn cfg(id: &str, t: ComponentType) -> ComponentSubmitConfig {
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

/// Insert an overdue one-shot row (`interval_ms = None`).
async fn insert_overdue_oneshot(reg: &ComponentRegistry, id: &str) {
    reg.insert("agent:root", &cfg(id, ComponentType::Task), None)
        .await
        .expect("insert");
    reg.set_expected_next_fire(id, Some(NOW - 1_000))
        .await
        .expect("set overdue");
}

// T08.a — 10 overdue rows, explicit cap 3: never more than 3 concurrent;
// all 10 dispatched exactly once.
#[tokio::test]
async fn t08a_explicit_cap_3_bounds_concurrency() {
    let td = tempfile::tempdir().unwrap();
    let reg = Arc::new(
        ComponentRegistry::open_in(td.path(), "components.db")
            .await
            .expect("open_in"),
    );
    for i in 0..10 {
        insert_overdue_oneshot(&reg, &format!("r{i}")).await;
    }
    let mock = Arc::new(MaxObservingDispatcher::default());
    let outcomes = TaskRunner::run_expired_catchup(Arc::clone(&reg), NOW, mock.clone(), 3)
        .await
        .expect("run_expired_catchup ok");
    assert_eq!(outcomes.len(), 10);
    assert_eq!(mock.count(), 10, "all 10 overdue rows dispatched once");
    assert!(
        mock.max() <= 3,
        "concurrency exceeded cap 3: {}",
        mock.max()
    );
    assert!(mock.max() >= 1);
}

// T08.b — default-consuming entry binds DEFAULT_MAX_CONCURRENT_CATCHUP (3).
#[tokio::test]
async fn t08b_default_entry_binds_default_cap() {
    let td = tempfile::tempdir().unwrap();
    let reg = Arc::new(
        ComponentRegistry::open_in(td.path(), "components.db")
            .await
            .expect("open_in"),
    );
    for i in 0..8 {
        insert_overdue_oneshot(&reg, &format!("d{i}")).await;
    }
    let mock = Arc::new(MaxObservingDispatcher::default());
    let outcomes = TaskRunner::run_expired_catchup_default(Arc::clone(&reg), NOW, mock.clone())
        .await
        .expect("default ok");
    assert_eq!(outcomes.len(), 8);
    assert_eq!(mock.count(), 8);
    assert!(
        mock.max() <= 3,
        "default cap (DEFAULT_MAX_CONCURRENT_CATCHUP=3) exceeded: {}",
        mock.max()
    );
}

// T08.c — fewer overdue than the cap: cap is a ceiling, not a floor.
#[tokio::test]
async fn t08c_cap_is_ceiling_not_floor() {
    let td = tempfile::tempdir().unwrap();
    let reg = Arc::new(
        ComponentRegistry::open_in(td.path(), "components.db")
            .await
            .expect("open_in"),
    );
    insert_overdue_oneshot(&reg, "a").await;
    insert_overdue_oneshot(&reg, "b").await;
    let mock = Arc::new(MaxObservingDispatcher::default());
    let outcomes = TaskRunner::run_expired_catchup(Arc::clone(&reg), NOW, mock.clone(), 3)
        .await
        .expect("ok");
    assert_eq!(outcomes.len(), 2);
    assert_eq!(mock.count(), 2);
    assert!(mock.max() <= 2, "only 2 rows → max in-flight ≤ 2");
}

// T08.d — reschedule parity with AC-08: recurring → expected_next_fire =
// now + interval; one-shot → cleared NULL.
#[tokio::test]
async fn t08d_reschedule_semantics_parity() {
    let td = tempfile::tempdir().unwrap();
    let reg = Arc::new(
        ComponentRegistry::open_in(td.path(), "components.db")
            .await
            .expect("open_in"),
    );
    reg.insert("agent:root", &cfg("rec", ComponentType::Cron), Some(5_000))
        .await
        .expect("insert recurring");
    reg.set_expected_next_fire("rec", Some(NOW - 1_000))
        .await
        .expect("overdue");
    insert_overdue_oneshot(&reg, "os").await;

    let mock = Arc::new(MaxObservingDispatcher::default());
    TaskRunner::run_expired_catchup(Arc::clone(&reg), NOW, mock.clone(), 3)
        .await
        .expect("ok");

    let rec = reg.get("rec").await.expect("ok").expect("present");
    assert_eq!(
        rec.expected_next_fire_at_ms,
        Some(NOW + 5_000),
        "recurring row rescheduled to now + interval"
    );
    let os = reg.get("os").await.expect("ok").expect("present");
    assert_eq!(
        os.expected_next_fire_at_ms, None,
        "one-shot row's expected_next_fire cleared to NULL"
    );
}

// T08.e — non-overdue rows are not dispatched.
#[tokio::test]
async fn t08e_non_overdue_not_dispatched() {
    let td = tempfile::tempdir().unwrap();
    let reg = Arc::new(
        ComponentRegistry::open_in(td.path(), "components.db")
            .await
            .expect("open_in"),
    );
    reg.insert("agent:root", &cfg("future", ComponentType::Task), None)
        .await
        .expect("insert");
    reg.set_expected_next_fire("future", Some(NOW + 100_000))
        .await
        .expect("set future");
    let mock = Arc::new(MaxObservingDispatcher::default());
    let outcomes = TaskRunner::run_expired_catchup(Arc::clone(&reg), NOW, mock.clone(), 3)
        .await
        .expect("ok");
    assert!(outcomes.is_empty(), "no overdue rows → no dispatch");
    assert_eq!(mock.count(), 0);
}

// T08.f — SEQUENTIAL idempotency parity with catch_up_components: 1st pass
// dispatches; 2nd pass (same `now`) dispatches 0 (one-shot cleared;
// recurring rescheduled beyond `now`). Cross-invocation *concurrency* is
// the waived_scope item and is explicitly NOT tested here.
#[tokio::test]
async fn t08f_sequential_invocation_idempotency() {
    let td = tempfile::tempdir().unwrap();
    let reg = Arc::new(
        ComponentRegistry::open_in(td.path(), "components.db")
            .await
            .expect("open_in"),
    );
    insert_overdue_oneshot(&reg, "f-os").await;
    reg.insert(
        "agent:root",
        &cfg("f-rec", ComponentType::Cron),
        Some(5_000),
    )
    .await
    .expect("insert recurring");
    reg.set_expected_next_fire("f-rec", Some(NOW - 1_000))
        .await
        .expect("overdue");

    let m1 = Arc::new(MaxObservingDispatcher::default());
    let o1 = TaskRunner::run_expired_catchup_default(Arc::clone(&reg), NOW, m1.clone())
        .await
        .expect("1st pass ok");
    assert_eq!(o1.len(), 2, "1st pass dispatches both overdue rows");
    assert_eq!(m1.count(), 2);

    let m2 = Arc::new(MaxObservingDispatcher::default());
    let o2 = TaskRunner::run_expired_catchup_default(Arc::clone(&reg), NOW, m2.clone())
        .await
        .expect("2nd pass ok");
    assert!(
        o2.is_empty(),
        "2nd sequential pass at same now dispatches 0 (one-shot cleared, recurring rescheduled to now+interval)"
    );
    assert_eq!(m2.count(), 0);
}

/// Dispatcher that panics on the `poison` row, succeeds (after a short
/// await) on every other — used to prove drain-before-reraise.
struct PanicOnPoison;

#[async_trait]
impl CatchupDispatcher for PanicOnPoison {
    async fn dispatch_catchup(&self, row: &ComponentRegistryRow) -> Result<(), HookError> {
        if row.id.as_str() == "poison" {
            panic!("injected dispatcher panic on `poison`");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        Ok(())
    }
}

// T08.g — adversarial r12 W1 regression: a dispatcher panic on ONE
// overdue row must NOT abandon sibling rows' `record_fire` bookkeeping.
// `run_expired_catchup` drains the whole JoinSet before re-raising the
// panic, so every healthy one-shot row is still cleared (record_fire
// completed) AND the injected panic still propagates (non-swallowing).
#[tokio::test]
async fn t08g_sibling_panic_does_not_abandon_record_fire() {
    let td = tempfile::tempdir().unwrap();
    let reg = Arc::new(
        ComponentRegistry::open_in(td.path(), "components.db")
            .await
            .expect("open_in"),
    );
    // 5 healthy overdue one-shot rows + 1 overdue "poison" row.
    for i in 0..5 {
        insert_overdue_oneshot(&reg, &format!("ok{i}")).await;
    }
    insert_overdue_oneshot(&reg, "poison").await;

    let reg2 = Arc::clone(&reg);
    let jh = tokio::spawn(async move {
        TaskRunner::run_expired_catchup(reg2, NOW, Arc::new(PanicOnPoison), 3).await
    });
    let joined = jh.await;
    // The injected dispatcher panic still propagates (non-swallowing —
    // AC-08 parity for panic VISIBILITY is preserved).
    assert!(
        joined.is_err() && joined.unwrap_err().is_panic(),
        "dispatcher panic must propagate out of run_expired_catchup"
    );

    // W1 fix: every healthy one-shot row's `record_fire` ran to
    // completion despite the sibling panic → expected_next_fire cleared.
    for i in 0..5 {
        let r = reg
            .get(&format!("ok{i}"))
            .await
            .expect("get ok")
            .expect("present");
        assert_eq!(
            r.expected_next_fire_at_ms, None,
            "healthy row ok{i}'s record_fire was abandoned by the sibling panic (W1 regression)"
        );
    }
}

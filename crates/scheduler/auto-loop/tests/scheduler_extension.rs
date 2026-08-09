//! AC-01 — AutoLoopDriver plugs into MODULE-014 via CONTRACT-133
//! SchedulerExtension; is the provider of CONTRACT-140 (start/stop/status).

mod common;

use std::sync::Arc;

use advance_scheduler::TriggerBusDispatchImpl;
use advance_scheduler::{
    ComponentEvent, ComponentId, Scheduler, SchedulerExtension, SchedulerTick,
};
use advance_scheduler_auto_loop::{
    AutoLoopConfig, AutoLoopDriver, AutoLoopError, AutoStatus, DefaultAutoLoopDriver,
};

use common::{CountingExtension, NoopIterationCheckpoint, NoopIterationRollback};

fn make_driver() -> Arc<DefaultAutoLoopDriver> {
    Arc::new(DefaultAutoLoopDriver::new(
        Arc::new(NoopIterationCheckpoint),
        Arc::new(NoopIterationRollback),
    ))
}

fn valid_config() -> AutoLoopConfig {
    // AutoLoopConfig is a type alias for SuccessCriteria — parse the
    // spec-canonical wrapped YAML rather than hand-building structs.
    advance_scheduler_auto_loop::SuccessCriteria::parse_yaml(
        r#"
auto-loop:
  objectives:
    - name: p
      role: primary
      metric_source: { type: file, path: m.json, key: v }
      predicate: { op: lt }
    - name: g
      role: guardrail
      metric_source: { type: file, path: q.json, key: w }
      predicate: { op: gt, threshold: 0.5 }
"#,
    )
    .expect("valid config")
}

// MODULE-015-T01-slA — register + observable fan-out (driver + CountingExtension).
#[tokio::test]
async fn registers_and_fan_out_reaches_every_extension() {
    let mut scheduler = Scheduler::new(Arc::new(TriggerBusDispatchImpl::new()));

    let driver = make_driver();
    let driver_handle = Arc::clone(&driver);
    scheduler.register_extension(driver as Arc<dyn SchedulerExtension>);

    let counter = Arc::new(CountingExtension::new("counter"));
    let counter_ticks = Arc::clone(&counter.ticks);
    scheduler.register_extension(counter as Arc<dyn SchedulerExtension>);

    assert_eq!(scheduler.extension_names(), vec!["auto-loop", "counter"]);

    // Fan-out (driver-observed): SchedulerTick::new — type is #[non_exhaustive].
    scheduler.dispatch_tick(SchedulerTick::new(1234)).await;
    assert_eq!(driver_handle.tick_count(), 1);
    scheduler.dispatch_tick(SchedulerTick::new(5678)).await;
    assert_eq!(driver_handle.tick_count(), 2);

    // Component event fan-out: ComponentEvent::started — #[non_exhaustive].
    scheduler
        .dispatch_component_event(ComponentEvent::started(
            ComponentId::new("c1".into()).unwrap(),
        ))
        .await;
    assert_eq!(driver_handle.event_count(), 1);

    // Whole-Vec proof: the CountingExtension also received every tick.
    use std::sync::atomic::Ordering;
    assert_eq!(driver_handle.tick_count(), 2);
    assert_eq!(counter_ticks.load(Ordering::Relaxed), 2);
}

// MODULE-015-T01b-slA — CONTRACT-140 start/stop/status.
#[tokio::test]
async fn contract_140_start_stop_status() {
    let driver = make_driver();
    assert!(driver.status("root").await.is_none());

    driver
        .start("root", valid_config())
        .await
        .expect("start ok");
    assert_eq!(driver.status("root").await, Some(AutoStatus::Active));

    driver.stop("root").await.expect("stop ok");
    assert!(driver.status("root").await.is_none());
}

// MODULE-015-T01c-slA — CONTRACT-140 trait object safety.
#[tokio::test]
async fn auto_loop_driver_is_object_safe() {
    let boxed: Box<dyn AutoLoopDriver> = Box::new(DefaultAutoLoopDriver::new(
        Arc::new(NoopIterationCheckpoint),
        Arc::new(NoopIterationRollback),
    ));
    // Exercise through the trait object to prove dyn-dispatch works.
    assert!(boxed.status("nobody").await.is_none());
}

// MODULE-015-T01d-slA — re-entry rejection + clean restart.
#[tokio::test]
async fn double_start_rejected_then_clean_restart() {
    let driver = make_driver();

    driver
        .start("root", valid_config())
        .await
        .expect("1st start ok");

    let second = driver.start("root", valid_config()).await;
    assert!(matches!(second, Err(AutoLoopError::AlreadyStarted(_))));
    // First session untouched.
    assert_eq!(driver.status("root").await, Some(AutoStatus::Active));

    driver.stop("root").await.expect("stop ok");
    // Clean restart — start never created a baseline tag, so no Conflict.
    driver
        .start("root", valid_config())
        .await
        .expect("3rd start ok after stop");
    assert_eq!(driver.status("root").await, Some(AutoStatus::Active));
}

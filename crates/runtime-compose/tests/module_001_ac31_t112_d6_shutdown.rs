//! MODULE-001-T112 (d.6) — reverse-bounded shutdown hooks and joined tasks.

use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, CapDecl, FixtureDriver, FixtureExtension, FixtureHome, FixtureHomeSpec,
    FixtureLifecycle, FixtureRecord, ShutdownMode,
};
use advance_runtime_compose::test_support::{ComposeProbe, MemoryComposeLog, TEARDOWN_ORDER};
use advance_runtime_compose::{compose, log_keys};

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac31_t112_d6_shutdown_hooks_reverse_bounded_panic_logged_task_joined() {
    let home = FixtureHome::new(FixtureHomeSpec {
        capabilities: vec![CapDecl::Granted("fs")],
        driver: FixtureDriver::None,
        git: true,
        providers_yaml: None,
    })
    .expect("home");
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let rec = Arc::new(FixtureRecord::default());
    let fixture = FixtureExtension::new("fixture")
        .sharing(&rec)
        .with_lifecycle(FixtureLifecycle {
            shutdown: ShutdownMode::Panic,
            spawn_ticker: true,
            ..FixtureLifecycle::default()
        });
    let two = FixtureExtension::new("fixture-two")
        .sharing(&rec)
        .with_lifecycle(FixtureLifecycle {
            shutdown: ShutdownMode::Hang,
            ..FixtureLifecycle::default()
        });
    let baseline = tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks();
    let rt = compose(
        home.options(Arc::new(log.clone()), Arc::clone(&probe)),
        vec![fixture.arc(), two.arc()],
    )
    .await
    .expect("compose");
    let deadline = Instant::now() + Duration::from_secs(2);
    while rec.ticks.load(std::sync::atomic::Ordering::SeqCst) < 3 {
        assert!(Instant::now() < deadline, "ticker did not tick");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let started = Instant::now();
    rt.shutdown().await.expect("shutdown");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(5) && elapsed < Duration::from_secs(8),
        "elapsed={elapsed:?}"
    );
    assert_eq!(
        *rec.hooks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
        vec!["fixture-two", "fixture"]
    );
    assert_eq!(log.count(log_keys::EXT_SHUTDOWN_ABANDONED), 1);
    assert!(log.lines().iter().any(|line| {
        line.key == log_keys::EXT_SHUTDOWN_ABANDONED && line.text.contains("fixture-two")
    }));
    assert_eq!(log.count(log_keys::EXT_SHUTDOWN_PANICKED), 1);
    let panicked = log
        .lines()
        .into_iter()
        .find(|line| line.key == log_keys::EXT_SHUTDOWN_PANICKED)
        .expect("panicked line");
    assert!(panicked.text.contains("fixture"), "{}", panicked.text);
    assert!(
        !panicked.text.contains("fixture shutdown panic"),
        "{}",
        panicked.text
    );
    assert!(rec.ticker_dropped.load(std::sync::atomic::Ordering::SeqCst));
    let ticks = rec.ticks.load(std::sync::atomic::Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        rec.ticks.load(std::sync::atomic::Ordering::SeqCst),
        ticks,
        "ticker kept running"
    );
    let steps = probe.record().step_names();
    let hooks = steps
        .iter()
        .position(|step| *step == "extensions.hooks")
        .expect("hooks step");
    let tasks = steps
        .iter()
        .position(|step| *step == "extensions.tasks")
        .expect("tasks step");
    assert!(hooks < tasks, "{steps:?}");
    assert!(
        TEARDOWN_ORDER.iter().position(|s| *s == "extensions.hooks")
            < TEARDOWN_ORDER.iter().position(|s| *s == "extensions.tasks")
    );
    assert_gone_for_home(&probe, home.home(), Some(baseline)).await;

    let log2 = MemoryComposeLog::new();
    let probe2 = Arc::new(ComposeProbe::new());
    let rt2 = compose(
        home.options(Arc::new(log2), Arc::clone(&probe2)),
        vec![FixtureExtension::new("fixture").arc()],
    )
    .await
    .expect("second compose");
    rt2.shutdown().await.expect("second shutdown");
    assert_gone_for_home(&probe2, home.home(), None).await;
}

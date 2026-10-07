//! MODULE-001-T112 (e.4) declaration panics and spawned-task containment.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use advance_runtime_compose::test_support::fixture::{
    assert_gone_for_home, CapDecl, FixtureBreaks, FixtureDriver, FixtureExtension, FixtureHome,
    FixtureHomeSpec, FixtureLifecycle,
};
use advance_runtime_compose::test_support::{reserved_homes, ComposeProbe, MemoryComposeLog};
use advance_runtime_compose::{compose, log_keys, ComposeError, ExtensionFailure, ExtensionPhase};

fn fs_home() -> FixtureHome {
    FixtureHome::new(FixtureHomeSpec {
        capabilities: vec![CapDecl::Granted("fs")],
        driver: FixtureDriver::None,
        git: true,
        providers_yaml: None,
    })
    .expect("home")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112_e4_declaration_panics_are_typed() {
    let home = fs_home();
    let probe = Arc::new(ComposeProbe::new());
    let error = compose(
        home.options(Arc::new(MemoryComposeLog::new()), Arc::clone(&probe)),
        vec![FixtureExtension::new("fixture")
            .with_breaks(FixtureBreaks {
                id_panics: true,
                ..FixtureBreaks::default()
            })
            .arc()],
    )
    .await
    .expect_err("id panic");
    match error {
        ComposeError::Extension {
            extension: "<unknown>",
            phase: ExtensionPhase::Capabilities,
            failure: ExtensionFailure::Panicked(ref message),
        } if message.contains("fixture id panic") => {}
        other => panic!("{other:?}"),
    }
    assert!(!home.home().join(".runtime/runtime.lock").exists());
    assert!(!reserved_homes().contains(&home.home().to_path_buf()));

    let probe = Arc::new(ComposeProbe::new());
    let error = compose(
        home.options(Arc::new(MemoryComposeLog::new()), Arc::clone(&probe)),
        vec![FixtureExtension::new("fixture")
            .with_breaks(FixtureBreaks {
                secret_need_panics: true,
                ..FixtureBreaks::default()
            })
            .arc()],
    )
    .await
    .expect_err("secret-need panic");
    match error {
        ComposeError::Extension {
            extension: "fixture",
            phase: ExtensionPhase::Capabilities,
            failure: ExtensionFailure::Panicked(_),
        } => {}
        other => panic!("{other:?}"),
    }
    assert!(!home.home().join(".runtime/runtime.lock").exists());
    assert!(!reserved_homes().contains(&home.home().to_path_buf()));

    let probe = Arc::new(ComposeProbe::new());
    let rt = compose(
        home.options(Arc::new(MemoryComposeLog::new()), Arc::clone(&probe)),
        vec![FixtureExtension::new("fixture").arc()],
    )
    .await
    .expect("plain compose");
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_containment_spawned_task_panic_logged_spawner_alive() {
    let home = FixtureHome::new(FixtureHomeSpec {
        capabilities: vec![CapDecl::Granted("fs")],
        driver: FixtureDriver::Minimal,
        git: true,
        providers_yaml: None,
    })
    .expect("home");
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let ext = FixtureExtension::new("fixture").with_lifecycle(FixtureLifecycle {
        spawn_ticker: true,
        ..FixtureLifecycle::default()
    });
    let rec = ext.record();
    let rt = compose(
        home.options(Arc::new(log.clone()), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    let snap = rec
        .started(Duration::from_secs(2))
        .await
        .expect("on_started");
    rec.panic_ticker();
    let deadline = Instant::now() + Duration::from_secs(2);
    while log.count(log_keys::EXT_TASK_PANICKED) == 0 {
        assert!(Instant::now() < deadline, "ticker panic was not logged");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(log.count(log_keys::EXT_TASK_PANICKED), 1);
    let line = log
        .lines()
        .into_iter()
        .find(|line| line.key == log_keys::EXT_TASK_PANICKED)
        .expect("line");
    assert!(line.text.contains("fixture"), "{}", line.text);
    assert!(!line.text.contains("fixture ticker panic"), "{}", line.text);
    let flag = Arc::new(AtomicBool::new(false));
    let spawned = Arc::clone(&flag);
    snap.cx
        .tasks()
        .spawn(async move {
            spawned.store(true, Ordering::SeqCst);
        })
        .expect("spawn after panic");
    let deadline = Instant::now() + Duration::from_secs(1);
    while !flag.load(Ordering::SeqCst) {
        assert!(Instant::now() < deadline, "spawned task did not run");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        rt.health().phase,
        advance_runtime_compose::RuntimePhase::Running
    );
    rt.shutdown().await.expect("shutdown");
    assert_gone_for_home(&probe, home.home(), None).await;
}

fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn module_001_ac31_t112_e4_client_families_panic_and_failure_are_typed_and_torn_down() {
    let home = FixtureHome::new(FixtureHomeSpec {
        capabilities: vec![CapDecl::Granted("fs"), CapDecl::Granted("llm")],
        driver: FixtureDriver::None,
        git: false,
        providers_yaml: None,
    })
    .expect("home");

    async fn refused(home: &FixtureHome, breaks: FixtureBreaks, check: impl FnOnce(&ComposeError)) {
        let log = MemoryComposeLog::new();
        let probe = Arc::new(ComposeProbe::new());
        let baseline = alive_tasks();
        let error = compose(
            home.options(Arc::new(log.clone()), Arc::clone(&probe)),
            vec![FixtureExtension::new("fixture").with_breaks(breaks).arc()],
        )
        .await
        .expect_err("client_families refused");
        check(&error);
        assert_eq!(log.count(log_keys::READY), 0);
        assert!(!home.home().join(".runtime/client-api").exists());
        assert_gone_for_home(&probe, home.home(), Some(baseline)).await;
    }

    refused(
        &home,
        FixtureBreaks {
            panic_in: Some(ExtensionPhase::ClientFamilies),
            ..FixtureBreaks::default()
        },
        |error| match error {
            ComposeError::Extension {
                extension: "fixture",
                phase: ExtensionPhase::ClientFamilies,
                failure: ExtensionFailure::Panicked(message),
            } if message.contains("fixture panic in client_families") => {}
            other => panic!("panic: {other:?}"),
        },
    )
    .await;

    refused(
        &home,
        FixtureBreaks {
            fail_in: Some(ExtensionPhase::ClientFamilies),
            ..FixtureBreaks::default()
        },
        |error| match error {
            ComposeError::Extension {
                extension: "fixture",
                phase: ExtensionPhase::ClientFamilies,
                failure: ExtensionFailure::Failed(message),
            } if message == "fixture failure in client_families" => {}
            other => panic!("fail: {other:?}"),
        },
    )
    .await;
}

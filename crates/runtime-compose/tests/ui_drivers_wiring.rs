//! ADR 2026-10-28 S1 — the UI families in the composition: a home declaring
//! `browser` gets the `browser__*` callables; an extension's driver is taken once
//! (`ui_drivers` runs after `host_functions` and before `client_families`); a
//! second driver for a surface, a failing or panicking hook, each fail `compose`
//! with a typed error; without the declaration the hook is not called.

use std::sync::Arc;

use advance_runtime_compose::test_support::fixture::{
    CapDecl, FixtureBreaks, FixtureDriver, FixtureExtension, FixtureHome, FixtureHomeSpec,
};
use advance_runtime_compose::test_support::{ComposeProbe, MemoryComposeLog};
use advance_runtime_compose::{
    compose, log_keys, ComposeError, ExtensionFailure, ExtensionPhase, UiDriverRefusal,
};

fn home(caps: Vec<CapDecl>) -> FixtureHome {
    FixtureHome::new(FixtureHomeSpec {
        capabilities: caps,
        driver: FixtureDriver::None,
        git: true,
        providers_yaml: None,
    })
    .expect("home")
}

const BROWSER_VERBS: usize = 14;
const SCREEN_VERBS: usize = 9;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_browser_home_registers_the_browser_callables_and_takes_the_driver() {
    let home = home(vec![CapDecl::Granted("fs"), CapDecl::Granted("browser")]);
    let probe = Arc::new(ComposeProbe::new());
    let log = Arc::new(MemoryComposeLog::new());
    let ext = FixtureExtension::new("fixture").with_fake_browser();
    let record = ext.record();
    let rt = compose(
        home.options(log.clone(), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");

    let names = probe
        .record()
        .ui_callables
        .expect("ui callables recorded for a browser home");
    assert_eq!(names.len(), BROWSER_VERBS, "{names:?}");
    assert!(names.contains(&"browser__navigate".to_string()));
    assert!(names.contains(&"browser__snapshot".to_string()));
    assert!(
        !names.iter().any(|n| n.starts_with("screen__")),
        "{names:?}"
    );

    assert_eq!(log.count(log_keys::UI_DRIVER_REGISTERED), 1);
    assert_eq!(log.count(log_keys::UI_CALLABLES), 1);
    let line = log
        .lines()
        .into_iter()
        .find(|l| l.key == log_keys::UI_CALLABLES)
        .expect("ui callables line");
    assert!(line.text.contains("browser driver: yes"), "{}", line.text);
    assert!(line.text.contains("screen driver: none"), "{}", line.text);

    let phases = record.phases();
    let at = |name: &str| {
        phases
            .iter()
            .position(|p| *p == name)
            .unwrap_or_else(|| panic!("{name} not in {phases:?}"))
    };
    assert!(at("host_functions") < at("ui_drivers"), "{phases:?}");
    assert!(at("ui_drivers") < at("client_families"), "{phases:?}");

    rt.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_screen_home_without_a_driver_still_lists_the_screen_callables() {
    let home = home(vec![CapDecl::Granted("fs"), CapDecl::Granted("screen")]);
    let probe = Arc::new(ComposeProbe::new());
    let log = Arc::new(MemoryComposeLog::new());
    let rt = compose(home.options(log.clone(), Arc::clone(&probe)), Vec::new())
        .await
        .expect("compose");
    let names = probe.record().ui_callables.expect("ui callables recorded");
    assert_eq!(names.len(), SCREEN_VERBS, "{names:?}");
    assert!(names.iter().all(|n| n.starts_with("screen__")), "{names:?}");
    assert_eq!(log.count(log_keys::UI_DRIVER_REGISTERED), 0);
    let line = log
        .lines()
        .into_iter()
        .find(|l| l.key == log_keys::UI_CALLABLES)
        .expect("ui callables line");
    assert!(line.text.contains("screen driver: none"), "{}", line.text);
    rt.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_the_declaration_the_hook_is_not_called() {
    let home = home(vec![CapDecl::Granted("fs")]);
    let probe = Arc::new(ComposeProbe::new());
    let log = Arc::new(MemoryComposeLog::new());
    let ext = FixtureExtension::new("fixture").with_fake_browser();
    let record = ext.record();
    let rt = compose(
        home.options(log.clone(), Arc::clone(&probe)),
        vec![ext.arc()],
    )
    .await
    .expect("compose");
    assert!(probe.record().ui_callables.is_none());
    assert_eq!(log.count(log_keys::UI_DRIVER_REGISTERED), 0);
    assert_eq!(log.count(log_keys::UI_CALLABLES), 0);
    assert!(
        !record.phases().contains(&"ui_drivers"),
        "{:?}",
        record.phases()
    );
    rt.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_browser_driver_is_refused_and_the_home_is_released() {
    let home = home(vec![CapDecl::Granted("fs"), CapDecl::Granted("browser")]);
    let probe = Arc::new(ComposeProbe::new());
    let error = compose(
        home.options(Arc::new(MemoryComposeLog::new()), Arc::clone(&probe)),
        vec![
            FixtureExtension::new("fixture").with_fake_browser().arc(),
            FixtureExtension::new("fixture-two")
                .with_fake_browser()
                .arc(),
        ],
    )
    .await
    .expect_err("duplicate driver");
    match error {
        ComposeError::UiDriver {
            extension: "fixture-two",
            refusal:
                UiDriverRefusal::Duplicate {
                    surface: "browser",
                    held_by: "fixture",
                },
        } => {}
        other => panic!("{other:?}"),
    }
    assert_eq!(
        error.to_string(),
        "extension fixture-two: ui driver refused: ui driver for browser: already registered by extension fixture"
    );
    assert!(!home.home().join(".runtime/runtime.lock").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panicking_or_failing_ui_drivers_hook_is_typed() {
    let home = home(vec![CapDecl::Granted("fs"), CapDecl::Granted("browser")]);
    for (breaks, expect_panic) in [
        (
            FixtureBreaks {
                panic_in: Some(ExtensionPhase::UiDrivers),
                ..FixtureBreaks::default()
            },
            true,
        ),
        (
            FixtureBreaks {
                fail_in: Some(ExtensionPhase::UiDrivers),
                ..FixtureBreaks::default()
            },
            false,
        ),
    ] {
        let probe = Arc::new(ComposeProbe::new());
        let error = compose(
            home.options(Arc::new(MemoryComposeLog::new()), Arc::clone(&probe)),
            vec![FixtureExtension::new("fixture").with_breaks(breaks).arc()],
        )
        .await
        .expect_err("broken hook");
        match (error, expect_panic) {
            (
                ComposeError::Extension {
                    extension: "fixture",
                    phase: ExtensionPhase::UiDrivers,
                    failure: ExtensionFailure::Panicked(_),
                },
                true,
            )
            | (
                ComposeError::Extension {
                    extension: "fixture",
                    phase: ExtensionPhase::UiDrivers,
                    failure: ExtensionFailure::Failed(_),
                },
                false,
            ) => {}
            (other, _) => panic!("{other:?}"),
        }
        assert!(!home.home().join(".runtime/runtime.lock").exists());
    }
}

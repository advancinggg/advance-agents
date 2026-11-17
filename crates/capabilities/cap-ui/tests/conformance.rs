//! V2 — the conformance suite is green on both Fake drivers.

use std::sync::Arc;

use cap_ui::conformance::{
    browser_conformance, browser_policy, fake_browser, fake_screen, screen_conformance,
    screen_policy,
};
use cap_ui::testing::{browser_family, screen_family};

#[tokio::test]
async fn fake_browser_passes_the_conformance_suite() {
    let (family, _, bus) = browser_family(Arc::new(fake_browser()), browser_policy());
    let outcome = browser_conformance(&family, "agent-a").await;
    outcome.assert_all_pass();
    assert!(outcome.cases.len() >= 20, "{:?}", outcome.names());
    assert!(bus.count("ui.action") > 0);
    assert!(bus.count("ui.observation") > 0);
    assert!(bus.count("ui.refused") > 0);
}

#[tokio::test]
async fn fake_screen_passes_the_conformance_suite() {
    let (family, _, bus) = screen_family(Arc::new(fake_screen()), screen_policy());
    let outcome = screen_conformance(&family, "agent-a").await;
    outcome.assert_all_pass();
    assert!(outcome.cases.len() >= 12, "{:?}", outcome.names());
    assert!(bus.count("ui.action") > 0);
    assert!(bus.count("ui.observation") > 0);
    assert!(bus.count("ui.refused") > 0);
}

#[tokio::test]
async fn the_suite_reports_failures_instead_of_panicking_midway() {
    // A browser family with no driver fails every case; the outcome lists them.
    let policy = cap_ui::testing::StaticUiPolicy {
        browser: Some(browser_policy()),
        screen: None,
    };
    let grant = Arc::new(cap_ui::testing::AllowlistGrant::from_policy(&policy));
    let bus = Arc::new(cap_ui::testing::CaptureBus::default());
    let family = cap_ui::UiFamily::new(
        cap_ui::testing::deps(Arc::new(policy), grant, bus),
        cap_ui::UiDrivers::none(),
        cap_ui::UiSurfaces::BROWSER,
    );
    let outcome = browser_conformance(&family, "agent-a").await;
    assert!(!outcome.all_passed());
    assert_eq!(outcome.failures().len(), outcome.cases.len());
    assert!(outcome.failures()[0].contains("no ui driver attached"));
}

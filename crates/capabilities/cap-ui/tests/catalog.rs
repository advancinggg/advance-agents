//! V1 — the catalog: a home declaring `browser` lists exactly the S1 browser
//! verbs (no screen verbs); without a driver every callable answers the fixed
//! refusal.

use std::sync::Arc;

use advance_runtime::callable_registry::{
    CallableError, CallableRegistry, InMemoryCallableRegistry,
};
use cap_ui::conformance::{browser_policy, fake_browser, screen_policy};
use cap_ui::testing::{browser_family, ctx, deps, AllowlistGrant, CaptureBus, StaticUiPolicy};
use cap_ui::{
    register_ui_callables, UiDrivers, UiFamily, UiSurfaces, BROWSER_NS, NO_DRIVER_REASON, SCREEN_NS,
};
use serde_json::json;

const BROWSER_NAMES: &[&str] = &[
    "browser__tabs",
    "browser__navigate",
    "browser__back",
    "browser__forward",
    "browser__reload",
    "browser__snapshot",
    "browser__click",
    "browser__type",
    "browser__press",
    "browser__scroll",
    "browser__select",
    "browser__hover",
    "browser__read",
    "browser__wait",
];

const SCREEN_NAMES: &[&str] = &[
    "screen__list_targets",
    "screen__describe",
    "screen__click",
    "screen__type",
    "screen__key",
    "screen__scroll",
    "screen__read",
    "screen__focus",
    "screen__wait",
];

#[test]
fn browser_family_lists_exactly_the_s1_browser_verbs() {
    let (family, _, _) = browser_family(Arc::new(fake_browser()), browser_policy());
    assert_eq!(family.names(), BROWSER_NAMES);
    for spec in family.specs() {
        assert_eq!(spec.capability, "browser");
        assert!(
            spec.original_function
                .starts_with(&format!("{BROWSER_NS}::")),
            "{}",
            spec.original_function
        );
        assert!(!spec.description.is_empty());
        assert_eq!(spec.parameters["type"], "object");
        assert_eq!(spec.parameters["additionalProperties"], false);
        assert!(
            spec.parameters["properties"]["tab"].is_object(),
            "{}",
            spec.name
        );
    }
    let observing = ["browser__tabs", "browser__snapshot", "browser__read"];
    for spec in family.specs() {
        let says_untrusted = spec.description.contains("untrusted data");
        assert_eq!(
            says_untrusted,
            observing.contains(&spec.name.as_str()),
            "{} description: {}",
            spec.name,
            spec.description
        );
    }
}

#[test]
fn registry_projects_the_family_by_declared_capabilities() {
    let registry = InMemoryCallableRegistry::new();
    let policy = StaticUiPolicy {
        browser: Some(browser_policy()),
        screen: None,
    };
    let grant = Arc::new(AllowlistGrant::from_policy(&policy));
    let bus = Arc::new(CaptureBus::default());
    let family = register_ui_callables(
        &registry,
        deps(Arc::new(policy), grant, bus),
        UiDrivers::browser(Arc::new(fake_browser())),
        UiSurfaces::BOTH,
    );
    assert_eq!(
        family.specs().len(),
        BROWSER_NAMES.len() + SCREEN_NAMES.len()
    );

    let listed = registry.list_for_capabilities(&["llm".into(), "browser".into()]);
    let names: Vec<&str> = listed.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        names, BROWSER_NAMES,
        "a browser-only home sees no screen verbs"
    );

    let screen = registry.list_for_capabilities(&["screen".into()]);
    let names: Vec<&str> = screen.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, SCREEN_NAMES);
    assert!(screen
        .iter()
        .all(|s| s.original_function.starts_with(&format!("{SCREEN_NS}::"))));

    assert!(registry.lookup("browser__navigate").is_some());
    assert!(
        registry.lookup("browser.navigate").is_none(),
        "catalog names use `__`"
    );
}

#[test]
fn surfaces_select_the_families() {
    let policy = StaticUiPolicy::default();
    let grant = Arc::new(AllowlistGrant::allow_all());
    let bus = Arc::new(CaptureBus::default());
    let only_screen = UiFamily::new(
        deps(Arc::new(policy), grant, bus),
        UiDrivers::none(),
        UiSurfaces::SCREEN,
    );
    assert_eq!(only_screen.names(), SCREEN_NAMES);
}

#[tokio::test]
async fn without_a_driver_every_callable_answers_the_fixed_refusal() {
    let policy = StaticUiPolicy {
        browser: Some(browser_policy()),
        screen: Some(screen_policy()),
    };
    let grant = Arc::new(AllowlistGrant::from_policy(&policy));
    let bus = Arc::new(CaptureBus::default());
    let family = UiFamily::new(
        deps(Arc::new(policy), grant, bus.clone()),
        UiDrivers::none(),
        UiSurfaces::BOTH,
    );
    let args = json!({
        "url": "https://fixture.test/", "ref": "e1", "text": "x", "key": "Enter",
        "keys": "a", "values": ["a"], "target": "win-1"
    });
    for name in family.names() {
        let err = family
            .invoke(&name, ctx("agent-a"), "c1", args.clone())
            .await
            .expect_err(&name);
        assert_eq!(
            err,
            CallableError::NotFound(NO_DRIVER_REASON.to_string()),
            "{name}"
        );
    }
    assert_eq!(
        bus.count("ui.refused"),
        BROWSER_NAMES.len() + SCREEN_NAMES.len()
    );
    assert_eq!(bus.count("ui.action"), 0);
}

#[tokio::test]
async fn an_unknown_callable_name_is_not_found() {
    let (family, _, _) = browser_family(Arc::new(fake_browser()), browser_policy());
    let err = family
        .invoke("browser__fly", ctx("agent-a"), "c1", json!({}))
        .await
        .unwrap_err();
    assert!(matches!(err, CallableError::NotFound(_)), "{err}");
}

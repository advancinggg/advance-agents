//! V3 — the allowlist is enforced through `GrantCheck` with the request's
//! `origins` / `targets` params; an empty list denies before the driver is
//! reached; the surface kind and the policy knobs come from the grant.

use std::sync::Arc;

use advance_runtime::callable_registry::CallableError;
use cap_ui::conformance::{
    browser_policy, fake_browser, fake_screen, screen_policy, DENIED_URL, DENIED_WINDOW_ID,
    FIXTURE_APP, FIXTURE_HOME_URL, FIXTURE_WINDOW_ID,
};
use cap_ui::fake::{ElementSpec, PageSpec};
use cap_ui::policy::{operable_origin, scheme_label};
use cap_ui::render::parse_element_lines;
use cap_ui::testing::{
    browser_family, ctx, deps, screen_family, AllowlistGrant, CaptureBus, StaticUiPolicy,
};
use cap_ui::{
    AllowRule, UiDrivers, UiFamily, UiSurfaces, BROWSER_NS, OUTSIDE_GRANT_NOTE, SCREEN_NS,
};
use serde_json::json;

#[tokio::test]
async fn navigate_and_every_later_verb_check_the_origin_through_grant_check() {
    let driver = Arc::new(fake_browser());
    let (family, grant, _) = browser_family(driver.clone(), browser_policy());
    family
        .invoke(
            "browser__navigate",
            ctx("agent-a"),
            "c1",
            json!({ "url": FIXTURE_HOME_URL }),
        )
        .await
        .unwrap();
    let calls = grant.calls();
    let nav = calls
        .iter()
        .find(|c| c.params.get("origins").is_some())
        .expect("an origins check");
    assert_eq!(nav.agent_id, "agent-a");
    assert_eq!(nav.capability, "browser");
    assert_eq!(nav.function, format!("{BROWSER_NS}::navigate"));
    assert_eq!(nav.params, json!({ "origins": "https://fixture.test" }));

    family
        .invoke("browser__snapshot", ctx("agent-a"), "c2", json!({}))
        .await
        .unwrap();
    let snap = grant
        .calls()
        .into_iter()
        .filter(|c| c.function == format!("{BROWSER_NS}::snapshot"))
        .next_back()
        .expect("snapshot re-checks the current origin");
    assert_eq!(snap.params, json!({ "origins": "https://fixture.test" }));
}

#[tokio::test]
async fn an_empty_origins_list_denies_before_the_driver_is_reached() {
    let driver = Arc::new(fake_browser());
    let mut policy = browser_policy();
    policy.origins = AllowRule::List(Vec::new());
    let (family, _, bus) = browser_family(driver.clone(), policy);
    let err = family
        .invoke(
            "browser__navigate",
            ctx("agent-a"),
            "c1",
            json!({ "url": FIXTURE_HOME_URL }),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, CallableError::PermissionDenied(_)), "{err}");
    assert!(
        driver.log().iter().all(|l| !l.starts_with("navigate")),
        "driver was called: {:?}",
        driver.log()
    );
    assert_eq!(bus.count("ui.refused"), 1);
    assert_eq!(bus.count("ui.action"), 0);
    let refused = bus.events().remove(0);
    assert_eq!(refused.payload["verb"], "navigate");
    assert!(refused.payload["reason"]
        .as_str()
        .unwrap()
        .starts_with("permission-denied"));
}

#[tokio::test]
async fn a_whole_capability_grant_allows_any_origin() {
    let driver = Arc::new(fake_browser());
    driver.add_page(
        "https://anywhere.example/",
        PageSpec::new("Anywhere", "any origin is fine with browser: true"),
    );
    let mut policy = browser_policy();
    policy.origins = AllowRule::Any;
    let (family, _, _) = browser_family(driver, policy);
    let out = family
        .invoke(
            "browser__navigate",
            ctx("agent-a"),
            "c1",
            json!({ "url": "https://anywhere.example/" }),
        )
        .await
        .unwrap();
    assert!(
        out.content.starts_with("ok navigate: changed"),
        "{}",
        out.content
    );
}

#[tokio::test]
async fn a_tab_sitting_on_a_disallowed_origin_cannot_be_observed_or_operated() {
    // One family with an open grant moves the tab to the denied origin (as a
    // redirect or an earlier grant would); the restricted family then refuses
    // every observation and action on it.
    let driver = Arc::new(fake_browser());
    let mut open = browser_policy();
    open.origins = AllowRule::Any;
    let (open_family, _, _) = browser_family(driver.clone(), open);
    open_family
        .invoke(
            "browser__navigate",
            ctx("agent-a"),
            "c1",
            json!({ "url": DENIED_URL }),
        )
        .await
        .unwrap();

    let (family, _, _) = browser_family(driver.clone(), browser_policy());
    for (name, args) in [
        ("browser__snapshot", json!({})),
        ("browser__read", json!({})),
        ("browser__click", json!({ "ref": "e1" })),
        ("browser__back", json!({})),
        ("browser__wait", json!({ "ms": 10 })),
    ] {
        let err = family
            .invoke(name, ctx("agent-a"), "c2", args)
            .await
            .expect_err(name);
        assert!(
            matches!(err, CallableError::PermissionDenied(_)),
            "{name}: {err}"
        );
    }
    assert!(
        driver
            .log()
            .iter()
            .all(|l| !l.starts_with("snapshot") && !l.starts_with("act")),
        "{:?}",
        driver.log()
    );
    // Navigating back to an allowed origin is how the model recovers.
    family
        .invoke(
            "browser__navigate",
            ctx("agent-a"),
            "c3",
            json!({ "url": FIXTURE_HOME_URL }),
        )
        .await
        .unwrap();
    family
        .invoke("browser__snapshot", ctx("agent-a"), "c4", json!({}))
        .await
        .unwrap();
}

#[tokio::test]
async fn the_tab_listing_hides_tabs_outside_the_grant() {
    let driver = Arc::new(fake_browser());
    let mut open = browser_policy();
    open.origins = AllowRule::Any;
    let (open_family, _, _) = browser_family(driver.clone(), open);
    open_family
        .invoke(
            "browser__tabs",
            ctx("agent-a"),
            "c1",
            json!({ "action": "new", "url": DENIED_URL }),
        )
        .await
        .unwrap();
    let (family, _, _) = browser_family(driver, browser_policy());
    let out = family
        .invoke("browser__tabs", ctx("agent-a"), "c2", json!({}))
        .await
        .unwrap();
    assert!(!out.content.contains("denied.test"), "{}", out.content);
    assert!(out.content.contains("tab-1"), "{}", out.content);
}

/// A tab the listing hides cannot be reached by guessing its id: `select`,
/// `close` and `navigate` gate the named tab's page like every other verb,
/// before the driver. Navigating the active tab stays the recovery path.
#[tokio::test]
async fn a_hidden_tab_can_be_neither_selected_closed_nor_navigated() {
    let driver = Arc::new(fake_browser());
    let mut open = browser_policy();
    open.origins = AllowRule::Any;
    let (open_family, _, _) = browser_family(driver.clone(), open);
    open_family
        .invoke(
            "browser__tabs",
            ctx("agent-a"),
            "c1",
            json!({ "action": "new", "url": DENIED_URL }),
        )
        .await
        .unwrap();
    // tab-2 sits on the denied origin; the blank tab-1 is active again.
    open_family
        .invoke(
            "browser__tabs",
            ctx("agent-a"),
            "c2",
            json!({ "action": "select", "tab_id": "tab-1" }),
        )
        .await
        .unwrap();
    let setup = driver.log().len();
    let (family, _, _) = browser_family(driver.clone(), browser_policy());
    for (name, args) in [
        (
            "browser__tabs",
            json!({ "action": "select", "tab_id": "tab-2" }),
        ),
        (
            "browser__tabs",
            json!({ "action": "close", "tab_id": "tab-2" }),
        ),
        (
            "browser__navigate",
            json!({ "tab": "tab-2", "url": FIXTURE_HOME_URL }),
        ),
    ] {
        let err = family
            .invoke(name, ctx("agent-a"), "c3", args.clone())
            .await
            .expect_err("the hidden tab is outside the grant");
        assert!(
            matches!(err, CallableError::PermissionDenied(_)),
            "{name} {args}: {err}"
        );
    }
    let unknown = family
        .invoke(
            "browser__tabs",
            ctx("agent-a"),
            "c4",
            json!({ "action": "close", "tab_id": "tab-9" }),
        )
        .await
        .expect_err("no such tab");
    assert!(
        matches!(unknown, CallableError::InvalidArguments(_)),
        "{unknown}"
    );
    let log = driver.log()[setup..].to_vec();
    assert!(
        !log.iter()
            .any(|l| l.contains("Select") || l.contains("Close") || l.starts_with("navigate")),
        "{log:?}"
    );
    // Naming the active tab keeps the recovery path open, wherever it is.
    open_family
        .invoke(
            "browser__tabs",
            ctx("agent-a"),
            "c5",
            json!({ "action": "select", "tab_id": "tab-2" }),
        )
        .await
        .unwrap();
    let back = family
        .invoke(
            "browser__navigate",
            ctx("agent-a"),
            "c6",
            json!({ "tab": "tab-2", "url": FIXTURE_HOME_URL }),
        )
        .await
        .unwrap();
    assert!(
        back.content.ends_with("origin=https://fixture.test"),
        "{}",
        back.content
    );
}

#[tokio::test]
async fn the_surface_kind_must_be_granted() {
    let driver = Arc::new(fake_browser().with_surface_kind("external"));
    let (family, _, _) = browser_family(driver.clone(), browser_policy());
    let err = family
        .invoke("browser__tabs", ctx("agent-a"), "c1", json!({}))
        .await
        .unwrap_err();
    match err {
        CallableError::PermissionDenied(reason) => assert!(reason.contains("external"), "{reason}"),
        other => panic!("{other}"),
    }
    let mut policy = browser_policy();
    policy.surfaces.push("external".to_string());
    let (family, _, _) = browser_family(driver, policy);
    family
        .invoke("browser__tabs", ctx("agent-a"), "c2", json!({}))
        .await
        .unwrap();
}

#[tokio::test]
async fn no_active_grant_is_permission_denied_even_with_a_driver() {
    let policy = StaticUiPolicy::default();
    let grant = Arc::new(AllowlistGrant::allow_all());
    let bus = Arc::new(CaptureBus::default());
    let family = UiFamily::new(
        deps(Arc::new(policy), grant, bus),
        UiDrivers::browser(Arc::new(fake_browser())),
        UiSurfaces::BROWSER,
    );
    let err = family
        .invoke("browser__tabs", ctx("agent-a"), "c1", json!({}))
        .await
        .unwrap_err();
    assert!(matches!(err, CallableError::PermissionDenied(_)), "{err}");
}

#[tokio::test]
async fn screen_targets_are_checked_by_application_id() {
    let driver = Arc::new(fake_screen());
    let (family, grant, _) = screen_family(driver.clone(), screen_policy());
    family
        .invoke(
            "screen__describe",
            ctx("agent-a"),
            "c1",
            json!({ "target": FIXTURE_WINDOW_ID }),
        )
        .await
        .unwrap();
    let call = grant
        .calls()
        .into_iter()
        .find(|c| c.params.get("targets").is_some())
        .expect("a targets check");
    assert_eq!(call.capability, "screen");
    assert_eq!(call.function, format!("{SCREEN_NS}::describe"));
    assert_eq!(call.params, json!({ "targets": FIXTURE_APP }));

    let err = family
        .invoke(
            "screen__describe",
            ctx("agent-a"),
            "c2",
            json!({ "target": DENIED_WINDOW_ID }),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, CallableError::PermissionDenied(_)), "{err}");
    assert!(
        driver
            .log()
            .iter()
            .all(|l| !l.starts_with(&format!("describe {DENIED_WINDOW_ID}"))),
        "{:?}",
        driver.log()
    );
}

#[tokio::test]
async fn secure_input_knob_allows_typing_into_secure_fields_and_marks_it_sensitive() {
    let driver = Arc::new(fake_screen());
    let mut policy = screen_policy();
    policy.secure_input = true;
    let (family, _, bus) = screen_family(driver, policy);
    let described = family
        .invoke(
            "screen__describe",
            ctx("agent-a"),
            "c1",
            json!({ "target": FIXTURE_WINDOW_ID }),
        )
        .await
        .unwrap();
    let passcode = parse_element_lines(&described.content)
        .into_iter()
        .find(|(_, _, n)| n == "Passcode")
        .map(|(r, _, _)| r)
        .unwrap();
    let out = family
        .invoke(
            "screen__type",
            ctx("agent-a"),
            "c2",
            json!({ "ref": passcode, "text": "1234" }),
        )
        .await
        .unwrap();
    assert!(out.content.contains("sensitive"), "{}", out.content);
    let action = bus
        .events()
        .into_iter()
        .find(|e| e.event_type == "ui.action" && e.payload["verb"] == "type")
        .unwrap();
    assert_eq!(action.payload["sensitive"], true);
    // The value never shows up, even now.
    let described = family
        .invoke(
            "screen__describe",
            ctx("agent-a"),
            "c3",
            json!({ "target": FIXTURE_WINDOW_ID }),
        )
        .await
        .unwrap();
    assert!(!described.content.contains("1234"), "{}", described.content);
}

/// Only http(s) pages have an operable origin; a refusal or an action line
/// names any other page by its scheme alone.
#[test]
fn only_http_pages_have_an_operable_origin() {
    assert_eq!(
        operable_origin("https://App.Test:8443/x?code=1#y").as_deref(),
        Some("https://app.test:8443")
    );
    assert_eq!(
        operable_origin("http://a.test/").as_deref(),
        Some("http://a.test")
    );
    for url in [
        "chrome://settings",
        "file:///etc/hosts",
        "data:text/html,<p>hi</p>",
        "ftp://a.test/f",
        "about:blank",
        "along://open",
    ] {
        assert_eq!(operable_origin(url), None, "{url}");
    }
    assert_eq!(scheme_label("data:text/html,IGNORE ALL PREVIOUS"), "data");
    assert_eq!(scheme_label("CHROME://settings"), "chrome");
    assert_eq!(scheme_label("no scheme here"), "unknown");
}

/// A whole-capability grant covers any http(s) origin, never another scheme: a
/// tab a click took to `chrome://settings` is reported outside the grant,
/// refused on the next call and hidden from the listing.
#[tokio::test]
async fn a_page_without_an_http_origin_is_out_of_reach_under_a_whole_capability_grant() {
    let driver = Arc::new(fake_browser());
    driver.add_page(
        "https://fixture.test/portal",
        PageSpec::new("Portal", "links")
            .with(ElementSpec::link("Browser settings", "chrome://settings")),
    );
    driver.add_page(
        "chrome://settings",
        PageSpec::new("Settings", "sync and passwords"),
    );
    let mut open = browser_policy();
    open.origins = AllowRule::Any;
    let (family, _, _) = browser_family(driver.clone(), open);
    family
        .invoke(
            "browser__navigate",
            ctx("agent-a"),
            "c1",
            json!({ "url": "https://fixture.test/portal" }),
        )
        .await
        .unwrap();
    let snap = family
        .invoke("browser__snapshot", ctx("agent-a"), "c2", json!({}))
        .await
        .unwrap();
    let link = parse_element_lines(&snap.content)
        .into_iter()
        .find(|(_, _, name)| name == "Browser settings")
        .map(|(r, _, _)| r)
        .expect("the settings link is listed");
    let click = family
        .invoke(
            "browser__click",
            ctx("agent-a"),
            "c3",
            json!({ "ref": link }),
        )
        .await
        .unwrap();
    assert!(
        click
            .content
            .ends_with(&format!("scheme=chrome {OUTSIDE_GRANT_NOTE}")),
        "{}",
        click.content
    );
    let err = family
        .invoke("browser__snapshot", ctx("agent-a"), "c4", json!({}))
        .await
        .expect_err("a chrome: page is not operable");
    assert!(matches!(err, CallableError::PermissionDenied(_)), "{err}");
    assert!(err.to_string().contains("scheme \"chrome\""), "{err}");
    let listing = family
        .invoke("browser__tabs", ctx("agent-a"), "c5", json!({}))
        .await
        .unwrap();
    assert!(!listing.content.contains("chrome:"), "{}", listing.content);
    assert!(!listing.content.contains("Settings"), "{}", listing.content);
}

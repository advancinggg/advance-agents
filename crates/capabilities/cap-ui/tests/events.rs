//! `ui.*` events: one `ui.action` per action, one `ui.observation` per
//! observation, `ui.refused` per refusal; correlation ids come from the call
//! context; driver failures are execution failures, not refusals.

use std::sync::Arc;

use cap_ui::conformance::{browser_policy, fake_browser, FIXTURE_HOME_URL};
use cap_ui::render::parse_element_lines;
use cap_ui::testing::{browser_family, ctx};
use serde_json::json;

#[tokio::test]
async fn navigate_snapshot_click_emit_two_actions_and_one_observation() {
    let (family, _, bus) = browser_family(Arc::new(fake_browser()), browser_policy());
    let mut c = ctx("agent-a");
    c.run_id = Some("run-7".to_string());
    c.trace_id = "trace-9".to_string();

    family
        .invoke(
            "browser__navigate",
            c.clone(),
            "c1",
            json!({ "url": FIXTURE_HOME_URL }),
        )
        .await
        .unwrap();
    let snap = family
        .invoke("browser__snapshot", c.clone(), "c2", json!({}))
        .await
        .unwrap();
    let link = parse_element_lines(&snap.content)
        .into_iter()
        .find(|(_, role, _)| role == "link")
        .map(|(r, _, _)| r)
        .unwrap();
    let clicked = family
        .invoke("browser__click", c.clone(), "c3", json!({ "ref": link }))
        .await
        .unwrap();
    assert!(
        clicked.content.starts_with("ok click: changed"),
        "{}",
        clicked.content
    );

    assert_eq!(bus.types(), ["ui.action", "ui.observation", "ui.action"]);
    let events = bus.events();
    for e in &events {
        assert_eq!(e.agent_id, "agent-a");
        assert_eq!(e.run_id.as_deref(), Some("run-7"));
        assert_eq!(e.trace_id, "trace-9");
        assert_eq!(e.payload["surface"], "browser");
    }
    assert_eq!(events[0].payload["verb"], "navigate");
    assert_eq!(events[0].payload["target"], "tab-1");
    assert_eq!(events[0].payload["is_error"], false);
    assert_eq!(events[0].payload["sensitive"], false);
    assert!(events[0].payload["duration_ms"].is_u64());
    assert!(events[0].duration_ms.is_some());
    assert_eq!(events[1].payload["kind"], "snapshot");
    assert_eq!(events[1].payload["elements"], 8);
    assert_eq!(events[1].payload["scan"], "clean");
    assert!(events[1].payload["bytes"].as_u64().unwrap() > 100);
    assert_eq!(events[2].payload["verb"], "click");
}

#[tokio::test]
async fn a_driver_failure_is_an_execution_failure_with_an_error_action() {
    let (family, _, bus) = browser_family(Arc::new(fake_browser()), browser_policy());
    let out = family
        .invoke(
            "browser__navigate",
            ctx("agent-a"),
            "c1",
            json!({ "url": "https://fixture.test/no-such-page" }),
        )
        .await
        .unwrap();
    assert!(out.is_error);
    assert!(
        out.content.starts_with("error navigate:"),
        "{}",
        out.content
    );
    assert_eq!(bus.types(), ["ui.action"]);
    assert_eq!(bus.events()[0].payload["is_error"], true);
}

#[tokio::test]
async fn refusals_emit_ui_refused_with_the_class_and_no_page_content() {
    let (family, _, bus) = browser_family(Arc::new(fake_browser()), browser_policy());
    family
        .invoke(
            "browser__navigate",
            ctx("agent-a"),
            "c1",
            json!({ "url": "https://denied.test/" }),
        )
        .await
        .unwrap_err();
    family
        .invoke(
            "browser__click",
            ctx("agent-a"),
            "c2",
            json!({ "ref": "e1" }),
        )
        .await
        .unwrap_err();
    assert_eq!(bus.types(), ["ui.refused", "ui.refused"]);
    let events = bus.events();
    assert!(events[0].payload["reason"]
        .as_str()
        .unwrap()
        .starts_with("permission-denied"));
    assert_eq!(events[1].payload["verb"], "click");
    assert!(events[1].payload["reason"]
        .as_str()
        .unwrap()
        .starts_with("invalid-arguments"));
}

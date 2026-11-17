//! The driver conformance suite (ADR 2026-10-28 S1 V2): the same cases run on
//! the Fake drivers here and on every product driver (a WKWebView, the Mac's
//! accessibility tree, a mirrored phone) in the product's tests.
//!
//! The suite is callable-level: it drives a [`UiFamily`] through
//! [`UiFamily::invoke`] with the standard policy ([`browser_policy`],
//! [`screen_policy`]) and checks outcomes, never driver internals. A product
//! test builds the family over its driver with `cap_ui::testing::browser_family`
//! (or `screen_family`), serves [`FIXTURE_HOME_HTML`] / [`FIXTURE_NEXT_HTML`]
//! at the fixture URLs (or loads them with that base URL), and asserts
//! `browser_conformance(&family, agent).await.assert_all_pass()`.

use advance_runtime::callable_registry::{CallableError, CallableOutcome};
use advance_shared_types::ui::{
    AllowRule, BrowserGrantPolicy, ConfirmPolicy, ScreenGrantPolicy, ScreenMode,
};
use serde_json::{json, Value};

use crate::fake::{ElementSpec, FakeBrowserDriver, FakeScreenDriver, PageSpec, WindowSpec};
use crate::family::UiFamily;
use crate::render::{parse_element_lines, parse_target_lines, OBSERVATION_BEGIN, OBSERVATION_END};
use crate::testing::ctx;

pub const FIXTURE_ORIGIN: &str = "https://fixture.test";
pub const FIXTURE_HOME_URL: &str = "https://fixture.test/";
pub const FIXTURE_NEXT_URL: &str = "https://fixture.test/next";
pub const DENIED_ORIGIN: &str = "https://denied.test";
pub const DENIED_URL: &str = "https://denied.test/";
/// The value of the fixture's password field; must never appear in an observation.
pub const PASSWORD_VALUE: &str = "hunter2-fixture-secret";

pub const FIXTURE_APP: &str = "com.fixture.app";
pub const FIXTURE_WINDOW_ID: &str = "win-1";
pub const DENIED_APP: &str = "com.denied.app";
pub const DENIED_WINDOW_ID: &str = "win-2";
/// The value of the fixture window's passcode field; must never appear in an observation.
pub const PASSCODE_VALUE: &str = "0000-fixture-secret";

/// The home page a product driver serves at [`FIXTURE_HOME_URL`].
pub const FIXTURE_HOME_HTML: &str = r#"<!doctype html>
<html><head><meta charset="utf-8"><title>Fixture Home</title></head>
<body>
<h1>Welcome</h1>
<p>Welcome to the fixture home page.</p>
<a href="/next">Next page</a>
<form action="/next" method="get">
<label>Search <input type="text" name="q" aria-label="Search"></label>
<label>Password <input type="password" name="pw" aria-label="Password" value="hunter2-fixture-secret"></label>
<label>Color <select aria-label="Color"><option>blue</option><option>red</option><option>green</option></select></label>
<label><input type="checkbox" aria-label="Agree"> Agree</label>
<button type="button">Go</button>
</form>
</body></html>
"#;

/// The second page a product driver serves at [`FIXTURE_NEXT_URL`].
pub const FIXTURE_NEXT_HTML: &str = r#"<!doctype html>
<html><head><meta charset="utf-8"><title>Next</title></head>
<body>
<h1>Second page</h1>
<p>You made it to the next page.</p>
<a href="/">Home</a>
</body></html>
"#;

/// The standard fixture pages, as the Fake browser serves them.
pub fn standard_pages() -> Vec<(String, PageSpec)> {
    vec![
        (
            FIXTURE_HOME_URL.to_string(),
            PageSpec::new("Fixture Home", "Welcome to the fixture home page.")
                .with(ElementSpec::heading("Welcome"))
                .with(ElementSpec::text("Welcome to the fixture home page."))
                .with(ElementSpec::link("Next page", FIXTURE_NEXT_URL))
                .with(ElementSpec::textbox_submit("Search", FIXTURE_NEXT_URL))
                .with(ElementSpec::password("Password", PASSWORD_VALUE))
                .with(ElementSpec::combobox("Color", &["blue", "red", "green"]))
                .with(ElementSpec::checkbox("Agree", false))
                .with(ElementSpec::button("Go")),
        ),
        (
            FIXTURE_NEXT_URL.to_string(),
            PageSpec::new("Next", "You made it to the next page.")
                .with(ElementSpec::heading("Second page"))
                .with(ElementSpec::text("You made it to the next page."))
                .with(ElementSpec::link("Home", FIXTURE_HOME_URL)),
        ),
        (
            DENIED_URL.to_string(),
            PageSpec::new("Denied", "This origin is outside the grant.")
                .with(ElementSpec::heading("Denied")),
        ),
    ]
}

/// The standard fixture windows, as the Fake screen serves them.
pub fn standard_windows() -> Vec<WindowSpec> {
    vec![
        WindowSpec::new(
            FIXTURE_WINDOW_ID,
            FIXTURE_APP,
            "Fixture Window",
            "A document.",
        )
        .with(ElementSpec::heading("Document"))
        .with(ElementSpec::button("Save"))
        .with(ElementSpec::textbox("Name"))
        .with(ElementSpec::password("Passcode", PASSCODE_VALUE))
        .with(ElementSpec::checkbox("Dark mode", false)),
        WindowSpec::new(
            DENIED_WINDOW_ID,
            DENIED_APP,
            "Denied Window",
            "Not for the agent.",
        )
        .with(ElementSpec::heading("Denied")),
    ]
}

pub fn fake_browser() -> FakeBrowserDriver {
    FakeBrowserDriver::with_fixture(standard_pages())
}

pub fn fake_screen() -> FakeScreenDriver {
    FakeScreenDriver::with_fixture(standard_windows())
}

/// The grant the suite assumes: `origins: [https://fixture.test]`, in-app only.
pub fn browser_policy() -> BrowserGrantPolicy {
    BrowserGrantPolicy {
        origins: AllowRule::List(vec![FIXTURE_ORIGIN.to_string()]),
        surfaces: vec!["in-app".to_string()],
        confirm: ConfirmPolicy::Never,
        downloads: false,
    }
}

/// The grant the suite assumes: `targets: [com.fixture.app]`, AX mode, no secure input.
pub fn screen_policy() -> ScreenGrantPolicy {
    ScreenGrantPolicy {
        targets: AllowRule::List(vec![FIXTURE_APP.to_string()]),
        mode: ScreenMode::Ax,
        confirm: ConfirmPolicy::Never,
        secure_input: false,
    }
}

/// One case's outcome.
#[derive(Debug, Clone)]
pub struct CaseResult {
    pub name: &'static str,
    pub outcome: Result<(), String>,
}

/// The suite's outcome.
#[derive(Debug, Clone, Default)]
pub struct ConformanceOutcome {
    pub cases: Vec<CaseResult>,
}

impl ConformanceOutcome {
    pub fn failures(&self) -> Vec<String> {
        self.cases
            .iter()
            .filter_map(|c| c.outcome.as_ref().err().map(|e| format!("{}: {e}", c.name)))
            .collect()
    }

    pub fn all_passed(&self) -> bool {
        self.failures().is_empty()
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.cases.iter().map(|c| c.name).collect()
    }

    /// Panic with every failure listed.
    pub fn assert_all_pass(&self) {
        let failures = self.failures();
        assert!(
            failures.is_empty(),
            "ui conformance: {} of {} cases failed:\n{}",
            failures.len(),
            self.cases.len(),
            failures.join("\n")
        );
    }
}

struct Runner<'a> {
    family: &'a UiFamily,
    agent_id: &'a str,
    cases: Vec<CaseResult>,
}

impl Runner<'_> {
    async fn invoke(&self, name: &str, args: Value) -> Result<CallableOutcome, CallableError> {
        self.family
            .invoke(name, ctx(self.agent_id), "conformance", args)
            .await
    }

    /// Expect `Ok` without `is_error`; returns the content.
    async fn ok(&self, name: &str, args: Value) -> Result<String, String> {
        match self.invoke(name, args).await {
            Ok(o) if !o.is_error => Ok(o.content),
            Ok(o) => Err(format!("{name}: execution failure: {}", o.content)),
            Err(e) => Err(format!("{name}: refused: {e}")),
        }
    }

    /// Expect a refusal of the given WIT class; returns its payload.
    async fn refused(&self, name: &str, args: Value, class: &str) -> Result<String, String> {
        match self.invoke(name, args).await {
            Err(e) if e.wit_case() == class => Ok(e.payload().to_string()),
            Err(e) => Err(format!("{name}: expected {class}, got {e}")),
            Ok(o) => Err(format!(
                "{name}: expected {class}, got Ok(is_error={}): {}",
                o.is_error, o.content
            )),
        }
    }

    fn record(&mut self, name: &'static str, outcome: Result<(), String>) {
        self.cases.push(CaseResult { name, outcome });
    }
}

fn observation(text: &str) -> Result<(), String> {
    if !text.starts_with(OBSERVATION_BEGIN) {
        return Err(format!(
            "observation does not start with the delimiter:\n{text}"
        ));
    }
    if !text.contains("untrusted-content") {
        return Err("observation header lacks `untrusted-content`".to_string());
    }
    if !text.trim_end().ends_with(OBSERVATION_END) {
        return Err(format!(
            "observation does not end with the delimiter:\n{text}"
        ));
    }
    Ok(())
}

fn starts_with(text: &str, prefix: &str) -> Result<(), String> {
    if text.starts_with(prefix) {
        Ok(())
    } else {
        Err(format!(
            "expected a result starting with {prefix:?}, got:\n{text}"
        ))
    }
}

fn contains(text: &str, needle: &str) -> Result<(), String> {
    if text.contains(needle) {
        Ok(())
    } else {
        Err(format!("expected {needle:?} in:\n{text}"))
    }
}

fn absent(text: &str, needle: &str) -> Result<(), String> {
    if text.contains(needle) {
        Err(format!("{needle:?} must not appear in:\n{text}"))
    } else {
        Ok(())
    }
}

fn find_ref(text: &str, role: &str, name: &str) -> Result<String, String> {
    parse_element_lines(text)
        .into_iter()
        .find(|(_, r, n)| r == role && n == name)
        .map(|(r, _, _)| r)
        .ok_or_else(|| format!("no {role} named {name:?} in:\n{text}"))
}

macro_rules! case {
    ($r:ident, $name:literal, $body:block) => {{
        let outcome: Result<(), String> = async { $body }.await;
        $r.record($name, outcome);
    }};
}

/// Run the browser cases against `family` (a browser family whose policy is
/// [`browser_policy`]) for `agent_id`.
pub async fn browser_conformance(family: &UiFamily, agent_id: &str) -> ConformanceOutcome {
    let mut r = Runner {
        family,
        agent_id,
        cases: Vec::new(),
    };
    let mut home_heading = String::new();
    let mut search = String::new();
    let mut password = String::new();
    let mut next_link = String::new();
    let mut color = String::new();
    let mut agree = String::new();

    case!(r, "tabs_list", {
        let t = r.ok("browser__tabs", json!({ "action": "list" })).await?;
        observation(&t)?;
        Ok::<(), String>(())
    });
    case!(r, "navigate_denied_origin", {
        r.refused(
            "browser__navigate",
            json!({ "url": DENIED_URL }),
            "permission-denied",
        )
        .await?;
        Ok::<(), String>(())
    });
    case!(r, "navigate_bad_scheme", {
        r.refused(
            "browser__navigate",
            json!({ "url": "javascript:alert(1)" }),
            "permission-denied",
        )
        .await?;
        r.refused(
            "browser__navigate",
            json!({ "url": "file:///etc/passwd" }),
            "permission-denied",
        )
        .await?;
        r.refused(
            "browser__navigate",
            json!({ "url": "not a url" }),
            "invalid-arguments",
        )
        .await?;
        Ok::<(), String>(())
    });
    case!(r, "navigate_allowed", {
        let t = r
            .ok("browser__navigate", json!({ "url": FIXTURE_HOME_URL }))
            .await?;
        starts_with(&t, "ok navigate: changed")?;
        // The action line names the landing origin only (no title, path or query).
        contains(&t, &format!("origin={FIXTURE_ORIGIN}"))?;
        absent(&t, "title=")?;
        Ok::<(), String>(())
    });
    case!(r, "snapshot_has_refs_and_masks_secure_values", {
        let t = r.ok("browser__snapshot", json!({})).await?;
        observation(&t)?;
        home_heading = find_ref(&t, "heading", "Welcome")?;
        search = find_ref(&t, "textbox", "Search")?;
        password = find_ref(&t, "textbox", "Password")?;
        next_link = find_ref(&t, "link", "Next page")?;
        color = find_ref(&t, "combobox", "Color")?;
        agree = find_ref(&t, "checkbox", "Agree")?;
        absent(&t, PASSWORD_VALUE)?;
        contains(&t, "[secure]")?;
        Ok::<(), String>(())
    });
    case!(r, "snapshot_options", {
        let t = r
            .ok(
                "browser__snapshot",
                json!({ "interactive_only": true, "max_elements": 3 }),
            )
            .await?;
        let lines = parse_element_lines(&t);
        if lines.len() != 3 {
            return Err(format!("expected 3 elements, got {}:\n{t}", lines.len()));
        }
        contains(&t, "(truncated)")?;
        r.refused(
            "browser__snapshot",
            json!({ "max_elements": 5000 }),
            "invalid-arguments",
        )
        .await?;
        Ok::<(), String>(())
    });
    case!(r, "unknown_ref", {
        r.refused(
            "browser__click",
            json!({ "ref": "e999" }),
            "invalid-arguments",
        )
        .await?;
        Ok::<(), String>(())
    });
    case!(r, "secure_type_refused", {
        r.refused(
            "browser__type",
            json!({ "ref": password, "text": "x" }),
            "permission-denied",
        )
        .await?;
        Ok::<(), String>(())
    });
    case!(r, "type_into_textbox", {
        let t = r
            .ok("browser__type", json!({ "ref": search, "text": "hello" }))
            .await?;
        starts_with(&t, "ok type: changed")?;
        let s = r.ok("browser__snapshot", json!({})).await?;
        contains(&s, "value=\"hello\"")?;
        Ok::<(), String>(())
    });
    case!(r, "select_option", {
        let t = r
            .ok(
                "browser__select",
                json!({ "ref": color, "values": ["red"] }),
            )
            .await?;
        starts_with(&t, "ok select: changed")?;
        Ok::<(), String>(())
    });
    case!(r, "checkbox_click", {
        let t = r.ok("browser__click", json!({ "ref": agree })).await?;
        starts_with(&t, "ok click: changed")?;
        Ok::<(), String>(())
    });
    case!(r, "hover_press_scroll", {
        starts_with(
            &r.ok("browser__hover", json!({ "ref": next_link })).await?,
            "ok hover",
        )?;
        starts_with(
            &r.ok("browser__press", json!({ "key": "Escape" })).await?,
            "ok press",
        )?;
        starts_with(
            &r.ok("browser__scroll", json!({ "dy": 200 })).await?,
            "ok scroll",
        )?;
        Ok::<(), String>(())
    });
    case!(r, "read_element_and_page", {
        let t = r
            .ok("browser__read", json!({ "ref": home_heading }))
            .await?;
        observation(&t)?;
        contains(&t, "Welcome")?;
        let p = r.ok("browser__read", json!({})).await?;
        observation(&p)?;
        contains(&p, "fixture")?;
        Ok::<(), String>(())
    });
    case!(r, "wait_bounds", {
        r.refused("browser__wait", json!({ "ms": 6000 }), "invalid-arguments")
            .await?;
        let t = r
            .ok("browser__wait", json!({ "text": "Welcome", "ms": 100 }))
            .await?;
        starts_with(&t, "ok wait")?;
        Ok::<(), String>(())
    });
    case!(r, "click_link_navigates", {
        let t = r.ok("browser__click", json!({ "ref": next_link })).await?;
        starts_with(&t, "ok click: changed")?;
        contains(&t, &format!("origin={FIXTURE_ORIGIN}"))?;
        Ok::<(), String>(())
    });
    case!(r, "stale_ref_refused", {
        r.refused(
            "browser__click",
            json!({ "ref": home_heading }),
            "invalid-arguments",
        )
        .await?;
        Ok::<(), String>(())
    });
    case!(r, "snapshot_after_navigation", {
        let t = r.ok("browser__snapshot", json!({})).await?;
        find_ref(&t, "heading", "Second page")?;
        contains(&t, FIXTURE_NEXT_URL)?;
        Ok::<(), String>(())
    });
    case!(r, "back_forward_reload", {
        let landed = format!("origin={FIXTURE_ORIGIN}");
        let b = r.ok("browser__back", json!({})).await?;
        starts_with(&b, "ok back: changed")?;
        contains(&b, &landed)?;
        let home = r.ok("browser__snapshot", json!({})).await?;
        find_ref(&home, "heading", "Welcome")?;
        let f = r.ok("browser__forward", json!({})).await?;
        starts_with(&f, "ok forward: changed")?;
        contains(&f, &landed)?;
        let next = r.ok("browser__snapshot", json!({})).await?;
        find_ref(&next, "heading", "Second page")?;
        starts_with(&r.ok("browser__reload", json!({})).await?, "ok reload")?;
        Ok::<(), String>(())
    });
    case!(r, "tabs_new_denied", {
        r.refused(
            "browser__tabs",
            json!({ "action": "new", "url": DENIED_URL }),
            "permission-denied",
        )
        .await?;
        Ok::<(), String>(())
    });
    case!(r, "tabs_new_select_close", {
        let t = r
            .ok(
                "browser__tabs",
                json!({ "action": "new", "url": FIXTURE_HOME_URL }),
            )
            .await?;
        let ids: Vec<String> = parse_target_lines(&t)
            .into_iter()
            .map(|(id, _, _)| id)
            .collect();
        if ids.len() != 2 {
            return Err(format!("expected 2 tabs after new, got {ids:?}:\n{t}"));
        }
        let first = ids[0].clone();
        let second = ids[1].clone();
        r.refused(
            "browser__tabs",
            json!({ "action": "select", "tab_id": "no-such-tab" }),
            "invalid-arguments",
        )
        .await?;
        r.ok(
            "browser__tabs",
            json!({ "action": "select", "tab_id": first }),
        )
        .await?;
        let t = r
            .ok(
                "browser__tabs",
                json!({ "action": "close", "tab_id": second }),
            )
            .await?;
        let ids: Vec<String> = parse_target_lines(&t)
            .into_iter()
            .map(|(id, _, _)| id)
            .collect();
        if ids.len() != 1 {
            return Err(format!("expected 1 tab after close, got {ids:?}:\n{t}"));
        }
        Ok::<(), String>(())
    });
    case!(r, "explicit_tab_argument", {
        let t = r.ok("browser__tabs", json!({ "action": "list" })).await?;
        let id = parse_target_lines(&t)
            .into_iter()
            .map(|(id, _, _)| id)
            .next()
            .ok_or_else(|| format!("no tab listed:\n{t}"))?;
        let s = r.ok("browser__snapshot", json!({ "tab": id })).await?;
        observation(&s)?;
        r.refused(
            "browser__snapshot",
            json!({ "tab": "no-such-tab" }),
            "invalid-arguments",
        )
        .await?;
        Ok::<(), String>(())
    });

    ConformanceOutcome { cases: r.cases }
}

/// Run the screen cases against `family` (a screen family whose policy is
/// [`screen_policy`]) for `agent_id`.
pub async fn screen_conformance(family: &UiFamily, agent_id: &str) -> ConformanceOutcome {
    let mut r = Runner {
        family,
        agent_id,
        cases: Vec::new(),
    };
    let mut heading = String::new();
    let mut save = String::new();
    let mut name = String::new();
    let mut passcode = String::new();
    let mut dark = String::new();

    case!(r, "act_without_current_target", {
        r.refused("screen__click", json!({ "ref": "e1" }), "invalid-arguments")
            .await?;
        Ok::<(), String>(())
    });
    case!(r, "list_targets_filtered_by_grant", {
        let t = r.ok("screen__list_targets", json!({})).await?;
        observation(&t)?;
        contains(&t, FIXTURE_APP)?;
        absent(&t, DENIED_APP)?;
        Ok::<(), String>(())
    });
    case!(r, "describe_denied_target", {
        r.refused(
            "screen__describe",
            json!({ "target": DENIED_WINDOW_ID }),
            "permission-denied",
        )
        .await?;
        Ok::<(), String>(())
    });
    case!(r, "describe_unknown_target", {
        r.refused(
            "screen__describe",
            json!({ "target": "no-such-window" }),
            "invalid-arguments",
        )
        .await?;
        Ok::<(), String>(())
    });
    case!(r, "describe_allowed_target_masks_secure_values", {
        let t = r
            .ok("screen__describe", json!({ "target": FIXTURE_WINDOW_ID }))
            .await?;
        observation(&t)?;
        heading = find_ref(&t, "heading", "Document")?;
        save = find_ref(&t, "button", "Save")?;
        name = find_ref(&t, "textbox", "Name")?;
        passcode = find_ref(&t, "textbox", "Passcode")?;
        dark = find_ref(&t, "checkbox", "Dark mode")?;
        absent(&t, PASSCODE_VALUE)?;
        contains(&t, "[secure]")?;
        Ok::<(), String>(())
    });
    case!(r, "click_button_and_checkbox", {
        starts_with(
            &r.ok("screen__click", json!({ "ref": save })).await?,
            "ok click",
        )?;
        let t = r.ok("screen__click", json!({ "ref": dark })).await?;
        starts_with(&t, "ok click: changed")?;
        Ok::<(), String>(())
    });
    case!(r, "type_secure_refused", {
        r.refused(
            "screen__type",
            json!({ "ref": passcode, "text": "1234" }),
            "permission-denied",
        )
        .await?;
        Ok::<(), String>(())
    });
    case!(r, "type_into_textbox", {
        let t = r
            .ok("screen__type", json!({ "ref": name, "text": "Ada" }))
            .await?;
        starts_with(&t, "ok type: changed")?;
        let d = r
            .ok("screen__describe", json!({ "target": FIXTURE_WINDOW_ID }))
            .await?;
        contains(&d, "value=\"Ada\"")?;
        heading = find_ref(&d, "heading", "Document")?;
        Ok::<(), String>(())
    });
    case!(r, "key_scroll_wait", {
        starts_with(
            &r.ok("screen__key", json!({ "keys": "cmd+s" })).await?,
            "ok key",
        )?;
        starts_with(
            &r.ok("screen__scroll", json!({ "ref": heading, "dy": 100 }))
                .await?,
            "ok scroll",
        )?;
        r.refused("screen__wait", json!({ "ms": 9000 }), "invalid-arguments")
            .await?;
        starts_with(&r.ok("screen__wait", json!({ "ms": 50 })).await?, "ok wait")?;
        Ok::<(), String>(())
    });
    case!(r, "read_element", {
        let t = r.ok("screen__read", json!({ "ref": heading })).await?;
        observation(&t)?;
        contains(&t, "Document")?;
        Ok::<(), String>(())
    });
    case!(r, "unknown_ref", {
        r.refused(
            "screen__click",
            json!({ "ref": "e999" }),
            "invalid-arguments",
        )
        .await?;
        Ok::<(), String>(())
    });
    case!(r, "focus_target", {
        let t = r
            .ok("screen__focus", json!({ "target": FIXTURE_WINDOW_ID }))
            .await?;
        starts_with(&t, "ok focus: changed")?;
        Ok::<(), String>(())
    });
    case!(r, "focus_denied_target", {
        r.refused(
            "screen__focus",
            json!({ "target": DENIED_WINDOW_ID }),
            "permission-denied",
        )
        .await?;
        Ok::<(), String>(())
    });
    case!(r, "target_named_by_app_id", {
        let t = r
            .ok("screen__describe", json!({ "target": FIXTURE_APP }))
            .await?;
        observation(&t)?;
        r.refused(
            "screen__describe",
            json!({ "target": DENIED_APP }),
            "permission-denied",
        )
        .await?;
        Ok::<(), String>(())
    });

    ConformanceOutcome { cases: r.cases }
}

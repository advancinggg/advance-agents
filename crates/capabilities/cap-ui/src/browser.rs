//! The `browser__*` family (ADR 2026-10-28 D2, text mode).
//!
//! Every verb: no driver → `not-found` (fixed reason) · no active `browser`
//! grant → `permission-denied` · driver surface kind not in the grant's
//! `surfaces` → `permission-denied` · the current page's origin (or the
//! navigation target's origin) is checked against the grant's `origins`
//! through `GrantCheck` (CONTRACT-122) · then the driver.

use std::sync::Arc;
use std::time::Instant;

use advance_runtime::callable_registry::{CallableError, CallableOutcome};
use advance_runtime::host_registry::HostCallContext;
use advance_shared_types::ui::{
    BrowserAction, BrowserDriverPort, BrowserGrantPolicy, HistoryAction, TabAction, UiActionResult,
    UiSurface, UiTargetInfo, WaitCondition,
};
use serde_json::{json, Map, Value};

use crate::common::{
    denied, driver_err, finish, invalid, object, observe, opt_bool, opt_i64, opt_str, parse_button,
    parse_count, parse_snapshot_options, parse_wait_ms, req_str, str_list, Args, Fail,
    UNTRUSTED_NOTE,
};
use crate::events;
use crate::family::{UiDeps, VerbSpec};
use crate::policy::{
    check_allowlist, exactly_allowlisted, navigable_origin, operable_origin, scheme_label,
    NO_DRIVER_REASON,
};
use crate::render::{render_action, render_read, render_snapshot, render_targets, Landing};

const SURFACE: UiSurface = UiSurface::Browser;

/// The S1 verbs, in catalog order.
pub const VERBS: &[&str] = &[
    "tabs", "navigate", "back", "forward", "reload", "snapshot", "click", "type", "press",
    "scroll", "select", "hover", "read", "wait",
];

const TAB_DESC: &str = "Tab id from browser__tabs; omitted = the selected tab.";
const REF_DESC: &str = "Element ref from the latest browser__snapshot, e.g. e12.";

fn schema(properties: Value, required: &[&str]) -> Value {
    let mut props: Map<String, Value> = properties.as_object().cloned().unwrap_or_default();
    props.insert(
        "tab".into(),
        json!({ "type": "string", "description": TAB_DESC }),
    );
    json!({
        "type": "object",
        "properties": Value::Object(props),
        "required": required,
        "additionalProperties": false
    })
}

fn spec(verb: &'static str, description: String, idempotent: bool, parameters: Value) -> VerbSpec {
    VerbSpec {
        verb,
        description,
        idempotent,
        parameters,
    }
}

pub fn verbs() -> Vec<VerbSpec> {
    let r = json!({ "type": "string", "description": REF_DESC });
    vec![
        spec(
            "tabs",
            format!("List, open, close or select browser tabs. `action` is list (default), new (optional `url`), close (`tab_id`) or select (`tab_id`). Returns the tab list.{UNTRUSTED_NOTE}"),
            false,
            schema(json!({
                "action": { "type": "string", "enum": ["list", "new", "close", "select"] },
                "url": { "type": "string", "description": "For new: an http(s) URL to open." },
                "tab_id": { "type": "string", "description": "For close / select." }
            }), &[]),
        ),
        spec(
            "navigate",
            "Navigate the selected tab (or `tab`) to an http(s) URL. Only origins the agent's grant allows can be opened. Take a browser__snapshot afterwards to get element refs.".to_string(),
            false,
            schema(json!({ "url": { "type": "string" } }), &["url"]),
        ),
        spec("back", "Go back one page in the tab's history.".to_string(), false, schema(json!({}), &[])),
        spec("forward", "Go forward one page in the tab's history.".to_string(), false, schema(json!({}), &[])),
        spec("reload", "Reload the current page.".to_string(), false, schema(json!({}), &[])),
        spec(
            "snapshot",
            format!("Observe the current page as a list of elements with refs (e1, e2, …), roles, names, values and states, plus the visible text. Refs stay valid until the page changes; a stale ref is refused and a new snapshot is needed. `scope` is viewport (default) or full; `interactive_only` lists only clickable / typeable elements; `max_elements` is at most 1000.{UNTRUSTED_NOTE}"),
            true,
            schema(json!({
                "scope": { "type": "string", "enum": ["viewport", "full"] },
                "interactive_only": { "type": "boolean" },
                "max_elements": { "type": "integer", "minimum": 1, "maximum": 1000 }
            }), &[]),
        ),
        spec(
            "click",
            "Click the element `ref` from the latest snapshot. `button` is left (default), right or middle; `count` is 1 (default) or 2 for a double click.".to_string(),
            false,
            schema(json!({
                "ref": r,
                "button": { "type": "string", "enum": ["left", "right", "middle"] },
                "count": { "type": "integer", "minimum": 1, "maximum": 2 }
            }), &["ref"]),
        ),
        spec(
            "type",
            "Type `text` into the element `ref` (a text field). `clear` replaces the current value first; `submit` presses Enter afterwards. Typing into password fields is refused.".to_string(),
            false,
            schema(json!({
                "ref": r,
                "text": { "type": "string" },
                "clear": { "type": "boolean" },
                "submit": { "type": "boolean" }
            }), &["ref", "text"]),
        ),
        spec(
            "press",
            "Press a key or chord on the page: Enter, Escape, Tab, ArrowDown, cmd+a, ctrl+shift+t.".to_string(),
            false,
            schema(json!({ "key": { "type": "string" } }), &["key"]),
        ),
        spec(
            "scroll",
            "Scroll the page (or the element `ref`) by `dx`, `dy` pixels; positive is right / down.".to_string(),
            false,
            schema(json!({
                "ref": r,
                "dx": { "type": "integer" },
                "dy": { "type": "integer" }
            }), &[]),
        ),
        spec(
            "select",
            "Choose `values` in the select / listbox element `ref`.".to_string(),
            false,
            schema(json!({
                "ref": r,
                "values": { "type": "array", "items": { "type": "string" }, "minItems": 1 }
            }), &["ref", "values"]),
        ),
        spec(
            "hover",
            "Move the pointer over the element `ref`.".to_string(),
            false,
            schema(json!({ "ref": r }), &["ref"]),
        ),
        spec(
            "read",
            format!("Read the text of the element `ref`, or of the whole page when `ref` is omitted.{UNTRUSTED_NOTE}"),
            true,
            schema(json!({ "ref": r }), &[]),
        ),
        spec(
            "wait",
            "Wait up to `ms` milliseconds (at most 5000; default 1000) for `text` to appear on the page, or just wait `ms` when `text` is omitted.".to_string(),
            true,
            schema(json!({
                "text": { "type": "string" },
                "ms": { "type": "integer", "minimum": 0, "maximum": 5000 }
            }), &[]),
        ),
    ]
}

/// Entry point used by the family's handler.
pub async fn invoke(
    deps: &UiDeps,
    driver: Option<&Arc<dyn BrowserDriverPort>>,
    ctx: &HostCallContext,
    verb: &'static str,
    call_id: String,
    arguments: Value,
) -> Result<CallableOutcome, CallableError> {
    let started = Instant::now();
    let result = run(deps, driver, ctx, verb, &arguments, started).await;
    finish(deps, ctx, SURFACE, verb, started, call_id, result)
}

struct Call<'a> {
    deps: &'a UiDeps,
    driver: &'a dyn BrowserDriverPort,
    ctx: &'a HostCallContext,
    policy: BrowserGrantPolicy,
    args: Args<'a>,
    tab: Option<&'a str>,
    started: Instant,
}

async fn run(
    deps: &UiDeps,
    driver: Option<&Arc<dyn BrowserDriverPort>>,
    ctx: &HostCallContext,
    verb: &str,
    arguments: &Value,
    started: Instant,
) -> Result<String, Fail> {
    let driver = driver
        .ok_or_else(|| Fail::Refusal(CallableError::NotFound(NO_DRIVER_REASON.to_string())))?;
    let args = object(arguments)?;
    let policy = deps
        .policy
        .browser_policy(&ctx.agent_id)
        .ok_or_else(|| denied("browser: the agent holds no active browser grant"))?;
    let kind = driver.surface_kind();
    if !policy.surfaces.iter().any(|s| s == kind) {
        return Err(denied(format!(
            "browser: the {kind} surface is not allowed by the grant (surfaces: {})",
            policy.surfaces.join(", ")
        )));
    }
    let c = Call {
        deps,
        driver: &**driver,
        ctx,
        policy,
        args,
        tab: opt_str(args, "tab"),
        started,
    };
    match verb {
        "tabs" => tabs(&c).await,
        "navigate" => navigate(&c).await,
        "back" | "forward" | "reload" => history(&c, verb).await,
        "snapshot" => snapshot(&c).await,
        "read" => read(&c).await,
        "wait" => wait(&c).await,
        "click" | "type" | "press" | "scroll" | "select" | "hover" => act(&c, verb).await,
        other => Err(Fail::Refusal(CallableError::NotFound(format!(
            "browser.{other}"
        )))),
    }
}

impl Call<'_> {
    /// Is this tab within the grant's reach? Blank tabs (`about:` or no URL)
    /// are; otherwise its page needs an http(s) origin the grant covers
    /// ([`operable_origin`]): `file:`, `data:`, `chrome:` or a custom scheme
    /// never is, even under a whole-capability grant. The tab listing, the
    /// landing note and [`Self::gate_page`] share this rule.
    fn in_reach(&self, page: &UiTargetInfo) -> bool {
        match page.url.as_deref() {
            None => true,
            Some(u) if u.starts_with("about:") => true,
            Some(u) => operable_origin(u).is_some_and(|o| self.policy.origins.covers_origin(&o)),
        }
    }

    /// The origin gate for one tab's page: blank tabs pass; an http(s) page's
    /// origin must be covered by the grant (`GrantCheck` with
    /// `{origins: <origin>}`); any other page is not operable. The refusal
    /// names the scheme only: a `data:` URL can carry any text.
    fn gate_page(&self, page: &UiTargetInfo) -> Result<(), Fail> {
        let Some(url) = page.url.as_deref() else {
            return Ok(());
        };
        if url.starts_with("about:") {
            return Ok(());
        }
        match operable_origin(url) {
            Some(origin) => Ok(check_allowlist(
                &*self.deps.grant,
                self.ctx,
                SURFACE,
                &origin,
            )?),
            None => Err(denied(format!(
                "browser: the page has no http(s) origin (scheme {:?}) and cannot be operated",
                scheme_label(url)
            ))),
        }
    }

    /// The gate for everything that touches the current page of the call's tab.
    async fn gate_current(&self) -> Result<UiTargetInfo, Fail> {
        let cur = self.driver.current(self.tab).await.map_err(driver_err)?;
        self.gate_page(&cur)?;
        Ok(cur)
    }

    /// A tab named by id must exist and its page must pass
    /// [`Self::gate_page`], so a tab the listing hides cannot be selected,
    /// closed or navigated by guessing its id. `navigate` exempts the active
    /// tab (`active_exempt`): navigating it is how the model leaves a page out
    /// of reach.
    async fn gate_tab(&self, verb: &str, tab_id: &str, active_exempt: bool) -> Result<(), Fail> {
        let tabs = self
            .driver
            .tabs(TabAction::List)
            .await
            .map_err(driver_err)?;
        let tab = tabs.iter().find(|t| t.id == tab_id).ok_or_else(|| {
            invalid(format!(
                "browser.{verb}: unknown tab {tab_id:?}; call browser__tabs to list them"
            ))
        })?;
        if active_exempt && tab.active {
            return Ok(());
        }
        self.gate_page(tab)
    }

    /// Scheme → allowlist → SSRF guard (unless the origin is named exactly).
    async fn check_url(&self, verb: &str, url: &str) -> Result<String, Fail> {
        let origin = navigable_origin(url)?;
        check_allowlist(&*self.deps.grant, self.ctx, SURFACE, &origin)?;
        if let Some(ssrf) = &self.deps.ssrf {
            if !exactly_allowlisted(&self.policy.origins, &origin) {
                ssrf.check(url).await.map_err(|e| {
                    denied(format!(
                        "browser.{verb}: {url} is refused by the SSRF guard ({e:?})"
                    ))
                })?;
            }
        }
        Ok(origin)
    }

    /// Where the action left the tab, and whether that is within reach
    /// ([`Self::in_reach`]): a click can follow a link off the allowlist or to
    /// another scheme, and the next call on that tab is refused by
    /// [`Self::gate_current`]. A blank tab names no landing.
    fn landing(&self, res: &UiActionResult) -> Option<Landing> {
        let page = res.target.as_ref()?;
        let url = page.url.as_deref()?;
        if url.starts_with("about:") {
            return None;
        }
        let place = match operable_origin(url) {
            Some(origin) => format!("origin={origin}"),
            None => format!("scheme={}", scheme_label(url)),
        };
        Some(Landing {
            covered: self.in_reach(page),
            place,
        })
    }

    fn action_ok(&self, verb: &str, res: &UiActionResult) -> String {
        let target = res.target.as_ref().map(|t| t.id.as_str()).or(self.tab);
        events::action(
            &*self.deps.events,
            self.ctx,
            SURFACE,
            verb,
            target,
            res.sensitive,
            self.started.elapsed().as_millis() as u64,
            false,
        );
        render_action(verb, res, self.landing(res).as_ref())
    }
}

async fn tabs(c: &Call<'_>) -> Result<String, Fail> {
    let action = opt_str(c.args, "action").unwrap_or("list");
    let ta = match action {
        "list" => TabAction::List,
        "new" => {
            let url = opt_str(c.args, "url").map(str::to_string);
            if let Some(u) = &url {
                c.check_url("tabs", u).await?;
            }
            TabAction::New { url }
        }
        "close" => {
            let tab_id = req_str(c.args, "tab_id")?;
            c.gate_tab("tabs", tab_id, false).await?;
            TabAction::Close {
                tab_id: tab_id.to_string(),
            }
        }
        "select" => {
            let tab_id = req_str(c.args, "tab_id")?;
            c.gate_tab("tabs", tab_id, false).await?;
            TabAction::Select {
                tab_id: tab_id.to_string(),
            }
        }
        other => {
            return Err(invalid(format!(
                "browser.tabs: unknown action {other:?} (list, new, close, select)"
            )))
        }
    };
    let is_action = !matches!(ta, TabAction::List);
    let target_id = match &ta {
        TabAction::Close { tab_id } | TabAction::Select { tab_id } => Some(tab_id.clone()),
        _ => None,
    };
    let tabs = c.driver.tabs(ta).await.map_err(driver_err)?;
    if is_action {
        events::action(
            &*c.deps.events,
            c.ctx,
            SURFACE,
            "tabs",
            target_id.as_deref(),
            false,
            c.started.elapsed().as_millis() as u64,
            false,
        );
    }
    // Tabs out of reach (an origin outside the grant, or a page without an
    // http(s) origin) are not listed: the model cannot operate them and their
    // titles / URLs are not its business.
    let visible: Vec<UiTargetInfo> = tabs.into_iter().filter(|t| c.in_reach(t)).collect();
    observe(
        c.deps,
        c.ctx,
        SURFACE,
        "tabs",
        render_targets(SURFACE, "tabs", None, &visible),
    )
}

async fn navigate(c: &Call<'_>) -> Result<String, Fail> {
    let url = req_str(c.args, "url")?;
    // Navigating the active tab leaves whatever page it is on (the recovery
    // path); another tab named by id must be in reach.
    if let Some(tab_id) = c.tab {
        c.gate_tab("navigate", tab_id, true).await?;
    }
    c.check_url("navigate", url).await?;
    let res = c.driver.navigate(c.tab, url).await.map_err(driver_err)?;
    Ok(c.action_ok("navigate", &res))
}

async fn history(c: &Call<'_>, verb: &str) -> Result<String, Fail> {
    let action = match verb {
        "back" => HistoryAction::Back,
        "forward" => HistoryAction::Forward,
        _ => HistoryAction::Reload,
    };
    c.gate_current().await?;
    let res = c.driver.history(c.tab, action).await.map_err(driver_err)?;
    Ok(c.action_ok(verb, &res))
}

async fn snapshot(c: &Call<'_>) -> Result<String, Fail> {
    let options = parse_snapshot_options(c.args, "browser.snapshot")?;
    c.gate_current().await?;
    let snap = c
        .driver
        .snapshot(c.tab, options)
        .await
        .map_err(driver_err)?;
    observe(
        c.deps,
        c.ctx,
        SURFACE,
        "snapshot",
        render_snapshot(SURFACE, &snap),
    )
}

async fn read(c: &Call<'_>) -> Result<String, Fail> {
    let r = opt_str(c.args, "ref");
    c.gate_current().await?;
    let res = c.driver.read(c.tab, r).await.map_err(driver_err)?;
    observe(
        c.deps,
        c.ctx,
        SURFACE,
        "read",
        render_read(SURFACE, &res, r),
    )
}

async fn wait(c: &Call<'_>) -> Result<String, Fail> {
    let ms = parse_wait_ms(c.args, "browser.wait")?;
    let text = opt_str(c.args, "text").map(str::to_string);
    c.gate_current().await?;
    let res = c
        .driver
        .wait(c.tab, WaitCondition { text, ms })
        .await
        .map_err(driver_err)?;
    Ok(c.action_ok("wait", &res))
}

async fn act(c: &Call<'_>, verb: &str) -> Result<String, Fail> {
    let action = match verb {
        "click" => BrowserAction::Click {
            r#ref: req_str(c.args, "ref")?.to_string(),
            button: parse_button(opt_str(c.args, "button"), "browser.click")?,
            count: parse_count(c.args, "browser.click")?,
        },
        "type" => BrowserAction::Type {
            r#ref: req_str(c.args, "ref")?.to_string(),
            text: req_str(c.args, "text")?.to_string(),
            submit: opt_bool(c.args, "submit", false),
            clear: opt_bool(c.args, "clear", false),
            // S1: the browser grant has no `secure-input` knob; password
            // fields are never typed into (ADR D2).
            allow_secure: false,
        },
        "press" => {
            let key = req_str(c.args, "key")?;
            if key.trim().is_empty() {
                return Err(invalid("browser.press: `key` is empty"));
            }
            BrowserAction::Press {
                key: key.to_string(),
            }
        }
        "scroll" => BrowserAction::Scroll {
            r#ref: opt_str(c.args, "ref").map(str::to_string),
            dx: opt_i64(c.args, "dx", 0),
            dy: opt_i64(c.args, "dy", 0),
        },
        "select" => {
            let values = str_list(c.args, "values")?;
            if values.is_empty() {
                return Err(invalid("browser.select: `values` is empty"));
            }
            BrowserAction::Select {
                r#ref: req_str(c.args, "ref")?.to_string(),
                values,
            }
        }
        "hover" => BrowserAction::Hover {
            r#ref: req_str(c.args, "ref")?.to_string(),
        },
        other => {
            return Err(Fail::Refusal(CallableError::NotFound(format!(
                "browser.{other}"
            ))))
        }
    };
    c.gate_current().await?;
    let res = c.driver.act(c.tab, action).await.map_err(driver_err)?;
    Ok(c.action_ok(verb, &res))
}

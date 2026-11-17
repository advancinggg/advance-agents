//! The `screen__*` family (ADR 2026-10-28 D2, accessibility text mode).
//!
//! Targets are windows / applications the driver lists; the grant's `targets`
//! names application ids. `screen__list_targets` shows only allowed targets;
//! operating one goes through `GrantCheck` with `{targets: <app id>}`
//! (CONTRACT-122). Refs are scoped to the current target: the one last
//! described or focused.

use std::sync::Arc;
use std::time::Instant;

use advance_runtime::callable_registry::{CallableError, CallableOutcome};
use advance_runtime::host_registry::HostCallContext;
use advance_shared_types::ui::{
    ScreenAction, ScreenDriverPort, ScreenGrantPolicy, UiActionResult, UiError, UiSurface,
    UiTargetInfo,
};
use serde_json::{json, Map, Value};

use crate::common::{
    denied, driver_err, finish, invalid, object, observe, opt_bool, opt_i64, opt_str, opt_u64,
    parse_button, parse_count, parse_snapshot_options, parse_wait_ms, req_str, str_list, Args,
    Fail, UNTRUSTED_NOTE,
};
use crate::events;
use crate::family::{UiDeps, VerbSpec};
use crate::policy::{check_allowlist, NO_DRIVER_REASON};
use crate::render::{defang, render_action, render_read, render_snapshot, render_targets, Landing};

const SURFACE: UiSurface = UiSurface::Screen;

/// The S1 verbs, in catalog order.
pub const VERBS: &[&str] = &[
    "list_targets",
    "describe",
    "click",
    "type",
    "key",
    "scroll",
    "read",
    "focus",
    "wait",
];

const TARGET_DESC: &str =
    "Target id (or application id) from screen__list_targets; omitted = the current target.";
const REF_DESC: &str = "Element ref from the latest screen__describe, e.g. e7.";

fn schema(properties: Value, required: &[&str], with_target: bool) -> Value {
    let mut props: Map<String, Value> = properties.as_object().cloned().unwrap_or_default();
    if with_target {
        props.insert(
            "target".into(),
            json!({ "type": "string", "description": TARGET_DESC }),
        );
    }
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
            "list_targets",
            format!("List the windows and applications the agent may operate, with their target ids.{UNTRUSTED_NOTE}"),
            true,
            schema(json!({}), &[], false),
        ),
        spec(
            "describe",
            format!("Observe a target's accessibility tree as elements with refs (e1, e2, …), roles, names, values and states, and make it the current target. Refs stay valid until the window changes; a stale ref is refused and a new describe is needed. `scope` is viewport (default) or full; `interactive_only` lists only actionable elements; `max_elements` is at most 1000.{UNTRUSTED_NOTE}"),
            true,
            schema(json!({
                "scope": { "type": "string", "enum": ["viewport", "full"] },
                "interactive_only": { "type": "boolean" },
                "max_elements": { "type": "integer", "minimum": 1, "maximum": 1000 }
            }), &["target"], true),
        ),
        spec(
            "click",
            "Click the element `ref` of the current target (or `target`). `button` is left (default), right or middle; `count` is 1 or 2; `modifiers` are cmd, shift, alt, ctrl.".to_string(),
            false,
            schema(json!({
                "ref": r,
                "button": { "type": "string", "enum": ["left", "right", "middle"] },
                "count": { "type": "integer", "minimum": 1, "maximum": 2 },
                "modifiers": { "type": "array", "items": { "type": "string", "enum": ["cmd", "shift", "alt", "ctrl"] } }
            }), &["ref"], true),
        ),
        spec(
            "type",
            "Type `text` into the element `ref` (or the focused element when `ref` is omitted). `replace` replaces the current value instead of appending. Typing into secure fields is refused unless the grant allows it.".to_string(),
            false,
            schema(json!({
                "ref": r,
                "text": { "type": "string" },
                "replace": { "type": "boolean" }
            }), &["text"], true),
        ),
        spec(
            "key",
            "Press a key or chord in the current target: Enter, Escape, Tab, cmd+s, ctrl+shift+t. `hold_ms` holds it.".to_string(),
            false,
            schema(json!({
                "keys": { "type": "string" },
                "hold_ms": { "type": "integer", "minimum": 0, "maximum": 5000 }
            }), &["keys"], true),
        ),
        spec(
            "scroll",
            "Scroll the element `ref` by `dx`, `dy` points; positive is right / down.".to_string(),
            false,
            schema(json!({
                "ref": r,
                "dx": { "type": "integer" },
                "dy": { "type": "integer" }
            }), &["ref"], true),
        ),
        spec(
            "read",
            format!("Read the text of the element `ref` in the current target (or `target`).{UNTRUSTED_NOTE}"),
            true,
            schema(json!({ "ref": r }), &["ref"], true),
        ),
        spec(
            "focus",
            "Bring `target` to the front and make it the current target.".to_string(),
            false,
            schema(json!({}), &["target"], true),
        ),
        spec(
            "wait",
            "Wait `ms` milliseconds (at most 5000; default 1000) for the current target to settle.".to_string(),
            true,
            schema(json!({
                "ms": { "type": "integer", "minimum": 0, "maximum": 5000 }
            }), &[], true),
        ),
    ]
}

/// Entry point used by the family's handler.
pub async fn invoke(
    deps: &UiDeps,
    driver: Option<&Arc<dyn ScreenDriverPort>>,
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
    driver: &'a dyn ScreenDriverPort,
    ctx: &'a HostCallContext,
    policy: ScreenGrantPolicy,
    args: Args<'a>,
    started: Instant,
}

async fn run(
    deps: &UiDeps,
    driver: Option<&Arc<dyn ScreenDriverPort>>,
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
        .screen_policy(&ctx.agent_id)
        .ok_or_else(|| denied("screen: the agent holds no active screen grant"))?;
    let c = Call {
        deps,
        driver: &**driver,
        ctx,
        policy,
        args,
        started,
    };
    match verb {
        "list_targets" => list_targets(&c).await,
        "describe" => describe(&c).await,
        "focus" => focus(&c).await,
        "read" => read(&c).await,
        "wait" => wait(&c).await,
        "click" | "type" | "key" | "scroll" => act(&c, verb).await,
        other => Err(Fail::Refusal(CallableError::NotFound(format!(
            "screen.{other}"
        )))),
    }
}

/// The value the `targets` allowlist is checked against: the application id,
/// or the target id for a driver that reports none.
fn key_of(t: &UiTargetInfo) -> &str {
    t.app.as_deref().unwrap_or(&t.id)
}

impl Call<'_> {
    /// Resolve a target named by id (or by application id) and pass it through
    /// the `targets` gate.
    async fn resolve(&self, target: &str) -> Result<UiTargetInfo, Fail> {
        let list = self.driver.list_targets().await.map_err(driver_err)?;
        let found = list
            .iter()
            .find(|t| t.id == target)
            .or_else(|| list.iter().find(|t| t.app.as_deref() == Some(target)))
            .cloned();
        let info = found.ok_or_else(|| {
            Fail::Refusal(CallableError::InvalidArguments(
                UiError::UnknownTarget {
                    target: target.to_string(),
                }
                .to_string(),
            ))
        })?;
        check_allowlist(&*self.deps.grant, self.ctx, SURFACE, key_of(&info))?;
        Ok(info)
    }

    /// The named target, or the driver's current one; gated either way.
    async fn current_or(&self, target: Option<&str>) -> Result<UiTargetInfo, Fail> {
        match target {
            Some(t) => self.resolve(t).await,
            None => {
                let cur = self
                    .driver
                    .current()
                    .await
                    .map_err(driver_err)?
                    .ok_or_else(|| {
                        invalid("screen: no current target; call screen__describe or screen__focus first")
                    })?;
                check_allowlist(&*self.deps.grant, self.ctx, SURFACE, key_of(&cur))?;
                Ok(cur)
            }
        }
    }

    /// Where the action left the screen: the target the driver reports after it
    /// (focus can move to another application), as ids only.
    fn landing(&self, res: &UiActionResult, before: &UiTargetInfo) -> Landing {
        let t = res.target.as_ref().unwrap_or(before);
        let mut place = format!("target={}", defang(&t.id));
        if let Some(app) = &t.app {
            place.push_str(&format!(" app={}", defang(app)));
        }
        Landing {
            covered: self.policy.targets.covers_target(key_of(t)),
            place,
        }
    }

    fn action_ok(&self, verb: &str, res: &UiActionResult, target: &UiTargetInfo) -> String {
        events::action(
            &*self.deps.events,
            self.ctx,
            SURFACE,
            verb,
            Some(&target.id),
            res.sensitive,
            self.started.elapsed().as_millis() as u64,
            false,
        );
        render_action(verb, res, Some(&self.landing(res, target)))
    }
}

async fn list_targets(c: &Call<'_>) -> Result<String, Fail> {
    let all = c.driver.list_targets().await.map_err(driver_err)?;
    let visible: Vec<UiTargetInfo> = all
        .into_iter()
        .filter(|t| c.policy.targets.covers_target(key_of(t)))
        .collect();
    observe(
        c.deps,
        c.ctx,
        SURFACE,
        "targets",
        render_targets(SURFACE, "targets", None, &visible),
    )
}

async fn describe(c: &Call<'_>) -> Result<String, Fail> {
    let target = req_str(c.args, "target")?;
    let options = parse_snapshot_options(c.args, "screen.describe")?;
    let info = c.resolve(target).await?;
    let snap = c
        .driver
        .describe(&info.id, options)
        .await
        .map_err(driver_err)?;
    observe(
        c.deps,
        c.ctx,
        SURFACE,
        "describe",
        render_snapshot(SURFACE, &snap),
    )
}

async fn focus(c: &Call<'_>) -> Result<String, Fail> {
    let target = req_str(c.args, "target")?;
    let info = c.resolve(target).await?;
    let res = c
        .driver
        .act(Some(&info.id), ScreenAction::Focus)
        .await
        .map_err(driver_err)?;
    Ok(c.action_ok("focus", &res, &info))
}

async fn read(c: &Call<'_>) -> Result<String, Fail> {
    let r = req_str(c.args, "ref")?;
    let named = opt_str(c.args, "target");
    let info = c.current_or(named).await?;
    let target = named.map(|_| info.id.as_str());
    let res = c.driver.read(target, r).await.map_err(driver_err)?;
    observe(
        c.deps,
        c.ctx,
        SURFACE,
        "read",
        render_read(SURFACE, &res, Some(r)),
    )
}

async fn wait(c: &Call<'_>) -> Result<String, Fail> {
    let ms = parse_wait_ms(c.args, "screen.wait")?;
    let named = opt_str(c.args, "target");
    let info = c.current_or(named).await?;
    let target = named.map(|_| info.id.as_str());
    let res = c.driver.wait(target, ms).await.map_err(driver_err)?;
    Ok(c.action_ok("wait", &res, &info))
}

async fn act(c: &Call<'_>, verb: &str) -> Result<String, Fail> {
    let action = match verb {
        "click" => {
            let modifiers = str_list(c.args, "modifiers")?;
            for m in &modifiers {
                if !matches!(m.as_str(), "cmd" | "shift" | "alt" | "ctrl") {
                    return Err(invalid(format!(
                        "screen.click: unknown modifier {m:?} (cmd, shift, alt, ctrl)"
                    )));
                }
            }
            ScreenAction::Click {
                r#ref: req_str(c.args, "ref")?.to_string(),
                button: parse_button(opt_str(c.args, "button"), "screen.click")?,
                count: parse_count(c.args, "screen.click")?,
                modifiers,
            }
        }
        "type" => ScreenAction::Type {
            r#ref: opt_str(c.args, "ref").map(str::to_string),
            text: req_str(c.args, "text")?.to_string(),
            replace: opt_bool(c.args, "replace", false),
            allow_secure: c.policy.secure_input,
        },
        "key" => {
            let keys = req_str(c.args, "keys")?;
            if keys.trim().is_empty() {
                return Err(invalid("screen.key: `keys` is empty"));
            }
            let hold_ms = opt_u64(c.args, "hold_ms");
            if hold_ms.is_some_and(|h| h > 5_000) {
                return Err(invalid("screen.key: hold_ms exceeds the bound of 5000 ms"));
            }
            ScreenAction::Key {
                keys: keys.to_string(),
                hold_ms,
            }
        }
        "scroll" => ScreenAction::Scroll {
            r#ref: req_str(c.args, "ref")?.to_string(),
            dx: opt_i64(c.args, "dx", 0),
            dy: opt_i64(c.args, "dy", 0),
        },
        other => {
            return Err(Fail::Refusal(CallableError::NotFound(format!(
                "screen.{other}"
            ))))
        }
    };
    let named = opt_str(c.args, "target");
    let info = c.current_or(named).await?;
    let target = named.map(|_| info.id.as_str());
    let res = c.driver.act(target, action).await.map_err(driver_err)?;
    Ok(c.action_ok(verb, &res, &info))
}

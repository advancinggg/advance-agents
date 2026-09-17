//! agenda-tools — the agenda pack's pure reducers, run by the host through `data.apply`.
//!
//! Input (JSON, from the host): `{ "op", "target", "self", "parent", "args", "now", "ids" }`.
//! Output: `{ "effects": [ … ] }` or `{ "error": "<reason>" }`. This code never touches
//! storage; the host validates every effect against the schema and applies the list in one
//! transaction. It reads no clock (`now` is an input) and no randomness (`ids` are supplied).
//!
//! Methods:
//! - `detach-occurrence { at }`: for a repeating event, remove the occurrence at `at` from the
//!   series (`exdates`) and create a standalone sibling event at `at` with the same length.
//! - `shift-series { by }`: move `starts` / `ends` / every `exdates` entry by a duration
//!   (`30m`, `2h`, `1d`, `7d`, `2w`, optionally negative).

wit_bindgen::generate!({
    path: "wit",
    world: "agenda-tools",
});

use chrono::{DateTime, Duration, FixedOffset, SecondsFormat};
use exports::advance::runtime::tool_exports::{Guest, MethodInfo, ToolDescription};
use serde_json::{json, Map, Value};

struct AgendaTools;

fn describe_method(name: &str, desc: &str, input: Value) -> MethodInfo {
    MethodInfo {
        name: name.to_string(),
        description: Some(desc.to_string()),
        input_schema: serde_json::to_string(&input).ok(),
        output_schema: serde_json::to_string(&json!({ "type": "object" })).ok(),
        idempotent: Some(true),
    }
}

impl Guest for AgendaTools {
    fn describe() -> ToolDescription {
        ToolDescription {
            description: "agenda series operations (pure reducers for data.apply)".to_string(),
            methods: vec![
                describe_method(
                    "detach-occurrence",
                    "Remove one occurrence from a repeating event and create it as a standalone sibling",
                    json!({ "type": "object", "required": ["op", "self", "args", "now", "ids"] }),
                ),
                describe_method(
                    "shift-series",
                    "Move starts / ends / exdates of an event by a duration",
                    json!({ "type": "object", "required": ["op", "self", "args", "now", "ids"] }),
                ),
            ],
        }
    }

    fn execute(method: String, params: Vec<u8>) -> Result<Vec<u8>, String> {
        let input: Value =
            serde_json::from_slice(&params).map_err(|e| format!("input is not JSON: {e}"))?;
        let out = match method.as_str() {
            "detach-occurrence" => detach_occurrence(&input),
            "shift-series" => shift_series(&input),
            other => return Err(format!("method-not-found: {other}")),
        };
        serde_json::to_vec(&out).map_err(|e| e.to_string())
    }
}

export!(AgendaTools with_types_in crate);

fn error(msg: impl Into<String>) -> Value {
    json!({ "error": msg.into() })
}

fn field<'a>(v: &'a Value, name: &str) -> Option<&'a Value> {
    v.get(name)
}

fn str_field<'a>(v: &'a Value, name: &str) -> Option<&'a str> {
    field(v, name).and_then(Value::as_str)
}

fn parse_dt(s: &str) -> Option<DateTime<FixedOffset>> {
    if let Ok(d) = DateTime::parse_from_rfc3339(s.trim()) {
        return Some(d);
    }
    // `YYYY-MM-DD` = midnight UTC.
    let date = chrono::NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d").ok()?;
    let naive = date.and_hms_opt(0, 0, 0)?;
    Some(DateTime::<FixedOffset>::from_naive_utc_and_offset(
        naive,
        FixedOffset::east_opt(0)?,
    ))
}

fn fmt_dt(d: DateTime<FixedOffset>) -> String {
    d.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    let (neg, s) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let split = s.find(|c: char| !c.is_ascii_digit())?;
    let (num, unit) = s.split_at(split);
    let n: i64 = num.parse().ok()?;
    let d = match unit {
        "m" => Duration::minutes(n),
        "h" => Duration::hours(n),
        "d" => Duration::days(n),
        "w" => Duration::weeks(n),
        _ => return None,
    };
    Some(if neg { -d } else { d })
}

/// The file part of `"path#e-…"` / `"path"`.
fn target_path(input: &Value) -> Option<String> {
    let t = str_field(input, "target")?;
    Some(t.split('#').next().unwrap_or(t).to_string())
}

fn detach_occurrence(input: &Value) -> Value {
    let this = match field(input, "self") {
        Some(v) if v.is_object() => v,
        _ => return error("input has no self record"),
    };
    let repeat = str_field(this, "repeat").map(str::trim).unwrap_or_default();
    if repeat.is_empty() {
        return error("not a repeating event");
    }
    let Some(at_text) = input.get("args").and_then(|a| a.get("at")).and_then(Value::as_str) else {
        return error("args.at (datetime) is required");
    };
    let Some(at) = parse_dt(at_text) else {
        return error("args.at is not a datetime");
    };
    let starts = str_field(this, "starts").and_then(parse_dt);
    let ends = str_field(this, "ends").and_then(parse_dt);
    let length = match (starts, ends) {
        (Some(s), Some(e)) => Some(e - s),
        _ => None,
    };
    let Some(target) = str_field(input, "target") else {
        return error("input has no target");
    };
    let Some(parent) = target_path(input) else {
        return error("input has no target path");
    };
    let mut exdates: Vec<String> = field(this, "exdates")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let at_text = fmt_dt(at);
    if !exdates.contains(&at_text) {
        exdates.push(at_text.clone());
    }
    // The detached sibling: every field of the series except identity / recurrence, moved to `at`.
    let mut sibling = Map::new();
    if let Some(obj) = this.as_object() {
        for (k, v) in obj {
            if matches!(k.as_str(), "id" | "repeat" | "exdates" | "starts" | "ends" | "items" | "parent" | "ref") {
                continue;
            }
            sibling.insert(k.clone(), v.clone());
        }
    }
    sibling.insert("starts".into(), Value::String(at_text.clone()));
    if let Some(len) = length {
        sibling.insert("ends".into(), Value::String(fmt_dt(at + len)));
    }
    if let Some(id) = field(input, "ids").and_then(Value::as_array).and_then(|a| a.first()).and_then(Value::as_str) {
        sibling.insert("id".into(), Value::String(id.to_string()));
    }
    json!({ "effects": [
        { "set": { "target": target, "field": "exdates", "value": exdates } },
        { "create": { "parent": parent, "record": Value::Object(sibling) } }
    ] })
}

fn shift_series(input: &Value) -> Value {
    let this = match field(input, "self") {
        Some(v) if v.is_object() => v,
        _ => return error("input has no self record"),
    };
    let Some(by_text) = input.get("args").and_then(|a| a.get("by")).and_then(Value::as_str) else {
        return error("args.by (duration) is required");
    };
    let Some(by) = parse_duration(by_text) else {
        return error("args.by is not a duration (30m / 2h / 1d / 7d / 2w, optional leading -)");
    };
    let Some(target) = str_field(input, "target") else {
        return error("input has no target");
    };
    let Some(starts) = str_field(this, "starts").and_then(parse_dt) else {
        return error("self has no starts");
    };
    let mut effects = vec![json!({ "set": { "target": target, "field": "starts", "value": fmt_dt(starts + by) } })];
    if let Some(ends) = str_field(this, "ends").and_then(parse_dt) {
        effects.push(json!({ "set": { "target": target, "field": "ends", "value": fmt_dt(ends + by) } }));
    }
    if let Some(ex) = field(this, "exdates").and_then(Value::as_array) {
        let shifted: Vec<Value> = ex
            .iter()
            .filter_map(|v| v.as_str().and_then(parse_dt))
            .map(|d| Value::String(fmt_dt(d + by)))
            .collect();
        effects.push(json!({ "set": { "target": target, "field": "exdates", "value": shifted } }));
    }
    json!({ "effects": effects })
}

//! MODULE-020-AC-14 / T14 — backward-compat gate over CONTRACT-192 response shape.
//!
//! Inventory + parent-oracle checker. Not a second contract stack: consumes
//! [`generate_schema_artifact`] and [`API_VERSION`]. Additive fields stay legal;
//! a drop/rename/required-loosening/closed-enum add requires a strict
//! `api_version` calendar increment **and** covering migration notes.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::process::Command;

use chrono::{Datelike, NaiveDate};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::envelope::API_VERSION;
use crate::schema::{canonical_json, generate_schema_artifact, schema_dir};

/// Response components that are inventoried (a field bag, enum, or tagged union).
pub const RESPONSE_COMPONENTS: &[&str] = &[
    "ClientEnvelope",
    "ClientError",
    "ClientWarning",
    "ClientRunSummary",
    "ClientRunMutation",
    "ClientAgentTreeNode",
    "ClientMessageAck",
    "ClientMessageStatus",
    "ClientToolEntry",
    "ClientMcpEntry",
    "ClientSkillEntry",
    "ClientToolInventory",
    "ClientEvent",
    "ClientEventPage",
    "ClientEventCursor",
    "ClientEventPriority",
    "ClientScalar",
    "ClientGrantDecision",
    "ClientGrantRevokeResult",
    "ClientPresetApplyResult",
    "ClientPendingGrant",
    "ClientCapParam",
    "ClientGrantTtl",
    "ClientHistoryEntry",
    "ClientHistoryResponse",
    "LlmDeltaItem",
    "LlmDeltaUsage",
    "LlmDeltaTerminal",
    "LlmDeltaCursor",
    "LlmDeltaPage",
    "LlmDeltaWirePage",
    "SessionInfo",
    "Principal",
    "Platform",
    "Scope",
    "Cursor",
    "ClientErrorCode",
    "GenUiDocument",
    "ComponentNode",
    "CatalogEntry",
    "ActionRef",
    "ValidationOutcome",
    "GenUiError",
];

/// Request / filter bodies — not a response-field bag.
pub const EXCLUDED_COMPONENTS: &[&str] = &[
    "ClientSendMessageRequest",
    "ClientGrantApproveRequest",
    "ClientGrantDenyRequest",
    "ClientGrantNarrowRequest",
    "ClientGrantRevokeRequest",
    "ClientPresetApplyRequest",
    "ClientEventsRequest",
    "ClientEventStreamRequest",
    "ClientEventFilter",
    "LlmDeltaStreamRequest",
];

/// Git path of the on-disk honesty baseline, relative to the repo root.
/// Must stay a canonical path (no `.` / `..` / `//`). The frozen probe below
/// uses a **separate** copy of this string so retargeting `BASELINE_REL` cannot
/// also retarget “does this blob exist on the parent commit?”.
pub const BASELINE_REL: &str = "crates/client-api/sdk-artifacts/schema/compat-baseline.json";
const FROZEN_BASELINE_REL: &str = "crates/client-api/sdk-artifacts/schema/compat-baseline.json";
const MAX_INVENTORY_LEAVES: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldMeta {
    #[serde(rename = "type")]
    pub type_token: String,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatSnapshot {
    pub api_version: String,
    pub fields: BTreeMap<String, BTreeMap<String, FieldMeta>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatMigration {
    pub from: String,
    pub to: String,
    pub removed: Vec<String>,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatMigrationsFile {
    pub migrations: Vec<CompatMigration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompatError {
    FieldDroppedSameVersion { fields: Vec<String> },
    FieldDroppedWithoutNotes { fields: Vec<String> },
    Inventory(String),
    Baseline(String),
    Parent(String),
    Io(String),
    Version(String),
}

impl fmt::Display for CompatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompatError::FieldDroppedSameVersion { fields } => write!(
                f,
                "response field(s) dropped without api_version increment: {}",
                fields.join(", ")
            ),
            CompatError::FieldDroppedWithoutNotes { fields } => write!(
                f,
                "response field(s) dropped without covering migration notes: {}",
                fields.join(", ")
            ),
            CompatError::Inventory(m) => write!(f, "compat inventory: {m}"),
            CompatError::Baseline(m) => write!(f, "compat baseline: {m}"),
            CompatError::Parent(m) => write!(f, "compat parent: {m}"),
            CompatError::Io(m) => write!(f, "compat io: {m}"),
            CompatError::Version(m) => write!(f, "compat version: {m}"),
        }
    }
}

impl std::error::Error for CompatError {}

#[derive(Debug, Clone)]
pub struct GitShowOutput {
    pub stdout: Vec<u8>,
    pub stderr: String,
    pub status_code: i32,
}

/// Live inventory of the generated CONTRACT-192 schema at [`API_VERSION`].
pub fn live_snapshot() -> Result<CompatSnapshot, CompatError> {
    let art = generate_schema_artifact();
    let fields = response_field_inventory(&art.schema)?;
    Ok(CompatSnapshot {
        api_version: API_VERSION.to_string(),
        fields,
    })
}

/// Canonical JSON of [`live_snapshot`] (local honesty file bytes).
pub fn live_baseline_json() -> Result<String, CompatError> {
    let snap = live_snapshot()?;
    let v = serde_json::to_value(&snap)
        .map_err(|e| CompatError::Inventory(format!("snapshot serialize: {e}")))?;
    Ok(canonical_json(&v))
}

pub fn response_field_inventory(
    schema: &Value,
) -> Result<BTreeMap<String, BTreeMap<String, FieldMeta>>, CompatError> {
    let components = schema
        .get("components")
        .and_then(Value::as_object)
        .ok_or_else(|| CompatError::Inventory("schema has no components object".into()))?;
    let live_keys: BTreeSet<String> = components.keys().cloned().collect();
    let response: BTreeSet<&str> = RESPONSE_COMPONENTS.iter().copied().collect();
    let excluded: BTreeSet<&str> = EXCLUDED_COMPONENTS.iter().copied().collect();
    if !response.is_disjoint(&excluded) {
        return Err(CompatError::Inventory(
            "RESPONSE and EXCLUDED lists overlap".into(),
        ));
    }
    let listed: BTreeSet<String> = response
        .iter()
        .chain(excluded.iter())
        .map(|s| (*s).to_string())
        .collect();
    if listed != live_keys {
        let missing: Vec<_> = live_keys.difference(&listed).cloned().collect();
        let extra: Vec<_> = listed.difference(&live_keys).cloned().collect();
        return Err(CompatError::Inventory(format!(
            "RESPONSE ∪ EXCLUDED is not a partition of components (missing {missing:?}, extra {extra:?})"
        )));
    }

    let all_components = live_keys;
    let mut out = BTreeMap::new();
    for name in RESPONSE_COMPONENTS {
        let node = components
            .get(*name)
            .ok_or_else(|| CompatError::Inventory(format!("RESPONSE component {name} missing")))?;
        let mut ctx = WalkCtx {
            component: name,
            root: node,
            all_components: &all_components,
            stack: vec![(name.to_string(), "#".to_string())],
            fields: BTreeMap::new(),
        };
        walk_node(&mut ctx, node, "")?;
        out.insert((*name).to_string(), ctx.fields);
    }
    let leaves: usize = out.values().map(BTreeMap::len).sum();
    if leaves >= MAX_INVENTORY_LEAVES {
        return Err(CompatError::Inventory(format!(
            "inventory has {leaves} leaves (cap {MAX_INVENTORY_LEAVES})"
        )));
    }
    Ok(out)
}

struct WalkCtx<'a> {
    component: &'a str,
    root: &'a Value,
    all_components: &'a BTreeSet<String>,
    stack: Vec<(String, String)>,
    fields: BTreeMap<String, FieldMeta>,
}

fn walk_node(ctx: &mut WalkCtx<'_>, node: &Value, path: &str) -> Result<(), CompatError> {
    match node {
        Value::Bool(_) | Value::Null | Value::Number(_) | Value::String(_) | Value::Array(_) => {
            Ok(())
        }
        Value::Object(map) => {
            if let Some(r) = map.get("$ref").and_then(Value::as_str) {
                return walk_ref(ctx, r, path);
            }
            if let Some(inner) = fold_nullable(node) {
                return walk_node(ctx, inner, path);
            }
            if let Some(arms) = union_arms(node) {
                if is_tagged_union(arms) {
                    return walk_tagged_union(ctx, arms, path);
                }
            }
            if let Some(props) = map.get("properties").and_then(Value::as_object) {
                let required = required_set(map.get("required"));
                for (k, v) in props {
                    let fname = join_path(path, k);
                    ctx.fields.insert(
                        fname.clone(),
                        FieldMeta {
                            type_token: token(v, ctx.component),
                            required: required.contains(k.as_str()),
                        },
                    );
                    walk_node(ctx, v, &fname)?;
                }
            }
            if let Some(items) = map.get("items") {
                if !is_ref_node(items) && is_object_schema(items) {
                    let item_path = if path.is_empty() {
                        "[]".to_string()
                    } else {
                        format!("{path}[]")
                    };
                    walk_node(ctx, items, &item_path)?;
                }
            }
            if let Some(arms) = union_arms(node) {
                if is_constraint_only_union(arms, &ctx.fields, path) {
                    return Ok(());
                }
                if arms.iter().all(is_type_union_arm) {
                    for arm in arms {
                        let key =
                            join_path(path, &format!("variant:{}", token(arm, ctx.component)));
                        ctx.fields.insert(
                            key,
                            FieldMeta {
                                type_token: token(arm, ctx.component),
                                required: false,
                            },
                        );
                    }
                    return Ok(());
                }
                for arm in arms {
                    walk_node(ctx, arm, path)?;
                }
                return Ok(());
            }
            record_enum_consts(ctx, node, path);
            Ok(())
        }
    }
}

fn walk_ref(ctx: &mut WalkCtx<'_>, r: &str, path: &str) -> Result<(), CompatError> {
    let target = parse_ref(r)?;
    match target {
        RefTarget::Root => {
            let rid = "#";
            if stack_has(&ctx.stack, ctx.component, rid) {
                return Ok(());
            }
            ctx.stack.push((ctx.component.to_string(), rid.to_string()));
            let root = ctx.root.clone();
            let res = walk_node(ctx, &root, path);
            ctx.stack.pop();
            res
        }
        RefTarget::Defs(name) => {
            if ctx.all_components.contains(name) {
                return Ok(());
            }
            let rid = format!("$defs/{name}");
            if stack_has(&ctx.stack, ctx.component, &rid) {
                return Ok(());
            }
            let resolved = ctx
                .root
                .get("$defs")
                .and_then(Value::as_object)
                .and_then(|d| d.get(name))
                .cloned()
                .ok_or_else(|| {
                    CompatError::Inventory(format!(
                        "unknown $ref {r} in component {}",
                        ctx.component
                    ))
                })?;
            ctx.stack.push((ctx.component.to_string(), rid));
            let res = walk_node(ctx, &resolved, path);
            ctx.stack.pop();
            res
        }
        RefTarget::Component(_name) => Ok(()),
    }
}

fn walk_tagged_union(ctx: &mut WalkCtx<'_>, arms: &[Value], path: &str) -> Result<(), CompatError> {
    for arm in arms {
        let disc = disc_const(arm).ok_or_else(|| {
            CompatError::Inventory(format!(
                "tagged union arm missing discriminator in {}",
                ctx.component
            ))
        })?;
        let variant_key = join_path(path, &format!("variant:{disc}"));
        ctx.fields.insert(
            variant_key.clone(),
            FieldMeta {
                type_token: format!("const<{disc}>"),
                required: true,
            },
        );
        let Some(props) = arm.get("properties").and_then(Value::as_object) else {
            continue;
        };
        let required = required_set(arm.get("required"));
        for (k, v) in props {
            let fname = format!("{variant_key}.{k}");
            ctx.fields.insert(
                fname.clone(),
                FieldMeta {
                    type_token: token(v, ctx.component),
                    required: required.contains(k.as_str()),
                },
            );
            walk_node(ctx, v, &fname)?;
        }
    }
    Ok(())
}

fn record_enum_consts(ctx: &mut WalkCtx<'_>, node: &Value, path: &str) {
    if let Some(arr) = node.get("enum").and_then(Value::as_array) {
        for v in arr {
            if let Some(s) = const_to_string(v) {
                if ctx.component == "ClientErrorCode" && s == "unknown" {
                    continue;
                }
                let key = enum_field_key(path, &s);
                ctx.fields.insert(
                    key,
                    FieldMeta {
                        type_token: format!("const<{s}>"),
                        required: false,
                    },
                );
            }
        }
    }
    if let Some(c) = node.get("const") {
        if let Some(s) = const_to_string(c) {
            if ctx.component == "ClientErrorCode" && s == "unknown" {
                return;
            }
            let key = enum_field_key(path, &s);
            ctx.fields.insert(
                key,
                FieldMeta {
                    type_token: format!("const<{s}>"),
                    required: false,
                },
            );
        }
    }
}

fn enum_field_key(path: &str, value: &str) -> String {
    if path.is_empty() {
        value.to_string()
    } else {
        format!("{path}:{value}")
    }
}

enum RefTarget<'a> {
    Root,
    Defs(&'a str),
    Component(&'a str),
}

fn parse_ref(r: &str) -> Result<RefTarget<'_>, CompatError> {
    if r == "#" {
        return Ok(RefTarget::Root);
    }
    if let Some(name) = r.strip_prefix("#/$defs/") {
        if name.is_empty() || name.contains('/') {
            return Err(CompatError::Inventory(format!("unsupported $ref {r}")));
        }
        return Ok(RefTarget::Defs(name));
    }
    if let Some(name) = r.strip_prefix("#/components/") {
        if name.is_empty() || name.contains('/') {
            return Err(CompatError::Inventory(format!("unsupported $ref {r}")));
        }
        return Ok(RefTarget::Component(name));
    }
    Err(CompatError::Inventory(format!("unknown $ref {r}")))
}

fn stack_has(stack: &[(String, String)], component: &str, rid: &str) -> bool {
    stack
        .iter()
        .any(|(c, r)| c == component && r.as_str() == rid)
}

fn join_path(path: &str, k: &str) -> String {
    if path.is_empty() {
        k.to_string()
    } else {
        format!("{path}.{k}")
    }
}

fn required_set(v: Option<&Value>) -> BTreeSet<&str> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn is_ref_node(v: &Value) -> bool {
    v.get("$ref").and_then(Value::as_str).is_some()
}

fn is_object_schema(v: &Value) -> bool {
    v.get("type").and_then(Value::as_str) == Some("object") || v.get("properties").is_some()
}

fn union_arms(node: &Value) -> Option<&[Value]> {
    node.get("anyOf")
        .or_else(|| node.get("oneOf"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
}

fn fold_nullable(node: &Value) -> Option<&Value> {
    if let Some(arr) = node.get("type").and_then(Value::as_array) {
        let types: Vec<&str> = arr.iter().filter_map(Value::as_str).collect();
        if types.iter().filter(|t| **t == "null").count() == 1
            && types.iter().filter(|t| **t != "null").count() == 1
        {
            // token() handles type:[T,null]; walker still needs to descend the same node
            // after stripping null from consideration — there is no separate inner Value.
            return None;
        }
    }
    let arms = union_arms(node)?;
    nullable_non_null_arm(arms)
}

fn nullable_non_null_arm(arms: &[Value]) -> Option<&Value> {
    if arms.len() != 2 {
        return None;
    }
    let mut null_i = None;
    let mut other_i = None;
    for (i, arm) in arms.iter().enumerate() {
        if is_null_schema(arm) {
            null_i = Some(i);
        } else {
            other_i = Some(i);
        }
    }
    if null_i.is_some() {
        other_i.map(|i| &arms[i])
    } else {
        None
    }
}

fn is_null_schema(v: &Value) -> bool {
    v.get("type").and_then(Value::as_str) == Some("null")
}

fn is_tagged_union(arms: &[Value]) -> bool {
    !arms.is_empty()
        && arms.iter().all(|a| {
            a.get("type").and_then(Value::as_str) == Some("object") && disc_const(a).is_some()
        })
}

fn disc_const(arm: &Value) -> Option<String> {
    let props = arm.get("properties")?.as_object()?;
    for key in ["code", "kind", "outcome", "variant"] {
        if let Some(c) = props.get(key).and_then(|p| p.get("const")) {
            return const_to_string(c);
        }
    }
    None
}

fn is_constraint_only_union(
    arms: &[Value],
    existing: &BTreeMap<String, FieldMeta>,
    path: &str,
) -> bool {
    let mut saw_props = false;
    for arm in arms {
        let Some(props) = arm.get("properties").and_then(Value::as_object) else {
            continue;
        };
        saw_props = true;
        for k in props.keys() {
            let fname = join_path(path, k);
            if !existing.contains_key(&fname) {
                return false;
            }
        }
    }
    saw_props
}

fn is_type_union_arm(v: &Value) -> bool {
    v.get("properties").is_none()
        && v.get("enum").is_none()
        && v.get("const").is_none()
        && v.get("oneOf").is_none()
        && v.get("anyOf").is_none()
        && (v.get("type").is_some() || v.get("$ref").is_some())
}

fn const_to_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null => Some("null".into()),
        _ => None,
    }
}

pub fn token(schema: &Value, current_component: &str) -> String {
    match schema {
        Value::Bool(true) => "any".into(),
        Value::Bool(false) => "never".into(),
        Value::Null => "null".into(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        Value::Array(_) => "any".into(),
        Value::Object(map) => {
            if let Some(r) = map.get("$ref").and_then(Value::as_str) {
                return token_ref(r, current_component);
            }
            if let Some(arr) = map.get("type").and_then(Value::as_array) {
                let types: Vec<&str> = arr.iter().filter_map(Value::as_str).collect();
                let nulls = types.iter().filter(|t| **t == "null").count();
                let non_null: Vec<&str> = types.into_iter().filter(|t| *t != "null").collect();
                if nulls == 1 && non_null.len() == 1 {
                    let mut copy = schema.clone();
                    copy["type"] = Value::String(non_null[0].to_string());
                    return format!("opt<{}>", token(&copy, current_component));
                }
                if !non_null.is_empty() {
                    let mut sorted = non_null;
                    sorted.sort_unstable();
                    let inner = format!("union<{}>", sorted.join(","));
                    return if nulls > 0 {
                        format!("opt<{inner}>")
                    } else {
                        inner
                    };
                }
            }
            if let Some(arms) = union_arms(schema) {
                if let Some(inner) = nullable_non_null_arm(arms) {
                    return format!("opt<{}>", token(inner, current_component));
                }
            }
            if map.get("not").is_some()
                && map.get("type").is_none()
                && map.get("properties").is_none()
                && map.get("$ref").is_none()
                && map.get("anyOf").is_none()
                && map.get("oneOf").is_none()
                && map.get("enum").is_none()
                && map.get("const").is_none()
            {
                return "not".into();
            }
            if let Some(c) = map.get("const") {
                if let Some(s) = const_to_string(c) {
                    return format!("const<{s}>");
                }
            }
            if let Some(en) = map.get("enum").and_then(Value::as_array) {
                let mut vals: Vec<String> = en.iter().filter_map(const_to_string).collect();
                vals.sort();
                return format!("enum<{}>", vals.join(","));
            }
            if let Some(ts) = map.get("type").and_then(Value::as_str) {
                return typed_token(ts, schema, current_component);
            }
            if let Some(arms) = union_arms(schema) {
                let mut toks: Vec<String> =
                    arms.iter().map(|a| token(a, current_component)).collect();
                toks.sort();
                return format!("union<{}>", toks.join(","));
            }
            "any".into()
        }
    }
}

fn token_ref(r: &str, current: &str) -> String {
    if r == "#" {
        return format!("ref:{current}");
    }
    if let Some(name) = r.strip_prefix("#/$defs/") {
        return format!("ref:{name}");
    }
    if let Some(name) = r.strip_prefix("#/components/") {
        return format!("ref:{name}");
    }
    format!("ref:{r}")
}

fn typed_token(ts: &str, schema: &Value, current: &str) -> String {
    let mut base = match ts {
        "array" => {
            let items = schema.get("items").unwrap_or(&Value::Bool(true));
            format!("array<{}>", token(items, current))
        }
        "object" => {
            if schema.get("properties").is_none() {
                if let Some(ap) = schema.get("additionalProperties") {
                    format!("map<{}>", token(ap, current))
                } else {
                    "object".into()
                }
            } else {
                "object".into()
            }
        }
        other => other.to_string(),
    };
    if ts != "array" && !base.starts_with("array<") && !base.starts_with("map<") {
        if let Some(fmt) = schema.get("format").and_then(Value::as_str) {
            base.push('+');
            base.push_str(fmt);
        }
    }
    append_constraints(&mut base, schema);
    base
}

fn append_constraints(base: &mut String, schema: &Value) {
    let push = |parts: &mut Vec<(String, String)>, json_key: &str, short: &str| {
        if let Some(v) = schema.get(json_key) {
            let rendered = match v {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                other => other.to_string(),
            };
            parts.push((short.to_string(), rendered));
        }
    };
    let mut tmp = Vec::new();
    push(&mut tmp, "maximum", "max");
    push(&mut tmp, "maxItems", "maxItems");
    push(&mut tmp, "maxLength", "maxLength");
    push(&mut tmp, "minimum", "min");
    push(&mut tmp, "minItems", "minItems");
    push(&mut tmp, "minLength", "minLength");
    push(&mut tmp, "pattern", "pattern");
    tmp.sort_by(|a, b| a.0.cmp(&b.0));
    for (k, v) in tmp {
        base.push('+');
        base.push_str(&k);
        base.push_str(&v);
    }
}

pub fn parse_yyyy_mm_dd(s: &str) -> Result<(i32, u32, u32), CompatError> {
    if s.len() != 10
        || !s.as_bytes().iter().enumerate().all(|(i, b)| {
            if i == 4 || i == 7 {
                *b == b'-'
            } else {
                b.is_ascii_digit()
            }
        })
    {
        return Err(CompatError::Version(format!(
            "api_version {s:?} is not YYYY-MM-DD"
        )));
    }
    let d = NaiveDate::parse_from_str(s, "%Y-%m-%d").map_err(|_| {
        CompatError::Version(format!("api_version {s:?} is not a real calendar date"))
    })?;
    Ok((d.year(), d.month(), d.day()))
}

fn parse_ord(s: &str) -> Result<i32, CompatError> {
    let (y, m, d) = parse_yyyy_mm_dd(s)?;
    Ok(y * 400 + (m as i32) * 32 + d as i32)
}

/// Parent SHA for a PR (`head != main`) or a push that is testing main (`head == main`).
/// Never returns `head` (the commit under test). A `before` that equals `head` is
/// `Err`, not a first-land skip — fail closed.
pub fn resolve_parent_spec(
    head: &str,
    main: Option<&str>,
    before: Option<&str>,
    file_at_main: bool,
    file_at_before: bool,
) -> Result<Option<String>, CompatError> {
    let before = normalize_parent_sha(before);
    let chosen = match main {
        Some(main_sha) if !head.eq_ignore_ascii_case(main_sha) => {
            if file_at_main {
                Some(main_sha.to_string())
            } else {
                None
            }
        }
        Some(_) => {
            if file_at_before {
                before.map(str::to_string)
            } else {
                None
            }
        }
        None => {
            if file_at_before {
                before.map(str::to_string)
            } else {
                None
            }
        }
    };
    match chosen {
        Some(sha) if sha.eq_ignore_ascii_case(head) => Err(CompatError::Parent(
            "parent SHA must not be the commit under test (HEAD)".into(),
        )),
        other => Ok(other),
    }
}

/// GitHub merge checkout: `head_is_merge` means HEAD^2 exists; `first_parent` is HEAD^1.
/// `Some` → use that SHA (blob present). `None` → caller must try other oracles
/// (`origin/main` / `before`), not treat this as a first-land skip of the whole gate.
pub fn prefer_merge_first_parent(
    head: &str,
    head_is_merge: bool,
    first_parent: Option<&str>,
    file_at_first: bool,
) -> Result<Option<String>, CompatError> {
    if !head_is_merge {
        return Ok(None);
    }
    let Some(first) = first_parent else {
        return Ok(None);
    };
    if first.eq_ignore_ascii_case(head) {
        return Err(CompatError::Parent(
            "merge first parent must not be HEAD".into(),
        ));
    }
    if file_at_first {
        Ok(Some(first.to_string()))
    } else {
        Ok(None)
    }
}

pub fn normalize_parent_sha(raw: Option<&str>) -> Option<&str> {
    parse_compat_parent_sha(raw).ok().flatten()
}

/// Empty / all-zero → unset. Non-hex (including `HEAD`) → error (fail-closed).
pub fn parse_compat_parent_sha(raw: Option<&str>) -> Result<Option<&str>, CompatError> {
    match raw.map(str::trim) {
        None | Some("") => Ok(None),
        Some(s) if is_zero_sha(s) => Ok(None),
        Some(s) if is_hex_sha(s) => Ok(Some(s)),
        Some(s) => Err(CompatError::Parent(format!(
            "COMPAT_PARENT_SHA {s:?} is not a hex SHA-1/SHA-256"
        ))),
    }
}

fn is_hex_sha(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_zero_sha(s: &str) -> bool {
    is_hex_sha(s) && s.bytes().all(|b| b == b'0')
}

pub fn classify_git_show(output: &GitShowOutput) -> Result<Option<CompatSnapshot>, CompatError> {
    if output.status_code == 0 {
        let text = std::str::from_utf8(&output.stdout)
            .map_err(|e| CompatError::Parent(format!("git show stdout is not utf-8: {e}")))?;
        let snap: CompatSnapshot = serde_json::from_str(text.trim()).map_err(|e| {
            CompatError::Parent(format!("git show produced unparseable baseline: {e}"))
        })?;
        return Ok(Some(snap));
    }
    if is_path_absent(&output.stderr) {
        return Ok(None);
    }
    Err(CompatError::Parent(format!(
        "git show failed (status {}): {}",
        output.status_code,
        output.stderr.trim()
    )))
}

fn is_path_absent(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    (s.contains("path") && s.contains("does not exist")) || s.contains("exists on disk, but not in")
}

/// `true` when `path` is a repo-relative git path with no empty / `.` / `..` components.
pub fn git_path_is_canonical(path: &str) -> bool {
    if path.is_empty() || path.starts_with('/') || path.ends_with('/') {
        return false;
    }
    let mut parts = 0usize;
    for c in path.split('/') {
        if c.is_empty() || c == "." || c == ".." {
            return false;
        }
        parts += 1;
    }
    parts >= 2
}

fn require_canonical_baseline_rel() -> Result<(), CompatError> {
    if !git_path_is_canonical(BASELINE_REL) || BASELINE_REL != FROZEN_BASELINE_REL {
        return Err(CompatError::Parent(format!(
            "BASELINE_REL {BASELINE_REL:?} must equal the frozen canonical path {FROZEN_BASELINE_REL:?}"
        )));
    }
    Ok(())
}

/// Combine `git show` classification with an independent frozen-path existence probe.
/// Path-absent is first-land `None` only when the frozen blob is also absent.
pub fn interpret_git_show(
    output: &GitShowOutput,
    frozen_blob_exists: bool,
) -> Result<Option<CompatSnapshot>, CompatError> {
    match classify_git_show(output)? {
        None if frozen_blob_exists => Err(CompatError::Parent(
            "git show reported path-absent but the frozen baseline exists on the parent commit"
                .into(),
        )),
        other => Ok(other),
    }
}

/// Classify `git cat-file -e` on `{sha}:{frozen path}` after the SHA is known to
/// be a commit. `0` → exists. Path-absent stderr → missing. Exit `1` / signal /
/// other failures are `Err` (not a first-land skip): missing path on a real
/// commit is git's path-absent 128 text, not POSIX `cat-file -e` exit 1.
pub fn classify_cat_file_exists(status_code: i32, stderr: &str) -> Result<bool, CompatError> {
    if status_code == 0 {
        return Ok(true);
    }
    if is_path_absent(stderr) {
        return Ok(false);
    }
    Err(CompatError::Parent(format!(
        "git cat-file -e failed (status {status_code}): {}",
        stderr.trim()
    )))
}

pub fn parent_baseline() -> Result<Option<CompatSnapshot>, CompatError> {
    require_canonical_baseline_rel()?;
    let env_sha = match std::env::var("COMPAT_PARENT_SHA") {
        Ok(raw) => parse_compat_parent_sha(Some(raw.as_str()))?.map(str::to_string),
        Err(_) => None,
    };
    if env_sha.is_some() && !git_available() {
        return Err(CompatError::Parent(
            "COMPAT_PARENT_SHA is set but git is unavailable".into(),
        ));
    }
    if !git_available() {
        return Ok(None);
    }
    let head = git_rev_parse("HEAD")?;
    // GitHub `pull_request` checkout is `refs/pull/*/merge`: HEAD^1 is the trusted
    // base SHA (not a mutable `origin/main` ref, not COMPAT_PARENT_SHA). Prefer it
    // so a PR cannot poison `refs/remotes/origin/main` or retarget the env SHA.
    if git_rev_parse("HEAD^2").is_ok() {
        if let Ok(first) = git_rev_parse("HEAD^1") {
            match prefer_merge_first_parent(
                &head,
                true,
                Some(&first),
                frozen_baseline_exists_at(&first)?,
            )? {
                Some(sha) => return git_show_baseline(&sha),
                None => {}
            }
        }
    }
    let main_ref = git_rev_parse("origin/main")
        .ok()
        .or_else(|| git_rev_parse("main").ok());
    // Env SHA is `before` for a push-to-main. It must not replace origin/main on a
    // PR (COMPAT_PARENT_SHA retarget). It MAY fill `main` when no main ref resolved
    // (CI `base.sha` fallback if fetch-depth is later reduced).
    let main = main_ref.or_else(|| env_sha.clone().filter(|s| !s.eq_ignore_ascii_case(&head)));
    let before = env_sha.or_else(|| git_rev_parse("HEAD^").ok());
    let file_at_main = match &main {
        Some(m) => frozen_baseline_exists_at(m)?,
        None => false,
    };
    let file_at_before = match &before {
        Some(b) => frozen_baseline_exists_at(b)?,
        None => false,
    };
    let parent = resolve_parent_spec(
        &head,
        main.as_deref(),
        before.as_deref(),
        file_at_main,
        file_at_before,
    )?;
    match parent {
        Some(sha) => git_show_baseline(&sha),
        None => Ok(None),
    }
}

fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn git_rev_parse(rev: &str) -> Result<String, CompatError> {
    let out = Command::new("git")
        .args(["rev-parse", rev])
        .current_dir(repo_root())
        .output()
        .map_err(|e| CompatError::Parent(format!("git rev-parse {rev}: {e}")))?;
    if !out.status.success() {
        return Err(CompatError::Parent(format!(
            "git rev-parse {rev} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn reject_self_parent(sha: &str) -> Result<(), CompatError> {
    if !git_available() {
        return Ok(());
    }
    if let Ok(head) = git_rev_parse("HEAD") {
        if sha.eq_ignore_ascii_case(&head) {
            return Err(CompatError::Parent(
                "parent SHA must not be the commit under test (HEAD)".into(),
            ));
        }
    }
    // GitHub `pull_request` checkout is `refs/pull/*/merge`: HEAD is the merge
    // commit, the PR tip is HEAD^2. Reject that tip so COMPAT_PARENT_SHA cannot
    // be retargeted at the PR's own rewritten baseline.
    if let Ok(tip) = git_rev_parse("HEAD^2") {
        if sha.eq_ignore_ascii_case(&tip) {
            let main = git_rev_parse("origin/main")
                .ok()
                .or_else(|| git_rev_parse("main").ok());
            let tip_is_main = main.as_deref().is_some_and(|m| sha.eq_ignore_ascii_case(m));
            if !tip_is_main {
                return Err(CompatError::Parent(
                    "parent SHA must not be the PR tip (HEAD^2)".into(),
                ));
            }
        }
    }
    Ok(())
}

/// Probe the **frozen** path, not `BASELINE_REL`, so a later edit of the git-show
/// path cannot also retarget existence.
fn frozen_baseline_exists_at(sha: &str) -> Result<bool, CompatError> {
    let kind = git_object_kind(sha)?;
    if kind != "commit" {
        return Err(CompatError::Parent(format!(
            "parent SHA {sha} is a {kind}, not a commit"
        )));
    }
    let spec = format!("{sha}:{FROZEN_BASELINE_REL}");
    let out = Command::new("git")
        .args(["cat-file", "-e", "--", &spec])
        .current_dir(repo_root())
        .output()
        .map_err(|e| CompatError::Parent(format!("git cat-file: {e}")))?;
    classify_cat_file_exists(
        out.status.code().unwrap_or(1),
        &String::from_utf8_lossy(&out.stderr),
    )
}

fn git_object_kind(sha: &str) -> Result<String, CompatError> {
    let out = Command::new("git")
        .args(["cat-file", "-t", sha])
        .current_dir(repo_root())
        .output()
        .map_err(|e| CompatError::Parent(format!("git cat-file -t: {e}")))?;
    if !out.status.success() {
        return Err(CompatError::Parent(format!(
            "parent SHA {sha} is not a git object"
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn git_show_baseline(sha: &str) -> Result<Option<CompatSnapshot>, CompatError> {
    require_canonical_baseline_rel()?;
    reject_self_parent(sha)?;
    let kind = git_object_kind(sha)?;
    if kind != "commit" {
        return Err(CompatError::Parent(format!(
            "parent SHA {sha} is a {kind}, not a commit"
        )));
    }
    let frozen_exists = frozen_baseline_exists_at(sha)?;
    let spec = format!("{sha}:{BASELINE_REL}");
    let out = Command::new("git")
        .args(["show", &spec])
        .current_dir(repo_root())
        .output()
        .map_err(|e| CompatError::Parent(format!("git show: {e}")))?;
    interpret_git_show(
        &GitShowOutput {
            stdout: out.stdout,
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            status_code: out.status.code().unwrap_or(1),
        },
        frozen_exists,
    )
}

fn repo_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

fn is_opt_tighten(prev: &str, curr: &str) -> bool {
    prev.strip_prefix("opt<")
        .and_then(|s| s.strip_suffix('>'))
        .is_some_and(|inner| inner == curr)
}

fn is_token_drop(prev: &str, curr: &str) -> bool {
    prev != curr && !is_opt_tighten(prev, curr)
}

fn flattened<'a>(comp: &'a str, field: &'a str) -> String {
    format!("{comp}.{field}")
}

pub fn is_closed_enum_leaf(component: &str, field: &str) -> bool {
    if component == "ClientErrorCode" {
        return false;
    }
    if let Some(rest) = field.strip_prefix("confirm.variant:") {
        return !rest.contains('.');
    }
    if let Some(rest) = field.strip_prefix("variant:") {
        return !rest.contains('.');
    }
    if matches!(component, "Platform" | "Scope" | "ClientEventPriority")
        && !field.contains('.')
        && !field.starts_with("variant:")
    {
        return true;
    }
    if component == "ClientScalar" && field.starts_with("variant:") {
        return true;
    }
    false
}

fn dropped_names(previous: &CompatSnapshot, current: &CompatSnapshot) -> Vec<String> {
    let mut dropped = BTreeSet::new();
    for (comp, fields) in &previous.fields {
        let curr_comp = current.fields.get(comp);
        for (name, meta) in fields {
            let key = flattened(comp, name);
            match curr_comp.and_then(|c| c.get(name)) {
                None => {
                    dropped.insert(key);
                }
                Some(cur) => {
                    if is_token_drop(&meta.type_token, &cur.type_token)
                        || (meta.required && !cur.required)
                    {
                        dropped.insert(key);
                    }
                }
            }
        }
    }
    for (comp, fields) in &current.fields {
        let prev_comp = previous.fields.get(comp);
        for name in fields.keys() {
            if prev_comp.and_then(|c| c.get(name)).is_none() && is_closed_enum_leaf(comp, name) {
                dropped.insert(flattened(comp, name));
            }
        }
    }
    dropped.into_iter().collect()
}

fn migration_covers(
    m: &CompatMigration,
    prev_ver: &str,
    curr_ver: &str,
    dropped: &[String],
) -> bool {
    m.from == prev_ver
        && m.to == curr_ver
        && !m.notes.trim().is_empty()
        && dropped.iter().all(|d| m.removed.iter().any(|r| r == d))
}

pub fn check_response_compat(
    previous: &CompatSnapshot,
    current: &CompatSnapshot,
    migrations: &[CompatMigration],
) -> Result<(), CompatError> {
    parse_yyyy_mm_dd(&previous.api_version)?;
    parse_yyyy_mm_dd(&current.api_version)?;
    let dropped = dropped_names(previous, current);
    let covering = migrations
        .iter()
        .any(|m| migration_covers(m, &previous.api_version, &current.api_version, &dropped));

    if dropped.is_empty() && current.api_version == previous.api_version {
        return Ok(());
    }
    if dropped.is_empty() && current.api_version != previous.api_version {
        let curr_ord = parse_ord(&current.api_version)?;
        let prev_ord = parse_ord(&previous.api_version)?;
        if curr_ord <= prev_ord {
            return Err(CompatError::Version(format!(
                "api_version {} is not a strict increment over {}",
                current.api_version, previous.api_version
            )));
        }
        return if covering {
            Ok(())
        } else {
            Err(CompatError::FieldDroppedWithoutNotes { fields: dropped })
        };
    }

    let curr_ord = parse_ord(&current.api_version)?;
    let prev_ord = parse_ord(&previous.api_version)?;
    if curr_ord <= prev_ord {
        return Err(CompatError::FieldDroppedSameVersion { fields: dropped });
    }
    if covering {
        Ok(())
    } else {
        Err(CompatError::FieldDroppedWithoutNotes { fields: dropped })
    }
}

pub fn enforce_compat_gate_at(
    artifact_dir: &Path,
    live: &CompatSnapshot,
    parent: Option<&CompatSnapshot>,
) -> Result<(), CompatError> {
    let baseline_path = artifact_dir.join("compat-baseline.json");
    let migrations_path = artifact_dir.join("compat-migrations.json");
    let baseline_raw = std::fs::read_to_string(&baseline_path).map_err(|e| {
        CompatError::Io(format!(
            "missing or unreadable {}: {e}",
            baseline_path.display()
        ))
    })?;
    let migrations_raw = std::fs::read_to_string(&migrations_path).map_err(|e| {
        CompatError::Io(format!(
            "missing or unreadable {}: {e}",
            migrations_path.display()
        ))
    })?;
    let local: CompatSnapshot = serde_json::from_str(&baseline_raw)
        .map_err(|e| CompatError::Baseline(format!("parse baseline: {e}")))?;
    let file: CompatMigrationsFile = serde_json::from_str(&migrations_raw)
        .map_err(|e| CompatError::Baseline(format!("parse migrations: {e}")))?;
    if local.api_version != live.api_version {
        return Err(CompatError::Baseline(format!(
            "local baseline api_version {} != live {}",
            local.api_version, live.api_version
        )));
    }
    if local.fields != live.fields {
        return Err(CompatError::Baseline(
            "local compat-baseline.json fields != live inventory".into(),
        ));
    }
    if let Some(p) = parent {
        check_response_compat(p, live, &file.migrations)?;
    }
    Ok(())
}

pub fn enforce_compat_gate() -> Result<(), CompatError> {
    let live = live_snapshot()?;
    if live.api_version != API_VERSION {
        return Err(CompatError::Version(format!(
            "live snapshot version {} != API_VERSION {API_VERSION}",
            live.api_version
        )));
    }
    parse_yyyy_mm_dd(&live.api_version)?;
    let parent = parent_baseline()?;
    enforce_compat_gate_at(&schema_dir(), &live, parent.as_ref())
}

#[cfg(test)]
mod write_artifacts {
    use super::*;

    #[test]
    #[ignore]
    fn write_compat_artifacts() {
        let baseline = live_baseline_json().expect("live baseline");
        let dir = schema_dir();
        std::fs::create_dir_all(&dir).expect("schema dir");
        std::fs::write(dir.join("compat-baseline.json"), baseline).expect("write baseline");
        std::fs::write(
            dir.join("compat-migrations.json"),
            crate::schema::canonical_json(&serde_json::json!({ "migrations": [] })),
        )
        .expect("write migrations");
    }
}

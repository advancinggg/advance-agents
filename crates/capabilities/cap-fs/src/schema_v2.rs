//! Meta-schema grammar v2: aspects, field
//! invariants (`transitions` / `derive` / `ensure` / `inherit`), named queries, views and
//! operation bindings, plus the closed expression language (`$now`, `$args.x`, `$self.x`,
//! literals, `± <duration>`).
//!
//! Two document shapes parse through [`parse_document`]:
//! - the workspace schema (`required` / `optional` / `aspects: {name: {…}}`), and
//! - a pack extension declaring ONE aspect at the top level (`aspect: name`, `key`, `fields`,
//!   `queries`, `views`, `operations`), optionally with a v1 `optional:` block.
//!
//! Aspect fields are namespaced under their aspect and validated for frontmatter records;
//! `optional` fields remain the `.meta.yaml` entry vocabulary. A field name shared by two
//! aspects must carry an identical spec (fields are a global vocabulary across aspects).
//! Unknown keys anywhere are rejected.

use std::collections::BTreeMap;

use advance_shared_types::entity::OrderKey;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::Deserialize;
use serde_yml::Value;
use sha2::{Digest, Sha256};

use crate::meta_schema::{AutoRule, FieldSpec, FieldType, MetaSchema, MetaSchemaError};

/// Comparison operator of `ensure` rules and `where` clauses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmp {
    Gt,
    Gte,
    Lt,
    Lte,
}

impl Cmp {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "gt" => Some(Self::Gt),
            "gte" => Some(Self::Gte),
            "lt" => Some(Self::Lt),
            "lte" => Some(Self::Lte),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gt => "gt",
            Self::Gte => "gte",
            Self::Lt => "lt",
            Self::Lte => "lte",
        }
    }
    /// Apply the comparison to two ordered values (`a OP b`).
    pub fn holds<T: PartialOrd>(self, a: &T, b: &T) -> bool {
        match self {
            Self::Gt => a > b,
            Self::Gte => a >= b,
            Self::Lt => a < b,
            Self::Lte => a <= b,
        }
    }
}

/// The closed expression language. `offset` is a `± <duration>` suffix.
#[derive(Debug, Clone, PartialEq)]
pub enum ValueExpr {
    Now {
        offset: Option<Duration>,
    },
    Arg {
        name: String,
        offset: Option<Duration>,
    },
    SelfField {
        name: String,
        offset: Option<Duration>,
    },
    Literal(Value),
}

/// What `derive` does when its `when` condition does not hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeriveElse {
    /// Remove the field.
    Unset,
    /// Leave whatever is there.
    Keep,
}

/// `derive: { when: {field: value, …}, value: <expr>, else: unset | keep }` — recomputed on
/// every write: when every `when` pair matches the record, the field is set to `value` if it
/// is absent; otherwise `else` applies.
#[derive(Debug, Clone, PartialEq)]
pub struct DeriveRule {
    pub when: BTreeMap<String, Value>,
    pub value: ValueExpr,
    pub else_: DeriveElse,
}

/// `ensure: { <op>: <sibling field> }` — the field must compare true against the sibling
/// whenever both are present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnsureRule {
    pub op: Cmp,
    pub field: String,
}

/// One `where` clause of a named query.
#[derive(Debug, Clone, PartialEq)]
pub enum WhereClause {
    Eq(Value),
    In(Vec<Value>),
    Cmp(Cmp, ValueExpr),
}

/// A named query: a parameterized `EntityQuery` template with pinned semantics.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct QuerySpec {
    pub args: BTreeMap<String, FieldType>,
    pub where_: BTreeMap<String, WhereClause>,
    pub due_between: Option<(ValueExpr, ValueExpr)>,
    pub occurs_between: Option<(ValueExpr, ValueExpr)>,
    pub any_between: Option<(ValueExpr, ValueExpr)>,
    pub order: Vec<OrderKey>,
}

/// The five view kinds every client renders (CONTRACT-192 vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewKind {
    List,
    Table,
    Board,
    Calendar,
    Form,
}

impl ViewKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "list" => Some(Self::List),
            "table" => Some(Self::Table),
            "board" => Some(Self::Board),
            "calendar" => Some(Self::Calendar),
            "form" => Some(Self::Form),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Table => "table",
            Self::Board => "board",
            Self::Calendar => "calendar",
            Self::Form => "form",
        }
    }
}

/// A declared view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewSpec {
    pub kind: ViewKind,
    pub query: Option<String>,
    pub group_by: Option<String>,
    pub columns: Vec<String>,
}

/// An operation binding: the skill tool (`skill::<tool>`) and method that compute the
/// operation's effect list. Logic lives in WASM; this is only the name binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationBinding {
    pub tool: String,
    pub method: String,
}

/// One aspect: the unit of ownership a pack declares.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AspectSpec {
    /// A record has the aspect iff ANY of these fields is present.
    pub key: Vec<String>,
    pub fields: BTreeMap<String, FieldSpec>,
    pub queries: BTreeMap<String, QuerySpec>,
    pub views: BTreeMap<String, ViewSpec>,
    pub operations: BTreeMap<String, OperationBinding>,
}

// ── YAML shapes ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct YamlDoc {
    #[serde(default)]
    required: BTreeMap<String, YamlField>,
    #[serde(default)]
    optional: BTreeMap<String, YamlField>,
    #[serde(default)]
    aspects: BTreeMap<String, YamlAspect>,
    // Single-aspect (pack extension) form.
    #[serde(default)]
    aspect: Option<String>,
    #[serde(default)]
    key: Option<Vec<String>>,
    #[serde(default)]
    fields: BTreeMap<String, YamlField>,
    #[serde(default)]
    queries: BTreeMap<String, YamlQuery>,
    #[serde(default)]
    views: BTreeMap<String, YamlView>,
    #[serde(default)]
    operations: BTreeMap<String, YamlOperation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct YamlAspect {
    key: Vec<String>,
    #[serde(default)]
    fields: BTreeMap<String, YamlField>,
    #[serde(default)]
    queries: BTreeMap<String, YamlQuery>,
    #[serde(default)]
    views: BTreeMap<String, YamlView>,
    #[serde(default)]
    operations: BTreeMap<String, YamlOperation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct YamlField {
    #[serde(rename = "type", default)]
    field_type: Option<Value>,
    #[serde(default)]
    auto: Option<String>,
    #[serde(default)]
    default: Option<Value>,
    #[serde(default)]
    transitions: Option<BTreeMap<String, Vec<String>>>,
    #[serde(default)]
    derive: Option<YamlDerive>,
    #[serde(default)]
    ensure: Option<BTreeMap<String, String>>,
    #[serde(default)]
    inherit: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct YamlDerive {
    when: BTreeMap<String, Value>,
    value: Value,
    #[serde(rename = "else", default)]
    else_: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct YamlQuery {
    #[serde(default)]
    args: BTreeMap<String, String>,
    #[serde(rename = "where", default)]
    where_: BTreeMap<String, Value>,
    #[serde(default)]
    due_between: Option<Vec<Value>>,
    #[serde(default)]
    occurs_between: Option<Vec<Value>>,
    #[serde(default)]
    any_between: Option<Vec<Value>>,
    #[serde(default)]
    order: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct YamlView {
    kind: String,
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    group_by: Option<String>,
    #[serde(default)]
    columns: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct YamlOperation {
    tool: String,
    method: String,
}

// ── parsing ─────────────────────────────────────────────────────────────────────────────────

fn err(msg: impl Into<String>) -> MetaSchemaError {
    MetaSchemaError::Validation(msg.into())
}

fn is_bare_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Parse a schema document (either shape, see the module docs).
pub fn parse_document(yaml: &str) -> Result<MetaSchema, MetaSchemaError> {
    if advance_shared_types::yaml_guard::yaml_has_alias_refs(yaml) {
        return Err(err("schema contains YAML alias references (`*name`)"));
    }
    if !advance_shared_types::yaml_guard::yaml_nesting_within_bound(yaml) {
        return Err(err("schema nesting is too deep"));
    }
    let doc: YamlDoc =
        serde_yml::from_str(yaml).map_err(|e| MetaSchemaError::Parse(format!("{e}")))?;

    let mut required: BTreeMap<String, FieldSpec> = BTreeMap::new();
    for (name, ys) in doc.required {
        check_field_name(&name)?;
        let auto = match ys.auto.as_deref() {
            Some("filename") => Some(AutoRule::Filename),
            Some("filename-to-slug") => Some(AutoRule::FilenameToSlug),
            Some("content-extract") => Some(AutoRule::ContentExtract),
            Some("entity-type-default") => Some(AutoRule::EntityTypeDefault),
            Some("ulid") => Some(AutoRule::Ulid),
            Some(other) => {
                return Err(err(format!(
                    "unknown auto-rule for required field {name}: {other}"
                )));
            }
            None => {
                return Err(err(format!(
                    "required field {name} has no auto-generation rule"
                )));
            }
        };
        let mut spec = parse_field(&name, &ys, false)?;
        spec.auto = auto;
        required.insert(name, spec);
    }

    let mut optional: BTreeMap<String, FieldSpec> = BTreeMap::new();
    for (name, ys) in doc.optional {
        check_field_name(&name)?;
        if ys.auto.is_some() {
            return Err(err(format!(
                "optional field {name}: auto rules are for required fields"
            )));
        }
        let spec = parse_field(&name, &ys, true)?;
        optional.insert(name, spec);
    }
    check_cross_refs("optional", &optional)?;

    let mut aspects: BTreeMap<String, AspectSpec> = BTreeMap::new();
    for (name, ya) in doc.aspects {
        check_aspect_name(&name)?;
        let spec = parse_aspect(&name, ya)?;
        aspects.insert(name, spec);
    }

    // Single-aspect form.
    let has_single_parts = doc.key.is_some()
        || !doc.fields.is_empty()
        || !doc.queries.is_empty()
        || !doc.views.is_empty()
        || !doc.operations.is_empty();
    match doc.aspect {
        Some(name) => {
            check_aspect_name(&name)?;
            let key = doc
                .key
                .ok_or_else(|| err(format!("aspect {name}: `key` is required")))?;
            if aspects.contains_key(&name) {
                return Err(err(format!("aspect {name} declared twice")));
            }
            let spec = parse_aspect(
                &name,
                YamlAspect {
                    key,
                    fields: doc.fields,
                    queries: doc.queries,
                    views: doc.views,
                    operations: doc.operations,
                },
            )?;
            aspects.insert(name, spec);
        }
        None if has_single_parts => {
            return Err(err(
                "`key` / `fields` / `queries` / `views` / `operations` need a top-level `aspect:`",
            ));
        }
        None => {}
    }

    // Cross-aspect: a shared field name must carry an identical spec.
    let mut seen: BTreeMap<&str, (&str, &FieldSpec)> = BTreeMap::new();
    for (aname, aspect) in &aspects {
        for (fname, fspec) in &aspect.fields {
            if let Some((other, ospec)) = seen.get(fname.as_str()) {
                if *ospec != fspec {
                    return Err(err(format!(
                        "field {fname} is declared differently by aspects {other} and {aname}"
                    )));
                }
            } else {
                seen.insert(fname, (aname, fspec));
            }
        }
    }

    Ok(MetaSchema {
        required,
        optional,
        aspects,
        description_max_chars: 500,
    })
}

fn check_field_name(name: &str) -> Result<(), MetaSchemaError> {
    if !is_bare_ident(name) {
        return Err(err(format!(
            "field name {name:?} must be a bare identifier (letters, digits, `_`, `-`; ≤ 64)"
        )));
    }
    if name == "items" {
        return Err(err("`items` is reserved for inline records"));
    }
    Ok(())
}

fn check_aspect_name(name: &str) -> Result<(), MetaSchemaError> {
    if !is_bare_ident(name) {
        return Err(err(format!(
            "aspect name {name:?} must be a bare identifier"
        )));
    }
    Ok(())
}

fn parse_field(
    name: &str,
    ys: &YamlField,
    default_allowed: bool,
) -> Result<FieldSpec, MetaSchemaError> {
    let field_type = crate::meta_schema::parse_field_type(&ys.field_type, name)?;
    let default = match &ys.default {
        Some(d) => {
            if !default_allowed {
                return Err(err(format!("required field {name} cannot carry a default")));
            }
            crate::meta_schema::validate_default_matches_type(name, &field_type, d)?;
            Some(d.clone())
        }
        None => None,
    };
    let transitions = match &ys.transitions {
        None => None,
        Some(t) => {
            let FieldType::EnumString(variants) = &field_type else {
                return Err(err(format!(
                    "field {name}: `transitions` is only valid on an enum field"
                )));
            };
            for (from, tos) in t {
                if !variants.contains(from) {
                    return Err(err(format!(
                        "field {name}: transition from undeclared variant {from:?}"
                    )));
                }
                for to in tos {
                    if !variants.contains(to) {
                        return Err(err(format!(
                            "field {name}: transition to undeclared variant {to:?}"
                        )));
                    }
                }
            }
            Some(t.clone())
        }
    };
    let derive = match &ys.derive {
        None => None,
        Some(d) => {
            if d.when.is_empty() {
                return Err(err(format!("field {name}: derive.when must not be empty")));
            }
            for k in d.when.keys() {
                check_field_name(k)?;
            }
            let value = parse_expr(&d.value, &BTreeMap::new(), true)
                .map_err(|m| err(format!("field {name}: derive.value: {m}")))?;
            if matches!(value, ValueExpr::Arg { .. }) {
                return Err(err(format!("field {name}: derive.value cannot use $args")));
            }
            let else_ = match d.else_.as_deref() {
                None | Some("unset") => DeriveElse::Unset,
                Some("keep") => DeriveElse::Keep,
                Some(other) => {
                    return Err(err(format!(
                        "field {name}: derive.else must be `unset` or `keep`, got {other:?}"
                    )));
                }
            };
            Some(DeriveRule {
                when: d.when.clone(),
                value,
                else_,
            })
        }
    };
    let ensure = match &ys.ensure {
        None => None,
        Some(e) => {
            if e.len() != 1 {
                return Err(err(format!(
                    "field {name}: `ensure` takes exactly one comparison"
                )));
            }
            let (op, field) = e.iter().next().expect("len == 1");
            let op = Cmp::parse(op).ok_or_else(|| {
                err(format!(
                    "field {name}: ensure operator must be gt / gte / lt / lte, got {op:?}"
                ))
            })?;
            check_field_name(field)?;
            if !matches!(field_type, FieldType::DateTime | FieldType::Integer) {
                return Err(err(format!(
                    "field {name}: `ensure` is only valid on datetime / integer fields"
                )));
            }
            Some(EnsureRule {
                op,
                field: field.clone(),
            })
        }
    };
    Ok(FieldSpec {
        field_type,
        auto: None,
        default,
        transitions,
        derive,
        ensure,
        inherit: ys.inherit.unwrap_or(false),
    })
}

fn parse_aspect(name: &str, ya: YamlAspect) -> Result<AspectSpec, MetaSchemaError> {
    if ya.key.is_empty() {
        return Err(err(format!(
            "aspect {name}: `key` must name at least one field"
        )));
    }
    let mut fields: BTreeMap<String, FieldSpec> = BTreeMap::new();
    for (fname, yf) in &ya.fields {
        check_field_name(fname)?;
        if yf.auto.is_some() {
            return Err(err(format!(
                "aspect {name}: field {fname}: auto rules are for required fields"
            )));
        }
        let spec = parse_field(fname, yf, true)?;
        fields.insert(fname.clone(), spec);
    }
    for k in &ya.key {
        if !fields.contains_key(k) {
            return Err(err(format!(
                "aspect {name}: key field {k:?} is not declared"
            )));
        }
    }
    check_cross_refs(&format!("aspect {name}"), &fields)?;

    let mut queries: BTreeMap<String, QuerySpec> = BTreeMap::new();
    for (qname, yq) in ya.queries {
        if !is_bare_ident(&qname) {
            return Err(err(format!(
                "aspect {name}: query name {qname:?} must be a bare identifier"
            )));
        }
        let mut args: BTreeMap<String, FieldType> = BTreeMap::new();
        for (aname, atype) in &yq.args {
            check_field_name(aname)?;
            let t = crate::meta_schema::parse_field_type(
                &Some(Value::String(atype.clone())),
                &format!("{qname}.args.{aname}"),
            )?;
            args.insert(aname.clone(), t);
        }
        let mut where_: BTreeMap<String, WhereClause> = BTreeMap::new();
        for (wfield, wval) in &yq.where_ {
            if !fields.contains_key(wfield) && !is_promoted_column(wfield) {
                return Err(err(format!(
                    "aspect {name}: query {qname}: where references undeclared field {wfield:?}"
                )));
            }
            let clause = match wval {
                Value::Sequence(items) => WhereClause::In(items.clone()),
                Value::Mapping(m) => {
                    if m.len() != 1 {
                        return Err(err(format!(
                            "aspect {name}: query {qname}: where.{wfield} takes exactly one operator"
                        )));
                    }
                    let (k, v) = m.iter().next().expect("len == 1");
                    let op = k.as_str().and_then(Cmp::parse).ok_or_else(|| {
                        err(format!(
                            "aspect {name}: query {qname}: where.{wfield}: unknown operator {k:?}"
                        ))
                    })?;
                    let expr = parse_expr(v, &args, false).map_err(|m| {
                        err(format!("aspect {name}: query {qname}: where.{wfield}: {m}"))
                    })?;
                    WhereClause::Cmp(op, expr)
                }
                other => WhereClause::Eq(other.clone()),
            };
            where_.insert(wfield.clone(), clause);
        }
        let window = |w: &Option<Vec<Value>>,
                      label: &str|
         -> Result<Option<(ValueExpr, ValueExpr)>, MetaSchemaError> {
            match w {
                None => Ok(None),
                Some(v) => {
                    if v.len() != 2 {
                        return Err(err(format!(
                            "aspect {name}: query {qname}: {label} must be [start, end]"
                        )));
                    }
                    let a = parse_expr(&v[0], &args, false).map_err(|m| {
                        err(format!("aspect {name}: query {qname}: {label}[0]: {m}"))
                    })?;
                    let b = parse_expr(&v[1], &args, false).map_err(|m| {
                        err(format!("aspect {name}: query {qname}: {label}[1]: {m}"))
                    })?;
                    Ok(Some((a, b)))
                }
            }
        };
        let due_between = window(&yq.due_between, "due_between")?;
        let occurs_between = window(&yq.occurs_between, "occurs_between")?;
        let any_between = window(&yq.any_between, "any_between")?;
        let mut order = Vec::new();
        for o in &yq.order {
            let mut parts = o.split_whitespace();
            let field = parts.next().unwrap_or_default().to_string();
            let dir = parts.next().unwrap_or("asc");
            if parts.next().is_some() {
                return Err(err(format!(
                    "aspect {name}: query {qname}: bad order entry {o:?}"
                )));
            }
            if !fields.contains_key(&field) && !is_promoted_column(&field) {
                return Err(err(format!(
                    "aspect {name}: query {qname}: order references undeclared field {field:?}"
                )));
            }
            let ascending = match dir {
                "asc" => true,
                "desc" => false,
                _ => {
                    return Err(err(format!(
                        "aspect {name}: query {qname}: order direction must be asc / desc"
                    )))
                }
            };
            order.push(OrderKey { field, ascending });
        }
        queries.insert(
            qname,
            QuerySpec {
                args,
                where_,
                due_between,
                occurs_between,
                any_between,
                order,
            },
        );
    }

    let mut views: BTreeMap<String, ViewSpec> = BTreeMap::new();
    for (vname, yv) in ya.views {
        if !is_bare_ident(&vname) {
            return Err(err(format!(
                "aspect {name}: view name {vname:?} must be a bare identifier"
            )));
        }
        let kind = ViewKind::parse(&yv.kind).ok_or_else(|| {
            err(format!(
                "aspect {name}: view {vname}: kind must be list / table / board / calendar / form"
            ))
        })?;
        if let Some(q) = &yv.query {
            if !queries.contains_key(q) {
                return Err(err(format!(
                    "aspect {name}: view {vname}: query {q:?} is not declared"
                )));
            }
        } else if kind != ViewKind::Form {
            return Err(err(format!(
                "aspect {name}: view {vname}: `query` is required"
            )));
        }
        if let Some(g) = &yv.group_by {
            if !fields.contains_key(g) {
                return Err(err(format!(
                    "aspect {name}: view {vname}: group_by references undeclared field {g:?}"
                )));
            }
        }
        for c in &yv.columns {
            if !fields.contains_key(c) && !is_promoted_column(c) {
                return Err(err(format!(
                    "aspect {name}: view {vname}: column references undeclared field {c:?}"
                )));
            }
        }
        views.insert(
            vname,
            ViewSpec {
                kind,
                query: yv.query,
                group_by: yv.group_by,
                columns: yv.columns,
            },
        );
    }

    let mut operations: BTreeMap<String, OperationBinding> = BTreeMap::new();
    for (oname, yo) in ya.operations {
        if !is_bare_ident(&oname) || !is_bare_ident(&yo.tool) || !is_bare_ident(&yo.method) {
            return Err(err(format!(
                "aspect {name}: operation {oname}: name, tool and method must be bare identifiers"
            )));
        }
        operations.insert(
            oname,
            OperationBinding {
                tool: yo.tool,
                method: yo.method,
            },
        );
    }

    Ok(AspectSpec {
        key: ya.key,
        fields,
        queries,
        views,
        operations,
    })
}

/// `derive` / `ensure` references must point at fields declared in the same map.
fn check_cross_refs(
    scope: &str,
    fields: &BTreeMap<String, FieldSpec>,
) -> Result<(), MetaSchemaError> {
    for (fname, spec) in fields {
        if let Some(d) = &spec.derive {
            for k in d.when.keys() {
                if !fields.contains_key(k) {
                    return Err(err(format!(
                        "{scope}: field {fname}: derive.when references undeclared field {k:?}"
                    )));
                }
            }
            if let ValueExpr::SelfField { name: f, .. } = &d.value {
                if !fields.contains_key(f) {
                    return Err(err(format!(
                        "{scope}: field {fname}: derive.value references undeclared field {f:?}"
                    )));
                }
            }
        }
        if let Some(e) = &spec.ensure {
            let Some(other) = fields.get(&e.field) else {
                return Err(err(format!(
                    "{scope}: field {fname}: ensure references undeclared field {:?}",
                    e.field
                )));
            };
            if other.field_type != spec.field_type {
                return Err(err(format!(
                    "{scope}: field {fname}: ensure compares against {} of a different type",
                    e.field
                )));
            }
        }
    }
    Ok(())
}

/// Record columns every query may reference even though no aspect declares them.
fn is_promoted_column(name: &str) -> bool {
    matches!(name, "title" | "type" | "updated_at")
}

/// Parse one expression value. `args` scopes `$args.<name>`; `allow_self` admits `$self.<f>`.
fn parse_expr(
    v: &Value,
    args: &BTreeMap<String, FieldType>,
    allow_self: bool,
) -> Result<ValueExpr, String> {
    let Value::String(s) = v else {
        return Ok(ValueExpr::Literal(v.clone()));
    };
    let s = s.trim();
    if !s.starts_with('$') {
        return Ok(ValueExpr::Literal(v.clone()));
    }
    // "$var" ["+"|"-" duration]
    let (head, rest) = match s.find(|c: char| c == '+' || c == '-') {
        Some(i) => (s[..i].trim(), Some((&s[i..i + 1], s[i + 1..].trim()))),
        None => (s, None),
    };
    let offset = match rest {
        None => None,
        Some((sign, dur)) => {
            let d = parse_duration(dur).ok_or_else(|| format!("bad duration {dur:?}"))?;
            Some(if sign == "-" { -d } else { d })
        }
    };
    if head == "$now" {
        return Ok(ValueExpr::Now { offset });
    }
    if let Some(name) = head.strip_prefix("$args.") {
        if !is_bare_ident(name) {
            return Err(format!("bad argument reference {head:?}"));
        }
        if !args.contains_key(name) {
            return Err(format!("undeclared argument {name:?}"));
        }
        return Ok(ValueExpr::Arg {
            name: name.to_string(),
            offset,
        });
    }
    if let Some(name) = head.strip_prefix("$self.") {
        if !allow_self {
            return Err("$self is not allowed here".into());
        }
        if !is_bare_ident(name) {
            return Err(format!("bad field reference {head:?}"));
        }
        return Ok(ValueExpr::SelfField {
            name: name.to_string(),
            offset,
        });
    }
    Err(format!(
        "unknown variable {head:?} (only $now, $args.<name>, $self.<field>)"
    ))
}

/// `30m` / `2h` / `1d` / `7d` / `2w`.
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit())?;
    let (num, unit) = s.split_at(split);
    let n: i64 = num.parse().ok()?;
    if n < 0 || n > 100_000 {
        return None;
    }
    match unit {
        "m" => Some(Duration::minutes(n)),
        "h" => Some(Duration::hours(n)),
        "d" => Some(Duration::days(n)),
        "w" => Some(Duration::weeks(n)),
        _ => None,
    }
}

/// RFC 3339 (any offset, normalized to UTC) or `YYYY-MM-DD` (= 00:00 UTC).
pub fn parse_datetime(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(d) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return d.and_hms_opt(0, 0, 0).map(|n| n.and_utc());
    }
    None
}

/// Canonical text of a UTC instant (`2026-09-17T08:00:00Z`).
pub fn format_datetime(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

// ── evaluation helpers shared by cap-fs (derive) and cap-data (queries) ─────────────────────

/// Evaluate `$now` / `$self.<f>` / literal in a record context. `$args` needs `args`.
pub fn eval_expr(
    expr: &ValueExpr,
    now: DateTime<Utc>,
    record: &serde_yml::Mapping,
    args: &BTreeMap<String, Value>,
) -> Result<Value, String> {
    fn shifted(base: DateTime<Utc>, offset: Option<Duration>) -> Value {
        Value::String(format_datetime(match offset {
            Some(d) => base + d,
            None => base,
        }))
    }
    match expr {
        ValueExpr::Now { offset } => Ok(shifted(now, *offset)),
        ValueExpr::Literal(v) => Ok(v.clone()),
        ValueExpr::Arg { name, offset } => {
            let v = args
                .get(name)
                .ok_or_else(|| format!("missing argument {name:?}"))?;
            match offset {
                None => Ok(v.clone()),
                Some(_) => {
                    let base = v
                        .as_str()
                        .and_then(parse_datetime)
                        .ok_or_else(|| format!("argument {name:?} is not a datetime"))?;
                    Ok(shifted(base, *offset))
                }
            }
        }
        ValueExpr::SelfField { name, offset } => {
            let v = record
                .get(Value::String(name.clone()))
                .ok_or_else(|| format!("record has no field {name:?}"))?;
            match offset {
                None => Ok(v.clone()),
                Some(_) => {
                    let base = v
                        .as_str()
                        .and_then(parse_datetime)
                        .ok_or_else(|| format!("field {name:?} is not a datetime"))?;
                    Ok(shifted(base, *offset))
                }
            }
        }
    }
}

// ── schema hash ─────────────────────────────────────────────────────────────────────────────

/// serde_yml → serde_json (mapping keys stringified; used by projections and `describe`).
pub fn yaml_to_json(v: &Value) -> serde_json::Value {
    match v {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                serde_json::Value::from(i)
            } else if let Some(u) = n.as_u64() {
                serde_json::Value::from(u)
            } else if let Some(f) = n.as_f64() {
                serde_json::Value::from(f)
            } else {
                serde_json::Value::String(n.to_string())
            }
        }
        Value::String(s) => serde_json::Value::String(s.clone()),
        Value::Sequence(items) => {
            serde_json::Value::Array(items.iter().map(yaml_to_json).collect())
        }
        Value::Mapping(m) => {
            let mut out = serde_json::Map::new();
            for (k, v) in m {
                let key = match k {
                    Value::String(s) => s.clone(),
                    other => serde_yml::to_string(other)
                        .unwrap_or_default()
                        .trim()
                        .to_string(),
                };
                out.insert(key, yaml_to_json(v));
            }
            serde_json::Value::Object(out)
        }
        Value::Tagged(t) => yaml_to_json(&t.value),
    }
}

fn expr_json(e: &ValueExpr) -> serde_json::Value {
    let off = |o: &Option<Duration>| o.map(|d| d.num_seconds());
    match e {
        ValueExpr::Now { offset } => serde_json::json!({ "now": off(offset) }),
        ValueExpr::Arg { name, offset } => {
            serde_json::json!({ "arg": name, "offset": off(offset) })
        }
        ValueExpr::SelfField { name, offset } => {
            serde_json::json!({ "self": name, "offset": off(offset) })
        }
        ValueExpr::Literal(v) => serde_json::json!({ "literal": yaml_to_json(v) }),
    }
}

pub(crate) fn field_type_json(t: &FieldType) -> serde_json::Value {
    match t {
        FieldType::String => serde_json::json!("string"),
        FieldType::Integer => serde_json::json!("integer"),
        FieldType::Boolean => serde_json::json!("boolean"),
        FieldType::DateTime => serde_json::json!("datetime"),
        FieldType::Duration => serde_json::json!("duration"),
        FieldType::ListString => serde_json::json!("list<string>"),
        FieldType::ListDateTime => serde_json::json!("list<datetime>"),
        FieldType::EnumString(v) => serde_json::json!(v),
    }
}

pub(crate) fn field_spec_json(f: &FieldSpec) -> serde_json::Value {
    let mut o = serde_json::Map::new();
    o.insert("type".into(), field_type_json(&f.field_type));
    if let Some(a) = &f.auto {
        o.insert("auto".into(), serde_json::json!(format!("{a:?}")));
    }
    if let Some(d) = &f.default {
        o.insert("default".into(), yaml_to_json(d));
    }
    if let Some(t) = &f.transitions {
        o.insert("transitions".into(), serde_json::json!(t));
    }
    if let Some(d) = &f.derive {
        let when: serde_json::Map<String, serde_json::Value> = d
            .when
            .iter()
            .map(|(k, v)| (k.clone(), yaml_to_json(v)))
            .collect();
        o.insert(
            "derive".into(),
            serde_json::json!({ "when": when, "value": expr_json(&d.value), "else": match d.else_ { DeriveElse::Unset => "unset", DeriveElse::Keep => "keep" } }),
        );
    }
    if let Some(e) = &f.ensure {
        o.insert(
            "ensure".into(),
            serde_json::json!({ e.op.as_str(): e.field }),
        );
    }
    if f.inherit {
        o.insert("inherit".into(), serde_json::json!(true));
    }
    serde_json::Value::Object(o)
}

fn query_json(q: &QuerySpec) -> serde_json::Value {
    let args: serde_json::Map<String, serde_json::Value> = q
        .args
        .iter()
        .map(|(k, t)| (k.clone(), field_type_json(t)))
        .collect();
    let where_: serde_json::Map<String, serde_json::Value> = q
        .where_
        .iter()
        .map(|(k, c)| {
            let v = match c {
                WhereClause::Eq(v) => serde_json::json!({ "eq": yaml_to_json(v) }),
                WhereClause::In(v) => {
                    serde_json::json!({ "in": v.iter().map(yaml_to_json).collect::<Vec<_>>() })
                }
                WhereClause::Cmp(op, e) => serde_json::json!({ op.as_str(): expr_json(e) }),
            };
            (k.clone(), v)
        })
        .collect();
    let win = |w: &Option<(ValueExpr, ValueExpr)>| {
        w.as_ref()
            .map(|(a, b)| serde_json::json!([expr_json(a), expr_json(b)]))
    };
    serde_json::json!({
        "args": args,
        "where": where_,
        "due_between": win(&q.due_between),
        "occurs_between": win(&q.occurs_between),
        "any_between": win(&q.any_between),
        "order": q.order.iter().map(|o| serde_json::json!({ "field": o.field, "ascending": o.ascending })).collect::<Vec<_>>(),
    })
}

/// Canonical JSON of the whole schema (deterministic key order via `BTreeMap` + serde_json's
/// preserve-order-off maps).
pub fn schema_canonical_json(schema: &MetaSchema) -> serde_json::Value {
    let fields = |m: &BTreeMap<String, FieldSpec>| -> serde_json::Value {
        serde_json::Value::Object(
            m.iter()
                .map(|(k, f)| (k.clone(), field_spec_json(f)))
                .collect(),
        )
    };
    let aspects: serde_json::Map<String, serde_json::Value> = schema
        .aspects
        .iter()
        .map(|(name, a)| {
            (
                name.clone(),
                serde_json::json!({
                    "key": a.key,
                    "fields": fields(&a.fields),
                    "queries": serde_json::Value::Object(a.queries.iter().map(|(k, q)| (k.clone(), query_json(q))).collect()),
                    "views": serde_json::Value::Object(a.views.iter().map(|(k, v)| (k.clone(), serde_json::json!({
                        "kind": v.kind.as_str(), "query": v.query, "group_by": v.group_by, "columns": v.columns
                    }))).collect()),
                    "operations": serde_json::Value::Object(a.operations.iter().map(|(k, o)| (k.clone(), serde_json::json!({ "tool": o.tool, "method": o.method }))).collect()),
                }),
            )
        })
        .collect();
    serde_json::json!({
        "required": fields(&schema.required),
        "optional": fields(&schema.optional),
        "aspects": aspects,
    })
}

/// sha256 hex of [`schema_canonical_json`].
pub fn schema_hash(schema: &MetaSchema) -> String {
    let text = serde_json::to_string(&schema_canonical_json(schema)).unwrap_or_default();
    let digest = Sha256::digest(text.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

// ── lookups on MetaSchema ───────────────────────────────────────────────────────────────────

impl MetaSchema {
    /// The union of every aspect's fields (identical across aspects by construction).
    pub fn aspect_field(&self, name: &str) -> Option<&FieldSpec> {
        self.aspects.values().find_map(|a| a.fields.get(name))
    }

    /// The spec that governs a frontmatter record field: aspect fields win over `optional`
    /// entry fields of the same name; `required` fields are checked as strings.
    pub fn record_field(&self, name: &str) -> Option<&FieldSpec> {
        self.aspect_field(name)
            .or_else(|| self.optional.get(name))
            .or_else(|| self.required.get(name))
    }

    /// Aspects a record has (any key field present), sorted.
    pub fn aspects_of(&self, record: &serde_yml::Mapping) -> Vec<String> {
        self.aspects
            .iter()
            .filter(|(_, a)| {
                a.key
                    .iter()
                    .any(|k| record.contains_key(Value::String(k.clone())))
            })
            .map(|(n, _)| n.clone())
            .collect()
    }

    /// Fields declared `inherit: true` across aspects.
    pub fn inherited_fields(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .aspects
            .values()
            .flat_map(|a| {
                a.fields
                    .iter()
                    .filter(|(_, f)| f.inherit)
                    .map(|(n, _)| n.clone())
            })
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Content-addressed hash of the schema (`describe` / `GET /client/schema`).
    pub fn schema_hash(&self) -> String {
        schema_hash(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_and_datetimes() {
        assert_eq!(parse_duration("30m"), Some(Duration::minutes(30)));
        assert_eq!(parse_duration("7d"), Some(Duration::days(7)));
        assert_eq!(parse_duration("3y"), None);
        assert_eq!(parse_duration("-1d"), None);
        assert_eq!(
            format_datetime(parse_datetime("2026-09-22T10:00:00+08:00").unwrap()),
            "2026-09-22T02:00:00Z"
        );
        assert_eq!(
            format_datetime(parse_datetime("2026-09-22").unwrap()),
            "2026-09-22T00:00:00Z"
        );
        assert!(parse_datetime("yesterday").is_none());
    }

    #[test]
    fn expressions() {
        let mut args = BTreeMap::new();
        args.insert("day".to_string(), FieldType::DateTime);
        let e = parse_expr(&Value::String("$args.day + 1d".into()), &args, false).unwrap();
        assert_eq!(
            e,
            ValueExpr::Arg {
                name: "day".into(),
                offset: Some(Duration::days(1))
            }
        );
        assert!(parse_expr(&Value::String("$now * 2".into()), &args, false).is_err());
        assert!(parse_expr(&Value::String("$args.nope".into()), &args, false).is_err());
        assert!(parse_expr(&Value::String("$self.x".into()), &args, false).is_err());
        assert_eq!(
            parse_expr(&Value::String("todo".into()), &args, false).unwrap(),
            ValueExpr::Literal(Value::String("todo".into()))
        );
    }
}

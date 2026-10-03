//! Meta-schema grammar v2: aspects, field
//! invariants (`transitions` / `derive` / `ensure` / `inherit`), named queries, views and
//! operation bindings, plus the closed expression language (`$now`, `$args.x`, `$self.x`,
//! literals, `± <duration>`) and each aspect's presentation (`display`).
//!
//! Two document shapes parse through [`parse_document`]:
//! - the workspace schema (`required` / `optional` / `aspects: {name: {…}}`), and
//! - a pack extension declaring ONE aspect at the top level (`aspect: name`, `key`, `fields`,
//!   `queries`, `views`, `operations`, `display`), optionally with a v1 `optional:` block.
//!
//! Aspect fields are namespaced under their aspect and validated for frontmatter records;
//! `optional` fields remain the `.meta.yaml` entry vocabulary. A field name shared by two
//! aspects must carry an identical spec (fields are a global vocabulary across aspects). A
//! query or operation name belongs to exactly one aspect, because requests name them without
//! their aspect.
//!
//! `display` holds presentation only: labels, icons, per-field formats, per-enum-value tones,
//! the default view and the view order. Validation, storage and queries never consult it, so
//! two aspects may present a shared field differently. Its vocabularies (formats, tones) are
//! closed. Unknown keys anywhere are rejected.

use std::collections::{BTreeMap, BTreeSet};

use advance_shared_types::entity::{OrderKey, MAX_ORDER_KEYS};
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
    /// The query that feeds the view (declared by the same aspect); `None` only on a form.
    pub query: Option<String>,
    /// A board's lanes (an enum field, required on a board) or a list / table's sections (a
    /// non-list field). A calendar or form takes none.
    pub group_by: Option<String>,
    /// The fields the view shows, in order: aspect fields or the promoted columns `title` /
    /// `type` / `updated_at` (a form shows neither `type` nor `updated_at`). Empty = the client
    /// chooses.
    pub columns: Vec<String>,
    /// The order a client presents the query's rows in (within each group when grouped). Empty
    /// = the query's own order. It never changes which rows the query returns. A calendar or
    /// form takes none.
    pub order: Vec<OrderKey>,
}

/// An operation binding: the skill tool (`skill::<tool>`) and method that compute the
/// operation's effect list. Logic lives in WASM; this is only the name binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationBinding {
    pub tool: String,
    pub method: String,
}

/// How a client presents a field's value (`display.fields.<f>.format`). The vocabulary is
/// closed, and each format suits only some field types ([`DisplayFormat::allows`]). Without a
/// declared format a client infers one from the field type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayFormat {
    /// Plain text.
    Text,
    /// A number.
    Number,
    /// A priority: a higher value is more urgent.
    Priority,
    /// A checkbox.
    Checkbox,
    /// A badge; an enum value takes its declared tone.
    Badge,
    /// A list of tags.
    Tags,
    /// A person, or a list of people.
    Person,
    /// A calendar date.
    Date,
    /// A date with a time of day.
    DateTime,
    /// A moment relative to now ("in 3 days", "2 hours ago").
    Relative,
    /// A length of time.
    Duration,
    /// An RFC 5545 recurrence rule.
    Recurrence,
    /// An IANA time zone name.
    Timezone,
}

impl DisplayFormat {
    /// Every format, in declaration order.
    pub const ALL: [Self; 13] = [
        Self::Text,
        Self::Number,
        Self::Priority,
        Self::Checkbox,
        Self::Badge,
        Self::Tags,
        Self::Person,
        Self::Date,
        Self::DateTime,
        Self::Relative,
        Self::Duration,
        Self::Recurrence,
        Self::Timezone,
    ];

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.as_str() == s)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Number => "number",
            Self::Priority => "priority",
            Self::Checkbox => "checkbox",
            Self::Badge => "badge",
            Self::Tags => "tags",
            Self::Person => "person",
            Self::Date => "date",
            Self::DateTime => "datetime",
            Self::Relative => "relative",
            Self::Duration => "duration",
            Self::Recurrence => "recurrence",
            Self::Timezone => "timezone",
        }
    }

    /// Whether the format may present a field of type `t`.
    pub fn allows(self, t: &FieldType) -> bool {
        use FieldType as T;
        match self {
            Self::Text => matches!(
                t,
                T::String | T::Integer | T::Boolean | T::DateTime | T::Duration | T::EnumString(_)
            ),
            Self::Number => matches!(t, T::Integer),
            Self::Priority => matches!(t, T::Integer | T::EnumString(_)),
            Self::Checkbox => matches!(t, T::Boolean),
            Self::Badge => matches!(t, T::String | T::EnumString(_)),
            Self::Tags => matches!(t, T::ListString),
            Self::Person => matches!(t, T::String | T::ListString),
            Self::Date | Self::DateTime => matches!(t, T::DateTime | T::ListDateTime),
            Self::Relative => matches!(t, T::DateTime),
            Self::Duration => matches!(t, T::Duration),
            Self::Recurrence | Self::Timezone => matches!(t, T::String),
        }
    }
}

/// The semantic tone of an enum value (`display.fields.<f>.values.<v>.tone`): a name a client
/// maps onto its own palette, never a color. The vocabulary is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Neutral,
    Info,
    Success,
    Warning,
    Error,
    Muted,
}

impl Tone {
    /// Every tone, in declaration order.
    pub const ALL: [Self; 6] = [
        Self::Neutral,
        Self::Info,
        Self::Success,
        Self::Warning,
        Self::Error,
        Self::Muted,
    ];

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == s)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Neutral => "neutral",
            Self::Info => "info",
            Self::Success => "success",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Muted => "muted",
        }
    }
}

/// Bound on the number of `columns` of one view.
pub const MAX_VIEW_COLUMNS: usize = 64;
/// Bound on the length of a label, in characters.
pub const MAX_LABEL_CHARS: usize = 64;
/// Bound on the length of an icon name, in bytes.
pub const MAX_ICON_BYTES: usize = 48;

/// How clients present one aspect (`display:`). Presentation only: validation, storage and
/// queries never consult it.
///
/// A label is plain single-line text of 1..=[`MAX_LABEL_CHARS`] characters, without control
/// characters, line or paragraph separators, bidi controls, `<` or `>`. An icon is a name in
/// the client's icon set (`[a-z0-9]+(-[a-z0-9]+)*`, at most [`MAX_ICON_BYTES`] bytes); a name
/// the client does not know renders without an icon.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AspectDisplay {
    pub label: Option<String>,
    pub icon: Option<String>,
    /// The view a client opens first; never a form. `None` = the client chooses.
    pub default_view: Option<String>,
    /// The order a client lists the views in: declared views, each at most once. Empty = the
    /// client chooses.
    pub view_order: Vec<String>,
    /// Label and icon per view, keyed by view name.
    pub views: BTreeMap<String, ViewDisplay>,
    /// Presentation per field, keyed by aspect field or promoted column (`title` / `type` /
    /// `updated_at`, typed string, string and datetime).
    pub fields: BTreeMap<String, FieldDisplay>,
}

/// Label and icon of one view (`display.views.<v>`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ViewDisplay {
    pub label: Option<String>,
    pub icon: Option<String>,
}

/// Presentation of one field (`display.fields.<f>`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FieldDisplay {
    /// A format that suits the field's type.
    pub format: Option<DisplayFormat>,
    pub label: Option<String>,
    pub icon: Option<String>,
    /// Enum fields only: presentation per variant, keyed by variant (any subset of them).
    pub values: BTreeMap<String, ValueDisplay>,
}

/// Presentation of one enum value (`display.fields.<f>.values.<v>`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ValueDisplay {
    pub tone: Option<Tone>,
    pub label: Option<String>,
    pub icon: Option<String>,
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
    /// How clients present the aspect.
    pub display: AspectDisplay,
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
    #[serde(default)]
    display: Option<YamlDisplay>,
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
    #[serde(default)]
    display: Option<YamlDisplay>,
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
    #[serde(default)]
    order: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct YamlOperation {
    tool: String,
    method: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct YamlDisplay {
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    icon: Option<String>,
    #[serde(default)]
    default_view: Option<String>,
    #[serde(default)]
    view_order: Vec<String>,
    #[serde(default)]
    views: BTreeMap<String, YamlLabelIcon>,
    #[serde(default)]
    fields: BTreeMap<String, YamlFieldDisplay>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct YamlLabelIcon {
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    icon: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct YamlFieldDisplay {
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    icon: Option<String>,
    #[serde(default)]
    values: BTreeMap<String, YamlValueDisplay>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct YamlValueDisplay {
    #[serde(default)]
    tone: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    icon: Option<String>,
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
        || !doc.operations.is_empty()
        || doc.display.is_some();
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
                    display: doc.display,
                },
            )?;
            aspects.insert(name, spec);
        }
        None if has_single_parts => {
            return Err(err(
                "`key` / `fields` / `queries` / `views` / `operations` / `display` need a \
                 top-level `aspect:`",
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

    // Cross-aspect: a request names a query or an operation without its aspect, so each name
    // belongs to exactly one aspect.
    let mut query_owner: BTreeMap<&str, &str> = BTreeMap::new();
    let mut operation_owner: BTreeMap<&str, &str> = BTreeMap::new();
    for (aname, aspect) in &aspects {
        for qname in aspect.queries.keys() {
            if let Some(other) = query_owner.insert(qname, aname) {
                return Err(err(format!(
                    "query {qname} is declared by aspects {other} and {aname}"
                )));
            }
        }
        for oname in aspect.operations.keys() {
            if let Some(other) = operation_owner.insert(oname, aname) {
                return Err(err(format!(
                    "operation {oname} is declared by aspects {other} and {aname}"
                )));
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
        let order = parse_order(&format!("aspect {name}: query {qname}"), &yq.order, &fields)?;
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
        let scope = format!("aspect {name}: view {vname}");
        let kind = ViewKind::parse(&yv.kind).ok_or_else(|| {
            err(format!(
                "{scope}: kind must be list / table / board / calendar / form"
            ))
        })?;
        if let Some(q) = &yv.query {
            if !queries.contains_key(q) {
                return Err(err(format!("{scope}: query {q:?} is not declared")));
            }
        } else if kind != ViewKind::Form {
            return Err(err(format!("{scope}: `query` is required")));
        }
        match &yv.group_by {
            Some(g) => {
                let Some(spec) = fields.get(g) else {
                    return Err(err(format!(
                        "{scope}: group_by references undeclared field {g:?}"
                    )));
                };
                match kind {
                    ViewKind::Board => {
                        if !matches!(spec.field_type, FieldType::EnumString(_)) {
                            return Err(err(format!(
                                "{scope}: a board groups by an enum field; {g} is not one"
                            )));
                        }
                    }
                    ViewKind::List | ViewKind::Table => {
                        if matches!(
                            spec.field_type,
                            FieldType::ListString | FieldType::ListDateTime
                        ) {
                            return Err(err(format!(
                                "{scope}: cannot group by the list field {g}"
                            )));
                        }
                    }
                    ViewKind::Calendar | ViewKind::Form => {
                        return Err(err(format!(
                            "{scope}: a {} takes no group_by",
                            kind.as_str()
                        )));
                    }
                }
            }
            None if kind == ViewKind::Board => {
                return Err(err(format!(
                    "{scope}: a board needs `group_by` (an enum field)"
                )));
            }
            None => {}
        }
        if yv.columns.len() > MAX_VIEW_COLUMNS {
            return Err(err(format!(
                "{scope}: at most {MAX_VIEW_COLUMNS} columns, got {}",
                yv.columns.len()
            )));
        }
        let mut shown: BTreeSet<&str> = BTreeSet::new();
        for c in &yv.columns {
            if !fields.contains_key(c) && !is_promoted_column(c) {
                return Err(err(format!(
                    "{scope}: column references undeclared field {c:?}"
                )));
            }
            if !shown.insert(c.as_str()) {
                return Err(err(format!("{scope}: column {c} is listed twice")));
            }
            if kind == ViewKind::Form && matches!(c.as_str(), "type" | "updated_at") {
                return Err(err(format!("{scope}: a form cannot edit {c}")));
            }
        }
        let order = if yv.order.is_empty() {
            Vec::new()
        } else {
            if matches!(kind, ViewKind::Calendar | ViewKind::Form) {
                return Err(err(format!("{scope}: a {} takes no order", kind.as_str())));
            }
            if yv.order.len() > MAX_ORDER_KEYS {
                return Err(err(format!(
                    "{scope}: at most {MAX_ORDER_KEYS} order keys, got {}",
                    yv.order.len()
                )));
            }
            let order = parse_order(&scope, &yv.order, &fields)?;
            let mut ordered: BTreeSet<&str> = BTreeSet::new();
            for k in &order {
                if !ordered.insert(k.field.as_str()) {
                    return Err(err(format!(
                        "{scope}: order lists the field {} twice",
                        k.field
                    )));
                }
            }
            order
        };
        views.insert(
            vname,
            ViewSpec {
                kind,
                query: yv.query,
                group_by: yv.group_by,
                columns: yv.columns,
                order,
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

    let display = match ya.display {
        None => AspectDisplay::default(),
        Some(yd) => parse_display(name, yd, &fields, &views)?,
    };

    Ok(AspectSpec {
        key: ya.key,
        fields,
        queries,
        views,
        operations,
        display,
    })
}

/// Parse `order` entries (`"<field>[ asc|desc]"`, ascending by default); each field is an
/// aspect field or a promoted column.
fn parse_order(
    scope: &str,
    entries: &[String],
    fields: &BTreeMap<String, FieldSpec>,
) -> Result<Vec<OrderKey>, MetaSchemaError> {
    let mut order = Vec::with_capacity(entries.len());
    for o in entries {
        let mut parts = o.split_whitespace();
        let field = parts.next().unwrap_or_default().to_string();
        let dir = parts.next().unwrap_or("asc");
        if parts.next().is_some() {
            return Err(err(format!("{scope}: bad order entry {o:?}")));
        }
        if !fields.contains_key(&field) && !is_promoted_column(&field) {
            return Err(err(format!(
                "{scope}: order references undeclared field {field:?}"
            )));
        }
        let ascending = match dir {
            "asc" => true,
            "desc" => false,
            _ => return Err(err(format!("{scope}: order direction must be asc / desc"))),
        };
        order.push(OrderKey { field, ascending });
    }
    Ok(order)
}

/// Parse an aspect's `display` block against the aspect's own fields and views.
fn parse_display(
    aspect: &str,
    yd: YamlDisplay,
    fields: &BTreeMap<String, FieldSpec>,
    views: &BTreeMap<String, ViewSpec>,
) -> Result<AspectDisplay, MetaSchemaError> {
    let scope = format!("aspect {aspect}: display");
    let label = check_label(&scope, yd.label)?;
    let icon = check_icon(&scope, yd.icon)?;
    if let Some(v) = &yd.default_view {
        match views.get(v) {
            None => {
                return Err(err(format!(
                    "{scope}: default_view {v:?} is not a declared view"
                )))
            }
            Some(spec) if spec.kind == ViewKind::Form => {
                return Err(err(format!(
                    "{scope}: default_view {v} is a form; a client opens a list, table, board \
                     or calendar first"
                )))
            }
            Some(_) => {}
        }
    }
    let mut listed: BTreeSet<&str> = BTreeSet::new();
    for v in &yd.view_order {
        if !views.contains_key(v) {
            return Err(err(format!(
                "{scope}: view_order names {v:?}, which is not a declared view"
            )));
        }
        if !listed.insert(v.as_str()) {
            return Err(err(format!("{scope}: view_order lists {v} twice")));
        }
    }

    let mut view_displays: BTreeMap<String, ViewDisplay> = BTreeMap::new();
    for (vname, yv) in yd.views {
        if !views.contains_key(&vname) {
            return Err(err(format!(
                "{scope}: views.{vname} is not a declared view"
            )));
        }
        let vscope = format!("{scope}: views.{vname}");
        let shown = ViewDisplay {
            label: check_label(&vscope, yv.label)?,
            icon: check_icon(&vscope, yv.icon)?,
        };
        view_displays.insert(vname, shown);
    }

    let mut field_displays: BTreeMap<String, FieldDisplay> = BTreeMap::new();
    for (fname, yf) in yd.fields {
        let field_type = match fields.get(&fname) {
            Some(spec) => spec.field_type.clone(),
            None => promoted_column_type(&fname).ok_or_else(|| {
                err(format!(
                    "{scope}: fields.{fname} is not a field of the aspect (nor title / type / \
                     updated_at)"
                ))
            })?,
        };
        let fscope = format!("{scope}: fields.{fname}");
        let YamlFieldDisplay {
            format,
            label,
            icon,
            values,
        } = yf;
        let format = match format {
            None => None,
            Some(f) => {
                let parsed = DisplayFormat::parse(&f).ok_or_else(|| {
                    err(format!(
                        "{fscope}: unknown format {f:?} (one of {})",
                        DisplayFormat::ALL.map(DisplayFormat::as_str).join(" / ")
                    ))
                })?;
                if !parsed.allows(&field_type) {
                    return Err(err(format!(
                        "{fscope}: format {f} does not suit a {} field",
                        field_type_name(&field_type)
                    )));
                }
                Some(parsed)
            }
        };
        let mut value_displays: BTreeMap<String, ValueDisplay> = BTreeMap::new();
        if !values.is_empty() {
            let FieldType::EnumString(variants) = &field_type else {
                return Err(err(format!(
                    "{fscope}: values are only for enum fields; {fname} is a {} field",
                    field_type_name(&field_type)
                )));
            };
            for (value, yv) in values {
                if !variants.contains(&value) {
                    return Err(err(format!(
                        "{fscope}: {value:?} is not a variant of {fname}"
                    )));
                }
                let vscope = format!("{fscope}: values.{value}");
                let tone = match yv.tone {
                    None => None,
                    Some(t) => Some(Tone::parse(&t).ok_or_else(|| {
                        err(format!(
                            "{vscope}: unknown tone {t:?} (one of {})",
                            Tone::ALL.map(Tone::as_str).join(" / ")
                        ))
                    })?),
                };
                let shown = ValueDisplay {
                    tone,
                    label: check_label(&vscope, yv.label)?,
                    icon: check_icon(&vscope, yv.icon)?,
                };
                value_displays.insert(value, shown);
            }
        }
        let shown = FieldDisplay {
            format,
            label: check_label(&fscope, label)?,
            icon: check_icon(&fscope, icon)?,
            values: value_displays,
        };
        field_displays.insert(fname, shown);
    }

    Ok(AspectDisplay {
        label,
        icon,
        default_view: yd.default_view,
        view_order: yd.view_order,
        views: view_displays,
        fields: field_displays,
    })
}

/// A label is plain single-line text of 1..=[`MAX_LABEL_CHARS`] characters. Control
/// characters, line and paragraph separators, bidi controls and `<` / `>` are refused, so a
/// label can neither break a line, reorder the text around it nor read as markup.
fn check_label(scope: &str, label: Option<String>) -> Result<Option<String>, MetaSchemaError> {
    let Some(l) = label else {
        return Ok(None);
    };
    if l.trim().is_empty() {
        return Err(err(format!("{scope}: label must not be blank")));
    }
    if l.chars().count() > MAX_LABEL_CHARS {
        return Err(err(format!(
            "{scope}: label is longer than {MAX_LABEL_CHARS} characters"
        )));
    }
    if let Some(c) = l.chars().find(|c| is_refused_label_char(*c)) {
        return Err(err(format!(
            "{scope}: label contains the refused character U+{:04X}",
            u32::from(c)
        )));
    }
    Ok(Some(l))
}

fn is_refused_label_char(c: char) -> bool {
    // `is_control` covers C0, DEL and C1.
    c.is_control()
        || matches!(
            c,
            '<' | '>'
                // line separator, paragraph separator
                | '\u{2028}'
                | '\u{2029}'
                // arabic letter mark, left-to-right mark, right-to-left mark
                | '\u{061C}'
                | '\u{200E}'
                | '\u{200F}'
                // embeddings, pop and overrides (LRE, RLE, PDF, LRO, RLO)
                | '\u{202A}'..='\u{202E}'
                // isolates (LRI, RLI, FSI, PDI)
                | '\u{2066}'..='\u{2069}'
        )
}

/// An icon is a name in the client's icon set: lowercase letters and digits in `-`-separated
/// words, at most [`MAX_ICON_BYTES`] bytes.
fn check_icon(scope: &str, icon: Option<String>) -> Result<Option<String>, MetaSchemaError> {
    let Some(i) = icon else {
        return Ok(None);
    };
    let well_formed = i.len() <= MAX_ICON_BYTES
        && i.split('-').all(|word| {
            !word.is_empty()
                && word
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        });
    if !well_formed {
        return Err(err(format!(
            "{scope}: icon {i:?} must be lowercase letters and digits in `-`-separated words \
             (at most {MAX_ICON_BYTES} bytes)"
        )));
    }
    Ok(Some(i))
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

/// Record columns every query and view may reference even though no aspect declares them.
fn is_promoted_column(name: &str) -> bool {
    promoted_column_type(name).is_some()
}

/// The fixed type of a promoted column: `title` and `type` are strings, `updated_at` is the
/// row's modification time.
fn promoted_column_type(name: &str) -> Option<FieldType> {
    match name {
        "title" | "type" => Some(FieldType::String),
        "updated_at" => Some(FieldType::DateTime),
        _ => None,
    }
}

/// The grammar's name of a field type (`enum` for any enum).
fn field_type_name(t: &FieldType) -> &'static str {
    match t {
        FieldType::String => "string",
        FieldType::Integer => "integer",
        FieldType::Boolean => "boolean",
        FieldType::DateTime => "datetime",
        FieldType::Duration => "duration",
        FieldType::ListString => "list<string>",
        FieldType::ListDateTime => "list<datetime>",
        FieldType::EnumString(_) => "enum",
    }
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
        FieldType::EnumString(v) => serde_json::json!(v),
        other => serde_json::json!(field_type_name(other)),
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
        "order": order_json(&q.order),
    })
}

fn order_json(order: &[OrderKey]) -> serde_json::Value {
    order
        .iter()
        .map(|o| serde_json::json!({ "field": o.field, "ascending": o.ascending }))
        .collect()
}

fn display_json(d: &AspectDisplay) -> serde_json::Value {
    let views: serde_json::Map<String, serde_json::Value> = d
        .views
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                serde_json::json!({ "label": v.label, "icon": v.icon }),
            )
        })
        .collect();
    let fields: serde_json::Map<String, serde_json::Value> = d
        .fields
        .iter()
        .map(|(k, f)| {
            let values: serde_json::Map<String, serde_json::Value> = f
                .values
                .iter()
                .map(|(v, vd)| {
                    (
                        v.clone(),
                        serde_json::json!({
                            "tone": vd.tone.map(Tone::as_str),
                            "label": vd.label,
                            "icon": vd.icon,
                        }),
                    )
                })
                .collect();
            (
                k.clone(),
                serde_json::json!({
                    "format": f.format.map(DisplayFormat::as_str),
                    "label": f.label,
                    "icon": f.icon,
                    "values": values,
                }),
            )
        })
        .collect();
    serde_json::json!({
        "label": d.label,
        "icon": d.icon,
        "default_view": d.default_view,
        "view_order": d.view_order,
        "views": views,
        "fields": fields,
    })
}

/// Canonical JSON of the whole schema (deterministic key order via `BTreeMap` + serde_json's
/// preserve-order-off maps). It covers presentation too (views' `order`, each aspect's
/// `display`), so a presentation change changes the hash.
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
                        "kind": v.kind.as_str(), "query": v.query, "group_by": v.group_by, "columns": v.columns,
                        "order": order_json(&v.order),
                    }))).collect()),
                    "operations": serde_json::Value::Object(a.operations.iter().map(|(k, o)| (k.clone(), serde_json::json!({ "tool": o.tool, "method": o.method }))).collect()),
                    "display": display_json(&a.display),
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

    #[test]
    fn display_formats_suit_exactly_their_field_types() {
        use DisplayFormat as F;
        assert_eq!(
            F::ALL.map(F::as_str),
            [
                "text",
                "number",
                "priority",
                "checkbox",
                "badge",
                "tags",
                "person",
                "date",
                "datetime",
                "relative",
                "duration",
                "recurrence",
                "timezone"
            ]
        );
        let types = [
            FieldType::String,
            FieldType::Integer,
            FieldType::Boolean,
            FieldType::DateTime,
            FieldType::Duration,
            FieldType::EnumString(vec!["a".into(), "b".into()]),
            FieldType::ListString,
            FieldType::ListDateTime,
        ];
        // One row per format. The columns follow `types`: string, integer, boolean, datetime,
        // duration, enum, list<string>, list<datetime>; `x` = the format suits the type.
        let matrix = [
            (F::Text, "xxxxxx.."),
            (F::Number, ".x......"),
            (F::Priority, ".x...x.."),
            (F::Checkbox, "..x....."),
            (F::Badge, "x....x.."),
            (F::Tags, "......x."),
            (F::Person, "x.....x."),
            (F::Date, "...x...x"),
            (F::DateTime, "...x...x"),
            (F::Relative, "...x...."),
            (F::Duration, "....x..."),
            (F::Recurrence, "x......."),
            (F::Timezone, "x......."),
        ];
        assert_eq!(
            matrix.map(|(f, _)| f),
            F::ALL,
            "one row per format, in order"
        );
        for (format, row) in matrix {
            assert_eq!(row.len(), types.len());
            for (t, cell) in types.iter().zip(row.chars()) {
                assert_eq!(
                    format.allows(t),
                    cell == 'x',
                    "{} on a {} field",
                    format.as_str(),
                    field_type_name(t)
                );
            }
            assert_eq!(F::parse(format.as_str()), Some(format));
        }
        for unknown in ["currency", "url", "markdown", "Text", ""] {
            assert_eq!(F::parse(unknown), None, "{unknown:?}");
        }
    }

    #[test]
    fn tones_are_six_semantic_names() {
        assert_eq!(
            Tone::ALL.map(Tone::as_str),
            ["neutral", "info", "success", "warning", "error", "muted"]
        );
        for tone in Tone::ALL {
            assert_eq!(Tone::parse(tone.as_str()), Some(tone));
        }
        for unknown in ["danger", "red", "#00ff00", "Info", ""] {
            assert_eq!(Tone::parse(unknown), None, "{unknown:?}");
        }
    }

    #[test]
    fn labels_are_plain_single_line_text() {
        let check = |l: &str| check_label("scope", Some(l.to_string()));
        assert_eq!(
            check("In progress").unwrap().as_deref(),
            Some("In progress")
        );
        assert!(check("Échéance · 截止 ✓").is_ok());
        assert!(check(&"x".repeat(MAX_LABEL_CHARS)).is_ok());
        assert!(
            check(&"é".repeat(MAX_LABEL_CHARS)).is_ok(),
            "the bound counts characters, not bytes"
        );
        assert_eq!(check_label("scope", None).unwrap(), None);
        let too_long = "x".repeat(MAX_LABEL_CHARS + 1);
        for bad in [
            "",
            "   ",
            too_long.as_str(),
            "a\nb",
            "a\tb",
            "a\u{7f}b",
            "a\u{85}b",
            "a\u{2028}b",
            "a\u{2029}b",
            "a\u{202E}b",
            "a\u{202A}b",
            "a\u{2066}b",
            "a\u{2069}b",
            "a\u{200E}b",
            "a\u{200F}b",
            "a\u{061C}b",
            "<b>bold</b>",
            "a > b",
        ] {
            assert!(check(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn icons_are_lowercase_dashed_names() {
        let check = |i: &str| check_icon("scope", Some(i.to_string()));
        let longest = "a".repeat(MAX_ICON_BYTES);
        for good in [
            "calendar",
            "list-todo",
            "calendar-check",
            "h1",
            "x",
            longest.as_str(),
        ] {
            assert!(check(good).is_ok(), "{good:?}");
        }
        let too_long = "a".repeat(MAX_ICON_BYTES + 1);
        for bad in [
            "",
            "Calendar",
            "cal endar",
            "-x",
            "x-",
            "a--b",
            "a_b",
            "ä",
            too_long.as_str(),
        ] {
            assert!(check(bad).is_err(), "{bad:?} must be refused");
        }
    }
}

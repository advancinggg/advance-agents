//! Frontmatter codec: parse a `.md` file's leading
//! `---` block into a [`FrontmatterDoc`], serialize it back in ONE canonical style, and
//! `normalize` a write (validate against the meta-schema, assign ids, enforce transitions,
//! recompute derived fields, check `ensure`) while preserving the body bytes exactly.
//!
//! The frontmatter block is machine-owned: key order follows [`CANONICAL_HEAD`], then declared
//! aspect fields alphabetically, then undeclared keys alphabetically, `items` last; comments
//! are not preserved; scalars are quoted only when YAML needs it. `parse(canonical(x)) == x`
//! and `canonical(canonical(x)) == canonical(x)`.
//!
//! Bounds: block ≤ [`MAX_FRONTMATTER_BLOCK_BYTES`], `items` ≤ [`MAX_ITEMS_PER_FILE`], nesting
//! one level (an item cannot carry `items`), YAML aliases rejected, nesting depth guarded.

use std::collections::BTreeMap;

use advance_shared_types::entity::ENTITY_ID_PREFIX;
use advance_shared_types::yaml_guard::{yaml_has_alias_refs, yaml_nesting_within_bound};
use chrono::{DateTime, Utc};
use serde_yml::{Mapping, Value};

use crate::meta_schema::{FieldSpec, FieldType, MetaSchema};
use crate::schema_v2::{
    eval_expr, format_datetime, parse_datetime, parse_duration, Cmp, DeriveElse,
};

/// Maximum size of the frontmatter block (between the delimiters).
pub const MAX_FRONTMATTER_BLOCK_BYTES: usize = 256 * 1024;
/// Maximum number of inline `items`.
pub const MAX_ITEMS_PER_FILE: usize = 256;
/// Well-known keys that lead a canonical block, in this order.
pub const CANONICAL_HEAD: &[&str] = &["id", "type", "title", "name", "slug", "description", "tags"];
const ITEMS_KEY: &str = "items";
const ID_KEY: &str = "id";
const TYPE_KEY: &str = "type";

/// A parsed frontmatter block: the file-level record and its inline items (each a flat
/// record without `items`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FrontmatterDoc {
    pub fields: Mapping,
    pub items: Vec<Mapping>,
}

impl FrontmatterDoc {
    /// The file-level `id`, if present.
    pub fn id(&self) -> Option<&str> {
        self.fields
            .get(Value::String(ID_KEY.into()))
            .and_then(Value::as_str)
    }
    /// The inline item with `id`, if any.
    pub fn item(&self, id: &str) -> Option<&Mapping> {
        self.items
            .iter()
            .find(|m| m.get(Value::String(ID_KEY.into())).and_then(Value::as_str) == Some(id))
    }
}

/// Supplies fresh entity ids (`e-` + ULID in production; a counter in tests).
pub trait IdSource {
    fn next_id(&mut self) -> String;
}

/// Production id source.
#[derive(Debug, Default, Clone, Copy)]
pub struct UlidIdSource;

impl IdSource for UlidIdSource {
    fn next_id(&mut self) -> String {
        format!("{ENTITY_ID_PREFIX}{}", ulid::Ulid::new())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrontmatterError {
    BlockTooLarge {
        bytes: usize,
        max: usize,
    },
    TooManyItems {
        count: usize,
        max: usize,
    },
    /// An inline item carries its own `items`.
    NestingTooDeep,
    /// A YAML alias reference (`*name`) is present.
    AliasRejected,
    /// The block is not a YAML mapping / is malformed.
    Yaml(String),
    /// A record violates the schema (type, enum, ensure, …).
    Schema(String),
    /// An enum field changed along an undeclared transition.
    Transition {
        record: String,
        field: String,
        from: String,
        to: String,
    },
}

impl std::fmt::Display for FrontmatterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BlockTooLarge { bytes, max } => {
                write!(f, "frontmatter block is {bytes} bytes (max {max})")
            }
            Self::TooManyItems { count, max } => {
                write!(f, "frontmatter has {count} items (max {max})")
            }
            Self::NestingTooDeep => write!(f, "inline items cannot carry their own items"),
            Self::AliasRejected => write!(f, "frontmatter contains YAML alias references"),
            Self::Yaml(m) => write!(f, "frontmatter yaml: {m}"),
            Self::Schema(m) => write!(f, "frontmatter schema: {m}"),
            Self::Transition {
                record,
                field,
                from,
                to,
            } => write!(
                f,
                "frontmatter schema: {record}: transition {field}: {from} -> {to} is not declared"
            ),
        }
    }
}

impl std::error::Error for FrontmatterError {}

/// Split `body` into its frontmatter block and the body offset. `Ok(None)` when the file does
/// not start with a `---` line.
pub fn parse_frontmatter(body: &[u8]) -> Result<Option<(FrontmatterDoc, usize)>, FrontmatterError> {
    let Some((block_start, block_end, body_offset)) = locate_block(body) else {
        return Ok(None);
    };
    let block = &body[block_start..block_end];
    if block.len() > MAX_FRONTMATTER_BLOCK_BYTES {
        return Err(FrontmatterError::BlockTooLarge {
            bytes: block.len(),
            max: MAX_FRONTMATTER_BLOCK_BYTES,
        });
    }
    let text = std::str::from_utf8(block)
        .map_err(|e| FrontmatterError::Yaml(format!("not utf-8: {e}")))?;
    if yaml_has_alias_refs(text) {
        return Err(FrontmatterError::AliasRejected);
    }
    if !yaml_nesting_within_bound(text) {
        return Err(FrontmatterError::Yaml("nesting too deep".into()));
    }
    let value: Value = if text.trim().is_empty() {
        Value::Mapping(Mapping::new())
    } else {
        serde_yml::from_str(text).map_err(|e| FrontmatterError::Yaml(e.to_string()))?
    };
    let Value::Mapping(mut fields) = value else {
        return Err(FrontmatterError::Yaml(
            "frontmatter must be a mapping".into(),
        ));
    };
    let mut items = Vec::new();
    if let Some(raw) = fields.remove(Value::String(ITEMS_KEY.into())) {
        let Value::Sequence(seq) = raw else {
            return Err(FrontmatterError::Yaml("`items` must be a sequence".into()));
        };
        if seq.len() > MAX_ITEMS_PER_FILE {
            return Err(FrontmatterError::TooManyItems {
                count: seq.len(),
                max: MAX_ITEMS_PER_FILE,
            });
        }
        for it in seq {
            let Value::Mapping(m) = it else {
                return Err(FrontmatterError::Yaml("each item must be a mapping".into()));
            };
            if m.contains_key(Value::String(ITEMS_KEY.into())) {
                return Err(FrontmatterError::NestingTooDeep);
            }
            items.push(m);
        }
    }
    for k in fields.keys() {
        if !matches!(k, Value::String(_)) {
            return Err(FrontmatterError::Yaml(
                "frontmatter keys must be strings".into(),
            ));
        }
    }
    Ok(Some((FrontmatterDoc { fields, items }, body_offset)))
}

/// `(block_start, block_end, body_offset)` for a leading `---` block, `\n` or `\r\n` line ends.
fn locate_block(body: &[u8]) -> Option<(usize, usize, usize)> {
    let after_open = if body.starts_with(b"---\n") {
        4
    } else if body.starts_with(b"---\r\n") {
        5
    } else {
        return None;
    };
    // Scan line by line for a line that is exactly `---`.
    let mut pos = after_open;
    while pos <= body.len() {
        let line_end = body[pos..]
            .iter()
            .position(|b| *b == b'\n')
            .map(|i| pos + i)
            .unwrap_or(body.len());
        let line = &body[pos..line_end];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line == b"---" {
            let body_offset = if line_end < body.len() {
                line_end + 1
            } else {
                body.len()
            };
            return Some((after_open, pos, body_offset));
        }
        if line_end >= body.len() {
            break;
        }
        pos = line_end + 1;
    }
    None
}

// ── canonical serialization ─────────────────────────────────────────────────────────────────

/// Serialize a document in the canonical style (no `---` delimiters).
pub fn canonicalize(doc: &FrontmatterDoc, schema: &MetaSchema) -> String {
    let mut root = order_record(&doc.fields, schema);
    if !doc.items.is_empty() {
        let items: Vec<Value> = doc
            .items
            .iter()
            .map(|m| Value::Mapping(order_record(m, schema)))
            .collect();
        root.insert(Value::String(ITEMS_KEY.into()), Value::Sequence(items));
    }
    let text = serde_yml::to_string(&Value::Mapping(root)).unwrap_or_default();
    let text = text.strip_prefix("---\n").unwrap_or(&text).to_string();
    let text = unquote_timestamps(&text);
    if text.ends_with('\n') {
        text
    } else {
        text + "\n"
    }
}

/// serde_yml single-quotes scalars that YAML 1.1 would read as timestamps
/// (`'2026-09-17T08:00:00Z'`). Our reader treats them as strings either way, and the
/// canonical style keeps datetimes bare, so strip the quotes from scalars that are exactly an
/// RFC 3339 instant or a `YYYY-MM-DD` date.
fn unquote_timestamps(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        let nl = if line.ends_with('\n') { "\n" } else { "" };
        let rewritten = match body.rsplit_once(": '") {
            Some((head, tail)) if tail.ends_with('\'') => {
                let inner = &tail[..tail.len() - 1];
                if is_bare_timestamp(inner) {
                    Some(format!("{head}: {inner}"))
                } else {
                    None
                }
            }
            _ => match body.trim_start().strip_prefix("- '") {
                Some(tail) if tail.ends_with('\'') => {
                    let inner = &tail[..tail.len() - 1];
                    if is_bare_timestamp(inner) {
                        let indent = &body[..body.len() - body.trim_start().len()];
                        Some(format!("{indent}- {inner}"))
                    } else {
                        None
                    }
                }
                _ => None,
            },
        };
        out.push_str(rewritten.as_deref().unwrap_or(body));
        out.push_str(nl);
    }
    out
}

/// A scalar that is written bare (unquoted) because it is a real date / RFC 3339 timestamp:
/// the shape is checked first (cheap), then the value must actually parse — `2026-13-99` has
/// the shape but is not a date and stays a quoted string.
fn is_bare_timestamp(s: &str) -> bool {
    has_timestamp_shape(s) && crate::schema_v2::parse_datetime(s).is_some()
}

fn has_timestamp_shape(s: &str) -> bool {
    let b = s.as_bytes();
    let digits = |r: std::ops::Range<usize>| {
        r.into_iter()
            .all(|i| b.get(i).map(u8::is_ascii_digit).unwrap_or(false))
    };
    let date_ok = b.len() >= 10
        && digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10);
    if !date_ok {
        return false;
    }
    if b.len() == 10 {
        return true;
    }
    if b.len() < 20
        || b[10] != b'T'
        || !digits(11..13)
        || b[13] != b':'
        || !digits(14..16)
        || b[16] != b':'
        || !digits(17..19)
    {
        return false;
    }
    let rest = &s[19..];
    rest == "Z"
        || (rest.len() == 6
            && (rest.starts_with('+') || rest.starts_with('-'))
            && rest.as_bytes()[3] == b':'
            && rest[1..3].bytes().all(|c| c.is_ascii_digit())
            && rest[4..6].bytes().all(|c| c.is_ascii_digit()))
}

fn order_record(record: &Mapping, schema: &MetaSchema) -> Mapping {
    let mut out = Mapping::new();
    let key = |s: &str| Value::String(s.to_string());
    for k in CANONICAL_HEAD {
        if let Some(v) = record.get(key(k)) {
            out.insert(key(k), v.clone());
        }
    }
    let mut declared: Vec<String> = record
        .keys()
        .filter_map(|k| k.as_str().map(str::to_string))
        .filter(|k| {
            !CANONICAL_HEAD.contains(&k.as_str())
                && k != ITEMS_KEY
                && schema.aspect_field(k).is_some()
        })
        .collect();
    declared.sort();
    for k in declared {
        out.insert(key(&k), record.get(key(&k)).cloned().unwrap_or(Value::Null));
    }
    let mut rest: Vec<String> = record
        .keys()
        .filter_map(|k| k.as_str().map(str::to_string))
        .filter(|k| {
            !CANONICAL_HEAD.contains(&k.as_str())
                && k != ITEMS_KEY
                && schema.aspect_field(k).is_none()
        })
        .collect();
    rest.sort();
    for k in rest {
        out.insert(key(&k), record.get(key(&k)).cloned().unwrap_or(Value::Null));
    }
    out
}

// ── normalize ───────────────────────────────────────────────────────────────────────────────

/// Validate + assign ids + recompute invariants, returning the whole file with a canonical
/// block and the original body bytes. A file without frontmatter is returned unchanged.
/// `previous` is the on-disk document before this write (transitions are checked against it).
pub fn normalize(
    body: &[u8],
    previous: Option<&FrontmatterDoc>,
    schema: &MetaSchema,
    ids: &mut dyn IdSource,
    now: DateTime<Utc>,
) -> Result<Vec<u8>, FrontmatterError> {
    let Some((mut doc, body_offset)) = parse_frontmatter(body)? else {
        return Ok(body.to_vec());
    };
    normalize_doc(&mut doc, previous, schema, ids, now)?;
    let mut out = Vec::with_capacity(body.len() + 64);
    out.extend_from_slice(b"---\n");
    out.extend_from_slice(canonicalize(&doc, schema).as_bytes());
    out.extend_from_slice(b"---\n");
    out.extend_from_slice(&body[body_offset..]);
    Ok(out)
}

/// The in-place half of [`normalize`]: ids, validation, transitions, derive, ensure on `doc`.
pub fn normalize_doc(
    doc: &mut FrontmatterDoc,
    previous: Option<&FrontmatterDoc>,
    schema: &MetaSchema,
    ids: &mut dyn IdSource,
    now: DateTime<Utc>,
) -> Result<(), FrontmatterError> {
    let id_key = Value::String(ID_KEY.into());
    if !doc.fields.contains_key(&id_key) {
        doc.fields
            .insert(id_key.clone(), Value::String(ids.next_id()));
    }
    check_id(&doc.fields, "file")?;
    let prev_file = previous.map(|p| &p.fields);
    validate_record(&mut doc.fields, prev_file, schema, now, "file")?;

    let mut seen_ids: Vec<String> = Vec::new();
    if let Some(id) = doc.id() {
        seen_ids.push(id.to_string());
    }
    for (i, item) in doc.items.iter_mut().enumerate() {
        if !item.contains_key(&id_key) {
            item.insert(id_key.clone(), Value::String(ids.next_id()));
        }
        let label = format!("items[{i}]");
        check_id(item, &label)?;
        if !item.contains_key(Value::String(TYPE_KEY.into())) {
            return Err(FrontmatterError::Schema(format!(
                "{label}: `type` is required"
            )));
        }
        let id = item
            .get(&id_key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if seen_ids.contains(&id) {
            return Err(FrontmatterError::Schema(format!(
                "{label}: duplicate id {id}"
            )));
        }
        seen_ids.push(id.clone());
        let prev_item = previous.and_then(|p| p.item(&id));
        validate_record(item, prev_item, schema, now, &label)?;
    }
    Ok(())
}

fn check_id(record: &Mapping, label: &str) -> Result<(), FrontmatterError> {
    let id = record
        .get(Value::String(ID_KEY.into()))
        .and_then(Value::as_str)
        .ok_or_else(|| FrontmatterError::Schema(format!("{label}: `id` must be a string")))?;
    if !id.starts_with(ENTITY_ID_PREFIX)
        || id.len() <= ENTITY_ID_PREFIX.len()
        || id.len() > 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(FrontmatterError::Schema(format!(
            "{label}: malformed id {id:?}"
        )));
    }
    Ok(())
}

/// Type / enum validation, transitions, derive and ensure for ONE record.
pub fn validate_record(
    record: &mut Mapping,
    previous: Option<&Mapping>,
    schema: &MetaSchema,
    now: DateTime<Utc>,
    label: &str,
) -> Result<(), FrontmatterError> {
    let key = |s: &str| Value::String(s.to_string());
    // 1. types + enums + transitions on present fields.
    let present: Vec<String> = record
        .keys()
        .filter_map(|k| k.as_str().map(str::to_string))
        .collect();
    for name in &present {
        if name == ITEMS_KEY {
            continue;
        }
        let Some(spec) = schema.record_field(name) else {
            continue; // undeclared keys are free-form
        };
        let v = record.get(key(name)).expect("present");
        if !value_matches(&spec.field_type, v) {
            return Err(FrontmatterError::Schema(format!(
                "{label}: field {name} does not match its declared type {}",
                describe_type(&spec.field_type)
            )));
        }
        if let (Some(transitions), Some(prev)) = (&spec.transitions, previous) {
            if let Some(Value::String(from)) = prev.get(key(name)) {
                let to = v.as_str().unwrap_or_default();
                if from != to {
                    let allowed = transitions
                        .get(from)
                        .map(|t| t.contains(&to.to_string()))
                        .unwrap_or(false);
                    if !allowed {
                        return Err(FrontmatterError::Transition {
                            record: label.to_string(),
                            field: name.clone(),
                            from: from.clone(),
                            to: to.to_string(),
                        });
                    }
                }
            }
        }
    }
    // 2. derive rules of every aspect field.
    let mut derived: Vec<(String, Option<Value>)> = Vec::new();
    for aspect in schema.aspects.values() {
        for (fname, spec) in &aspect.fields {
            let Some(rule) = &spec.derive else { continue };
            let matches = rule.when.iter().all(|(k, v)| record.get(key(k)) == Some(v));
            if matches {
                if !record.contains_key(key(fname)) {
                    let v = eval_expr(&rule.value, now, record, &BTreeMap::new()).map_err(|m| {
                        FrontmatterError::Schema(format!("{label}: derive {fname}: {m}"))
                    })?;
                    derived.push((fname.clone(), Some(v)));
                }
            } else if rule.else_ == DeriveElse::Unset && record.contains_key(key(fname)) {
                derived.push((fname.clone(), None));
            }
        }
    }
    for (fname, v) in derived {
        match v {
            Some(v) => {
                record.insert(key(&fname), v);
            }
            None => {
                record.remove(key(&fname));
            }
        }
    }
    // 3. ensure rules.
    for aspect in schema.aspects.values() {
        for (fname, spec) in &aspect.fields {
            let Some(rule) = &spec.ensure else { continue };
            let (Some(a), Some(b)) = (record.get(key(fname)), record.get(key(&rule.field))) else {
                continue;
            };
            let ok = match spec.field_type {
                FieldType::DateTime => match (
                    a.as_str().and_then(parse_datetime),
                    b.as_str().and_then(parse_datetime),
                ) {
                    (Some(x), Some(y)) => rule.op.holds(&x, &y),
                    _ => false,
                },
                FieldType::Integer => match (a.as_i64(), b.as_i64()) {
                    (Some(x), Some(y)) => rule.op.holds(&x, &y),
                    _ => false,
                },
                _ => true,
            };
            if !ok {
                return Err(FrontmatterError::Schema(format!(
                    "{label}: ensure {fname} {} {} does not hold",
                    cmp_word(rule.op),
                    rule.field
                )));
            }
        }
    }
    Ok(())
}

fn cmp_word(c: Cmp) -> &'static str {
    match c {
        Cmp::Gt => ">",
        Cmp::Gte => ">=",
        Cmp::Lt => "<",
        Cmp::Lte => "<=",
    }
}

/// Does a YAML value satisfy a field type?
pub fn value_matches(t: &FieldType, v: &Value) -> bool {
    match t {
        FieldType::String => v.is_string(),
        FieldType::Integer => v.as_i64().is_some() || v.as_u64().is_some(),
        FieldType::Boolean => v.is_bool(),
        FieldType::DateTime => v.as_str().and_then(parse_datetime).is_some(),
        FieldType::Duration => v.as_str().and_then(parse_duration).is_some(),
        FieldType::ListString => {
            matches!(v, Value::Sequence(items) if items.iter().all(Value::is_string))
        }
        FieldType::ListDateTime => {
            matches!(v, Value::Sequence(items) if items.iter().all(|i| i.as_str().and_then(parse_datetime).is_some()))
        }
        FieldType::EnumString(variants) => v
            .as_str()
            .map(|s| variants.iter().any(|x| x == s))
            .unwrap_or(false),
    }
}

fn describe_type(t: &FieldType) -> String {
    match t {
        FieldType::EnumString(v) => format!("enum {v:?}"),
        other => format!("{other:?}").to_lowercase(),
    }
}

/// Canonical `now` text used by derived timestamps.
pub fn now_text(now: DateTime<Utc>) -> String {
    format_datetime(now)
}

/// Look up a declared field's spec for callers outside this module.
pub fn field_spec<'a>(schema: &'a MetaSchema, name: &str) -> Option<&'a FieldSpec> {
    schema.record_field(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locate_handles_crlf_and_eof() {
        assert_eq!(locate_block(b"---\na: 1\n---\nbody"), Some((4, 9, 13)));
        assert_eq!(
            locate_block(b"---\r\na: 1\r\n---\r\nbody"),
            Some((5, 11, 16))
        );
        assert_eq!(locate_block(b"---\na: 1\n---"), Some((4, 9, 12)));
        assert_eq!(locate_block(b"# no\n"), None);
        assert_eq!(locate_block(b"---\nunterminated\n"), None);
    }

    #[test]
    fn timestamps_are_written_bare() {
        let text = "due: '2026-09-20T18:00:00+08:00'\nwhen: '2026-09-20'\nexdates:\n- '2026-10-05T02:00:00Z'\nnote: '2026-13-99'\ntitle: 'not: a date'\n";
        let out = unquote_timestamps(text);
        assert_eq!(
            out,
            "due: 2026-09-20T18:00:00+08:00\nwhen: 2026-09-20\nexdates:\n- 2026-10-05T02:00:00Z\nnote: '2026-13-99'\ntitle: 'not: a date'\n"
        );
        assert!(is_bare_timestamp("2026-09-17T08:00:00Z"));
        assert!(!is_bare_timestamp("2026-09-17T08:00:00"));
        assert!(!is_bare_timestamp("20260917"));
    }

    #[test]
    fn parse_rejects_bad_shapes() {
        assert!(matches!(
            parse_frontmatter(b"---\n- a\n- b\n---\n").unwrap_err(),
            FrontmatterError::Yaml(_)
        ));
        assert!(matches!(
            parse_frontmatter(b"---\nitems: 3\n---\n").unwrap_err(),
            FrontmatterError::Yaml(_)
        ));
        let (doc, off) = parse_frontmatter(b"---\n---\nx").unwrap().unwrap();
        assert!(doc.fields.is_empty());
        assert_eq!(off, 8);
    }
}

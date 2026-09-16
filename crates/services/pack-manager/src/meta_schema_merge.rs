//! PACK-GAP-CLOSURE P2 (§3.1, #9) — STRUCTURED merge of a pack
//! `meta-schema-extensions/{name}.yaml` into a workspace `meta-schema.yaml`.
//!
//! Slice C's `merge_meta_schema_extension` appended the extension as a second
//! `---`-separated YAML document, which no consumer parsed: cap-fs's
//! `MetaSchemaLoader` reads ONE document (`{required, optional}`), so every
//! extension was silently dropped at load. P2 parses both sides and emits a
//! single document:
//!
//! - an extension may only ADD `optional` fields (`required` must be absent or
//!   empty — a pack cannot make every existing `.meta.yaml` entry invalid);
//! - each field is `{type, default}` with the grammar cap-fs enforces (`string`
//!   / `integer` / `boolean` / `list<string>` or an enum list; `default` present
//!   and matching the type) so the merged file loads through
//!   `MetaSchemaLoader::reload_from_disk` without a second round of errors;
//! - a field already present with an IDENTICAL spec is idempotent (reported as
//!   `unchanged`); a field present with a DIFFERENT spec (type, default or any
//!   attribute) or already declared `required` is a conflict — nothing is
//!   written and the target is untouched;
//! - every other top-level key of the target is preserved verbatim.
//!
//! Both files are read through `O_NOFOLLOW` + fstat with a 1 MiB cap, alias-
//! guarded and nesting-bounded; the result is written atomically (sibling
//! tempfile + rename).

use std::path::{Path, PathBuf};

use serde_yml::{Mapping, Value};

use crate::component_manifest::yaml_nesting_within_bound;
use crate::error::PackError;
use crate::manifest::yaml_has_alias_refs;
use crate::materialize_impl::read_bytes_nofollow_bounded;

/// Cap on both the extension and the target document (mirrors the other
/// small-YAML caps in this crate).
pub const MAX_META_SCHEMA_YAML_BYTES: u64 = 1024 * 1024;
const MAX_FIELD_NAME_LEN: usize = 64;
const MAX_FIELDS_PER_EXTENSION: usize = 256;
const MAX_ENUM_VARIANTS: usize = 256;

/// What a merge did. `added` / `unchanged` are field names in extension order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetaSchemaMergeReport {
    pub added: Vec<String>,
    pub unchanged: Vec<String>,
}

/// Structured merge failure. Converts into [`PackError`] for the materializer
/// (`Conflict` → `ConstraintViolation`, the grammar variants → `InvalidManifest`,
/// `Io` passes through); the cli bridge maps `Conflict` to its own
/// `SchemaConflict` variant.
#[derive(Debug)]
pub enum MetaSchemaMergeError {
    /// `field` exists in the target with a different spec (or as `required`).
    /// `existing` / `incoming` are single-line YAML renderings of the two specs.
    Conflict {
        field: String,
        existing: String,
        incoming: String,
    },
    /// The extension document violates the grammar above.
    InvalidExtension(String),
    /// The target document exists but is not a `{required, optional}` mapping.
    InvalidTarget(String),
    /// A file-level failure (symlink / size / read / write) of
    /// [`merge_meta_schema_extension_file`], or a caller's pre-write validation
    /// rejecting the merged document.
    Io(PackError),
}

impl std::fmt::Display for MetaSchemaMergeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetaSchemaMergeError::Conflict {
                field,
                existing,
                incoming,
            } => write!(
                f,
                "meta-schema extension conflicts on field `{field}`: existing {existing}, \
                 incoming {incoming}"
            ),
            MetaSchemaMergeError::InvalidExtension(m) => {
                write!(f, "invalid meta-schema extension: {m}")
            }
            MetaSchemaMergeError::InvalidTarget(m) => {
                write!(f, "invalid meta-schema target: {m}")
            }
            MetaSchemaMergeError::Io(e) => write!(f, "meta-schema merge: {e}"),
        }
    }
}

impl std::error::Error for MetaSchemaMergeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MetaSchemaMergeError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<MetaSchemaMergeError> for PackError {
    fn from(e: MetaSchemaMergeError) -> Self {
        match e {
            MetaSchemaMergeError::Conflict { .. } => PackError::ConstraintViolation {
                reason: e.to_string(),
            },
            MetaSchemaMergeError::Io(inner) => inner,
            other => PackError::InvalidManifest(other.to_string()),
        }
    }
}

impl From<PackError> for MetaSchemaMergeError {
    fn from(e: PackError) -> Self {
        MetaSchemaMergeError::Io(e)
    }
}

/// Merge the extension at `source` into `target` (created when absent). The
/// target is rewritten atomically ONLY when the merge succeeds; on any error it
/// is byte-identical to before.
pub fn merge_meta_schema_extension_file(
    source: &Path,
    target: &Path,
) -> Result<MetaSchemaMergeReport, MetaSchemaMergeError> {
    merge_meta_schema_extension_file_with(source, target, |_| Ok(()))
}

/// [`merge_meta_schema_extension_file`] with a caller validation of the merged
/// document BEFORE anything is written (the cli bridge dry-runs cap-fs's own
/// schema parser here). `Err(msg)` from `pre_write` → `Io(InvalidManifest)`,
/// target untouched.
pub fn merge_meta_schema_extension_file_with(
    source: &Path,
    target: &Path,
    pre_write: impl FnOnce(&str) -> Result<(), String>,
) -> Result<MetaSchemaMergeReport, MetaSchemaMergeError> {
    let source_bytes = read_bytes_nofollow_bounded(
        source,
        MAX_META_SCHEMA_YAML_BYTES,
        "meta-schema-extension source",
    )?;
    let source_text = std::str::from_utf8(&source_bytes).map_err(|_| {
        PackError::InvalidManifest(format!(
            "meta-schema-extension source is not valid UTF-8: {}",
            source.display()
        ))
    })?;

    let target_text: Option<String> = match std::fs::symlink_metadata(target) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Ok(md) if md.file_type().is_symlink() => {
            return Err(MetaSchemaMergeError::Io(PackError::InvalidManifest(
                format!(
                    "meta-schema-extension target is a symlink (rejected): {}",
                    target.display()
                ),
            )));
        }
        Ok(_) => {
            let bytes = read_bytes_nofollow_bounded(
                target,
                MAX_META_SCHEMA_YAML_BYTES,
                "meta-schema-extension target",
            )?;
            Some(String::from_utf8(bytes).map_err(|_| {
                PackError::InvalidManifest(format!(
                    "meta-schema-extension target is not valid UTF-8: {}",
                    target.display()
                ))
            })?)
        }
        Err(e) => {
            return Err(MetaSchemaMergeError::Io(PackError::Io {
                path: target.to_path_buf(),
                source: e,
            }));
        }
    };

    let (merged, report) = merge_documents(target_text.as_deref(), source_text)?;
    pre_write(&merged).map_err(|msg| {
        MetaSchemaMergeError::Io(PackError::InvalidManifest(format!(
            "merged meta-schema rejected before write: {msg}"
        )))
    })?;
    atomic_write_sibling(target, merged.as_bytes())?;
    Ok(report)
}

/// Pure merge of two in-memory documents → `(merged single-document YAML,
/// report)`. `target_yaml == None` means "no target yet" (fresh
/// `{optional: …}` document).
pub fn merge_documents(
    target_yaml: Option<&str>,
    extension_yaml: &str,
) -> Result<(String, MetaSchemaMergeReport), MetaSchemaMergeError> {
    let extension = parse_extension(extension_yaml)?;

    let mut target: Mapping = match target_yaml {
        None => Mapping::new(),
        Some(text) => {
            guard_yaml(text).map_err(MetaSchemaMergeError::InvalidTarget)?;
            if text.trim().is_empty() {
                Mapping::new()
            } else {
                let v: Value = serde_yml::from_str(text)
                    .map_err(|e| MetaSchemaMergeError::InvalidTarget(format!("yaml parse: {e}")))?;
                match v {
                    Value::Mapping(m) => m,
                    Value::Null => Mapping::new(),
                    other => {
                        return Err(MetaSchemaMergeError::InvalidTarget(format!(
                            "root must be a mapping, got {}",
                            value_kind(&other)
                        )))
                    }
                }
            }
        }
    };

    // Existing `required` names (a conflict target) and the existing `optional`
    // map (merged into). Both sections must be mappings when present.
    let required_names: Vec<String> = match target.get(Value::from("required")) {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Mapping(m)) => m
            .keys()
            .map(|k| {
                k.as_str().map(str::to_string).ok_or_else(|| {
                    MetaSchemaMergeError::InvalidTarget(
                        "required field names must be strings".into(),
                    )
                })
            })
            .collect::<Result<_, _>>()?,
        Some(other) => {
            return Err(MetaSchemaMergeError::InvalidTarget(format!(
                "`required` must be a mapping, got {}",
                value_kind(other)
            )))
        }
    };
    let mut optional: Mapping = match target.remove(Value::from("optional")) {
        None | Some(Value::Null) => Mapping::new(),
        Some(Value::Mapping(m)) => m,
        Some(other) => {
            return Err(MetaSchemaMergeError::InvalidTarget(format!(
                "`optional` must be a mapping, got {}",
                value_kind(&other)
            )))
        }
    };

    let mut report = MetaSchemaMergeReport::default();
    for (name, spec) in extension {
        // Collision checks FIRST: a redeclaration is judged against what the
        // target already has (identical → idempotent, different → conflict)
        // before the incoming spec's own grammar — so a type clash reports as
        // the conflict it is, not as a grammar nit of the incoming side.
        if required_names.iter().any(|r| r == &name) {
            return Err(MetaSchemaMergeError::Conflict {
                field: name,
                existing: "declared as a required field".into(),
                incoming: render_inline(&spec),
            });
        }
        match optional.get(Value::from(name.as_str())) {
            None => {
                validate_optional_spec(&name, &spec)?;
                optional.insert(Value::from(name.as_str()), spec);
                report.added.push(name);
            }
            Some(existing) if *existing == spec => report.unchanged.push(name),
            Some(existing) => {
                return Err(MetaSchemaMergeError::Conflict {
                    field: name,
                    existing: render_inline(existing),
                    incoming: render_inline(&spec),
                });
            }
        }
    }
    // Re-insert `optional` (at its original position when the target had one —
    // `Mapping` preserves insertion order, and `remove` shifts later keys up; the
    // section order `required` → `optional` → rest is what cap-fs documents).
    target.insert(Value::from("optional"), Value::Mapping(optional));

    let mut merged = serde_yml::to_string(&Value::Mapping(target))
        .map_err(|e| MetaSchemaMergeError::InvalidTarget(format!("yaml emit: {e}")))?;
    if !merged.ends_with('\n') {
        merged.push('\n');
    }
    Ok((merged, report))
}

/// Parse + structurally validate an extension document → `(field, spec)` in
/// declaration order (per-field grammar is applied by [`merge_documents`]).
fn parse_extension(yaml: &str) -> Result<Vec<(String, Value)>, MetaSchemaMergeError> {
    guard_yaml(yaml).map_err(MetaSchemaMergeError::InvalidExtension)?;
    let root: Value = serde_yml::from_str(yaml)
        .map_err(|e| MetaSchemaMergeError::InvalidExtension(format!("yaml parse: {e}")))?;
    let root = match root {
        Value::Mapping(m) => m,
        other => {
            return Err(MetaSchemaMergeError::InvalidExtension(format!(
                "root must be a mapping, got {}",
                value_kind(&other)
            )))
        }
    };
    for key in root.keys() {
        match key.as_str() {
            Some("optional") | Some("required") => {}
            Some(other) => {
                return Err(MetaSchemaMergeError::InvalidExtension(format!(
                    "unknown top-level key `{other}` (only `optional` is accepted)"
                )))
            }
            None => {
                return Err(MetaSchemaMergeError::InvalidExtension(
                    "top-level keys must be strings".into(),
                ))
            }
        }
    }
    match root.get(Value::from("required")) {
        None | Some(Value::Null) => {}
        Some(Value::Mapping(m)) if m.is_empty() => {}
        Some(_) => {
            return Err(MetaSchemaMergeError::InvalidExtension(
                "extensions may only add `optional` fields; `required` must be absent or empty"
                    .into(),
            ))
        }
    }
    let optional = match root.get(Value::from("optional")) {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Mapping(m)) => m,
        Some(other) => {
            return Err(MetaSchemaMergeError::InvalidExtension(format!(
                "`optional` must be a mapping, got {}",
                value_kind(other)
            )))
        }
    };
    if optional.len() > MAX_FIELDS_PER_EXTENSION {
        return Err(MetaSchemaMergeError::InvalidExtension(format!(
            "`optional` declares {} fields (max {MAX_FIELDS_PER_EXTENSION})",
            optional.len()
        )));
    }
    let mut out = Vec::with_capacity(optional.len());
    for (k, spec) in optional {
        let name = k.as_str().ok_or_else(|| {
            MetaSchemaMergeError::InvalidExtension("field names must be strings".into())
        })?;
        validate_field_name(name)?;
        // The per-field grammar (`type` / `default`) is checked by the merge for
        // NEW fields; redeclarations are judged against the existing spec first.
        out.push((name.to_string(), spec.clone()));
    }
    Ok(out)
}

fn guard_yaml(text: &str) -> Result<(), String> {
    if yaml_has_alias_refs(text) {
        return Err(
            "contains alias references (`*name`) — rejected to prevent billion-laughs \
                    amplification"
                .into(),
        );
    }
    if !yaml_nesting_within_bound(text) {
        return Err(
            "nesting/indentation is too deep — rejected to prevent parse-time resource \
                    exhaustion"
                .into(),
        );
    }
    Ok(())
}

fn validate_field_name(name: &str) -> Result<(), MetaSchemaMergeError> {
    if name.is_empty() || name.len() > MAX_FIELD_NAME_LEN {
        return Err(MetaSchemaMergeError::InvalidExtension(format!(
            "field name {name:?} must be 1..={MAX_FIELD_NAME_LEN} bytes"
        )));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return Err(MetaSchemaMergeError::InvalidExtension(format!(
            "field name {name:?} must match [A-Za-z0-9_-]+"
        )));
    }
    Ok(())
}

/// The cap-fs `optional` field grammar: `type` (scalar name or enum list),
/// `default` present + type-matching, no `auto` (auto rules are for `required`).
fn validate_optional_spec(name: &str, spec: &Value) -> Result<(), MetaSchemaMergeError> {
    let m = spec.as_mapping().ok_or_else(|| {
        MetaSchemaMergeError::InvalidExtension(format!(
            "field {name}: spec must be a mapping with `type` and `default`"
        ))
    })?;
    for key in m.keys() {
        match key.as_str() {
            Some("type") | Some("default") => {}
            Some("auto") => {
                return Err(MetaSchemaMergeError::InvalidExtension(format!(
                    "field {name}: `auto` rules apply to required fields only"
                )))
            }
            Some(other) => {
                return Err(MetaSchemaMergeError::InvalidExtension(format!(
                    "field {name}: unknown spec key `{other}`"
                )))
            }
            None => {
                return Err(MetaSchemaMergeError::InvalidExtension(format!(
                    "field {name}: spec keys must be strings"
                )))
            }
        }
    }
    let ty = m.get(Value::from("type")).ok_or_else(|| {
        MetaSchemaMergeError::InvalidExtension(format!("field {name}: missing `type`"))
    })?;
    let default = m.get(Value::from("default")).ok_or_else(|| {
        MetaSchemaMergeError::InvalidExtension(format!(
            "field {name}: optional fields need a `default`"
        ))
    })?;
    let ok = match ty {
        Value::String(s) => match s.as_str() {
            "string" => matches!(default, Value::String(_)),
            "integer" => matches!(default, Value::Number(n) if n.is_i64() || n.is_u64()),
            "boolean" => matches!(default, Value::Bool(_)),
            "list<string>" => {
                matches!(default, Value::Sequence(items) if items.iter().all(|i| matches!(i, Value::String(_))))
            }
            other => {
                return Err(MetaSchemaMergeError::InvalidExtension(format!(
                    "field {name}: unknown type `{other}` (string / integer / boolean / \
                     list<string> / [enum, variants])"
                )))
            }
        },
        Value::Sequence(variants) => {
            if variants.is_empty() || variants.len() > MAX_ENUM_VARIANTS {
                return Err(MetaSchemaMergeError::InvalidExtension(format!(
                    "field {name}: enum type needs 1..={MAX_ENUM_VARIANTS} string variants"
                )));
            }
            let mut names = Vec::with_capacity(variants.len());
            for v in variants {
                match v {
                    Value::String(s) => names.push(s.as_str()),
                    _ => {
                        return Err(MetaSchemaMergeError::InvalidExtension(format!(
                            "field {name}: enum variants must be strings"
                        )))
                    }
                }
            }
            matches!(default, Value::String(d) if names.contains(&d.as_str()))
        }
        _ => {
            return Err(MetaSchemaMergeError::InvalidExtension(format!(
                "field {name}: `type` must be a string or an enum list"
            )))
        }
    };
    if !ok {
        return Err(MetaSchemaMergeError::InvalidExtension(format!(
            "field {name}: `default` does not match the declared type"
        )));
    }
    Ok(())
}

fn value_kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Sequence(_) => "sequence",
        Value::Mapping(_) => "mapping",
        Value::Tagged(_) => "tagged",
    }
}

/// Single-line rendering for conflict messages (never fails the merge).
fn render_inline(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| format!("{v:?}"))
}

/// Atomic replace: sibling tempfile → fsync → rename. On rename failure the
/// tempfile is removed (best effort) and the target is untouched.
pub(crate) fn atomic_write_sibling(target: &Path, bytes: &[u8]) -> Result<(), PackError> {
    use std::io::Write;
    let parent: PathBuf = target
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let nanos = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let tmp = parent.join(format!(
        ".meta-schema-merge.tmp.{}.{}",
        std::process::id(),
        nanos
    ));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| PackError::Io {
                path: tmp.clone(),
                source: e,
            })?;
        f.write_all(bytes).map_err(|e| PackError::Io {
            path: tmp.clone(),
            source: e,
        })?;
        f.sync_all().map_err(|e| PackError::Io {
            path: tmp.clone(),
            source: e,
        })?;
    }
    std::fs::rename(&tmp, target).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        PackError::Io {
            path: target.to_path_buf(),
            source: e,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXT_INT: &str = "optional:\n  priority:\n    type: integer\n    default: 0\n";
    const EXT_STR: &str = "optional:\n  priority:\n    type: string\n    default: \"\"\n";
    const EXT_ENUM: &str = "optional:\n  stage:\n    type: [draft, live]\n    default: draft\n";

    #[test]
    fn fresh_target_becomes_single_document() {
        let (merged, report) = merge_documents(None, EXT_INT).unwrap();
        assert_eq!(report.added, vec!["priority".to_string()]);
        assert!(report.unchanged.is_empty());
        assert!(!merged.contains("---"));
        let doc: Value = serde_yml::from_str(&merged).unwrap();
        assert_eq!(
            doc["optional"]["priority"]["type"].as_str(),
            Some("integer")
        );
    }

    #[test]
    fn preserves_required_and_is_idempotent() {
        let target = "required:\n  name:\n    type: string\n    auto: filename\nother: 1\n";
        let (merged, r1) = merge_documents(Some(target), EXT_INT).unwrap();
        assert_eq!(r1.added, vec!["priority".to_string()]);
        let (merged2, r2) = merge_documents(Some(&merged), EXT_INT).unwrap();
        assert!(r2.added.is_empty());
        assert_eq!(r2.unchanged, vec!["priority".to_string()]);
        assert_eq!(merged, merged2, "idempotent re-merge is byte-identical");
        let doc: Value = serde_yml::from_str(&merged).unwrap();
        assert_eq!(doc["required"]["name"]["auto"].as_str(), Some("filename"));
        assert_eq!(doc["other"].as_i64(), Some(1));
    }

    #[test]
    fn differing_spec_and_required_collision_conflict() {
        let (merged, _) = merge_documents(None, EXT_INT).unwrap();
        match merge_documents(Some(&merged), EXT_STR) {
            Err(MetaSchemaMergeError::Conflict { field, .. }) => assert_eq!(field, "priority"),
            other => panic!("expected Conflict, got {other:?}"),
        }
        let target = "required:\n  priority:\n    type: integer\n    auto: filename\n";
        assert!(matches!(
            merge_documents(Some(target), EXT_INT),
            Err(MetaSchemaMergeError::Conflict { .. })
        ));
        // Same type, different default is a conflict too (the effective default
        // would silently differ from what the pack declares).
        let other_default = "optional:\n  priority:\n    type: integer\n    default: 5\n";
        assert!(matches!(
            merge_documents(Some(&merged), other_default),
            Err(MetaSchemaMergeError::Conflict { .. })
        ));
    }

    #[test]
    fn extension_grammar_is_enforced() {
        for bad in [
            "required:\n  x:\n    type: string\n    auto: filename\n",
            "optional:\n  x:\n    type: string\n",
            "optional:\n  x:\n    type: integer\n    default: nope\n",
            "optional:\n  x:\n    type: string\n    default: a\n    auto: filename\n",
            "optional:\n  \"bad name\":\n    type: string\n    default: a\n",
            "ext: {}\n",
            "optional:\n  x:\n    type: [a, b]\n    default: c\n",
            "- just\n- a list\n",
        ] {
            assert!(
                matches!(
                    merge_documents(None, bad),
                    Err(MetaSchemaMergeError::InvalidExtension(_))
                ),
                "should reject: {bad:?}"
            );
        }
        assert!(merge_documents(None, EXT_ENUM).is_ok());
        assert!(merge_documents(None, "a: &x 1\noptional: *x\n").is_err());
    }

    #[test]
    fn invalid_target_is_reported_not_overwritten() {
        assert!(matches!(
            merge_documents(Some("- a\n- list\n"), EXT_INT),
            Err(MetaSchemaMergeError::InvalidTarget(_))
        ));
        assert!(matches!(
            merge_documents(Some("optional: 3\n"), EXT_INT),
            Err(MetaSchemaMergeError::InvalidTarget(_))
        ));
    }

    #[test]
    fn conflict_converts_to_constraint_violation() {
        let e: PackError = MetaSchemaMergeError::Conflict {
            field: "priority".into(),
            existing: "a".into(),
            incoming: "b".into(),
        }
        .into();
        match e {
            PackError::ConstraintViolation { reason } => assert!(reason.contains("priority")),
            other => panic!("{other:?}"),
        }
    }
}

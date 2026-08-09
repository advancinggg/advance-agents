//! Workspace meta-schema loader + hot-reload watcher (slice B; watcher added
//! by the hotreload pre-build, 2026-06-10).
//!
//! Manages `/workspace/.agent/meta-schema.yaml` per MODULE-002 §1.4.5 / §1.4.7.
//! The schema declares required + optional fields for every `.meta.yaml` entry.
//! `MetaSchemaLoader` exposes load + reload APIs (fail-closed: a rejected
//! schema retains the previous one). [`MetaSchemaWatcher`] is the production
//! schema-file watcher — it lives HERE in cap-fs (MODULE-002), superseding the
//! earlier "future M001 runtime slice will subscribe to FsWatchEvents" plan: a
//! polling watcher on a dedicated std thread (cap-fs takes no `notify`
//! dependency), which on change re-validates + swaps the schema via
//! [`MetaSchemaLoader::reload_from_yaml`] and emits `runtime.schema_reloaded`
//! through the optional [`EventBusEmit`] sink (see `events::emit_schema_reloaded`).
//! The composition root only needs to `MetaSchemaWatcher::spawn(...)` over the
//! shared `Arc<MetaSchemaLoader>` — do NOT build a second watcher elsewhere.

use std::collections::BTreeMap;
use std::io::Read;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use advance_shared_types::traits::EventBusEmit;
use serde::{Deserialize, Serialize};

/// Maximum bytes read from the head of a `.md` file to extract OKF frontmatter `type`
/// (ADR 2026-06-29 Decision 1). Bounds the reconciler's `.md` head-read — a `type` in a
/// frontmatter block larger than this is not read (falls back to `document`).
pub const MAX_FRONTMATTER_HEAD_BYTES: usize = 8 * 1024;

/// Maximum length of an extracted entity `type` discriminator. A `type` is a short,
/// single-line token (`collection` / `document` / `project` / `work-item` / …); a longer,
/// multiline, or control-char-bearing value from a hand-authored / imported frontmatter is
/// rejected → the `document` fallback, so a guest cannot inflate `.meta.yaml` / the scan
/// `Val` via an oversized `type` (adversarial-round defense-in-depth).
const MAX_ENTITY_TYPE_BYTES: usize = 128;

/// Auto-generation rule for required fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoRule {
    /// `name` field — strip extension from filename.
    Filename,
    /// `slug` field — lowercase + non-alphanumeric → `-`.
    FilenameToSlug,
    /// `description` field — first non-empty line capped at 500 chars.
    ContentExtract,
    /// `type` field — the OKF entity/concept discriminator per ADR 2026-06-29
    /// Decision 1 deterministic defaults table (never model-inferred). At the
    /// [`MetaSchema::auto_generate`] site (which sees only `file_name` + `body`)
    /// this resolves the FILE default via [`entity_type`] with `is_dir = false`;
    /// the directory/scope → `collection` case is set explicitly at the
    /// directory sites (`ensure_dir_meta`, reconcile) which know `is_dir`.
    EntityTypeDefault,
}

/// Field type constraint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldType {
    String,
    Integer,
    Boolean,
    EnumString(Vec<String>),
    ListString,
}

/// Field declaration.
///
/// `PartialEq` (hotreload pre-build, 2026-06-10) powers the watcher's
/// [`schema_changes`] diff; `serde_yml::Value` is `PartialEq`, so the derive
/// is purely additive.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldSpec {
    pub field_type: FieldType,
    pub auto: Option<AutoRule>,
    pub default: Option<serde_yml::Value>,
}

/// Parsed meta-schema (in-memory representation).
#[derive(Debug, Clone, PartialEq)]
pub struct MetaSchema {
    pub required: BTreeMap<String, FieldSpec>,
    pub optional: BTreeMap<String, FieldSpec>,
    /// Maximum description length cap — from `meta.description_max_chars` config (default 500).
    pub description_max_chars: usize,
}

impl Default for MetaSchema {
    fn default() -> Self {
        let mut required = BTreeMap::new();
        required.insert(
            "name".to_string(),
            FieldSpec {
                field_type: FieldType::String,
                auto: Some(AutoRule::Filename),
                default: None,
            },
        );
        required.insert(
            "slug".to_string(),
            FieldSpec {
                field_type: FieldType::String,
                auto: Some(AutoRule::FilenameToSlug),
                default: None,
            },
        );
        required.insert(
            "description".to_string(),
            FieldSpec {
                field_type: FieldType::String,
                auto: Some(AutoRule::ContentExtract),
                default: None,
            },
        );
        // Entity `type` — first-class required discriminator (ADR 2026-06-29
        // Decision 1). Free-form String (collection/document/asset/project/...),
        // NOT an enum; auto-populated deterministically, never model-inferred.
        required.insert(
            "type".to_string(),
            FieldSpec {
                field_type: FieldType::String,
                auto: Some(AutoRule::EntityTypeDefault),
                default: None,
            },
        );
        let mut optional = BTreeMap::new();
        optional.insert(
            "tags".to_string(),
            FieldSpec {
                field_type: FieldType::ListString,
                auto: None,
                default: Some(serde_yml::Value::Sequence(vec![])),
            },
        );
        optional.insert(
            "status".to_string(),
            FieldSpec {
                field_type: FieldType::EnumString(vec![
                    "draft".to_string(),
                    "active".to_string(),
                    "archived".to_string(),
                ]),
                auto: None,
                default: Some(serde_yml::Value::String("active".to_string())),
            },
        );
        Self {
            required,
            optional,
            description_max_chars: 500,
        }
    }
}

impl MetaSchema {
    /// Auto-generate a value for a required field using its AutoRule.
    pub fn auto_generate(&self, field: &str, file_name: &str, body: &[u8]) -> Option<String> {
        let spec = self.required.get(field)?;
        match &spec.auto {
            Some(AutoRule::Filename) => Some(strip_extension(file_name)),
            Some(AutoRule::FilenameToSlug) => Some(filename_to_slug(file_name)),
            Some(AutoRule::ContentExtract) => {
                Some(content_extract(body, self.description_max_chars))
            }
            // FILE default (is_dir = false) — this site only sees file_name + body,
            // and every `auto_generate` caller writes a FILE entry (fs.write is
            // never a directory). The dir/scope → `collection` case is set
            // explicitly at the directory sites.
            Some(AutoRule::EntityTypeDefault) => Some(entity_type(
                file_name,
                false,
                parse_frontmatter_type(body).as_deref(),
            )),
            None => None,
        }
    }
}

/// True if `name` is a Markdown file (`.md` / `.markdown`, case-insensitive).
pub fn is_markdown_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".md") || lower.ends_with(".markdown")
}

/// Deterministic OKF entity `type` per ADR 2026-06-29 Decision 1 defaults table.
/// NEVER model-inferred. Rules:
/// - directory / scope entry → `collection`
/// - Markdown file WITH a non-empty OKF frontmatter `type` → that value
/// - Markdown file WITHOUT → `document`
/// - any non-Markdown file → `asset`
///
/// `md_frontmatter` is the already-parsed frontmatter `type` for a `.md` file
/// (`None` when absent / empty / not-Markdown); it is ignored for directories
/// and non-Markdown files. An empty/whitespace `md_frontmatter` is treated as
/// absent by the caller ([`parse_frontmatter_type`] returns `None` for it), but
/// this fn also trims defensively so it can never return an empty string.
pub fn entity_type(name: &str, is_dir: bool, md_frontmatter: Option<&str>) -> String {
    if is_dir {
        return "collection".to_string();
    }
    if is_markdown_name(name) {
        match md_frontmatter {
            Some(t) if !t.trim().is_empty() => t.trim().to_string(),
            _ => "document".to_string(),
        }
    } else {
        "asset".to_string()
    }
}

/// Parse a non-empty OKF `type` from a leading YAML frontmatter block
/// (`---\n … \n---`) at the head of `body`. Bounded: only the first
/// [`MAX_FRONTMATTER_HEAD_BYTES`] are scanned. Returns `None` for: non-UTF-8
/// head, no leading `---`, no closing `---` within the head window, a
/// frontmatter block that is not a YAML map, a missing/non-string `type`, or an
/// empty/whitespace `type` (treated as absent → the caller falls back to
/// `document`). Mirrors the cap-skills `check_frontmatter` delimiter handling.
pub fn parse_frontmatter_type(body: &[u8]) -> Option<String> {
    let head = &body[..body.len().min(MAX_FRONTMATTER_HEAD_BYTES)];
    // Decode the LONGEST-VALID-UTF-8 prefix of the head, not the whole head: a
    // multi-byte char straddling the MAX_FRONTMATTER_HEAD_BYTES boundary (common
    // for CJK / accented Markdown > 8 KiB) must NOT poison a small, well-formed
    // frontmatter block sitting at the very top of the file (audit r7 Warning —
    // otherwise a Chinese/Japanese knowledge base loses its declared `type`s en
    // masse). The frontmatter block is bounded and near the top, so it always
    // lies fully within the valid prefix.
    let content = match std::str::from_utf8(head) {
        Ok(s) => s,
        Err(e) => std::str::from_utf8(&head[..e.valid_up_to()])
            .expect("valid_up_to() prefix is valid UTF-8 by definition"),
    };
    let content = content.trim_start();
    if !content.starts_with("---") {
        return None;
    }
    // Skip the opening delimiter line's trailing newline(s).
    let after = content[3..].trim_start_matches(['\n', '\r']);
    // The closing delimiter is a line starting with `---`.
    let end = after.find("\n---")?;
    let block = &after[..end];
    // Deserialize ONLY the `type` field. Every OTHER frontmatter field is skipped
    // via serde's `ignore_any`, which — UNLIKE deserializing the whole block to a
    // `serde_yml::Value` — does NOT eagerly expand YAML anchors/aliases. This
    // closes the alias-bomb amplification (a crafted ≤8 KiB block deserialized to
    // `Value` forces a ~200 MB transient allocation; via this shallow struct the
    // same input is bounded to the source size, empirically ~1 MB). The DoS
    // resistance therefore no longer rests solely on serde_yml's internal
    // repetition limit (adversarial-round defense-in-depth).
    let fm: FrontmatterType = serde_yml::from_str(block).ok()?;
    let t = fm.r#type?;
    let t = t.trim();
    // Bound the discriminator: reject empty / oversized / control-char (incl.
    // newline) values → the `document` fallback.
    if t.is_empty() || t.len() > MAX_ENTITY_TYPE_BYTES || t.bytes().any(|b| b < 0x20) {
        None
    } else {
        Some(t.to_string())
    }
}

/// Deserialize target for [`parse_frontmatter_type`] capturing ONLY the `type`
/// field; all other keys are `ignore_any`-skipped (no eager alias expansion —
/// the alias-bomb DoS defense; see `parse_frontmatter_type`).
#[derive(Deserialize)]
struct FrontmatterType {
    #[serde(default, rename = "type")]
    r#type: Option<String>,
}

/// Hardened bounded head-read of a `.md` file's OKF frontmatter `type`.
///
/// Mirrors [`read_schema_bounded`]: unix `O_NOFOLLOW | O_NONBLOCK` open +
/// handle-`fstat` regular-file re-check + bounded read. A FIFO/device/socket
/// never blocks `open()` (`O_NONBLOCK`) and is rejected by the fstat; a leaf
/// symlink fails the open with `ELOOP`; any of these → `None` (→ `document`
/// fallback). This is the deliberate, bounded exception to the reconciler's
/// "does NOT read each file's bytes" policy (MODULE-002 §1.4.6) and is called
/// ONLY for type-absent `.md` entries during reconciliation.
pub fn read_frontmatter_type_bounded(path: &Path) -> Option<String> {
    #[cfg(unix)]
    let opened = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
    };
    #[cfg(not(unix))]
    let opened = {
        match std::fs::symlink_metadata(path) {
            Ok(meta) if !meta.file_type().is_file() => return None,
            Err(_) => return None,
            Ok(_) => {}
        }
        std::fs::File::open(path)
    };
    let file = opened.ok()?;
    // Re-verify on the actual handle: nothing non-regular was swapped in.
    match file.metadata() {
        Ok(meta) if meta.file_type().is_file() => {}
        _ => return None,
    }
    let mut bytes = Vec::new();
    file.take(MAX_FRONTMATTER_HEAD_BYTES as u64)
        .read_to_end(&mut bytes)
        .ok()?;
    parse_frontmatter_type(&bytes)
}

/// Strip the last `.ext` from a filename.
fn strip_extension(name: &str) -> String {
    match name.rfind('.') {
        Some(idx) if idx > 0 => name[..idx].to_string(),
        _ => name.to_string(),
    }
}

/// Lowercase + replace non-alphanumeric with `-`, collapse runs, trim leading/trailing `-`.
fn filename_to_slug(name: &str) -> String {
    let stem = strip_extension(name);
    let mut out = String::with_capacity(stem.len());
    let mut last_dash = false;
    for ch in stem.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

/// First non-empty line, optionally stripping leading `# ` (markdown heading prefix),
/// capped at `max_chars`. Returns `[pending] {file_name}` for binary / empty bodies
/// — but only if the body is not valid UTF-8 OR has no extractable line.
fn content_extract(body: &[u8], max_chars: usize) -> String {
    // Heuristic: if the bytes are not UTF-8 OR contain control characters that aren't
    // \t / \n / \r, treat as binary.
    let s = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return String::new(), // Binary: caller adds [pending] prefix.
    };
    if s.bytes()
        .any(|b| b < 0x20 && b != b'\t' && b != b'\n' && b != b'\r')
    {
        return String::new();
    }
    for line in s.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Strip markdown heading prefix `# ` / `## ` etc.
        let extracted = if let Some(stripped) = trimmed.strip_prefix("# ") {
            stripped.trim()
        } else if let Some(stripped) = trimmed.strip_prefix("## ") {
            stripped.trim()
        } else if let Some(stripped) = trimmed.strip_prefix("### ") {
            stripped.trim()
        } else {
            trimmed
        };
        let truncated: String = extracted.chars().take(max_chars).collect();
        return truncated;
    }
    String::new()
}

/// Yaml structure of meta-schema.yaml. Used internally by parse.
#[derive(Debug, Deserialize, Serialize)]
struct YamlSchemaFile {
    #[serde(default)]
    required: BTreeMap<String, YamlFieldSpec>,
    #[serde(default)]
    optional: BTreeMap<String, YamlFieldSpec>,
}

#[derive(Debug, Deserialize, Serialize)]
struct YamlFieldSpec {
    #[serde(rename = "type", default)]
    field_type: Option<serde_yml::Value>,
    #[serde(default)]
    auto: Option<String>,
    #[serde(default)]
    default: Option<serde_yml::Value>,
}

/// Errors during schema parsing / validation.
#[derive(Debug)]
pub enum MetaSchemaError {
    Io(String),
    Parse(String),
    Validation(String),
}

impl std::fmt::Display for MetaSchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s) => write!(f, "schema IO error: {s}"),
            Self::Parse(s) => write!(f, "schema parse error: {s}"),
            Self::Validation(s) => write!(f, "schema validation error: {s}"),
        }
    }
}

impl std::error::Error for MetaSchemaError {}

/// Hot-reloadable meta-schema container.
pub struct MetaSchemaLoader {
    current: RwLock<Arc<MetaSchema>>,
    schema_path: PathBuf,
}

impl MetaSchemaLoader {
    /// Construct a new loader with an in-memory default schema (used by tests
    /// when no `.agent/meta-schema.yaml` exists).
    pub fn new_with_default(schema_path: PathBuf) -> Self {
        Self {
            current: RwLock::new(Arc::new(MetaSchema::default())),
            schema_path,
        }
    }

    /// Construct a loader from a yaml string at the given path, used as the
    /// canonical schema source for future reload_from_disk calls.
    pub fn from_yaml(schema_path: PathBuf, yaml: &str) -> Result<Self, MetaSchemaError> {
        let schema = parse_and_validate(yaml)?;
        Ok(Self {
            current: RwLock::new(Arc::new(schema)),
            schema_path,
        })
    }

    /// Construct from disk. If the schema file doesn't exist, returns a default schema.
    pub fn load_from_disk(schema_path: &Path) -> Result<Self, MetaSchemaError> {
        match std::fs::read_to_string(schema_path) {
            Ok(yaml) => Self::from_yaml(schema_path.to_path_buf(), &yaml),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(Self::new_with_default(schema_path.to_path_buf()))
            }
            Err(e) => Err(MetaSchemaError::Io(format!("{}", e.kind()))),
        }
    }

    /// Get the current schema. Cheap clone of the Arc.
    pub fn current(&self) -> Arc<MetaSchema> {
        Arc::clone(&self.current.read().expect("schema RwLock poisoned"))
    }

    /// Re-parse the supplied yaml, validate, and atomically swap the inner Arc.
    /// On validation failure, the previous schema is preserved.
    pub fn reload_from_yaml(&self, yaml: &str) -> Result<(), MetaSchemaError> {
        let new_schema = parse_and_validate(yaml)?;
        let mut guard = self.current.write().expect("schema RwLock poisoned");
        *guard = Arc::new(new_schema);
        Ok(())
    }

    /// Re-read from `self.schema_path` and apply via `reload_from_yaml`.
    pub fn reload_from_disk(&self) -> Result<(), MetaSchemaError> {
        let yaml = std::fs::read_to_string(&self.schema_path)
            .map_err(|e| MetaSchemaError::Io(format!("{}", e.kind())))?;
        self.reload_from_yaml(&yaml)
    }

    /// The canonical schema-file path this loader was constructed with
    /// (additive accessor, hotreload pre-build 2026-06-10). The watcher's
    /// hardened bounded read needs the path directly — it deliberately does
    /// NOT delegate to [`Self::reload_from_disk`], whose plain unbounded
    /// `read_to_string` lacks the FIFO/oversize protections.
    pub fn schema_path(&self) -> &Path {
        &self.schema_path
    }
}

fn parse_and_validate(yaml: &str) -> Result<MetaSchema, MetaSchemaError> {
    let parsed: YamlSchemaFile =
        serde_yml::from_str(yaml).map_err(|e| MetaSchemaError::Parse(format!("{e}")))?;

    let mut required: BTreeMap<String, FieldSpec> = BTreeMap::new();
    for (name, ys) in parsed.required {
        let auto = match ys.auto.as_deref() {
            Some("filename") => Some(AutoRule::Filename),
            Some("filename-to-slug") => Some(AutoRule::FilenameToSlug),
            Some("content-extract") => Some(AutoRule::ContentExtract),
            Some("entity-type-default") => Some(AutoRule::EntityTypeDefault),
            Some(other) => {
                return Err(MetaSchemaError::Validation(format!(
                    "unknown auto-rule for required field {name}: {other}"
                )));
            }
            None => {
                return Err(MetaSchemaError::Validation(format!(
                    "required field {name} has no auto-generation rule"
                )));
            }
        };
        let field_type = parse_field_type(&ys.field_type, &name)?;
        required.insert(
            name,
            FieldSpec {
                field_type,
                auto,
                default: None,
            },
        );
    }

    let mut optional: BTreeMap<String, FieldSpec> = BTreeMap::new();
    for (name, ys) in parsed.optional {
        let field_type = parse_field_type(&ys.field_type, &name)?;
        let default = ys.default.ok_or_else(|| {
            MetaSchemaError::Validation(format!("optional field {name} has no default value"))
        })?;
        // Validate that the default value matches the declared field_type so
        // misconfigured schemas are rejected at load time, not silently dropped
        // when add_entry_for_write reads the default later.
        validate_default_matches_type(&name, &field_type, &default)?;
        optional.insert(
            name,
            FieldSpec {
                field_type,
                auto: None,
                default: Some(default),
            },
        );
    }

    Ok(MetaSchema {
        required,
        optional,
        description_max_chars: 500,
    })
}

/// Validate that an optional field's default value matches its declared FieldType.
fn validate_default_matches_type(
    field_name: &str,
    field_type: &FieldType,
    default: &serde_yml::Value,
) -> Result<(), MetaSchemaError> {
    let ok = match field_type {
        FieldType::String => matches!(default, serde_yml::Value::String(_)),
        FieldType::Integer => {
            matches!(default, serde_yml::Value::Number(n) if n.is_i64() || n.is_u64())
        }
        FieldType::Boolean => matches!(default, serde_yml::Value::Bool(_)),
        FieldType::ListString => match default {
            serde_yml::Value::Sequence(items) => items
                .iter()
                .all(|i| matches!(i, serde_yml::Value::String(_))),
            _ => false,
        },
        FieldType::EnumString(variants) => match default {
            serde_yml::Value::String(s) => variants.iter().any(|v| v == s),
            _ => false,
        },
    };
    if !ok {
        return Err(MetaSchemaError::Validation(format!(
            "optional field {field_name} default value does not match declared type"
        )));
    }
    Ok(())
}

fn parse_field_type(
    ys_type: &Option<serde_yml::Value>,
    field_name: &str,
) -> Result<FieldType, MetaSchemaError> {
    let v = ys_type
        .as_ref()
        .ok_or_else(|| MetaSchemaError::Validation(format!("field {field_name} has no type")))?;
    match v {
        serde_yml::Value::String(s) => match s.as_str() {
            "string" => Ok(FieldType::String),
            "integer" => Ok(FieldType::Integer),
            "boolean" => Ok(FieldType::Boolean),
            "list<string>" => Ok(FieldType::ListString),
            other if other.starts_with("enum") => Err(MetaSchemaError::Validation(format!(
                "field {field_name} enum types must be specified via list syntax"
            ))),
            other => Err(MetaSchemaError::Validation(format!(
                "field {field_name} unknown type: {other}"
            ))),
        },
        serde_yml::Value::Sequence(items) => {
            // enum-style: [draft, active, archived]
            let mut variants = Vec::new();
            for item in items {
                match item {
                    serde_yml::Value::String(s) => variants.push(s.clone()),
                    other => {
                        return Err(MetaSchemaError::Validation(format!(
                            "field {field_name} enum variant must be a string, got {other:?}"
                        )));
                    }
                }
            }
            Ok(FieldType::EnumString(variants))
        }
        other => Err(MetaSchemaError::Validation(format!(
            "field {field_name} type must be a string or sequence, got {other:?}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// SchemaChanges + MetaSchemaWatcher (hotreload pre-build, 2026-06-10)
// ---------------------------------------------------------------------------

/// Default poll cadence for [`MetaSchemaWatcher`] — comfortably inside the
/// <1 s hot-reload SLO (SYS-AC-259 leaves witness margin for the future
/// harness slice).
pub const DEFAULT_SCHEMA_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Lower clamp on the poll interval (busy-spin guard).
const MIN_SCHEMA_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Stop-flag check granularity inside the inter-tick sleep — bounds how long
/// `stop()`/`Drop` wait on a healthy idle thread.
const STOP_CHECK_SLICE: Duration = Duration::from_millis(25);

/// Maximum size of `meta-schema.yaml` the watcher will read (1 MiB). Real
/// schemas are a few KiB; the cap bounds per-tick memory against a hostile or
/// runaway schema file (streaming `take(MAX + 1)` read — the cap cannot be
/// bypassed by special files).
pub const MAX_META_SCHEMA_SIZE: u64 = 1 << 20;

/// Bounded join budget for `stop()`/`Drop` (≈2 s of 10 ms `is_finished` polls).
const JOIN_POLL_STEP: Duration = Duration::from_millis(10);
const JOIN_POLL_LIMIT: u32 = 200;

/// Field-name diff between two [`MetaSchema`]s — the `runtime.schema_reloaded`
/// payload shape (NAMES only; never field specs or values).
///
/// `description_max_chars` is intentionally excluded: `parse_and_validate`
/// hardcodes it to 500, so it can never differ across a reload today. If a
/// future slice makes it configurable, this diff MUST grow a bucket for it —
/// otherwise a cap-only reload would swap the schema (PartialEq sees the
/// difference) while `is_empty()` suppresses the event (silent reload).
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct SchemaChanges {
    pub required_added: Vec<String>,
    pub required_removed: Vec<String>,
    pub required_changed: Vec<String>,
    pub optional_added: Vec<String>,
    pub optional_removed: Vec<String>,
    pub optional_changed: Vec<String>,
}

impl SchemaChanges {
    /// True when no field-level difference exists (used to skip phantom
    /// `runtime.schema_reloaded` events on equal-value reloads).
    pub fn is_empty(&self) -> bool {
        self.required_added.is_empty()
            && self.required_removed.is_empty()
            && self.required_changed.is_empty()
            && self.optional_added.is_empty()
            && self.optional_removed.is_empty()
            && self.optional_changed.is_empty()
    }
}

/// Compute the per-bucket field-name diff between two schemas. Names come out
/// in `BTreeMap` iteration order — deterministic for tests and payloads.
pub fn schema_changes(old: &MetaSchema, new: &MetaSchema) -> SchemaChanges {
    fn diff_maps(
        old: &BTreeMap<String, FieldSpec>,
        new: &BTreeMap<String, FieldSpec>,
    ) -> (Vec<String>, Vec<String>, Vec<String>) {
        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut changed = Vec::new();
        for (name, new_spec) in new {
            match old.get(name) {
                None => added.push(name.clone()),
                Some(old_spec) if old_spec != new_spec => changed.push(name.clone()),
                Some(_) => {}
            }
        }
        for name in old.keys() {
            if !new.contains_key(name) {
                removed.push(name.clone());
            }
        }
        (added, removed, changed)
    }

    let (required_added, required_removed, required_changed) =
        diff_maps(&old.required, &new.required);
    let (optional_added, optional_removed, optional_changed) =
        diff_maps(&old.optional, &new.optional);
    SchemaChanges {
        required_added,
        required_removed,
        required_changed,
        optional_added,
        optional_removed,
        optional_changed,
    }
}

/// One poll-tick's read outcome (see the per-arm `last_seen` invariant on
/// [`MetaSchemaWatcher`]: failures BEFORE content is successfully read map to
/// `last_seen = None`; failures AFTER a successful read store the read bytes).
enum SchemaRead {
    /// File does not exist (NotFound).
    Absent,
    /// Full content read within the size cap.
    Content(Vec<u8>),
    /// Read exceeded [`MAX_META_SCHEMA_SIZE`] — capped bytes retained for the
    /// byte-compare (so identical oversize content does not re-thrash).
    Oversize(Vec<u8>),
    /// Open/fstat/read failed before trustworthy content existed
    /// (non-regular file, symlink under `O_NOFOLLOW`, permissions, I/O error).
    BeforeReadError(String),
}

/// Hardened bounded read of the schema file.
///
/// Unix: `O_NOFOLLOW | O_NONBLOCK` open + handle-`fstat` regular-file check —
/// closes the metadata-then-open TOCTOU (a FIFO swapped in cannot block the
/// open, and the fstat on the HANDLE rejects it; a leaf symlink fails the
/// open with `ELOOP`). Non-unix fallback: `symlink_metadata` pre-check then a
/// plain open (residual TOCTOU accepted — the same documented posture as
/// config.rs's macOS fallback). Error messages carry `e.kind()` only (the
/// `MetaSchemaError::Io` precedent — no path/OS detail leak).
fn read_schema_bounded(path: &Path) -> SchemaRead {
    #[cfg(unix)]
    let opened = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
    };
    #[cfg(not(unix))]
    let opened = {
        match std::fs::symlink_metadata(path) {
            Ok(meta) if !meta.file_type().is_file() => {
                return SchemaRead::BeforeReadError(
                    "schema path is not a regular file".to_string(),
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return SchemaRead::Absent,
            Err(e) => {
                return SchemaRead::BeforeReadError(format!(
                    "schema metadata check failed: {}",
                    e.kind()
                ));
            }
            Ok(_) => {}
        }
        std::fs::File::open(path)
    };

    let file = match opened {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return SchemaRead::Absent,
        Err(e) => {
            return SchemaRead::BeforeReadError(format!("schema open failed: {}", e.kind()));
        }
    };

    // Re-verify on the actual handle: nothing non-regular was swapped in.
    match file.metadata() {
        Ok(meta) if meta.file_type().is_file() => {}
        Ok(_) => {
            return SchemaRead::BeforeReadError(
                "schema path is not a regular file (FIFO/socket/device rejected fail-closed)"
                    .to_string(),
            );
        }
        Err(e) => {
            return SchemaRead::BeforeReadError(format!("schema fstat failed: {}", e.kind()));
        }
    }

    let mut bytes = Vec::new();
    if let Err(e) = file.take(MAX_META_SCHEMA_SIZE + 1).read_to_end(&mut bytes) {
        return SchemaRead::BeforeReadError(format!("schema read failed: {}", e.kind()));
    }
    if bytes.len() as u64 > MAX_META_SCHEMA_SIZE {
        SchemaRead::Oversize(bytes)
    } else {
        SchemaRead::Content(bytes)
    }
}

/// Polling hot-reload watcher for the workspace meta-schema file.
///
/// Spawns a dedicated std thread (no tokio-runtime requirement, no `notify`
/// dependency) that every `poll_interval` performs a hardened bounded read of
/// `loader.schema_path()`, byte-compares against the last-seen content, and on
/// change re-validates + swaps the schema via
/// [`MetaSchemaLoader::reload_from_yaml`] (fail-closed: a rejected schema
/// retains the previous one) and emits ONE `runtime.schema_reloaded` event
/// through the optional emitter (names-only, bucket-capped payload — see
/// `events::emit_schema_reloaded`).
///
/// Operational notes:
/// - **Sole reload writer**: the watcher diffs `loader.current()` around its
///   own reload; concurrent external `reload_from_yaml`/`reload_from_disk`
///   calls make emitted change-sets unattributable.
/// - **File-absence semantics**: an initially/perpetually absent schema file
///   is NOT an error (the default/loaded schema is in effect — mirrors
///   `load_from_disk`'s NotFound-is-default contract). Deleted-after-present
///   is fail-closed: previous schema retained, `last_error` recorded once;
///   recreation triggers a reload.
/// - **Atomic-rename writers recommended**: a non-atomic writer can be read
///   mid-write; a torn prefix that fails validation is fail-closed and
///   self-heals next tick; a torn prefix that happens to be valid YAML
///   applies transiently for ≤1 interval (an extra intermediate event — two
///   real swaps) before the final-content tick corrects it.
/// - **Shutdown**: `stop()`/`Drop` block the calling thread ~35 ms typical,
///   ≤2 s worst-case (bounded join; a wedged tick is detached with a
///   `last_error` record). Async consumers should drop the watcher
///   off-runtime or via `spawn_blocking`. If the wedge was inside
///   `reload_from_yaml` itself, the in-flight Arc swap — and/or one in-flight
///   emit — may still land after detach (zombie ticks can never emit beyond
///   that, clear, or overwrite `last_error` thanks to stop-gated writes).
/// - **Emitter contract (CONTRACT-180)**: `emit` MUST be non-blocking and
///   MUST NOT panic; `EventBus::new_synchronous_for_tests` buses are
///   forbidden here (blocking I/O per emit would wedge the poll thread past
///   the join budget). A panicking emitter is contained: the poll thread
///   survives, `last_error` records the panic.
pub struct MetaSchemaWatcher {
    loader: Arc<MetaSchemaLoader>,
    stop: Arc<AtomicBool>,
    last_error: Arc<Mutex<Option<String>>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl MetaSchemaWatcher {
    /// Spawn the watcher over the shared loader. `poll_interval` is clamped
    /// to ≥10 ms (busy-spin guard); pathological values like `Duration::MAX`
    /// are safe (the sliced sleep uses saturating arithmetic — no overflow).
    pub fn spawn(
        loader: Arc<MetaSchemaLoader>,
        emitter: Option<Arc<dyn EventBusEmit>>,
        poll_interval: Duration,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let last_error = Arc::new(Mutex::new(None));
        let interval = poll_interval.max(MIN_SCHEMA_POLL_INTERVAL);

        let thread_loader = Arc::clone(&loader);
        let thread_stop = Arc::clone(&stop);
        let thread_err = Arc::clone(&last_error);
        let handle = std::thread::Builder::new()
            .name("meta-schema-watcher".to_string())
            .spawn(move || {
                watcher_loop(thread_loader, emitter, interval, thread_stop, thread_err);
            })
            .expect("failed to spawn meta-schema watcher thread");

        Self {
            loader,
            stop,
            last_error,
            handle: Some(handle),
        }
    }

    /// The shared loader (accessor surface for the future harness slice —
    /// `current()` reflects every applied reload).
    pub fn loader(&self) -> Arc<MetaSchemaLoader> {
        Arc::clone(&self.loader)
    }

    /// Last fail-closed rejection / emission failure (None after the most
    /// recent clean reload). Mirrors the `RuntimeConfigWatcher::last_error`
    /// observability posture.
    pub fn last_error(&self) -> Option<String> {
        self.last_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Liveness signal: `true` while the poll thread is running. A tick-body
    /// panic outside the emit containment kills the thread WITHOUT touching
    /// `last_error` — this accessor is how such a death is observable.
    pub fn is_alive(&self) -> bool {
        self.handle
            .as_ref()
            .map(|h| !h.is_finished())
            .unwrap_or(false)
    }

    /// Stop the watcher and join the poll thread (bounded — see the struct
    /// docs' shutdown notes). Equivalent to dropping the watcher; provided
    /// for explicit shutdown at call sites that want the join to happen NOW.
    pub fn stop(mut self) {
        self.shutdown();
        // Drop runs next, but `handle` is now None — its second pass no-ops.
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Release);
        let Some(handle) = self.handle.take() else {
            return;
        };
        let mut polls = 0u32;
        while !handle.is_finished() && polls < JOIN_POLL_LIMIT {
            std::thread::sleep(JOIN_POLL_STEP);
            polls += 1;
        }
        if handle.is_finished() {
            // A panicked poll thread surfaces here as Err — deliberately
            // IGNORED (never re-panic: panic-in-drop aborts the process).
            // Pre-drop liveness diagnosis is `is_alive()`'s job.
            let _ = handle.join();
        } else {
            // Wedged tick (slow filesystem / hostile input past the read
            // cap's reach): record and detach. The stop flag is set, so the
            // zombie tick's stop-gated writes cannot overwrite this record,
            // emit, or clear anything once it unwedges.
            *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(
                "watcher thread did not terminate within the join budget; detached".to_string(),
            );
            drop(handle);
        }
    }
}

impl Drop for MetaSchemaWatcher {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Record a fail-closed diagnostic — NO-OP once the stop flag is set (one
/// structural rule covering every tick arm, so a post-detach zombie tick can
/// never overwrite the Drop-recorded "detached" diagnostic).
fn record_error(stop: &AtomicBool, slot: &Mutex<Option<String>>, msg: String) {
    if stop.load(Ordering::Acquire) {
        return;
    }
    *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(msg);
}

/// Clear the diagnostic on a clean reload — same stop-gating as `record_error`.
fn clear_error(stop: &AtomicBool, slot: &Mutex<Option<String>>) {
    if stop.load(Ordering::Acquire) {
        return;
    }
    *slot.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

fn watcher_loop(
    loader: Arc<MetaSchemaLoader>,
    emitter: Option<Arc<dyn EventBusEmit>>,
    interval: Duration,
    stop: Arc<AtomicBool>,
    last_error: Arc<Mutex<Option<String>>>,
) {
    // NO seed-read special case: `last_seen` starts `None` and the FIRST tick
    // runs the normal logic below. An unchanged file produces a harmless
    // equal-value reload with an empty diff (no event); a file that diverged
    // from the loader between load and spawn is APPLIED and emitted as a real
    // change; a FIFO/oversize file at spawn hits the same hardened arms as
    // any later tick (a separate unhardened seed read would reopen all three
    // defect classes).
    let mut last_seen: Option<Vec<u8>> = None;

    while !stop.load(Ordering::Acquire) {
        tick(
            &loader,
            emitter.as_ref(),
            &stop,
            &last_error,
            &mut last_seen,
        );

        // Sliced sleep with saturating arithmetic (Duration::MAX-safe; no
        // Instant deadline math that could overflow-panic the thread).
        let mut remaining = interval;
        while !stop.load(Ordering::Acquire) && remaining > Duration::ZERO {
            let slice = remaining.min(STOP_CHECK_SLICE);
            std::thread::sleep(slice);
            remaining = remaining.saturating_sub(slice);
        }
    }
}

fn tick(
    loader: &Arc<MetaSchemaLoader>,
    emitter: Option<&Arc<dyn EventBusEmit>>,
    stop: &AtomicBool,
    last_error: &Mutex<Option<String>>,
    last_seen: &mut Option<Vec<u8>>,
) {
    match read_schema_bounded(loader.schema_path()) {
        SchemaRead::Absent => {
            if last_seen.is_some() {
                // Deleted-after-present: fail-closed (previous schema stays in
                // effect); `None` makes recreation — even with byte-identical
                // content — register as a change, whose reload clears the
                // record below.
                record_error(
                    stop,
                    last_error,
                    "schema file removed; retaining previous schema".to_string(),
                );
                *last_seen = None;
            }
            // Initially/perpetually absent: NOT an error (default schema in
            // effect — the load_from_disk NotFound-is-default contract).
        }
        SchemaRead::BeforeReadError(msg) => {
            // General invariant: failure BEFORE content was successfully read
            // ⇒ last_seen = None, so restoring a healthy byte-identical file
            // is detected as a change → reload → unconditional clear (no
            // permanent phantom error after recovery).
            record_error(stop, last_error, msg);
            *last_seen = None;
        }
        SchemaRead::Oversize(bytes) => {
            if last_seen.as_deref() == Some(bytes.as_slice()) {
                return; // identical oversize content — no per-tick re-thrash
            }
            record_error(
                stop,
                last_error,
                format!(
                    "schema file exceeds {MAX_META_SCHEMA_SIZE} bytes; retaining previous schema"
                ),
            );
            // Failure AFTER a successful (capped) read ⇒ store the bytes.
            *last_seen = Some(bytes);
        }
        SchemaRead::Content(bytes) => {
            if last_seen.as_deref() == Some(bytes.as_slice()) {
                return; // unchanged
            }
            // Post-detach zombie containment: never APPLY after stop.
            if stop.load(Ordering::Acquire) {
                return;
            }
            let content = match std::str::from_utf8(&bytes) {
                Ok(s) => s,
                Err(_) => {
                    record_error(
                        stop,
                        last_error,
                        "schema file is not valid UTF-8; retaining previous schema".to_string(),
                    );
                    *last_seen = Some(bytes);
                    return;
                }
            };
            let prev = loader.current();
            match loader.reload_from_yaml(content) {
                Err(e) => {
                    record_error(
                        stop,
                        last_error,
                        format!("schema reload rejected (previous schema retained): {e}"),
                    );
                    *last_seen = Some(bytes);
                }
                Ok(()) => {
                    // Re-check stop IMMEDIATELY after reload-Ok, BEFORE any
                    // last_error write: a tick that wedged inside the parse
                    // past the join budget must not erase the detached record
                    // or emit (the Arc swap itself is the disclosed,
                    // unavoidable residue).
                    if stop.load(Ordering::Acquire) {
                        return;
                    }
                    clear_error(stop, last_error);
                    let changes = schema_changes(&prev, &loader.current());
                    *last_seen = Some(bytes);
                    if changes.is_empty() {
                        return; // equal-value reload (tick-0, revert-to-original)
                    }
                    if stop.load(Ordering::Acquire) {
                        return; // pre-emit stop re-check
                    }
                    if let Some(em_shared) = emitter {
                        let em = Arc::clone(em_shared);
                        // Two-catch discipline (mirrors the config-side bridge;
                        // this thread's own Arc keeps the refcount ≥2 so the
                        // in-catch drop is structurally never last-ref, but the
                        // discipline stays uniform).
                        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| {
                            crate::events::emit_schema_reloaded(&*em, &changes)
                        })) {
                            let msg = format!(
                                "schema-reload event emitter panicked: {}",
                                panic_payload_to_message(payload)
                            );
                            record_error(stop, last_error, msg);
                        }
                        if let Err(payload) = catch_unwind(AssertUnwindSafe(move || drop(em))) {
                            let msg = format!(
                                "schema-reload event emitter Drop panicked: {}",
                                panic_payload_to_message(payload)
                            );
                            record_error(stop, last_error, msg);
                        }
                    }
                }
            }
        }
    }
}

/// Convert a caught panic payload into a diagnostic message, neutralizing
/// hostile payloads: `String`/`&str` extracted and dropped normally (their
/// `Drop` cannot panic); unknown payload types are `mem::forget`-ten — a
/// `panic_any` payload with a panicking `Drop` would otherwise re-panic
/// outside the catch and kill the poll thread. The forget leaks at most one
/// small allocation per panicking emit, rate-limited by real schema-file
/// changes (the no-leak property holds only for the `String`/`&str` case).
fn panic_payload_to_message(payload: Box<dyn std::any::Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(s) => *s,
        Err(payload) => match payload.downcast::<&'static str>() {
            Ok(s) => (*s).to_string(),
            Err(payload) => {
                std::mem::forget(payload);
                "non-string panic payload (forgotten)".to_string()
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_schema_has_four_required_fields() {
        // ADR 2026-06-29 Decision 1: entity `type` is a 4th required field.
        let s = MetaSchema::default();
        assert_eq!(s.required.len(), 4);
        assert!(s.required.contains_key("name"));
        assert!(s.required.contains_key("slug"));
        assert!(s.required.contains_key("description"));
        assert!(s.required.contains_key("type"));
        assert!(s.optional.contains_key("tags"));
        assert!(s.optional.contains_key("status"));
    }

    // --- AC-18: entity `type` deterministic auto-population (MODULE-002-T52) ---

    #[test]
    fn t52_entity_type_resolver_defaults_table() {
        // Non-Markdown file → asset.
        assert_eq!(entity_type("photo.png", false, None), "asset");
        // Markdown without frontmatter type → document.
        assert_eq!(entity_type("notes.md", false, None), "document");
        // Markdown WITH frontmatter type → that value.
        assert_eq!(entity_type("notes.md", false, Some("project")), "project");
        // Directory/scope → collection (frontmatter ignored).
        assert_eq!(entity_type("research", true, Some("project")), "collection");
        // Empty/whitespace frontmatter type is treated as absent → document.
        assert_eq!(entity_type("notes.md", false, Some("   ")), "document");
        // .markdown extension also counts as Markdown.
        assert_eq!(entity_type("readme.markdown", false, None), "document");
    }

    #[test]
    fn t52_default_schema_auto_generates_type() {
        let s = MetaSchema::default();
        // .md with frontmatter type via auto_generate (file default, is_dir=false).
        let body = b"---\ntype: project\nname: X\n---\n# heading\n";
        assert_eq!(
            s.auto_generate("type", "roadmap.md", body),
            Some("project".to_string())
        );
        // .md without frontmatter → document.
        assert_eq!(
            s.auto_generate("type", "notes.md", b"# just a heading\n"),
            Some("document".to_string())
        );
        // non-md → asset.
        assert_eq!(
            s.auto_generate("type", "photo.png", &[0xFF, 0xD8]),
            Some("asset".to_string())
        );
    }

    #[test]
    fn t52_parse_and_validate_accepts_entity_type_default() {
        let yaml = r#"
required:
  name:
    type: string
    auto: filename
  slug:
    type: string
    auto: filename-to-slug
  description:
    type: string
    auto: content-extract
  type:
    type: string
    auto: entity-type-default
optional:
  tags:
    type: list<string>
    default: []
"#;
        let s = parse_and_validate(yaml).unwrap();
        assert_eq!(s.required.len(), 4);
        assert_eq!(
            s.required.get("type").unwrap().auto,
            Some(AutoRule::EntityTypeDefault)
        );
    }

    // --- AC-18: bounded frontmatter parser (MODULE-002-T53) ---

    #[test]
    fn t53_parse_frontmatter_type_cases() {
        // Well-formed frontmatter.
        assert_eq!(
            parse_frontmatter_type(b"---\ntype: work-item\nname: A\n---\nbody"),
            Some("work-item".to_string())
        );
        // No frontmatter delimiter.
        assert_eq!(parse_frontmatter_type(b"# heading\nbody"), None);
        // Malformed (no closing ---).
        assert_eq!(parse_frontmatter_type(b"---\ntype: x\nno closing"), None);
        // Empty type → None (absent → caller falls back to document).
        assert_eq!(
            parse_frontmatter_type(b"---\ntype: \"\"\nname: A\n---\n"),
            None
        );
        // Whitespace-only type → None.
        assert_eq!(parse_frontmatter_type(b"---\ntype: \"   \"\n---\n"), None);
        // No `type` key.
        assert_eq!(parse_frontmatter_type(b"---\nname: A\n---\n"), None);
    }

    #[test]
    fn t53_parse_frontmatter_type_is_bounded() {
        // A frontmatter whose closing `---` (and the `type`) sit PAST the 8 KiB
        // head window: the closing delimiter is never found within the scanned
        // head → None (falls back to `document`); the whole file is never read.
        let mut huge = String::from("---\n");
        huge.push_str(&"x: y\n".repeat(4000)); // > 8 KiB before the close/`type`
        huge.push_str("type: project\n---\n");
        assert_eq!(parse_frontmatter_type(huge.as_bytes()), None);
    }

    #[test]
    fn t53_parse_frontmatter_type_utf8_boundary_recovery() {
        // Audit r7 Warning regression guard: a small, valid frontmatter `type`
        // at the very top, followed by CJK content that pushes the body well
        // past 8 KiB with a 3-byte char straddling the head boundary. The
        // valid top-of-file block must still be parsed (NOT poisoned to None by
        // the far-away boundary split).
        let mut body = String::from("---\ntype: project\n---\n");
        body.push_str(&"あ".repeat(4000)); // 3 bytes each → ~12 KiB, boundary mid-char
        assert!(!body.is_char_boundary(MAX_FRONTMATTER_HEAD_BYTES)); // the split is real
        assert_eq!(
            parse_frontmatter_type(body.as_bytes()),
            Some("project".to_string())
        );
    }

    #[test]
    fn t53_parse_frontmatter_type_alias_bomb_is_bounded() {
        // Adversarial-round guard: a YAML alias-bomb hidden in an unrelated
        // frontmatter field must NOT amplify (deserializing the whole block to a
        // `serde_yml::Value` would force a ~200 MB transient; the shallow struct
        // `ignore_any`-skips the bomb field). The valid `type` is still read. If
        // this regressed to Value-deserialize, the test would OOM/hang rather
        // than complete. Run a few iterations to keep any leak/spike observable.
        let mut block = String::from("type: project\n");
        block.push_str("anchor: &a [");
        for i in 0..1400 {
            if i > 0 {
                block.push(',');
            }
            block.push('0');
        }
        block.push_str("]\n");
        block.push_str("bomb: [");
        let mut first = true;
        while block.len() < 7900 {
            if !first {
                block.push(',');
            }
            block.push_str("*a");
            first = false;
        }
        block.push_str("]\n");
        let body = format!("---\n{block}---\n");
        assert!(body.len() <= MAX_FRONTMATTER_HEAD_BYTES + 16);
        for _ in 0..50 {
            assert_eq!(
                parse_frontmatter_type(body.as_bytes()),
                Some("project".to_string())
            );
        }
        // A bomb with NO valid `type` (or a non-scalar type) → None, not an OOM.
        let no_type = body.replace("type: project\n", "");
        assert_eq!(parse_frontmatter_type(no_type.as_bytes()), None);
    }

    #[test]
    fn t53_parse_frontmatter_type_value_length_and_control_capped() {
        // Oversized `type` (> MAX_ENTITY_TYPE_BYTES) → document fallback.
        let long = "x".repeat(MAX_ENTITY_TYPE_BYTES + 1);
        let body = format!("---\ntype: {long}\n---\n");
        assert_eq!(parse_frontmatter_type(body.as_bytes()), None);
        // A boundary-length value is accepted.
        let ok = "y".repeat(MAX_ENTITY_TYPE_BYTES);
        let body_ok = format!("---\ntype: {ok}\n---\n");
        assert_eq!(parse_frontmatter_type(body_ok.as_bytes()), Some(ok));
        // A multiline / control-char `type` (YAML block scalar) → document fallback.
        let body_ml = "---\ntype: \"a\\nb\"\n---\n";
        assert_eq!(parse_frontmatter_type(body_ml.as_bytes()), None);
    }

    #[test]
    fn auto_generate_filename_strips_extension() {
        let s = MetaSchema::default();
        assert_eq!(
            s.auto_generate("name", "my-doc.md", b""),
            Some("my-doc".to_string())
        );
        assert_eq!(
            s.auto_generate("name", "no-extension", b""),
            Some("no-extension".to_string())
        );
    }

    #[test]
    fn auto_generate_slug_lowercases_and_replaces() {
        let s = MetaSchema::default();
        assert_eq!(
            s.auto_generate("slug", "My Doc.md", b""),
            Some("my-doc".to_string())
        );
        assert_eq!(
            s.auto_generate("slug", "AB_CD.txt", b""),
            Some("ab-cd".to_string())
        );
    }

    #[test]
    fn auto_generate_description_first_line() {
        let s = MetaSchema::default();
        let out = s
            .auto_generate("description", "f.md", b"# Hello\n\nbody")
            .unwrap();
        assert_eq!(out, "Hello");
    }

    #[test]
    fn auto_generate_description_caps_length() {
        let s = MetaSchema::default();
        let body = "x".repeat(1000);
        let out = s
            .auto_generate("description", "f.txt", body.as_bytes())
            .unwrap();
        assert_eq!(out.len(), 500);
    }

    #[test]
    fn auto_generate_description_empty_for_binary() {
        let s = MetaSchema::default();
        let out = s
            .auto_generate("description", "img.png", &[0xFF, 0xD8, 0xFF, 0xE0])
            .unwrap();
        assert_eq!(out, "");
    }

    #[test]
    fn parse_valid_yaml_schema() {
        let yaml = r#"
required:
  name:
    type: string
    auto: filename
  slug:
    type: string
    auto: filename-to-slug
  description:
    type: string
    auto: content-extract
optional:
  tags:
    type: list<string>
    default: []
  status:
    type: [draft, active, archived]
    default: active
"#;
        let s = parse_and_validate(yaml).unwrap();
        assert_eq!(s.required.len(), 3);
        assert_eq!(s.optional.len(), 2);
    }

    #[test]
    fn parse_rejects_required_without_auto() {
        let yaml = r#"
required:
  name:
    type: string
optional: {}
"#;
        let err = parse_and_validate(yaml).unwrap_err();
        match err {
            MetaSchemaError::Validation(s) => {
                assert!(s.contains("auto-generation rule"), "got: {s}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_optional_without_default() {
        let yaml = r#"
required: {}
optional:
  priority:
    type: integer
"#;
        let err = parse_and_validate(yaml).unwrap_err();
        match err {
            MetaSchemaError::Validation(s) => assert!(s.contains("default")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_unknown_auto_rule() {
        let yaml = r#"
required:
  x:
    type: string
    auto: unknown-rule
optional: {}
"#;
        let err = parse_and_validate(yaml).unwrap_err();
        match err {
            MetaSchemaError::Validation(s) => assert!(s.contains("unknown auto-rule")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn loader_reload_from_yaml_swaps_schema() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("schema.yaml");
        let loader = MetaSchemaLoader::new_with_default(path.clone());
        assert_eq!(loader.current().required.len(), 4);

        let yaml = r#"
required:
  name:
    type: string
    auto: filename
optional:
  priority:
    type: integer
    default: 0
"#;
        loader.reload_from_yaml(yaml).unwrap();
        assert_eq!(loader.current().required.len(), 1);
        assert_eq!(loader.current().optional.len(), 1);
        assert!(loader.current().optional.contains_key("priority"));
    }

    #[test]
    fn loader_reload_with_invalid_yaml_keeps_previous() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("schema.yaml");
        let loader = MetaSchemaLoader::new_with_default(path);
        let original_required_len = loader.current().required.len();

        let bad_yaml = r#"
required:
  bad:
    type: string
"#; // missing auto rule
        let err = loader.reload_from_yaml(bad_yaml);
        assert!(err.is_err());
        // Previous schema preserved.
        assert_eq!(loader.current().required.len(), original_required_len);
    }

    #[test]
    fn loader_load_from_disk_missing_returns_default() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.yaml");
        let loader = MetaSchemaLoader::load_from_disk(&path).unwrap();
        assert_eq!(loader.current().required.len(), 4);
    }

    #[test]
    fn loader_reload_from_disk_after_writing_yaml() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("schema.yaml");
        let loader = MetaSchemaLoader::new_with_default(path.clone());
        std::fs::write(
            &path,
            r#"
required:
  name:
    type: string
    auto: filename
optional:
  priority:
    type: integer
    default: 0
"#,
        )
        .unwrap();
        loader.reload_from_disk().unwrap();
        assert_eq!(loader.current().required.len(), 1);
        assert!(loader.current().optional.contains_key("priority"));
    }
}

#[cfg(test)]
mod watcher_tests {
    //! Hotreload pre-build (2026-06-10): MetaSchemaWatcher + SchemaChanges
    //! tests (HR-F1..HR-F17 from the plan's test design; traces to REQ-126/127
    //! and the future harness witnesses SYS-AC-259/260/261 — no flips here).
    //!
    //! Test determinism: schema files are written via temp-file + atomic
    //! rename (excludes the disclosed torn-read window from exact-event-count
    //! assertions); poll-until loops use the same 3 s CI tolerance as the
    //! runtime-side hot-reload tests (the <1 s SLO witness belongs to the
    //! future harness slice).

    use super::*;
    use advance_shared_types::event::Event as BusEvent;
    use std::time::Instant;

    const TEST_POLL: Duration = Duration::from_millis(50);
    const CI_TOLERANCE: Duration = Duration::from_secs(3);

    const SCHEMA_A: &str = r#"
required:
  name:
    type: string
    auto: filename
optional:
  tags:
    type: list<string>
    default: []
"#;

    /// SCHEMA_A plus one new optional field (`priority`).
    const SCHEMA_B: &str = r#"
required:
  name:
    type: string
    auto: filename
optional:
  tags:
    type: list<string>
    default: []
  priority:
    type: integer
    default: 0
"#;

    /// Invalid: required field without an auto-generation rule.
    const SCHEMA_BAD: &str = r#"
required:
  name:
    type: string
optional: {}
"#;

    #[derive(Default)]
    struct RecordingBus {
        events: Mutex<Vec<BusEvent>>,
    }

    impl RecordingBus {
        fn len(&self) -> usize {
            self.events.lock().unwrap().len()
        }
        fn event_type_at(&self, i: usize) -> String {
            self.events.lock().unwrap()[i].event_type.clone()
        }
        fn agent_id_at(&self, i: usize) -> String {
            self.events.lock().unwrap()[i].agent_id.clone()
        }
        fn payload_at(&self, i: usize) -> serde_json::Value {
            self.events.lock().unwrap()[i].payload.clone()
        }
    }

    impl EventBusEmit for RecordingBus {
        fn emit(&self, event: BusEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    struct PanickingBus;
    impl EventBusEmit for PanickingBus {
        fn emit(&self, _event: BusEvent) {
            panic!("hostile emitter panic");
        }
    }

    /// Atomic-rename write (temp file + rename — the recommended writer
    /// pattern; keeps exact-event-count assertions torn-read-free).
    fn write_schema(path: &Path, content: &[u8]) {
        let tmp = path.with_extension("tmp-write");
        std::fs::write(&tmp, content).expect("write tmp schema");
        std::fs::rename(&tmp, path).expect("rename schema into place");
    }

    fn wait_until(deadline: Duration, mut cond: impl FnMut() -> bool) -> bool {
        let start = Instant::now();
        while start.elapsed() < deadline {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        cond()
    }

    // HR-F1: schema_changes buckets + is_empty.
    #[test]
    fn schema_changes_buckets_and_is_empty() {
        let a = parse_and_validate(SCHEMA_A).unwrap();
        let b = parse_and_validate(SCHEMA_B).unwrap();

        // Added optional field.
        let diff = schema_changes(&a, &b);
        assert_eq!(diff.optional_added, vec!["priority"]);
        assert!(diff.required_added.is_empty());
        assert!(diff.required_removed.is_empty());
        assert!(!diff.is_empty());

        // Removed (b -> a reverses to removed).
        let diff_rev = schema_changes(&b, &a);
        assert_eq!(diff_rev.optional_removed, vec!["priority"]);

        // Removed required + changed type.
        let c = parse_and_validate(
            "required: {}\noptional:\n  tags:\n    type: string\n    default: \"x\"\n",
        )
        .unwrap();
        let diff_c = schema_changes(&a, &c);
        assert_eq!(diff_c.required_removed, vec!["name"]);
        assert_eq!(diff_c.optional_changed, vec!["tags"]);

        // Identical -> empty.
        let a2 = parse_and_validate(SCHEMA_A).unwrap();
        assert!(schema_changes(&a, &a2).is_empty());
    }

    // HR-F14: description_max_chars intentionally excluded from the diff.
    #[test]
    fn schema_changes_excludes_description_max_chars() {
        let a = parse_and_validate(SCHEMA_A).unwrap();
        let mut b = parse_and_validate(SCHEMA_A).unwrap();
        b.description_max_chars = 9999;
        assert_ne!(a, b, "PartialEq must see the cap difference");
        assert!(
            schema_changes(&a, &b).is_empty(),
            "the diff deliberately ignores description_max_chars (hardcoded 500 today)"
        );
    }

    // HR-F2 + HR-F4: change detected within tolerance; current() swapped;
    // one event naming the field; auto_generate uses the new schema.
    #[test]
    fn watcher_applies_change_and_emits() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("meta-schema.yaml");
        write_schema(&path, SCHEMA_A.as_bytes());

        let loader = Arc::new(MetaSchemaLoader::load_from_disk(&path).unwrap());
        let bus = Arc::new(RecordingBus::default());
        let watcher = MetaSchemaWatcher::spawn(
            Arc::clone(&loader),
            Some(bus.clone() as Arc<dyn EventBusEmit>),
            TEST_POLL,
        );
        assert!(watcher.is_alive());

        // HR-F4 leg: add a REQUIRED field with an auto rule + the optional.
        let schema_with_required: &str = r#"
required:
  name:
    type: string
    auto: filename
  slug:
    type: string
    auto: filename-to-slug
optional:
  tags:
    type: list<string>
    default: []
  priority:
    type: integer
    default: 0
"#;
        write_schema(&path, schema_with_required.as_bytes());

        assert!(
            wait_until(CI_TOLERANCE, || bus.len() >= 1),
            "no runtime.schema_reloaded within the CI tolerance"
        );
        assert_eq!(bus.len(), 1, "exactly one event per applied reload");
        assert_eq!(bus.event_type_at(0), "runtime.schema_reloaded");
        assert_eq!(bus.agent_id_at(0), "runtime");
        assert_eq!(
            bus.payload_at(0)["required_added"],
            serde_json::json!(["slug"])
        );
        assert_eq!(
            bus.payload_at(0)["optional_added"],
            serde_json::json!(["priority"])
        );
        assert_eq!(bus.payload_at(0)["required_added_count"], 1);

        // current() swapped; the NEW field participates in auto_generate.
        let current = loader.current();
        assert!(current.required.contains_key("slug"));
        assert_eq!(
            current.auto_generate("slug", "My Doc.md", b""),
            Some("my-doc".to_string()),
            "auto_generate must use the newly-declared field after reload"
        );
        assert!(watcher.last_error().is_none());
        watcher.stop();
    }

    // HR-F3 + HR-F11: invalid schema and invalid UTF-8 are fail-closed
    // (no swap, no event, last_error); a subsequent valid edit recovers.
    #[test]
    fn invalid_schema_fail_closed_then_recovers() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("meta-schema.yaml");
        write_schema(&path, SCHEMA_A.as_bytes());

        let loader = Arc::new(MetaSchemaLoader::load_from_disk(&path).unwrap());
        let bus = Arc::new(RecordingBus::default());
        let watcher = MetaSchemaWatcher::spawn(
            Arc::clone(&loader),
            Some(bus.clone() as Arc<dyn EventBusEmit>),
            TEST_POLL,
        );
        let before = loader.current();

        // Invalid schema (required without auto rule).
        write_schema(&path, SCHEMA_BAD.as_bytes());
        assert!(
            wait_until(CI_TOLERANCE, || watcher.last_error().is_some()),
            "rejection must be recorded in last_error"
        );
        assert_eq!(bus.len(), 0, "fail-closed rejection must not emit");
        assert_eq!(
            loader.current().required.len(),
            before.required.len(),
            "previous schema must stay in effect"
        );

        // HR-F11: invalid UTF-8 bytes are equally fail-closed.
        write_schema(&path, &[0xFF, 0xFE, 0x00, 0x01]);
        assert!(wait_until(CI_TOLERANCE, || watcher
            .last_error()
            .map(|e| e.contains("UTF-8"))
            .unwrap_or(false)));
        assert_eq!(bus.len(), 0);

        // Recovery: valid new schema applies + emits + clears the error.
        write_schema(&path, SCHEMA_B.as_bytes());
        assert!(
            wait_until(CI_TOLERANCE, || bus.len() >= 1),
            "valid write after rejections must resume emission"
        );
        assert!(wait_until(CI_TOLERANCE, || watcher.last_error().is_none()));
        assert!(loader.current().optional.contains_key("priority"));
        watcher.stop();
    }

    // HR-F5: oversize schema file is fail-closed (no swap, no event).
    #[test]
    fn oversize_schema_fail_closed() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("meta-schema.yaml");
        write_schema(&path, SCHEMA_A.as_bytes());

        let loader = Arc::new(MetaSchemaLoader::load_from_disk(&path).unwrap());
        let bus = Arc::new(RecordingBus::default());
        let watcher = MetaSchemaWatcher::spawn(
            Arc::clone(&loader),
            Some(bus.clone() as Arc<dyn EventBusEmit>),
            TEST_POLL,
        );

        let oversize = vec![b'#'; (MAX_META_SCHEMA_SIZE + 1024) as usize];
        write_schema(&path, &oversize);
        assert!(wait_until(CI_TOLERANCE, || watcher
            .last_error()
            .map(|e| e.contains("exceeds"))
            .unwrap_or(false)));
        assert_eq!(bus.len(), 0);
        assert!(loader.current().required.contains_key("name"));
        watcher.stop();
    }

    // HR-F6: stop() joins promptly; no reloads after stop.
    #[test]
    fn stop_joins_promptly_and_halts_reloads() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("meta-schema.yaml");
        write_schema(&path, SCHEMA_A.as_bytes());

        let loader = Arc::new(MetaSchemaLoader::load_from_disk(&path).unwrap());
        let watcher = MetaSchemaWatcher::spawn(Arc::clone(&loader), None, TEST_POLL);
        assert!(watcher.is_alive());

        let start = Instant::now();
        watcher.stop();
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "healthy stop must join promptly, took {:?}",
            start.elapsed()
        );

        // No reloads after stop.
        write_schema(&path, SCHEMA_B.as_bytes());
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            !loader.current().optional.contains_key("priority"),
            "no reload may be applied after stop()"
        );
    }

    // HR-F7: deleted-after-present is fail-closed; recreation reloads + emits.
    #[test]
    fn deleted_then_recreated_recovers() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("meta-schema.yaml");
        write_schema(&path, SCHEMA_A.as_bytes());

        let loader = Arc::new(MetaSchemaLoader::load_from_disk(&path).unwrap());
        let bus = Arc::new(RecordingBus::default());
        let watcher = MetaSchemaWatcher::spawn(
            Arc::clone(&loader),
            Some(bus.clone() as Arc<dyn EventBusEmit>),
            TEST_POLL,
        );
        // Let tick-0 see the file once so deletion is a Some -> None transition.
        assert!(wait_until(CI_TOLERANCE, || watcher.last_error().is_none()));
        std::thread::sleep(TEST_POLL * 3);

        std::fs::remove_file(&path).unwrap();
        assert!(wait_until(CI_TOLERANCE, || watcher
            .last_error()
            .map(|e| e.contains("removed"))
            .unwrap_or(false)));
        assert!(
            loader.current().required.contains_key("name"),
            "previous schema retained after deletion"
        );

        // Recreate with DIFFERENT content -> reload + event + clear.
        write_schema(&path, SCHEMA_B.as_bytes());
        assert!(wait_until(CI_TOLERANCE, || bus.len() >= 1));
        assert!(wait_until(CI_TOLERANCE, || watcher.last_error().is_none()));
        assert!(loader.current().optional.contains_key("priority"));
        watcher.stop();
    }

    // HR-F8: emitter None -> reloads still work.
    #[test]
    fn no_emitter_reload_works() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("meta-schema.yaml");
        write_schema(&path, SCHEMA_A.as_bytes());

        let loader = Arc::new(MetaSchemaLoader::load_from_disk(&path).unwrap());
        let watcher = MetaSchemaWatcher::spawn(Arc::clone(&loader), None, TEST_POLL);

        write_schema(&path, SCHEMA_B.as_bytes());
        assert!(wait_until(CI_TOLERANCE, || loader
            .current()
            .optional
            .contains_key("priority")));
        watcher.stop();
    }

    // HR-F9 (unix): FIFO swapped in mid-run is rejected without blocking the
    // poll thread; stop() still joins promptly.
    #[cfg(unix)]
    #[test]
    fn fifo_rejected_without_blocking() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("meta-schema.yaml");
        write_schema(&path, SCHEMA_A.as_bytes());

        let loader = Arc::new(MetaSchemaLoader::load_from_disk(&path).unwrap());
        let watcher = MetaSchemaWatcher::spawn(Arc::clone(&loader), None, TEST_POLL);
        assert!(wait_until(CI_TOLERANCE, || watcher.last_error().is_none()));

        // Swap the schema path for a FIFO (mkfifo subprocess: cap-fs is
        // #![forbid(unsafe_code)], so the libc::mkfifo FFI is not usable here).
        std::fs::remove_file(&path).unwrap();
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("mkfifo spawns");
        assert!(status.success(), "mkfifo failed");

        assert!(
            wait_until(CI_TOLERANCE, || watcher
                .last_error()
                .map(|e| e.contains("not a regular file") || e.contains("removed"))
                .unwrap_or(false)),
            "non-regular file must be rejected fail-closed; got {:?}",
            watcher.last_error()
        );
        assert!(watcher.is_alive(), "poll thread must NOT block on the FIFO");
        assert!(
            loader.current().required.contains_key("name"),
            "previous schema retained"
        );

        let start = Instant::now();
        watcher.stop();
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "stop must join promptly with a FIFO at the path, took {:?}",
            start.elapsed()
        );
    }

    // HR-F10: tick-0 semantics (no seed-read special case).
    #[test]
    fn tick_zero_semantics() {
        // (a) Unchanged existing file -> no event on first ticks.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("meta-schema.yaml");
        write_schema(&path, SCHEMA_A.as_bytes());
        let loader = Arc::new(MetaSchemaLoader::load_from_disk(&path).unwrap());
        let bus = Arc::new(RecordingBus::default());
        let watcher = MetaSchemaWatcher::spawn(
            Arc::clone(&loader),
            Some(bus.clone() as Arc<dyn EventBusEmit>),
            TEST_POLL,
        );
        std::thread::sleep(TEST_POLL * 6);
        assert_eq!(
            bus.len(),
            0,
            "unchanged file must not produce a startup event"
        );
        assert!(watcher.last_error().is_none());
        watcher.stop();

        // (b) File absent -> NOT an error (NotFound-is-default contract).
        let dir_b = tempfile::TempDir::new().unwrap();
        let absent = dir_b.path().join("meta-schema.yaml");
        let loader_b = Arc::new(MetaSchemaLoader::load_from_disk(&absent).unwrap());
        let watcher_b = MetaSchemaWatcher::spawn(Arc::clone(&loader_b), None, TEST_POLL);
        std::thread::sleep(TEST_POLL * 6);
        assert!(
            watcher_b.last_error().is_none(),
            "perpetual absence must not spam last_error"
        );
        watcher_b.stop();

        // (c) Loader divergent from on-disk content at spawn -> tick-0 APPLIES
        // the file content and emits the real change.
        let dir_c = tempfile::TempDir::new().unwrap();
        let path_c = dir_c.path().join("meta-schema.yaml");
        write_schema(&path_c, SCHEMA_B.as_bytes());
        let loader_c = Arc::new(MetaSchemaLoader::from_yaml(path_c.clone(), SCHEMA_A).unwrap());
        let bus_c = Arc::new(RecordingBus::default());
        let watcher_c = MetaSchemaWatcher::spawn(
            Arc::clone(&loader_c),
            Some(bus_c.clone() as Arc<dyn EventBusEmit>),
            TEST_POLL,
        );
        assert!(
            wait_until(CI_TOLERANCE, || bus_c.len() >= 1),
            "divergent-at-spawn content must be applied + emitted by tick-0"
        );
        assert_eq!(
            bus_c.payload_at(0)["optional_added"],
            serde_json::json!(["priority"])
        );
        assert!(loader_c.current().optional.contains_key("priority"));
        watcher_c.stop();
    }

    // HR-F12: two sequential edits -> two events with STEP-LOCAL change sets.
    #[test]
    fn sequential_edits_emit_step_local_changes() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("meta-schema.yaml");
        write_schema(&path, SCHEMA_A.as_bytes());

        let loader = Arc::new(MetaSchemaLoader::load_from_disk(&path).unwrap());
        let bus = Arc::new(RecordingBus::default());
        let watcher = MetaSchemaWatcher::spawn(
            Arc::clone(&loader),
            Some(bus.clone() as Arc<dyn EventBusEmit>),
            TEST_POLL,
        );

        write_schema(&path, SCHEMA_B.as_bytes());
        assert!(wait_until(CI_TOLERANCE, || bus.len() >= 1));

        let schema_c: &str = r#"
required:
  name:
    type: string
    auto: filename
  slug:
    type: string
    auto: filename-to-slug
optional:
  tags:
    type: list<string>
    default: []
  priority:
    type: integer
    default: 0
"#;
        write_schema(&path, schema_c.as_bytes());
        assert!(wait_until(CI_TOLERANCE, || bus.len() >= 2));

        assert_eq!(bus.len(), 2);
        assert_eq!(
            bus.payload_at(0)["optional_added"],
            serde_json::json!(["priority"]),
            "first event carries only the first delta"
        );
        assert_eq!(
            bus.payload_at(1)["required_added"],
            serde_json::json!(["slug"]),
            "second event is step-local"
        );
        assert_eq!(
            bus.payload_at(1)["optional_added"],
            serde_json::json!([]),
            "second event must NOT re-report the first delta"
        );
        assert_eq!(bus.event_type_at(1), "runtime.schema_reloaded");
        assert_eq!(bus.agent_id_at(1), "runtime");
        watcher.stop();
    }

    // HR-F13: payload bound — bucket cap, name truncation, < 64 KiB serialized.
    #[test]
    fn payload_bounded_under_bus_cap() {
        let bus = RecordingBus::default();
        let mut changes = SchemaChanges::default();
        let long_name = "x".repeat(1100);
        for i in 0..200 {
            changes.optional_added.push(format!("{long_name}-{i:04}"));
        }
        crate::events::emit_schema_reloaded(&bus, &changes);

        assert_eq!(bus.len(), 1);
        let payload = bus.payload_at(0);
        let names = payload["optional_added"].as_array().unwrap();
        assert_eq!(names.len(), 64, "bucket capped at 64 names");
        for n in names {
            assert!(
                n.as_str().unwrap().len() <= 64,
                "each name truncated to 64 bytes"
            );
        }
        assert_eq!(payload["optional_added_count"], 200, "full count preserved");
        let serialized = serde_json::to_string(&payload).unwrap();
        assert!(
            serialized.len() < 64 * 1024,
            "payload must stay under the 64 KiB bus bound, got {} bytes",
            serialized.len()
        );
    }

    // HR-F15: recovery-to-identical-content from every before/after-read
    // failure class clears the stale error (per-arm last_seen semantics).
    #[cfg(unix)]
    #[test]
    fn recovery_to_identical_content_clears_errors() {
        use std::os::unix::fs::PermissionsExt;

        // FIFO-then-restore-identical.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("meta-schema.yaml");
        write_schema(&path, SCHEMA_A.as_bytes());
        let loader = Arc::new(MetaSchemaLoader::load_from_disk(&path).unwrap());
        let bus = Arc::new(RecordingBus::default());
        let watcher = MetaSchemaWatcher::spawn(
            Arc::clone(&loader),
            Some(bus.clone() as Arc<dyn EventBusEmit>),
            TEST_POLL,
        );
        std::thread::sleep(TEST_POLL * 3); // let tick-0 see the healthy file

        std::fs::remove_file(&path).unwrap();
        assert!(std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success());
        assert!(wait_until(CI_TOLERANCE, || watcher.last_error().is_some()));

        std::fs::remove_file(&path).unwrap();
        write_schema(&path, SCHEMA_A.as_bytes()); // byte-identical restore
        assert!(
            wait_until(CI_TOLERANCE, || watcher.last_error().is_none()),
            "identical-content restore must clear the stale error; got {:?}",
            watcher.last_error()
        );
        assert_eq!(bus.len(), 0, "equal-value recovery must not emit");

        // Oversize-then-shrink-to-identical.
        let oversize = vec![b'#'; (MAX_META_SCHEMA_SIZE + 1024) as usize];
        write_schema(&path, &oversize);
        assert!(wait_until(CI_TOLERANCE, || watcher
            .last_error()
            .map(|e| e.contains("exceeds"))
            .unwrap_or(false)));
        write_schema(&path, SCHEMA_A.as_bytes());
        assert!(
            wait_until(CI_TOLERANCE, || watcher.last_error().is_none()),
            "shrink-to-identical must clear the oversize error"
        );
        assert_eq!(bus.len(), 0);

        // chmod-000-then-restore-identical (open-Err arm; skipped for root,
        // which bypasses permission checks).
        if !nix_is_root() {
            let perms = std::fs::Permissions::from_mode(0o000);
            std::fs::set_permissions(&path, perms).unwrap();
            assert!(wait_until(CI_TOLERANCE, || watcher.last_error().is_some()));
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(
                wait_until(CI_TOLERANCE, || watcher.last_error().is_none()),
                "permission restore with identical content must clear the error"
            );
            assert_eq!(bus.len(), 0);
        }
        watcher.stop();
    }

    #[cfg(unix)]
    fn nix_is_root() -> bool {
        // Best-effort root detection without unsafe/FFI (root bypasses
        // chmod 000, which would invalidate the open-Err leg above).
        std::env::var("USER").map(|u| u == "root").unwrap_or(false)
    }

    // HR-F16: panicking emitter — poll thread survives, last_error records,
    // a subsequent reload still applies (mirror of the runtime-side HR-R7).
    #[test]
    fn panicking_emitter_does_not_kill_the_watcher() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("meta-schema.yaml");
        write_schema(&path, SCHEMA_A.as_bytes());

        let loader = Arc::new(MetaSchemaLoader::load_from_disk(&path).unwrap());
        let watcher = MetaSchemaWatcher::spawn(
            Arc::clone(&loader),
            Some(Arc::new(PanickingBus) as Arc<dyn EventBusEmit>),
            TEST_POLL,
        );

        write_schema(&path, SCHEMA_B.as_bytes());
        assert!(
            wait_until(CI_TOLERANCE, || loader
                .current()
                .optional
                .contains_key("priority")),
            "reload must apply even when the emitter panics"
        );
        assert!(wait_until(CI_TOLERANCE, || watcher
            .last_error()
            .map(|e| e.contains("panicked"))
            .unwrap_or(false)));
        assert!(watcher.is_alive(), "poll thread must survive the panic");

        // A subsequent reload still applies.
        let schema_c = SCHEMA_B.replace("priority", "severity");
        write_schema(&path, schema_c.as_bytes());
        assert!(
            wait_until(CI_TOLERANCE, || loader
                .current()
                .optional
                .contains_key("severity")),
            "watcher must keep reloading after an emitter panic"
        );
        watcher.stop();
    }

    // HR-F17: pathological intervals — clamped, no overflow panic, prompt stop.
    #[test]
    fn pathological_intervals_are_safe() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("meta-schema.yaml");
        write_schema(&path, SCHEMA_A.as_bytes());
        let loader = Arc::new(MetaSchemaLoader::load_from_disk(&path).unwrap());

        // Duration::ZERO -> clamped to the 10 ms floor (no busy spin).
        let w_zero = MetaSchemaWatcher::spawn(Arc::clone(&loader), None, Duration::ZERO);
        std::thread::sleep(Duration::from_millis(100));
        assert!(w_zero.is_alive());
        let start = Instant::now();
        w_zero.stop();
        assert!(start.elapsed() < Duration::from_secs(1));

        // Duration::MAX -> saturating sleep arithmetic (no overflow panic);
        // tick-0 still ran first; stop joins promptly via slice checks.
        let w_max = MetaSchemaWatcher::spawn(Arc::clone(&loader), None, Duration::MAX);
        std::thread::sleep(Duration::from_millis(100));
        assert!(w_max.is_alive(), "Duration::MAX must not panic the thread");
        let start = Instant::now();
        w_max.stop();
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "stop with Duration::MAX must join via slice checks, took {:?}",
            start.elapsed()
        );
    }
}

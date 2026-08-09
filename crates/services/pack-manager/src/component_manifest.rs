//! Pack `component.yaml` parser + REQ-073 constraint surface enforcement
//! for `resolve_pack_component` (AC-14).
//!
//! Schema source: PRD §4.7.4 lines 826-840 (constraint surface for auto-loop
//! evaluator components) plus PRD §4.3 `component-submit-config` base schema.
//! Field names use the hyphenated YAML form (`component-type`, `behavior-ref`,
//! `output-dir`, `restart-policy`, `initial-grants`).
//!
//! Slice C semantic decisions (recorded in MODULE-018 §2.3 / §2.7):
//! - At least one of `binary` / `behavior-ref` MUST be set (PRD says "must
//!   exist", NOT XOR). If both present, `behavior-ref` is preferred — it is
//!   the canonical Pack form per PRD §19.3 example `behavior-ref:
//!   ../../behavior-binaries/...`.
//! - `trigger` MUST be absent or empty (None / null / empty mapping / empty
//!   sequence) — matches PRD line 835 "必须缺失或为空" verbatim.
//! - `id`, `restart-policy`, `delay`, `initial-grants`, `preset` are
//!   accept-and-ignore stubs per PRD line 838. Forward-compat extra fields
//!   (e.g. `retry`, `chain-id`) silently dropped — no `deny_unknown_fields`.
//! - `output-dir` resolution: when declared, return raw `PathBuf::from(s)` —
//!   NOT joined against `install_path`. Preserves §6.4 read-only-pack-tree
//!   invariant; caller (M015 AutoLoopDriver) joins against per-iteration
//!   workspace. When omitted, return `PathBuf::new()` as documented
//!   sentinel for "runtime-generated per PRD §3034".

use std::path::{Path, PathBuf};

use advance_shared_types::capability::{CapRequest, CapabilityId};
use serde::Deserialize;

use crate::{error::PackError, manifest::yaml_has_alias_refs, registry::ComponentManifest};

/// Maximum permitted `component.yaml` size (matches `MAX_PACK_YAML_BYTES`).
const MAX_COMPONENT_YAML_BYTES: u64 = 1024 * 1024;

/// Maximum permitted evaluator binary size in bytes (matches
/// `verify::MAX_PER_ENTRY_BYTES`).
const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;

/// Maximum permitted `output-dir` string length (matches Slice B workflow
/// applier's `MAX_TARGET_PATH_LEN`).
const MAX_OUTPUT_DIR_LEN: usize = 4096;

/// Deserialised view of `component.yaml`. Permissive (`no deny_unknown_fields`)
/// per PRD §4.7.4 line 838's accept-and-ignore policy — unknown fields are
/// silently dropped. The constraint surface is enforced post-parse on the
/// fields we DO recognise.
#[derive(Debug, Deserialize)]
struct ComponentSubmitConfig {
    #[serde(rename = "component-type")]
    component_type: String,

    #[serde(default)]
    binary: Option<String>,

    #[serde(rename = "behavior-ref", default)]
    behavior_ref: Option<String>,

    #[serde(default)]
    capabilities: Vec<CapabilityDecl>,

    #[serde(rename = "output-dir", default)]
    output_dir: Option<String>,

    /// Constraint-surface presence detection only — content is NOT
    /// interpreted. Any non-empty value violates AC-14.
    #[serde(default)]
    trigger: Option<serde_yml::Value>,

    // Accept-and-ignore stubs per PRD §4.7.4 line 838. Captured so
    // `deny_unknown_fields`-less parse doesn't fail on them; bodies are
    // intentionally discarded after deserialisation.
    #[serde(default)]
    id: Option<serde_yml::Value>,
    #[serde(rename = "restart-policy", default)]
    restart_policy: Option<serde_yml::Value>,
    #[serde(default)]
    delay: Option<serde_yml::Value>,
    #[serde(rename = "initial-grants", default)]
    initial_grants: Option<serde_yml::Value>,
    #[serde(default)]
    preset: Option<serde_yml::Value>,
}

#[derive(Debug, Deserialize)]
struct CapabilityDecl {
    capability: String,
    // PRD §4.3 allows additional fields here (e.g. params). Slice C only
    // needs the capability ID; rest silently ignored via absence of
    // `deny_unknown_fields` on this struct.
}

/// Parse `component.yaml` from a component directory and enforce the
/// REQ-073 constraint surface. Returns a tuple of `(binary, capabilities,
/// output_dir, manifest)` for `resolve_pack_component`.
///
/// `install_path` is the pack install root (`/.advance/packs/{name}@{ver}/`);
/// `name` is the bare component name (the directory under `components/`).
pub(crate) fn parse_component_manifest(
    install_path: &Path,
    name: &str,
) -> Result<(Vec<u8>, Vec<CapRequest>, PathBuf, ComponentManifest), PackError> {
    let component_dir = install_path.join("components").join(name);
    let yaml_path = component_dir.join("component.yaml");

    // Pre-parse leaf symlink check for an accurate diagnostic (the
    // O_NOFOLLOW open below catches the same case as ELOOP, but the
    // leaf check produces a friendlier message when the path itself is
    // a symlink at probe time).
    match std::fs::symlink_metadata(&yaml_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(PackError::InvalidManifest(format!(
                "component.yaml missing for component {name:?}: {}",
                yaml_path.display()
            )));
        }
        Err(e) => {
            return Err(PackError::Io {
                path: yaml_path.clone(),
                source: e,
            });
        }
        Ok(leaf_md) => {
            if leaf_md.file_type().is_symlink() {
                return Err(PackError::InvalidManifest(format!(
                    "component.yaml is a symlink (rejected): {}",
                    yaml_path.display()
                )));
            }
        }
    }

    // O_NOFOLLOW + fstat-on-FD + bounded read: closes the TOCTOU window
    // between the leaf check above and the read of `component.yaml`
    // (round 12 W1 fix — the manifest file itself was previously
    // stat-then-read with the 1 MiB cap bypassable by a swap).
    let yaml = open_text_nofollow_bounded(&yaml_path, MAX_COMPONENT_YAML_BYTES, "component.yaml")?;
    if yaml_has_alias_refs(&yaml) {
        return Err(PackError::InvalidManifest(
            "component.yaml contains YAML alias references (`*name`) — rejected to prevent billion-laughs amplification".into(),
        ));
    }
    if !yaml_nesting_within_bound(&yaml) {
        return Err(PackError::InvalidManifest(
            "component.yaml nesting/indentation is too deep — rejected to prevent parse-time resource exhaustion (serde_yml deep-nesting DoS)".into(),
        ));
    }

    let cfg: ComponentSubmitConfig = serde_yml::from_str(&yaml)
        .map_err(|e| PackError::InvalidManifest(format!("component.yaml parse: {e}")))?;

    // ── Constraint surface ──────────────────────────────────────────────

    // (1) component-type MUST be "task".
    if cfg.component_type != "task" {
        return Err(PackError::ConstraintViolation {
            reason: format!(
                "component-type must be `task` for auto-loop evaluator (got {:?})",
                cfg.component_type
            ),
        });
    }

    // (2) trigger MUST be absent or empty (None / null / empty
    //     mapping / empty sequence). PRD §4.7.4 line 835.
    if let Some(ref t) = cfg.trigger {
        if !is_trigger_empty(t) {
            return Err(PackError::ConstraintViolation {
                reason: "trigger must be absent or empty for auto-loop evaluator (REQ-073)".into(),
            });
        }
    }

    // (3) at least one of binary / behavior-ref MUST be set. behavior-ref
    //     preferred when both present (canonical Pack form per PRD §19.3).
    //     `source_field` is the YAML key the selected value came from — used
    //     for accurate diagnostics so a `behavior-ref: ""` failure does NOT
    //     mis-blame the `binary` field.
    let (binary_source, source_field) = match (&cfg.behavior_ref, &cfg.binary) {
        (Some(b), _) => (b.clone(), "behavior-ref"),
        (None, Some(b)) => (b.clone(), "binary"),
        (None, None) => {
            return Err(PackError::ConstraintViolation {
                reason: "either `binary` or `behavior-ref` must be set".into(),
            });
        }
    };

    // Read accept-and-ignore stubs to silence dead-code warnings;
    // these fields are intentionally discarded after deserialisation
    // per PRD §4.7.4 line 838.
    let _ = (
        &cfg.id,
        &cfg.restart_policy,
        &cfg.delay,
        &cfg.initial_grants,
        &cfg.preset,
    );

    // ── Binary path resolution ──────────────────────────────────────────

    if binary_source.is_empty() {
        return Err(PackError::ConstraintViolation {
            reason: format!("`{source_field}` path is empty"),
        });
    }
    if binary_source.contains('\0') {
        return Err(PackError::InvalidManifest(format!(
            "component `{source_field}` path contains null byte: {binary_source:?}"
        )));
    }
    let binary_rel = Path::new(&binary_source);
    if binary_rel.is_absolute() {
        return Err(PackError::InvalidManifest(format!(
            "component `{source_field}` path must be workspace-relative (got absolute): {binary_source:?}"
        )));
    }

    // Join against component_dir (allows `..` segments that PRD §19.3
    // shows for `behavior-ref: ../../behavior-binaries/...`).
    let binary_path = component_dir.join(binary_rel);
    // (i) Pre-canonicalize symlink_metadata check: reject a symlink AT
    //     the path leaf outright. This produces a precise "symlink
    //     rejected" diagnostic even when the symlink target happens to
    //     resolve outside install_path (which the canonicalize+ancestor
    //     check below would otherwise blame as "path escapes").
    let leaf_md = std::fs::symlink_metadata(&binary_path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => PackError::InvalidManifest(format!(
            "component `{source_field}` file declared but missing on disk: {}",
            binary_path.display()
        )),
        _ => PackError::Io {
            path: binary_path.clone(),
            source: e,
        },
    })?;
    if leaf_md.file_type().is_symlink() {
        return Err(PackError::InvalidManifest(format!(
            "component `{source_field}` is a symlink (rejected): {}",
            binary_path.display()
        )));
    }
    // (ii) Canonicalize + ancestor check: catches intermediate symlinks
    //      that resolve outside install_path via parent-dir swaps.
    let install_canon = std::fs::canonicalize(install_path).map_err(|e| PackError::Io {
        path: install_path.to_path_buf(),
        source: e,
    })?;
    let binary_canon = std::fs::canonicalize(&binary_path).map_err(|e| PackError::Io {
        path: binary_path.clone(),
        source: e,
    })?;
    if !binary_canon.starts_with(&install_canon) {
        return Err(PackError::InvalidManifest(format!(
            "component `{source_field}` path escapes install_path: {}",
            binary_path.display()
        )));
    }
    // (iii) Open with O_NOFOLLOW (Unix) so a swap between canonicalize and
    //       open is rejected as ELOOP → InvalidManifest. On non-Unix,
    //       residual TOCTOU bounded by the admin-trust model (§2.9
    //       Slice A pattern).
    let binary = open_and_read_binary_bounded(&binary_canon, source_field)?;

    // ── Capabilities ────────────────────────────────────────────────────

    let mut capabilities = Vec::with_capacity(cfg.capabilities.len());
    for entry in &cfg.capabilities {
        if entry.capability.is_empty() {
            return Err(PackError::ConstraintViolation {
                reason: "capability entry has empty `capability` field".into(),
            });
        }
        capabilities.push(CapRequest {
            capability: CapabilityId::new(entry.capability.clone()),
        });
    }

    // ── output-dir resolution ───────────────────────────────────────────

    let output_dir = match cfg.output_dir.as_deref() {
        None => {
            // Documented sentinel: empty PathBuf means "runtime-generated
            // default per PRD §3034 `/.components/{id}/output/`".
            PathBuf::new()
        }
        Some(s) => {
            if s.is_empty() {
                return Err(PackError::ConstraintViolation {
                    reason: "output-dir declared but empty".into(),
                });
            }
            if s.len() > MAX_OUTPUT_DIR_LEN {
                return Err(PackError::InvalidManifest(format!(
                    "output-dir exceeds max length {MAX_OUTPUT_DIR_LEN} bytes ({} bytes)",
                    s.len()
                )));
            }
            if s.contains('\0') {
                return Err(PackError::InvalidManifest(
                    "output-dir contains null byte".into(),
                ));
            }
            let p = PathBuf::from(s);
            for seg in p.components() {
                if matches!(seg, std::path::Component::ParentDir) {
                    return Err(PackError::InvalidManifest(
                        "output-dir contains `..` traversal".into(),
                    ));
                }
            }
            if p.is_absolute() {
                return Err(PackError::InvalidManifest(
                    "output-dir must be workspace-relative (got absolute)".into(),
                ));
            }
            // Return RAW declared path — NOT joined against install_path.
            // Preserves §6.4 read-only-pack-tree invariant; caller joins
            // against per-iteration workspace.
            p
        }
    };

    let manifest = ComponentManifest {
        component_type: cfg.component_type,
        raw_yaml: yaml,
    };

    Ok((binary, capabilities, output_dir, manifest))
}

/// Slice C adversarial round 12 W1 fix: open a small text file
/// (typically `component.yaml`) with O_NOFOLLOW on Unix, fstat the open
/// FD to bound the size, then read into a UTF-8 `String` with a
/// `Read::take` cap. Closes the leaf-level TOCTOU window between
/// `symlink_metadata` and `read_to_string` on small text files.
///
/// `pub(crate)` so `InMemoryPackRegistry::rescan` can re-use it for the
/// per-pack `pack.yaml` read (adversarial round 13 W2 — rescan's read
/// was previously a plain `read_to_string` after `canonicalize`).
pub(crate) fn open_text_nofollow_bounded(
    path: &Path,
    max_bytes: u64,
    label: &str,
) -> Result<String, PackError> {
    use std::io::Read;
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| {
                if e.raw_os_error() == Some(libc::ELOOP) {
                    PackError::InvalidManifest(format!(
                        "{label} is a symlink (rejected by O_NOFOLLOW): {}",
                        path.display()
                    ))
                } else {
                    PackError::Io {
                        path: path.to_path_buf(),
                        source: e,
                    }
                }
            })?
    };
    #[cfg(not(unix))]
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|e| PackError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
    let md = file.metadata().map_err(|e| PackError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    if !md.is_file() {
        return Err(PackError::InvalidManifest(format!(
            "{label} must be a regular file: {}",
            path.display()
        )));
    }
    if md.len() > max_bytes {
        return Err(PackError::InvalidManifest(format!(
            "{label} exceeds max size {max_bytes} bytes ({} bytes)",
            md.len()
        )));
    }
    let mut buf = String::with_capacity(md.len() as usize);
    (&mut file)
        .take(max_bytes)
        .read_to_string(&mut buf)
        .map_err(|e| PackError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
    Ok(buf)
}

/// Open `binary_canon` with O_NOFOLLOW on Unix, fstat on the open FD to
/// enforce the 256 MiB cap against the SAME inode the subsequent read
/// will consume, then read up to that cap via `Read::take`. Closes the
/// Slice C adversarial round 11 W2 TOCTOU window where a swap between
/// `canonicalize` and `std::fs::read` could redirect the read to a
/// different inode (e.g. larger or symlinked). On non-Unix platforms
/// the open uses default behavior — residual TOCTOU bounded by the
/// admin-trust model (§2.9 Slice A pattern).
///
/// `source_field` is the YAML key the path came from (`binary` or
/// `behavior-ref`), used for accurate error attribution.
fn open_and_read_binary_bounded(
    binary_canon: &Path,
    source_field: &str,
) -> Result<Vec<u8>, PackError> {
    use std::io::Read;
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(binary_canon)
            .map_err(|e| {
                if e.raw_os_error() == Some(libc::ELOOP) {
                    PackError::InvalidManifest(format!(
                        "component `{source_field}` is a symlink (rejected by O_NOFOLLOW): {}",
                        binary_canon.display()
                    ))
                } else {
                    PackError::Io {
                        path: binary_canon.to_path_buf(),
                        source: e,
                    }
                }
            })?
    };
    #[cfg(not(unix))]
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .open(binary_canon)
        .map_err(|e| PackError::Io {
            path: binary_canon.to_path_buf(),
            source: e,
        })?;
    let md = file.metadata().map_err(|e| PackError::Io {
        path: binary_canon.to_path_buf(),
        source: e,
    })?;
    if !md.is_file() {
        return Err(PackError::InvalidManifest(format!(
            "component `{source_field}` must be a regular file: {}",
            binary_canon.display()
        )));
    }
    if md.len() > MAX_BINARY_BYTES {
        return Err(PackError::InvalidManifest(format!(
            "component `{source_field}` exceeds max size {MAX_BINARY_BYTES} bytes ({} bytes)",
            md.len()
        )));
    }
    let mut buf = Vec::with_capacity(md.len() as usize);
    (&mut file)
        .take(MAX_BINARY_BYTES)
        .read_to_end(&mut buf)
        .map_err(|e| PackError::Io {
            path: binary_canon.to_path_buf(),
            source: e,
        })?;
    Ok(buf)
}

/// Returns `true` when the trigger value is structurally empty (Null, empty
/// Mapping, empty Sequence). Used by REQ-073 constraint surface to honour
/// PRD §4.7.4 line 835's "absent or empty" semantic.
fn is_trigger_empty(value: &serde_yml::Value) -> bool {
    match value {
        serde_yml::Value::Null => true,
        serde_yml::Value::Mapping(m) => m.is_empty(),
        serde_yml::Value::Sequence(s) => s.is_empty(),
        _ => false,
    }
}

// ── AC-17 (REQ-380): resource-capability `capability.yaml` parser ──────────────
//
// Directory-backed 11th provide category. The manifest shape is defined by ADR
// 2026-06-29 Decision 3 ("Pack-Provided Resource Capabilities"). Parsing mirrors
// `parse_component_manifest` (leaf symlink pre-check → O_NOFOLLOW/fstat/bounded
// read → YAML alias-bomb guard → deserialize → constraint validation) and uses
// the SAME bounded / symlink-safe read gates the other 10 categories use.

/// Maximum permitted `capability.yaml` size (matches `MAX_COMPONENT_YAML_BYTES`).
const MAX_RESOURCE_CAPABILITY_YAML_BYTES: u64 = 1024 * 1024;

/// Bounded counts on the ADR manifest lists — defense-in-depth against a
/// pathological manifest (same bounded posture as the other categories).
const MAX_CANONICAL_SURFACES: usize = 8;
const MAX_CAPABILITY_TOOLS: usize = 256;
const MAX_CAPABILITY_WIDGETS: usize = 256;
const MAX_SUPPORTS_LIST: usize = 64;
const MAX_CAPABILITY_ID_LEN: usize = 256;
const MAX_TOOL_NAME_LEN: usize = 256;

/// ADR Decision-3 taxonomy of durable source-of-truth surfaces.
const CANONICAL_SURFACE_KINDS: &[&str] = &[
    "body-native",
    "projection-native",
    "asset-native",
    "external-owned",
];

/// Max TOTAL flow-open bytes (`[` + `{`) allowed. The real YAML flow-nesting DEPTH is
/// bounded by the count of `[`/`{` opens, so capping the count caps the depth — and thus
/// libyaml's O(depth²) deep-nesting term. Legit manifests use ≤~260 opens even in
/// worst-case all-flow form (`MAX_CAPABILITY_TOOLS` = 256 `{…}` + a handful of `[…]`
/// lists); 1000 leaves ~4× headroom.
const MAX_YAML_FLOW_OPENS: usize = 1000;
/// Max `flow_opens × input_len` "work" product allowed. libyaml's flow scan ALSO has an
/// O(depth × width) term (each scalar token at flow depth D pays ~O(D)), which the depth
/// bound alone does NOT bound: a `<1 MiB` doc at depth 1000 with ~500k scalars parses in
/// ~1.1 s (adversarial round 18 Finding 2). Bounding `opens × len` bounds that product
/// (`opens ≥ depth`, `len ≥ width`), holding the worst-case pre-parse cost to sub-second on
/// every guarded (≤1 MiB pack-shipped) entry point. 2e8 keeps realistic high-opens manifests
/// (256-flow-tool capability.yaml, ~40 KB → ~3e7) well clear.
const MAX_YAML_FLOW_WORK: usize = 200_000_000;
/// Max leading-whitespace (block-indentation depth proxy) allowed on any line — bounds
/// block-style nesting depth (each level ≥ 1 space).
const MAX_YAML_LEADING_INDENT: usize = 1024;

/// Cheap single-pass pre-scan rejecting untrusted YAML whose flow-nesting or
/// block-indentation would drive `serde_yml`/libyaml's super-linear flow scanner. That
/// scanner has TWO costly terms — an O(depth²) term (deep nesting: 200 KB of `[`-nesting →
/// ~36 s) and an O(depth × width) term (many scalars at depth: a `<1 MiB` doc at depth 1000
/// with ~500k scalars → ~1.1 s). This runs before `serde_yml::from_str`, alongside
/// `yaml_has_alias_refs`, and bounds BOTH terms:
///  - **depth bound** (`MAX_YAML_FLOW_OPENS`): total `[`/`{` opens ≤ 1000. Max real
///    flow-nesting depth ≤ total opens, so this caps depth → caps the O(depth²) term.
///  - **work bound** (`MAX_YAML_FLOW_WORK`): `opens × input_len` ≤ 2e8. Since `opens ≥
///    depth` and `len ≥ width`, this caps the O(depth × width) term (adversarial round 18
///    Finding 2 — the depth bound alone left a deep-AND-wide document parsing >1 s, amplified
///    N× by serial `rescan()`). The effective per-input open cap is
///    `min(MAX_YAML_FLOW_OPENS, MAX_YAML_FLOW_WORK / len)`, so a larger input gets a tighter
///    open cap — worst-case pre-parse cost stays sub-second on every guarded (≤1 MiB
///    pack-shipped) entry point.
///
/// Robustness (adversarial round 14): the guard **counts the TOTAL number of `[`/`{`
/// open bytes and never decrements**. Counting is deliberately QUOTE- and COMMENT-BLIND: a
/// `[`/`{` inside a quoted scalar or comment is not a real flow-open, so counting it only
/// OVER-counts (makes the guard stricter) — it can NEVER be fooled into UNDER-counting. This
/// closes the round-14 bypass where a *net-depth* counter that decremented on
/// quoted/comment fake-closes (`["]",["]",…`, `# ]]]`) could oscillate near zero while the
/// parser's real nesting grew unbounded. No legitimate manifest carries 1000 flow-open
/// bytes, a 2e8 opens×len product, or 1 KiB of leading indentation.
///
/// `pub(crate)` — adversarial rounds 16 + 18 extended this guard to every UNTRUSTED
/// PACK-SHIPPED YAML file: `pack.yaml` (`manifest::PackManifest::from_yaml`), `component.yaml`
/// + `capability.yaml` (`component_manifest`), and `workflows/{name}.yaml`
/// (`workflow::WorkflowApplier::apply`) — not just `capability.yaml`, since the same
/// deep-flow-nesting parse-DoS (measured ~5–6 min for a 1 MiB deep-nested pack.yaml; ~15 min
/// for a workflow) applies to every one of them. These are BOUNDED manifests (no legitimate
/// one carries 1000 flow-open bytes / a 2e8 opens×len product / 1 KiB of leading indentation).
/// If a NEW `serde_yml::from_str` on untrusted PACK-SHIPPED content is added, it MUST call this
/// guard first (alongside `yaml_has_alias_refs`).
///
/// EXCLUDED — `.meta.yaml` (`meta::read_meta_index`): it is a MANAGER-GENERATED index that
/// `write_meta_index_atomic` always re-serializes (block style), so pack-controlled content is
/// only ever string SCALARS (O(n)), never injected nesting; and its cardinality scales with the
/// installed-pack count, so a total-opens cap would count one `[` per entry and reject the
/// tool's own index at scale (adversarial round 20 brick). `.meta.yaml` is bounded by its size
/// cap + alias guard; deep NESTING there requires direct `packs_dir` write (admin trust). See
/// `meta::read_meta_index`.
pub(crate) fn yaml_nesting_within_bound(yaml: &str) -> bool {
    // Fold the depth bound and the work bound into a single per-input open cap: a larger
    // input gets a tighter cap so `opens × len` can never exceed MAX_YAML_FLOW_WORK.
    let opens_cap = MAX_YAML_FLOW_OPENS.min(MAX_YAML_FLOW_WORK / yaml.len().max(1));
    let mut flow_opens: usize = 0;
    let mut at_line_start = true;
    let mut indent: usize = 0;
    for &b in yaml.as_bytes() {
        match b {
            b'[' | b'{' => {
                flow_opens += 1;
                if flow_opens > opens_cap {
                    return false;
                }
                at_line_start = false;
            }
            b'\n' => {
                at_line_start = true;
                indent = 0;
            }
            b' ' | b'\t' if at_line_start => {
                indent += 1;
                if indent > MAX_YAML_LEADING_INDENT {
                    return false;
                }
            }
            _ => {
                at_line_start = false;
            }
        }
    }
    true
}

/// Deserialised view of `resource-capabilities/{name}/capability.yaml` (AC-17).
/// Permissive parse (no `deny_unknown_fields`) — forward-compat accept-and-ignore,
/// matching `ComponentSubmitConfig`. The `#[derive(Debug)]` also keeps every field
/// "read" for the dead-code lint (the pack-manager tier consumes `id` +
/// bound-validates the structural fields; `store`/`mcp`/`read_only`/`description`
/// are captured for the M017 exposure legs (deferred) + forward-compat).
#[derive(Debug, Deserialize)]
pub(crate) struct ResourceCapabilityManifest {
    /// Canonical capability id (e.g. `advance.structured-data`) → the returned
    /// `ResourceCapabilityId`. Required, non-empty, ASCII, no control bytes.
    pub id: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub supports: SupportsDecl,
    #[serde(default)]
    pub canonical_surfaces: Vec<String>,
    #[serde(default)]
    pub store: Option<StoreDecl>,
    #[serde(default)]
    pub tools: Vec<ResourceToolDecl>,
    #[serde(default)]
    pub mcp: Option<McpExposureDecl>,
    #[serde(default)]
    pub widgets: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct SupportsDecl {
    #[serde(default)]
    pub resource_types: Vec<String>,
    #[serde(default)]
    pub mime_types: Vec<String>,
    #[serde(default)]
    pub ref_schemes: Vec<String>,
    #[serde(default)]
    pub projection_schemas: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct StoreDecl {
    #[serde(default)]
    pub default_backend: Option<String>,
    #[serde(default)]
    pub ownership: Option<String>,
    #[serde(default)]
    pub projection_format: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ResourceToolDecl {
    pub name: String,
    #[serde(default)]
    pub read_only: bool,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct McpExposureDecl {
    #[serde(default)]
    pub expose_tools: bool,
    #[serde(default)]
    pub expose_resources: bool,
}

/// Parse + validate `{cap_dir}/capability.yaml` (AC-17). `cap_dir` is the capability
/// directory (`{install}/resource-capabilities/{name}`). Register-not-copy: this only
/// reads + validates; nothing is written. Errors mirror `parse_component_manifest`:
/// `InvalidManifest` (missing / symlink / oversize / non-UTF-8 / alias-bomb / parse) or
/// `ConstraintViolation` (ADR-shape violation).
pub(crate) fn parse_resource_capability_manifest(
    cap_dir: &Path,
) -> Result<ResourceCapabilityManifest, PackError> {
    let yaml_path = cap_dir.join("capability.yaml");

    // Pre-parse leaf symlink check for a friendly diagnostic (the O_NOFOLLOW open
    // below is the authoritative gate against a leaf-symlink swap at read time).
    match std::fs::symlink_metadata(&yaml_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(PackError::InvalidManifest(format!(
                "capability.yaml missing for resource-capability at {}",
                yaml_path.display()
            )));
        }
        Err(e) => {
            return Err(PackError::Io {
                path: yaml_path.clone(),
                source: e,
            });
        }
        Ok(leaf_md) => {
            if leaf_md.file_type().is_symlink() {
                return Err(PackError::InvalidManifest(format!(
                    "capability.yaml is a symlink (rejected): {}",
                    yaml_path.display()
                )));
            }
        }
    }

    let yaml = open_text_nofollow_bounded(
        &yaml_path,
        MAX_RESOURCE_CAPABILITY_YAML_BYTES,
        "capability.yaml",
    )?;
    if yaml_has_alias_refs(&yaml) {
        return Err(PackError::InvalidManifest(
            "capability.yaml contains YAML alias references (`*name`) — rejected to prevent billion-laughs amplification".into(),
        ));
    }
    if !yaml_nesting_within_bound(&yaml) {
        return Err(PackError::InvalidManifest(
            "capability.yaml nesting/indentation is too deep — rejected to prevent parse-time resource exhaustion (serde_yml deep-nesting DoS)".into(),
        ));
    }

    let manifest: ResourceCapabilityManifest = serde_yml::from_str(&yaml)
        .map_err(|e| PackError::InvalidManifest(format!("capability.yaml parse: {e}")))?;

    validate_resource_capability_manifest(&manifest)?;
    Ok(manifest)
}

/// Enforce the ADR Decision-3 constraint surface on a parsed `capability.yaml`.
fn validate_resource_capability_manifest(m: &ResourceCapabilityManifest) -> Result<(), PackError> {
    // (1) id — required, non-empty, bounded, ASCII, no control bytes (matches the
    //     manifest.rs name-validation / registry.rs key-validation posture).
    if m.id.is_empty() {
        return Err(PackError::ConstraintViolation {
            reason: "capability.yaml `id` must be non-empty".into(),
        });
    }
    if m.id.len() > MAX_CAPABILITY_ID_LEN {
        return Err(PackError::ConstraintViolation {
            reason: format!(
                "capability.yaml `id` exceeds max {MAX_CAPABILITY_ID_LEN} bytes ({} bytes)",
                m.id.len()
            ),
        });
    }
    if m.id.chars().any(|c| !c.is_ascii() || c.is_ascii_control()) {
        return Err(PackError::ConstraintViolation {
            reason: "capability.yaml `id` must be ASCII without control bytes".into(),
        });
    }

    // (2) canonical_surfaces — non-empty, each in the ADR taxonomy, bounded count.
    if m.canonical_surfaces.is_empty() {
        return Err(PackError::ConstraintViolation {
            reason: "capability.yaml `canonical_surfaces` must declare at least one surface".into(),
        });
    }
    if m.canonical_surfaces.len() > MAX_CANONICAL_SURFACES {
        return Err(PackError::ConstraintViolation {
            reason: format!(
                "capability.yaml `canonical_surfaces` count {} exceeds max {MAX_CANONICAL_SURFACES}",
                m.canonical_surfaces.len()
            ),
        });
    }
    for s in &m.canonical_surfaces {
        if !CANONICAL_SURFACE_KINDS.contains(&s.as_str()) {
            return Err(PackError::ConstraintViolation {
                reason: format!(
                    "capability.yaml `canonical_surfaces` has unknown surface {s:?} (allowed: {CANONICAL_SURFACE_KINDS:?})"
                ),
            });
        }
    }

    // (3) tools — bounded count; each name non-empty + bounded. `read_only` is typed.
    if m.tools.len() > MAX_CAPABILITY_TOOLS {
        return Err(PackError::ConstraintViolation {
            reason: format!(
                "capability.yaml `tools` count {} exceeds max {MAX_CAPABILITY_TOOLS}",
                m.tools.len()
            ),
        });
    }
    for t in &m.tools {
        if t.name.is_empty() || t.name.len() > MAX_TOOL_NAME_LEN {
            return Err(PackError::ConstraintViolation {
                reason: format!(
                    "capability.yaml tool name must be non-empty and <= {MAX_TOOL_NAME_LEN} bytes (got {:?}, read_only={})",
                    t.name, t.read_only
                ),
            });
        }
    }

    // (4) widgets — bounded count; each non-empty.
    if m.widgets.len() > MAX_CAPABILITY_WIDGETS {
        return Err(PackError::ConstraintViolation {
            reason: format!(
                "capability.yaml `widgets` count {} exceeds max {MAX_CAPABILITY_WIDGETS}",
                m.widgets.len()
            ),
        });
    }
    for w in &m.widgets {
        if w.is_empty() {
            return Err(PackError::ConstraintViolation {
                reason: "capability.yaml `widgets` entries must be non-empty".into(),
            });
        }
    }

    // (5) supports.* + description + store — bounded (defense-in-depth; also keeps
    //     these forward-compat fields consumed).
    for (label, list) in [
        ("resource_types", &m.supports.resource_types),
        ("mime_types", &m.supports.mime_types),
        ("ref_schemes", &m.supports.ref_schemes),
        ("projection_schemas", &m.supports.projection_schemas),
    ] {
        if list.len() > MAX_SUPPORTS_LIST {
            return Err(PackError::ConstraintViolation {
                reason: format!(
                    "capability.yaml `supports.{label}` count {} exceeds max {MAX_SUPPORTS_LIST}",
                    list.len()
                ),
            });
        }
    }
    if let Some(d) = &m.description {
        if d.len() > MAX_RESOURCE_CAPABILITY_YAML_BYTES as usize {
            return Err(PackError::ConstraintViolation {
                reason: "capability.yaml `description` is implausibly large".into(),
            });
        }
    }
    if let Some(store) = &m.store {
        for (label, v) in [
            ("default_backend", &store.default_backend),
            ("ownership", &store.ownership),
            ("projection_format", &store.projection_format),
        ] {
            if let Some(val) = v {
                if val.len() > MAX_CAPABILITY_ID_LEN {
                    return Err(PackError::ConstraintViolation {
                        reason: format!(
                            "capability.yaml `store.{label}` exceeds max {MAX_CAPABILITY_ID_LEN} bytes"
                        ),
                    });
                }
            }
        }
    }
    // `mcp` toggles carry no additional constraint at the pack-manager tier — the
    // exposure they gate is the deferred M017 leg — but read them so the shape is
    // fully validated / consumed.
    if let Some(mcp) = &m.mcp {
        let _ = (mcp.expose_tools, mcp.expose_resources);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trigger_empty_helper() {
        assert!(is_trigger_empty(&serde_yml::Value::Null));
        assert!(is_trigger_empty(&serde_yml::Value::Mapping(
            Default::default()
        )));
        assert!(is_trigger_empty(&serde_yml::Value::Sequence(Vec::new())));
        // Non-empty cases:
        let mut m = serde_yml::Mapping::new();
        m.insert(
            serde_yml::Value::String("event-type".into()),
            serde_yml::Value::String("foo".into()),
        );
        assert!(!is_trigger_empty(&serde_yml::Value::Mapping(m)));
        assert!(!is_trigger_empty(&serde_yml::Value::Sequence(vec![
            serde_yml::Value::String("x".into())
        ])));
        assert!(!is_trigger_empty(&serde_yml::Value::String("x".into())));
    }

    // ── MODULE-018-T92 (AC-17): parse_resource_capability_manifest ──────────
    //
    // Calls the parser DIRECTLY (it is pub(crate); integration tests in
    // tests/resource_capabilities.rs cannot reach it). The symlink case is
    // witnessed here because at install the source-side copy_dir_no_symlinks
    // would reject a symlink first (plan-eval R1 Info-4).

    fn cap_dir_with(yaml: &str) -> tempfile::TempDir {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("capability.yaml"), yaml.as_bytes()).unwrap();
        dir
    }

    const VALID_CAPABILITY_YAML: &str = r#"
id: advance.structured-data
description: Structured data resource capability.
supports:
  resource_types: [project, collection]
  mime_types: [text/markdown]
  ref_schemes: [data]
  projection_schemas: [advance.entity-table.v1]
canonical_surfaces:
  - projection-native
store:
  default_backend: sqlite
  ownership: workspace-owned
  projection_format: ndjson
tools:
  - name: advance.data.query
    read_only: true
  - name: advance.data.upsert
    read_only: false
mcp:
  expose_tools: true
  expose_resources: true
widgets:
  - entity.table
  - entity.form
"#;

    #[test]
    fn t92_valid_adr_shape_parses_and_yields_id() {
        let dir = cap_dir_with(VALID_CAPABILITY_YAML);
        let m = parse_resource_capability_manifest(dir.path()).unwrap();
        assert_eq!(m.id, "advance.structured-data");
        assert_eq!(m.canonical_surfaces, vec!["projection-native".to_string()]);
        assert_eq!(m.tools.len(), 2);
        assert!(m.tools[0].read_only);
        assert!(!m.tools[1].read_only);
        assert_eq!(m.widgets.len(), 2);
    }

    #[test]
    fn t92_unknown_fields_accepted_and_ignored() {
        // Forward-compat: extra top-level keys don't fail the parse.
        let yaml = "id: advance.x\ncanonical_surfaces: [projection-native]\nfuture_field: whatever\nreconcilers: [a, b]\n";
        let m = parse_resource_capability_manifest(cap_dir_with(yaml).path()).unwrap();
        assert_eq!(m.id, "advance.x");
    }

    #[test]
    fn t92_empty_id_rejected() {
        let yaml = "id: \"\"\ncanonical_surfaces: [projection-native]\n";
        match parse_resource_capability_manifest(cap_dir_with(yaml).path()) {
            Err(PackError::ConstraintViolation { reason }) => assert!(reason.contains("`id`")),
            other => panic!("expected ConstraintViolation, got {other:?}"),
        }
    }

    #[test]
    fn t92_missing_id_rejected() {
        // serde: `id` is required (no default) → parse error surfaces as InvalidManifest.
        let yaml = "canonical_surfaces: [projection-native]\n";
        match parse_resource_capability_manifest(cap_dir_with(yaml).path()) {
            Err(PackError::InvalidManifest(msg)) => assert!(msg.contains("parse")),
            other => panic!("expected InvalidManifest (parse), got {other:?}"),
        }
    }

    #[test]
    fn t92_non_ascii_id_rejected() {
        let yaml = "id: advance.dａta\ncanonical_surfaces: [projection-native]\n";
        match parse_resource_capability_manifest(cap_dir_with(yaml).path()) {
            Err(PackError::ConstraintViolation { reason }) => assert!(reason.contains("ASCII")),
            other => panic!("expected ConstraintViolation, got {other:?}"),
        }
    }

    #[test]
    fn t92_empty_canonical_surfaces_rejected() {
        let yaml = "id: advance.x\ncanonical_surfaces: []\n";
        match parse_resource_capability_manifest(cap_dir_with(yaml).path()) {
            Err(PackError::ConstraintViolation { reason }) => {
                assert!(reason.contains("canonical_surfaces"))
            }
            other => panic!("expected ConstraintViolation, got {other:?}"),
        }
    }

    #[test]
    fn t92_unknown_canonical_surface_rejected() {
        let yaml = "id: advance.x\ncanonical_surfaces: [not-a-real-surface]\n";
        match parse_resource_capability_manifest(cap_dir_with(yaml).path()) {
            Err(PackError::ConstraintViolation { reason }) => {
                assert!(reason.contains("unknown surface"))
            }
            other => panic!("expected ConstraintViolation, got {other:?}"),
        }
    }

    #[test]
    fn t92_over_count_tools_rejected() {
        let mut yaml =
            String::from("id: advance.x\ncanonical_surfaces: [projection-native]\ntools:\n");
        for i in 0..(MAX_CAPABILITY_TOOLS + 1) {
            yaml.push_str(&format!("  - name: t{i}\n    read_only: true\n"));
        }
        match parse_resource_capability_manifest(cap_dir_with(&yaml).path()) {
            Err(PackError::ConstraintViolation { reason }) => assert!(reason.contains("`tools`")),
            other => panic!("expected ConstraintViolation, got {other:?}"),
        }
    }

    #[test]
    fn t92_empty_tool_name_rejected() {
        let yaml = "id: advance.x\ncanonical_surfaces: [projection-native]\ntools:\n  - name: \"\"\n    read_only: true\n";
        match parse_resource_capability_manifest(cap_dir_with(yaml).path()) {
            Err(PackError::ConstraintViolation { reason }) => assert!(reason.contains("tool name")),
            other => panic!("expected ConstraintViolation, got {other:?}"),
        }
    }

    #[test]
    fn t92_alias_bomb_rejected() {
        // YAML alias reference → billion-laughs guard (InvalidManifest, pre-parse).
        let yaml = "id: &a advance.x\ncanonical_surfaces: [*a]\n";
        match parse_resource_capability_manifest(cap_dir_with(yaml).path()) {
            Err(PackError::InvalidManifest(msg)) => assert!(msg.contains("alias")),
            other => panic!("expected InvalidManifest (alias), got {other:?}"),
        }
    }

    #[test]
    fn t92_oversize_rejected() {
        let mut yaml = String::from("id: advance.x\ncanonical_surfaces: [projection-native]\n# ");
        yaml.push_str(&"A".repeat(MAX_RESOURCE_CAPABILITY_YAML_BYTES as usize + 16));
        match parse_resource_capability_manifest(cap_dir_with(&yaml).path()) {
            Err(PackError::InvalidManifest(msg)) => assert!(msg.contains("exceeds max size")),
            other => panic!("expected InvalidManifest (oversize), got {other:?}"),
        }
    }

    #[test]
    fn t92_missing_capability_yaml_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        match parse_resource_capability_manifest(dir.path()) {
            Err(PackError::InvalidManifest(msg)) => assert!(msg.contains("missing")),
            other => panic!("expected InvalidManifest (missing), got {other:?}"),
        }
    }

    #[test]
    fn t92_deep_nesting_rejected_fast() {
        // Adversarial round 12: a <1 MiB but deeply flow-nested capability.yaml drives
        // serde_yml into ~O(n²) (200 KB `[`-nesting measured at ~36s). The pre-parse
        // nesting guard must reject it BEFORE serde_yml runs — assert it rejects in well
        // under a second (the guard fires, not the parser).
        let mut yaml = String::from("id: advance.x\ncanonical_surfaces: [projection-native]\nx: ");
        yaml.push_str(&"[".repeat(50_000));
        yaml.push_str(&"]".repeat(50_000));
        yaml.push('\n');
        let start = std::time::Instant::now();
        let r = parse_resource_capability_manifest(cap_dir_with(&yaml).path());
        let elapsed = start.elapsed();
        match r {
            Err(PackError::InvalidManifest(msg)) => {
                assert!(
                    msg.contains("nesting") || msg.contains("deep"),
                    "got: {msg}"
                )
            }
            other => panic!("expected InvalidManifest (deep nesting), got {other:?}"),
        }
        assert!(
            elapsed.as_secs() < 2,
            "nesting guard should reject FAST (before serde_yml's O(n^2) scan); took {elapsed:?}"
        );
    }

    #[test]
    fn t92_deep_block_indent_rejected() {
        // Block-indentation depth proxy: a manifest whose deepest line carries a huge
        // leading indent is rejected by the same guard.
        let mut yaml = String::from("id: advance.x\ncanonical_surfaces: [projection-native]\n");
        yaml.push_str(&" ".repeat(2_000));
        yaml.push_str("deep: 1\n");
        match parse_resource_capability_manifest(cap_dir_with(&yaml).path()) {
            Err(PackError::InvalidManifest(msg)) => {
                assert!(
                    msg.contains("nesting") || msg.contains("deep"),
                    "got: {msg}"
                )
            }
            other => panic!("expected InvalidManifest (deep indent), got {other:?}"),
        }
    }

    #[test]
    fn t92_quoted_fake_close_nesting_bypass_rejected() {
        // Adversarial round 14 (dual-model): the round-12 NET-depth guard decremented on
        // `]` bytes inside quoted scalars, so `["]",["]",…` oscillated its counter near
        // zero while real nesting grew (900 KB measured at ~66 s). The total-opens guard
        // (no decrement, quote-blind) rejects it — each `["]` is a real `[` open; 2000 >
        // MAX_YAML_FLOW_OPENS — and rejects FAST (the OLD guard let this through to
        // serde_yml's O(n²) scan; this timing bound is the anti-regression discriminator).
        let mut yaml = String::from("id: advance.x\ncanonical_surfaces: [projection-native]\nx: ");
        yaml.push_str(&"[\"]\",".repeat(2_000));
        yaml.push_str("null");
        yaml.push_str(&"]".repeat(2_000));
        yaml.push('\n');
        let start = std::time::Instant::now();
        let r = parse_resource_capability_manifest(cap_dir_with(&yaml).path());
        let elapsed = start.elapsed();
        match r {
            Err(PackError::InvalidManifest(msg)) => {
                assert!(
                    msg.contains("nesting") || msg.contains("deep"),
                    "got: {msg}"
                )
            }
            other => panic!("expected InvalidManifest (quoted-fake-close bypass), got {other:?}"),
        }
        assert!(
            elapsed.as_secs() < 2,
            "guard must reject the quoted-fake-close bypass FAST; took {elapsed:?}"
        );
    }

    #[test]
    fn t92_comment_fake_close_nesting_bypass_rejected() {
        // Comment `# ]]]` closes must not fool the guard either (quote/comment-blind).
        let mut yaml = String::from("id: advance.x\ncanonical_surfaces: [projection-native]\nx: ");
        yaml.push_str(&"[ # ]\n".repeat(2_000));
        match parse_resource_capability_manifest(cap_dir_with(&yaml).path()) {
            Err(PackError::InvalidManifest(msg)) => {
                assert!(
                    msg.contains("nesting") || msg.contains("deep"),
                    "got: {msg}"
                )
            }
            other => panic!("expected InvalidManifest (comment-fake-close bypass), got {other:?}"),
        }
    }

    #[test]
    fn t92_deep_wide_hybrid_rejected_fast() {
        // Adversarial round 18 Finding 2: a deep(1000)+wide(~450k scalars) flow document keeps
        // total-opens at 1000 (the depth-only cap PASSED it) but costs O(depth×width) — ~1.1 s
        // parse on <1 MiB. The work bound (opens × len ≤ 2e8) rejects it FAST: at ~0.9 MiB the
        // per-input open cap tightens to ~220, so the scan bails after ~220 `[`.
        let mut yaml = String::from("x: ");
        yaml.push_str(&"[".repeat(1_000));
        yaml.push_str(&"9,".repeat(450_000)); // ~0.9 MiB of scalars at depth 1000
        yaml.push_str(&"]".repeat(1_000));
        yaml.push('\n');
        assert!(
            (yaml.len() as u64) < MAX_RESOURCE_CAPABILITY_YAML_BYTES,
            "must stay under the size cap"
        );
        let start = std::time::Instant::now();
        let r = parse_resource_capability_manifest(cap_dir_with(&yaml).path());
        let elapsed = start.elapsed();
        match r {
            Err(PackError::InvalidManifest(msg)) => {
                assert!(
                    msg.contains("nesting") || msg.contains("deep"),
                    "got: {msg}"
                )
            }
            other => panic!("expected InvalidManifest (deep+wide), got {other:?}"),
        }
        assert!(
            elapsed.as_secs() < 2,
            "work bound must reject the deep+wide hybrid FAST; took {elapsed:?}"
        );
    }

    #[test]
    fn t92_wide_flow_manifest_within_bound_accepts() {
        // A WIDE-but-shallow legit-shaped manifest (many sibling flow tools, depth ~2)
        // stays under the opens cap and parses fast — proves the guard is not a blanket
        // reject of flow style. 256 tools = ~256 `{` opens (< MAX_YAML_FLOW_OPENS).
        let mut tools = String::from("tools: [");
        for i in 0..256 {
            if i > 0 {
                tools.push_str(", ");
            }
            tools.push_str(&format!("{{name: t{i}, read_only: true}}"));
        }
        tools.push_str("]\n");
        let yaml = format!("id: advance.x\ncanonical_surfaces: [projection-native]\n{tools}");
        let m = parse_resource_capability_manifest(cap_dir_with(&yaml).path()).unwrap();
        assert_eq!(m.tools.len(), 256);
    }

    #[test]
    fn component_yaml_deep_flow_nesting_rejected_fast() {
        // Adversarial round 16 (crate-wide): the shared guard now also protects the
        // component.yaml parser (a 1 MiB deep-nested component.yaml was measured at ~5–6 min).
        let dir = tempfile::TempDir::new().unwrap();
        let comp_dir = dir.path().join("components").join("comp");
        std::fs::create_dir_all(&comp_dir).unwrap();
        let mut body = String::from("component-type: task\nx: ");
        body.push_str(&"[".repeat(5_000));
        std::fs::write(comp_dir.join("component.yaml"), body).unwrap();
        let start = std::time::Instant::now();
        let r = parse_component_manifest(dir.path(), "comp");
        assert!(start.elapsed().as_secs() < 2, "guard must reject fast");
        match r {
            Err(PackError::InvalidManifest(m)) => {
                assert!(m.contains("nesting") || m.contains("deep"), "got: {m}")
            }
            other => panic!("expected InvalidManifest (deep nesting), got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn t92_capability_yaml_symlink_rejected() {
        // The parser's OWN leaf-symlink gate (not the install-time copy guard).
        let dir = tempfile::TempDir::new().unwrap();
        let real = dir.path().join("real.yaml");
        std::fs::write(&real, VALID_CAPABILITY_YAML).unwrap();
        std::os::unix::fs::symlink(&real, dir.path().join("capability.yaml")).unwrap();
        match parse_resource_capability_manifest(dir.path()) {
            Err(PackError::InvalidManifest(msg)) => assert!(msg.contains("symlink")),
            other => panic!("expected InvalidManifest (symlink), got {other:?}"),
        }
    }
}

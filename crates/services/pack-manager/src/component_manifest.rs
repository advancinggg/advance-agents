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

// ── Shared YAML nesting guard (every pack-shipped YAML document) ───────────────

/// Max TOTAL flow-open bytes (`[` + `{`) allowed. The real YAML flow-nesting DEPTH is
/// bounded by the count of `[`/`{` opens, so capping the count caps the depth — and thus
/// libyaml's O(depth²) deep-nesting term. Pack documents are normally block style, which
/// opens none; even a `pack.yaml` declaring the maximum 256 dependencies as flow mappings
/// uses about 260 opens.
const MAX_YAML_FLOW_OPENS: usize = 1000;
/// Max `flow_opens × input_len` "work" product allowed. libyaml's flow scan ALSO has an
/// O(depth × width) term (each scalar token at flow depth D pays ~O(D)), which the depth
/// bound alone does NOT bound: a `<1 MiB` doc at depth 1000 with ~500k scalars parses in
/// ~1.1 s (adversarial round 18 Finding 2). Bounding `opens × len` bounds that product
/// (`opens ≥ depth`, `len ≥ width`), holding the worst-case pre-parse cost to sub-second on
/// every guarded (≤1 MiB pack-shipped) entry point. 2e8 keeps realistic high-opens documents
/// well clear (that 256-dependency flow-style `pack.yaml`: ~260 opens over ~9 KB → ~2.4e6).
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
/// `pub(crate)` — every UNTRUSTED PACK-SHIPPED YAML document goes through this guard:
/// `pack.yaml` (`manifest::PackManifest::from_yaml`), `component.yaml`
/// (`parse_component_manifest`), `workflows/{name}.yaml` (`workflow::WorkflowApplier::apply`),
/// `meta-schema-extensions/{name}.yaml` (`meta_schema_merge`) and `mcp-servers/{name}.yaml`
/// (`mcp_server_manifest`), since the same deep-flow-nesting parse-DoS (measured ~5–6 min for a
/// 1 MiB deep-nested pack.yaml; ~15 min for a workflow) applies to every one of them. These are
/// BOUNDED documents (no realistic one carries 1000 flow-open bytes / a 2e8 opens×len product /
/// 1 KiB of leading indentation). If a NEW `serde_yml::from_str` on untrusted PACK-SHIPPED
/// content is added, it MUST call this guard first (alongside `yaml_has_alias_refs`).
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::PackManifest;

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

    // ── Shared YAML nesting guard + bounded reader ──────────────────────────────────
    //
    // Every pack-shipped YAML document passes `yaml_nesting_within_bound` before serde_yml,
    // and rescan reads every installed `pack.yaml` through `open_text_nofollow_bounded`.
    // These pin the bypasses each one closes, driven through `pack.yaml`.

    fn pack_yaml_with(tail: &str) -> String {
        format!("name: x\nversion: 1.0.0\nruntime-version: \">=0.0.1\"\n{tail}")
    }

    fn expect_nesting_rejection(r: Result<PackManifest, PackError>) {
        match r {
            Err(PackError::InvalidManifest(msg)) => {
                assert!(
                    msg.contains("nesting") || msg.contains("deep"),
                    "got: {msg}"
                )
            }
            other => panic!("expected InvalidManifest (nesting), got {other:?}"),
        }
    }

    #[test]
    fn nesting_guard_rejects_deep_block_indent() {
        // Block-indentation depth proxy: one line with a huge leading indent is rejected.
        let mut yaml = pack_yaml_with("");
        yaml.push_str(&" ".repeat(2_000));
        yaml.push_str("deep: 1\n");
        assert!(!yaml_nesting_within_bound(&yaml));
        expect_nesting_rejection(PackManifest::from_yaml(&yaml));
    }

    #[test]
    fn nesting_guard_rejects_quoted_fake_close_bypass() {
        // A net-depth counter that decremented on `]` inside quoted scalars let `["]",["]",…`
        // oscillate near zero while the real nesting grew (900 KB measured at ~66 s). The
        // guard counts every `[`/`{` and never decrements (quote-blind): 2000 opens exceed
        // MAX_YAML_FLOW_OPENS. The timing bound tells the guard apart from serde_yml's scan.
        let mut yaml = pack_yaml_with("x: ");
        yaml.push_str(&"[\"]\",".repeat(2_000));
        yaml.push_str("null");
        yaml.push_str(&"]".repeat(2_000));
        yaml.push('\n');
        assert!(!yaml_nesting_within_bound(&yaml));
        let start = std::time::Instant::now();
        let r = PackManifest::from_yaml(&yaml);
        let elapsed = start.elapsed();
        expect_nesting_rejection(r);
        assert!(
            elapsed.as_secs() < 2,
            "guard must reject the quoted-fake-close bypass FAST; took {elapsed:?}"
        );
    }

    #[test]
    fn nesting_guard_rejects_comment_fake_close_bypass() {
        // Comment `# ]` closes must not fool the guard either (comment-blind).
        let mut yaml = pack_yaml_with("x: ");
        yaml.push_str(&"[ # ]\n".repeat(2_000));
        assert!(!yaml_nesting_within_bound(&yaml));
        expect_nesting_rejection(PackManifest::from_yaml(&yaml));
    }

    #[test]
    fn nesting_guard_rejects_deep_wide_hybrid_fast() {
        // A deep (1000) + wide (~450k scalars) flow document has exactly as many opens as the
        // depth cap allows, so only the work bound (opens × len ≤ 2e8) can reject it; parsed,
        // it costs O(depth × width), ~1.1 s on <1 MiB. At ~0.9 MiB the per-input open cap
        // tightens to ~220, so the scan bails after ~220 `[`.
        let mut yaml = pack_yaml_with("x: ");
        yaml.push_str(&"[".repeat(1_000));
        yaml.push_str(&"9,".repeat(450_000));
        yaml.push_str(&"]".repeat(1_000));
        yaml.push('\n');
        assert!(
            (yaml.len() as u64) < MAX_COMPONENT_YAML_BYTES,
            "must stay under the 1 MiB size cap of the guarded documents"
        );
        assert_eq!(
            yaml.bytes().filter(|b| matches!(b, b'[' | b'{')).count(),
            MAX_YAML_FLOW_OPENS,
            "the depth cap alone accepts this document"
        );
        assert!(!yaml_nesting_within_bound(&yaml));
        let start = std::time::Instant::now();
        let r = PackManifest::from_yaml(&yaml);
        let elapsed = start.elapsed();
        expect_nesting_rejection(r);
        assert!(
            elapsed.as_secs() < 2,
            "work bound must reject the deep+wide hybrid FAST; took {elapsed:?}"
        );
    }

    #[test]
    fn nesting_guard_accepts_wide_shallow_flow() {
        // A wide-but-shallow realistic document stays under both caps and parses: the guard
        // is no blanket reject of flow style. 256 dependency mappings = 256 `{` + 1 `[` opens.
        let deps: Vec<String> = (0..256)
            .map(|i| format!("{{name: dep{i}, version: \"^1.0.0\"}}"))
            .collect();
        let yaml = pack_yaml_with(&format!(
            "dependencies: [{}]\nchecksums:\n  algo: sha256\n  files: {{}}\n",
            deps.join(", ")
        ));
        assert!(yaml_nesting_within_bound(&yaml));
        let m = PackManifest::from_yaml(&yaml).unwrap();
        assert_eq!(m.dependencies.len(), 256);
    }

    #[test]
    fn bounded_reader_rejects_oversize() {
        // The size bound of the reader rescan uses for every installed pack.yaml and the
        // component parser for component.yaml: one byte over is refused, the bound reads.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("component.yaml");
        let max = MAX_COMPONENT_YAML_BYTES as usize;
        std::fs::write(&path, vec![b'a'; max + 1]).unwrap();
        match open_text_nofollow_bounded(&path, MAX_COMPONENT_YAML_BYTES, "component.yaml") {
            Err(PackError::InvalidManifest(msg)) => {
                assert!(msg.contains("exceeds max size"), "got: {msg}")
            }
            other => panic!("expected InvalidManifest (oversize), got {other:?}"),
        }
        std::fs::write(&path, vec![b'a'; max]).unwrap();
        let text = open_text_nofollow_bounded(&path, MAX_COMPONENT_YAML_BYTES, "component.yaml")
            .expect("a file at the bound reads");
        assert_eq!(text.len(), max);
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
}

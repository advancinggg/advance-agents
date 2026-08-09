//! `PackTemplateResolver` — a [`TemplateResolver`] over an `Arc<dyn PackRegistry>`
//! (sat/pack-template-bridge, 2026-06-15).
//!
//! Realizes the MODULE-005 §1.4.3 lookup-chain **pack-tier resolution
//! mechanism**: resolve a pack FQ-ref via `PackRegistry::resolve`
//! (CONTRACT-170, MODULE-018 — consumed read-only) → read the on-disk
//! `agent-templates/{name}/` layout (MODULE-018 §2.5: `template.yaml` +
//! `AGENTS.md` + `skills/`; MODULE-005 §1.4.3: `behavior: { type: embedded,
//! binary: behavior.wasm }`) → produce a [`TemplateContent`] (CONTRACT-042)
//! that the existing [`apply_template`](crate::templates::apply_template)
//! materializes onto a freshly-spawned `.agent/` skeleton (inject via
//! [`DefaultSpawner::with_template_resolver`](crate::spawn::DefaultSpawner::with_template_resolver)).
//!
//! # Scope (minimal bridge)
//!
//! - `behavior.type: embedded` only → reads `behavior.wasm` bytes. A
//!   `behavior.type: pack-ref` (a template whose behavior points at another
//!   pack component) yields `behavior_wasm: None` — the recursion (the literal
//!   §1.4.3 step-1 trigger) is a documented TODO for the mainline harvest.
//! - `memory_seed_jsonl` is always `None`: memory-seeds are a SEPARATE pack
//!   content type (`ComponentKind::MemorySeed`, `memory-seeds/*.jsonl` at pack
//!   root), NOT an in-template field — inventing a mapping would be wrong.
//! - `list()` returns empty: the `PackRegistry` trait exposes no per-pack
//!   `provides` enumeration, so a faithful template-name list is not derivable
//!   here. `resolve` is the load-bearing path.
//!
//! # Security
//!
//! Packs are admin-trust but **post-install-tamperable**. Every on-disk read
//! goes through the [`checked_read`] / [`checked_read_dir`] seams, which:
//! 1. assert the target is under `local_path` (a structural containment guard
//!    that closes [`symlink_check`]'s strip_prefix fail-open — see [`guard_under`]);
//! 2. run [`symlink_check`] anchored at the derived pack **install root**
//!    (`local_path.parent().parent()`), so the walk covers the `agent-templates/`
//!    + `{name}/` ancestors and every traversed subdir — catching a post-install
//!    symlink swap of an ancestor dir, not just a leaf;
//! 3. bound the read at [`MAX_BYTES`].
//!
//! The read path is check-then-`File::open` (the same posture as
//! `apply_template`'s write side), NOT pack-manager's `O_NOFOLLOW` helper
//! (which is pack-manager-internal and not reusable here); the residual
//! check-then-open TOCTOU is the crate-documented Slice-A model, and
//! `packs_dir`-and-above is the admin-trust boundary (the `PackRegistry` trait
//! exposes no `packs_dir`, so the install-root anchor is the strongest anchor
//! reachable through the abstraction). See MODULE-005 §3.8.

use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use advance_pack_manager::{ComponentKind, PackRegistry};

use crate::atomic::MAX_BYTES;
use crate::error::SpawnError;
use crate::identifier::is_workspace_hidden_name;
use crate::templates::{
    TemplateContent, TemplateError, TemplateResolver, TemplateSkillEntry, MAX_TEMPLATE_SKILLS,
    MAX_TEMPLATE_TOTAL_BYTES,
};
use crate::workspace::{symlink_check, MAX_PATH_DEPTH};

const TEMPLATE_MANIFEST: &str = "template.yaml";
const AGENTS_MD: &str = "AGENTS.md";
const SKILLS_DIR: &str = "skills";
const DEFAULT_BEHAVIOR_BINARY: &str = "behavior.wasm";

/// Bound on directories walked under `skills/` (defense against a tampered
/// pack with a pathological directory fan-out; files are separately bounded
/// by `MAX_TEMPLATE_SKILLS`).
const MAX_SKILL_DIRS: usize = MAX_TEMPLATE_SKILLS;

/// Per-directory entry-enumeration cap for the skills walk. A single directory
/// in a legitimate template cannot exceed `MAX_TEMPLATE_SKILLS` files +
/// `MAX_SKILL_DIRS` subdirs. Enforcing it INSIDE the `read_dir` loop bounds the
/// `Vec<PathBuf>` allocation AND the downstream per-entry `symlink_metadata`
/// syscalls — so a tampered pack with one fat `skills/` directory (millions of
/// entries) cannot OOM / syscall-storm the resolver before the per-file /
/// per-dir caps trip (adversarial round 11 fix).
const MAX_SKILL_DIR_ENTRIES: usize = MAX_TEMPLATE_SKILLS + MAX_SKILL_DIRS;

/// A [`TemplateResolver`] backed by a [`PackRegistry`]: resolves a pack
/// FQ-ref to a pack-installed agent-template on disk.
#[derive(Clone)]
pub struct PackTemplateResolver {
    registry: Arc<dyn PackRegistry>,
}

impl PackTemplateResolver {
    /// Construct a resolver over an installed-pack registry (consumed
    /// read-only). The `template_ref` passed to [`TemplateResolver::resolve`]
    /// is the pack FQ-ref (`{pack}@{version}/agent-templates/{name}`), forwarded
    /// verbatim to `PackRegistry::resolve`.
    pub fn new(registry: Arc<dyn PackRegistry>) -> Self {
        Self { registry }
    }
}

impl TemplateResolver for PackTemplateResolver {
    fn resolve(&self, template_ref: &str) -> Result<TemplateContent, TemplateError> {
        // Step 1 — resolve via the pack registry (read-only). Any PackError
        // (unversioned/unknown pack/component-not-found/ambiguous) means the
        // ref does not resolve to a template → NotFound.
        let resolution = self
            .registry
            .resolve(template_ref)
            .map_err(|e| TemplateError::NotFound(format!("pack resolve '{template_ref}': {e}")))?;

        // Step 2 — the ref must resolve to an agent-template specifically.
        // (A successful resolution to a different kind is a wrong-kind config
        // error, distinct from an unresolvable ref above.)
        if resolution.component_kind != ComponentKind::AgentTemplate {
            return Err(TemplateError::InvalidContent(format!(
                "pack ref '{template_ref}' resolved to {:?}, not an AgentTemplate",
                resolution.component_kind
            )));
        }

        let local_path = resolution.local_path.as_path();

        // Step 3 — derive the pack install root. For AgentTemplate,
        // `path_for_kind` guarantees `local_path == install_root/agent-templates/{name}`,
        // so `install_root == local_path.parent().parent()`. Anchoring the
        // symlink walk here (not at local_path) lets it cover the
        // `agent-templates/` + `{name}/` ancestor dirs.
        let install_root = local_path.parent().and_then(Path::parent).ok_or_else(|| {
            TemplateError::InvalidContent(format!(
                "cannot derive pack install root from local_path {}",
                local_path.display()
            ))
        })?;

        // template.yaml (REQUIRED) — kept verbatim so `apply_template`'s
        // `check_manifest_kind` sees the original top-level Mapping.
        let manifest_bytes = checked_read(
            install_root,
            local_path,
            &local_path.join(TEMPLATE_MANIFEST),
            MAX_BYTES,
        )
        .map_err(|e| missing_to_invalid(e, "template.yaml"))?;
        let manifest_yaml = String::from_utf8(manifest_bytes).map_err(|_| {
            TemplateError::InvalidContent("template.yaml is not valid UTF-8".to_string())
        })?;

        // AGENTS.md (REQUIRED).
        let agents_bytes = checked_read(
            install_root,
            local_path,
            &local_path.join(AGENTS_MD),
            MAX_BYTES,
        )
        .map_err(|e| missing_to_invalid(e, "AGENTS.md"))?;
        let agents_md = String::from_utf8(agents_bytes).map_err(|_| {
            TemplateError::InvalidContent("AGENTS.md is not valid UTF-8".to_string())
        })?;

        // Parse a COPY of template.yaml for `name` + `behavior` extraction
        // (the verbatim bytes above are the canonical manifest_yaml). This is
        // the FIRST parse of attacker-controllable pack bytes, so run the same
        // YAML anchor/alias amplification pre-scan that `templates.rs` documents
        // for the pack-resolver path (a 64 KiB manifest can still encode a
        // billion-laughs payload — the MAX_BYTES read cap alone is insufficient)
        // BEFORE handing bytes to `serde_yml`. `apply_template`'s
        // `check_manifest_kind` re-runs it later on the write side.
        crate::templates::precheck_manifest_anchors(&manifest_yaml)?;
        let parsed: serde_yml::Value = serde_yml::from_str(&manifest_yaml).map_err(|e| {
            TemplateError::InvalidContent(format!("template.yaml parse error: {e}"))
        })?;

        // name ← template.yaml top-level `name`, else the resolved component name.
        let name = parsed
            .as_mapping()
            .and_then(|m| m.get(serde_yml::Value::String("name".to_string())))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| resolution.manifest_snippet.name.clone());

        let behavior_wasm = read_embedded_behavior(install_root, local_path, &parsed)?;
        // Seed the skills walk's running aggregate with the already-read fields so
        // the resolver's transient payload is bounded by MAX_TEMPLATE_TOTAL_BYTES
        // at read time (not only by apply_template's write-side check).
        let prior_bytes =
            manifest_yaml.len() + agents_md.len() + behavior_wasm.as_ref().map_or(0, |b| b.len());
        let skills = collect_skills(install_root, local_path, prior_bytes)?;

        Ok(TemplateContent {
            name,
            manifest_yaml,
            agents_md,
            skills,
            // Memory-seeds are a separate pack content type, not in-template.
            memory_seed_jsonl: None,
            behavior_wasm,
        })
    }

    fn list(&self) -> Vec<String> {
        // The PackRegistry trait exposes no per-pack `provides` enumeration
        // (`list_installed()` yields PackMetadata —
        // name/version/install_path/trust_level/required_capabilities — but NOT
        // the `provides` lists), so a faithful agent-template-name list is not
        // derivable here. Sanctioned empty; `resolve` is the load-bearing path.
        Vec::new()
    }
}

/// Map a `NotFound` read error to `InvalidContent` for a REQUIRED file: a pack
/// agent-template MUST carry `template.yaml` + `AGENTS.md` (and, when it
/// declares `behavior.type: embedded`, the named binary). A symlink/containment
/// (`PathTraversal`) or size/IO (`InvalidContent`) error propagates unchanged.
fn missing_to_invalid(e: TemplateError, label: &str) -> TemplateError {
    match e {
        TemplateError::NotFound(_) => {
            TemplateError::InvalidContent(format!("required {label} missing from pack template"))
        }
        other => other,
    }
}

/// Structural containment guard. [`symlink_check`]`(root, target)` computes
/// `rel = target.strip_prefix(root).unwrap_or("")`, so if `target` is NOT
/// under `root` the component walk runs zero iterations and the function
/// returns `Ok` after only checking the anchor — a fail-open. Asserting the
/// target is under `local_path` first makes the symlink defense structural
/// rather than discipline-dependent.
fn guard_under(local_path: &Path, path: &Path) -> Result<(), TemplateError> {
    if !path.starts_with(local_path) {
        return Err(TemplateError::PathTraversal(format!(
            "{} escapes pack template dir {}",
            path.display(),
            local_path.display()
        )));
    }
    Ok(())
}

/// Map a `symlink_check` failure with variant fidelity: a detected symlink
/// (`SpawnError::PathTraversal`) stays `PathTraversal`; an anchor stat/IO
/// failure (`SpawnError::WorkspaceIoFailure`, e.g. a missing `install_root` —
/// reachable only off the validated `rescan` path) surfaces as `InvalidContent`
/// rather than masquerading as a traversal/security error.
fn map_symlink_err(e: SpawnError, ctx: &str) -> TemplateError {
    match e {
        SpawnError::PathTraversal(m) => TemplateError::PathTraversal(format!("{ctx}: {m}")),
        other => TemplateError::InvalidContent(format!("{ctx}: {other}")),
    }
}

/// Read a file under `local_path`: containment guard → install-root-anchored
/// `symlink_check` → bounded read (≤ `max`).
fn checked_read(
    install_root: &Path,
    local_path: &Path,
    path: &Path,
    max: usize,
) -> Result<Vec<u8>, TemplateError> {
    guard_under(local_path, path)?;
    symlink_check(install_root, path)
        .map_err(|e| map_symlink_err(e, &format!("symlink_check {}", path.display())))?;
    let file = std::fs::File::open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => {
            TemplateError::NotFound(format!("file not found: {}", path.display()))
        }
        _ => TemplateError::InvalidContent(format!("open {}: {e}", path.display())),
    })?;
    let mut buf = Vec::new();
    // Bound memory at max+1 so an oversized file is rejected, not slurped.
    file.take((max as u64).saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| TemplateError::InvalidContent(format!("read {}: {e}", path.display())))?;
    if buf.len() > max {
        return Err(TemplateError::InvalidContent(format!(
            "{} exceeds MAX_BYTES {max}",
            path.display()
        )));
    }
    Ok(buf)
}

/// List the entries of a directory under `local_path`: containment guard →
/// install-root-anchored `symlink_check` (rejects the dir itself or any
/// ancestor being a symlink) → `read_dir`.
fn checked_read_dir(
    install_root: &Path,
    local_path: &Path,
    dir: &Path,
) -> Result<Vec<PathBuf>, TemplateError> {
    guard_under(local_path, dir)?;
    symlink_check(install_root, dir)
        .map_err(|e| map_symlink_err(e, &format!("symlink_check {}", dir.display())))?;
    let mut entries = Vec::new();
    let rd = std::fs::read_dir(dir)
        .map_err(|e| TemplateError::InvalidContent(format!("read_dir {}: {e}", dir.display())))?;
    for ent in rd {
        // Cap enumeration BEFORE pushing/stat'ing — bounds the Vec + the
        // downstream symlink_metadata syscalls so a single fat directory cannot
        // exhaust memory/syscalls before the per-file/per-dir caps trip.
        if entries.len() >= MAX_SKILL_DIR_ENTRIES {
            return Err(TemplateError::InvalidContent(format!(
                "directory {} entry count exceeds MAX_SKILL_DIR_ENTRIES {MAX_SKILL_DIR_ENTRIES}",
                dir.display()
            )));
        }
        let ent = ent.map_err(|e| {
            TemplateError::InvalidContent(format!("dir entry under {}: {e}", dir.display()))
        })?;
        entries.push(ent.path());
    }
    Ok(entries)
}

/// Read embedded behavior bytes IFF `template.yaml` declares
/// `behavior.type: embedded`. `pack-ref` / unset / unknown → `None` (recursion
/// is mainline/future work). The `behavior.binary` value (default
/// `behavior.wasm`) is validated as a single safe path component before being
/// joined under `local_path`.
fn read_embedded_behavior(
    install_root: &Path,
    local_path: &Path,
    parsed: &serde_yml::Value,
) -> Result<Option<Vec<u8>>, TemplateError> {
    let behavior = match parsed
        .as_mapping()
        .and_then(|m| m.get(serde_yml::Value::String("behavior".to_string())))
        .and_then(|v| v.as_mapping())
    {
        Some(b) => b,
        None => return Ok(None),
    };
    let btype = behavior
        .get(serde_yml::Value::String("type".to_string()))
        .and_then(|v| v.as_str());
    if btype != Some("embedded") {
        // pack-ref / unset / unknown → no embedded bytes (TODO: pack-ref recursion).
        return Ok(None);
    }
    let binary = behavior
        .get(serde_yml::Value::String("binary".to_string()))
        .and_then(|v| v.as_str())
        .unwrap_or(DEFAULT_BEHAVIOR_BINARY);
    validate_single_component(binary)?;
    let bytes = checked_read(
        install_root,
        local_path,
        &local_path.join(binary),
        MAX_BYTES,
    )
    .map_err(|e| missing_to_invalid(e, "behavior.wasm"))?;
    Ok(Some(bytes))
}

/// Reject a `behavior.binary` value that is anything other than a single, safe
/// filename component (no separators, no `..`, not absolute, not a hidden /
/// workspace-reserved name) before it is joined under `local_path`.
fn validate_single_component(name: &str) -> Result<(), TemplateError> {
    // Reject NUL and backslash up front: a NUL stays inside a single
    // `Component::Normal` (so the component check below would pass it) and `\`
    // is an ordinary filename byte on Unix but a separator on Windows — explicit
    // rejection matches this fn's name + doc and keeps it safe if reused without
    // the `guard_under` backstop / on another platform (adversarial round 11).
    if name.contains('\0') || name.contains('\\') {
        return Err(TemplateError::PathTraversal(format!(
            "behavior binary contains a NUL or backslash: {name:?}"
        )));
    }
    let p = Path::new(name);
    let mut comps = p.components();
    match (comps.next(), comps.next()) {
        (Some(Component::Normal(s)), None) => {
            if is_workspace_hidden_name(&s.to_string_lossy()) {
                return Err(TemplateError::PathTraversal(format!(
                    "behavior binary is a hidden/reserved name: {name}"
                )));
            }
            Ok(())
        }
        _ => Err(TemplateError::PathTraversal(format!(
            "behavior binary must be a single path component: {name}"
        ))),
    }
}

/// Walk `skills/` under the template dir into a `TemplateSkillEntry` list.
/// Absent `skills/` → empty. Each directory is `checked_read_dir`'d before
/// recursion (so a swapped subdir is caught even when empty); each file is
/// `checked_read`. Bounded by `MAX_TEMPLATE_SKILLS` (files), `MAX_SKILL_DIRS`
/// (dirs), `MAX_SKILL_DIR_ENTRIES` (per-dir fan-out), `MAX_PATH_DEPTH` (depth),
/// `MAX_BYTES` (per-file) and — running from `prior_bytes` (the already-read
/// manifest+agents+behavior) — the `MAX_TEMPLATE_TOTAL_BYTES` aggregate, so the
/// resolver's transient payload is self-bounded at ~1 MiB rather than relying on
/// `apply_template`'s write-side aggregate check (adversarial round 11).
/// `apply_template` re-validates each skill path + size on write.
fn collect_skills(
    install_root: &Path,
    local_path: &Path,
    prior_bytes: usize,
) -> Result<Vec<TemplateSkillEntry>, TemplateError> {
    let skills_root = local_path.join(SKILLS_DIR);
    match std::fs::symlink_metadata(&skills_root) {
        Ok(_) => {}
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(TemplateError::InvalidContent(format!("stat skills/: {e}"))),
    }
    let mut out: Vec<TemplateSkillEntry> = Vec::new();
    let mut dirs_visited = 0usize;
    let mut aggregate = prior_bytes;
    let mut stack: Vec<(PathBuf, usize)> = vec![(skills_root.clone(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_PATH_DEPTH {
            return Err(TemplateError::PathTraversal(format!(
                "skills/ depth exceeds MAX_PATH_DEPTH {MAX_PATH_DEPTH}"
            )));
        }
        dirs_visited += 1;
        if dirs_visited > MAX_SKILL_DIRS {
            return Err(TemplateError::InvalidContent(format!(
                "skills/ directory count exceeds MAX_SKILL_DIRS {MAX_SKILL_DIRS}"
            )));
        }
        for entry in checked_read_dir(install_root, local_path, &dir)? {
            let meta = std::fs::symlink_metadata(&entry).map_err(|e| {
                TemplateError::InvalidContent(format!("stat {}: {e}", entry.display()))
            })?;
            if meta.file_type().is_symlink() {
                return Err(TemplateError::PathTraversal(format!(
                    "symlink in skills/: {}",
                    entry.display()
                )));
            }
            if meta.is_dir() {
                stack.push((entry, depth + 1));
            } else if meta.is_file() {
                if out.len() >= MAX_TEMPLATE_SKILLS {
                    return Err(TemplateError::InvalidContent(format!(
                        "skills count exceeds MAX_TEMPLATE_SKILLS {MAX_TEMPLATE_SKILLS}"
                    )));
                }
                let content = checked_read(install_root, local_path, &entry, MAX_BYTES)?;
                aggregate = aggregate.saturating_add(content.len());
                if aggregate > MAX_TEMPLATE_TOTAL_BYTES {
                    return Err(TemplateError::InvalidContent(format!(
                        "template aggregate size exceeds MAX_TEMPLATE_TOTAL_BYTES {MAX_TEMPLATE_TOTAL_BYTES}"
                    )));
                }
                let relative_path = entry
                    .strip_prefix(&skills_root)
                    .map_err(|_| {
                        TemplateError::PathTraversal(format!(
                            "skill {} not under skills/",
                            entry.display()
                        ))
                    })?
                    .to_path_buf();
                out.push(TemplateSkillEntry {
                    relative_path,
                    content,
                });
            }
            // Non file/dir/symlink (fifo, socket, …) → skipped.
        }
    }
    Ok(out)
}

//! Slice-B template materialization (MODULE-005 AC-07/08/09/10/19,
//! CONTRACT-042 TemplateResolver — internal, no external consumers per
//! ARCHITECTURE.md §6.1 row CONTRACT-042).
//!
//! Three public surfaces:
//! - [`TemplateContent`] / [`TemplateSkillEntry`] — in-memory template
//!   payload, identical shape for built-in and pack-sourced templates.
//! - [`TemplateResolver`] trait + [`BuiltinTemplateRegistry`] impl with
//!   4 hardcoded runtime built-ins.
//! - [`apply_template`] overlay function — invoked by `DefaultSpawner`
//!   after `init_child_workspace` to materialize template-supplied
//!   bytes onto the freshly-created `.agent/` skeleton.
//!
//! Slice B shipped only the runtime-built-in resolver here; the pack-sourced
//! resolver lands in [`crate::pack_template_resolver::PackTemplateResolver`]
//! (sat/pack-template-bridge, 2026-06-15), which reads a pack-installed
//! agent-template via `PackRegistry` into a [`TemplateContent`]. The lookup
//! chain documented in MODULE-005 §1.4.3 (pack → /.advance/agent-templates/ →
//! runtime built-in) thus now has the pack-tier resolution mechanism (step 1's
//! `behavior.type: pack-ref` recursion remains a documented TODO) and the
//! runtime built-in (step 3, [`BuiltinTemplateRegistry`]) at the cap-lifecycle
//! layer; the admin-local dir tier (step 2) is still future work.

use std::path::{Component, Path, PathBuf};

use advance_shared_types::agent_tree::AgentKind;

use crate::atomic::{atomic_write, MAX_BYTES};
use crate::identifier::is_workspace_hidden_name;
use crate::template_data::builtins;
use crate::workspace::{symlink_check, MAX_PATH_DEPTH};

/// Soft cap on the number of skill entries per template payload.
pub const MAX_TEMPLATE_SKILLS: usize = 64;

/// Aggregate payload cap across all fields of a `TemplateContent`.
/// Defense-in-depth: per-field cap is `atomic::MAX_BYTES` (64 KiB) but
/// 64 entries × 64 KiB = 4 MiB; 1 MiB total cap brings worst-case
/// per-spawn IO back to a reasonable level.
pub const MAX_TEMPLATE_TOTAL_BYTES: usize = 1024 * 1024;

/// Per-manifest defensive caps mirroring `auto_bootstrap`'s anchor /
/// alias pre-scan. Adversarial round-3 fix: a caller-supplied
/// `TemplateResolver` (Slice C pack adapter) can return a
/// `manifest_yaml` up to `MAX_BYTES` (64 KiB) that encodes a YAML
/// billion-laughs amplification. We pre-scan the same way
/// `precheck_yaml_anchors` does before invoking `serde_yml::from_str`
/// inside `check_manifest_kind`.
pub const MAX_MANIFEST_YAML_ANCHORS: usize = 64;
pub const MAX_MANIFEST_YAML_ALIASES: usize = 64;

#[derive(Debug, Clone)]
pub struct TemplateContent {
    pub name: String,
    pub manifest_yaml: String,
    pub agents_md: String,
    pub skills: Vec<TemplateSkillEntry>,
    pub memory_seed_jsonl: Option<String>,
    /// Raw embedded behavior bytes (the manifest's `behavior: { type: embedded,
    /// binary: behavior.wasm }`, MODULE-005 §1.4.3). Raw `Vec<u8>` mirrors
    /// `TemplateSkillEntry.content` rather than a path — a path would couple the
    /// in-memory payload to a filesystem layout and break the built-in/pack
    /// symmetry. Materialized by `apply_template` to `.agent/behavior.wasm` for
    /// ALL kinds (incl. Sub — a Sub still needs a behavior to run), unlike the
    /// kind-gated memory seed. Additive (`None`-default); no external CONTRACT-042
    /// consumer. sat/template-materialization 2026-06-13.
    pub behavior_wasm: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct TemplateSkillEntry {
    pub relative_path: PathBuf,
    pub content: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    #[error("template not found: {0}")]
    NotFound(String),
    #[error("invalid template content: {0}")]
    InvalidContent(String),
    #[error("template path traversal rejected: {0}")]
    PathTraversal(String),
    #[error("template materialization I/O failure: {0}")]
    MaterializationFailure(String),
}

pub trait TemplateResolver: Send + Sync {
    fn resolve(&self, template_ref: &str) -> Result<TemplateContent, TemplateError>;
    fn list(&self) -> Vec<String>;
}

#[derive(Clone)]
pub struct BuiltinTemplateRegistry {
    templates: Vec<TemplateContent>,
}

impl Default for BuiltinTemplateRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BuiltinTemplateRegistry {
    pub fn new() -> Self {
        Self {
            templates: builtins(),
        }
    }
}

impl TemplateResolver for BuiltinTemplateRegistry {
    fn resolve(&self, template_ref: &str) -> Result<TemplateContent, TemplateError> {
        self.templates
            .iter()
            .find(|t| t.name == template_ref)
            .cloned()
            .ok_or_else(|| TemplateError::NotFound(template_ref.to_string()))
    }

    fn list(&self) -> Vec<String> {
        self.templates.iter().map(|t| t.name.clone()).collect()
    }
}

/// Validate a template-supplied skill `relative_path` using Slice A's
/// lexical-walk rules but emit `TemplateError::PathTraversal` instead
/// of `SpawnError::PathTraversal`. Mirrors `workspace::resolve_under_parent`'s
/// component checks. Skill content is later written under
/// `target_dir/.agent/skills/<relative_path>`.
pub(crate) fn validate_template_skill_path(relative_path: &Path) -> Result<(), TemplateError> {
    if relative_path.as_os_str().is_empty() {
        return Err(TemplateError::InvalidContent(
            "skill relative_path is empty".to_string(),
        ));
    }
    if relative_path.is_absolute() {
        return Err(TemplateError::PathTraversal(format!(
            "skill relative_path must be relative: {}",
            relative_path.display()
        )));
    }
    let mut depth = 0usize;
    for comp in relative_path.components() {
        match comp {
            Component::ParentDir => {
                return Err(TemplateError::PathTraversal(format!(
                    "`..` component rejected in skill path: {}",
                    relative_path.display()
                )));
            }
            Component::CurDir => continue,
            Component::Normal(s) => {
                let s = s.to_string_lossy();
                if is_workspace_hidden_name(&s) {
                    return Err(TemplateError::PathTraversal(format!(
                        "hidden-name component rejected in skill path: {s}"
                    )));
                }
                depth += 1;
                if depth > MAX_PATH_DEPTH {
                    return Err(TemplateError::PathTraversal(format!(
                        "skill path depth exceeds MAX_PATH_DEPTH={MAX_PATH_DEPTH}"
                    )));
                }
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err(TemplateError::PathTraversal(format!(
                    "absolute / prefix component rejected in skill path: {}",
                    relative_path.display()
                )));
            }
        }
    }
    Ok(())
}

fn kind_label(kind: &AgentKind) -> &'static str {
    match kind {
        AgentKind::Root => "root",
        AgentKind::Child => "child",
        AgentKind::Sub => "sub",
    }
}

/// Schema-validate a parsed manifest YAML and confirm any `kind:` field
/// matches the actual spawn kind. Returns Ok if no `kind:` is set or
/// the declared value matches; Err with InvalidContent on mismatch /
/// parse failure.
/// Pre-scan `manifest_yaml` for excessive YAML anchor (`&name`) / alias
/// (`*name`) tokens before invoking `serde_yml::from_str`. Bounds the
/// billion-laughs amplification surface for the Slice-C pack-resolver
/// path. Mirrors `auto_bootstrap::precheck_yaml_anchors` semantics.
pub(crate) fn precheck_manifest_anchors(manifest_yaml: &str) -> Result<(), TemplateError> {
    let mut anchor_count = 0usize;
    let mut alias_count = 0usize;
    let bytes = manifest_yaml.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if (b == b'&' || b == b'*') && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            let is_word = next.is_ascii_alphanumeric() || next == b'_' || next == b'-';
            if is_word {
                if b == b'&' {
                    anchor_count += 1;
                    if anchor_count > MAX_MANIFEST_YAML_ANCHORS {
                        return Err(TemplateError::InvalidContent(format!(
                            "manifest_yaml anchor count {anchor_count} exceeds MAX_MANIFEST_YAML_ANCHORS {MAX_MANIFEST_YAML_ANCHORS}"
                        )));
                    }
                } else {
                    alias_count += 1;
                    if alias_count > MAX_MANIFEST_YAML_ALIASES {
                        return Err(TemplateError::InvalidContent(format!(
                            "manifest_yaml alias count {alias_count} exceeds MAX_MANIFEST_YAML_ALIASES {MAX_MANIFEST_YAML_ALIASES}"
                        )));
                    }
                }
            }
        }
        i += 1;
    }
    Ok(())
}

fn check_manifest_kind(manifest_yaml: &str, spawn_kind: &AgentKind) -> Result<(), TemplateError> {
    // Adversarial round-3 fix: pre-scan anchors/aliases before serde_yml parse.
    precheck_manifest_anchors(manifest_yaml)?;
    let value: serde_yml::Value = serde_yml::from_str(manifest_yaml)
        .map_err(|e| TemplateError::InvalidContent(format!("manifest_yaml parse error: {e}")))?;
    // Adversarial round-1 Warning fix: reject non-mapping root values so a
    // pack-supplied YAML sequence/scalar manifest cannot bypass the kind:
    // consistency check. The Slice B contract is "manifest_yaml is a
    // top-level mapping (or empty)". Empty (Null) is tolerated; everything
    // else must be a Mapping.
    let mapping = match value {
        serde_yml::Value::Mapping(m) => m,
        serde_yml::Value::Null => return Ok(()),
        other => {
            let kind_name = match other {
                serde_yml::Value::Sequence(_) => "Sequence",
                serde_yml::Value::String(_) => "String",
                serde_yml::Value::Number(_) => "Number",
                serde_yml::Value::Bool(_) => "Bool",
                serde_yml::Value::Tagged(_) => "Tagged",
                _ => "non-mapping",
            };
            return Err(TemplateError::InvalidContent(format!(
                "manifest_yaml root must be a Mapping or empty, got {kind_name}"
            )));
        }
    };
    let declared = mapping
        .get(serde_yml::Value::String("kind".to_string()))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    if let Some(decl) = declared {
        let expected = kind_label(spawn_kind);
        if decl != expected {
            return Err(TemplateError::InvalidContent(format!(
                "template kind mismatch: declared '{decl}', spawn kind '{expected}'"
            )));
        }
    }
    Ok(())
}

/// Per-field + aggregate size pre-check. Fires BEFORE any IO so payload
/// rejections surface as `InvalidContent` rather than atomic_write's
/// `MaterializationFailure` path.
fn check_payload_sizes(template: &TemplateContent) -> Result<(), TemplateError> {
    if template.manifest_yaml.len() > MAX_BYTES {
        return Err(TemplateError::InvalidContent(format!(
            "manifest_yaml {} exceeds MAX_BYTES {MAX_BYTES}",
            template.manifest_yaml.len()
        )));
    }
    if template.agents_md.len() > MAX_BYTES {
        return Err(TemplateError::InvalidContent(format!(
            "agents_md {} exceeds MAX_BYTES {MAX_BYTES}",
            template.agents_md.len()
        )));
    }
    if let Some(seed) = template.memory_seed_jsonl.as_ref() {
        if seed.len() > MAX_BYTES {
            return Err(TemplateError::InvalidContent(format!(
                "memory_seed_jsonl {} exceeds MAX_BYTES {MAX_BYTES}",
                seed.len()
            )));
        }
    }
    if let Some(behavior) = template.behavior_wasm.as_ref() {
        if behavior.len() > MAX_BYTES {
            return Err(TemplateError::InvalidContent(format!(
                "behavior_wasm {} exceeds MAX_BYTES {MAX_BYTES}",
                behavior.len()
            )));
        }
    }
    if template.skills.len() > MAX_TEMPLATE_SKILLS {
        return Err(TemplateError::InvalidContent(format!(
            "skills.len() {} exceeds MAX_TEMPLATE_SKILLS {MAX_TEMPLATE_SKILLS}",
            template.skills.len()
        )));
    }
    let mut aggregate = template.manifest_yaml.len()
        + template.agents_md.len()
        + template.memory_seed_jsonl.as_ref().map_or(0, |s| s.len())
        + template.behavior_wasm.as_ref().map_or(0, |b| b.len());
    for skill in &template.skills {
        if skill.content.len() > MAX_BYTES {
            return Err(TemplateError::InvalidContent(format!(
                "skill `{}` content {} exceeds MAX_BYTES {MAX_BYTES}",
                skill.relative_path.display(),
                skill.content.len()
            )));
        }
        aggregate += skill.content.len();
    }
    if aggregate > MAX_TEMPLATE_TOTAL_BYTES {
        return Err(TemplateError::InvalidContent(format!(
            "aggregate size {aggregate} exceeds MAX_TEMPLATE_TOTAL_BYTES {MAX_TEMPLATE_TOTAL_BYTES}"
        )));
    }
    Ok(())
}

fn check_skill_total_depth(
    target_dir: &Path,
    workspace_root: &Path,
    relative_path: &Path,
) -> Result<(), TemplateError> {
    let target_rel = target_dir.strip_prefix(workspace_root).map_err(|_| {
        TemplateError::PathTraversal(format!(
            "target_dir {} outside workspace_root {}",
            target_dir.display(),
            workspace_root.display()
        ))
    })?;
    let target_depth = target_rel
        .components()
        .filter(|c| !matches!(c, Component::CurDir))
        .count();
    const SKILLS_PREFIX_DEPTH: usize = 2;
    let skill_depth = relative_path
        .components()
        .filter(|c| !matches!(c, Component::CurDir))
        .count();
    let total = target_depth + SKILLS_PREFIX_DEPTH + skill_depth;
    if total > MAX_PATH_DEPTH {
        return Err(TemplateError::PathTraversal(format!(
            "total path depth {total} exceeds MAX_PATH_DEPTH {MAX_PATH_DEPTH}"
        )));
    }
    Ok(())
}

/// Overlay `template`'s contents on top of the Slice A `init_child_workspace`
/// skeleton at `target_dir`. Idempotent at the file level (atomic_write
/// rename overwrites existing placeholders). On any error the caller
/// (typically the spawner) is responsible for target_dir-level rollback
/// — `apply_template` does NOT clean up partial writes itself.
pub fn apply_template(
    target_dir: &Path,
    template: &TemplateContent,
    kind: AgentKind,
    workspace_root: &Path,
) -> Result<(), TemplateError> {
    debug_assert!(
        target_dir.join(".agent").is_dir(),
        "apply_template precondition: target_dir/.agent/ must exist"
    );

    // Step 1: pre-materialization symlink defense. Surface as PathTraversal
    // (NOT MaterializationFailure) so callers can distinguish a symlink-based
    // attack from a true IO failure — and so the spawn-side TemplateError →
    // SpawnError mapping preserves the PathTraversal variant.
    symlink_check(workspace_root, target_dir)
        .map_err(|e| TemplateError::PathTraversal(format!("symlink_check: {e}")))?;

    // Step 2: aggregate + per-field size pre-check.
    check_payload_sizes(template)?;

    // Step 2b: manifest schema-validation (kind field consistency).
    check_manifest_kind(&template.manifest_yaml, &kind)?;

    let agent_dir = target_dir.join(".agent");

    // Step 3: overwrite config.yaml.
    atomic_write(
        &agent_dir.join("config.yaml"),
        template.manifest_yaml.as_bytes(),
    )
    .map_err(|e| TemplateError::MaterializationFailure(format!("config.yaml: {e}")))?;

    // Step 4: overwrite AGENTS.md.
    atomic_write(&agent_dir.join("AGENTS.md"), template.agents_md.as_bytes())
        .map_err(|e| TemplateError::MaterializationFailure(format!("AGENTS.md: {e}")))?;

    // Step 5: skills (each path validated, total-depth check, per-skill
    // symlink_check re-run, then write). The per-skill re-run narrows the
    // TOCTOU window from "single up-front check before N writes" to
    // "single check per write" — matches Slice A `init_child_workspace`'s
    // belt-and-suspenders posture.
    let skills_root = agent_dir.join("skills");
    for skill in &template.skills {
        validate_template_skill_path(&skill.relative_path)?;
        check_skill_total_depth(target_dir, workspace_root, &skill.relative_path)?;
        let dest = skills_root.join(&skill.relative_path);
        if let Some(parent) = dest.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    TemplateError::MaterializationFailure(format!(
                        "create_dir_all {}: {e}",
                        parent.display()
                    ))
                })?;
            }
        }
        symlink_check(workspace_root, &dest)
            .map_err(|e| TemplateError::PathTraversal(format!("skill symlink_check: {e}")))?;
        atomic_write(&dest, &skill.content).map_err(|e| {
            TemplateError::MaterializationFailure(format!("skill {}: {e}", dest.display()))
        })?;
    }

    // Step 5b: behavior.wasm (ALL kinds — incl. Sub, which still needs a
    // behavior to run; deliberately NOT kind-gated like the memory seed at
    // Step 6). The dest is a fixed leaf under `.agent/` (not caller-controlled),
    // so it inherits workspace containment; the per-write `symlink_check`
    // mirrors the skills loop's belt-and-suspenders TOCTOU narrowing, and the
    // size is already bounded by `check_payload_sizes` (per-field MAX_BYTES +
    // the MAX_TEMPLATE_TOTAL_BYTES aggregate). MODULE-005 §1.4.3, SYS-AC-022.
    if let Some(behavior) = template.behavior_wasm.as_ref() {
        let dest = agent_dir.join("behavior.wasm");
        symlink_check(workspace_root, &dest).map_err(|e| {
            TemplateError::PathTraversal(format!("behavior.wasm symlink_check: {e}"))
        })?;
        atomic_write(&dest, behavior)
            .map_err(|e| TemplateError::MaterializationFailure(format!("behavior.wasm: {e}")))?;
    }

    // Step 6: memory seed (Child + Root only — never for Sub).
    match kind {
        AgentKind::Child | AgentKind::Root => {
            if let Some(seed) = template.memory_seed_jsonl.as_ref() {
                let memory_dir = agent_dir.join("memory");
                let knowledge = memory_dir.join("knowledge.jsonl");
                atomic_write(&knowledge, seed.as_bytes()).map_err(|e| {
                    TemplateError::MaterializationFailure(format!("knowledge.jsonl: {e}"))
                })?;
            }
        }
        AgentKind::Sub => {
            // Silent skip per AC-09: memory-seed materialized for {Child, Root}
            // only; never for Sub regardless of template content. AC-09's
            // load-bearing invariant is the negative case (never for Sub) —
            // the {Child, Root} positive set is documented in MODULE-005 §1.4
            // AC-09 + §1.4.3 Materialization at spawn.
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn canon(p: &Path) -> PathBuf {
        p.canonicalize().expect("canonicalize")
    }

    fn make_child_skeleton(root: &Path) -> (PathBuf, PathBuf) {
        let target = root.join("agents").join("foo");
        crate::workspace::init_child_workspace(&target, AgentKind::Child, root)
            .expect("init_child_workspace");
        (target.clone(), target.join(".agent"))
    }

    fn make_sub_skeleton(root: &Path) -> (PathBuf, PathBuf) {
        let target = root.join(".sub").join("sub-uuid");
        crate::workspace::init_child_workspace(&target, AgentKind::Sub, root)
            .expect("init_child_workspace");
        (target.clone(), target.join(".agent"))
    }

    fn builtin_explorer() -> TemplateContent {
        BuiltinTemplateRegistry::new().resolve("explorer").unwrap()
    }

    #[test]
    fn builtin_registry_lists_four_names() {
        let r = BuiltinTemplateRegistry::new();
        let list = r.list();
        assert_eq!(list.len(), 4);
        assert!(list.contains(&"explorer".to_string()));
        assert!(list.contains(&"planner".to_string()));
        assert!(list.contains(&"reviewer".to_string()));
        assert!(list.contains(&"general-purpose".to_string()));
    }

    #[test]
    fn builtin_registry_resolves_each() {
        let r = BuiltinTemplateRegistry::new();
        for name in ["explorer", "planner", "reviewer", "general-purpose"] {
            let t = r.resolve(name).unwrap();
            assert_eq!(t.name, name);
            assert!(
                !t.manifest_yaml.is_empty(),
                "manifest_yaml empty for {name}"
            );
            assert!(t.agents_md.contains("Self-Improvement Guidelines"));
        }
    }

    #[test]
    fn resolve_unknown_returns_not_found() {
        let r = BuiltinTemplateRegistry::new();
        let err = r.resolve("nope").unwrap_err();
        assert!(matches!(err, TemplateError::NotFound(_)));
    }

    #[test]
    fn apply_template_writes_config_yaml() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let (target, agent) = make_child_skeleton(&root);
        let template = builtin_explorer();
        apply_template(&target, &template, AgentKind::Child, &root).unwrap();
        let contents = std::fs::read_to_string(agent.join("config.yaml")).unwrap();
        assert_eq!(contents, template.manifest_yaml);
    }

    #[test]
    fn apply_template_writes_agents_md() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let (target, agent) = make_child_skeleton(&root);
        let template = builtin_explorer();
        apply_template(&target, &template, AgentKind::Child, &root).unwrap();
        let contents = std::fs::read_to_string(agent.join("AGENTS.md")).unwrap();
        assert_eq!(contents, template.agents_md);
        assert!(contents.contains("Self-Improvement Guidelines"));
    }

    #[test]
    fn apply_template_memory_seed_kind_child() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let (target, agent) = make_child_skeleton(&root);
        let mut template = builtin_explorer();
        template.memory_seed_jsonl = Some("{\"key\": \"value\"}\n".to_string());
        apply_template(&target, &template, AgentKind::Child, &root).unwrap();
        let contents = std::fs::read_to_string(agent.join("memory/knowledge.jsonl")).unwrap();
        assert_eq!(contents, "{\"key\": \"value\"}\n");
    }

    #[test]
    fn apply_template_memory_seed_kind_sub_skipped() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let (target, agent) = make_sub_skeleton(&root);
        let mut template = builtin_explorer();
        template.memory_seed_jsonl = Some("{\"should\": \"not write\"}\n".to_string());
        // Sub's .agent/memory/ does NOT exist; apply_template MUST skip silently.
        apply_template(&target, &template, AgentKind::Sub, &root).unwrap();
        assert!(!agent.join("memory").exists());
    }

    #[test]
    fn apply_template_rejects_oversize_config_yaml() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let (target, _agent) = make_child_skeleton(&root);
        let mut template = builtin_explorer();
        template.manifest_yaml = "x".repeat(MAX_BYTES + 1);
        let err = apply_template(&target, &template, AgentKind::Child, &root).unwrap_err();
        assert!(
            matches!(err, TemplateError::InvalidContent(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn apply_template_rejects_aggregate_oversize() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let (target, _agent) = make_child_skeleton(&root);
        let mut template = builtin_explorer();
        // Build aggregate > 1 MiB using ~17 max-sized skills (= ~1.06 MiB).
        let big = vec![0u8; MAX_BYTES];
        for i in 0..17 {
            template.skills.push(TemplateSkillEntry {
                relative_path: PathBuf::from(format!("skill_{i}.md")),
                content: big.clone(),
            });
        }
        let err = apply_template(&target, &template, AgentKind::Child, &root).unwrap_err();
        assert!(
            matches!(err, TemplateError::InvalidContent(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn apply_template_rejects_skills_overlimit() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let (target, _agent) = make_child_skeleton(&root);
        let mut template = builtin_explorer();
        for i in 0..(MAX_TEMPLATE_SKILLS + 1) {
            template.skills.push(TemplateSkillEntry {
                relative_path: PathBuf::from(format!("skill_{i}.md")),
                content: b"x".to_vec(),
            });
        }
        let err = apply_template(&target, &template, AgentKind::Child, &root).unwrap_err();
        assert!(matches!(err, TemplateError::InvalidContent(_)));
    }

    #[test]
    fn apply_template_rejects_skill_path_traversal() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let (target, _agent) = make_child_skeleton(&root);
        let mut template = builtin_explorer();
        template.skills.push(TemplateSkillEntry {
            relative_path: PathBuf::from("../escape"),
            content: b"x".to_vec(),
        });
        let err = apply_template(&target, &template, AgentKind::Child, &root).unwrap_err();
        assert!(matches!(err, TemplateError::PathTraversal(_)));
    }

    #[test]
    fn apply_template_rejects_skill_absolute_path() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let (target, _agent) = make_child_skeleton(&root);
        let mut template = builtin_explorer();
        template.skills.push(TemplateSkillEntry {
            relative_path: PathBuf::from("/etc/passwd"),
            content: b"x".to_vec(),
        });
        let err = apply_template(&target, &template, AgentKind::Child, &root).unwrap_err();
        assert!(matches!(err, TemplateError::PathTraversal(_)));
    }

    #[test]
    fn apply_template_writes_skills() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let (target, agent) = make_child_skeleton(&root);
        let mut template = builtin_explorer();
        template.skills.push(TemplateSkillEntry {
            relative_path: PathBuf::from("nested/skill.md"),
            content: b"# my skill\n".to_vec(),
        });
        apply_template(&target, &template, AgentKind::Child, &root).unwrap();
        let contents = std::fs::read_to_string(agent.join("skills/nested/skill.md")).unwrap();
        assert_eq!(contents, "# my skill\n");
    }

    #[test]
    fn apply_template_rejects_kind_mismatch_in_manifest() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let (target, _agent) = make_sub_skeleton(&root);
        let mut template = builtin_explorer();
        template.manifest_yaml = "name: explorer\nkind: child\n".to_string();
        let err = apply_template(&target, &template, AgentKind::Sub, &root).unwrap_err();
        assert!(
            matches!(err, TemplateError::InvalidContent(ref msg) if msg.contains("kind mismatch")),
            "got {err:?}"
        );
    }

    #[test]
    fn apply_template_accepts_kind_omitted_in_manifest() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let (target, _agent) = make_sub_skeleton(&root);
        let template = builtin_explorer(); // built-in omits `kind:`
        apply_template(&target, &template, AgentKind::Sub, &root).unwrap();
    }

    #[test]
    fn apply_template_accepts_kind_matching_manifest() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let (target, _agent) = make_child_skeleton(&root);
        let mut template = builtin_explorer();
        template.manifest_yaml = "name: explorer\nkind: child\n".to_string();
        apply_template(&target, &template, AgentKind::Child, &root).unwrap();
    }

    #[test]
    fn apply_template_rejects_non_mapping_manifest_sequence() {
        // Adversarial round-1 Warning fix: a top-level YAML sequence cannot
        // carry a `kind:` field, but the kind-mismatch check would have
        // silently accepted it under the prior implementation, letting a
        // pack-supplied template bypass the kind: consistency rule.
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let (target, _agent) = make_child_skeleton(&root);
        let mut template = builtin_explorer();
        template.manifest_yaml = "- a\n- b\n".to_string();
        let err = apply_template(&target, &template, AgentKind::Child, &root).unwrap_err();
        assert!(
            matches!(err, TemplateError::InvalidContent(ref msg) if msg.contains("Mapping")),
            "got {err:?}"
        );
    }

    #[test]
    fn apply_template_rejects_non_mapping_manifest_scalar() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let (target, _agent) = make_child_skeleton(&root);
        let mut template = builtin_explorer();
        template.manifest_yaml = "\"just a string\"\n".to_string();
        let err = apply_template(&target, &template, AgentKind::Child, &root).unwrap_err();
        assert!(
            matches!(err, TemplateError::InvalidContent(ref msg) if msg.contains("Mapping")),
            "got {err:?}"
        );
    }

    #[test]
    fn apply_template_rejects_manifest_with_anchor_amplification() {
        // Adversarial round-3 fix: pre-scan blocks billion-laughs payloads
        // in caller-supplied manifest_yaml before serde_yml parse.
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let (target, _agent) = make_child_skeleton(&root);
        let mut template = builtin_explorer();
        let mut manifest = String::from("name: x\n");
        for i in 0..=MAX_MANIFEST_YAML_ANCHORS {
            manifest.push_str(&format!("key_{i}: &a_{i} value\n"));
        }
        template.manifest_yaml = manifest;
        let err = apply_template(&target, &template, AgentKind::Child, &root).unwrap_err();
        assert!(
            matches!(err, TemplateError::InvalidContent(ref msg) if msg.contains("anchor")),
            "got {err:?}"
        );
    }

    // ── behavior.wasm materialization (sat/template-materialization 2026-06-13) ──

    #[test]
    fn apply_template_writes_behavior_wasm() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let (target, agent) = make_child_skeleton(&root);
        let mut template = builtin_explorer();
        template.behavior_wasm = Some(b"\0asm\x01\0\0\0".to_vec());
        apply_template(&target, &template, AgentKind::Child, &root).unwrap();
        let bytes = std::fs::read(agent.join("behavior.wasm")).unwrap();
        assert_eq!(bytes, b"\0asm\x01\0\0\0");
    }

    #[test]
    fn apply_template_no_behavior_wasm_when_none() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let (target, agent) = make_child_skeleton(&root);
        let template = builtin_explorer(); // behavior_wasm: None
        apply_template(&target, &template, AgentKind::Child, &root).unwrap();
        assert!(!agent.join("behavior.wasm").exists());
    }

    #[test]
    fn apply_template_writes_behavior_wasm_for_sub() {
        // Load-bearing: unlike the kind-gated memory seed (Child/Root only),
        // behavior.wasm IS materialized for a Sub — a Sub still needs a behavior
        // to run. Contrast `apply_template_memory_seed_kind_sub_skipped`.
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let (target, agent) = make_sub_skeleton(&root);
        let mut template = builtin_explorer();
        template.behavior_wasm = Some(b"\0asm\x01\0\0\0".to_vec());
        apply_template(&target, &template, AgentKind::Sub, &root).unwrap();
        let bytes = std::fs::read(agent.join("behavior.wasm")).unwrap();
        assert_eq!(bytes, b"\0asm\x01\0\0\0");
        // The memory seed is still NOT written for a Sub.
        assert!(!agent.join("memory").exists());
    }

    #[test]
    fn apply_template_rejects_oversize_behavior_wasm() {
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let (target, _agent) = make_child_skeleton(&root);
        let mut template = builtin_explorer();
        template.behavior_wasm = Some(vec![0u8; MAX_BYTES + 1]);
        let err = apply_template(&target, &template, AgentKind::Child, &root).unwrap_err();
        // Pin the per-field behavior_wasm clause specifically (a MAX_BYTES+1
        // payload with the tiny explorer base is far under the 1 MiB aggregate,
        // so only the per-field cap can reject it).
        assert!(
            matches!(err, TemplateError::InvalidContent(ref msg) if msg.contains("behavior_wasm")),
            "got {err:?}"
        );
    }

    #[test]
    fn apply_template_behavior_wasm_folds_into_aggregate() {
        // 15 max-sized skills (983040 B) + the explorer 297-byte base = 983337 B
        // < MAX_TEMPLATE_TOTAL_BYTES (1048576) → passes; adding behavior_wasm at
        // MAX_BYTES (65536 B) → 1048873 B > cap → InvalidContent. So behavior_wasm
        // is what tips the aggregate over. Build on builtin_explorer() — a zeroed
        // base lands at exactly 16×MAX == cap (not `>`) and would falsely pass.
        let tmp = TempDir::new().unwrap();
        let root = canon(tmp.path());
        let (target, _agent) = make_child_skeleton(&root);
        let mut template = builtin_explorer();
        let big = vec![0u8; MAX_BYTES];
        for i in 0..15 {
            template.skills.push(TemplateSkillEntry {
                relative_path: PathBuf::from(format!("skill_{i}.md")),
                content: big.clone(),
            });
        }
        // 15 max skills + explorer base alone stay under the aggregate cap.
        apply_template(&target, &template, AgentKind::Child, &root)
            .expect("15 max skills + explorer base must fit under MAX_TEMPLATE_TOTAL_BYTES");
        // Folding behavior_wasm at MAX_BYTES into the aggregate tips it over.
        template.behavior_wasm = Some(big.clone());
        let err = apply_template(&target, &template, AgentKind::Child, &root).unwrap_err();
        assert!(
            matches!(err, TemplateError::InvalidContent(_)),
            "got {err:?}"
        );
    }
}

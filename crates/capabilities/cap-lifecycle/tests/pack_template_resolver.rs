//! Witness for `PackTemplateResolver` (sat/pack-template-bridge, 2026-06-15).
//! MODULE-005-T39. Strengthens AC-07 (template structure: template.yaml /
//! behavior.wasm / AGENTS.md / skills — NOT the memory-seed clause) + AC-08
//! (materialization) from the **pack-sourced** angle (previously only built-in
//! templates were witnessed). 16 cases.
//!
//! Fixture mirrors pack-manager/tests/namespace_lookup.rs's MINIMAL-provides
//! install pattern (declare only what is materialized at top level), driving a
//! real `advance_pack_manager::Installer` so resolution reads a genuinely
//! installed pack on disk.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use advance_pack_manager::{
    AutoApprove, InMemoryPackRegistry, Installer, PackRegistry, RecordingTraceSink,
};
use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus, Capability};
use cap_lifecycle::{
    AgentTreeStore, DefaultSpawner, PackTemplateResolver, SpawnChildConfig, SpawnError, Spawner,
    SpawnerSubsetGate, TemplateError, TemplateResolver, MAX_BYTES, MAX_MANIFEST_YAML_ANCHORS,
};
use tempfile::TempDir;

#[cfg(unix)]
use std::os::unix::fs::symlink;

const PACK: &str = "researcher-pack";
const VER: &str = "1.0.0";
const FQ: &str = "researcher-pack@1.0.0/agent-templates/researcher";

const EMBEDDED_TEMPLATE_YAML: &str = "name: researcher\nversion: 1.0.0\ndescription: Research template\nbehavior:\n  type: embedded\n  binary: behavior.wasm\ndefault-model: sonnet\n";
const PACKREF_TEMPLATE_YAML: &str =
    "name: researcher\nbehavior:\n  type: pack-ref\n  ref: other-pack@1.0.0/behavior-binaries/x\n";
const NOBEHAVIOR_TEMPLATE_YAML: &str = "name: researcher\ndescription: no behavior block\n";
const AGENTS_MD_MARKER: &str = "RESEARCHER-TEMPLATE-MARKER";
const TINY_WASM: &[u8] = b"\0asm\x01\0\0\0";
const SKILL_REL: &str = "web-search/SKILL.md";
const SKILL_CONTENT: &str = "# Web search skill";

// ── fixture ────────────────────────────────────────────────────────────────

struct PackOpts {
    /// `None` = omit template.yaml from the installed template dir.
    template_yaml: Option<String>,
    /// `None` = omit AGENTS.md.
    agents_md: Option<String>,
    /// `Some` = write behavior.wasm inside the template dir.
    behavior_wasm: Option<Vec<u8>>,
    /// `Some((rel, content))` = write a nested skills/<rel> file inside the template dir.
    skill: Option<(&'static str, &'static str)>,
    /// `Some((count, bytes_each))` = write `count` flat files of `bytes_each`
    /// bytes directly under the template's `skills/` dir (drives the per-dir
    /// fan-out and aggregate-size DoS bounds).
    bulk_skills: Option<(usize, usize)>,
    /// Also declare top-level `provides: skills: [web-search]` + materialize the
    /// matching top-level `skills/web-search/SKILL.md` (drives the wrong-kind case).
    declare_skill: bool,
}

impl Default for PackOpts {
    fn default() -> Self {
        Self {
            template_yaml: Some(EMBEDDED_TEMPLATE_YAML.to_string()),
            agents_md: Some(format!("# Researcher\n\n{AGENTS_MD_MARKER}\n")),
            behavior_wasm: Some(TINY_WASM.to_vec()),
            skill: Some((SKILL_REL, SKILL_CONTENT)),
            bulk_skills: None,
            declare_skill: false,
        }
    }
}

fn write_source(src: &Path, opts: &PackOpts) {
    let tdir = src.join("agent-templates").join("researcher");
    std::fs::create_dir_all(&tdir).unwrap();
    if let Some(ref ty) = opts.template_yaml {
        std::fs::write(tdir.join("template.yaml"), ty).unwrap();
    }
    if let Some(ref md) = opts.agents_md {
        std::fs::write(tdir.join("AGENTS.md"), md).unwrap();
    }
    if let Some(ref bw) = opts.behavior_wasm {
        std::fs::write(tdir.join("behavior.wasm"), bw).unwrap();
    }
    if let Some((rel, content)) = opts.skill {
        let p = tdir.join("skills").join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content.as_bytes()).unwrap();
    }
    if let Some((count, bytes_each)) = opts.bulk_skills {
        let sd = tdir.join("skills");
        std::fs::create_dir_all(&sd).unwrap();
        let blob = vec![b'x'; bytes_each];
        for i in 0..count {
            std::fs::write(sd.join(format!("sk_{i}.md")), &blob).unwrap();
        }
    }
    let mut provides = String::from("  agent-templates: [researcher]\n");
    if opts.declare_skill {
        provides.push_str("  skills: [web-search]\n");
        let sp = src.join("skills").join("web-search");
        std::fs::create_dir_all(&sp).unwrap();
        std::fs::write(sp.join("SKILL.md"), b"# top-level skill").unwrap();
    }
    let pack_yaml = format!(
        "name: {PACK}\nversion: {VER}\nruntime-version: \">=0.0.1\"\ndependencies: []\nprovides:\n{provides}required-capabilities: []\ntrust-level: untrusted\nchecksums:\n  algo: sha256\n  files: {{}}\n"
    );
    std::fs::write(src.join("pack.yaml"), pack_yaml).unwrap();
}

/// Build a source pack + install it via the async `Installer` into a packs dir.
/// Returns the kept-alive TempDir (holds the installed copy resolve() reads) and
/// the populated registry.
async fn install_pack(opts: PackOpts) -> (TempDir, Arc<InMemoryPackRegistry>) {
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("source-pack");
    std::fs::create_dir_all(&src).unwrap();
    write_source(&src, &opts);
    let packs_dir = tmp.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let installer = Installer {
        packs_dir,
        registry: registry.clone(),
        current_runtime_version: "0.5.0".into(),
        approval: Arc::new(AutoApprove),
        trace_sink: Arc::new(RecordingTraceSink::default()),
        dep_resolver: None,
        event_bus: None,
        registry_client: None,
        fetch_timeout: None,
    };
    installer
        .install(src.to_string_lossy().as_ref())
        .await
        .expect("install fixture pack");
    (tmp, registry)
}

fn installed_template_dir(reg: &Arc<InMemoryPackRegistry>) -> PathBuf {
    reg.resolve(FQ).expect("resolve FQ").local_path
}

// ── resolve cases ────────────────────────────────────────────────────────────

#[tokio::test]
async fn t_ptr_01_resolve_happy_embedded() {
    let (_tmp, reg) = install_pack(PackOpts::default()).await;
    let resolver = PackTemplateResolver::new(reg);
    let tc = resolver.resolve(FQ).expect("resolve");
    assert_eq!(tc.name, "researcher");
    // manifest_yaml is the verbatim template.yaml (so check_manifest_kind sees the original).
    assert_eq!(tc.manifest_yaml, EMBEDDED_TEMPLATE_YAML);
    assert!(
        tc.agents_md.contains(AGENTS_MD_MARKER),
        "agents_md: {}",
        tc.agents_md
    );
    assert_eq!(tc.behavior_wasm.as_deref(), Some(TINY_WASM));
    assert_eq!(tc.memory_seed_jsonl, None);
    assert_eq!(tc.skills.len(), 1, "expected exactly the one nested skill");
    assert_eq!(tc.skills[0].relative_path, PathBuf::from(SKILL_REL));
    assert_eq!(tc.skills[0].content, SKILL_CONTENT.as_bytes());
}

#[tokio::test]
async fn t_ptr_02_behavior_pack_ref_yields_none() {
    let (_tmp, reg) = install_pack(PackOpts {
        template_yaml: Some(PACKREF_TEMPLATE_YAML.to_string()),
        behavior_wasm: None,
        ..Default::default()
    })
    .await;
    let resolver = PackTemplateResolver::new(reg);
    let tc = resolver.resolve(FQ).expect("resolve");
    assert_eq!(
        tc.behavior_wasm, None,
        "pack-ref behavior must not be read (recursion TODO)"
    );
}

#[tokio::test]
async fn t_ptr_03_no_behavior_block_yields_none() {
    let (_tmp, reg) = install_pack(PackOpts {
        template_yaml: Some(NOBEHAVIOR_TEMPLATE_YAML.to_string()),
        behavior_wasm: None,
        ..Default::default()
    })
    .await;
    let resolver = PackTemplateResolver::new(reg);
    let tc = resolver.resolve(FQ).expect("resolve");
    assert_eq!(tc.behavior_wasm, None);
}

#[tokio::test]
async fn t_ptr_04_missing_template_yaml_is_invalid() {
    let (_tmp, reg) = install_pack(PackOpts {
        template_yaml: None,
        ..Default::default()
    })
    .await;
    let resolver = PackTemplateResolver::new(reg);
    let err = resolver.resolve(FQ).unwrap_err();
    assert!(
        matches!(err, TemplateError::InvalidContent(_)),
        "got {err:?}"
    );
}

#[tokio::test]
async fn t_ptr_05_missing_agents_md_is_invalid() {
    let (_tmp, reg) = install_pack(PackOpts {
        agents_md: None,
        ..Default::default()
    })
    .await;
    let resolver = PackTemplateResolver::new(reg);
    let err = resolver.resolve(FQ).unwrap_err();
    assert!(
        matches!(err, TemplateError::InvalidContent(_)),
        "got {err:?}"
    );
}

#[tokio::test]
async fn t_ptr_06_unknown_ref_is_not_found() {
    let (_tmp, reg) = install_pack(PackOpts::default()).await;
    let resolver = PackTemplateResolver::new(reg);
    let err = resolver
        .resolve("nope-pack@9.9.9/agent-templates/x")
        .unwrap_err();
    assert!(matches!(err, TemplateError::NotFound(_)), "got {err:?}");
}

#[tokio::test]
async fn t_ptr_07_wrong_kind_is_invalid() {
    // Declare + materialize a real top-level skill so resolve() SUCCEEDS with
    // ComponentKind::Skill — the only way to reach the step-2 wrong-kind guard
    // (a minimal agent-templates-only fixture would yield ComponentNotFound →
    // NotFound and never exercise step 2).
    let (_tmp, reg) = install_pack(PackOpts {
        declare_skill: true,
        ..Default::default()
    })
    .await;
    let resolver = PackTemplateResolver::new(reg);
    let err = resolver
        .resolve("researcher-pack@1.0.0/skills/web-search")
        .unwrap_err();
    assert!(
        matches!(err, TemplateError::InvalidContent(_)),
        "got {err:?}"
    );
}

#[tokio::test]
async fn t_ptr_08_oversize_template_yaml_is_invalid() {
    let (_tmp, reg) = install_pack(PackOpts {
        template_yaml: Some("x".repeat(MAX_BYTES + 1)),
        behavior_wasm: None,
        skill: None,
        ..Default::default()
    })
    .await;
    let resolver = PackTemplateResolver::new(reg);
    let err = resolver.resolve(FQ).unwrap_err();
    assert!(
        matches!(err, TemplateError::InvalidContent(_)),
        "got {err:?}"
    );
}

#[tokio::test]
async fn t_ptr_14_anchor_amplification_template_yaml_is_invalid() {
    // The resolver runs the YAML anchor/alias amplification pre-scan BEFORE
    // serde_yml::from_str (a 64 KiB manifest can still encode billion-laughs;
    // the MAX_BYTES read cap is insufficient). > MAX_MANIFEST_YAML_ANCHORS
    // anchors → InvalidContent at resolve time.
    let mut manifest = String::from("name: researcher\n");
    for i in 0..=MAX_MANIFEST_YAML_ANCHORS {
        manifest.push_str(&format!("key_{i}: &a_{i} value\n"));
    }
    let (_tmp, reg) = install_pack(PackOpts {
        template_yaml: Some(manifest),
        behavior_wasm: None,
        skill: None,
        ..Default::default()
    })
    .await;
    let resolver = PackTemplateResolver::new(reg);
    let err = resolver.resolve(FQ).unwrap_err();
    assert!(
        matches!(err, TemplateError::InvalidContent(_)),
        "got {err:?}"
    );
}

#[tokio::test]
async fn t_ptr_15_fat_skills_dir_is_invalid() {
    // A single skills/ dir with far more entries than the per-dir fan-out cap is
    // rejected during enumeration (before the Vec/syscall storm) — adversarial
    // round-11 DoS regression. 300 > MAX_SKILL_DIR_ENTRIES (= 2*MAX_TEMPLATE_SKILLS = 128).
    let (_tmp, reg) = install_pack(PackOpts {
        skill: None,
        behavior_wasm: None,
        bulk_skills: Some((300, 1)),
        ..Default::default()
    })
    .await;
    let resolver = PackTemplateResolver::new(reg);
    let err = resolver.resolve(FQ).unwrap_err();
    assert!(
        matches!(err, TemplateError::InvalidContent(_)),
        "got {err:?}"
    );
}

#[tokio::test]
async fn t_ptr_16_aggregate_over_total_bytes_is_invalid() {
    // 16 × 64 KiB skill files = 1 MiB; with the manifest/agents prior bytes the
    // running aggregate exceeds MAX_TEMPLATE_TOTAL_BYTES. Each file is ≤ MAX_BYTES
    // and 16 is under both the per-file-count and per-dir caps, so the resolver's
    // own aggregate guard is what rejects (adversarial round-11 regression).
    let (_tmp, reg) = install_pack(PackOpts {
        skill: None,
        behavior_wasm: None,
        bulk_skills: Some((16, MAX_BYTES)),
        ..Default::default()
    })
    .await;
    let resolver = PackTemplateResolver::new(reg);
    let err = resolver.resolve(FQ).unwrap_err();
    assert!(
        matches!(err, TemplateError::InvalidContent(_)),
        "got {err:?}"
    );
}

#[tokio::test]
async fn t_ptr_11_list_returns_empty() {
    let (_tmp, reg) = install_pack(PackOpts::default()).await;
    let resolver = PackTemplateResolver::new(reg);
    assert!(resolver.list().is_empty());
}

// ── security: post-install symlink tamper ────────────────────────────────────

#[cfg(unix)]
#[tokio::test]
async fn t_ptr_09_leaf_symlink_is_path_traversal() {
    let (_tmp, reg) = install_pack(PackOpts::default()).await;
    let local = installed_template_dir(&reg);
    let agents = local.join("AGENTS.md");
    std::fs::remove_file(&agents).unwrap();
    // Replace AGENTS.md with a symlink (even to a real in-dir file).
    symlink(local.join("template.yaml"), &agents).unwrap();
    let resolver = PackTemplateResolver::new(reg);
    let err = resolver.resolve(FQ).unwrap_err();
    assert!(
        matches!(err, TemplateError::PathTraversal(_)),
        "got {err:?}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn t_ptr_12_ancestor_dir_swap_is_path_traversal() {
    // Swap the installed `agent-templates/` ANCESTOR dir for a symlink. The
    // install-root-anchored symlink_check must catch it (a local_path-anchored
    // check would not — symlink_metadata silently follows ancestors).
    let (_tmp, reg) = install_pack(PackOpts::default()).await;
    let local = installed_template_dir(&reg);
    let agent_templates = local.parent().unwrap().to_path_buf();
    let renamed = agent_templates
        .parent()
        .unwrap()
        .join("agent-templates-real");
    std::fs::rename(&agent_templates, &renamed).unwrap();
    symlink(&renamed, &agent_templates).unwrap();
    let resolver = PackTemplateResolver::new(reg);
    let err = resolver.resolve(FQ).unwrap_err();
    assert!(
        matches!(err, TemplateError::PathTraversal(_)),
        "got {err:?}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn t_ptr_13_skills_dir_swap_is_path_traversal() {
    // Swap the installed template's `skills/` subtree for a symlink — caught by
    // the dir-level checked_read_dir before the walk reads any file.
    let (_tmp, reg) = install_pack(PackOpts::default()).await;
    let local = installed_template_dir(&reg);
    let skills = local.join("skills");
    let renamed = local.join("skills-real");
    std::fs::rename(&skills, &renamed).unwrap();
    symlink(&renamed, &skills).unwrap();
    let resolver = PackTemplateResolver::new(reg);
    let err = resolver.resolve(FQ).unwrap_err();
    assert!(
        matches!(err, TemplateError::PathTraversal(_)),
        "got {err:?}"
    );
}

// ── e2e: resolved-via-PackRegistry → apply_template materialization ───────────

struct AlwaysOkGate;
impl SpawnerSubsetGate for AlwaysOkGate {
    fn check(&self, _p: &[Capability], _c: &[Capability]) -> Result<(), SpawnError> {
        Ok(())
    }
}

#[tokio::test]
async fn t_ptr_10_e2e_spawn_child_materializes_pack_template() {
    let (_tmp, reg) = install_pack(PackOpts::default()).await;
    let resolver: Arc<dyn TemplateResolver> = Arc::new(PackTemplateResolver::new(reg));

    // Separate workspace tree (independent of the pack install dir).
    let ws_tmp = TempDir::new().unwrap();
    let workspace_root = ws_tmp.path().canonicalize().unwrap();
    let tree = AgentTreeStore::new(workspace_root.clone()).unwrap();
    let root_ws = workspace_root.join("root_ws");
    std::fs::create_dir_all(&root_ws).unwrap();
    tree.insert_root(AgentNode {
        id: AgentId("root".to_string()),
        kind: AgentKind::Root,
        parent: None,
        workspace_path: root_ws,
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    })
    .unwrap();
    let spawner =
        DefaultSpawner::with_template_resolver(tree.clone(), Arc::new(AlwaysOkGate), resolver);

    spawner
        .spawn_child(SpawnChildConfig {
            parent_id: AgentId("root".to_string()),
            child_id: AgentId("scout".to_string()),
            child_workspace_path: PathBuf::from("agents/scout"),
            capabilities: Vec::new(),
            // The FQ ref flows verbatim into PackRegistry::resolve.
            template_ref: Some(FQ.to_string()),
            binary: None,
        })
        .unwrap();

    let node = tree.get_node(&AgentId("scout".to_string())).unwrap();
    let agent = node.workspace_path.join(".agent");
    assert_eq!(
        std::fs::read_to_string(agent.join("config.yaml")).unwrap(),
        EMBEDDED_TEMPLATE_YAML
    );
    assert!(std::fs::read_to_string(agent.join("AGENTS.md"))
        .unwrap()
        .contains(AGENTS_MD_MARKER));
    assert_eq!(
        std::fs::read(agent.join("behavior.wasm")).unwrap(),
        TINY_WASM
    );
    assert_eq!(
        std::fs::read_to_string(agent.join("skills").join("web-search").join("SKILL.md")).unwrap(),
        SKILL_CONTENT
    );
}

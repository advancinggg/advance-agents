//! Track I — SYS-J-29 "admin installs a pack" system-acceptance witnesses.
//!
//! Journey (docs/SYSTEM-ACCEPTANCE.md §1): MODULE-018 → MODULE-003 → MODULE-017.
//! "An admin installs a pack (source parse, checksum verify, approval, recursive
//! deps, copy, registry update) and its templates/skills become available."
//!
//! These drive the REAL admin-side `advance_pack_manager::Installer` end-to-end
//! (the production library entry — the admin surface; an `advance pack install`
//! CLI shell does not yet exist and is out of this track's scope). The §2
//! "Verified By Task" column records this run's /dev task_id (per the §2 legend);
//! the library-Installer substitution for SYS-AC-090 is documented here, in the
//! commit message, and in the run SUMMARY — not as free-form text in the ledger
//! cell. No module in the chain is mocked: the real `Installer`,
//! `InMemoryPackRegistry`, `verify_checksums`, `copy_dir_no_symlinks`, layout +
//! provides validation, and `.meta.yaml` atomic write all run. `AutoApprove` /
//! `AutoReject` are production `ApprovalStrategy` impls; `RecordingTraceSink` and
//! the recording `EventBusEmit` bus are OBSERVATION sinks (not chain mocks).
//!
//! Witnesses (GREEN): SYS-AC-090, SYS-AC-091, SYS-AC-092, SYS-AC-222, SYS-AC-223.
//! Queued (#[ignore], HF): SYS-AC-093 — needs spawn-agent-from-template (the
//! multi-agent `.agents()` spawn path owned by Track HF / harness `lib.rs`).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use advance_pack_manager::{
    ApprovalStrategy, AutoApprove, AutoReject, DependencyResolver, InMemoryPackRegistry,
    InstallStep, Installer, PackError, PackRegistry, RecordingTraceSink, SourceRef,
};
use advance_shared_types::agent_tree::AgentId;
use advance_shared_types::event::Event;
use advance_shared_types::traits::EventBusEmit;
use async_trait::async_trait;

// ───────────────────────── observation sinks (not chain mocks) ─────────────

/// Captures emitted events for assertion. The REAL `Installer` performs the
/// emit; this only records what crossed the wire (the same pattern the harness
/// `CapturingBus` uses).
#[derive(Default)]
struct RecordingBus {
    events: Mutex<Vec<Event>>,
}

impl EventBusEmit for RecordingBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

/// Maps dependency name → on-disk `SourceRef::Local` for the recursive-deps
/// (cycle) witness. Same shape as `pack-manager/tests/recursive_deps.rs`.
struct MapResolver {
    map: Mutex<Vec<(String, SourceRef)>>,
}

#[async_trait]
impl DependencyResolver for MapResolver {
    async fn resolve(&self, name: &str, _req: &semver::VersionReq) -> Result<SourceRef, PackError> {
        for (n, s) in self.map.lock().unwrap().iter() {
            if n == name {
                return Ok(s.clone());
            }
        }
        Err(PackError::DependencyNotFound {
            name: name.into(),
            version_req: "<test>".into(),
        })
    }
}

// ───────────────────────── fixtures (this track's own) ─────────────────────

/// Write a valid Local pack source tree at `root/source-{name}-{version}`:
/// `pack.yaml` + `behavior-binaries/researcher.wasm`. `deps_yaml` is the
/// top-level `dependencies:` block; `files_yaml` is the content after
/// `checksums.files:` (` {}` for none, or a nested map to force a mismatch).
/// Returns the source dir to hand to `Installer::install`.
fn write_pack(
    root: &Path,
    name: &str,
    version: &str,
    deps_yaml: &str,
    files_yaml: &str,
) -> PathBuf {
    let pack_dir = root.join(format!("source-{name}-{version}"));
    std::fs::create_dir_all(pack_dir.join("behavior-binaries")).unwrap();
    // Empty researcher.wasm → sha256("") = e3b0c442…, which never equals the
    // all-zero hash the checksum-mismatch fixture declares.
    std::fs::write(
        pack_dir.join("behavior-binaries").join("researcher.wasm"),
        b"",
    )
    .unwrap();
    std::fs::write(
        pack_dir.join("pack.yaml"),
        format!(
            "name: {name}\n\
             version: {version}\n\
             runtime-version: \">=0.0.1\"\n\
             {deps_yaml}\n\
             provides:\n  behavior-binaries: [researcher]\n\
             required-capabilities: []\n\
             trust-level: untrusted\n\
             checksums:\n  algo: sha256\n  files:{files_yaml}\n"
        ),
    )
    .unwrap();
    pack_dir
}

fn valid_pack(root: &Path, name: &str, version: &str) -> PathBuf {
    write_pack(root, name, version, "dependencies: []", " {}")
}

fn installer(
    packs_dir: PathBuf,
    registry: Arc<InMemoryPackRegistry>,
    approval: Arc<dyn ApprovalStrategy>,
    trace_sink: Arc<RecordingTraceSink>,
    dep_resolver: Option<Arc<dyn DependencyResolver>>,
    event_bus: Option<Arc<dyn EventBusEmit>>,
) -> Installer {
    Installer {
        packs_dir,
        registry,
        current_runtime_version: "0.5.0".into(),
        approval,
        trace_sink,
        dep_resolver,
        event_bus,
        registry_client: None,
        fetch_timeout: None,
    }
}

const EIGHT_STEPS: [InstallStep; 8] = [
    InstallStep::Step1ParseSource,
    InstallStep::Step2DownloadToTemp,
    InstallStep::Step3VerifyChecksums,
    InstallStep::Step4AdminApproval,
    InstallStep::Step5RecursiveDeps,
    InstallStep::Step6CopyToInstallDir,
    InstallStep::Step7UpdateMetaIndex,
    InstallStep::Step8RegistryRescan,
];

// ───────────────────────── SYS-AC-090 ──────────────────────────────────────
// "advance pack install <source> on a valid pack completes the 8-step flow and
//  returns a PackInstallReport; each step emits a trace event."

#[tokio::test]
async fn sys_ac_090_valid_pack_completes_8_step_flow_with_report_and_traces() {
    let dir = tempfile::TempDir::new().unwrap();
    let src = valid_pack(dir.path(), "alpha", "1.0.0");
    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let sink = Arc::new(RecordingTraceSink::new());

    let inst = installer(
        packs_dir.clone(),
        registry.clone(),
        Arc::new(AutoApprove),
        sink.clone(),
        None,
        None,
    );
    let report = inst
        .install(src.to_string_lossy().as_ref())
        .await
        .expect("valid pack installs");

    // PackInstallReport identity.
    assert_eq!(report.name, "alpha");
    assert_eq!(report.version, "1.0.0");
    assert_eq!(
        report.install_path,
        packs_dir.join("alpha@1.0.0"),
        "install_path is /.advance/packs/{{name}}@{{version}}"
    );
    // The 8 steps ran in PRD §19.5 order …
    assert_eq!(report.trace_steps, EIGHT_STEPS, "8-step flow in order");
    // … and each step emitted a trace event (the audit hook saw all 8).
    assert_eq!(sink.steps(), EIGHT_STEPS, "each step emits a trace event");
    // Content actually landed on disk.
    assert!(
        report.install_path.join("pack.yaml").is_file(),
        "pack content copied to the install dir"
    );
}

// ───────────────────────── SYS-AC-091 ──────────────────────────────────────
// "A pack whose computed SHA-256 checksums do not match the manifest is rejected
//  before admin-approval (install aborts, no copy to /.advance/packs/)."

#[tokio::test]
async fn sys_ac_091_checksum_mismatch_rejected_before_approval_no_copy() {
    let dir = tempfile::TempDir::new().unwrap();
    // Declare a checksum for researcher.wasm that does NOT match its real
    // (empty-file) SHA-256 → ChecksumMismatch at step ③.
    let src = write_pack(
        dir.path(),
        "ckfail",
        "1.0.0",
        "dependencies: []",
        &format!(
            "\n    behavior-binaries/researcher.wasm: \"{}\"",
            "0".repeat(64)
        ),
    );
    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let sink = Arc::new(RecordingTraceSink::new());

    // AutoApprove proves the rejection is the checksum gate, NOT approval.
    let inst = installer(
        packs_dir.clone(),
        registry.clone(),
        Arc::new(AutoApprove),
        sink.clone(),
        None,
        None,
    );
    match inst.install(src.to_string_lossy().as_ref()).await {
        Err(PackError::ChecksumMismatch(rel, _expected, _actual)) => {
            assert_eq!(rel, "behavior-binaries/researcher.wasm");
        }
        other => panic!("expected ChecksumMismatch, got {other:?}"),
    }
    // Rejected BEFORE admin-approval: ③ ran, ④ never did.
    let steps = sink.steps();
    assert!(steps.contains(&InstallStep::Step3VerifyChecksums));
    assert!(
        !steps.contains(&InstallStep::Step4AdminApproval),
        "checksum mismatch must abort before the approval step"
    );
    // No copy to /.advance/packs/.
    assert!(
        !packs_dir.join("ckfail@1.0.0").exists(),
        "no content copied on checksum failure"
    );
    assert!(registry.list_installed().is_empty());
}

// ───────────────────────── SYS-AC-092 ──────────────────────────────────────
// "After install, exactly one pack.registry_reloaded event fires and the pack
//  appears via list_installed without a runtime restart."

#[tokio::test]
async fn sys_ac_092_exactly_one_registry_reloaded_event_and_list_installed() {
    let dir = tempfile::TempDir::new().unwrap();
    let src = valid_pack(dir.path(), "beta", "2.3.0");
    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let bus = Arc::new(RecordingBus::default());

    let inst = installer(
        packs_dir,
        registry.clone(),
        Arc::new(AutoApprove),
        Arc::new(RecordingTraceSink::new()),
        None,
        Some(bus.clone() as Arc<dyn EventBusEmit>),
    );
    inst.install(src.to_string_lossy().as_ref())
        .await
        .expect("install beta");

    // Exactly one pack.registry_reloaded event, naming the installed pack.
    let events = bus.events.lock().unwrap();
    assert_eq!(events.len(), 1, "exactly one pack.registry_reloaded event");
    assert_eq!(events[0].event_type, "pack.registry_reloaded");
    assert_eq!(events[0].payload["installed_pack"], "beta@2.3.0");

    // Available via list_installed with no runtime restart (same registry).
    assert!(
        registry.has("beta", "2.3.0"),
        "the just-installed pack is queryable without a restart"
    );
    assert!(registry
        .list_installed()
        .iter()
        .any(|m| m.name == "beta" && m.version == "2.3.0"));
}

// ───────────────────────── SYS-AC-222 ──────────────────────────────────────
// "A pack whose admin approval is declined at the approval step (step 4) aborts
//  with PackError::AdminRejected and no content is copied to /.advance/packs/."

#[tokio::test]
async fn sys_ac_222_admin_declined_aborts_with_admin_rejected_no_copy() {
    let dir = tempfile::TempDir::new().unwrap();
    let src = valid_pack(dir.path(), "rej", "1.0.0");
    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let sink = Arc::new(RecordingTraceSink::new());

    let inst = installer(
        packs_dir.clone(),
        registry.clone(),
        Arc::new(AutoReject),
        sink.clone(),
        None,
        None,
    );
    match inst.install(src.to_string_lossy().as_ref()).await {
        Err(PackError::AdminRejected) => {}
        other => panic!("expected AdminRejected, got {other:?}"),
    }
    // The approval step was reached, but copy was not.
    let steps = sink.steps();
    assert!(steps.contains(&InstallStep::Step4AdminApproval));
    assert!(
        !steps.contains(&InstallStep::Step6CopyToInstallDir),
        "rejection must abort before the copy step"
    );
    assert!(
        !packs_dir.join("rej@1.0.0").exists(),
        "no content copied on admin rejection"
    );
    assert!(registry.list_installed().is_empty());
}

// ───────────────────────── SYS-AC-223 ──────────────────────────────────────
// "A pack whose recursive dependency graph contains a cycle (or exceeds depth
//  cap 32) aborts at the dependency-install step with DependencyCycle /
//  DependencyDepthExceeded before any copy."
//
// Cycle A→B→A. Both edges use IDENTICAL version-req strings ("^1.0.0") and
// neither pack is pre-installed. install_deps_recursive keys the in_flight DFS
// stack on (dep.name, dep.version-req STRING) exact equality (deps.rs:80); the
// root pack A is NOT pushed (only deps are), so the cycle fires one level
// deeper — when A's install recurses and re-encounters dep `cyc-b` already on
// the stack — yielding path ["cyc-b","cyc-a","cyc-b"]. Identical req strings on
// both edges are what make the back-edge match (rather than dedup-skipping or
// recursing to the depth cap). The assertion below checks the variant + that
// both packs are named in the path, so it is robust to the exact path order.

#[tokio::test]
async fn sys_ac_223_dependency_cycle_aborts_before_any_copy() {
    let dir = tempfile::TempDir::new().unwrap();
    let a_src = write_pack(
        dir.path(),
        "cyc-a",
        "1.0.0",
        "dependencies:\n  - {name: cyc-b, version: \"^1.0.0\"}",
        " {}",
    );
    let b_src = write_pack(
        dir.path(),
        "cyc-b",
        "1.0.0",
        "dependencies:\n  - {name: cyc-a, version: \"^1.0.0\"}",
        " {}",
    );

    let resolver = Arc::new(MapResolver {
        map: Mutex::new(vec![
            ("cyc-a".into(), SourceRef::Local(a_src.clone())),
            ("cyc-b".into(), SourceRef::Local(b_src)),
        ]),
    });
    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));

    let inst = installer(
        packs_dir.clone(),
        registry.clone(),
        Arc::new(AutoApprove),
        Arc::new(RecordingTraceSink::new()),
        Some(resolver as Arc<dyn DependencyResolver>),
        None,
    );
    match inst.install(a_src.to_string_lossy().as_ref()).await {
        Err(PackError::DependencyCycle { path }) => {
            assert!(
                path.contains(&"cyc-a".to_string()) && path.contains(&"cyc-b".to_string()),
                "cycle path names both packs: {path:?}"
            );
        }
        // depth-cap fallback is also an acceptable abort per the OR-criterion.
        Err(PackError::DependencyDepthExceeded { .. }) => {}
        other => panic!("expected DependencyCycle/DependencyDepthExceeded, got {other:?}"),
    }
    // Aborted before any copy: neither pack reached step ⑥/⑦/⑧.
    assert!(!packs_dir.join("cyc-a@1.0.0").exists());
    assert!(!packs_dir.join("cyc-b@1.0.0").exists());
    assert!(
        registry.list_installed().is_empty(),
        "no pack installed when the dependency graph cycles"
    );
}

// ───────────────────────── SYS-AC-093 ──────────────────────────────────────
// "A template from the installed pack is materializable: spawn-agent-from-template
//  copies its content into a target workspace, resolved via PackRegistry."
//
// FLIPPED 2026-06-15 (sat/pack-template-bridge landed `cap_lifecycle::PackTemplateResolver`,
// the PackRegistry→TemplateResolver bridge the prior deferral said did not exist). This
// witnesses the FULL criterion end-to-end through the production stack:
//
//   1. A REAL pack providing an `agent-templates/researcher` is genuinely INSTALLED via
//      the admin-side `advance_pack_manager::Installer` (the same 8-step flow the 090-223
//      witnesses above drive): source tree → checksum verify → approval → copy to
//      `packs_dir/{name}@{version}/` → `.meta.yaml` write → registry rescan/index. No
//      hand-built `.meta.yaml`; the pack is queryable via `registry.has(...)`.
//   2. Resolution flows through `PackRegistry`: a real
//      `cap_lifecycle::PackTemplateResolver::new(Arc<dyn PackRegistry>)` is injected into
//      `DefaultSpawner::with_template_resolver` (NOT pack-manager's dir-copy
//      `materialize_template`, which bypasses `apply_template`). The FQ-ref
//      `{pack}@{version}/agent-templates/{name}` flows verbatim into `PackRegistry::resolve`.
//   3. The spawn is driven through the REAL WIT `spawn-agent-from-template` host-fn (param
//      order kind=0, template-ref=1, target-path=2 — wit_impl.rs:463), dispatched through a
//      real `register_agent_lifecycle` registry (the shared `lifecycle_support` driver), NOT
//      `spawner.spawn_child(...)` directly (already covered at the cap-lifecycle crate level
//      in tests/pack_template_resolver.rs::t_ptr_10). The WIT child arm derives the child-id
//      from the target-path leaf → `spawn_child(template_ref)` → `apply_template`.
//
// Every load-bearing assertion binds to on-disk PRODUCT bytes the spawner+apply_template
// wrote into the NEW agent's `.agent/` workspace at `tree.get_node(child).workspace_path`:
// behavior.wasm == the pack's; AGENTS.md == the pack's; a skill file == the pack's; and
// config.yaml == the pack's verbatim template.yaml. NO harness-injected value stands in for
// the materialized content. A non-vacuity CONTROL drives spawn-agent-from-template with a
// `template_ref` that does NOT resolve in the registry → surfaces `invalid-config` (the
// resolver-driven NotFound→InvalidConfig→invalid-config lowering), proving resolution
// actually ran rather than the materialization being short-circuited.

#[path = "lifecycle_support/mod.rs"]
mod lifecycle_support;

const TINY_WASM: &[u8] = b"\0asm\x01\0\0\0";
const TEMPLATE_YAML: &str = "name: researcher\nversion: 1.0.0\ndescription: Research template\nbehavior:\n  type: embedded\n  binary: behavior.wasm\ndefault-model: sonnet\n";
const AGENTS_MD_MARKER: &str = "RESEARCHER-TEMPLATE-MARKER";
const SKILL_REL: &str = "web-search/SKILL.md";
const SKILL_CONTENT: &str = "# Web search skill — materialized from the installed pack\n";

/// Write a pack SOURCE tree that PROVIDES an `agent-templates/researcher`:
/// `template.yaml` (embedded behavior) + `AGENTS.md` + `behavior.wasm` (tiny
/// bytes) + a nested `skills/web-search/SKILL.md`. Only `agent-templates` is
/// declared in `provides` (NOT a top-level `skills`), so `verify_skill_tool_exports`
/// is not triggered on the template's own knowledge-only skill file. Mirrors the
/// cap-lifecycle `tests/pack_template_resolver.rs` MINIMAL-provides fixture so the
/// REAL `Installer` accepts it (layout + provides-on-disk validation pass). Empty
/// `checksums.files: {}` is valid (pack.yaml is not required to self-checksum).
fn write_template_pack(root: &Path, name: &str, version: &str, tmpl: &str) -> PathBuf {
    let src = root.join(format!("source-{name}-{version}"));
    let tdir = src.join("agent-templates").join(tmpl);
    std::fs::create_dir_all(&tdir).unwrap();
    std::fs::write(tdir.join("template.yaml"), TEMPLATE_YAML).unwrap();
    std::fs::write(
        tdir.join("AGENTS.md"),
        format!("# Researcher\n\n{AGENTS_MD_MARKER}\n"),
    )
    .unwrap();
    std::fs::write(tdir.join("behavior.wasm"), TINY_WASM).unwrap();
    let skill = tdir.join("skills").join(SKILL_REL);
    std::fs::create_dir_all(skill.parent().unwrap()).unwrap();
    std::fs::write(&skill, SKILL_CONTENT.as_bytes()).unwrap();
    std::fs::write(
        src.join("pack.yaml"),
        format!(
            "name: {name}\n\
             version: {version}\n\
             runtime-version: \">=0.0.1\"\n\
             dependencies: []\n\
             provides:\n  agent-templates: [{tmpl}]\n\
             required-capabilities: []\n\
             trust-level: untrusted\n\
             checksums:\n  algo: sha256\n  files: {{}}\n"
        ),
    )
    .unwrap();
    src
}

#[tokio::test]
async fn sys_ac_093_template_materializable_via_spawn_from_template() {
    use cap_lifecycle::{PackTemplateResolver, TemplateResolver};
    use lifecycle_support::{err_variant_name, LifecycleFixture};
    use wasmtime::component::Val;

    // ── 1. Genuinely INSTALL a pack providing an agent-template (real Installer). ──
    let dir = tempfile::TempDir::new().unwrap();
    let src = write_template_pack(dir.path(), "researcher-pack", "1.0.0", "researcher");
    let packs_dir = dir.path().join("packs");
    let registry = Arc::new(InMemoryPackRegistry::new(packs_dir.clone()));
    let inst = installer(
        packs_dir.clone(),
        registry.clone(),
        Arc::new(AutoApprove),
        Arc::new(RecordingTraceSink::new()),
        None,
        None,
    );
    inst.install(src.to_string_lossy().as_ref())
        .await
        .expect("install template-providing pack");
    // The pack is indexed and queryable without a runtime restart.
    assert!(
        registry.has("researcher-pack", "1.0.0"),
        "the just-installed template pack is in the registry"
    );

    // The FQ-ref the spawn will pass verbatim into PackRegistry::resolve.
    const FQ: &str = "researcher-pack@1.0.0/agent-templates/researcher";

    // ── 2. PackRegistry → PackTemplateResolver → resolver-backed spawner. ──
    let resolver: Arc<dyn TemplateResolver> = Arc::new(PackTemplateResolver::new(
        registry.clone() as Arc<dyn PackRegistry>
    ));
    // The fixture wires `DefaultSpawner::with_template_resolver(tree, OkGate, resolver)`
    // into the bundle and runs a REAL `register_agent_lifecycle`. Bare ids only
    // (cap-lifecycle `validate_agent_id` rejects colons).
    let fx = LifecycleFixture::new_with_root_and_resolver("root-a", Some(resolver));

    // ── 3. Drive the REAL WIT `spawn-agent-from-template` host-fn. ──
    // Params: kind=child (variant), template-ref=FQ, target-path="agents/child093".
    // The WIT child arm derives child-id from the target-path leaf ("child093").
    let res = fx
        .call(
            "root-a",
            "spawn-agent-from-template",
            vec![
                Val::Variant("child".to_string(), None),
                Val::String(FQ.to_string()),
                Val::Option(Some(Box::new(Val::String("agents/child093".to_string())))),
                Val::Option(None),
            ],
        )
        .await
        .expect("spawn-agent-from-template dispatch");
    // Ok(agent-id) == the target-path leaf "child093".
    let child_id = match &res[0] {
        Val::Result(Ok(Some(b))) => match b.as_ref() {
            Val::String(s) => s.clone(),
            other => panic!("expected agent-id string, got {other:?}"),
        },
        other => panic!("expected Ok(agent-id) from spawn-from-template, got {other:?}"),
    };
    assert_eq!(
        child_id, "child093",
        "child-id derived from target-path leaf"
    );

    // ── 4. Assert the materialized files on disk in the NEW agent's workspace. ──
    // The product spawner registered the child + set its workspace_path; the
    // resolver-driven apply_template wrote `.agent/` from the pack's bytes.
    let node = fx
        .tree
        .get_node(&AgentId("child093".into()))
        .expect("child node registered in the tree by the product spawner");
    let agent = node.workspace_path.join(".agent");

    // behavior.wasm bytes == the pack's (apply_template wrote these from the
    // PackTemplateResolver's embedded-behavior read).
    assert_eq!(
        std::fs::read(agent.join("behavior.wasm")).expect("behavior.wasm materialized"),
        TINY_WASM,
        "materialized behavior.wasm == the installed pack's bytes"
    );
    // AGENTS.md == the pack's (carries the pack template's marker).
    assert!(
        std::fs::read_to_string(agent.join("AGENTS.md"))
            .expect("AGENTS.md materialized")
            .contains(AGENTS_MD_MARKER),
        "materialized AGENTS.md == the installed pack's template AGENTS.md"
    );
    // A skill file == the pack's (the template's nested skills/web-search/SKILL.md).
    assert_eq!(
        std::fs::read_to_string(agent.join("skills").join("web-search").join("SKILL.md"))
            .expect("skill materialized"),
        SKILL_CONTENT,
        "materialized skill content == the installed pack's template skill"
    );
    // config.yaml == the pack's verbatim template.yaml (apply_template's manifest dest).
    assert_eq!(
        std::fs::read_to_string(agent.join("config.yaml")).expect("config.yaml materialized"),
        TEMPLATE_YAML,
        "materialized config.yaml == the installed pack's verbatim template.yaml"
    );

    // ── 5. Non-vacuity CONTROL — a template_ref that does NOT resolve in the ──
    // ── registry surfaces `invalid-config` (resolver-driven), proving the    ──
    // ── resolver actually ran (not short-circuited materialization).         ──
    let ctrl = fx
        .call(
            "root-a",
            "spawn-agent-from-template",
            vec![
                Val::Variant("child".to_string(), None),
                // Same grammar, but no such pack@version is installed → resolve
                // fails → PackTemplateResolver yields NotFound → InvalidConfig →
                // lowered to the `invalid-config` host variant.
                Val::String("ghost-pack@9.9.9/agent-templates/missing".to_string()),
                Val::Option(Some(Box::new(Val::String("agents/ctrl093".to_string())))),
                Val::Option(None),
            ],
        )
        .await
        .expect("control spawn-agent-from-template dispatch");
    assert_eq!(
        err_variant_name(&ctrl[0]),
        "invalid-config",
        "an unresolvable template_ref surfaces invalid-config (resolver-driven)"
    );
    // And nothing was registered/materialized for the failed control spawn.
    assert!(
        fx.tree.get_node(&AgentId("ctrl093".into())).is_none(),
        "no child node registered after the unresolvable-ref control spawn"
    );
}

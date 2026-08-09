//! MODULE-017 T22 (AC-20 full flow) + T28 (AC-26 two-part structure) + the L0/L1
//! leg of T29 (AC-27) — Slice V1-c (2026-05-30).
//!
//! End-to-end "progressive skill use" against REAL artifacts, crossing
//! cap-skills (knowledge + materialize + summary extractor) and cap-tools (L2
//! tool-invoke):
//!
//!   - materialize 2 skill bundles into an agent-local `.agent/skills/` tree —
//!     `echoer` carries the committed `echo_tool.component.wasm` as its
//!     `tool.wasm` (+ a `tool.capabilities.json`); `noter` is knowledge-only;
//!   - **L0** — read each materialized `SKILL.md`, extract the first-paragraph
//!     summary (cap-skills `extract_skill_summary`, ≤ 100 tokens), and render
//!     the Tier-2 ⑩ `# Available Skills` section via the M010
//!     `format_available_skills_section` (the production L0 content pipeline;
//!     the live `assemble()` injection + budget cap is witnessed by
//!     MODULE-010-T19 `context-engine/tests/skill_l0_inject.rs`);
//!   - **L1** — `fs.read` the chosen skill's FULL `SKILL.md` (the instructions
//!     beyond the L0 summary), from the plain `.agent/skills/` directory (AC-25);
//!   - **L2** — load the materialized `tool.wasm` into an engine-bearing
//!     `LazyToolRegistry` (CONTRACT-163 isolated sandbox) and invoke
//!     `execute("echo", params) == params`.

use advance_context_engine::{
    format_available_skills_section, SkillSummaryEntry, SKILL_BUDGET_TOKENS_DEFAULT,
};
use advance_runtime::component_loader::{ComponentRuntime, ToolEngineHandle};
use advance_runtime::config::WasmConfig;

use cap_skills::persistence::DiskSkillStorage;
use cap_skills::{
    extract_skill_summary, materialize_skill, AdminPoolStorage, Provenance, SkillBundle, TrustLevel,
};
use cap_tools::{LazyRegistryConfig, LazyToolRegistry, ToolError, ToolRegistry};

use tempfile::TempDir;

/// The committed real tool component (exports `advance:runtime/tool-exports`).
const ECHO_TOOL_WASM: &[u8] = include_bytes!("fixtures/echo_tool.component.wasm");

const ECHOER_SKILL_MD: &str = "\
---
name: echoer
description: echoes input
---

# Echoer Skill

Echoes any input bytes back unchanged via its bundled WASM tool.

## Usage
Invoke the echo method with arbitrary bytes; it returns them verbatim. This \
detailed usage section is L1/L2 content that the L0 summary deliberately omits.
";

const NOTER_SKILL_MD: &str = "\
---
name: noter
description: takes notes
---

# Noter Skill

Records notes using cap-fs; knowledge-only with no executable tool.
";

const ECHOER_SUMMARY: &str = "Echoes any input bytes back unchanged via its bundled WASM tool.";
const NOTER_SUMMARY: &str = "Records notes using cap-fs; knowledge-only with no executable tool.";

fn tool_engine() -> ToolEngineHandle {
    let cfg = WasmConfig {
        max_memory_pages: 256,
        epoch_interruption_ms: 100,
        fuel_enabled: false,
    };
    ComponentRuntime::new(&cfg)
        .expect("construct ComponentRuntime")
        .tool_engine_handle()
}

fn small_config() -> LazyRegistryConfig {
    LazyRegistryConfig {
        max_result_bytes: 1024,
        ..Default::default()
    }
}

/// Build the admin pool with the two bundles + materialize both into an
/// agent-local tree. Returns the two `TempDir`s (kept alive by the caller) +
/// the agent root path.
async fn setup() -> (TempDir, TempDir, std::path::PathBuf) {
    let admin_dir = TempDir::new().expect("admin tempdir");
    let agent_dir = TempDir::new().expect("agent tempdir");

    let admin = AdminPoolStorage::with_default_writer(admin_dir.path().to_path_buf());

    // `echoer` — knowledge SKILL.md + optional executable tool.wasm (+ caps).
    let echoer = SkillBundle::new(
        "echoer".into(),
        ECHOER_SKILL_MD.into(),
        Some(ECHO_TOOL_WASM.to_vec()),
        Some(r#"{"capabilities":[]}"#.into()),
        Vec::new(),
        Vec::new(),
        Provenance::Imported,
        TrustLevel::Trusted,
    )
    .expect("echoer bundle");
    admin.write_bundle(&echoer).await.expect("write echoer");

    // `noter` — knowledge-only (Path A shape: no tool.wasm).
    let noter = SkillBundle::new(
        "noter".into(),
        NOTER_SKILL_MD.into(),
        None,
        None,
        Vec::new(),
        Vec::new(),
        Provenance::Imported,
        TrustLevel::Trusted,
    )
    .expect("noter bundle");
    admin.write_bundle(&noter).await.expect("write noter");

    let agent_root = agent_dir.path().to_path_buf();
    let disk = DiskSkillStorage::with_default_writer(agent_root.clone());
    materialize_skill("echoer", &admin, &disk)
        .await
        .expect("materialize echoer");
    materialize_skill("noter", &admin, &disk)
        .await
        .expect("materialize noter");

    (admin_dir, agent_dir, agent_root)
}

fn skill_md_path(agent_root: &std::path::Path, name: &str) -> std::path::PathBuf {
    agent_root.join(".agent/skills").join(name).join("SKILL.md")
}

fn tool_wasm_path(agent_root: &std::path::Path, name: &str) -> std::path::PathBuf {
    agent_root
        .join(".agent/skills")
        .join(name)
        .join("tool.wasm")
}

/// T22 (AC-20) + T29 L0 leg: full L0 → L1 → L2 against the materialized skills.
#[tokio::test]
async fn progressive_skill_l0_l1_l2_end_to_end() {
    let (_admin_dir, _agent_dir, agent_root) = setup().await;

    // ── L0: build summaries from the materialized SKILL.md files (the
    // production reader's job) and render the Tier-2 ⑩ section.
    let mut entries: Vec<SkillSummaryEntry> = Vec::new();
    for (name, score) in [("echoer", 0.9_f32), ("noter", 0.5)] {
        let md = std::fs::read_to_string(skill_md_path(&agent_root, name)).expect("read SKILL.md");
        let summary = extract_skill_summary(&md);
        assert!(
            !summary.is_empty() && summary.len() <= 400,
            "{name} summary ≤100 tok (≤400 bytes): {summary:?}"
        );
        entries.push(SkillSummaryEntry {
            name: name.into(),
            summary,
            score,
        });
    }
    let section = format_available_skills_section(&entries, SKILL_BUDGET_TOKENS_DEFAULT)
        .expect("L0 `# Available Skills` section");
    assert!(section.starts_with("# Available Skills\n\n"));
    assert!(
        section.contains(&format!("- echoer: {ECHOER_SUMMARY}")),
        "L0 lists echoer summary: {section}"
    );
    assert!(
        section.contains(&format!("- noter: {NOTER_SUMMARY}")),
        "L0 lists noter summary: {section}"
    );

    // ── L1: read the chosen skill's FULL SKILL.md (instructions beyond L0).
    let full = std::fs::read_to_string(skill_md_path(&agent_root, "echoer")).expect("L1 read");
    assert!(
        full.contains("## Usage"),
        "L1 surfaces the full instructions"
    );
    assert!(
        full.contains("returns them verbatim"),
        "L1 body goes beyond the L0 summary"
    );
    // The L0 summary is a strict subset of the L1 content (progressive drill-down).
    assert!(full.contains(ECHOER_SUMMARY));

    // ── L2: load the materialized tool.wasm + invoke it in the sandbox.
    let wasm = std::fs::read(tool_wasm_path(&agent_root, "echoer")).expect("read tool.wasm");
    let reg = LazyToolRegistry::new_with_engine(small_config(), tool_engine());
    reg.register_binary("skill::echoer", wasm).await;
    let out = reg
        .invoke("skill::echoer", "echo", b"l2-payload")
        .await
        .expect("L2 tool invoke");
    assert_eq!(out, b"l2-payload", "execute(\"echo\", p) == p");
}

/// T28 (AC-26): the two-part structure — knowledge `SKILL.md` + optional
/// executable `tool.wasm` (with its own `tool.capabilities.json`) — and the
/// tool runs in an isolated sandbox loaded via the ToolRegistry (CONTRACT-163).
#[tokio::test]
async fn skill_two_part_structure_runs_in_sandbox() {
    let (_admin_dir, _agent_dir, agent_root) = setup().await;

    // Part 1: knowledge file present + readable as a plain file (AC-25).
    assert!(
        skill_md_path(&agent_root, "echoer").is_file(),
        "knowledge SKILL.md materialized"
    );
    // Part 2: optional executable + its capabilities sidecar present.
    let wasm_path = tool_wasm_path(&agent_root, "echoer");
    assert!(wasm_path.is_file(), "executable tool.wasm materialized");
    assert!(
        agent_root
            .join(".agent/skills/echoer/tool.capabilities.json")
            .is_file(),
        "tool's own capabilities sidecar materialized"
    );
    // `noter` is knowledge-only — no tool.wasm.
    assert!(
        !tool_wasm_path(&agent_root, "noter").exists(),
        "knowledge-only skill has no tool.wasm"
    );

    // The tool.wasm loads into an isolated Wasmtime sandbox via ToolRegistry
    // and executes; an unknown method maps to method-not-found.
    let wasm = std::fs::read(&wasm_path).expect("read tool.wasm");
    let reg = LazyToolRegistry::new_with_engine(small_config(), tool_engine());
    reg.register_binary("skill::echoer", wasm).await;
    assert_eq!(
        reg.invoke("skill::echoer", "echo", b"sandboxed")
            .await
            .expect("sandbox execute"),
        b"sandboxed"
    );
    match reg.invoke("skill::echoer", "missing", b"x").await {
        Err(ToolError::MethodNotFound(m)) => assert_eq!(m, "missing"),
        other => panic!("expected MethodNotFound, got {other:?}"),
    }
}

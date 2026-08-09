//! Track I — SYS-J-26 "progressive skill loading" (L0 → L1 → L2).
//!
//! Journey (docs/SYSTEM-ACCEPTANCE.md §1): MODULE-010 → MODULE-017 → MODULE-002.
//! "A skill surfaces via L0 injection, the agent reads SKILL.md (L1), then loads
//! templates/tool.wasm (L2) on demand within the turn."
//!
//! Wave-6 Lane A — the `.with_skills_summary()` axis (system-acceptance/src/lib.rs)
//! installs the REAL production `DiskSkillSummaryReader` (cli
//! `build_context_assembler_for_agent_with_skills`, the SAME fn `start.rs:~680`
//! installs on the production assemble() path) on the per-turn ContextAssembler,
//! rooted at the cap-skills provider root (`agent_workspace`, canonicalized). A
//! generate-calling guest (`guest-rust-hello-llm`) emits the assembled prompt as
//! its `/v1/chat/completions` body via the `PublishingContextAssembler`, captured
//! by `llm_all_chat_request_bodies()` (the SYS-AC-010/192 mechanism). This retires
//! the old harness-assembler block (`MinimalContextAssembler` / "no body") AND the
//! old "StubSkillSummary unbuilt" deferral — the reader is now real and on the SUT
//! turn (098/101/109 precedent: a real production seam with no prior SYS-AC caller).
//!
//! Witness-floor: every assertion binds to PRODUCT output — the captured assembled-
//! prompt bytes (real `DiskSkillSummaryReader` → `format_available_skills_section`)
//! and the on-disk `SKILL.md` read via the REAL `fs.read` host-fn — never a harness-
//! injected section.
//!
//! SYS-AC-080 (L2 tool.wasm invoke) is witnessed by Wave-14 Lane C: the production
//! skill→tool-registry bridge (`advance_cli::wiring::register_skill_tools`) registers
//! a materialized skill's `tool.wasm` sidecar under `skill::{name}`, and the
//! `guest-rust-tool-invoke` fixture CALLS `tool-invoke("skill::echo-skill",…)` through
//! the real registry within the turn. The old "UNVERSIONED agent-tools" defer reason
//! was stale (cap-tools registers the VERSIONED `advance:runtime/agent-tools@0.1.0`);
//! the true blocker — no production path loaded a skill `tool.wasm` into the registry —
//! is closed by the bridge (080-a positive + 080-b/080-c discriminators below).

use cap_skills::persistence::{DiskSkillStorage, SkillBlob, SkillStorage};
use cap_skills::{Provenance, SkillSidecar, TrustLevel};
use cap_tools::ToolRegistry; // brings the async `invoke()` trait method into scope (the 080 oracle)
use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::{Cap, LlmMode, SystemUnderTest, AGENT_DIR};
use wasmtime::component::Val;

const HELLO_LLM_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-hello-llm.core.wasm");

/// Wave-14 (SYS-AC-080): the guest that CALLS `tool-invoke("skill::echo-skill","echo",PAYLOAD)`
/// then `fs.write`s the executed bytes (imports agent-tools + agent-fs).
const TOOL_INVOKE_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-tool-invoke.core.wasm");
/// The skill-bundled tool: the committed echo tool COMPONENT (exports `tool-exports`:
/// `describe` + `execute("echo",p)==p`). Used as the `SkillSidecar::ToolWasm` bytes.
const ECHO_TOOL_COMPONENT: &[u8] =
    include_bytes!("../../capabilities/cap-tools/tests/fixtures/echo_tool.component.wasm");
/// MUST match the guest fixture's `PAYLOAD` byte-for-byte (echo returns it verbatim).
const L2_PAYLOAD: &[u8] = &[
    0x5E, 0xC0, 0x80, 0x17, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0xAC, 0x08, 0x00, 0xFF, 0x42, 0x5A,
];
/// The guest writes the executed bytes here; the witness reads them back via `fs.read`.
const L2_RESULT_PATH: &str = "tool-result.bin";

const SKILLS_NS: &str = "advance:runtime/agent-skills@0.1.0";
const FS_NS: &str = "advance:runtime/agent-fs@0.1.0";

// ── helpers ──────────────────────────────────────────────────────────

/// Build a Fs+Skills+Llm SUT with the real `DiskSkillSummaryReader` on the turn
/// (the `.with_skills_summary()` axis) + a loopback gateway. One `ok_chat` script
/// suffices: only the guest's `generate` dials the loopback `/v1/chat/completions`
/// (the `PublishingContextAssembler` publish is a `gateway.publish_assembled`
/// store-write whose assembled messages — incl. `# Available Skills` — the cap-llm
/// generate handler then PREPENDS into that captured request body, the SYS-AC-010/192
/// mechanism); and the loopback replays its last response once drained anyway.
async fn skills_sut() -> SystemUnderTest {
    SystemUnderTest::builder()
        .caps(&[Cap::Fs, Cap::Skills, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            "reply", 7, 9,
        )]))
        .with_skills_summary()
        .build(HELLO_LLM_CORE)
        .await
}

fn ok_string(v: &Val) -> Option<String> {
    match v {
        Val::Result(Ok(Some(inner))) => match inner.as_ref() {
            Val::String(s) => Some(s.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// Materialize an active skill through the REAL production skill host-fns
/// (propose-skill-draft + activate-skill, the SYS-AC-074 path) — the activated
/// `SKILL.md` lands at `<ws>/agent/.agent/skills/{name}/` (the same provider root
/// the L0 reader is rooted at, and where `fs.read .agent/skills/...` resolves).
async fn activate_skill(sut: &SystemUnderTest, name: &str, content: &str) {
    let proposed = sut
        .call_host_fn_as_agent(
            sut.agent_id(),
            "skills",
            SKILLS_NS,
            "propose-skill-draft",
            vec![
                Val::String(name.to_string()),
                Val::String(content.to_string()),
                Val::List(Vec::new()),
            ],
        )
        .await
        .expect("propose-skill-draft dispatch");
    assert_eq!(
        proposed.first().and_then(ok_string).as_deref(),
        Some(name),
        "propose-skill-draft returns the draft id"
    );
    let activated = sut
        .call_host_fn_as_agent(
            sut.agent_id(),
            "skills",
            SKILLS_NS,
            "activate-skill",
            vec![Val::String(name.to_string())],
        )
        .await
        .expect("activate-skill dispatch");
    assert_eq!(
        activated.first().and_then(ok_string).as_deref(),
        Some(name),
        "activate-skill returns Ok(skill-id)"
    );
}

/// `fs.read` over the REAL agent-fs host-fn → the full file as UTF-8 (None on Err).
async fn fs_read_text(sut: &SystemUnderTest, path: &str) -> Option<String> {
    let out = sut
        .call_host_fn_n("fs", FS_NS, "read", vec![Val::String(path.to_string())], 1)
        .await
        .expect("fs.read dispatch");
    match out.into_iter().next() {
        Some(Val::Result(Ok(Some(inner)))) => match inner.as_ref() {
            Val::List(items) => {
                let bytes: Vec<u8> = items
                    .iter()
                    .map(|x| match x {
                        Val::U8(b) => *b,
                        other => panic!("non-u8 in fs.read list: {other:?}"),
                    })
                    .collect();
                Some(String::from_utf8(bytes).expect("utf8"))
            }
            _ => None,
        },
        _ => None,
    }
}

/// Materialize an active skill with an EXPLICIT version (score == version) via the
/// production `DiskSkillStorage` low-level writer — needed by 081, which requires
/// distinct versions the activate-skill host-fn does not let a test control. The
/// writer canonicalizes its root, matching the harness reader's canonicalized root.
async fn write_active_skill(agent_root: &std::path::Path, id: &str, version: u32, content: &str) {
    DiskSkillStorage::with_default_writer(agent_root.to_path_buf())
        .write_active(&SkillBlob {
            skill_id: id.to_string(),
            version,
            content: content.to_string(),
            tags: vec![],
            provenance: Provenance::AgentCreated,
            trust_level: TrustLevel::Untrusted,
        })
        .await
        .expect("write_active");
}

/// Wave-14 (SYS-AC-080): materialize an active skill that ALSO carries a `tool.wasm`
/// sidecar (the committed `echo_tool` component) at `<agent_root>/.agent/skills/{id}/`
/// — the exact on-disk shape `register_skill_tools` reads. `write_active` first (so
/// `list_active` enumerates it), then the `SkillSidecar::ToolWasm` write. All
/// `SkillBlob` fields are explicit (no `Default`), mirroring `write_active_skill`.
async fn seed_skill_with_tool(agent_root: &std::path::Path, id: &str, tool_wasm: &[u8]) {
    let storage = DiskSkillStorage::with_default_writer(agent_root.to_path_buf());
    storage
        .write_active(&SkillBlob {
            skill_id: id.to_string(),
            version: 1,
            content: format!(
                "---\nname: {id}\ndescription: bundles an echo tool\n---\n# {id}\n\nInvokes a sandboxed echo tool.\n"
            ),
            tags: vec![],
            provenance: Provenance::AgentCreated,
            trust_level: TrustLevel::Untrusted,
        })
        .await
        .expect("write_active (skill with tool)");
    storage
        .write_skill_sidecar(id, SkillSidecar::ToolWasm, tool_wasm)
        .await
        .expect("write tool.wasm sidecar");
}

/// `fs.read` over the REAL agent-fs host-fn → the file as raw bytes (None on Err /
/// absent file). The binary sibling of `fs_read_text` — used to read back the
/// guest-written `tool-result.bin` (the executed tool bytes).
async fn fs_read_bytes(sut: &SystemUnderTest, path: &str) -> Option<Vec<u8>> {
    let out = sut
        .call_host_fn_n("fs", FS_NS, "read", vec![Val::String(path.to_string())], 1)
        .await
        .expect("fs.read dispatch");
    match out.into_iter().next() {
        Some(Val::Result(Ok(Some(inner)))) => match inner.as_ref() {
            Val::List(items) => Some(
                items
                    .iter()
                    .map(|x| match x {
                        Val::U8(b) => *b,
                        other => panic!("non-u8 in fs.read list: {other:?}"),
                    })
                    .collect(),
            ),
            _ => None,
        },
        _ => None,
    }
}

// ── SYS-AC-078 ───────────────────────────────────────────────────────

/// The assembled per-turn context carries the visible skill's ≤100-token L0
/// first-paragraph summary, WITHOUT the agent calling any load tool.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_078_l0_skill_summary_in_assembled_context() {
    let sut = skills_sut().await;

    // One activated skill with a distinctive first-paragraph summary.
    const SUMMARY: &str = "Greets the user warmly by name and offers a concise opening line";
    let content =
        format!("---\nname: greeterskill\ndescription: x\n---\n# greeterskill\n\n{SUMMARY}.\n");
    activate_skill(&sut, "greeterskill", &content).await;

    // A generate-calling turn publishes the host-assembled context (with the L0
    // section) to the loopback. The guest (HELLO_LLM_CORE) only calls `generate` —
    // it issues NO skill-load/fs host-fn — so the skill surfaces purely via host L0
    // injection (no load tool).
    sut.inject_message("tester", b"hi").await;
    sut.run_turn().await;

    let bodies = sut.llm_all_chat_request_bodies();
    assert!(
        bodies
            .iter()
            .any(|b| b.contains("# Available Skills") && b.contains(SUMMARY)),
        "the L0 `# Available Skills` section + the skill's first-paragraph summary reached the \
         assembled prompt (real DiskSkillSummaryReader → published body; {} bodies captured)",
        bodies.len()
    );
    assert!(
        bodies.iter().any(|b| b.contains("greeterskill")),
        "the L0 section lists the activated skill by name"
    );
}

// ── SYS-AC-079 ───────────────────────────────────────────────────────

/// Within the same turn the agent reads the skill's FULL SKILL.md via fs.read (L1)
/// AFTER it surfaced only as an L0 summary. Discriminator: a unique marker placed
/// in a LATER paragraph is in the full file (L1 read) but NOT in the ≤100-token
/// first-paragraph L0 summary.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_079_l1_full_skill_md_read_after_l0_summary() {
    let sut = skills_sut().await;

    const SUMMARY: &str = "Surfaces a short first-paragraph summary for progressive loading";
    const L1_MARKER: &str = "UNIQUE_L1_MARKER_only_in_full_file_x7q";
    // First paragraph = the summary; the marker is a SEPARATE later paragraph, so
    // extract_skill_summary (stops at the first blank line) excludes it from L0.
    let content = format!(
        "---\nname: readableskill\ndescription: x\n---\n# readableskill\n\n{SUMMARY} and nothing \
         else here.\n\n{L1_MARKER}\n"
    );
    activate_skill(&sut, "readableskill", &content).await;

    // L0 leg: the turn surfaces the skill ONLY as its first-paragraph summary.
    sut.inject_message("tester", b"hi").await;
    sut.run_turn().await;
    let bodies = sut.llm_all_chat_request_bodies();
    assert!(
        bodies
            .iter()
            .any(|b| b.contains("# Available Skills") && b.contains(SUMMARY)),
        "L0: the assembled prompt carries the skill's first-paragraph summary"
    );
    assert!(
        bodies.iter().all(|b| !b.contains(L1_MARKER)),
        "L0: the later-paragraph marker is NOT in the assembled prompt — surfaced only as an L0 summary"
    );

    // L1 leg: the agent reads the FULL SKILL.md via the REAL fs.read host-fn (074
    // mechanism). The full file contains BOTH the summary AND the L1-only marker.
    let full = fs_read_text(&sut, ".agent/skills/readableskill/SKILL.md")
        .await
        .expect("the active SKILL.md is readable via the real fs.read host-fn");
    assert!(
        full.contains(SUMMARY),
        "L1 full read returns the file body (incl. the summary text)"
    );
    assert!(
        full.contains(L1_MARKER),
        "L1 full read returns the later-paragraph marker that the L0 summary omitted"
    );

    // Discriminator: an un-activated skill path is not readable.
    assert!(
        fs_read_text(&sut, ".agent/skills/never-activated/SKILL.md")
            .await
            .is_none(),
        "an un-activated skill path is not readable (the L1 read is real, not a fixture)"
    );
}

// ── SYS-AC-080 ────────────────────────────────────────────────────────

/// Within ONE turn the agent invokes the skill's bundled `tool.wasm` via
/// `agent-tools::tool-invoke` (L2) and receives the executed result bytes — through
/// the PRODUCTION skill→tool-registry bridge (`advance_cli::wiring::register_skill_tools`).
///
/// Witness-floor: a real `Cap::Tools + Cap::Fs` wired SUT over the
/// `guest-rust-tool-invoke` fixture (which CALLS `tool-invoke`). A skill `echo-skill`
/// is materialized WITH a `tool.wasm` sidecar (the real `echo_tool` component); the
/// PRODUCTION bridge registers it under `skill::echo-skill` into the SAME concrete
/// registry the `tool-invoke` host-fn drives; the guest's turn invokes it → real
/// component `execute` → the bytes are `fs.write`n and read back. Anti-fake-green is
/// layered (the cli `wire_capabilities_registers_skill_tools` regression is the
/// PRIMARY Step-7-wiring proof): 080-b/080-c prove registration is necessary,
/// `cache_len==1` proves a real lazy load, and the echo oracle is a cross-check that
/// the execution is real (echo returns params verbatim).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_080_l2_skill_tool_invoke_within_turn() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Tools, Cap::Fs])
        .build(TOOL_INVOKE_CORE)
        .await;

    // Materialize a skill carrying the echo tool.wasm sidecar, then drive the
    // PRODUCTION bridge over the SAME registry the tool-invoke host-fn uses.
    let agent_root = sut.workspace_root().join(AGENT_DIR);
    seed_skill_with_tool(&agent_root, "echo-skill", ECHO_TOOL_COMPONENT).await;
    let registered =
        advance_cli::wiring::register_skill_tools(sut.tool_registry().unwrap(), &agent_root).await;
    assert_eq!(
        registered, 1,
        "the production bridge registered exactly the one skill tool.wasm sidecar"
    );

    // The turn: the guest calls tool-invoke("skill::echo-skill","echo",PAYLOAD)
    // through the bridged registry → real execute → fs.write the result.
    sut.inject_message("tester", b"go").await;
    sut.run_turn().await;

    // The guest received + persisted the EXECUTED bytes.
    let got = fs_read_bytes(&sut, L2_RESULT_PATH)
        .await
        .expect("the guest wrote the executed tool bytes to tool-result.bin");

    // A real lazy load happened during the guest's invoke (register_binary is lazy).
    assert_eq!(
        sut.tool_registry().unwrap().cache_len().await,
        1,
        "the guest's tool-invoke caused a real lazy load of the skill tool"
    );

    // Real events: tool.invoke (pre-lookup) then tool.result (Ok only).
    sut.assert_event("tool.invoke", |_| true);
    sut.assert_event("tool.result", |_| true);

    // Cross-check oracle: a direct execute through the production registry returns
    // the SAME bytes the guest got (both traverse the real component execute).
    let oracle = sut
        .tool_registry()
        .unwrap()
        .invoke("skill::echo-skill", "echo", L2_PAYLOAD)
        .await
        .expect("direct execute of the bridged skill tool through the production registry");
    assert_eq!(
        got, oracle,
        "guest-received bytes == a real registry execute of the same tool"
    );
    assert_eq!(
        got, L2_PAYLOAD,
        "echo returns the invoked PAYLOAD verbatim (the executed result reached the guest)"
    );
}

/// Discriminator (the bridge is load-bearing): the skill is materialized but the
/// PRODUCTION bridge is NOT run → the registry is empty → the guest's `tool-invoke`
/// returns not-found → no result file + no `tool.result` event. Single variable vs
/// 080-a: the `register_skill_tools` call.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_080_no_bridge_no_execute() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Tools, Cap::Fs])
        .build(TOOL_INVOKE_CORE)
        .await;

    // Seed the skill (identical to 080-a) but DO NOT run register_skill_tools.
    let agent_root = sut.workspace_root().join(AGENT_DIR);
    seed_skill_with_tool(&agent_root, "echo-skill", ECHO_TOOL_COMPONENT).await;

    sut.inject_message("tester", b"go").await;
    sut.run_turn().await;

    assert!(
        fs_read_bytes(&sut, L2_RESULT_PATH).await.is_none(),
        "without the production bridge the skill tool is unregistered → tool-invoke not-found → no result file"
    );
    assert!(
        sut.events_of_types(&["tool.result"]).is_empty(),
        "no execute ran: no tool.result event (only tool.invoke + tool.error)"
    );
    assert_eq!(
        sut.tool_registry().unwrap().cache_len().await,
        0,
        "registry empty (no bridge) → nothing loaded"
    );
}

/// Discriminator (unregistered tool-id): the bridge runs but registers the skill
/// under a DIFFERENT name (`other-skill` → `skill::other-skill`), so the guest's
/// hardcoded `skill::echo-skill` resolves to nothing → not-found → no file. Proves
/// the registered id must MATCH — the bridge is not a stub echoing the input.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_080_unregistered_skill_id_no_execute() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Tools, Cap::Fs])
        .build(TOOL_INVOKE_CORE)
        .await;

    let agent_root = sut.workspace_root().join(AGENT_DIR);
    seed_skill_with_tool(&agent_root, "other-skill", ECHO_TOOL_COMPONENT).await;
    let registered =
        advance_cli::wiring::register_skill_tools(sut.tool_registry().unwrap(), &agent_root).await;
    assert_eq!(
        registered, 1,
        "the bridge registered the other-skill tool (under skill::other-skill)"
    );

    sut.inject_message("tester", b"go").await;
    sut.run_turn().await;

    assert!(
        fs_read_bytes(&sut, L2_RESULT_PATH).await.is_none(),
        "the guest invokes skill::echo-skill but only skill::other-skill is registered → not-found → no file"
    );
    assert!(
        sut.events_of_types(&["tool.result"]).is_empty(),
        "no execute ran for the unregistered tool-id (only tool.invoke + tool.error)"
    );
}

// ── SYS-AC-081 ───────────────────────────────────────────────────────

/// When aggregate skill summaries exceed the effective skill budget
/// (`min(skill_budget_tokens=2000, ⌊budget·0.05⌋, 10K)`), the LOWEST-scoring
/// summaries are truncated first — the SYS-AC-081 §2 criterion verbatim. This
/// witnesses score-ordered truncation exactly as worded; the product's `score` is
/// `version as f32` (the deterministic proxy the real `DiskSkillSummaryReader` sets,
/// context_wiring.rs:330-335), so "lowest-scoring" == "lowest-`version`" here. NOTE:
/// `score=version` is the DISCLOSED inverse of MODULE-017 AC-27's recency intent (a
/// pre-existing product hand-off documented at context_wiring.rs:231-237 + MODULE-010
/// §3.6) — NOT closed by this harness run (no product edits; no module AC in scope).
/// This witness binds to the §2 "lowest-scoring first" wording, which the as-built
/// product satisfies. The effective cap is 348 tokens because the harness driver leaves
/// `model = ""` (scheduler/agent_loop.rs:120) → `model_context_window("")` =
/// SMALL_MODEL_WINDOW 8192 → budget 6964 → ⌊6964/20⌋ = 348. Anti-fake-green: assert
/// ONLY a kept (highest-version) name present AND a dropped (lowest-version) name absent
/// — NOT a survivor count — robust to exact line-byte/word-boundary variation (holds for
/// any cap in [~1 line, ~aggregate)).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_081_skill_budget_truncation_lowest_scoring_first() {
    let sut = skills_sut().await;

    // 8 active skills with DISTINCT versions 1..=8 (score == version). Each
    // first-paragraph summary is long enough to max at the formatter's ≤100-tok
    // (~397-byte) cap, so the 8 rendered lines (~3.2 KB) far exceed the 348-token
    // (~1389-byte) section budget → the lowest versions are dropped, the highest kept.
    let agent_root = sut.workspace_root().join(AGENT_DIR);
    let long_para = "word ".repeat(140); // ~700 chars → summary truncated to ~397 B
    for v in 1..=8u32 {
        let id = format!("skillv{v:02}");
        let content = format!("---\nname: {id}\ndescription: x\n---\n# {id}\n\n{long_para}\n");
        write_active_skill(&agent_root, &id, v, &content).await;
    }

    // Tiny prompt → the whole-Tier-2 degrade guard never fires; only the in-section
    // skill_cap truncation is exercised.
    sut.inject_message("tester", b"hi").await;
    sut.run_turn().await;

    let bodies = sut.llm_all_chat_request_bodies();
    let section = bodies
        .iter()
        .find(|b| b.contains("# Available Skills"))
        .expect("a captured body carries the `# Available Skills` section");
    assert!(
        section.contains("skillv08"),
        "the HIGHEST-version skill (score 8) is kept under the budget"
    );
    assert!(
        !section.contains("skillv01"),
        "the LOWEST-version skill (score 1) is truncated first (dropped) — lowest-scoring-first"
    );
}

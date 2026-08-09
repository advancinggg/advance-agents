//! Wave-20 lane m001loop — MODULE-001-AC-18 witness: a single composed all-real-impl
//! `serve()` integration test.
//!
//! The ADR `docs/adr/2026-06-26-cli-spine-agent-loop-composition-root.md` blesses the
//! CLI daemon spine as the agent-loop composition root and names the deferred witness:
//! "a single composed all-real-impl `serve()` integration test driving the production
//! CLI-spine loop with the real `ContextAssemblerImpl` 10-port stack + real
//! `PostProcessor` + `WasmMessageHandler` + `MailboxStore`." No single existing test
//! composed all of those over `serve()` — `mode_assembled_context.rs` runs the real
//! assembler but via single-turn `run_turn` and NO live PostProcessor;
//! `sys_j22_postproc_writeback.rs` runs the live PostProcessor but with a non-generate
//! guest (no assembled-context-reaches-LLM leg). THIS test composes ALL of them and
//! drives the PRODUCTION serve loop via `serve_n_turns` (which shares the production
//! `run_turn_once` with `serve`).
//!
//! Composed-real-impl set (one turn through the production serve loop):
//!   - real `AgentLoopDriverImpl` + `serve_n_turns` (the production loop)
//!   - real `WasmMessageHandler` over `guest-rust-hello-llm` (calls `agent-llm/generate`)
//!   - real `ContextAssemblerImpl` 10-port stack (installed by `.llm(...)`; the
//!     `PublishingContextAssembler` runs + emits `context.assembled` + feeds the LLM)
//!   - real components-backed live `PostProcessor` (`.with_live_memory()`)
//!   - real `MailboxStore` + real loopback `LlmGateway`
//!
//! Two-leg, anti-fake-green oracle (each leg has a discriminator a mock would change):
//!   (i)  the real 10-port assembler emits a `context.assembled` event carrying the
//!        per-tier token counts — `MinimalContextAssembler` (the no-LLM default) NEVER
//!        emits this event, so its PRESENCE is the discriminator (the field VALUES are
//!        mode-dependent, so presence + tier keys is the load-bearing fact).
//!   (ii) the live components-backed `PostProcessor` writes `summary.yaml`/`turn-index.yaml`
//!        from the post-turn extraction — the trace-only default `PostProcessor::new()`
//!        writes NOTHING. The axis-OFF build (no `.with_live_memory()`) is the discriminator.
//!
//! Witness-floor: every assertion binds to PRODUCT output (the `context.assembled` event,
//! on-disk YAML) on the real wired chain. REQ-041 stays Partial (Witness:e2e — a module-AC
//! flip cannot promote it; the SYS-AC witness is separate).

use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::{Cap, LlmMode, SystemUnderTest};

/// A real wit-bindgen guest that imports `agent-llm@0.1.0`; its `handle-message`
/// reads `msg.payload` as the prompt and calls `agent-llm/generate` — so the real
/// assembler's published context reaches the LLM, exercising the 10-port stack.
const HELLO_LLM_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-hello-llm.core.wasm");

const GENERATE_REPLY: &str = "ac18-composed-serve-generate-reply";
/// A unique extraction digest marker — can ONLY appear in turn-index.yaml if the REAL
/// extraction result drove the live PostProcessor Step-7 writeback.
const DIGEST_MARKER: &str = "ac18-composed-serve-extraction-digest";
const TASK_SLUG: &str = "task-ac18-composed-serve";

fn extraction_json(digest: &str) -> String {
    format!(
        r#"{{"digest":"{digest}","knowledge":[{{"content":"ac18-knowledge","tags":["t"],"kind":"fact"}}]}}"#
    )
}

/// MODULE-001-AC-18: ONE turn through the production `serve_n_turns` loop composes ALL
/// real impls; the assembler oracle (i) AND the live-PostProcessor oracle (ii) both hold.
#[tokio::test(flavor = "multi_thread")]
async fn module_001_ac18_composed_serve_all_real_impls() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mem = dir.path().join(".agent/memory");

    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Llm, Cap::Memory])
        // POST#1 = the guest's `generate` reply (assembled context reaches the LLM);
        // POST#2 = the post-turn live-PostProcessor batched extraction (drives writeback).
        .llm(LlmMode::LoopbackScripted(vec![
            ScriptedResponse::ok_chat(GENERATE_REPLY, 7, 9),
            ScriptedResponse::ok_chat(&extraction_json(DIGEST_MARKER), 7, 9),
        ]))
        .with_memory_dir(mem.clone())
        .with_live_memory()
        .build(HELLO_LLM_CORE)
        .await;

    sut.inject_message_with_task("tester", TASK_SLUG, b"summarize the composed serve wiring")
        .await;
    // The PRODUCTION serve loop (serve_n_turns shares run_turn_once with serve).
    sut.run_turns(1).await;

    // ── Oracle (i): the real 10-port ContextAssemblerImpl ran (context.assembled +
    //    per-tier token counts). MinimalContextAssembler never emits this event. ──
    let assembled: Vec<_> = sut
        .events()
        .into_iter()
        .filter(|e| e.event_type == "context.assembled")
        .collect();
    assert_eq!(
        assembled.len(),
        1,
        "exactly one context.assembled event (the real 10-port assembler ran over serve_n_turns); got {}",
        assembled.len()
    );
    let payload = &assembled[0].payload;
    let counts = payload.get("tier_token_counts").unwrap_or_else(|| {
        panic!("context.assembled carries tier_token_counts; payload={payload}")
    });
    for tier in ["tier1a", "tier1b", "tier2", "tier3"] {
        assert!(
            counts.get(tier).is_some(),
            "tier_token_counts must carry {tier} (10-port assembler discriminator); payload={payload}"
        );
    }

    // The published assembled context reached the LLM (the guest dialed generate through
    // the real gateway) — a Minimal/mock assembler would not feed the gateway. With
    // `.with_live_memory()` there are TWO chat POSTs: [0] = the guest's generate (carries
    // the assembled tiers), [1] = the post-turn extraction. Check the GENERATE body (0).
    let bodies = sut.llm_all_chat_request_bodies();
    assert!(
        bodies.len() >= 2,
        "expected ≥2 chat POSTs (guest generate + post-turn extraction); got {}",
        bodies.len()
    );
    assert!(
        bodies[0].contains("# Available Tools"),
        "the guest's generate POST carried the real assembler's merged tools section; body={}",
        bodies[0]
    );

    // ── Oracle (ii): the live components-backed PostProcessor ran (summary.yaml +
    //    turn-index.yaml written from the REAL extraction). Trace-only default writes none. ──
    let task_dir = mem.join("tasks").join(TASK_SLUG);
    let summary = task_dir.join("summary.yaml");
    let turn_index = task_dir.join("turn-index.yaml");
    assert!(
        summary.exists() && turn_index.exists(),
        "the live PostProcessor wrote summary.yaml + turn-index.yaml under tasks/{TASK_SLUG}/"
    );
    let ti = std::fs::read_to_string(&turn_index).expect("read turn-index.yaml");
    assert!(
        ti.contains(DIGEST_MARKER),
        "turn-index.yaml carries the REAL extraction digest (the live PostProcessor's extraction \
         result — not a mechanical fallback — drove Step-7); ti={ti}"
    );

    // ── Discriminator: axis OFF → trace-only PostProcessor::new() → NO writeback. ──
    let dir2 = tempfile::tempdir().expect("tempdir2");
    let mem2 = dir2.path().join(".agent/memory");
    let sut_off = SystemUnderTest::builder()
        .caps(&[Cap::Llm, Cap::Memory])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            GENERATE_REPLY,
            7,
            9,
        )]))
        .with_memory_dir(mem2.clone())
        // NO .with_live_memory() — the trace-only baseline.
        .build(HELLO_LLM_CORE)
        .await;
    sut_off
        .inject_message_with_task("tester", TASK_SLUG, b"summarize the composed serve wiring")
        .await;
    sut_off.run_turns(1).await;
    assert!(
        !mem2.join("tasks").join(TASK_SLUG).join("summary.yaml").exists(),
        "discriminator: with the live-memory axis OFF the trace-only PostProcessor writes NO summary.yaml"
    );
}

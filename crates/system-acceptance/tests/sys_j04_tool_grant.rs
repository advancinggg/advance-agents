//! SYS-J-04 — SYS-AC-012: a WASM tool the agent lacks an L1 `tools` grant for is
//! absent from the assembled `# Available Tools` section (post-grant filter, CONTRACT-165
//! realized via CONTRACT-183).
//!
//! Journey (docs/SYSTEM-ACCEPTANCE.md §1): MODULE-010 → MODULE-017 → MODULE-005.
//!
//! Wave-15 Lane E FLIP — a REAL e2e witness. The `.with_tool_grant_filter()` axis wires a
//! populated production `cap_tools::CallableInventory` (`[wasmtool, secrettool]`) carrying
//! a CONTRACT-183 `ToolsGrantReaderImpl` over a DEDICATED `GrantStore`, fed as the turn
//! assembler's `CallableInventoryReader` port. The witness seeds a `"tools"` grant
//! `ids=<one tool>` for `AGENT_ID` via the colon-tolerant `seed_grant` helper, runs a turn,
//! and asserts the granted tool surfaces in `# Available Tools` while the ungranted tool is
//! ABSENT. The discriminator flips the grant's `ids` → the absence is grant-driven, not a
//! constant inventory omission.

#[path = "d_grant/mod.rs"]
mod d_grant;

use cap_grant::data::GrantTtl;
use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::{Cap, LlmMode, SystemUnderTest, AGENT_ID};

use d_grant::{cap, seed_grant};

const HELLO_LLM_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-hello-llm.core.wasm");

/// Build a `.with_tool_grant_filter()` SUT, seed a `"tools"` grant with the given `ids`
/// CSV for `AGENT_ID` (the id the assembler passes to `list_wasm_tools`), run a turn, and
/// return the serialized `/v1/chat/completions` prompt body (the oracle).
async fn tools_grant_body(ids_csv: &str) -> String {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Llm, Cap::Fs, Cap::Tools])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            "tool-grant-witness-reply",
            5,
            5,
        )]))
        .with_tool_grant_filter()
        .build(HELLO_LLM_CORE)
        .await;

    let store = sut
        .grant_store()
        .expect(".with_tool_grant_filter() exposes a dedicated GrantStore");
    // Seed under the COLON `AGENT_ID` (= `ctx.agent_id` the assembler passes to
    // `list_wasm_tools`); `seed_grant` uses the colon-tolerant `insert_dynamic` path.
    seed_grant(
        store,
        "g-tools",
        AGENT_ID,
        "tools",
        vec![cap("ids", ids_csv)],
        GrantTtl::Persistent,
        None,
    );

    sut.inject_message("tester", b"use a tool").await;
    sut.run_turn().await;
    sut.llm_last_chat_request_body()
        .expect("a /v1/chat/completions body was recorded (the guest dialed generate)")
}

/// SYS-AC-012 [FLIP, Wave-15 Lane E]: with a `"tools"` grant for `wasmtool` only, the
/// GRANTED tool is present in `# Available Tools` and the UNGRANTED `secrettool` is absent.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_012_ungranted_wasm_tool_absent() {
    let body = tools_grant_body("wasmtool").await;
    assert!(
        body.contains("# Available Tools"),
        "the Tools section reaches the prompt; body = {body}"
    );
    assert!(
        body.contains("wasmtool"),
        "the GRANTED wasm tool is present; body = {body}"
    );
    assert!(
        !body.contains("secrettool"),
        "the UNGRANTED wasm tool is absent (post-L1-`tools`-grant filter); body = {body}"
    );
}

/// Discriminator (SYS-AC-012): the absence is GRANT-DRIVEN, not a constant — a grant for
/// a DIFFERENT tool (`secrettool`) makes `secrettool` present and `wasmtool` absent.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_012_discriminator_grant_drives_visibility() {
    let body = tools_grant_body("secrettool").await;
    assert!(
        body.contains("secrettool"),
        "the now-granted tool (secrettool) is present; body = {body}"
    );
    assert!(
        !body.contains("wasmtool"),
        "the now-ungranted wasmtool is absent (proves the filter is grant-driven); body = {body}"
    );
}

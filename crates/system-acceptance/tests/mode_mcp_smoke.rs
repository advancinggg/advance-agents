//! HF fast-follow smoke (2026-06-03): `.with_mcp_transports()` + `drive_mcp_tool()`.
//!
//! Drives a real `McpClient::invoke_tool` (whitelist → tool-pattern → transport)
//! over an injected in-process scripted transport — no subprocess/network.

use system_acceptance::{McpServerSpec, SystemUnderTest};

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

#[tokio::test]
async fn mcp_tool_call_returns_scripted_result_and_blocks_unlisted() {
    let sut = SystemUnderTest::builder()
        .with_mcp_transports(vec![
            McpServerSpec::scripted("srv", &["echo"]).reply(br#"{"ok":true}"#)
        ])
        .build(CORE_BYTES)
        .await;

    // Allowed tool → the scripted result flows back through invoke_tool.
    let out = sut
        .drive_mcp_tool("srv", "echo", br#"{"x":1}"#)
        .await
        .expect("invoke allowed tool 'echo'");
    assert_eq!(
        out, br#"{"ok":true}"#,
        "scripted tools/call result returned"
    );

    // A tool not in the Literal patterns is rejected by the tool-pattern gate.
    let err = sut
        .drive_mcp_tool("srv", "denied", br#"{}"#)
        .await
        .expect_err("unlisted tool 'denied' is blocked");
    assert!(
        format!("{err:?}").contains("denied"),
        "tool-pattern gate rejects 'denied', got {err:?}"
    );
}

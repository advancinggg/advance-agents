//! HF fast-follow smoke (2026-06-03): `.with_channel_capture()` (SYS-J-01 reply leg).
//!
//! Inbound: enqueue → poll round-trip through the REAL `SubscriptionManager`.
//! Outbound: `send-raw` driven through the registered `SendRawHandler` →
//! `OutboundDispatcher` → the capturing `HttpSecurityChain` seam (the guest path
//! is namespace-linker-blocked; the host-fn primitive drives it instead).

use system_acceptance::SystemUnderTest;

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

#[tokio::test]
async fn channel_inbound_inject_then_poll_round_trip() {
    let sut = SystemUnderTest::builder()
        .with_channel_capture()
        .build(CORE_BYTES)
        .await;
    sut.inject_channel_inbound(b"inbound-msg", vec![])
        .expect("enqueue inbound");
    let got = sut
        .poll_channel_inbound()
        .expect("poll ok")
        .expect("an event is queued");
    assert_eq!(
        got.data, b"inbound-msg",
        "the injected inbound event polls back"
    );
    // Drained.
    assert!(sut.poll_channel_inbound().expect("poll ok").is_none());
}

#[tokio::test]
async fn channel_outbound_send_raw_is_captured() {
    let sut = SystemUnderTest::builder()
        .with_channel_capture()
        .build(CORE_BYTES)
        .await;
    sut.drive_channel_send_raw(b"reply-out")
        .await
        .expect("send-raw via the registered handler");
    let captured = sut.captured_outbound();
    assert_eq!(captured.len(), 1, "exactly one outbound request captured");
    assert_eq!(
        captured[0].body, b"reply-out",
        "the send-raw payload reached the chain seam"
    );
    assert_eq!(
        captured[0].agent_id,
        sut.agent_id(),
        "captured with the SUT agent as the outbound caller"
    );
}

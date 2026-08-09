//! /dev Slice BS-3 — harness reusability smoke (the real deliverable: the harness
//! generalizes, not SYS-J-01 alone). A SECOND journey — different sender, different
//! payload, different assertions — proving "add a journey = a new test file + new
//! input + new assertions, nothing else". NOT a gated SYS-AC.

use system_acceptance::SystemUnderTest;

const J01_SKELETON: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

#[tokio::test]
async fn harness_generalizes_to_a_second_journey() {
    let sut = SystemUnderTest::start(J01_SKELETON).await;
    // A distinct inbound payload → a distinct on-disk result, via the SAME harness API.
    let payload = b"second-journey-distinct-bytes";

    sut.inject_message("bob", payload).await;
    sut.run_turn().await;

    // The harness's event surface generalizes — witness msg.received from a different sender.
    sut.assert_event("msg.received", |e| {
        e.payload.get("from").and_then(|v| v.as_str()) == Some("user:bob")
    });
    // The second journey's distinct payload is what landed on disk.
    assert_eq!(
        sut.read_workspace_file("j01.txt").as_deref(),
        Some(&payload[..]),
        "the second journey's distinct payload was written"
    );
    assert_eq!(sut.turn_commits().len(), 1, "one turn commit");
}

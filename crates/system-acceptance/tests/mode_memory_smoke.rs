//! Mode smoke (Slice S2): `.caps([Cap::Memory])`.
//!
//! The full `remember`→`recall` guest-turn witness was BLOCKED upstream until /dev
//! Slice N1 (n1-namespaces) versioned the cap-memory host-fn namespace. cap-memory now
//! registers its host fns under the VERSIONED namespace
//! `"advance:runtime/agent-memory@0.1.0"` (cap-memory `host_fn.rs:23`), which the
//! wit-bindgen guest (package `advance:runtime@0.1.0`) import matches in the Wasmtime
//! component linker — the same versioned form cap-fs uses for the j01 fs guest. The
//! previously-`#[ignore]`d witness is now active (below).
//!
//! What IS witnessed here (green): the memory cap registers and coexists with a real
//! fs turn — the substrate wires `.caps([Memory])` without error.

use system_acceptance::{Cap, SystemUnderTest};

const J01_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");
const MEM_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-mem-skeleton.core.wasm");

/// Green: the memory provider registers and the substrate boots + drives a turn with
/// the memory cap active (here via the fs guest, which also exercises fs). Proves
/// `.caps([Memory, Fs])` wires cleanly.
#[tokio::test]
async fn memory_cap_registers_and_coexists_with_fs_turn() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs, Cap::Memory])
        .build(J01_CORE)
        .await;
    sut.inject_message("harness", b"coexist").await;
    sut.run_turn().await;

    sut.assert_event("msg.received", |_| true);
    assert_eq!(
        sut.turn_commits().iter().filter(|c| c.is_turn).count(),
        1,
        "the fs turn commits with the memory cap also registered"
    );
}

/// Full memory `remember`→`recall` guest-turn witness. Un-ignored by /dev Slice N1
/// (n1-namespaces): cap-memory now registers the VERSIONED host-fn namespace
/// `advance:runtime/agent-memory@0.1.0`, which the wit-bindgen guest (package
/// `advance:runtime@0.1.0`) import matches in the Wasmtime component linker.
#[tokio::test]
async fn memory_remember_recall_through_a_real_turn() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory])
        .build(MEM_CORE)
        .await;
    sut.inject_message("harness", b"a-durable-insight").await;
    sut.run_turn().await;

    sut.assert_event("memory.remember", |_| true);
    sut.assert_event("memory.recall", |_| true);
}

//! Mode smoke (Slice S2): `GrantMode::Real` wires the REAL cap-grant `GrantCheckImpl`
//! as the L1 capability gate. Witnessed via the fs guest: under `AllowAll` the
//! guest's `fs.write` commits; under `Real` (with no fs grant issued) the SAME write
//! is denied at the L1 gate, so no turn commit lands and the file never appears.
//! This is a real authorization witness (SYS-J-15 shape: L0 present, L1 denied),
//! contrasting the two grant modes through an identical turn.

use system_acceptance::{Cap, GrantMode, SystemUnderTest};

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

fn turn_commit_count(sut: &SystemUnderTest) -> usize {
    sut.turn_commits().iter().filter(|c| c.is_turn).count()
}

#[tokio::test]
async fn allow_all_grant_lets_fs_write_commit() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .grant(GrantMode::AllowAll)
        .build(CORE_BYTES)
        .await;
    sut.inject_message("harness", b"granted-write").await;
    sut.run_turn().await;

    assert_eq!(
        turn_commit_count(&sut),
        1,
        "AllowAll: the fs.write committed a turn"
    );
    assert_eq!(
        sut.read_workspace_file("j01.txt").as_deref(),
        Some(b"granted-write".as_slice()),
        "the written file landed under AllowAll"
    );
}

#[tokio::test]
async fn real_grant_denies_ungranted_fs_write() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .grant(GrantMode::Real)
        .build(CORE_BYTES)
        .await;
    sut.inject_message("harness", b"ungranted-write").await;
    sut.run_turn().await;

    // The real GrantCheckImpl has no fs grant for this agent → the fs.write is denied
    // at the L1 gate, so the turn produces no commit and no file (vs AllowAll above).
    assert_eq!(
        turn_commit_count(&sut),
        0,
        "Real grant: an ungranted fs.write is denied at L1 → no turn commit"
    );
    assert!(
        sut.read_workspace_file("j01.txt").is_none(),
        "the denied write never landed"
    );
}

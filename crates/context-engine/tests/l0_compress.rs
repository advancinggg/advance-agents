//! AC-07 — L0 3-step compression (T08 dedup / T09 invalidate / T10 skeleton).

use advance_context_engine::{l0_compress, L0Action, L0Entry, L0Kind};

fn read(turn: u64, path: &str) -> L0Entry {
    L0Entry {
        turn_id: turn,
        kind: L0Kind::Read { path: path.into() },
    }
}
fn write(turn: u64, path: &str) -> L0Entry {
    L0Entry {
        turn_id: turn,
        kind: L0Kind::Write { path: path.into() },
    }
}
fn assistant(turn: u64, text: &str) -> L0Entry {
    L0Entry {
        turn_id: turn,
        kind: L0Kind::Assistant { text: text.into() },
    }
}

/// T08 — dedup: the same file read twice (no intervening write) marks the
/// OLDER read `Superseded`; unrelated reads stay `Keep`.
#[test]
fn t08_dedup_supersedes_older_duplicate_read() {
    let entries = vec![read(1, "a"), read(1, "b"), read(1, "a")];
    let actions = l0_compress(&entries);
    assert_eq!(actions[0], L0Action::Superseded, "older Read(a) superseded");
    assert_eq!(actions[1], L0Action::Keep, "Read(b) untouched");
    assert_eq!(actions[2], L0Action::Keep, "newer Read(a) kept");
}

/// T09 — invalidate: a Read whose file is later Written is `Invalid` (stale
/// across the write), NOT merely Superseded. The post-write read stays Keep.
#[test]
fn t09_read_before_write_is_invalid_not_superseded() {
    let entries = vec![read(1, "a"), write(1, "a"), read(1, "a")];
    let actions = l0_compress(&entries);
    assert_eq!(
        actions[0],
        L0Action::Invalid,
        "Read(a) before Write(a) is Invalid (stale), not Superseded"
    );
    assert_eq!(actions[1], L0Action::Keep, "Write(a) kept");
    assert_eq!(actions[2], L0Action::Keep, "post-write Read(a) is current");
}

/// T10 — skeleton extract: an `Invalid` entry WITH a same-`turn_id`
/// assistant collapses to `Skeleton{tool,args,conclusion}` where the
/// conclusion is the assistant's first sentence.
#[test]
fn t10_invalid_with_same_turn_assistant_becomes_skeleton() {
    let entries = vec![read(1, "a"), write(1, "a"), assistant(1, "Read a. Done.")];
    let actions = l0_compress(&entries);
    match &actions[0] {
        L0Action::Skeleton {
            tool,
            args,
            conclusion,
        } => {
            assert_eq!(tool, "fs.read");
            assert_eq!(args, "path=a");
            assert_eq!(conclusion, "Read a.", "first sentence only");
        }
        other => panic!("expected Skeleton, got {other:?}"),
    }
    assert_eq!(actions[1], L0Action::Keep);
    assert_eq!(actions[2], L0Action::Keep);
}

/// Same shape as T09 but with NO same-turn assistant → stays `Invalid`
/// (cannot build a meaningful skeleton without a conclusion). Locks the
/// documented Slice-B reading of §1.3.4 Step C.
#[test]
fn invalid_without_assistant_stays_invalid() {
    let entries = vec![read(1, "a"), write(1, "a")];
    let actions = l0_compress(&entries);
    assert_eq!(actions[0], L0Action::Invalid);
    assert_eq!(actions[1], L0Action::Keep);
}

/// Determinism: same input → identical output across calls (pure function).
#[test]
fn l0_compress_is_deterministic() {
    let entries = vec![
        read(1, "a"),
        read(1, "b"),
        write(2, "a"),
        read(2, "a"),
        assistant(2, "Rewrote a; verified. Extra."),
    ];
    assert_eq!(l0_compress(&entries), l0_compress(&entries));
}

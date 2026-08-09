//! Track A — SYS-J-47 witness: an `fs_write` turn fans out `fs.write` + `meta.updated`.
//!
//! Witnesses **SYS-AC-150** end-to-end on the REAL wired system: a single agent turn
//! that performs one `agent-fs::write` emits BOTH an `fs.write` event AND a
//! `meta.updated` event, observable through the real `EventBus` SQLite `events` table —
//! the same persisted store that `/query/events?event_type=fs.write` (named in the
//! SYS-AC-150 criterion) serves (`event-bus/src/query_api.rs` reads the same `events`
//! table via a `SELECT … FROM events WHERE event_type = ?` query — same store, with the
//! route adding the type filter / ordering / limit our read-back does not need). The
//! in-process harness exposes no HTTP route, so the SQLite read-back IS the faithful
//! same-store witness — identical to how `mode_events_smoke.rs` witnesses `msg.received`.
//!
//! Real wired chain (no mocks): the production composition root
//! (`advance_cli::agent_loop::build_agent_loop` + `WasmMessageHandler`) drives the
//! `guest-rust-j01-skeleton` guest through the real `cap-fs` provider, which emits the
//! two events via the real `EventBusEmit` only AFTER a successful on-disk write
//! (`cap-fs/src/events.rs:146-163`, emit-on-success; top-level `Event.agent_id` set for
//! every variant at events.rs:152).
//!
//! Scope discipline (witness-floor): the SYS-AC-150 test asserts the two events + the
//! on-disk file/`.meta.yaml`. The SQLite-INDEX leg (**SYS-AC-149/151**) is witnessed by
//! the two tests BELOW (stage-B): the `.with_sqlite_index()` axis now wires the cap-fs
//! triple-sync trio, so `sqlite_sync_after_write` runs and the write fans out to a real
//! `meta_index`/`content_index`/`content_fts` — 149 asserts the rows are present
//! atomically (no rebuild), 151 asserts the new content is FTS-recallable immediately
//! (no rebuild). The turn commit still happens (visible via `turn_commits()`), but
//! `git.commit` is never emitted as an event (SYS-AC-247, a separate recorded deferral),
//! so it is not asserted here.
//!
//! `#[tokio::test(flavor = "multi_thread")]` is mandatory: the synchronous `EventBus`
//! writes inline during the turn (harness docstring in `lib.rs`; precedent
//! `mode_events_smoke.rs`).

use cap_fs::MAX_WRITE_BYTES;
use system_acceptance::{Cap, EventSink, SystemUnderTest};
use wasmtime::component::Val;

const J01_SKELETON: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");

/// The cap-fs `write` host-fn coordinates (cap `"fs"`, the versioned namespace, op `"write"`)
/// — the same tuple `register_agent_fs` registers and the lookup in `call_host_fn_n` resolves.
const FS_WRITE_NS: &str = "advance:runtime/agent-fs@0.1.0";

#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_150_fs_write_fans_out_fs_write_and_meta_updated_events() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .events(EventSink::RealBus)
        .build(J01_SKELETON)
        .await;

    let payload = b"sys-j47-fs-write";
    sut.inject_message("alice", payload).await;
    sut.run_turn().await;

    // SYS-AC-150 core — the write fanned out BOTH events, persisted to the real
    // EventBus SQLite `events` table (the /query/events store).
    let fs_write = sut.assert_db_event("fs.write", |r| {
        r.agent_id.as_deref() == Some(sut.agent_id())
    });
    assert!(
        fs_write.payload.is_some(),
        "fs.write row carries a payload (agent_id/path/size/is_new_file)"
    );
    sut.assert_db_event("meta.updated", |r| {
        r.agent_id.as_deref() == Some(sut.agent_id())
    });

    // The real bus dropped nothing (oversize / dup-id / backpressure).
    sut.assert_no_dropped_events();
    assert!(
        sut.db_event_count(Some("fs.write")) >= 1,
        "at least one fs.write row persisted"
    );
    assert!(
        sut.db_event_count(Some("meta.updated")) >= 1,
        "at least one meta.updated row persisted"
    );

    // Corroborate the write actually landed on disk (SYS-AC-150 premise: "the write"),
    // and its parent `.meta.yaml` was maintained — WITHOUT asserting the unwired
    // SQLite-index leg (SYS-AC-149/151 are recorded deferrals).
    let file = sut
        .read_workspace_file("j01.txt")
        .expect("the turn's fs.write landed in the agent workspace");
    assert_eq!(file, payload, "written file content == injected payload");
    assert!(
        sut.read_workspace_file(".meta.yaml").is_some(),
        "the write maintained the parent directory's .meta.yaml (meta.updated leg)"
    );

    // RealBus does not populate the in-memory events() accessor (sanity, matches
    // mode_events_smoke.rs).
    assert!(
        sut.events().is_empty(),
        "in-memory events() is empty for RealBus"
    );
}

/// SYS-AC-149: a single `agent-fs::write` updates the file content, its parent
/// `.meta.yaml` `_entries` row, AND the SQLite `meta_index`/`content_index` rows
/// atomically — proven WITHOUT any rebuild (the write-path triple-sync fan-out).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_149_fs_write_updates_sqlite_meta_and_content_index_atomically() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .with_sqlite_index()
        .build(J01_SKELETON)
        .await;

    // One real guest fs-write turn (drains fully before we read the single-conn index).
    let payload = b"sysj47 atomic triple zebracanary";
    sut.inject_message("alice", payload).await;
    sut.run_turn().await;

    // Leg 1 — file content on disk.
    let file = sut
        .read_workspace_file("j01.txt")
        .expect("the turn's fs.write landed in the agent workspace");
    assert_eq!(file, payload, "written file content == injected payload");

    // Leg 2 — parent `.meta.yaml` `_entries` row.
    let meta = sut
        .read_workspace_file(".meta.yaml")
        .expect("the write maintained the parent directory's .meta.yaml");
    let meta_text = String::from_utf8(meta).expect("meta yaml utf8");
    assert!(
        meta_text.contains("j01.txt"),
        ".meta.yaml _entries lists the written file, got:\n{meta_text}"
    );

    // Leg 3 — SQLite meta_index + content_index rows present (no rebuild). The guest
    // wrote `j01.txt` into its own workspace (`<ws>/agent`), so the M004 scope is
    // agent_id "agent", directory "/agent", file_path "/agent/j01.txt".
    let agent = sut.agent_m004_id();
    assert_eq!(agent, "agent", "single-agent M004 scope");
    let (meta_row, content_row) =
        sut.sqlite_file_indexed(&agent, "/agent", "j01.txt", "/agent/j01.txt");
    assert!(
        meta_row,
        "SQLite meta_index row present atomically after the write (no rebuild)"
    );
    assert!(
        content_row,
        "SQLite content_index row present atomically after the write (no rebuild)"
    );
}

/// SYS-AC-151: immediately after the write (NO rebuild), a recall/unified_search for
/// the new content returns the row — proving the SQLite sync rode the `fs.*` fan-out
/// (not a later reconcile). Uses the FTS/keyword path (content_vec is unpopulated on
/// the write path — `embedding=None` — so the vector path would return nothing).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_151_recall_immediately_after_write_no_rebuild() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .with_sqlite_index()
        .build(J01_SKELETON)
        .await;

    let payload = b"sysj47 immediate recall zebracanary";
    sut.inject_message("alice", payload).await;
    sut.run_turn().await;

    // No boot_reconcile() / rebuild here — recall must hit the write-path-synced row.
    let agent = sut.agent_m004_id();
    let hits = sut.fts_recall(&agent, "zebracanary").await;
    assert!(
        hits.iter()
            .any(|r| r.file_path.as_deref() == Some("/agent/j01.txt")),
        "FTS recall for the new content returns the just-written row (no rebuild); got {:?}",
        hits.iter().map(|r| r.file_path.clone()).collect::<Vec<_>>()
    );
}

/// SYS-AC-236: when the git (commit-queue) leg of an fs.write FAILS, the runtime
/// emits `runtime.degraded.git_sync_failed` AND the fs.write still succeeds (file +
/// .meta.yaml + SQLite legs committed) — fail-soft on the git leg only. The git
/// leg is fault-injected via `.with_failing_git_sync()` (a `FailingGitSync` at the
/// designed `Arc<dyn GitSync>` port — the legitimate seam, mirroring the cap-fs
/// sibling `sc_t28` sqlite-leg degraded witness). The §3 "needs an HF
/// fault-injection seam on git_sync" reason is now satisfied by that test-only
/// seam. The whole chain (cap-fs FsWriteHandler → `git_sync_after_write` Err branch
/// → real `emit_runtime_degraded`) is the real product path; only the GitSync impl
/// is the injected fault.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_236_git_leg_failure_emits_degraded_and_fs_write_succeeds() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .with_sqlite_index()
        .with_failing_git_sync()
        .build(J01_SKELETON)
        .await;

    let payload = b"sysj47 git-failsoft zebracanary";
    sut.inject_message("alice", payload).await;
    sut.run_turn().await;

    let evs = sut.events();
    // (a) the git leg failure emitted the degraded event.
    assert!(
        evs.iter()
            .any(|e| e.event_type == "runtime.degraded.git_sync_failed"),
        "git leg failure emits runtime.degraded.git_sync_failed; got {:?}",
        evs.iter().map(|e| &e.event_type).collect::<Vec<_>>()
    );

    // (b) fs.write STILL succeeded — all non-git legs committed.
    let file = sut
        .read_workspace_file("j01.txt")
        .expect("file written despite git leg failure (fail-soft)");
    assert_eq!(
        file, payload,
        "written content == payload despite git failure"
    );
    assert!(
        sut.read_workspace_file(".meta.yaml").is_some(),
        ".meta.yaml maintained despite git failure"
    );
    let agent = sut.agent_m004_id();
    let (meta_row, content_row) =
        sut.sqlite_file_indexed(&agent, "/agent", "j01.txt", "/agent/j01.txt");
    assert!(
        meta_row && content_row,
        "SQLite meta+content legs committed despite git failure (fail-soft on git only)"
    );
    // The fs.write event itself still fired (the FS leg succeeded).
    assert!(
        evs.iter().any(|e| e.event_type == "fs.write"),
        "fs.write event still emitted (the FS leg succeeded)"
    );
}

/// SYS-AC-236 discriminator: with a HEALTHY (non-failing) GitSync, NO degraded
/// event is emitted (the same write turn, default git leg).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_236_discriminator_healthy_git_emits_no_degraded() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .with_sqlite_index()
        .build(J01_SKELETON)
        .await;

    sut.inject_message("alice", b"sysj47 healthy git zebracanary")
        .await;
    sut.run_turn().await;

    let evs = sut.events();
    assert!(
        !evs.iter()
            .any(|e| e.event_type == "runtime.degraded.git_sync_failed"),
        "a healthy git leg emits NO degraded event; got {:?}",
        evs.iter().map(|e| &e.event_type).collect::<Vec<_>>()
    );
    assert!(
        evs.iter().any(|e| e.event_type == "fs.write"),
        "the write still happened in the control case"
    );
}

/// SYS-AC-235: a single `agent-fs::write` whose payload exceeds `MAX_WRITE_BYTES` (64 MiB) is
/// rejected with a typed `invalid-path` err-variant, and NO file / `.meta.yaml` / SQLite row is
/// mutated.
///
/// The §3 deferral ("64 MiB write-rejection unreachable through the guest: guest linear memory
/// caps at 16 MiB, so the guest cannot allocate 64 MiB+1 to reach the host check") is resolved by
/// DIRECT-DRIVING the REAL registered `FsWriteHandler` via `call_host_fn_n` (the
/// `host_fn_invoke_smoke` / 098/101/109/202 drive-prod-fn-no-caller precedent) with a HOST-built
/// oversized `Val::List` — sidestepping the guest's 16 MiB linear-memory cap while exercising the
/// SAME production reject branch (`cap-fs/src/host_fn.rs:810`: `d.len() > MAX_WRITE_BYTES` on the
/// BORROWED list, BEFORE the FD semaphore acquire and the `Vec<u8>` materialization).
///
/// RESOURCE COST (inherent + accepted): the host-built `Vec<Val>` of `MAX_WRITE_BYTES + 1` elements
/// is a ~2.5 GiB transient (MEASURED ~2.53 GiB peak RSS; `size_of::<wasmtime::component::Val>()` ≈
/// 40 B × 67,108,865), dropped at the rejected call's return. This is INTRINSIC to witnessing a
/// 64-MiB-LENGTH bound at the system level — the handler reads `d.len()` of a real `Vec<Val>`, so no
/// cheaper construction exists; the §3-deferred alternative ("HF larger-guest-memory harness
/// config") would materialize the same host-side `Vec<Val>` at the WASM→host lift. On a
/// memory-constrained CI runner this CAN OOM-abort the binary: its 6 sibling tests are light (so the
/// IN-binary peak is this one test's single allocation), but cargo's default CROSS-binary
/// parallelism can coincide it with another crate's heavy test — pin `--test-threads`/`--jobs` or
/// run this binary in isolation on runners with < ~4 GiB free.
///
/// `.with_sqlite_index()` wires the SQLite triple-sync leg LIVE (so the "no SQLite mutation" leg is
/// checked against a real, write-populated index — a successful write WOULD add the row, per
/// SYS-AC-149/236) and `EventSink::RealBus` checks event-absence on the SAME persisted `events`
/// store SYS-AC-150 asserts against. NOTE these absence checks are CORROBORATING, not the
/// load-bearing oracle: the reject fires at host_fn.rs:810 BEFORE the semaphore / resolution /
/// materialization / index-sync / event-emit, so file/.meta.yaml/SQLite/event absence holds
/// regardless of wiring. The LOAD-BEARING, fabrication-resistant oracle is the typed `invalid-path`
/// err-variant carrying the EXACT over-cap length (below), which a no-op handler could not produce.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_235_oversized_write_rejected_no_mutation() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .with_sqlite_index()
        .events(EventSink::RealBus)
        .build(J01_SKELETON)
        .await;

    // Lock the SYS-AC-235 acceptance contract: the criterion names the literal 64 MiB, so assert
    // the product const IS 64 MiB. Without this, a future MAX_WRITE_BYTES drift would silently pass
    // this witness while changing the bound the criterion promises (adversarial r10 — cap drift).
    assert_eq!(
        MAX_WRITE_BYTES,
        64 * 1024 * 1024,
        "SYS-AC-235 contract: MAX_WRITE_BYTES == 64 MiB"
    );

    // One byte over the 64 MiB cap (the guest cannot build this — its linear memory caps at
    // 16 MiB; THE §3 blocker). Built host-side, where there is no such cap.
    let oversize = MAX_WRITE_BYTES + 1; // 67108865
    let data: Vec<Val> = vec![Val::U8(0u8); oversize];
    let out = sut
        .call_host_fn_n(
            "fs",
            FS_WRITE_NS,
            "write",
            vec![Val::String("oversized.txt".into()), Val::List(data)],
            1, // FsWriteHandler guards results_len == 1 BEFORE the size check (host_fn.rs:801)
        )
        .await
        .expect("the handler returns Ok at the host level (a typed err-variant, not a host trap)");

    // PRIMARY oracle — the typed `invalid-path` err-variant carrying the EXACT over-cap length.
    // Real shape: Result(Err(Some(Box<Variant("invalid-path", Some(Box<String>))>))) — TWO Box
    // layers (host_fn.rs:135 `ok_err_variant` → error.rs:83-88 `fs_error_to_val`).
    let Val::Result(Err(Some(b))) = &out[0] else {
        panic!(
            "expected the typed err arm Result(Err(..)), got {:?}",
            out[0]
        );
    };
    let Val::Variant(case, Some(payload)) = b.as_ref() else {
        panic!("expected a Variant payload, got {:?}", b);
    };
    assert_eq!(
        case, "invalid-path",
        "the size reject lowers to the invalid-path fs-error"
    );
    let Val::String(msg) = payload.as_ref() else {
        panic!("expected a String payload, got {:?}", payload);
    };
    assert!(
        msg.contains("exceeds MAX_WRITE_BYTES"),
        "binds to the size-reject branch (not results_len / param-shape, which trap at the host \
         level); got: {msg}"
    );
    assert!(
        msg.contains(&oversize.to_string()),
        "carries the ACTUAL over-cap length {oversize} (a no-op handler could not fabricate it); \
         got: {msg}"
    );

    // NO MUTATION — all three criterion legs:
    // (1) SQLite (LIVE triple-sync index): no meta_index / content_index row for the rejected file.
    let agent = sut.agent_m004_id();
    let (meta_row, content_row) =
        sut.sqlite_file_indexed(&agent, "/agent", "oversized.txt", "/agent/oversized.txt");
    assert!(
        !meta_row && !content_row,
        "no SQLite row for the rejected write (meta={meta_row}, content={content_row})"
    );
    // (2) Events (RealBus): no fs.write / meta.updated persisted; the bus dropped nothing.
    assert_eq!(
        sut.db_event_count(Some("fs.write")),
        0,
        "no fs.write event on the rejected write"
    );
    assert_eq!(
        sut.db_event_count(Some("meta.updated")),
        0,
        "no meta.updated event on the rejected write"
    );
    sut.assert_no_dropped_events();
    // (3) Disk (corroborating — the reject precedes path resolution, so absence holds regardless of
    // territory mapping; NOT the load-bearing oracle).
    assert!(
        sut.read_workspace_file("oversized.txt").is_none(),
        "no file written for the rejected write"
    );
    assert!(
        sut.read_workspace_file(".meta.yaml").is_none(),
        "no .meta.yaml created for the rejected write"
    );
}

/// SYS-AC-235 discriminator (non-vacuity): a SMALL (under-cap) write through the SAME
/// `call_host_fn_n` primitive is NOT size-rejected — proving the `d.len()` bound is
/// input-size-CONDITIONAL, not a blanket reject of every direct-driven write. Whether the small
/// write succeeds or fails at territory resolution, its result is NEVER the "exceeds
/// MAX_WRITE_BYTES" err-variant. (The full accept path is independently proven end-to-end by the
/// passing SYS-AC-150: a real guest turn writes the file AND fans out fs.write + meta.updated.)
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_235_under_cap_write_not_size_rejected() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs])
        .with_sqlite_index()
        .events(EventSink::RealBus)
        .build(J01_SKELETON)
        .await;

    let small: Vec<Val> = vec![Val::U8(b'h'), Val::U8(b'i')];
    let out = sut
        .call_host_fn_n(
            "fs",
            FS_WRITE_NS,
            "write",
            vec![Val::String("under.txt".into()), Val::List(small)],
            1,
        )
        .await
        .expect("host-level Ok");

    // The size-reject branch did NOT fire — the result carries no "exceeds MAX_WRITE_BYTES" message
    // (it is ok, or a territory-dependent different err). Robust whole-value Debug check.
    let rendered = format!("{:?}", out);
    assert!(
        !rendered.contains("exceeds MAX_WRITE_BYTES"),
        "an under-cap write must NOT hit the size-reject branch; got: {rendered}"
    );
}

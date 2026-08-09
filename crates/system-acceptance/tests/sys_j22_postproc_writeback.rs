//! SYS-J-22 (SYS-AC-065 / 067 / 213 / 254) — components-backed PostProcessor on a
//! REAL wired turn via the default-off `.with_live_memory()` axis.
//!
//! Stage-C MAINLINE harvest pass-1. The axis installs the SAME components-backed
//! `PostProcessor` production wires (cli `build_live_post_processor`): a real
//! `LlmBatchExtractor` over the loopback gateway → on-disk `summary.yaml` /
//! `turn-index.yaml` writeback + durable `RusqliteSqliteIndex` upsert. A NON-generate
//! guest (`guest-rust-mem-skeleton`, which calls only `remember`/`recall`) isolates
//! the post-turn EXTRACTION call as the SOLE `/v1/chat/completions` POST, so the
//! loopback request count witnesses "exactly one batched extraction call".
//!
//! Witness-floor: every assertion binds to PRODUCT output (on-disk YAML, SQLite rows,
//! the loopback request count) on the real wired chain (MODULE-014→011→009→002→004→003).
//! Each row carries a discriminator: the axis-OFF (trace-only `PostProcessor::new()`)
//! build writes nothing / makes no extraction call.

use cap_fs::{DefaultAtomicWriter, MetaMaintainer, MetaSchemaLoader};
use cap_memory::{
    MemoryStore, RusqliteSqliteIndex, SqliteIndex, DEFAULT_MAX_ACTIVE_PER_AGENT,
    MECHANICAL_TURN_DIGEST,
};
use std::sync::Arc;
use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::{Cap, LlmMode, SystemUnderTest, AGENT_ID};

const MEM_SKELETON: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-mem-skeleton.core.wasm");

// A unique digest marker that can ONLY appear in turn-index.yaml if the REAL
// extraction result drove Step-7 writeback (a mechanical fallback uses
// `MECHANICAL_TURN_DIGEST`, never this marker).
const DIGEST_MARKER: &str = "stagec-extraction-digest-marker-067";
const TASK_SLUG: &str = "task-stagec-067"; // plain [a-z0-9-] — writer + reader agree
                                           // The knowledge content the EXTRACTION reconciles into memory — distinct from any
                                           // content the guest itself remembers, so a memory_index row carrying THIS marker
                                           // proves the extraction (not the guest's remember()) drove Step-8's memory sync.
const KNOWLEDGE_MARKER: &str = "stagec-knowledge-marker";

fn extraction_json(digest: &str) -> String {
    format!(
        r#"{{"digest":"{digest}","knowledge":[{{"content":"{KNOWLEDGE_MARKER}","tags":["t"],"kind":"fact"}}]}}"#
    )
}

/// SYS-AC-067: after a turn, `summary.yaml` (L4) + `turn-index.yaml` (L0/L2/L3) are
/// written under `<memory_dir>/tasks/{task}/` FROM the extraction result. Plus its
/// discriminator: the axis-OFF build (trace-only PostProcessor) writes neither file.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_067_summary_and_turn_index_written_from_extraction() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mem = dir.path().join(".agent/memory");

    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        // Non-generate guest → the post-turn extraction is the ONLY chat POST.
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            &extraction_json(DIGEST_MARKER),
            7,
            9,
        )]))
        .with_memory_dir(mem.clone())
        .with_live_memory()
        .build(MEM_SKELETON)
        .await;

    sut.inject_message_with_task("tester", TASK_SLUG, b"please-remember-this-turn")
        .await;
    sut.run_turn().await;

    let task_dir = mem.join("tasks").join(TASK_SLUG);
    let summary = task_dir.join("summary.yaml");
    let turn_index = task_dir.join("turn-index.yaml");
    assert!(
        summary.exists(),
        "summary.yaml must be written under tasks/{TASK_SLUG}/ by the live PostProcessor Step-7"
    );
    assert!(
        turn_index.exists(),
        "turn-index.yaml must be written under tasks/{TASK_SLUG}/ by the live PostProcessor Step-7"
    );

    let ti = std::fs::read_to_string(&turn_index).expect("read turn-index.yaml");
    assert!(
        ti.contains(DIGEST_MARKER),
        "turn-index.yaml must carry the REAL extraction digest (proves the extraction \
         result — not a mechanical fallback — drove Step-7); ti={ti}"
    );
    let s = std::fs::read_to_string(&summary).expect("read summary.yaml");
    assert!(s.contains("turns_total: 1"), "summary turns_total==1: {s}");

    // ── Discriminator: axis OFF → trace-only PostProcessor::new() → no files ──
    let dir2 = tempfile::tempdir().expect("tempdir2");
    let mem2 = dir2.path().join(".agent/memory");
    let sut_off = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            &extraction_json(DIGEST_MARKER),
            7,
            9,
        )]))
        .with_memory_dir(mem2.clone())
        // NO .with_live_memory() — the trace-only baseline.
        .build(MEM_SKELETON)
        .await;
    sut_off
        .inject_message_with_task("tester", TASK_SLUG, b"please-remember-this-turn")
        .await;
    sut_off.run_turn().await;
    assert!(
        !mem2
            .join("tasks")
            .join(TASK_SLUG)
            .join("summary.yaml")
            .exists(),
        "discriminator: with the axis OFF the trace-only PostProcessor writes NO summary.yaml"
    );
}

/// SYS-AC-065: the post-processor issues a SINGLE batched LLM extraction call whose
/// result drives the downstream writes. A non-generate guest makes the extraction the
/// SOLE chat POST → `llm_chat_request_count() == 1`. Discriminator: no turn → 0; and
/// axis-off → 0 (the trace-only PostProcessor makes no extraction call).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_065_single_batched_extraction_call_drives_writes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mem = dir.path().join(".agent/memory");
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            &extraction_json("digest-065"),
            7,
            9,
        )]))
        .with_memory_dir(mem.clone())
        .with_live_memory()
        .build(MEM_SKELETON)
        .await;
    assert_eq!(
        sut.llm_chat_request_count(),
        0,
        "no turn yet → no extraction call"
    );

    sut.inject_message_with_task("tester", "task-065", b"turn-payload")
        .await;
    sut.run_turn().await;

    assert_eq!(
        sut.llm_chat_request_count(),
        1,
        "exactly ONE batched extraction call post-turn (non-generate guest → the \
         extraction is the only /v1/chat/completions POST)"
    );
    // The single call's result drove Step-7: turn-index carries that extraction digest.
    let ti = std::fs::read_to_string(mem.join("tasks/task-065/turn-index.yaml"))
        .expect("turn-index.yaml written");
    assert!(
        ti.contains("digest-065"),
        "the single extraction call's RESULT drove the downstream writes; ti={ti}"
    );

    // Discriminator: axis OFF → trace-only → no extraction call at all.
    let dir2 = tempfile::tempdir().unwrap();
    let sut_off = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            &extraction_json("d"),
            7,
            9,
        )]))
        .with_memory_dir(dir2.path().join(".agent/memory"))
        .build(MEM_SKELETON)
        .await;
    sut_off
        .inject_message_with_task("tester", "task-065", b"turn-payload")
        .await;
    sut_off.run_turn().await;
    assert_eq!(
        sut_off.llm_chat_request_count(),
        0,
        "discriminator: axis-off trace-only PostProcessor makes NO extraction call"
    );
}

/// SYS-AC-254: in the same pass the SQLite turn_index / task_index / memory_index rows
/// are upserted from the one extraction call, DURABLY (RusqliteSqliteIndex survives a
/// SUT drop + reopen). Bound to the digest (the real extraction). Discriminator:
/// axis-off → no durable index file.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_254_sqlite_indices_upserted_from_extraction() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mem = dir.path().join(".agent/memory");
    {
        let sut = SystemUnderTest::builder()
            .caps(&[Cap::Memory, Cap::Llm])
            .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
                &extraction_json("digest-254"),
                7,
                9,
            )]))
            .with_memory_dir(mem.clone())
            .with_live_memory()
            .build(MEM_SKELETON)
            .await;
        sut.inject_message_with_task("tester", "task-254", b"turn-payload")
            .await;
        sut.run_turn().await;
    } // drop the SUT — the on-disk index must persist.

    // The durable index file must exist on disk — a silent degrade-to-in-memory
    // (RusqliteSqliteIndex::open Err → eprintln) would leave NO file, which we catch
    // here rather than letting an empty reopened index pass as green.
    assert!(
        mem.join("index.sqlite").exists(),
        "Step-8 must open a DURABLE on-disk RusqliteSqliteIndex (no silent in-memory degrade)"
    );
    // Reopen the durable on-disk index: the Step-8 rows are present + persistent.
    let idx = RusqliteSqliteIndex::open(mem.join("index.sqlite")).expect("reopen durable index");
    let turns = idx.list_turns_for_agent(AGENT_ID);
    assert_eq!(
        turns.len(),
        1,
        "Step-8 upserted exactly one turn_index row, durable across the SUT drop"
    );
    assert_eq!(
        turns[0].digest, "digest-254",
        "turn_index row digest is bound to the REAL extraction result (not fabricated)"
    );
    assert_eq!(
        idx.list_tasks_for_agent(AGENT_ID).len(),
        1,
        "Step-8 upserted a task_index row"
    );
    // memory_index leg — bind to the EXTRACTION's reconciled knowledge entry, NOT the
    // guest's own remember(). Step-8 `sync_memory_index` mirrors EVERY `store.list`
    // entry, and the mem-skeleton guest calls `remember()` during the turn, so a bare
    // `!is_empty()` check would pass from the guest alone (adversarial finding). Reopen
    // the durable store, find the entry the extraction reconciled (content == the
    // extraction's knowledge marker — distinct from the guest's payload), and assert
    // THAT id is present in the durable memory_index.
    let store = MemoryStore::open(&mem, DEFAULT_MAX_ACTIVE_PER_AGENT).expect("reopen store");
    let extraction_entry = store
        .list(AGENT_ID)
        .into_iter()
        .find(|e| e.content == KNOWLEDGE_MARKER)
        .expect("the extraction's knowledge entry must be reconciled into the store (Step 5)");
    let mem_rows = idx.list_memory_for_agent(AGENT_ID);
    assert!(
        mem_rows.iter().any(|r| r.memory_id == extraction_entry.id),
        "Step-8 must upsert a memory_index row for the EXTRACTION's reconciled knowledge \
         entry (id={}) — distinct from the guest's own remember()",
        extraction_entry.id
    );

    // Discriminator: axis OFF → trace-only → no durable index file opened/written.
    let dir2 = tempfile::tempdir().unwrap();
    let mem2 = dir2.path().join(".agent/memory");
    let sut_off = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            &extraction_json("d"),
            7,
            9,
        )]))
        .with_memory_dir(mem2.clone())
        .build(MEM_SKELETON)
        .await;
    sut_off
        .inject_message_with_task("tester", "task-254", b"turn-payload")
        .await;
    sut_off.run_turn().await;
    assert!(
        !mem2.join("index.sqlite").exists(),
        "discriminator: axis-off trace-only opens NO durable RusqliteSqliteIndex"
    );
}

/// SYS-AC-213: a FAILING extraction call degrades to the mechanical-digest fallback
/// (writes still happen, the turn is NOT hard-failed); a second turn within the
/// cooldown window SKIPS the LLM call entirely. Discriminator: a succeeding extractor
/// → no mechanical fallback (the REAL digest, not `MECHANICAL_TURN_DIGEST`).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_213_extraction_failure_mechanical_fallback_and_cooldown_skip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mem = dir.path().join(".agent/memory");
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        // The extraction gets a 200 with UNPARSEABLE output → the extractor's
        // try_parse_and_validate fails → BatchExtractorError::LlmFailure → mechanical
        // fallback. (A 200 means the gateway does NOT retry — unlike a 503/backoff —
        // so the extraction is exactly ONE HTTP POST, keeping the cooldown-skip signal
        // clean: turn-1 = 1 POST, turn-2 within cooldown = 0.)
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            "not-json-degrade-to-mechanical",
            7,
            9,
        )]))
        .with_memory_dir(mem.clone())
        .with_live_memory()
        .build(MEM_SKELETON)
        .await;

    // Two turns on one persistent run loop (cooldown lives on the per-SUT PostProcessor,
    // not the guest store, so it survives the serve_n_turns init).
    sut.inject_message_with_task("tester", "task-213", b"turn-one")
        .await;
    sut.inject_message_with_task("tester", "task-213", b"turn-two")
        .await;
    sut.run_turns(2).await;

    // Turn-1 attempted the extraction once (then failed → mechanical fallback still wrote).
    let ti = std::fs::read_to_string(mem.join("tasks/task-213/turn-index.yaml"))
        .expect("turn-index written despite the failed extraction");
    assert!(
        ti.contains(MECHANICAL_TURN_DIGEST),
        "failed extraction → mechanical-digest fallback drove the write (turn NOT hard-failed); ti={ti}"
    );
    // The cooldown skipped turn-2's LLM call entirely → exactly ONE chat POST total.
    assert_eq!(
        sut.llm_chat_request_count(),
        1,
        "turn-1 attempted the extraction once; turn-2 within the cooldown window SKIPS \
         the LLM call entirely (total chat POSTs unchanged)"
    );

    // Discriminator: a SUCCEEDING extractor → real digest, no mechanical fallback.
    let dir2 = tempfile::tempdir().unwrap();
    let mem2 = dir2.path().join(".agent/memory");
    let sut_ok = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            &extraction_json("real-digest-213"),
            7,
            9,
        )]))
        .with_memory_dir(mem2.clone())
        .with_live_memory()
        .build(MEM_SKELETON)
        .await;
    sut_ok
        .inject_message_with_task("tester", "task-213", b"turn-one")
        .await;
    sut_ok.run_turn().await;
    let ti_ok = std::fs::read_to_string(mem2.join("tasks/task-213/turn-index.yaml"))
        .expect("turn-index for the succeeding extractor");
    assert!(
        ti_ok.contains("real-digest-213") && !ti_ok.contains(MECHANICAL_TURN_DIGEST),
        "discriminator: a succeeding extractor writes the REAL digest with NO mechanical \
         fallback; ti={ti_ok}"
    );
}

// ---------------------------------------------------------------------------
// SYS-AC-066 (Stage-C MAINLINE harvest pass-3) — the `.meta.yaml` writeback on the
// TEXT/LLM `DescriptionUpdate` path, via the default-off `.with_vlm_indexer()` axis.
// ---------------------------------------------------------------------------

/// An extraction reply listing one `(path, "x")` description item. The `description` value
/// is ignored by Step-3 (only `path` drives indexing); the schema only requires the key.
fn descriptions_extraction(digest: &str, path: &str) -> String {
    format!(r#"{{"digest":"{digest}","descriptions":[{{"path":"{path}","description":"x"}}]}}"#)
}

/// Read back `.meta.yaml` rooted at `ws` with a fresh default-schema MetaMaintainer
/// (mirror vlm_indexer.rs:757-765 — `ws` == `sut.workspace_root()`, the same root the
/// indexer canonicalizes under via the `/var`→`/private/var` symlink).
async fn read_meta_j22(ws: &std::path::Path) -> cap_fs::MetaFile {
    let loader = Arc::new(MetaSchemaLoader::new_with_default(
        ws.join(".meta-schema.yaml"),
    ));
    let m = MetaMaintainer::new(loader, Arc::new(DefaultAtomicWriter));
    m.load(ws)
        .await
        .expect("load .meta.yaml")
        .expect("meta exists")
}

/// SYS-AC-066: the text/LLM `DescriptionUpdate` is written back to the file's `.meta.yaml`
/// entry (the `.meta.yaml` half of the post-processing pipeline on the TEXT path). A text
/// file (`readme.md`) added in a turn routes via Step-3 → CONTRACT-081 `gateway.chat` → the
/// returned description is written back. Bound to a DISTINCT marker so an off-by-one loopback
/// script (replay-last on drain) fails LOUD (a missing POST#2 would replay the extraction
/// JSON → `description != TEXT_DESC`). Discriminator: indexer-absent → no `readme.md`
/// `.meta.yaml` entry. (No "exactly 1 chat POST" discriminator — the text path issues a 2nd
/// in-turn POST.)
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_066_text_description_written_to_meta_yaml() {
    const TEXT_DESC: &str = "harness-text-llm-desc-marker-066";
    let dir = tempfile::tempdir().expect("tempdir");
    let mem = dir.path().join(".agent/memory");
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![
            // POST#1: the post-turn extraction listing readme.md.
            ScriptedResponse::ok_chat(&descriptions_extraction("d-066", "readme.md"), 7, 9),
            // POST#2: Step-3's text-file `gateway.chat` description for readme.md.
            ScriptedResponse::ok_chat(TEXT_DESC, 7, 9),
        ]))
        .with_memory_dir(mem.clone())
        .with_live_memory()
        .with_vlm_indexer()
        .build(MEM_SKELETON)
        .await;
    std::fs::write(
        sut.workspace_root().join("readme.md"),
        b"# readme\nsome text content",
    )
    .expect("write md");

    sut.inject_message_with_task("tester", "task-066", b"go")
        .await;
    sut.run_turn().await;

    let mf = read_meta_j22(sut.workspace_root()).await;
    let entry = mf
        .entries
        .get("readme.md")
        .expect("readme.md .meta.yaml entry must be written by the text→LLM writeback");
    assert_eq!(
        entry.description, TEXT_DESC,
        "the text/LLM-generated description is written back to readme.md's .meta.yaml entry"
    );

    // ── Discriminator: indexer-absent → no writeback → no readme.md `.meta.yaml` entry. ──
    let dir2 = tempfile::tempdir().expect("tempdir2");
    let off = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![
            ScriptedResponse::ok_chat(&descriptions_extraction("d-066", "readme.md"), 7, 9),
            ScriptedResponse::ok_chat(TEXT_DESC, 7, 9),
        ]))
        .with_memory_dir(dir2.path().join(".agent/memory"))
        .with_live_memory()
        .build(MEM_SKELETON)
        .await;
    std::fs::write(
        off.workspace_root().join("readme.md"),
        b"# readme\nsome text content",
    )
    .expect("write md");
    off.inject_message_with_task("tester", "task-066", b"go")
        .await;
    off.run_turn().await;
    let off_ws = off.workspace_root().to_path_buf();
    if off_ws.join(".meta.yaml").exists() {
        let mf_off = read_meta_j22(&off_ws).await;
        assert!(
            !mf_off.entries.contains_key("readme.md"),
            "discriminator: indexer-absent → no readme.md entry in .meta.yaml"
        );
    }
}

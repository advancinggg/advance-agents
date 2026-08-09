//! SYS-J-24 (SYS-AC 071 / 072 / 073 / 217) — the VLM-into-PostProcessor bridge wired onto the
//! `.with_live_memory()` post-processor via the opt-in `.with_vlm_indexer()` axis
//! (Stage-C MAINLINE harvest pass-3).
//!
//! These drive the REAL wired system end-to-end: a non-generate guest
//! (`guest-rust-mem-skeleton`) runs a production turn; the components-backed PostProcessor
//! issues ONE batched extraction call over the loopback gateway, and — with the axis on —
//! Step-3 routes each extraction-listed changed file by MIME via the cli
//! `VlmDescriptionIndexer` (text → CONTRACT-081 `gateway.chat`, image/pdf → CONTRACT-082
//! `HarnessVlm::extract_description`, binary/unknown → no-index), writes the description
//! back to `.meta.yaml`, and stores a `FileRef`-sourced recall-able entry. Witness-floor:
//! every assertion binds to PRODUCT output — the recorded VLM `FileContent` variant, the
//! on-disk `.meta.yaml` description, and `MemoryStore::recall` over the FileRef entry — on
//! the real wired chain (MODULE-014→011→009→002→004). Each row carries an
//! indexer-absent discriminator.
//!
//! Injection surface: the loopback EXTRACTION reply's `descriptions:[{path,description}]`
//! lists the changed files to index (Step-3 uses only `d.path`; the reply's `description`
//! is ignored) + the real file(s) written into `sut.workspace_root()` BEFORE `run_turn`
//! (Step-3 reads at turn-time via the indexer's `confine`). The stored/written-back
//! description is the INDEXER's output (the `HarnessVlm` canned string for images; the
//! `gateway.chat` reply for text), NOT the reply's `description` field.

use cap_fs::{DefaultAtomicWriter, MetaMaintainer, MetaSchemaLoader};
use cap_memory::{MemorySource, MemoryStore, DEFAULT_MAX_ACTIVE_PER_AGENT};
use std::sync::Arc;
use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::{Cap, LlmMode, SystemUnderTest, AGENT_ID};

const MEM_SKELETON: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-mem-skeleton.core.wasm");

// A real on-disk PNG (PNG magic + payload). MIME routing is extension-only (`sniff_mime`),
// and the harness VLM ignores the bytes, so a faithful-enough fake suffices.
const PNG_BYTES: &[u8] = b"\x89PNG\r\n\x1a\nharness-fake-png-payload-071";
// A fake PDF (PDF magic). `.pdf` → `application/pdf` → VLM `Pdf` variant (extension-only sniff).
const PDF_BYTES: &[u8] = b"%PDF-1.4\nharness-fake-pdf-payload-217";

// The harness VLM's canned description (== the lib-private `HARNESS_VLM_DESC`). The 071/072
// witnesses bind to THIS exact string, so a drift in the lib const would fail them loudly.
const HARNESS_VLM_DESC: &str = "harness-vlm-described non-text file (canned-071)";

/// An extraction reply listing `(path, "x")` description items. The `description` value is
/// ignored by Step-3 (only `path` drives indexing) but the schema requires the key present.
fn extraction_with_paths(digest: &str, paths: &[&str]) -> String {
    let items: Vec<String> = paths
        .iter()
        .map(|p| format!(r#"{{"path":"{p}","description":"x"}}"#))
        .collect();
    format!(
        r#"{{"digest":"{digest}","descriptions":[{}]}}"#,
        items.join(",")
    )
}

/// Read back the `.meta.yaml` rooted at `ws` with a FRESH `MetaMaintainer` (the indexer
/// already flushed it to disk). Mirrors `vlm_indexer.rs:757-765` — same default-schema
/// loader. `ws` is `sut.workspace_root()` (the same root the indexer canonicalizes under
/// via the `/var`→`/private/var` symlink, so it lands on the same physical `.meta.yaml`).
async fn read_meta(ws: &std::path::Path) -> cap_fs::MetaFile {
    let loader = Arc::new(MetaSchemaLoader::new_with_default(
        ws.join(".meta-schema.yaml"),
    ));
    let m = MetaMaintainer::new(loader, Arc::new(DefaultAtomicWriter));
    m.load(ws)
        .await
        .expect("load .meta.yaml")
        .expect("meta exists")
}

/// SYS-AC-071: with the VLM configured, adding a non-text file (image) in a turn invokes the
/// VlmExtractor (CONTRACT-082) to generate a description, which is stored as a recall-able
/// FileRef-sourced entry. Discriminator: the indexer-absent build makes no VLM call.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_071_image_invokes_vlm_and_is_recallable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mem = dir.path().join(".agent/memory");
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        // Non-generate guest → the post-turn extraction is the only chat POST (no Step-3
        // text leg here — the single file is an image → in-process VLM, not gateway.chat).
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            &extraction_with_paths("d-071", &["diagram.png"]),
            7,
            9,
        )]))
        .with_memory_dir(mem.clone())
        .with_live_memory()
        .with_vlm_indexer()
        .build(MEM_SKELETON)
        .await;
    // Write the real non-text file into the workspace BEFORE the turn (Step-3 reads it).
    std::fs::write(sut.workspace_root().join("diagram.png"), PNG_BYTES).expect("write png");

    sut.inject_message_with_task("tester", "task-071", b"go")
        .await;
    sut.run_turn().await;

    // (a) The VlmExtractor was invoked exactly once, with the Image variant (image leg).
    assert_eq!(
        sut.vlm_calls(),
        vec!["Image".to_string()],
        "the VlmExtractor must be invoked exactly once with the Image variant for diagram.png"
    );

    // (b) The generated description is stored as a FileRef-sourced, recall-able entry.
    let store =
        MemoryStore::open(sut.memory_dir(), DEFAULT_MAX_ACTIVE_PER_AGENT).expect("reopen store");
    let hits = store.recall(AGENT_ID, HARNESS_VLM_DESC, 0);
    assert_eq!(
        hits.len(),
        1,
        "exactly one recall hit for the VLM-generated description; got {}",
        hits.len()
    );
    assert_eq!(
        hits[0].content, HARNESS_VLM_DESC,
        "the stored content IS the VLM-generated description (not the reply's description field)"
    );
    assert!(
        hits[0].sources.iter().any(|s| matches!(
            s,
            MemorySource::FileRef { vpath, .. } if vpath == "diagram.png"
        )),
        "the entry is FileRef-sourced with vpath diagram.png; sources={:?}",
        hits[0].sources
    );

    // ── Discriminator: `.with_live_memory()` WITHOUT `.with_vlm_indexer()` → Step-3 is the
    //    documented no-op → zero VLM calls, zero file-description recall. ──
    let dir2 = tempfile::tempdir().expect("tempdir2");
    let mem2 = dir2.path().join(".agent/memory");
    let off = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            &extraction_with_paths("d-071", &["diagram.png"]),
            7,
            9,
        )]))
        .with_memory_dir(mem2.clone())
        .with_live_memory()
        .build(MEM_SKELETON)
        .await;
    std::fs::write(off.workspace_root().join("diagram.png"), PNG_BYTES).expect("write png");
    off.inject_message_with_task("tester", "task-071", b"go")
        .await;
    off.run_turn().await;
    assert!(
        off.vlm_calls().is_empty(),
        "discriminator: indexer-absent → no VLM call; got {:?}",
        off.vlm_calls()
    );
    let store2 =
        MemoryStore::open(off.memory_dir(), DEFAULT_MAX_ACTIVE_PER_AGENT).expect("reopen store2");
    assert!(
        store2.recall(AGENT_ID, HARNESS_VLM_DESC, 0).is_empty(),
        "discriminator: indexer-absent → no file-description recall"
    );
}

/// SYS-AC-073: the VLM-generated description is recall-able via `MemoryStore::recall` over
/// the description CONTENT — a description-SUBSTRING query (not the full string) returns the
/// file's FileRef-sourced entry. This binds 073 to the real recall path (`MemoryStore` /
/// `knowledge.jsonl` content matching, `store.rs:1039` `contains`), NOT the status-only SQLite
/// `MemoryIndexRow` (which has no content column — the documented fake-green the /spec re-word
/// retired). Same `.with_vlm_indexer()` axis as 071/072; the indexer-absent build is the
/// discriminator.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_073_description_recallable_by_substring() {
    // A SUBSTRING of HARNESS_VLM_DESC ("harness-vlm-described non-text file (canned-071)").
    const DESC_SUBSTR: &str = "canned-071";
    let dir = tempfile::tempdir().expect("tempdir");
    let mem = dir.path().join(".agent/memory");
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            &extraction_with_paths("d-073", &["diagram.png"]),
            7,
            9,
        )]))
        .with_memory_dir(mem.clone())
        .with_live_memory()
        .with_vlm_indexer()
        .build(MEM_SKELETON)
        .await;
    std::fs::write(sut.workspace_root().join("diagram.png"), PNG_BYTES).expect("write png");
    sut.inject_message_with_task("tester", "task-073", b"go")
        .await;
    sut.run_turn().await;

    // Recall by a SUBSTRING of the description (recall is case-insensitive `contains` over
    // content) → exactly the FileRef-sourced entry for diagram.png.
    let store =
        MemoryStore::open(sut.memory_dir(), DEFAULT_MAX_ACTIVE_PER_AGENT).expect("reopen store");
    let hits = store.recall(AGENT_ID, DESC_SUBSTR, 0);
    assert_eq!(
        hits.len(),
        1,
        "exactly one recall hit for the description substring {DESC_SUBSTR:?}; got {}",
        hits.len()
    );
    assert_eq!(
        hits[0].content, HARNESS_VLM_DESC,
        "the recalled entry's content IS the full VLM-generated description"
    );
    assert!(
        hits[0].sources.iter().any(|s| matches!(
            s,
            MemorySource::FileRef { vpath, .. } if vpath == "diagram.png"
        )),
        "the recalled entry is FileRef-sourced with vpath diagram.png; sources={:?}",
        hits[0].sources
    );

    // ── Discriminator: `.with_live_memory()` WITHOUT `.with_vlm_indexer()` → Step-3 is the
    //    documented no-op → no file-description entry → the substring recall is empty. ──
    let dir2 = tempfile::tempdir().expect("tempdir2");
    let off = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            &extraction_with_paths("d-073", &["diagram.png"]),
            7,
            9,
        )]))
        .with_memory_dir(dir2.path().join(".agent/memory"))
        .with_live_memory()
        .build(MEM_SKELETON)
        .await;
    std::fs::write(off.workspace_root().join("diagram.png"), PNG_BYTES).expect("write png");
    off.inject_message_with_task("tester", "task-073", b"go")
        .await;
    off.run_turn().await;
    let store2 =
        MemoryStore::open(off.memory_dir(), DEFAULT_MAX_ACTIVE_PER_AGENT).expect("reopen store2");
    assert!(
        store2.recall(AGENT_ID, DESC_SUBSTR, 0).is_empty(),
        "discriminator: indexer-absent → no file-description recall for the substring"
    );
}

/// SYS-AC-072: the generated (image/VLM) description is written back to the file's
/// `.meta.yaml` entry via the cap-fs update-meta path. Discriminator: indexer-absent → no
/// `diagram.png` entry in `.meta.yaml`.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_072_image_description_written_to_meta_yaml() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mem = dir.path().join(".agent/memory");
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            &extraction_with_paths("d-072", &["diagram.png"]),
            7,
            9,
        )]))
        .with_memory_dir(mem.clone())
        .with_live_memory()
        .with_vlm_indexer()
        .build(MEM_SKELETON)
        .await;
    std::fs::write(sut.workspace_root().join("diagram.png"), PNG_BYTES).expect("write png");
    sut.inject_message_with_task("tester", "task-072", b"go")
        .await;
    sut.run_turn().await;

    // The VLM-generated description is written back to diagram.png's `.meta.yaml` entry.
    // (The indexer loads `<ws>/.meta-schema.yaml` (absent → DEFAULT schema); writeback still
    // succeeds — assert the DESCRIPTION, never a schema-specific field.)
    let mf = read_meta(sut.workspace_root()).await;
    let entry = mf
        .entries
        .get("diagram.png")
        .expect("diagram.png .meta.yaml entry must be written by the VLM writeback");
    assert_eq!(
        entry.description, HARNESS_VLM_DESC,
        "the VLM-generated description is written back to the file's .meta.yaml entry"
    );

    // ── Discriminator: indexer-absent → no writeback → no diagram.png entry. ──
    let dir2 = tempfile::tempdir().expect("tempdir2");
    let off = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            &extraction_with_paths("d-072", &["diagram.png"]),
            7,
            9,
        )]))
        .with_memory_dir(dir2.path().join(".agent/memory"))
        .with_live_memory()
        .build(MEM_SKELETON)
        .await;
    std::fs::write(off.workspace_root().join("diagram.png"), PNG_BYTES).expect("write png");
    off.inject_message_with_task("tester", "task-072", b"go")
        .await;
    off.run_turn().await;
    let off_ws = off.workspace_root().to_path_buf();
    if off_ws.join(".meta.yaml").exists() {
        let mf_off = read_meta(&off_ws).await;
        assert!(
            !mf_off.entries.contains_key("diagram.png"),
            "discriminator: indexer-absent → no diagram.png entry in .meta.yaml"
        );
    }
}

/// SYS-AC-217: the VlmExtractor is invoked ONLY for non-text files — a text file (.md) is
/// routed to the LLM generate path (gateway.chat), and a binary/unknown file (.bin) gets no
/// generated description and is NOT indexed — proving file-type routing discrimination, not
/// blanket VLM dispatch.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_217_vlm_invoked_only_for_non_text_files() {
    const TEXT_DESC: &str = "harness-text-llm-desc-marker-217";
    let dir = tempfile::tempdir().expect("tempdir");
    let mem = dir.path().join(".agent/memory");
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![
            // POST#1: the post-turn extraction listing the FOUR changed files (in this order).
            ScriptedResponse::ok_chat(
                &extraction_with_paths(
                    "d-217",
                    &["readme.md", "diagram.png", "report.pdf", "data.bin"],
                ),
                7,
                9,
            ),
            // POST#2: Step-3's text-file `gateway.chat` description for readme.md. A DISTINCT
            // marker so an off-by-one script (loopback replay-last on drain) fails LOUD: a
            // missing POST#2 would replay the extraction JSON here → `description` != TEXT_DESC.
            ScriptedResponse::ok_chat(TEXT_DESC, 7, 9),
        ]))
        .with_memory_dir(mem.clone())
        .with_live_memory()
        .with_vlm_indexer()
        .build(MEM_SKELETON)
        .await;
    std::fs::write(
        sut.workspace_root().join("readme.md"),
        b"# readme\nhello world",
    )
    .expect("write md");
    std::fs::write(sut.workspace_root().join("diagram.png"), PNG_BYTES).expect("write png");
    std::fs::write(sut.workspace_root().join("report.pdf"), PDF_BYTES).expect("write pdf");
    std::fs::write(
        sut.workspace_root().join("data.bin"),
        b"\x00\x01\x02\x03\xffbinary",
    )
    .expect("write bin");

    sut.inject_message_with_task("tester", "task-217", b"go")
        .await;
    sut.run_turn().await;

    // Load-bearing routing evidence (a): the VLM fired for the NON-TEXT files ONLY — exactly
    // `Image` (diagram.png) then `Pdf` (report.pdf), in descriptions order — and NOT for
    // readme.md (→ gateway.chat) NOR data.bin (→ octet-stream no-index). Covers 4 of the 5
    // MIME classes (audio/video legs are deferred per the SYS-AC-217 criterion).
    assert_eq!(
        sut.vlm_calls(),
        vec!["Image".to_string(), "Pdf".to_string()],
        "the VLM must be invoked for the image + pdf ONLY (Image, Pdf), not for .md/.bin"
    );

    let mf = read_meta(sut.workspace_root()).await;
    // (b): the .md text leg routed to the LLM (gateway.chat) → its description written back.
    let md = mf
        .entries
        .get("readme.md")
        .expect("readme.md .meta.yaml entry (the text→LLM leg wrote it back)");
    assert_eq!(
        md.description, TEXT_DESC,
        "readme.md description is the gateway.chat reply (text→LLM routing), not the VLM string"
    );
    // (c): the binary leg is NOT indexed → no data.bin `.meta.yaml` entry.
    assert!(
        !mf.entries.contains_key("data.bin"),
        "data.bin (octet-stream) must NOT be indexed (no .meta.yaml entry); entries={:?}",
        mf.entries.keys().collect::<Vec<_>>()
    );

    // Supplementary corroboration (recall matches content/tags, not vpath — so this is NOT
    // the load-bearing no-index proof; the `.meta.yaml`-absent + `vlm_calls()` checks carry
    // 217): no recall-able description mentions data.bin, and the .md text desc IS recall-able.
    let store =
        MemoryStore::open(sut.memory_dir(), DEFAULT_MAX_ACTIVE_PER_AGENT).expect("reopen store");
    assert!(
        store.recall(AGENT_ID, "data.bin", 0).is_empty(),
        "supplementary: no recall-able description mentions data.bin"
    );
    let md_hits = store.recall(AGENT_ID, TEXT_DESC, 0);
    assert_eq!(
        md_hits.len(),
        1,
        "the readme.md text description landed as a recall-able FileRef entry; got {}",
        md_hits.len()
    );
}

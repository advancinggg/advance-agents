//! SYS-J-03 dense+sparse dual-path recall witness (SYS-AC-009).
//!
//! Wave-20 Lane `search`. Drives a real turn whose assembled prompt's
//! `# Recalled Context` is produced by MODULE-004's dense+sparse
//! `R2d2UnifiedSearchImpl` (dense `vec_distance_cosine` + sparse `content_fts
//! MATCH` BM25, merged), bridged into MODULE-010's assembler `UnifiedSearchPort`
//! by the cli `R2d2UnifiedSearchAdapter` (`build_dual_recall_unified_search`),
//! opted into by the default-off `.with_dual_recall_corpus()` SUT axis.
//!
//! SYS-AC-009: "The assembled prompt includes recall results sourced from both
//! dense and sparse paths over files and memory (CONTRACT-031/032)." Witnessed on
//! the FULL real chain (`run_agent` → `run_turn_once` → real
//! `PublishingContextAssembler`/`ContextAssemblerImpl` → real `unified_search`
//! coordinator → REAL `R2d2UnifiedSearchAdapter` → REAL `R2d2UnifiedSearchImpl`
//! over a REAL in-memory SQLite index [migrations + FTS5 + sqlite-vec] → real
//! `format_recall_section` Tier-3 → guest `agent-llm/generate` → harness loopback,
//! the ONLY double) — only the cap-llm EMBED seam (CONTRACT-081) is a fixture
//! ([`FixtureEmbedding`], the standard recall-witness stub), with CONTROLLED
//! geometry so a doc can be made provably dense-EXCLUDED while still FTS-matchable.
//!
//! The load-bearing discriminator holds the corpus CONSTANT across two turns and
//! varies ONLY the query:
//!   - `dense.md`  (no `SPARSEMARK` → `e0`, aligned with every query → dense sim 1.0)
//!     = the DENSE-leg control. In turn 1 it surfaces via cosine ONLY (it FTS-misses the
//!     "zubernockle" keyword query) — that is the dense-leg proof; in turn 2 its own
//!     tokens (quokka/platypus) also FTS-match, which is irrelevant: the load-bearing
//!     discriminator rides on `sparse.md`, not on `dense.md`.
//!   - `sparse.md` (has `SPARSEMARK` → `e_anti`, cosine −1 vs every query → dense
//!     sim 0.0 < threshold 0.3 → dense EXCLUDES it; has the keyword "zubernockle")
//!     = SPARSE-ONLY (surfaces ONLY via `content_fts MATCH`).
//!   - one memory entry (no `SPARSEMARK` → `e0`) = DENSE memory hit (memory has no
//!     `memory_fts` table by engine design → "sparse over memory" is N/A;
//!     SYS-AC-009 is witnessed as dense+sparse over files, dense over memory).
//! Turn 1 (keyword query): BOTH `dense.md` AND `sparse.md` appear → both legs.
//! Turn 2 (no-keyword query): `sparse.md` DISAPPEARS (dense-excluded + FTS-miss)
//! while `dense.md` remains → proves the FTS sparse leg is load-bearing.
//! A dense-only impl (`RankingUnifiedSearch`, which ignores query text) gives
//! identical results for both queries and so cannot reproduce this toggle.

use cap_memory::{MemoryEntry, MemoryStatus, MemoryType};
use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::{Cap, LlmMode, SystemUnderTest, AGENT_ID};

/// The committed reference guest: `handle-message` reads `msg.payload` as the prompt
/// and calls `agent-llm/generate`, returning the reply text as its single action.
const HELLO_LLM_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-hello-llm.core.wasm");

const DENSE_VPATH: &str = "dense.md";
const SPARSE_VPATH: &str = "sparse.md";
const MEM_ID: &str = "mem-009";

const REPLY_1: &str = "reply-one-coherent-dual-recall";
const REPLY_2: &str = "reply-two-coherent-dual-recall";

// Query 1 carries ONLY `sparse.md`'s keywords (zubernockle/widget → FTS match for
// sparse.md, NOT dense.md). Query 2 carries ONLY `dense.md`'s keywords (quokka/platypus
// → FTS match for dense.md, NOT sparse.md). The two files share NO keyword, and neither
// query shares a keyword with the OTHER file — so the no-keyword query cannot leak
// sparse.md via FTS. Neither query contains `SPARSEMARK`, so both embed to `e0`.
const KEYWORD_QUERY: &[u8] = b"zubernockle widget";
const NOKEYWORD_QUERY: &[u8] = b"quokka platypus";

fn fact(id: &str, content: &str) -> MemoryEntry {
    MemoryEntry {
        id: id.into(),
        agent_id: AGENT_ID.into(), // colon id → seeded under (and recalled by) the assemble id
        entry_type: MemoryType::Fact,
        content: content.into(),
        tags: vec![],
        created_at: "2026-01-01T00:00:00Z".into(),
        task_origin: None,
        is_active: true,
        superseded_by: None,
        status: MemoryStatus::Active,
        supersession_reason: None,
        cluster_id: None,
        sources: vec![],
    }
}

/// SYS-AC-009 — dual-path recall: a keyword-only SPARSE hit and a semantic-only
/// DENSE hit BOTH reach the assembled prompt, and the SPARSE hit is provably
/// FTS-gated (drops when its keyword leaves the query).
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_009_dual_path_dense_and_sparse_reach_prompt() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![
            ScriptedResponse::ok_chat(REPLY_1, 7, 9),
            ScriptedResponse::ok_chat(REPLY_2, 7, 9),
        ]))
        // memory (no SPARSEMARK → e0 → dense hit); id `mem-009` is the rendered marker.
        .with_seeded_knowledge(vec![fact(MEM_ID, "the deploy uses an rsync mirror")])
        // dense.md: e0 (aligned), no "zubernockle" → DENSE-only.
        .with_seeded_workspace_file(DENSE_VPATH, b"DENSEMARK quokka platypus")
        // sparse.md: e_anti (anti-correlated → dense-excluded), has "zubernockle" → SPARSE-only.
        .with_seeded_workspace_file(SPARSE_VPATH, b"SPARSEMARK zubernockle widget")
        .with_reply_capture()
        .with_dual_recall_corpus()
        .build(HELLO_LLM_CORE)
        .await;

    // Turn 1 — query CARRIES sparse.md's keyword "zubernockle".
    sut.inject_message("tester", KEYWORD_QUERY).await;
    sut.run_turn().await;

    // Turn 2 — same baked corpus, query WITHOUT "zubernockle".
    sut.inject_message("tester", NOKEYWORD_QUERY).await;
    sut.run_turn().await;

    let bodies = sut.llm_all_chat_request_bodies();
    assert_eq!(
        bodies.len(),
        2,
        "two turns each dial generate exactly once (got {})",
        bodies.len()
    );
    let keyword_body = &bodies[0];
    let nokeyword_body = &bodies[1];

    // ── Turn 1 (keyword query): BOTH legs present. ──
    assert!(
        keyword_body.contains("# Recalled Context"),
        "turn-1 assembled prompt must carry the recall section; body={keyword_body}"
    );
    assert!(
        keyword_body.contains("## Files"),
        "turn-1 recall must have a ## Files section; body={keyword_body}"
    );
    // DENSE leg: dense.md surfaces by cosine (e0), not by keyword (FTS miss for "zubernockle").
    assert!(
        keyword_body.contains(DENSE_VPATH),
        "turn-1: the DENSE-only file `{DENSE_VPATH}` must surface (dense leg); body={keyword_body}"
    );
    // SPARSE leg: sparse.md surfaces ONLY by FTS keyword match (e_anti is dense-excluded).
    assert!(
        keyword_body.contains(SPARSE_VPATH),
        "turn-1: the SPARSE-only file `{SPARSE_VPATH}` must surface (sparse FTS5 leg); body={keyword_body}"
    );
    // MEMORY (dense) over memory — honors "over files and memory".
    assert!(
        keyword_body.contains("## Memory") && keyword_body.contains(MEM_ID),
        "turn-1 recall must include the dense memory entry `{MEM_ID}`; body={keyword_body}"
    );

    // ── Turn 2 (no-keyword query): the SPARSE-only file DISAPPEARS, the DENSE file stays. ──
    // This is the load-bearing anti-fake-green discriminator: sparse.md's presence in turn 1
    // was caused by the FTS5 leg (its embedding is dense-excluded), so removing its keyword
    // from the query removes it from recall — a dense-only impl could never do this.
    assert!(
        nokeyword_body.contains(DENSE_VPATH),
        "turn-2: the DENSE file `{DENSE_VPATH}` must still surface under a different query (dense leg query-independent up to similarity); body={nokeyword_body}"
    );
    assert!(
        !nokeyword_body.contains(SPARSE_VPATH),
        "turn-2: the SPARSE-only file `{SPARSE_VPATH}` MUST be absent without its keyword \
         (dense-excluded by anti-correlation + FTS miss) — proves the sparse leg is load-bearing; body={nokeyword_body}"
    );

    // Both turns produced a coherent delivered reply through the real outbound seam.
    assert_eq!(
        sut.delivered_replies(),
        vec![REPLY_1.as_bytes().to_vec(), REPLY_2.as_bytes().to_vec()],
        "both turns deliver their coherent reply in order"
    );
}

/// Discriminator (anti-fake-green): with the axis OFF — same seeds, but no
/// `.with_dual_recall_corpus()` — the production default `real_unified_search`
/// feeds the assembler an EMPTY corpus + the 16-dim `StubEmbedding`, so
/// `format_recall_section` returns `None` and the assembled prompt has NO
/// `# Recalled Context` (and never mentions either seeded file). Proves the recall
/// section is CAUSED by the dual-path corpus, not fabricated by the witness.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_009_axis_off_yields_no_recall_section() {
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Memory, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            REPLY_1, 7, 9,
        )]))
        .with_seeded_knowledge(vec![fact(MEM_ID, "the deploy uses an rsync mirror")])
        .with_seeded_workspace_file(DENSE_VPATH, b"DENSEMARK quokka platypus")
        .with_seeded_workspace_file(SPARSE_VPATH, b"SPARSEMARK zubernockle widget")
        // NO .with_dual_recall_corpus() → empty corpus + StubEmbedding (DORMANT prod path).
        .build(HELLO_LLM_CORE)
        .await;

    sut.inject_message("tester", KEYWORD_QUERY).await;
    sut.run_turn().await;

    let bodies = sut.llm_all_chat_request_bodies();
    assert_eq!(bodies.len(), 1, "one turn dials generate once");
    assert!(
        !bodies[0].contains("# Recalled Context"),
        "axis OFF → empty corpus → NO recall section; body={}",
        bodies[0]
    );
    assert!(
        !bodies[0].contains(DENSE_VPATH) && !bodies[0].contains(SPARSE_VPATH),
        "neither seeded file may reach the prompt without the recall axis; body={}",
        bodies[0]
    );
}

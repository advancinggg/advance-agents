//! AC-20 — `inject_tier3_warning` round-trip + isolation + bounded-queue +
//! agent_id-validation tests (CONTRACT-090 invariants 3 + 4).

#[path = "common/mod.rs"]
mod common;

use advance_shared_types::context::ContextAssembler;
use common::*;

#[tokio::test]
async fn injected_warning_appears_in_next_assemble_tier3() {
    let asm = build_assembler_with_empty_inventories();
    asm.inject_tier3_warning("agent-1", "Repetition detected");

    let mut ctx = stub_ctx();
    ctx.agent_id = "agent-1".into();
    let result = asm.assemble(ctx).await.unwrap();

    let found = result
        .messages
        .iter()
        .any(|m| m.content.contains("Repetition detected"));
    assert!(
        found,
        "expected injected warning to appear; got messages: {:?}",
        result
            .messages
            .iter()
            .map(|m| &m.content)
            .collect::<Vec<_>>()
    );

    // Idempotent drain: a second assemble for the same agent must NOT
    // duplicate the warning.
    let mut ctx2 = stub_ctx();
    ctx2.agent_id = "agent-1".into();
    let result2 = asm.assemble(ctx2).await.unwrap();
    let count2 = result2
        .messages
        .iter()
        .filter(|m| m.content.contains("Repetition detected"))
        .count();
    assert_eq!(
        count2, 0,
        "warning must not duplicate on second assemble; got count: {count2}"
    );
}

#[tokio::test]
async fn warnings_are_isolated_by_agent_id() {
    let asm = build_assembler_with_empty_inventories();
    asm.inject_tier3_warning("agent-1", "Warning A");
    asm.inject_tier3_warning("agent-2", "Warning B");

    let mut ctx = stub_ctx();
    ctx.agent_id = "agent-2".into();
    let r = asm.assemble(ctx).await.unwrap();
    let dump = r
        .messages
        .iter()
        .map(|m| m.content.as_str())
        .collect::<Vec<_>>()
        .join("|");
    assert!(dump.contains("Warning B"), "agent-2 should see B: {dump}");
    assert!(
        !dump.contains("Warning A"),
        "agent-2 should NOT see A: {dump}"
    );
}

#[tokio::test]
async fn queue_bounded_at_max_len_drops_oldest() {
    let asm = build_assembler_with_empty_inventories();
    for i in 0..2000_u32 {
        asm.inject_tier3_warning("agent-1", &format!("msg-{i:04}"));
    }
    let mut ctx = stub_ctx();
    ctx.agent_id = "agent-1".into();
    let r = asm.assemble(ctx).await.unwrap();

    // Each warning is delivered as its own system message; strip the `msg-`
    // prefix to recover the index, in order of appearance in Tier 3.
    let preserved: Vec<String> = r
        .messages
        .iter()
        .filter_map(|m| m.content.strip_prefix("msg-").map(str::to_string))
        .collect();
    assert_eq!(
        preserved.len(),
        1024,
        "queue must cap at MAX_QUEUE_LEN=1024; got {}",
        preserved.len()
    );
    // FIFO drop-oldest semantics: the surviving entries are the last 1024
    // pushed — indices 0976..1999.
    assert_eq!(preserved.first().map(String::as_str), Some("0976"));
    assert_eq!(preserved.last().map(String::as_str), Some("1999"));
}

#[tokio::test]
async fn warning_appears_before_prompt_in_tier3() {
    // CONTRACT-090 / MODULE-010 §3.8 Slice A: the WarnThenTerminate warning
    // must surface to the LLM with precedence over the next user message —
    // assemble() emits Tier 3 as turn_buffer → warnings → prompt.
    let asm = build_assembler_with_empty_inventories();
    asm.inject_tier3_warning("agent-1", "WARN");

    let mut ctx = stub_ctx();
    ctx.agent_id = "agent-1".into();
    ctx.prompt = "user says hi".into();
    // Seed a turn_buffer entry to verify the full ordering: turn → warn → prompt.
    ctx.turn_buffer
        .push(advance_shared_types::context::LlmMessage {
            role: "assistant".into(),
            content: "PRIOR_TURN".into(),
        });

    let r = asm.assemble(ctx).await.unwrap();

    // Find positions of the three Tier-3 markers in the assembled output.
    let pos_turn = r
        .messages
        .iter()
        .position(|m| m.content == "PRIOR_TURN")
        .expect("PRIOR_TURN missing");
    let pos_warn = r
        .messages
        .iter()
        .position(|m| m.content == "WARN")
        .expect("WARN missing");
    let pos_prompt = r
        .messages
        .iter()
        .position(|m| m.content == "user says hi")
        .expect("user prompt missing");
    assert!(
        pos_turn < pos_warn,
        "turn must precede warn; got {pos_turn} vs {pos_warn}"
    );
    assert!(
        pos_warn < pos_prompt,
        "warn must precede prompt; got {pos_warn} vs {pos_prompt}"
    );
}

#[tokio::test]
async fn outer_keyspace_bounded_at_max_agent_keyspace_via_lru_eviction() {
    // CONTRACT-090 invariant 3 outer bound: when the LRU is at
    // MAX_AGENT_KEYSPACE=4096 distinct agent_ids, pushing a NEW agent_id
    // evicts the LEAST-RECENTLY-TOUCHED entry — preserving availability for
    // the most-recently-active agent set (fixes the saturation-DoS gap
    // surfaced in AUDIT round 8).
    let asm = build_assembler_with_empty_inventories();

    // Push 5000 distinct valid agent_ids — exceeds the 4096 cap.
    // LRU semantics: the EARLIEST-pushed 904 (5000 - 4096) get evicted.
    for i in 0..5000_u32 {
        asm.inject_tier3_warning(&format!("agent-{i:05}"), "flood");
    }

    // The earliest pushed (`agent-00000`) was the FIRST to be touched, so
    // it should have been evicted long before the flood ended.
    let mut ctx = stub_ctx();
    ctx.agent_id = "agent-00000".into();
    let r = asm.assemble(ctx).await.unwrap();
    let evicted_surfaced = r.messages.iter().any(|m| m.content == "flood");
    assert!(
        !evicted_surfaced,
        "agent-00000 should have been evicted by LRU during the flood"
    );

    // The MOST recently pushed before the next test (`agent-04999`) must
    // still have its warning available — LRU keeps fresh entries.
    let mut ctx2 = stub_ctx();
    ctx2.agent_id = "agent-04999".into();
    let r2 = asm.assemble(ctx2).await.unwrap();
    let fresh_surfaced = r2.messages.iter().any(|m| m.content == "flood");
    assert!(
        fresh_surfaced,
        "agent-04999 (most recent) must survive LRU eviction"
    );

    // A brand-new agent_id pushed AFTER the flood succeeds — its insertion
    // evicts the now-LRU entry. This is the availability-preserving fix:
    // a flood no longer permanently locks the keyspace.
    asm.inject_tier3_warning("agent-postflood", "fresh signal");
    let mut ctx3 = stub_ctx();
    ctx3.agent_id = "agent-postflood".into();
    let r3 = asm.assemble(ctx3).await.unwrap();
    let postflood_surfaced = r3.messages.iter().any(|m| m.content == "fresh signal");
    assert!(
        postflood_surfaced,
        "post-flood agent must succeed (LRU eviction preserves availability)"
    );
}

#[tokio::test]
async fn assemble_rejects_invalid_agent_id() {
    // CONTRACT-090 invariant 4 enforcement at the assemble() entry: an
    // invalid agent_id must NOT be propagated to the inventory readers.
    // The error payload must carry INPUT_VALIDATION_PREFIX so downstream
    // callers can pattern-match on the prefix to distinguish input
    // rejection from genuine M004 store outages (see MODULE-010 §3.6
    // Known Gaps row 5 + §3.8 for the rationale on why this is not its
    // own AssemblyError variant in Slice A).
    use advance_context_engine::INPUT_VALIDATION_PREFIX;
    use advance_shared_types::context::AssemblyError;

    let asm = build_assembler_with_empty_inventories();

    for bad in &[
        "",
        "ag\u{0001}id",
        &"x".repeat(200),
        "path/with/slash",
        "space inside",
        "../etc/passwd",
        "agent;injection",
    ] {
        let mut ctx = stub_ctx();
        ctx.agent_id = bad.to_string();
        let result = asm.assemble(ctx).await;
        match result {
            Err(AssemblyError::MemoryStoreFailure(msg)) => {
                // Lock the full wire format (not just the prefix) so future
                // regressions that drop the `:` separator or rewrite the
                // suffix would fail. Telemetry consumers may pattern-match
                // on either the prefix or the full payload; both are stable.
                assert_eq!(
                    msg, "INPUT_VALIDATION: invalid agent_id",
                    "wire format must be stable for {bad:?}; got {msg:?}"
                );
                assert!(
                    msg.starts_with(INPUT_VALIDATION_PREFIX),
                    "prefix discriminator must be present"
                );
            }
            other => panic!("expected MemoryStoreFailure for {bad:?}; got {other:?}"),
        }
    }

    // Valid REQ-069 form returns Ok.
    let mut ctx = stub_ctx();
    ctx.agent_id = "auto:agent-foo".into();
    asm.assemble(ctx)
        .await
        .expect("valid agent_id should succeed");
}

#[tokio::test]
async fn oversized_warning_message_is_truncated_at_char_boundary() {
    // CONTRACT-090 invariant 3 defense-in-depth: per-message size cap at
    // MAX_WARNING_MSG_LEN=4096 bytes. Truncation (not rejection) preserves
    // the load-bearing repetition signal even when the body is degraded.
    let asm = build_assembler_with_empty_inventories();

    // 5 KiB payload — well over the 4 KiB cap.
    let huge: String = "a".repeat(5000);
    asm.inject_tier3_warning("agent-1", &huge);

    let mut ctx = stub_ctx();
    ctx.agent_id = "agent-1".into();
    let r = asm.assemble(ctx).await.unwrap();
    let warning = r
        .messages
        .iter()
        .find(|m| m.content.starts_with("aaaa"))
        .unwrap_or_else(|| panic!("warning not found in messages"));
    // Truncated to <= MAX_WARNING_MSG_LEN bytes.
    assert!(
        warning.content.len() <= 4096,
        "expected truncation to <=4096 bytes; got {} bytes",
        warning.content.len()
    );
    // For ASCII content the truncation is exact (each `a` is 1 byte).
    assert_eq!(warning.content.len(), 4096);

    // UTF-8 multi-byte safety: pad with a 4-byte char so naïve byte slicing
    // at MAX_WARNING_MSG_LEN would split it. Truncation must back off to a
    // char boundary.
    let mut multi: String = "x".repeat(4093);
    multi.push('𝛼'); // U+1D6FC — 4 UTF-8 bytes (4093 + 4 = 4097 > 4096)
    asm.inject_tier3_warning("agent-2", &multi);
    let mut ctx2 = stub_ctx();
    ctx2.agent_id = "agent-2".into();
    let r2 = asm.assemble(ctx2).await.unwrap();
    let w2 = r2
        .messages
        .iter()
        .find(|m| m.content.starts_with("xxxx"))
        .unwrap();
    // Truncation must NOT split the 4-byte char. So the surviving prefix is
    // the 4093 `x`s WITHOUT the multi-byte char (since 4093 + 4 > 4096 and
    // backing off lands at position 4093).
    assert_eq!(w2.content.len(), 4093);
    assert!(!w2.content.contains('𝛼'));
    // Result is still valid UTF-8 (would panic on String construction otherwise).
}

#[tokio::test]
async fn invalid_agent_id_silently_rejected() {
    let asm = build_assembler_with_empty_inventories();

    // Invalid by the M008 `validate_task_id` whitelist:
    asm.inject_tier3_warning("", "empty drops");
    asm.inject_tier3_warning("ag\u{0001}id", "ctrl char drops");
    asm.inject_tier3_warning(&"x".repeat(200), "over-128 drops");
    asm.inject_tier3_warning("path/with/slash", "slash drops");
    asm.inject_tier3_warning("space inside", "space drops");
    asm.inject_tier3_warning("../etc/passwd", "traversal drops");
    asm.inject_tier3_warning("agent;injection", "semicolon drops");

    // Valid REQ-069 patterns:
    asm.inject_tier3_warning("auto:agent-foo", "auto namespace OK");
    asm.inject_tier3_warning("user:alice.smith", "tenant prefix OK");

    let mut ctx = stub_ctx();
    ctx.agent_id = "auto:agent-foo".into();
    let r = asm.assemble(ctx).await.unwrap();
    let dump = r
        .messages
        .iter()
        .map(|m| m.content.as_str())
        .collect::<Vec<_>>()
        .join("|");

    for forbidden in &[
        "empty drops",
        "ctrl char drops",
        "over-128 drops",
        "slash drops",
        "space drops",
        "traversal drops",
        "semicolon drops",
    ] {
        assert!(
            !dump.contains(forbidden),
            "rejected-id payload leaked: {forbidden}; dump: {dump}"
        );
    }
    assert!(
        dump.contains("auto namespace OK"),
        "valid auto: id should be accepted; dump: {dump}"
    );
}

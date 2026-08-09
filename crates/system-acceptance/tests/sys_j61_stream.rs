//! SYS-J-61 — `stream` → `poll-stream` ordered deltas until a `done` chunk, with a
//! single `llm.response` (token/cost) emitted only at completion and the run budget
//! checked once before the stream starts.
//! S4: migrated to gated text/event-stream SSE mode for live path (JSON default still
//! available for back-compat; the scripted now exercises real SSE for the live consumer).
//! Chain: MODULE-009 cap-llm → MODULE-008 run-manager → MODULE-019 observability.
//!
//! Witnessed since the small-witness slice (2026-06-11) through the REAL registered
//! `agent-llm/{stream, poll-stream}` host-fn handlers (the cap-llm-gaps 2026-06-04
//! product — `StreamRegistry` handle table + buffer-then-replay lifecycle) over the
//! REAL cap-llm gateway + cap-http chain, against the SUT's loopback backend. The
//! drive surface is `SystemUnderTest::call_host_fn_for_run` (run_id-carrying
//! `HostCallContext`, the SAME field production fills via
//! `ComponentCtx::to_host_call_context`); the asserted properties — handle
//! lifecycle, delta ordering, budget preflight, deferred `llm.response` — all live
//! BELOW the handler boundary (gateway/StreamRegistry internals), within the
//! `call_host_fn` witness-fidelity caveat. The previous ledger deferral reasons
//! ("single-chunk stub / poll-stream unimplemented") were stale — the missing piece
//! was only this harness drive surface.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use advance_shared_types::capability::BudgetDecision;
use advance_shared_types::traits::RunBudget;
use system_acceptance::llm_loopback::ScriptedResponse;
use system_acceptance::{Cap, LlmMode, SystemUnderTest};
use wasmtime::component::Val;

const CORE_BYTES: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-j01-skeleton.core.wasm");
const LLM_NS: &str = "advance:runtime/agent-llm@0.1.0";
const RUN_ID: &str = "rid-j61";

/// A counting RunBudget wrapper: the CONTRACT-073 trait IS the observation seam —
/// every preflight goes through `check`. Always allows (the budget-deny leg is
/// witnessed elsewhere, e.g. sys_budget_session_2turn); here we count check calls
/// to assert "checked ONCE before the stream starts".
#[derive(Default)]
struct CountingBudget {
    checks: AtomicUsize,
}

impl RunBudget for CountingBudget {
    fn check(&self, _run_id: &str, _tokens: u64, _cost: f64) -> BudgetDecision {
        self.checks.fetch_add(1, Ordering::SeqCst);
        BudgetDecision::Allow
    }
    fn commit(&self, _run_id: &str, _tokens: u64, _cost: f64) {}
}

/// The WIT `llm-request` record arg for `stream` (prompt-only — no schema/params).
fn stream_request(prompt: &str) -> Val {
    Val::Record(vec![
        ("prompt".into(), Val::String(prompt.into())),
        ("output-schema".into(), Val::Option(None)),
        ("params".into(), Val::Option(None)),
    ])
}

/// Decode `result<stream-handle, llm-error>` → the u64 handle.
fn decode_handle(out: &[Val]) -> u64 {
    assert_eq!(out.len(), 1);
    match &out[0] {
        Val::Result(Ok(Some(boxed))) => match boxed.as_ref() {
            Val::U64(h) => *h,
            other => panic!("expected stream-handle u64, got {other:?}"),
        },
        other => panic!("expected Ok(stream-handle), got {other:?}"),
    }
}

/// Decode one `result<stream-chunk, llm-error>` poll outcome.
/// Returns (delta, done, response-record-fields-if-done).
fn decode_chunk(out: &[Val]) -> (Option<String>, bool, Option<Vec<(String, Val)>>) {
    assert_eq!(out.len(), 1);
    let chunk = match &out[0] {
        Val::Result(Ok(Some(boxed))) => boxed.as_ref(),
        other => panic!("expected Ok(stream-chunk), got {other:?}"),
    };
    let fields = match chunk {
        Val::Record(fields) => fields,
        other => panic!("expected stream-chunk record, got {other:?}"),
    };
    let mut delta = None;
    let mut done = false;
    let mut response = None;
    for (name, val) in fields {
        match (name.as_str(), val) {
            ("delta", Val::Option(Some(b))) => {
                if let Val::String(s) = b.as_ref() {
                    delta = Some(s.clone());
                }
            }
            ("done", Val::Bool(d)) => done = *d,
            ("response", Val::Option(Some(b))) => {
                if let Val::Record(r) = b.as_ref() {
                    response = Some(r.clone());
                }
            }
            _ => {}
        }
    }
    (delta, done, response)
}

async fn stream_sut(reply_text: &str) -> (SystemUnderTest, Arc<CountingBudget>) {
    let budget = Arc::new(CountingBudget::default());
    let sut = SystemUnderTest::builder()
        .caps(&[Cap::Fs, Cap::Llm])
        .llm(LlmMode::LoopbackScripted(vec![ScriptedResponse::ok_chat(
            reply_text, 7, 9,
        )]))
        .budget(budget.clone())
        .build(CORE_BYTES)
        .await;
    (sut, budget)
}

/// SYS-AC-188 — `stream(messages, params)` returns a stream handle and successive
/// `poll-stream` calls return ordered content deltas terminated by a chunk with
/// `done==true`.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_188_poll_stream_returns_ordered_deltas() {
    let text = "alpha beta gamma delta";
    let (sut, _budget) = stream_sut(text).await;

    // stream() → handle, through the REAL registered stream handler (preflight +
    // real chain dial + chunk + insert into the REAL StreamRegistry).
    let out = sut
        .call_host_fn_for_run(
            RUN_ID,
            "llm",
            LLM_NS,
            "stream",
            vec![stream_request("go")],
            1,
        )
        .await
        .expect("stream() host fn ok");
    let handle = decode_handle(&out);

    // poll-stream until done: ordered deltas reconstruct the scripted text exactly.
    let mut deltas: Vec<String> = Vec::new();
    let mut done_response = None;
    for _ in 0..256 {
        let out = sut
            .call_host_fn_for_run(
                RUN_ID,
                "llm",
                LLM_NS,
                "poll-stream",
                vec![Val::U64(handle)],
                1,
            )
            .await
            .expect("poll-stream host fn ok");
        let (delta, done, response) = decode_chunk(&out);
        if done {
            assert!(delta.is_none(), "the terminal chunk carries no delta");
            done_response = response;
            break;
        }
        deltas.push(delta.expect("non-terminal chunk carries a delta"));
    }

    assert!(
        deltas.len() >= 2,
        "multi-word text yields multiple ordered deltas, got {deltas:?}"
    );
    assert_eq!(
        deltas.concat(),
        text,
        "ordered deltas reconstruct the response exactly"
    );
    let response = done_response.expect("done chunk carries the final llm-response");
    let resp_text = response
        .iter()
        .find(|(n, _)| n == "text")
        .and_then(|(_, v)| match v {
            Val::String(s) => Some(s.clone()),
            _ => None,
        })
        .expect("response.text");
    assert_eq!(resp_text, text);

    // The handle was consumed at done — a re-poll errors (expired/unknown).
    let out = sut
        .call_host_fn_for_run(
            RUN_ID,
            "llm",
            LLM_NS,
            "poll-stream",
            vec![Val::U64(handle)],
            1,
        )
        .await
        .expect("poll-stream host fn ok (returns Err inside the result)");
    assert!(
        matches!(&out[0], Val::Result(Err(_))),
        "consumed handle is gone: {out:?}"
    );
}

/// SYS-AC-189 — exactly one `llm.response` event (with tokens_in/out and cost_usd)
/// is emitted at stream completion — not per delta — and RunBudget is checked once
/// before the stream starts.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_189_single_llm_response_at_stream_completion() {
    let text = "one two three";
    let (sut, budget) = stream_sut(text).await;

    let out = sut
        .call_host_fn_for_run(
            RUN_ID,
            "llm",
            LLM_NS,
            "stream",
            vec![stream_request("go")],
            1,
        )
        .await
        .expect("stream() ok");
    let handle = decode_handle(&out);

    // Budget checked exactly ONCE, before any poll (run_id-gated preflight in
    // stream_begin — "checked once before the stream starts").
    assert_eq!(
        budget.checks.load(Ordering::SeqCst),
        1,
        "preflight ran once at stream()"
    );

    // No llm.response yet — emission is deferred to the done poll.
    let pre_poll_responses = sut
        .events()
        .iter()
        .filter(|e| e.event_type == "llm.response")
        .count();
    assert_eq!(
        pre_poll_responses, 0,
        "no llm.response before the stream completes"
    );

    // Drain deltas to done.
    for _ in 0..256 {
        let out = sut
            .call_host_fn_for_run(
                RUN_ID,
                "llm",
                LLM_NS,
                "poll-stream",
                vec![Val::U64(handle)],
                1,
            )
            .await
            .expect("poll-stream ok");
        let (_, done, _) = decode_chunk(&out);
        if done {
            break;
        }
        // Mid-stream: under Δ3 emission is at owner-terminal and poll-independent, so
        // it may already have happened. The per-delta ZERO assertion this replaced is
        // superseded by that sanctioned delta (MODULE-009 §2.7 inv 6 Δ3 + the §3.3
        // migration note) — but the count must never EXCEED one at any point.
        let mid = sut
            .events()
            .iter()
            .filter(|e| e.event_type == "llm.response")
            .count();
        assert!(
            mid <= 1,
            "never more than one llm.response mid-drain, saw {mid}"
        );
    }

    // Exactly ONE llm.response, at completion, carrying tokens + cost.
    let responses: Vec<_> = sut
        .events()
        .into_iter()
        .filter(|e| e.event_type == "llm.response")
        .collect();
    assert_eq!(
        responses.len(),
        1,
        "exactly one llm.response at stream completion"
    );
    let payload = &responses[0].payload;
    assert!(
        payload
            .get("input_tokens")
            .and_then(|v| v.as_u64())
            .is_some(),
        "tokens_in present"
    );
    assert!(
        payload
            .get("output_tokens")
            .and_then(|v| v.as_u64())
            .is_some(),
        "tokens_out present"
    );
    assert!(
        payload.get("cost_usd").and_then(|v| v.as_f64()).is_some(),
        "cost_usd present"
    );

    // Budget still checked exactly once (no per-delta/done recheck).
    assert_eq!(
        budget.checks.load(Ordering::SeqCst),
        1,
        "budget not re-checked after stream()"
    );
}

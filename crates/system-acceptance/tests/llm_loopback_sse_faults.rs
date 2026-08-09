//! grok-repass Item 2 witnesses (L2-T1..T4, T6, T9, T10): the loopback's SSE
//! fault vocabulary, driven over REAL TCP through the REAL
//! `DefaultHttpSecurityChain::execute_streaming` (`LoopbackLlm::streaming_chain`)
//! — the sanctioned consumer of the pre-scan wire bytes.
//!
//! Timing discipline (Item 4 conventions): synchronization is awaiting the
//! Nth expected event (gate releases + frame counting), never a fixed sleep;
//! the gate's bounded acquire is a FAILURE bound, not a synchronization
//! primitive, and its signal is the out-of-band `timed_out()` accessor.

use std::sync::{Arc, Mutex};

use advance_shared_types::event::Event;
use advance_shared_types::security_validator::{
    Allowlist, HttpBodyStream, HttpCapability, HttpMethod, HttpRequest,
};
use advance_shared_types::traits::EventBusEmit;
use system_acceptance::llm_loopback::{
    LoopbackLlm, ScriptedBody, ScriptedResponse, SseEvent, SseGate,
};

#[derive(Default)]
struct NoopBus {
    events: Mutex<Vec<Event>>,
}

impl EventBusEmit for NoopBus {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

async fn boot(script: Vec<ScriptedResponse>) -> LoopbackLlm {
    LoopbackLlm::start(
        script,
        None,
        None,
        Arc::new(NoopBus::default()),
        "sse-fault-agent".to_string(),
    )
    .await
}

fn chat_req(lb: &LoopbackLlm) -> HttpRequest {
    HttpRequest {
        method: HttpMethod::Post,
        url: lb.chat_completions_url(),
        headers: vec![],
        body: b"{}".to_vec(),
    }
}

fn cap() -> HttpCapability {
    HttpCapability {
        allowlist: Allowlist {
            patterns: vec!["harness-llm.test".to_string()],
        },
        credentials: vec![],
        component_id: "sse-faults".to_string(),
    }
}

/// Expected wire form of one scripted event (mirrors the serving rules:
/// optional event: line, one data: line per line of data, blank terminator).
/// KNOWN BOUNDED MIRROR (audit rounds 1–3): this is a test-local copy of the
/// production serializer, so `== wire_of(..)` pins "server == this copy",
/// not "the wire form is valid SSE" — a shared serialization bug would be
/// mirrored. The mirror is closed by two mechanisms, scoped precisely:
/// (a) rows carry mirror-independent LITERAL claims — L2-T1/T2/T3 assert
/// literal absence/presence/raw-bytes, L2-T4's full drain and L2-T10 assert
/// hardcoded content fragments and anchored data-line counts (L2-T10's
/// first == second is the row's replay property, restated for readability —
/// the literals are what detect a mirrored bug); (b) the serializer's two
/// CONDITIONAL branches (event-name line, multi-line data), which no other
/// passing row executes, are pinned by l2t11 against a fully HARDCODED
/// expected string that references neither wire_of nor the production
/// serializer.
fn wire_of(events: &[SseEvent]) -> String {
    let mut out = String::new();
    for ev in events {
        if let Some(name) = &ev.event {
            out.push_str("event: ");
            out.push_str(name);
            out.push('\n');
        }
        for line in ev.data.split('\n') {
            out.push_str("data: ");
            out.push_str(line);
            out.push('\n');
        }
        out.push('\n');
    }
    out
}

fn delta(content: &str) -> SseEvent {
    SseEvent {
        event: None,
        data: format!(
            r#"{{"choices":[{{"index":0,"delta":{{"content":"{content}"}},"finish_reason":null}}]}}"#
        ),
    }
}

async fn drain(body: &mut Box<dyn HttpBodyStream>) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(chunk) = body.next_chunk().await {
        out.extend(chunk.expect("scripted sse yields no chain errors"));
    }
    out
}

fn frames_in(bytes: &[u8]) -> usize {
    String::from_utf8_lossy(bytes).matches("\n\n").count()
}

/// Await the Nth expected frame (Item-4 convention (b)): keep pulling until
/// `n` blank-line-terminated frames are visible — no sleeps.
async fn read_until_frames(body: &mut Box<dyn HttpBodyStream>, n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    while frames_in(&out) < n {
        let chunk = body
            .next_chunk()
            .await
            .expect("stream must stay open until the Nth frame")
            .expect("no chain error");
        out.extend(chunk);
    }
    out
}

/// L2-T1 — EOF with no terminal frame: the body ends exactly at the last
/// scripted event; nothing (no finish_reason, no usage, no DONE) is
/// synthesized. Unscriptable before ScriptedBody::Sse existed.
#[tokio::test(flavor = "multi_thread")]
async fn l2t1_eof_with_no_terminal_frame_is_scriptable() {
    let events = vec![delta("alpha "), delta("beta")];
    let lb = boot(vec![ScriptedResponse::sse(200, events.clone())]).await;
    let chain = lb.streaming_chain();

    let (head, mut body) = chain
        .execute_streaming("sse-fault-agent", chat_req(&lb), &cap())
        .await
        .expect("head ok");
    assert_eq!(head.status, 200);
    let bytes = drain(&mut body).await;
    let text = String::from_utf8(bytes).expect("utf8");

    assert_eq!(
        text,
        wire_of(&events),
        "body ends exactly at the last scripted event"
    );
    assert!(!text.contains("[DONE]"), "no DONE synthesized");
    assert!(
        !text.contains("finish_reason\":\"stop"),
        "no terminal synthesized"
    );
    assert!(!text.contains("usage"), "no usage synthesized");
}

/// L2-T2 — usage frame omitted: terminal carries finish_reason but no usage.
#[tokio::test(flavor = "multi_thread")]
async fn l2t2_usage_frame_omission_is_scriptable() {
    let events = vec![
        delta("alpha "),
        SseEvent {
            event: None,
            data: r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#.to_string(),
        },
        SseEvent {
            event: None,
            data: "[DONE]".to_string(),
        },
    ];
    let lb = boot(vec![ScriptedResponse::sse(200, events.clone())]).await;
    let chain = lb.streaming_chain();

    let (_, mut body) = chain
        .execute_streaming("sse-fault-agent", chat_req(&lb), &cap())
        .await
        .expect("head ok");
    let text = String::from_utf8(drain(&mut body).await).expect("utf8");

    assert_eq!(text, wire_of(&events));
    // Terminal-SPECIFIC literal (audit round 3): every delta frame embeds
    // finish_reason:null, so only the "stop" form proves the terminal frame
    // reached the wire.
    assert!(text.contains(r#""finish_reason":"stop""#));
    assert!(!text.contains("usage"), "usage omission reaches the wire");
}

/// L2-T3 — a malformed frame reaches the client byte-identical, uncorrected.
#[tokio::test(flavor = "multi_thread")]
async fn l2t3_malformed_frame_reaches_client_byte_identical() {
    let events = vec![SseEvent {
        event: None,
        data: "{not json".to_string(),
    }];
    let lb = boot(vec![ScriptedResponse::sse(200, events.clone())]).await;
    let chain = lb.streaming_chain();

    let (_, mut body) = chain
        .execute_streaming("sse-fault-agent", chat_req(&lb), &cap())
        .await
        .expect("head ok");
    let text = String::from_utf8(drain(&mut body).await).expect("utf8");

    assert_eq!(text, wire_of(&events));
    assert!(
        text.contains("data: {not json\n"),
        "byte-identical, uncorrected"
    );
}

/// L2-T4 — the gate actually gates: after releasing exactly k (< N) permits
/// and reading k frames, `events_emitted() == k` — a positive, timing-free
/// equality on shared state (with the gate deleted, all N frames stream
/// immediately and the counter reads N > k). Then releasing `events + 1`
/// total drains the stream to a clean EOF with no timeout.
#[tokio::test(flavor = "multi_thread")]
async fn l2t4_gate_release_k_read_k_events_emitted_is_exactly_k() {
    let events = vec![delta("a "), delta("b "), delta("c")];
    let gate = SseGate::new();
    let lb = boot(vec![
        ScriptedResponse::sse(200, events.clone()).with_gate(gate.clone())
    ])
    .await;
    let chain = lb.streaming_chain();

    let (_, mut body) = chain
        .execute_streaming("sse-fault-agent", chat_req(&lb), &cap())
        .await
        .expect("head ok");

    gate.release(2);
    let partial = read_until_frames(&mut body, 2).await;
    assert_eq!(frames_in(&partial), 2);
    assert_eq!(
        gate.events_emitted(),
        2,
        "after releasing exactly 2 and reading 2, the counter is exactly 2"
    );

    // events + 1 total (3 events + terminal EOF pull = 4 permits).
    gate.release(2);
    let mut rest = partial;
    rest.extend(drain(&mut body).await);
    let text = String::from_utf8(rest).expect("utf8");
    assert_eq!(text, wire_of(&events), "full drain is byte-exact");
    // Mirror-independent literals (audit round 2): content fragments and
    // structure that a shared serializer bug could not fabricate.
    assert!(text.contains(r#""content":"a ""#));
    assert!(text.contains(r#""content":"c""#));
    // Anchored line-start count (audit round 3): an embedded "data: " in
    // content must not satisfy the frame count.
    assert_eq!(text.lines().filter(|l| l.starts_with("data: ")).count(), 3);
    assert!(text.ends_with("\n\n"));
    assert_eq!(gate.events_emitted(), 3);
    assert_eq!(gate.timed_out(), None, "clean drain never trips the bound");
}

/// L2-T6 — eager validation: CR/LF in an event name panics at enqueue,
/// naming the offending index.
#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "SseEvent.event name contains CR/LF")]
async fn l2t6_crlf_event_name_panics_at_enqueue() {
    let _ = boot(vec![ScriptedResponse::sse(
        200,
        vec![SseEvent {
            event: Some("bad\nname".to_string()),
            data: "x".to_string(),
        }],
    )])
    .await;
}

/// L2-T6c (audit round 4) — eager validation: a bare CR in event data would
/// frame differently than the script declares on a conforming SSE parser
/// (lines terminate on CR too); rejected at enqueue like CR/LF in names.
#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "SseEvent.data contains a CR")]
async fn l2t6c_cr_in_data_panics_at_enqueue() {
    let _ = boot(vec![ScriptedResponse::sse(
        200,
        vec![SseEvent {
            event: None,
            data: "bad\rdata".to_string(),
        }],
    )])
    .await;
}

/// L2-T6b — eager validation: a gate on a non-Sse body would be a
/// silently-ignored no-op (a witness that cannot fail), so it is rejected
/// at enqueue.
#[tokio::test(flavor = "multi_thread")]
#[should_panic(expected = "a gate on a non-Sse body")]
async fn l2t6b_gate_on_non_sse_body_panics_at_enqueue() {
    let _ = boot(vec![
        ScriptedResponse::ok_chat("hi", 1, 1).with_gate(SseGate::new())
    ])
    .await;
}

/// L2-T9 — too few permits: the bounded acquire expires and the handler
/// publishes the OUT-OF-BAND timeout index BEFORE abandoning the body, so the
/// test fails deterministically instead of hanging — and the signal is not
/// satisfiable by the clean-EOF byte pattern L2-T1 scripts (the wire looks
/// identical; the accessor is what distinguishes them).
#[tokio::test(flavor = "multi_thread")]
async fn l2t9_starved_gate_times_out_out_of_band() {
    let events = vec![delta("a "), delta("b "), delta("c")];
    let gate = SseGate::new();
    let lb = boot(vec![
        ScriptedResponse::sse(200, events).with_gate(gate.clone())
    ])
    .await;
    let chain = lb.streaming_chain();

    let (_, mut body) = chain
        .execute_streaming("sse-fault-agent", chat_req(&lb), &cap())
        .await
        .expect("head ok");

    gate.release(1);
    let bytes = drain(&mut body).await;

    assert_eq!(
        frames_in(&bytes),
        1,
        "exactly the one released frame arrived"
    );
    assert_eq!(
        gate.timed_out(),
        Some(1),
        "the handler recorded the starved index before abandoning the body"
    );
    assert_eq!(gate.events_emitted(), 1);
}

/// L2-T10 — the replay branch never gates (round-7 structural close of hang
/// entrance (i)): once the FIFO drains, a second call served from replay
/// streams to EOF with ZERO additional releases, the gate untouched.
#[tokio::test(flavor = "multi_thread")]
async fn l2t10_replay_of_gated_entry_serves_ungated() {
    let events = vec![delta("a "), delta("b")];
    let gate = SseGate::new();
    let lb = boot(vec![
        ScriptedResponse::sse(200, events.clone()).with_gate(gate.clone())
    ])
    .await;
    let chain = lb.streaming_chain();

    // First call: served from the FIFO, fully released (2 events + EOF).
    gate.release(3);
    let (_, mut body) = chain
        .execute_streaming("sse-fault-agent", chat_req(&lb), &cap())
        .await
        .expect("head ok");
    let first = drain(&mut body).await;
    assert_eq!(String::from_utf8_lossy(&first), wire_of(&events));
    assert_eq!(gate.events_emitted(), 2);

    // Second call: FIFO empty → replay. NO further releases; the spent gate
    // must be ignored, the body must drain, and the gate must be untouched.
    let (_, mut body2) = chain
        .execute_streaming("sse-fault-agent", chat_req(&lb), &cap())
        .await
        .expect("head ok");
    let second = drain(&mut body2).await;
    // Mirror-independent claims (audit round 2): the row's actual property
    // is replay byte-equality, plus literal content/structure fragments a
    // shared serializer bug could not fabricate.
    assert_eq!(second, first, "replay serves byte-identical wire content");
    assert_eq!(String::from_utf8_lossy(&second), wire_of(&events));
    let second_text = String::from_utf8_lossy(&second);
    assert!(second_text.contains(r#""content":"a ""#));
    assert!(second_text.contains(r#""content":"b""#));
    assert_eq!(
        second_text
            .lines()
            .filter(|l| l.starts_with("data: "))
            .count(),
        2
    );
    assert_eq!(gate.events_emitted(), 2, "replay does not touch the gate");
    assert_eq!(gate.timed_out(), None, "replay cannot hang on a spent gate");
}

/// L2-T11 (audit round 3) — the serializer's two CONDITIONAL branches,
/// which no other passing row executes: an event NAME line and MULTI-LINE
/// data. Pinned against a fully HARDCODED expected string — no wire_of, no
/// shared helper — so a bug in either branch cannot hide behind the mirror.
#[tokio::test(flavor = "multi_thread")]
async fn l2t11_event_name_and_multiline_data_serialize_to_hardcoded_wire() {
    let events = vec![
        SseEvent {
            event: Some("notice".to_string()),
            data: "line one\nline two".to_string(),
        },
        SseEvent {
            event: None,
            data: "tail".to_string(),
        },
    ];
    let lb = boot(vec![ScriptedResponse::sse(200, events)]).await;
    let chain = lb.streaming_chain();

    let (_, mut body) = chain
        .execute_streaming("sse-fault-agent", chat_req(&lb), &cap())
        .await
        .expect("head ok");
    let text = String::from_utf8(drain(&mut body).await).expect("utf8");

    let expected = "event: notice\n\
                    data: line one\n\
                    data: line two\n\
                    \n\
                    data: tail\n\
                    \n";
    assert_eq!(
        text, expected,
        "hardcoded wire form, both branches exercised"
    );
}

/// CONTROL — a ScriptedBody::Raw body is written byte-for-byte.
#[tokio::test(flavor = "multi_thread")]
async fn l2_raw_body_is_byte_for_byte() {
    let raw = "data: {half\ndata";
    let lb = boot(vec![ScriptedResponse::raw(200, raw)]).await;
    let chain = lb.streaming_chain();

    let (_, mut body) = chain
        .execute_streaming("sse-fault-agent", chat_req(&lb), &cap())
        .await
        .expect("head ok");
    let text = String::from_utf8(drain(&mut body).await).expect("utf8");
    assert_eq!(text, raw);
}

/// CONTROL — the Json arm's non-streaming wire path is unchanged by the
/// retype: a scripted ok_chat still serves the exact JSON envelope.
#[tokio::test(flavor = "multi_thread")]
async fn l2_json_nonstreaming_path_byte_identical() {
    let lb = boot(vec![ScriptedResponse::ok_chat("hello", 3, 4)]).await;
    let chain = lb.streaming_chain();

    let (head, mut body) = chain
        .execute_streaming("sse-fault-agent", chat_req(&lb), &cap())
        .await
        .expect("head ok");
    assert_eq!(head.status, 200);
    let text = String::from_utf8(drain(&mut body).await).expect("utf8");
    let expected = match &ScriptedResponse::ok_chat("hello", 3, 4).body {
        ScriptedBody::Json(s) => s.clone(),
        other => panic!("ok_chat builds Json, got {other:?}"),
    };
    assert_eq!(text, expected);
}

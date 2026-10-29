//! ADR 2026-10-24 D4 — host-owned turn transcript (S1 / V1).
//!
//! Three guest `generate`s inside one stamped turn: every captured OpenAI
//! request body starts with the assembled identity prefix; request 3 carries
//! request 2's assistant `tool_calls` plus a matching tool-role message;
//! `transcript: fresh` carries neither.
//!
//! The transcript is keyed by the invocation's transcript scope: a trusted turn's
//! id, or a key the host mints for one unprotected invocation, which never reaches
//! the trusted turn id. A prompt the assembled seed already ends with is sent and
//! recorded once.

use std::sync::{Arc, Mutex};

use advance_runtime::host_registry::{HostCallContext, HostFunctionHandler};
use advance_shared_types::context::LlmMessage;
use advance_shared_types::security_validator::HttpResponse;
use advance_shared_types::turn_attribution::{CostAttributionLookup, TurnCostAttributionReadPort};
use serde_json::Value;
use wasmtime::component::Val;

use crate::gateway::{ChatMessage, ChatResponse, ChatRole, ToolCall, TranscriptMode};
use crate::host_fn::{AgentLlmGenerateHandler, AgentLlmPollStreamHandler, AgentLlmStreamHandler};
use crate::stream::StreamRegistry;
use crate::test_support::{test_gateway_with, MockEventBusEmit, MockHttpSecurityChain};

const AGENT: &str = "agent-transcript";
const TURN: &str = "turn-1";
const IDENTITY: &str = "IDENTITY-PREFIX-ROOT";

fn turn_ctx() -> HostCallContext {
    HostCallContext {
        agent_id: AGENT.into(),
        trace_id: "tr-transcript".into(),
        turn_id: Some(TURN.into()),
        transcript_scope: Some(TURN.into()),
        capability: "llm".into(),
        function: "advance:runtime/agent-llm@0.1.0::generate".into(),
        run_id: None,
        iteration: None,
    }
}

fn ok_text(content: &str, prompt_tokens: u64, completion_tokens: u64) -> HttpResponse {
    let body = serde_json::json!({
        "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens},
        "model": "gpt-4o-mini",
    });
    HttpResponse {
        status: 200,
        headers: vec![],
        body: serde_json::to_vec(&body).unwrap(),
    }
}

fn ok_tools(id: &str, name: &str, arguments: &str) -> HttpResponse {
    let body = serde_json::json!({
        "choices": [{
            "message": {
                "content": serde_json::Value::Null,
                "tool_calls": [{
                    "id": id,
                    "type": "function",
                    "function": { "name": name, "arguments": arguments }
                }]
            },
            "finish_reason": "tool_calls"
        }],
        "usage": {"prompt_tokens": 20, "completion_tokens": 8},
        "model": "gpt-4o-mini",
    });
    HttpResponse {
        status: 200,
        headers: vec![],
        body: serde_json::to_vec(&body).unwrap(),
    }
}

fn messages_json(body: &[u8]) -> Vec<Value> {
    let v: Value = serde_json::from_slice(body).expect("chat body is JSON");
    v.get("messages")
        .and_then(Value::as_array)
        .cloned()
        .expect("messages array")
}

fn prompt_val(prompt: &str) -> Val {
    Val::Record(vec![("prompt".into(), Val::String(prompt.into()))])
}

fn fresh_val(prompt: &str) -> Val {
    let params = Val::Option(Some(Box::new(Val::Record(vec![(
        "transcript".into(),
        Val::Option(Some(Box::new(Val::Enum("fresh".into())))),
    )]))));
    Val::Record(vec![
        ("prompt".into(), Val::String(prompt.into())),
        ("params".into(), params),
    ])
}

fn expect_ok(result: &[Val]) {
    match result {
        [Val::Result(Ok(_))] => {}
        other => panic!("expected generate Ok, got {other:?}"),
    }
}

#[tokio::test]
async fn v1_three_generates_identity_tool_role_and_fresh() {
    let bus = Arc::new(MockEventBusEmit::default());
    let chain = Arc::new(MockHttpSecurityChain::default());
    chain.push_response("/v1/chat/completions", Ok(ok_text("round-1-ok", 40, 6)));
    chain.push_response(
        "/v1/chat/completions",
        Ok(ok_tools("call_1", "write", r#"{"path":"roadmap.md"}"#)),
    );
    chain.push_response("/v1/chat/completions", Ok(ok_text("round-3-ok", 80, 4)));
    chain.push_response("/v1/chat/completions", Ok(ok_text("fresh-ok", 12, 3)));
    let gw = test_gateway_with(bus, Arc::clone(&chain));
    gw.publish_assembled(
        AGENT,
        Arc::from(vec![LlmMessage {
            role: "system".into(),
            content: IDENTITY.into(),
        }]),
    );

    let handler = AgentLlmGenerateHandler {
        gateway: Arc::clone(&gw),
        turn_cost: None,
    };
    let ctx = turn_ctx();

    expect_ok(
        &handler
            .call(ctx.clone(), vec![prompt_val("round-1")], 1)
            .await
            .unwrap(),
    );
    expect_ok(
        &handler
            .call(ctx.clone(), vec![prompt_val("round-2")], 1)
            .await
            .unwrap(),
    );
    gw.record_tool_result(AGENT, TURN, "call_1", "write", "wrote roadmap.md");
    expect_ok(
        &handler
            .call(ctx.clone(), vec![prompt_val("")], 1)
            .await
            .unwrap(),
    );
    expect_ok(
        &handler
            .call(ctx, vec![fresh_val("side-query")], 1)
            .await
            .unwrap(),
    );

    let log = chain.call_log.lock().unwrap();
    assert_eq!(log.len(), 4, "three continue generates plus one fresh");
    let bodies: Vec<Vec<Value>> = log.iter().map(|r| messages_json(&r.body)).collect();

    for (i, msgs) in bodies.iter().enumerate() {
        assert_eq!(
            msgs[0]["role"].as_str(),
            Some("system"),
            "generate {} must start with the identity prefix",
            i + 1
        );
        assert_eq!(
            msgs[0]["content"].as_str(),
            Some(IDENTITY),
            "generate {} lost the assembled identity seed",
            i + 1
        );
    }

    let g2 = &bodies[1];
    assert!(
        g2.iter()
            .any(|m| m["role"] == "user" && m["content"] == "round-1"),
        "generate 2 carries the first user prompt: {g2:?}"
    );
    assert!(
        g2.iter()
            .any(|m| m["role"] == "assistant" && m["content"] == "round-1-ok"),
        "generate 2 carries the first assistant reply: {g2:?}"
    );

    let g3 = &bodies[2];
    let tool_assistant = g3.iter().find(|m| {
        m["role"] == "assistant" && m.get("tool_calls").and_then(Value::as_array).is_some()
    });
    let tool_calls = tool_assistant
        .expect("generate 3 carries assistant tool_calls from generate 2")
        .get("tool_calls")
        .and_then(Value::as_array)
        .expect("tool_calls array");
    assert_eq!(tool_calls[0]["id"].as_str(), Some("call_1"));
    assert_eq!(tool_calls[0]["function"]["name"].as_str(), Some("write"));
    let tool_msg = g3
        .iter()
        .find(|m| m["role"] == "tool")
        .expect("generate 3 carries a tool-role message");
    assert_eq!(tool_msg["tool_call_id"].as_str(), Some("call_1"));
    assert!(
        tool_msg["content"]
            .as_str()
            .is_some_and(|c| c.contains("wrote roadmap.md")),
        "tool-role content: {tool_msg:?}"
    );

    let fresh = &bodies[3];
    assert!(
        fresh
            .iter()
            .any(|m| m["role"] == "user" && m["content"] == "side-query"),
        "fresh carries the side prompt: {fresh:?}"
    );
    assert!(
        !fresh
            .iter()
            .any(|m| m["content"] == "round-1" || m["content"] == "round-2"),
        "fresh must not carry the continue transcript: {fresh:?}"
    );
    assert!(
        !fresh.iter().any(|m| m["role"] == "tool"
            || m.get("tool_calls")
                .and_then(Value::as_array)
                .is_some_and(|a| !a.is_empty())),
        "fresh must not carry tool_calls or tool-role messages: {fresh:?}"
    );
}

#[test]
fn build_guest_messages_continue_fresh_empty_prompt_and_end_turn() {
    let bus = Arc::new(MockEventBusEmit::default());
    let chain = Arc::new(MockHttpSecurityChain::default());
    let gw = test_gateway_with(bus, chain);
    gw.publish_assembled(
        AGENT,
        Arc::from(vec![LlmMessage {
            role: "system".into(),
            content: IDENTITY.into(),
        }]),
    );

    let first = gw.build_guest_messages(AGENT, Some(TURN), "hello", TranscriptMode::Continue);
    assert_eq!(first[0].content, IDENTITY);
    assert_eq!(first[1].role, ChatRole::User);
    assert_eq!(first[1].content, "hello");

    gw.record_generate(
        AGENT,
        TURN,
        "hello",
        &ChatResponse {
            text: "hi".into(),
            model: "m".into(),
            input_tokens: 1,
            output_tokens: 1,
            finish_reason: "stop".into(),
            parsed_output: None,
            tool_calls: vec![ToolCall {
                id: "c1".into(),
                name: "write".into(),
                arguments: "{}".into(),
            }],
        },
    );
    gw.record_tool_result(AGENT, TURN, "c1", "write", "ok");

    let cont = gw.build_guest_messages(AGENT, Some(TURN), "", TranscriptMode::Continue);
    assert_eq!(cont[0].content, IDENTITY);
    assert!(cont.iter().any(|m| m.role == ChatRole::Tool
        && m.tool_call_id.as_deref() == Some("c1")
        && m.content == "ok"));
    assert!(
        !cont
            .iter()
            .any(|m| m.role == ChatRole::User && m.content.is_empty()),
        "empty prompt is omitted"
    );

    let orphan_before = gw.build_guest_messages(AGENT, Some(TURN), "", TranscriptMode::Continue);
    gw.record_tool_result(AGENT, TURN, "missing", "other", "nope");
    let orphan_after = gw.build_guest_messages(AGENT, Some(TURN), "", TranscriptMode::Continue);
    assert_eq!(orphan_after.len(), orphan_before.len() + 1);
    assert!(orphan_after
        .iter()
        .any(|m| m.role == ChatRole::User && m.content.starts_with("[tool result: other]")));

    let fresh = gw.build_guest_messages(AGENT, Some(TURN), "side", TranscriptMode::Fresh);
    assert_eq!(fresh.len(), 2);
    assert_eq!(fresh[0].content, IDENTITY);
    assert_eq!(fresh[1].content, "side");

    gw.end_turn(AGENT, TURN);
    assert!(
        gw.assembled_for(AGENT).is_none(),
        "end_turn also clears the assembled seed"
    );
    let after = gw.build_guest_messages(AGENT, Some(TURN), "next", TranscriptMode::Continue);
    assert_eq!(
        after.len(),
        1,
        "end_turn drops the transcript slot and the seed"
    );
    assert_eq!(after[0].content, "next");
}

#[test]
fn v13_error_format_records_as_tool_role() {
    let bus = Arc::new(MockEventBusEmit::default());
    let chain = Arc::new(MockHttpSecurityChain::default());
    let gw = test_gateway_with(bus, chain);
    gw.record_generate(
        AGENT,
        TURN,
        "please remember",
        &ChatResponse {
            text: String::new(),
            model: "m".into(),
            input_tokens: 1,
            output_tokens: 1,
            finish_reason: "tool_calls".into(),
            parsed_output: None,
            tool_calls: vec![ToolCall {
                id: "bad_1".into(),
                name: "remember".into(),
                arguments: "{}".into(),
            }],
        },
    );
    let content = "[invoke-callable error: invalid-arguments] missing required property 'content'";
    gw.record_tool_result(AGENT, TURN, "bad_1", "remember", content);
    let msgs = gw.build_guest_messages(AGENT, Some(TURN), "", TranscriptMode::Continue);
    assert!(
        msgs.iter().any(|m| m.role == ChatRole::Tool
            && m.tool_call_id.as_deref() == Some("bad_1")
            && m.content.contains("invalid-arguments")),
        "refusal is a tool-role message answering the pending call: {msgs:?}"
    );
}

#[test]
fn assembled_seed_is_peeked_not_consumed() {
    let bus = Arc::new(MockEventBusEmit::default());
    let chain = Arc::new(MockHttpSecurityChain::default());
    let gw = test_gateway_with(bus, chain);
    gw.publish_assembled(
        AGENT,
        Arc::from(vec![LlmMessage {
            role: "system".into(),
            content: IDENTITY.into(),
        }]),
    );
    let a = gw.build_guest_messages(AGENT, None, "one", TranscriptMode::Continue);
    let b = gw.build_guest_messages(AGENT, None, "two", TranscriptMode::Continue);
    assert_eq!(a[0].content, IDENTITY);
    assert_eq!(b[0].content, IDENTITY);
    assert_eq!(a[1].content, "one");
    assert_eq!(b[1].content, "two");
}

#[test]
fn chat_message_helpers() {
    let m = ChatMessage::new(ChatRole::User, "hi");
    assert_eq!(m.tool_call_id, None);
    assert!(m.tool_calls.is_empty());
    let t = ChatMessage::tool("c1", "ok");
    assert_eq!(t.role, ChatRole::Tool);
    assert_eq!(t.tool_call_id.as_deref(), Some("c1"));
    let a = ChatMessage::assistant_with_calls(
        "",
        vec![ToolCall {
            id: "c1".into(),
            name: "write".into(),
            arguments: "{}".into(),
        }],
    );
    assert_eq!(a.role, ChatRole::Assistant);
    assert_eq!(a.tool_calls.len(), 1);
}

// ── A host-minted transcript scope (an unprotected invocation) ──────────────────────────────

/// The key the host mints for one unprotected invocation (its shape does not matter here).
const MINTED: &str = "invocation-7f1c";

/// An unprotected invocation: no trusted turn, a host-minted transcript scope.
fn minted_ctx() -> HostCallContext {
    HostCallContext {
        turn_id: None,
        transcript_scope: Some(MINTED.into()),
        ..turn_ctx()
    }
}

/// Records every cost-attribution lookup (the trusted-turn ids it is asked about).
#[derive(Default)]
struct RecordingTurnCost(Mutex<Vec<String>>);

impl TurnCostAttributionReadPort for RecordingTurnCost {
    fn cost_attribution(&self, turn_id: &str, _expected_agent: &str) -> CostAttributionLookup {
        self.0.lock().unwrap().push(turn_id.to_string());
        CostAttributionLookup::Untracked
    }
}

/// An unprotected invocation records its rounds under the minted scope: round 2 replays round
/// 1's tool call and its result, cost attribution is never asked about the minted key, and
/// `end_turn` with the key drops the transcript and the seed.
#[tokio::test]
async fn a_minted_scope_records_and_replays_tool_results_without_a_trusted_turn() {
    let bus = Arc::new(MockEventBusEmit::default());
    let chain = Arc::new(MockHttpSecurityChain::default());
    chain.push_response(
        "/v1/chat/completions",
        Ok(ok_tools("call_1", "write", r#"{"path":"notes.md"}"#)),
    );
    chain.push_response("/v1/chat/completions", Ok(ok_text("written", 30, 2)));
    let gw = test_gateway_with(bus, Arc::clone(&chain));
    gw.publish_assembled(
        AGENT,
        Arc::from(vec![LlmMessage {
            role: "system".into(),
            content: IDENTITY.into(),
        }]),
    );
    let turn_cost = Arc::new(RecordingTurnCost::default());
    let handler = AgentLlmGenerateHandler {
        gateway: Arc::clone(&gw),
        turn_cost: Some(Arc::clone(&turn_cost) as Arc<dyn TurnCostAttributionReadPort>),
    };

    expect_ok(
        &handler
            .call(minted_ctx(), vec![prompt_val("write the notes")], 1)
            .await
            .unwrap(),
    );
    // The callable dispatcher records the result under the invocation's scope.
    gw.record_tool_result(AGENT, MINTED, "call_1", "write", "wrote notes.md");
    expect_ok(
        &handler
            .call(minted_ctx(), vec![prompt_val("")], 1)
            .await
            .unwrap(),
    );

    let log = chain.call_log.lock().unwrap();
    assert_eq!(log.len(), 2);
    let round2 = messages_json(&log[1].body);
    assert_eq!(round2[0]["content"], IDENTITY);
    assert_eq!(round2[1]["role"], "user");
    assert_eq!(round2[1]["content"], "write the notes");
    assert_eq!(round2[2]["role"], "assistant");
    assert_eq!(round2[2]["tool_calls"][0]["id"], "call_1");
    assert_eq!(round2[2]["tool_calls"][0]["function"]["name"], "write");
    assert_eq!(round2[3]["role"], "tool");
    assert_eq!(round2[3]["tool_call_id"], "call_1");
    assert_eq!(round2[3]["content"], "wrote notes.md");
    assert_eq!(round2.len(), 4, "{round2:?}");
    drop(log);

    assert!(
        turn_cost.0.lock().unwrap().is_empty(),
        "cost attribution never sees the minted scope"
    );

    gw.end_turn(AGENT, MINTED);
    assert!(gw.assembled_for(AGENT).is_none());
    assert!(
        gw.build_guest_messages(AGENT, Some(MINTED), "", TranscriptMode::Continue)
            .is_empty(),
        "the invocation's transcript is gone"
    );
}

/// A trusted turn keeps its own id as its transcript scope, and attribution still reads the
/// trusted turn.
#[tokio::test]
async fn a_trusted_turn_is_its_own_transcript_scope_and_attribution_reads_it() {
    let bus = Arc::new(MockEventBusEmit::default());
    let chain = Arc::new(MockHttpSecurityChain::default());
    chain.push_response("/v1/chat/completions", Ok(ok_text("one", 10, 1)));
    let gw = test_gateway_with(bus, Arc::clone(&chain));
    let turn_cost = Arc::new(RecordingTurnCost::default());
    let handler = AgentLlmGenerateHandler {
        gateway: Arc::clone(&gw),
        turn_cost: Some(Arc::clone(&turn_cost) as Arc<dyn TurnCostAttributionReadPort>),
    };
    expect_ok(
        &handler
            .call(turn_ctx(), vec![prompt_val("first")], 1)
            .await
            .unwrap(),
    );
    assert_eq!(*turn_cost.0.lock().unwrap(), [TURN]);
    let replay = gw.build_guest_messages(AGENT, Some(TURN), "", TranscriptMode::Continue);
    assert_eq!(replay.len(), 2, "{replay:?}");
    assert_eq!(replay[0].content, "first");
    assert_eq!(replay[1].content, "one");
    // Another scope sees nothing of it.
    assert!(gw
        .build_guest_messages(AGENT, Some(MINTED), "", TranscriptMode::Continue)
        .is_empty());
}

// ── The current prompt is sent once ─────────────────────────────────────────────────────────

/// A seed as the context engine assembles it: the identity, then the inbound message as the
/// current prompt (its last message, unwrapped).
fn seed_ending_with(prompt: &str) -> Arc<[LlmMessage]> {
    Arc::from(vec![
        LlmMessage {
            role: "system".into(),
            content: IDENTITY.into(),
        },
        LlmMessage {
            role: "user".into(),
            content: prompt.into(),
        },
    ])
}

fn roles_and_contents(msgs: &[Value]) -> Vec<(String, String)> {
    msgs.iter()
        .map(|m| {
            (
                m["role"].as_str().unwrap_or_default().to_string(),
                m["content"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

fn pairs(expected: &[(&str, &str)]) -> Vec<(String, String)> {
    expected
        .iter()
        .map(|(r, c)| (r.to_string(), c.to_string()))
        .collect()
}

/// The guest sends the inbound text as its prompt: round 1 carries it once, and round 2's
/// transcript does not repeat it.
#[tokio::test]
async fn the_prompt_the_seed_ends_with_is_sent_and_recorded_once() {
    let bus = Arc::new(MockEventBusEmit::default());
    let chain = Arc::new(MockHttpSecurityChain::default());
    chain.push_response("/v1/chat/completions", Ok(ok_text("hi there", 10, 2)));
    chain.push_response("/v1/chat/completions", Ok(ok_text("still here", 12, 2)));
    let gw = test_gateway_with(bus, Arc::clone(&chain));
    gw.publish_assembled(AGENT, seed_ending_with("hello"));
    let handler = AgentLlmGenerateHandler {
        gateway: Arc::clone(&gw),
        turn_cost: None,
    };
    expect_ok(
        &handler
            .call(turn_ctx(), vec![prompt_val("hello")], 1)
            .await
            .unwrap(),
    );
    expect_ok(
        &handler
            .call(turn_ctx(), vec![prompt_val("")], 1)
            .await
            .unwrap(),
    );
    let log = chain.call_log.lock().unwrap();
    assert_eq!(
        roles_and_contents(&messages_json(&log[0].body)),
        pairs(&[("system", IDENTITY), ("user", "hello")]),
        "round 1 carries the prompt once"
    );
    assert_eq!(
        roles_and_contents(&messages_json(&log[1].body)),
        pairs(&[
            ("system", IDENTITY),
            ("user", "hello"),
            ("assistant", "hi there")
        ]),
        "round 2's transcript does not repeat it"
    );
}

/// Any other prompt is appended and recorded as before: a different prompt, an empty seed, a
/// seed whose last message is not a user message, and `fresh` mode.
#[test]
fn any_other_prompt_is_appended_and_recorded() {
    let bus = Arc::new(MockEventBusEmit::default());
    let chain = Arc::new(MockHttpSecurityChain::default());
    let gw = test_gateway_with(bus, chain);
    let contents = |msgs: &[ChatMessage]| -> Vec<(ChatRole, String)> {
        msgs.iter().map(|m| (m.role, m.content.clone())).collect()
    };

    // A different prompt.
    gw.publish_assembled(AGENT, seed_ending_with("hello"));
    let guest = gw.guest_messages(AGENT, Some(TURN), "hello again", TranscriptMode::Continue);
    assert!(!guest.prompt_in_seed);
    assert_eq!(
        contents(&guest.messages),
        [
            (ChatRole::System, IDENTITY.to_string()),
            (ChatRole::User, "hello".to_string()),
            (ChatRole::User, "hello again".to_string()),
        ]
    );
    // A prompt the seed carries, but not as its last message.
    gw.publish_assembled(
        AGENT,
        Arc::from(vec![
            LlmMessage {
                role: "user".into(),
                content: "hello".into(),
            },
            LlmMessage {
                role: "system".into(),
                content: IDENTITY.into(),
            },
        ]),
    );
    let guest = gw.guest_messages(AGENT, Some(TURN), "hello", TranscriptMode::Continue);
    assert!(!guest.prompt_in_seed);
    assert_eq!(guest.messages.len(), 3);
    // The same text as an assistant message is not the prompt.
    gw.publish_assembled(
        AGENT,
        Arc::from(vec![LlmMessage {
            role: "assistant".into(),
            content: "hello".into(),
        }]),
    );
    let guest = gw.guest_messages(AGENT, Some(TURN), "hello", TranscriptMode::Continue);
    assert!(!guest.prompt_in_seed);
    assert_eq!(guest.messages.len(), 2);
    // `fresh` keeps its meaning: seed ++ prompt.
    gw.publish_assembled(AGENT, seed_ending_with("hello"));
    let guest = gw.guest_messages(AGENT, Some(TURN), "hello", TranscriptMode::Fresh);
    assert!(!guest.prompt_in_seed);
    assert_eq!(guest.messages.len(), 3);
    // An empty seed.
    gw.end_turn(AGENT, TURN);
    let guest = gw.guest_messages(AGENT, Some(TURN), "hello", TranscriptMode::Continue);
    assert!(!guest.prompt_in_seed);
    assert_eq!(
        contents(&guest.messages),
        [(ChatRole::User, "hello".to_string())]
    );
    // What is appended is also recorded: the next round replays it.
    gw.record_generate(
        AGENT,
        TURN,
        "hello",
        &ChatResponse {
            text: "hi".into(),
            model: "m".into(),
            input_tokens: 1,
            output_tokens: 1,
            finish_reason: "stop".into(),
            parsed_output: None,
            tool_calls: Vec::new(),
        },
    );
    let next = gw.build_guest_messages(AGENT, Some(TURN), "", TranscriptMode::Continue);
    assert_eq!(
        contents(&next),
        [
            (ChatRole::User, "hello".to_string()),
            (ChatRole::Assistant, "hi".to_string()),
        ]
    );
}

/// A differing prompt reaches the wire after the seed, and round 2 replays it.
#[tokio::test]
async fn a_differing_prompt_is_still_sent_and_replayed() {
    let bus = Arc::new(MockEventBusEmit::default());
    let chain = Arc::new(MockHttpSecurityChain::default());
    chain.push_response("/v1/chat/completions", Ok(ok_text("sure", 10, 1)));
    chain.push_response("/v1/chat/completions", Ok(ok_text("done", 12, 1)));
    let gw = test_gateway_with(bus, Arc::clone(&chain));
    gw.publish_assembled(AGENT, seed_ending_with("hello"));
    let handler = AgentLlmGenerateHandler {
        gateway: Arc::clone(&gw),
        turn_cost: None,
    };
    expect_ok(
        &handler
            .call(turn_ctx(), vec![prompt_val("summarise it")], 1)
            .await
            .unwrap(),
    );
    expect_ok(
        &handler
            .call(turn_ctx(), vec![prompt_val("")], 1)
            .await
            .unwrap(),
    );
    let log = chain.call_log.lock().unwrap();
    assert_eq!(
        roles_and_contents(&messages_json(&log[0].body)),
        pairs(&[
            ("system", IDENTITY),
            ("user", "hello"),
            ("user", "summarise it")
        ])
    );
    assert_eq!(
        roles_and_contents(&messages_json(&log[1].body)),
        pairs(&[
            ("system", IDENTITY),
            ("user", "hello"),
            ("user", "summarise it"),
            ("assistant", "sure"),
        ])
    );
}

/// The stream path follows the same rule: its request carries the prompt once, and what it
/// records at the end of the stream does not repeat it.
#[tokio::test]
async fn the_stream_path_sends_and_records_the_prompt_once() {
    let bus = Arc::new(MockEventBusEmit::default());
    let chain = Arc::new(MockHttpSecurityChain::default());
    let body = serde_json::json!({
        "choices": [{"message": {"content": "streamed answer"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 2},
        "model": "gpt-4o-mini",
    });
    chain.push_response(
        "/v1/chat/completions",
        Ok(HttpResponse {
            status: 200,
            headers: vec![],
            body: serde_json::to_vec(&body).unwrap(),
        }),
    );
    let gw = test_gateway_with(bus, Arc::clone(&chain));
    gw.publish_assembled(AGENT, seed_ending_with("hello"));
    let registry = Arc::new(StreamRegistry::new());
    let stream = AgentLlmStreamHandler {
        gateway: Arc::clone(&gw),
        registry: Arc::clone(&registry),
        turn_cost: None,
    };
    let poll = AgentLlmPollStreamHandler {
        gateway: Arc::clone(&gw),
        registry,
    };
    let handle = match stream
        .call(turn_ctx(), vec![prompt_val("hello")], 1)
        .await
        .unwrap()
        .as_slice()
    {
        [Val::Result(Ok(Some(boxed)))] => match boxed.as_ref() {
            Val::U64(handle) => *handle,
            other => panic!("expected a handle, got {other:?}"),
        },
        other => panic!("expected a stream handle, got {other:?}"),
    };
    let mut done = false;
    for _ in 0..1000 {
        let chunk = poll
            .call(turn_ctx(), vec![Val::U64(handle)], 1)
            .await
            .unwrap();
        let [Val::Result(Ok(Some(record)))] = chunk.as_slice() else {
            panic!("expected a stream chunk, got {chunk:?}");
        };
        let Val::Record(fields) = record.as_ref() else {
            panic!("expected a stream-chunk record, got {record:?}");
        };
        if fields
            .iter()
            .any(|(name, val)| name == "done" && matches!(val, Val::Bool(true)))
        {
            done = true;
            break;
        }
    }
    assert!(done, "the stream must finish");
    let log = chain.call_log.lock().unwrap();
    assert_eq!(
        roles_and_contents(&messages_json(&log[0].body)),
        pairs(&[("system", IDENTITY), ("user", "hello")]),
        "the stream request carries the prompt once"
    );
    drop(log);
    let next = gw.build_guest_messages(AGENT, Some(TURN), "", TranscriptMode::Continue);
    let next: Vec<(ChatRole, String)> = next.iter().map(|m| (m.role, m.content.clone())).collect();
    assert_eq!(
        next,
        [
            (ChatRole::System, IDENTITY.to_string()),
            (ChatRole::User, "hello".to_string()),
            (ChatRole::Assistant, "streamed answer".to_string()),
        ],
        "the recorded transcript does not repeat the prompt"
    );
}

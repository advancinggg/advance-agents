//! ADR 2026-10-24 D4 — host-owned turn transcript (S1 / V1).
//!
//! Three guest `generate`s inside one stamped turn: every captured OpenAI
//! request body starts with the assembled identity prefix; request 3 carries
//! request 2's assistant `tool_calls` plus a matching tool-role message;
//! `transcript: fresh` carries neither.

use std::sync::Arc;

use advance_runtime::host_registry::{HostCallContext, HostFunctionHandler};
use advance_shared_types::context::LlmMessage;
use advance_shared_types::security_validator::HttpResponse;
use serde_json::Value;
use wasmtime::component::Val;

use crate::gateway::{ChatMessage, ChatResponse, ChatRole, ToolCall, TranscriptMode};
use crate::host_fn::AgentLlmGenerateHandler;
use crate::test_support::{test_gateway_with, MockEventBusEmit, MockHttpSecurityChain};

const AGENT: &str = "agent-transcript";
const TURN: &str = "turn-1";
const IDENTITY: &str = "IDENTITY-PREFIX-ROOT";

fn turn_ctx() -> HostCallContext {
    HostCallContext {
        agent_id: AGENT.into(),
        trace_id: "tr-transcript".into(),
        turn_id: Some(TURN.into()),
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
    let after = gw.build_guest_messages(AGENT, Some(TURN), "next", TranscriptMode::Continue);
    assert_eq!(after.len(), 2, "end_turn drops the transcript slot");
    assert_eq!(after[0].content, IDENTITY);
    assert_eq!(after[1].content, "next");
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

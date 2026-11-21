//! A Client API message's stream follows its whole turn. A client reads the reply of a
//! message on the one stream its status names. When the agent's first model call calls a
//! tool, the answer comes from the call after the tool result: it is on that stream too,
//! after the first call's text, and the stream ends once, with the turn's usage. An answer
//! that ends in what could begin a secret reads whole too: the hub holds that tail back only
//! until the stream's complete terminal (MODULE-020-T24-h).

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use advance_runtime_compose::test_support::fixture::ROOT_MAILBOX;
use advance_runtime_compose::test_support::LlmSecurityOverride;
use advance_shared_types::security_validator::{HttpRequest, HttpResponse, RedirectCheck};
use cap_http::{DefaultSsrfGuard, ExecutorError, HttpExecutor, MockResolver};
use serde_json::{json, Value};

#[path = "support/context_home.rs"]
mod context_home;
use context_home::is_extraction;

const HOST: &str = "llm.example.test";
const WAIT: Duration = Duration::from_secs(90);

const PROMPT: &str = "how many steps does the plan have?";
const PLAN: &str = "plan.md";
const PREAMBLE: &str = "Let me read the plan.";
const ANSWER: &str = "The plan has three steps.";
/// An answer whose end could begin a secret: on v0.1.58 the hub held it back for good.
const HELD_ANSWER: &str = "Three steps. Water the seedlings";
const DIGEST: &str = "The user asked how many steps the plan has.";
const READ_CALL_ID: &str = "call_read_plan";

/// The model service: the agent's request for [`PROMPT`] gets [`PREAMBLE`] and a call of
/// `read` on the plan; its request after the tool result gets `answer`. A turn-end
/// extraction gets a digest, any other request of the host (the L6 consolidation) a plain
/// answer, an embedding a vector.
struct Peer {
    answer: &'static str,
    /// The agent's own model requests (not the extractions), in order.
    agent_requests: Mutex<Vec<Value>>,
}

impl Peer {
    fn answering(answer: &'static str) -> Arc<Self> {
        Arc::new(Self {
            answer,
            agent_requests: Mutex::new(Vec::new()),
        })
    }

    fn security(self: &Arc<Self>) -> LlmSecurityOverride {
        let public = vec!["8.8.8.8".parse::<IpAddr>().expect("public address")];
        LlmSecurityOverride {
            ssrf: Arc::new(DefaultSsrfGuard::with_resolver(Box::new(
                MockResolver::new().with(HOST, public),
            ))),
            executor: Arc::clone(self) as Arc<dyn HttpExecutor>,
        }
    }
}

#[async_trait::async_trait]
impl HttpExecutor for Peer {
    async fn execute(
        &self,
        req: &HttpRequest,
        _redirect_check: Arc<dyn RedirectCheck>,
    ) -> Result<HttpResponse, ExecutorError> {
        let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        if req.url.ends_with("/v1/embeddings") {
            return Ok(json_response(
                json!({ "data": [{ "embedding": [0.6, 0.8] }] }),
            ));
        }
        if !req.url.ends_with("/v1/chat/completions") {
            return Ok(HttpResponse {
                status: 404,
                headers: Vec::new(),
                body: Vec::new(),
            });
        }
        if is_extraction(&body) {
            let digest = json!({ "digest": DIGEST, "knowledge": [], "descriptions": [] });
            return Ok(json_response(completion(json!({
                "role": "assistant",
                "content": digest.to_string()
            }))));
        }
        if !last_user(&body).contains(PROMPT) {
            return Ok(json_response(completion(json!({
                "role": "assistant",
                "content": "noted"
            }))));
        }
        let answered = answered_since_last_user(&body);
        self.agent_requests.lock().unwrap().push(body);
        Ok(json_response(if answered {
            completion(json!({ "role": "assistant", "content": self.answer }))
        } else {
            let arguments = json!({ "path": PLAN }).to_string();
            let mut call = completion(json!({
                "role": "assistant",
                "content": PREAMBLE,
                "tool_calls": [{
                    "id": READ_CALL_ID,
                    "type": "function",
                    "function": { "name": "read", "arguments": arguments }
                }]
            }));
            call["choices"][0]["finish_reason"] = json!("tool_calls");
            call["usage"] = json!({ "prompt_tokens": 12, "completion_tokens": 5 });
            call
        }))
    }
}

/// A chat completion answering `message`.
fn completion(message: Value) -> Value {
    json!({
        "id": "chatcmpl-scripted",
        "object": "chat.completion",
        "model": "scripted-model",
        "choices": [{ "index": 0, "message": message, "finish_reason": "stop" }],
        "usage": { "prompt_tokens": 20, "completion_tokens": 3 }
    })
}

fn json_response(body: Value) -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: serde_json::to_vec(&body).expect("response json"),
    }
}

/// The content of the last user message of a chat body.
fn last_user(body: &Value) -> String {
    body.get("messages")
        .and_then(Value::as_array)
        .and_then(|messages| {
            messages
                .iter()
                .rev()
                .find(|message| message.get("role").and_then(Value::as_str) == Some("user"))
        })
        .and_then(|message| message.get("content").and_then(Value::as_str))
        .unwrap_or_default()
        .to_string()
}

/// Whether a tool result follows the last user message of a chat body.
fn answered_since_last_user(body: &Value) -> bool {
    let messages = body
        .get("messages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let role = |message: &Value| {
        message
            .get("role")
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let last_user = messages
        .iter()
        .rposition(|message| role(message).as_deref() == Some("user"));
    messages[last_user.map_or(0, |i| i + 1)..]
        .iter()
        .any(|message| role(message).as_deref() == Some("tool"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tool_turns_answer_reaches_the_stream_its_message_names() {
    tool_turn_reads_whole(ANSWER).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_ending_in_a_held_start_reads_whole() {
    // The precondition: the wire layer's hold geometry holds this answer's tail.
    let held_from =
        cap_http::canonical_facade::decoded_hold_split(HELD_ANSWER.as_bytes(), 4 * 1024 * 1024)
            .expect("the hold geometry");
    assert!(
        held_from < HELD_ANSWER.len(),
        "{HELD_ANSWER:?} ends in a held start"
    );
    tool_turn_reads_whole(HELD_ANSWER).await;
}

/// A tool turn answering `answer`: the stream its message names reads both calls' text whole,
/// to its completed terminal.
async fn tool_turn_reads_whole(answer: &'static str) {
    let entry = format!(
        "  - id: main\n    endpoint: https://{HOST}\n    api-key-secret: main-api-key\n    model-aliases: {{ default: main-chat }}\n    cost-per-mtoken-in: 1.0\n    cost-per-mtoken-out: 2.0\n    rate-limit: {{ requests-per-minute: 1000, tokens-per-minute: 1000000 }}\n    embedding-model: main-embed\n"
    );
    let home = context_home::memory_home(
        false,
        &[],
        &[("main", entry, "main-key-value".to_string())],
        &["provider: main"],
    );
    std::fs::write(home.home().join(PLAN), "1. draft\n2. review\n3. ship\n").expect("the plan");
    let peer = Peer::answering(answer);
    context_home::serve(&home, peer.security(), WAIT, |client| {
        let peer = Arc::clone(&peer);
        async move {
            let id = client.send_message(ROOT_MAILBOX, PROMPT).await;
            let page = client.read_message_stream(&id).await;
            client.await_message_turn(&id).await;

            // The turn called `read`, then answered from its result.
            let requests = peer.agent_requests.lock().unwrap().clone();
            assert_eq!(requests.len(), 2, "{requests:#?}");
            assert!(answered_since_last_user(&requests[1]), "{:#?}", requests[1]);

            let text: String = page.deltas.iter().map(|item| item.text.as_str()).collect();
            assert_eq!(
                text,
                format!("{PREAMBLE}\n\n{answer}"),
                "both model calls of the turn, on the message's one stream"
            );
            assert_eq!(
                (page.dropped_count, page.rejected_count, page.redacted_count),
                (0, 0, 0)
            );
            let terminal = page
                .terminal
                .as_ref()
                .expect("the stream ended with its turn");
            assert_eq!(terminal.reason, "completed", "{terminal:?}");
            assert_eq!(
                Some(terminal.seq),
                page.deltas.last().map(|item| item.to_seq + 1),
                "the terminal follows the turn's last seq"
            );
            let usage = terminal
                .usage
                .as_ref()
                .expect("both calls settled with usage");
            assert_eq!(
                (usage.input_tokens, usage.output_tokens),
                (12 + 20, 5 + 3),
                "the turn's usage, both calls summed"
            );
        }
    })
    .await;
}

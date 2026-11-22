//! The context engine on a real home, through the production composition.
//!
//! Everything is `compose()` on a home whose root agent declares `memory`. The model is a
//! scripted peer standing in for the network inside the production LLM egress chain
//! (`ComposeFailpoints::llm_security`): credential injection, leak scan, rate limit and
//! events stay the production ones, and every request that leaves the home is recorded
//! with the host it was sent to.
//!
//! What an agent says goes only where that agent chats:
//! - A root agent pinned to one provider entry embeds its prompt and its turn digest ONLY
//!   on that entry, with that entry's embedding model — never on another
//!   embedding-capable entry, even one listed first — and its next turn recalls the first.
//! - A child agent pinned to another entry embeds on THAT entry, never on its parent's,
//!   and recalls only its own turns. The model call the host makes for it at the end of a
//!   turn (the memory extraction) is asked of the child's entry too: nothing that carries
//!   the child's text reaches the root's entry, and nothing of the root's reaches the
//!   child's.
//! - An entry that names no `embedding-model` (and is not OpenAI's own API) is never sent
//!   an embedding request: the turns run, their index rows are written, nothing is guessed.
//! - An agent whose `llm:` block leaves several entries open embeds on the entry that
//!   served its own request, even one listed after another that could embed — and nowhere
//!   before an entry has served it, which is the case again after every restart.
//! - A turn indexed while its agent could not embed gets its vector at a later turn end,
//!   once the agent chats on an entry that embeds, and is recalled from then on.
//! - Deleting an agent removes what the home's index holds under its id, and nothing of
//!   another agent.
//! - The prompt budget is the window of the model the agent chats on: the window its entry
//!   declares for that model, an edit of which applies from the next turn on; without one, a
//!   model of no known family gets the small-model fallback.
//! - Every turn is logged under its task (`.agent/tasks/active/<task>/llm-turns.jsonl`) — the
//!   prompt, each tool call, its result and each reply, one line each, numbered from 1 and
//!   never rewritten — and its turn-index entry locates it by line and records what it did:
//!   its tool use, the files it named, the version of each file it read, its collapsed view.
//!   A later turn that names one of those files is a reference to it.
//! - The next turns carry the last turns of the task whole — the prompt, each tool call, its
//!   result, the reply — until a file a turn read changes: that turn is then carried as its
//!   digest.
//!
//! A turn is awaited to its END — the reply and the whole turn-end pipeline — before
//! anything it sent is looked at, so no request it makes is missed.

use std::future::Future;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use advance_runtime_compose::test_support::fixture::{FixtureHome, ROOT_MAILBOX};
use advance_runtime_compose::test_support::LlmSecurityOverride;
use advance_shared_types::security_validator::{HttpRequest, HttpResponse, RedirectCheck};
use cap_http::{DefaultSsrfGuard, ExecutorError, HttpExecutor, MockResolver};
use cap_memory::{RusqliteSqliteIndex, SqliteIndex};
use serde_json::{json, Value};

#[path = "support/context_home.rs"]
mod context_home;
use context_home::{
    contents, give_child_the_default_driver, is_extraction, recalled_turns, recalls, text_of,
    Agent, Client,
};

/// The entry the root agent chats with.
const MAIN: &str = "main";
const MAIN_HOST: &str = "llm.example.test";
/// Another entry of the same home, which the root agent does not chat with.
const OTHER: &str = "other";
const OTHER_HOST: &str = "other.example.test";

/// The longest a scripted turn, with the turn-end pipeline after it, may take.
const WAIT: Duration = Duration::from_secs(90);

/// The id of the `read` call a scripted read makes.
const READ_CALL_ID: &str = "call_read_scripted";

// ---------------------------------------------------------------------------
// The scripted peer
// ---------------------------------------------------------------------------

/// One request that left the home.
#[derive(Clone, Debug)]
struct Sent {
    host: String,
    body: Value,
}

/// Serves `/v1/chat/completions` and `/v1/embeddings` on every host it is asked for and
/// records each request.
///
/// - The turn-end memory extraction (its system message names the
///   "memory-extraction assistant") of the turn a scripted prompt started is answered
///   with that prompt's digest, and with the fact scripted for that prompt if there is
///   one.
/// - Every other chat request is answered in text.
/// - Every embedding request is answered with the SAME vector, so any stored row is as
///   close as can be to any query: whether a row is recalled depends only on whether a
///   vector was stored and may be compared, never on ranking.
/// - The turn of a prompt scripted to read a file calls `read` on it in its first round and
///   answers with the scripted conclusion once the result is back.
struct Peer {
    /// `(prompt, the digest of its turn)`.
    turns: Vec<(&'static str, &'static str)>,
    /// `(prompt, a fact the extraction of its turn yields)`.
    facts: Vec<(&'static str, &'static str)>,
    /// `(prompt, the path its turn reads, the conclusion it answers with)`.
    reads: Vec<(&'static str, &'static str, &'static str)>,
    /// `(prompt, the paths its turn reads one after the other, the conclusion it answers
    /// with)`.
    loops: Vec<(&'static str, &'static [&'static str], &'static str)>,
    /// The prompts whose turn sees its first request after its last read refused as too
    /// long, as NEAR AI refuses it ([`NEAR_TOO_LONG`]).
    refuse_once: Mutex<Vec<&'static str>>,
    chats: Mutex<Vec<Sent>>,
    embeddings: Mutex<Vec<Sent>>,
}

impl Peer {
    fn new(turns: &[(&'static str, &'static str)]) -> Arc<Self> {
        Self::with_facts(turns, &[])
    }

    fn with_facts(
        turns: &[(&'static str, &'static str)],
        facts: &[(&'static str, &'static str)],
    ) -> Arc<Self> {
        Self::scripted(turns, facts, &[])
    }

    fn with_reads(
        turns: &[(&'static str, &'static str)],
        reads: &[(&'static str, &'static str, &'static str)],
    ) -> Arc<Self> {
        Self::scripted(turns, &[], reads)
    }

    fn scripted(
        turns: &[(&'static str, &'static str)],
        facts: &[(&'static str, &'static str)],
        reads: &[(&'static str, &'static str, &'static str)],
    ) -> Arc<Self> {
        Arc::new(Self {
            turns: turns.to_vec(),
            facts: facts.to_vec(),
            reads: reads.to_vec(),
            loops: Vec::new(),
            refuse_once: Mutex::new(Vec::new()),
            chats: Mutex::new(Vec::new()),
            embeddings: Mutex::new(Vec::new()),
        })
    }

    /// A peer whose `loops` prompts read several files one after the other, and whose
    /// `refuse_once` prompts see their first request after the last read refused as too long.
    fn with_read_loops(
        turns: &[(&'static str, &'static str)],
        reads: &[(&'static str, &'static str, &'static str)],
        loops: &[(&'static str, &'static [&'static str], &'static str)],
        refuse_once: &[&'static str],
    ) -> Arc<Self> {
        Arc::new(Self {
            turns: turns.to_vec(),
            facts: Vec::new(),
            reads: reads.to_vec(),
            loops: loops.to_vec(),
            refuse_once: Mutex::new(refuse_once.to_vec()),
            chats: Mutex::new(Vec::new()),
            embeddings: Mutex::new(Vec::new()),
        })
    }

    /// The answer of a `loops` turn to `sent`: its next read, the refusal as too long once,
    /// then its conclusion. `None` for any other request.
    fn read_loop_step(&self, sent: &Sent) -> Option<HttpResponse> {
        if is_extraction(&sent.body) {
            return None;
        }
        let (prompt, paths, conclusion) = self
            .loops
            .iter()
            .find(|(prompt, _, _)| last_user(&sent.body).contains(prompt))?;
        let done = results_since_last_user(&sent.body);
        if let Some(path) = paths.get(done) {
            return Some(json_response(
                200,
                read_call_as(&format!("call_read_{done}"), path),
            ));
        }
        let mut armed = self.refuse_once.lock().unwrap();
        if let Some(i) = armed.iter().position(|armed| armed == prompt) {
            armed.remove(i);
            return Some(HttpResponse {
                status: 400,
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: NEAR_TOO_LONG.as_bytes().to_vec(),
            });
        }
        Some(json_response(200, text_completion(conclusion)))
    }

    fn chats(&self) -> Vec<Sent> {
        self.chats.lock().unwrap().clone()
    }

    fn embeddings(&self) -> Vec<Sent> {
        self.embeddings.lock().unwrap().clone()
    }

    /// Every request so far — a model request, a turn-end extraction, an embedding —
    /// whose body carries `text`.
    fn carrying(&self, text: &str) -> Vec<Sent> {
        let mut sent = self.chats();
        sent.extend(self.embeddings());
        sent.retain(|sent| sent.body.to_string().contains(text));
        sent
    }

    /// The text of every embedding request so far.
    fn embedded_texts(&self) -> Vec<String> {
        self.embeddings()
            .iter()
            .map(|sent| text_of(&sent.body, "input"))
            .collect()
    }

    /// The agent's own model request (not the memory extraction) that carries `prompt`.
    fn turn_request(&self, prompt: &str) -> Sent {
        self.chats()
            .into_iter()
            .find(|sent| !is_extraction(&sent.body) && contents(&sent.body).contains(prompt))
            .unwrap_or_else(|| panic!("no model request carries {prompt:?}: {:#?}", self.chats()))
    }

    /// All message contents of [`Self::turn_request`], joined.
    fn turn_prompt(&self, prompt: &str) -> String {
        contents(&self.turn_request(prompt).body)
    }

    fn security(self: &Arc<Self>) -> LlmSecurityOverride {
        let public = vec!["8.8.8.8".parse::<IpAddr>().expect("public address")];
        let resolver = MockResolver::new()
            .with(MAIN_HOST, public.clone())
            .with(OTHER_HOST, public);
        LlmSecurityOverride {
            ssrf: Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver))),
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
        let rest = req.url.strip_prefix("https://").unwrap_or(&req.url);
        let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
        let sent = Sent {
            host: host.to_string(),
            body: serde_json::from_slice(&req.body).unwrap_or(Value::Null),
        };
        Ok(match path {
            "v1/embeddings" => {
                self.embeddings.lock().unwrap().push(sent);
                json_response(200, json!({ "data": [{ "embedding": [0.6, 0.8] }] }))
            }
            "v1/chat/completions" => {
                if let Some(response) = self.read_loop_step(&sent) {
                    self.chats.lock().unwrap().push(sent);
                    return Ok(response);
                }
                let read = self
                    .reads
                    .iter()
                    .filter(|_| !is_extraction(&sent.body))
                    .find(|(prompt, _, _)| last_user(&sent.body).contains(prompt));
                let content = if let Some((_, path, conclusion)) = read {
                    if !answered_since_last_user(&sent.body) {
                        self.chats.lock().unwrap().push(sent);
                        return Ok(json_response(200, read_call(path)));
                    }
                    conclusion.to_string()
                } else if is_extraction(&sent.body) {
                    let turn = contents(&sent.body);
                    let digest = self
                        .turns
                        .iter()
                        .find(|(prompt, _)| turn.contains(prompt))
                        .map_or("an unscripted turn", |(_, digest)| digest);
                    let knowledge: Vec<Value> = self
                        .facts
                        .iter()
                        .filter(|(prompt, _)| turn.contains(prompt))
                        .map(|(_, fact)| json!({ "content": fact, "kind": "fact" }))
                        .collect();
                    json!({ "digest": digest, "knowledge": knowledge, "descriptions": [] })
                        .to_string()
                } else {
                    "noted".to_string()
                };
                self.chats.lock().unwrap().push(sent);
                json_response(
                    200,
                    json!({
                        "id": "chatcmpl-scripted",
                        "object": "chat.completion",
                        "model": "scripted-model",
                        "choices": [{
                            "index": 0,
                            "message": { "role": "assistant", "content": content },
                            "finish_reason": "stop"
                        }],
                        "usage": { "prompt_tokens": 12, "completion_tokens": 3 }
                    }),
                )
            }
            _ => json_response(404, json!({ "error": { "message": "not scripted" } })),
        })
    }
}

fn json_response(status: u16, body: Value) -> HttpResponse {
    HttpResponse {
        status,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: serde_json::to_vec(&body).expect("response json"),
    }
}

/// The messages of a chat body.
fn messages_of(body: &Value) -> Vec<Value> {
    body.get("messages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// The content of the last user message of a chat body.
fn last_user(body: &Value) -> String {
    messages_of(body)
        .iter()
        .rev()
        .find(|message| message.get("role").and_then(Value::as_str) == Some("user"))
        .and_then(|message| message.get("content").and_then(Value::as_str))
        .unwrap_or_default()
        .to_string()
}

/// Whether a tool result follows the last user message of a chat body.
fn answered_since_last_user(body: &Value) -> bool {
    let messages = messages_of(body);
    let last_user = messages
        .iter()
        .rposition(|message| message.get("role").and_then(Value::as_str) == Some("user"));
    messages[last_user.map_or(0, |i| i + 1)..]
        .iter()
        .any(|message| message.get("role").and_then(Value::as_str) == Some("tool"))
}

/// How many tool results follow the last user message of a chat body.
fn results_since_last_user(body: &Value) -> usize {
    let messages = messages_of(body);
    let last_user = messages
        .iter()
        .rposition(|message| message.get("role").and_then(Value::as_str) == Some("user"));
    messages[last_user.map_or(0, |i| i + 1)..]
        .iter()
        .filter(|message| message.get("role").and_then(Value::as_str) == Some("tool"))
        .count()
}

/// A chat completion that answers `content`.
fn text_completion(content: &str) -> Value {
    json!({
        "id": "chatcmpl-scripted",
        "object": "chat.completion",
        "model": "scripted-model",
        "choices": [{
            "index": 0,
            "message": { "role": "assistant", "content": content },
            "finish_reason": "stop"
        }],
        "usage": { "prompt_tokens": 12, "completion_tokens": 3 }
    })
}

/// A chat completion that calls `read` on `path`.
fn read_call(path: &str) -> Value {
    read_call_as(READ_CALL_ID, path)
}

/// A chat completion that calls `read` on `path`, as the call `id`.
fn read_call_as(id: &str, path: &str) -> Value {
    json!({
        "id": "chatcmpl-read",
        "object": "chat.completion",
        "model": "scripted-model",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": id,
                    "type": "function",
                    "function": { "name": "read", "arguments": json!({ "path": path }).to_string() }
                }]
            },
            "finish_reason": "tool_calls"
        }],
        "usage": { "prompt_tokens": 12, "completion_tokens": 5 }
    })
}

// ---------------------------------------------------------------------------
// The home and the composition
// ---------------------------------------------------------------------------

/// One `llm-providers:` list item (openai-chat dialect, cloud-http) at `host`.
fn entry(id: &str, host: &str, extra_keys: &[&str]) -> String {
    let mut item = format!(
        "  - id: {id}\n    endpoint: https://{host}\n    api-key-secret: {id}-api-key\n    model-aliases: {{ default: {id}-chat }}\n    cost-per-mtoken-in: 1.0\n    cost-per-mtoken-out: 2.0\n    rate-limit: {{ requests-per-minute: 1000, tokens-per-minute: 1000000 }}\n"
    );
    for key in extra_keys {
        item.push_str(&format!("    {key}\n"));
    }
    item
}

/// A home whose root agent declares `fs` + `llm` + `memory` and `more`, runs the default
/// driver and has `entries` as its provider list. `agent_llm` is the agent's `llm:` block
/// body (one `key: value` per item), empty for none.
fn memory_home(
    more: &[&'static str],
    entries: &[(&str, String)],
    agent_llm: &[&str],
) -> FixtureHome {
    let entries: Vec<(&str, String, String)> = entries
        .iter()
        .map(|(id, item)| (*id, item.clone(), format!("{id}-key-value")))
        .collect();
    context_home::memory_home(false, more, &entries, agent_llm)
}

/// Compose `home` as the daemon does, with `peer` as the network of the LLM egress chain,
/// and run `body` against the live Client API ([`context_home::serve`]).
async fn serve<F, Fut>(home: &FixtureHome, peer: &Arc<Peer>, body: F)
where
    F: FnOnce(Client) -> Fut,
    Fut: Future<Output = ()>,
{
    context_home::serve(home, peer.security(), WAIT, body).await;
}

// ---------------------------------------------------------------------------
// Embedding follows the agent's chat provider
// ---------------------------------------------------------------------------

const FIRST_PROMPT: &str = "the launch codename is bluebird";
const SECOND_PROMPT: &str = "what is the launch codename?";
const THIRD_PROMPT: &str = "who chose the launch codename?";
const FOURTH_PROMPT: &str = "when is the launch?";
const FIRST_DIGEST: &str = "The user fixed the launch codename as bluebird.";
const SECOND_DIGEST: &str = "The user asked for the launch codename.";
const THIRD_DIGEST: &str = "The user asked who chose the launch codename.";
const FOURTH_DIGEST: &str = "The user asked for the launch date.";

/// The four scripted turns of the root agent.
const FOUR_TURNS: [(&str, &str); 4] = [
    (FIRST_PROMPT, FIRST_DIGEST),
    (SECOND_PROMPT, SECOND_DIGEST),
    (THIRD_PROMPT, THIRD_DIGEST),
    (FOURTH_PROMPT, FOURTH_DIGEST),
];

const RECALL_OFF: &str = "- recall: disabled (no embedding model is available to this agent)";

/// Each of `texts` was embedded, and every embedding request carrying one of them went
/// to `host` with `model`. (A digest is embedded with its turn and again in the brief of
/// its task, so a text may be carried by several requests.)
fn assert_embedded_only_on(peer: &Peer, texts: &[&str], host: &str, model: &str) {
    for text in texts {
        let carried: Vec<(String, String)> = peer
            .embeddings()
            .iter()
            .filter(|sent| text_of(&sent.body, "input").contains(text))
            .map(|sent| (sent.host.clone(), text_of(&sent.body, "model")))
            .collect();
        assert!(!carried.is_empty(), "{text:?} was embedded");
        for (sent_host, sent_model) in carried {
            assert_eq!(
                (sent_host.as_str(), sent_model.as_str()),
                (host, model),
                "an embedding of {text:?}"
            );
        }
    }
}

/// Each of `texts` left the home, and every request carrying one — the agent's own model
/// request, the extraction of its turn, an embedding — went to `host`.
fn assert_carried_only_to(peer: &Peer, texts: &[&str], host: &str) {
    for text in texts {
        let carried = peer.carrying(text);
        assert!(!carried.is_empty(), "{text:?} left the home");
        for sent in carried {
            assert_eq!(
                sent.host, host,
                "a request carrying {text:?}: {}",
                sent.body
            );
        }
    }
}

/// The hosts the turn-end extraction of the turn `prompt` started was asked of.
fn extraction_hosts(peer: &Peer, prompt: &str) -> Vec<String> {
    peer.chats()
        .iter()
        .filter(|sent| is_extraction(&sent.body) && contents(&sent.body).contains(prompt))
        .map(|sent| sent.host.clone())
        .collect()
}

/// Every embedding request so far carries one of `texts`: nothing else was embedded.
fn assert_nothing_else_embedded(peer: &Peer, texts: &[&str]) {
    for input in peer.embedded_texts() {
        assert!(
            texts.iter().any(|text| input.contains(text)),
            "an embedding of something else: {input:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pinned_agent_embeds_only_on_its_own_provider_and_recalls_its_earlier_turn() {
    // `other` is listed FIRST and serves embeddings too: an embedding that went to the
    // first embedding-capable entry of the list would land there.
    let home = memory_home(
        &[],
        &[
            (
                OTHER,
                entry(OTHER, OTHER_HOST, &["embedding-model: other-embed"]),
            ),
            (
                MAIN,
                entry(MAIN, MAIN_HOST, &["embedding-model: main-embed"]),
            ),
        ],
        &["provider: main"],
    );
    let peer = &Peer::new(&[(FIRST_PROMPT, FIRST_DIGEST), (SECOND_PROMPT, SECOND_DIGEST)]);
    serve(&home, peer, |client| async move {
        client.turn(ROOT_MAILBOX, FIRST_PROMPT).await;
        client.context_with_turns(Agent::Root, 1).await;
        let first = peer.turn_prompt(FIRST_PROMPT);
        assert!(
            !first.contains("# Recalled Context"),
            "nothing to recall on the first turn: {first}"
        );

        client.turn(ROOT_MAILBOX, SECOND_PROMPT).await;
        let context = client.context_with_turns(Agent::Root, 2).await;
        let second = peer.turn_prompt(SECOND_PROMPT);
        assert!(
            recalls(&second, FIRST_DIGEST),
            "the second turn recalls the first: {second}"
        );
        assert!(
            second.contains("- recall: semantic"),
            "the runtime section reports the live route: {second}"
        );

        // Both prompts were embedded for the query side and both digests for the index —
        // each on the agent's own entry, with that entry's model.
        let texts = [FIRST_PROMPT, FIRST_DIGEST, SECOND_PROMPT, SECOND_DIGEST];
        assert_embedded_only_on(peer, &texts, MAIN_HOST, "main-embed");
        assert_nothing_else_embedded(peer, &texts);
        // Nothing at all reached the entry the agent does not chat with.
        for sent in peer.embeddings().iter().chain(&peer.chats()) {
            assert_eq!(sent.host, MAIN_HOST, "a request left for {}", sent.host);
        }

        assert_eq!(
            context.pointer("/embedding/active"),
            Some(&json!(true)),
            "{context}"
        );
        assert_eq!(
            context.pointer("/embedding/model"),
            Some(&json!("main-embed")),
            "{context}"
        );
        assert_eq!(
            context.pointer("/latest/recall/attempted"),
            Some(&json!(true)),
            "{context}"
        );
        assert_eq!(
            context.pointer("/latest/recall/turns"),
            Some(&json!(1)),
            "{context}"
        );
    })
    .await;
}

const HELPER: &str = "helper";
const HELPER_MAILBOX: &str = "agent:helper";
const ROOT_PROMPT: &str = "the office door code is 4411";
const ROOT_DIGEST: &str = "The user gave the office door code.";
const ROOT_SECOND_PROMPT: &str = "who else has the office door code?";
const ROOT_SECOND_DIGEST: &str = "The user asked who else has the office door code.";
const HELPER_FIRST_PROMPT: &str = "the staging password rotates on fridays";
const HELPER_SECOND_PROMPT: &str = "when does the staging password rotate?";
const HELPER_FIRST_DIGEST: &str = "The user said the staging password rotates on Fridays.";
const HELPER_SECOND_DIGEST: &str = "The user asked when the staging password rotates.";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_child_agent_embeds_on_its_own_provider_not_on_its_parents() {
    // A child is served only on a home whose root declares `messaging`.
    let home = memory_home(
        &["messaging"],
        &[
            (
                MAIN,
                entry(MAIN, MAIN_HOST, &["embedding-model: main-embed"]),
            ),
            (
                OTHER,
                entry(OTHER, OTHER_HOST, &["embedding-model: other-embed"]),
            ),
        ],
        &["provider: main"],
    );
    let peer = &Peer::new(&[
        (ROOT_PROMPT, ROOT_DIGEST),
        (HELPER_FIRST_PROMPT, HELPER_FIRST_DIGEST),
        (HELPER_SECOND_PROMPT, HELPER_SECOND_DIGEST),
        (ROOT_SECOND_PROMPT, ROOT_SECOND_DIGEST),
    ]);

    // A child created over the Client API and pinned to the other entry. A built-in
    // template ships no driver, so the child is served from the next start, once a driver
    // is in its territory.
    serve(&home, peer, |client| async move {
        client
            .create_child(HELPER, &["fs", "llm", "memory"], OTHER)
            .await;
    })
    .await;
    give_child_the_default_driver(&home, HELPER);

    serve(&home, peer, |client| async move {
        client.turn(ROOT_MAILBOX, ROOT_PROMPT).await;
        client.context_with_turns(Agent::Root, 1).await;
        client.child_turn(HELPER_MAILBOX, HELPER_FIRST_PROMPT).await;
        client.context_with_turns(Agent::Child(HELPER), 1).await;
        client
            .child_turn(HELPER_MAILBOX, HELPER_SECOND_PROMPT)
            .await;
        let helper = client.context_with_turns(Agent::Child(HELPER), 2).await;
        // A turn of the root's after the child's: what the root reads at its turn — its
        // recall, its catch-up, its memory — has the child's rows in the index by now.
        client.turn(ROOT_MAILBOX, ROOT_SECOND_PROMPT).await;
        let root = client.context_with_turns(Agent::Root, 2).await;

        // Each agent's own model requests went to the entry it is pinned to.
        for prompt in [ROOT_PROMPT, ROOT_SECOND_PROMPT] {
            assert_eq!(peer.turn_request(prompt).host, MAIN_HOST, "{prompt:?}");
        }
        for prompt in [HELPER_FIRST_PROMPT, HELPER_SECOND_PROMPT] {
            assert_eq!(peer.turn_request(prompt).host, OTHER_HOST, "{prompt:?}");
        }

        // So did its embeddings — the prompt (query side) and the digest (index side).
        let of_root = [
            ROOT_PROMPT,
            ROOT_DIGEST,
            ROOT_SECOND_PROMPT,
            ROOT_SECOND_DIGEST,
        ];
        let of_helper = [
            HELPER_FIRST_PROMPT,
            HELPER_FIRST_DIGEST,
            HELPER_SECOND_PROMPT,
            HELPER_SECOND_DIGEST,
        ];
        assert_embedded_only_on(peer, &of_root, MAIN_HOST, "main-embed");
        assert_embedded_only_on(peer, &of_helper, OTHER_HOST, "other-embed");
        assert_nothing_else_embedded(peer, &[of_root.as_slice(), &of_helper].concat());

        // And so did the model call the host makes for it at the end of each turn: the
        // extraction of a child's turn is asked of the child's entry, not of the root's.
        for prompt in [ROOT_PROMPT, ROOT_SECOND_PROMPT] {
            assert_eq!(extraction_hosts(peer, prompt), [MAIN_HOST], "{prompt:?}");
        }
        for prompt in [HELPER_FIRST_PROMPT, HELPER_SECOND_PROMPT] {
            assert_eq!(extraction_hosts(peer, prompt), [OTHER_HOST], "{prompt:?}");
        }
        // Nothing that carries an agent's text reached the other agent's entry.
        assert_carried_only_to(peer, &of_root, MAIN_HOST);
        assert_carried_only_to(peer, &of_helper, OTHER_HOST);

        // The child recalls its own earlier turn, and nothing of its parent's.
        let second = peer.turn_prompt(HELPER_SECOND_PROMPT);
        assert!(
            recalls(&second, HELPER_FIRST_DIGEST),
            "the child's second turn recalls its first: {second}"
        );
        assert!(
            !second.contains(ROOT_DIGEST),
            "the parent's turn is not the child's to recall: {second}"
        );
        // Nor the child's the parent's.
        let root_second = peer.turn_prompt(ROOT_SECOND_PROMPT);
        for digest in [HELPER_FIRST_DIGEST, HELPER_SECOND_DIGEST] {
            assert!(
                !root_second.contains(digest),
                "the child's turn is not the parent's to recall: {root_second}"
            );
        }

        assert_eq!(
            helper.pointer("/embedding/model"),
            Some(&json!("other-embed")),
            "{helper}"
        );
        assert_eq!(
            helper.pointer("/latest/recall/turns"),
            Some(&json!(1)),
            "{helper}"
        );
        assert_eq!(
            root.pointer("/embedding/model"),
            Some(&json!("main-embed")),
            "{root}"
        );
        assert_eq!(root.pointer("/index/turns"), Some(&json!(2)), "{root}");
    })
    .await;
}

/// Two agents of one home on one entry, and so on one embedding model: every vector of
/// one may be compared with every vector of the other, and the peer gives every text the
/// same vector, so the other's rows are as close to a query as the agent's own. Each still
/// recalls its own turns and none of the other's — recall is the agent's, not only the
/// model's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agents_on_one_embedding_model_recall_only_their_own_turns() {
    let home = memory_home(
        &["messaging"],
        &[(
            MAIN,
            entry(MAIN, MAIN_HOST, &["embedding-model: main-embed"]),
        )],
        &["provider: main"],
    );
    let peer = &Peer::new(&[
        (ROOT_PROMPT, ROOT_DIGEST),
        (HELPER_FIRST_PROMPT, HELPER_FIRST_DIGEST),
        (HELPER_SECOND_PROMPT, HELPER_SECOND_DIGEST),
        (ROOT_SECOND_PROMPT, ROOT_SECOND_DIGEST),
    ]);
    serve(&home, peer, |client| async move {
        client
            .create_child(HELPER, &["fs", "llm", "memory"], MAIN)
            .await;
    })
    .await;
    give_child_the_default_driver(&home, HELPER);

    serve(&home, peer, |client| async move {
        client.turn(ROOT_MAILBOX, ROOT_PROMPT).await;
        client.context_with_turns(Agent::Root, 1).await;
        client.child_turn(HELPER_MAILBOX, HELPER_FIRST_PROMPT).await;
        client.context_with_turns(Agent::Child(HELPER), 1).await;
        client
            .child_turn(HELPER_MAILBOX, HELPER_SECOND_PROMPT)
            .await;
        client.context_with_turns(Agent::Child(HELPER), 2).await;
        client.turn(ROOT_MAILBOX, ROOT_SECOND_PROMPT).await;
        client.context_with_turns(Agent::Root, 2).await;

        // Everything of both was embedded on the one entry, by the one model.
        let texts = [
            ROOT_PROMPT,
            ROOT_DIGEST,
            HELPER_FIRST_PROMPT,
            HELPER_FIRST_DIGEST,
            HELPER_SECOND_PROMPT,
            HELPER_SECOND_DIGEST,
            ROOT_SECOND_PROMPT,
            ROOT_SECOND_DIGEST,
        ];
        assert_embedded_only_on(peer, &texts, MAIN_HOST, "main-embed");

        // Each recalls its own earlier turn ...
        let helper_second = peer.turn_prompt(HELPER_SECOND_PROMPT);
        assert!(
            recalls(&helper_second, HELPER_FIRST_DIGEST),
            "the child's second turn recalls its first: {helper_second}"
        );
        let root_second = peer.turn_prompt(ROOT_SECOND_PROMPT);
        assert!(
            recalls(&root_second, ROOT_DIGEST),
            "the root's second turn recalls its first: {root_second}"
        );
        // ... and nothing of the other's.
        assert!(
            !helper_second.contains(ROOT_DIGEST),
            "the parent's turn is not the child's to recall: {helper_second}"
        );
        for digest in [HELPER_FIRST_DIGEST, HELPER_SECOND_DIGEST] {
            assert!(
                !root_second.contains(digest),
                "the child's turn is not the parent's to recall: {root_second}"
            );
        }
    })
    .await;
}

/// The fact the extraction of the helper's first turn yields: a memory row of the helper.
const HELPER_FACT: &str = "The staging password rotates every Friday.";

/// Deleting an agent removes what the home's index holds under its id — the digests of
/// its turns, the briefs of its tasks, their vectors, its memory rows — and what the
/// gateway noted of it (the entry that served it), and nothing of another agent. (The
/// index is the home's, not the agent's territory: it outlives the agent's `.agent/`.)
///
/// The helper is pinned to no entry and the home has two, so the entry it chats with is
/// known only from the one that served it: while that record stands the gateway can
/// name the helper's embedding route, and once it is gone it cannot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deleted_agent_leaves_no_rows_in_the_homes_index() {
    let home = memory_home(
        &["messaging"],
        &[
            (
                MAIN,
                entry(MAIN, MAIN_HOST, &["embedding-model: main-embed"]),
            ),
            (
                OTHER,
                entry(OTHER, OTHER_HOST, &["embedding-model: other-embed"]),
            ),
        ],
        &["provider: main"],
    );
    let peer = &Peer::with_facts(
        &[
            (ROOT_PROMPT, ROOT_DIGEST),
            (HELPER_FIRST_PROMPT, HELPER_FIRST_DIGEST),
        ],
        &[(HELPER_FIRST_PROMPT, HELPER_FACT)],
    );
    serve(&home, peer, |client| async move {
        client
            .create_unpinned_child(HELPER, &["fs", "llm", "memory"])
            .await;
    })
    .await;
    give_child_the_default_driver(&home, HELPER);
    let index_path = home.home().join(".agent/memory/index.sqlite");

    let ids = Arc::new(Mutex::new(None));
    let noted = ids.clone();
    let index_file = index_path.clone();
    serve(&home, peer, |client| async move {
        client.turn(ROOT_MAILBOX, ROOT_PROMPT).await;
        client.context_with_turns(Agent::Root, 1).await;
        client.child_turn(HELPER_MAILBOX, HELPER_FIRST_PROMPT).await;
        let helper = client.context_with_turns(Agent::Child(HELPER), 1).await;
        assert_eq!(helper.pointer("/index/tasks"), Some(&json!(1)), "{helper}");
        let root_id = client.listed_id(Agent::Root).await.expect("the root");
        let helper_id = client
            .listed_id(Agent::Child(HELPER))
            .await
            .expect("the helper");
        // Before the delete: the helper's memory row is in the index, and the gateway
        // knows the entry that served it.
        let live = RusqliteSqliteIndex::open(&index_file).expect("the home's index");
        assert!(
            !live.list_memory_for_agent(&helper_id).is_empty(),
            "the helper's fact has its memory row"
        );
        drop(live);
        let gateway = client.gateway();
        assert!(
            gateway.embedding_route_for(&helper_id).is_ok(),
            "the entry that served the helper is known"
        );

        client.delete_child(HELPER).await;
        assert_eq!(client.listed_id(Agent::Child(HELPER)).await, None);
        assert_eq!(
            client
                .status_of(&format!("/client/agents/{helper_id}/context"))
                .await,
            404,
            "the context of a deleted agent"
        );
        assert!(
            matches!(
                gateway.embedding_route_for(&helper_id),
                Err(cap_llm::EmbeddingUnavailable::ChatProviderUnknown)
            ),
            "the gateway still knows the entry that served the deleted agent: {:?}",
            gateway
                .embedding_route_for(&helper_id)
                .map(|route| route.model)
        );
        assert_eq!(
            gateway
                .embedding_route_for(&root_id)
                .map(|route| route.model)
                .ok(),
            Some("main-embed".to_string()),
            "the root's route is the root's"
        );
        *noted.lock().unwrap() = Some((root_id, helper_id));
    })
    .await;

    // The composition is shut down — the last pass over the helper's records with it:
    // read the home's index as it is on disk.
    let (root_id, helper_id) = ids.lock().unwrap().clone().expect("the ids were noted");
    let index = RusqliteSqliteIndex::open(&index_path).expect("the home's index");
    assert!(
        index.list_turns_for_agent(&helper_id).is_empty(),
        "turn rows of the deleted agent"
    );
    assert!(
        index.list_tasks_for_agent(&helper_id).is_empty(),
        "task rows of the deleted agent"
    );
    assert!(
        index.list_memory_for_agent(&helper_id).is_empty(),
        "memory rows of the deleted agent"
    );
    assert_eq!(index.list_turns_for_agent(&root_id).len(), 1);
    assert_eq!(index.list_tasks_for_agent(&root_id).len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_entry_without_an_embedding_model_is_never_sent_an_embedding_request() {
    // An OpenAI-compatible endpoint that is not OpenAI's own API, with no
    // `embedding-model`: no model id is guessed for it.
    let home = memory_home(&[], &[(MAIN, entry(MAIN, MAIN_HOST, &[]))], &[]);
    let peer = &Peer::new(&[(FIRST_PROMPT, FIRST_DIGEST), (SECOND_PROMPT, SECOND_DIGEST)]);
    serve(&home, peer, |client| async move {
        client.turn(ROOT_MAILBOX, FIRST_PROMPT).await;
        client.context_with_turns(Agent::Root, 1).await;
        client.turn(ROOT_MAILBOX, SECOND_PROMPT).await;
        let context = client.context_with_turns(Agent::Root, 2).await;

        assert!(
            peer.embeddings().is_empty(),
            "no embedding request may be made: {:#?}",
            peer.embeddings()
        );
        let second = peer.turn_prompt(SECOND_PROMPT);
        assert!(!second.contains("# Recalled Context"), "{second}");
        assert!(second.contains(RECALL_OFF), "{second}");
        assert_eq!(
            context.pointer("/embedding/active"),
            Some(&json!(false)),
            "{context}"
        );
        assert_eq!(context.pointer("/embedding/model"), None, "{context}");
        assert_eq!(
            context.pointer("/latest/recall/attempted"),
            Some(&json!(false)),
            "{context}"
        );
        // The turns were extracted and indexed all the same: both digests were asked for.
        assert_eq!(
            peer.chats()
                .iter()
                .filter(|sent| is_extraction(&sent.body))
                .count(),
            2
        );
    })
    .await;
}

/// No request so far — a model request, an extraction, an embedding — went anywhere but
/// to `host`.
fn assert_everything_went_to(peer: &Peer, host: &str) {
    for sent in peer.embeddings().iter().chain(&peer.chats()) {
        assert_eq!(sent.host, host, "a request left for {}", sent.host);
    }
}

/// Whether `prompt` was sent for embedding as a recall query: alone. A turn's own
/// vector quotes its prompt too, in the turn's collapsed view after its digest (PRD
/// §11.3, the L1 layer), so a mention inside another text is no query.
fn embedded_as_query(peer: &Peer, prompt: &str) -> bool {
    peer.embedded_texts().iter().any(|input| input == prompt)
}

/// `prompt` was never sent for embedding as a recall query.
fn assert_not_embedded(peer: &Peer, prompt: &str) {
    assert!(
        !embedded_as_query(peer, prompt),
        "{prompt:?} was sent for embedding: {:#?}",
        peer.embeddings()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_agent_free_to_chat_on_several_entries_embeds_where_it_is_served() {
    // The agent's `llm:` block names a model and no provider: both entries stay open to
    // it, and each of its requests is placed by that model — on `main`, which is listed
    // SECOND. `other`, listed first, serves embeddings too: an embedding sent to the
    // first embedding-capable entry of the list would land there.
    let home = memory_home(
        &[],
        &[
            (
                OTHER,
                entry(OTHER, OTHER_HOST, &["embedding-model: other-embed"]),
            ),
            (
                MAIN,
                entry(MAIN, MAIN_HOST, &["embedding-model: main-embed"]),
            ),
        ],
        &["model: main-chat"],
    );
    let peer = &Peer::new(&FOUR_TURNS);
    serve(&home, peer, |client| async move {
        client.turn(ROOT_MAILBOX, FIRST_PROMPT).await;
        client.context_with_turns(Agent::Root, 1).await;
        assert_eq!(peer.turn_request(FIRST_PROMPT).host, MAIN_HOST);

        // Until an entry has served the agent nobody can say where it chats: its first
        // prompt was embedded nowhere, and the turn was told that recall is off.
        assert_not_embedded(peer, FIRST_PROMPT);
        let first = peer.turn_prompt(FIRST_PROMPT);
        assert!(first.contains(RECALL_OFF), "{first}");

        client.turn(ROOT_MAILBOX, SECOND_PROMPT).await;
        let context = client.context_with_turns(Agent::Root, 2).await;
        let second = peer.turn_prompt(SECOND_PROMPT);
        assert!(
            recalls(&second, FIRST_DIGEST),
            "the second turn recalls the first: {second}"
        );
        assert!(second.contains("- recall: semantic"), "{second}");
        // The second prompt was embedded as a query (the form the checks above and below
        // look for), and the first turn's own vector quotes its prompt in its view.
        assert!(
            embedded_as_query(peer, SECOND_PROMPT),
            "{:#?}",
            peer.embeddings()
        );
        let quoted = format!("[user] \"{FIRST_PROMPT}\"");
        assert!(
            peer.embedded_texts()
                .iter()
                .any(|input| input.starts_with(FIRST_DIGEST) && input.contains(&quoted)),
            "{:#?}",
            peer.embeddings()
        );

        // From its first reply on, everything of the agent's goes where it was served:
        // the digest of the first turn, the second prompt, the second digest, and the
        // extraction of both turns.
        let embedded = [FIRST_DIGEST, SECOND_PROMPT, SECOND_DIGEST];
        assert_embedded_only_on(peer, &embedded, MAIN_HOST, "main-embed");
        assert_nothing_else_embedded(peer, &embedded);
        for prompt in [FIRST_PROMPT, SECOND_PROMPT] {
            assert_eq!(extraction_hosts(peer, prompt), [MAIN_HOST], "{prompt:?}");
        }
        assert_everything_went_to(peer, MAIN_HOST);

        assert_eq!(
            context.pointer("/embedding/model"),
            Some(&json!("main-embed")),
            "{context}"
        );
        assert_eq!(
            context.pointer("/latest/recall/turns"),
            Some(&json!(1)),
            "{context}"
        );
    })
    .await;

    // A restart forgets where the agent was served. Its first prompt after the start is
    // embedded nowhere again; from its first reply on it embeds where it was served, and
    // the turns indexed before the restart are recalled as before.
    serve(&home, peer, |client| async move {
        let context = client.context(Agent::Root).await;
        assert_eq!(
            context.pointer("/embedding/active"),
            Some(&json!(false)),
            "no entry has served the agent since the start: {context}"
        );

        client.turn(ROOT_MAILBOX, THIRD_PROMPT).await;
        client.context_with_turns(Agent::Root, 3).await;
        assert_not_embedded(peer, THIRD_PROMPT);
        let third = peer.turn_prompt(THIRD_PROMPT);
        assert!(third.contains(RECALL_OFF), "{third}");
        assert!(!third.contains("# Recalled Context"), "{third}");

        client.turn(ROOT_MAILBOX, FOURTH_PROMPT).await;
        let context = client.context_with_turns(Agent::Root, 4).await;
        let fourth = peer.turn_prompt(FOURTH_PROMPT);
        for digest in [FIRST_DIGEST, SECOND_DIGEST, THIRD_DIGEST] {
            assert!(
                recalls(&fourth, digest),
                "the fourth turn recalls {digest:?}: {fourth}"
            );
        }
        assert_embedded_only_on(
            peer,
            &[THIRD_DIGEST, FOURTH_PROMPT, FOURTH_DIGEST],
            MAIN_HOST,
            "main-embed",
        );
        assert_everything_went_to(peer, MAIN_HOST);
        assert_eq!(
            context.pointer("/latest/recall/turns"),
            Some(&json!(3)),
            "{context}"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_turn_indexed_without_a_vector_gets_one_once_the_agent_can_embed() {
    // The agent starts on an entry that serves no embeddings.
    let home = memory_home(
        &[],
        &[
            (OTHER, entry(OTHER, OTHER_HOST, &[])),
            (
                MAIN,
                entry(MAIN, MAIN_HOST, &["embedding-model: main-embed"]),
            ),
        ],
        &["provider: other"],
    );
    let peer = &Peer::new(&FOUR_TURNS);
    serve(&home, peer, |client| async move {
        client.turn(ROOT_MAILBOX, FIRST_PROMPT).await;
        client.context_with_turns(Agent::Root, 1).await;
        assert!(
            peer.embeddings().is_empty(),
            "the first turn is indexed without a vector: {:#?}",
            peer.embeddings()
        );

        // The agent moves to an entry that embeds. The move applies to its next turn.
        client.pin_root(MAIN).await;
        client.turn(ROOT_MAILBOX, SECOND_PROMPT).await;
        client.context_with_turns(Agent::Root, 2).await;
        let second = peer.turn_prompt(SECOND_PROMPT);
        assert!(second.contains("- recall: semantic"), "{second}");
        assert_eq!(
            recalled_turns(&second),
            Vec::<&str>::new(),
            "the first turn had no vector when the second was assembled: {second}"
        );

        // The end of the second turn embedded the first turn's digest as well, so the
        // third turn recalls both.
        client.turn(ROOT_MAILBOX, THIRD_PROMPT).await;
        let context = client.context_with_turns(Agent::Root, 3).await;
        let third = peer.turn_prompt(THIRD_PROMPT);
        for digest in [FIRST_DIGEST, SECOND_DIGEST] {
            assert!(
                recalls(&third, digest),
                "the third turn recalls {digest:?}: {third}"
            );
        }
        assert_eq!(recalled_turns(&third).len(), 2, "{third}");
        assert_eq!(
            context.pointer("/latest/recall/turns"),
            Some(&json!(2)),
            "{context}"
        );

        // Every embedding was asked of the entry the agent chats on now — the first
        // turn's digest too — and none of the entry it left.
        assert_embedded_only_on(
            peer,
            &[FIRST_DIGEST, SECOND_PROMPT, SECOND_DIGEST, THIRD_PROMPT],
            MAIN_HOST,
            "main-embed",
        );
        for sent in peer.embeddings() {
            assert_eq!(sent.host, MAIN_HOST, "an embedding left for {}", sent.host);
        }
        assert_not_embedded(peer, FIRST_PROMPT);
    })
    .await;
}

/// The knowledge a deleted agent learned is kept, as history, and its parent takes it over
/// (owner decision 2026-11-17). On the production terminate path the fact the helper's turn
/// extracted, held under the helper's id, ends under the root's — naming the helper — and
/// the helper's id holds no knowledge, as the composition leaves the home on disk. The root
/// recalls it, and its memory rows mirror it once its next turn has ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deleted_agent_hands_its_knowledge_over_to_its_parent() {
    let home = memory_home(
        &["messaging"],
        &[(
            MAIN,
            entry(MAIN, MAIN_HOST, &["embedding-model: main-embed"]),
        )],
        &["provider: main"],
    );
    let peer = &Peer::with_facts(
        &[
            (ROOT_PROMPT, ROOT_DIGEST),
            (HELPER_FIRST_PROMPT, HELPER_FIRST_DIGEST),
        ],
        &[(HELPER_FIRST_PROMPT, HELPER_FACT)],
    );
    serve(&home, peer, |client| async move {
        client
            .create_unpinned_child(HELPER, &["fs", "llm", "memory"])
            .await;
    })
    .await;
    give_child_the_default_driver(&home, HELPER);
    let memory_root = home.home().join(".agent/memory");

    let ids = Arc::new(Mutex::new(None));
    let noted = ids.clone();
    let knowledge_dir = memory_root.clone();
    serve(&home, peer, |client| async move {
        client.child_turn(HELPER_MAILBOX, HELPER_FIRST_PROMPT).await;
        client.context_with_turns(Agent::Child(HELPER), 1).await;
        let root_id = client.listed_id(Agent::Root).await.expect("the root");
        let helper_id = client
            .listed_id(Agent::Child(HELPER))
            .await
            .expect("the helper");
        // Before the delete: the helper's turn left its fact under the helper's id.
        let helper_file = knowledge_dir
            .join(cap_memory::persistence::slug(&helper_id))
            .join(cap_memory::persistence::KNOWLEDGE_JSONL_FILENAME);
        let held = std::fs::read_to_string(&helper_file).unwrap_or_default();
        assert!(
            held.contains(HELPER_FACT),
            "the helper's fact is held under its id: {held}"
        );

        client.delete_child(HELPER).await;
        assert_eq!(client.listed_id(Agent::Child(HELPER)).await, None);
        // The root's next turn ends: its memory rows mirror what it took over.
        client.turn(ROOT_MAILBOX, ROOT_PROMPT).await;
        client.context_with_turns(Agent::Root, 1).await;
        *noted.lock().unwrap() = Some((root_id, helper_id));
    })
    .await;

    // The composition is shut down, its last pass over the helper's records with it: read
    // the home's knowledge as it is on disk.
    let (root_id, helper_id) = ids.lock().unwrap().clone().expect("the ids were noted");
    let store =
        cap_memory::MemoryStore::open(&memory_root, cap_memory::DEFAULT_MAX_ACTIVE_PER_AGENT)
            .expect("the home's knowledge");
    assert!(
        store.list(&helper_id).is_empty(),
        "the deleted agent's id holds no knowledge: {:?}",
        store.list(&helper_id)
    );
    let taken: Vec<cap_memory::MemoryEntry> = store
        .list(&root_id)
        .into_iter()
        .filter(|entry| entry.content.contains(HELPER_FACT))
        .collect();
    assert_eq!(
        taken.len(),
        1,
        "the root holds the helper's fact, once: {:?}",
        store.list(&root_id)
    );
    assert_eq!(taken[0].agent_id, root_id);
    assert!(
        taken[0]
            .tags
            .contains(&format!("{}{helper_id}", cap_memory::FROM_AGENT_TAG_PREFIX)),
        "the fact names the agent it came from: {:?}",
        taken[0].tags
    );
    assert!(taken[0].is_active, "it is the root's knowledge now");
    // The root recalls it as its own — what a guest's `recall` serves from
    // (`MemoryStore::recall`) —, and the deleted helper's id recalls nothing.
    let recalled: Vec<String> = store
        .recall(&root_id, "staging password", 10)
        .into_iter()
        .map(|entry| entry.id)
        .collect();
    assert!(
        recalled.contains(&taken[0].id),
        "the root recalls the helper's fact: {recalled:?}"
    );
    assert!(store.recall(&helper_id, "staging password", 10).is_empty());
    // The root's memory rows mirror it since its turn ended; the deleted helper has none.
    let index = RusqliteSqliteIndex::open(&home.home().join(".agent/memory/index.sqlite"))
        .expect("the home's index");
    let rows: Vec<String> = index
        .list_memory_for_agent(&root_id)
        .into_iter()
        .map(|row| row.memory_id)
        .collect();
    assert!(
        rows.contains(&taken[0].id),
        "the root's memory rows mirror the fact it took over: {rows:?}"
    );
    assert!(index.list_memory_for_agent(&helper_id).is_empty());
}

// ---------------------------------------------------------------------------
// The budget follows the model the agent chats on
// ---------------------------------------------------------------------------

const GARDEN_PROMPT: &str = "the greenhouse is watered on tuesdays";
const GARDEN_SECOND_PROMPT: &str = "which day is the greenhouse watered?";
const GARDEN_THIRD_PROMPT: &str = "who waters the greenhouse?";

/// The latest assembly of the root agent's context, once its index holds `turns` turns.
async fn latest_assembly(client: &context_home::Client, turns: u64) -> Value {
    let context = client.context_with_turns(Agent::Root, turns).await;
    context
        .get("latest")
        .cloned()
        .unwrap_or_else(|| panic!("no assembly recorded: {context}"))
}

/// Wait until the running config gives the root agent `window` for the model it chats on:
/// the config watcher has applied an edit of the provider list.
async fn wait_for_root_window(client: &context_home::Client, window: Option<u32>) {
    let deadline = Instant::now() + WAIT;
    loop {
        let live = client
            .gateway()
            .chat_model_for("root")
            .and_then(|model| model.window)
            .map(|(tokens, _)| tokens);
        if live == window {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the root agent's window is still {live:?}, not {window:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_budget_is_the_window_of_the_model_the_agent_chats_on() {
    let home = memory_home(
        &[],
        &[(
            MAIN,
            entry(
                MAIN,
                MAIN_HOST,
                &["model-context-windows: { main-chat: 1048576 }"],
            ),
        )],
        &["provider: main"],
    );
    let peer = &Peer::new(&[]);
    serve(&home, peer, |client| async move {
        // The window the agent's entry declares for the model it chats on.
        client.turn(ROOT_MAILBOX, GARDEN_PROMPT).await;
        let latest = latest_assembly(&client, 1).await;
        assert_eq!(latest["model_provider"], json!(MAIN), "{latest}");
        assert_eq!(latest["model"], json!("main-chat"), "{latest}");
        assert_eq!(latest["model_context_window"], json!(1_048_576), "{latest}");
        assert_eq!(latest["model_window_source"], json!("provider"), "{latest}");
        assert_eq!(latest["response_reserve"], json!(30_000), "{latest}");
        assert_eq!(latest["budget_tokens"], json!(1_018_576), "{latest}");
        let prompt = peer.turn_prompt(GARDEN_PROMPT);
        assert!(prompt.contains("- llm: main / main-chat\n"), "{prompt}");
        assert!(
            prompt.contains("- context window: 1048576 tokens (prompt budget 1018576)\n"),
            "{prompt}"
        );

        // An edit of the entry applies from the next turn on, with nothing restarted.
        client
            .update_provider(
                MAIN,
                json!({ "model_context_windows": { "main-chat": 200_000 } }),
            )
            .await;
        wait_for_root_window(&client, Some(200_000)).await;
        client.turn(ROOT_MAILBOX, GARDEN_SECOND_PROMPT).await;
        let latest = latest_assembly(&client, 2).await;
        assert_eq!(latest["model_context_window"], json!(200_000), "{latest}");
        assert_eq!(latest["model_window_source"], json!("provider"), "{latest}");
        assert_eq!(latest["budget_tokens"], json!(170_000), "{latest}");

        // Without a declared window, a model of no known family gets the small-model
        // fallback — still on the agent's own entry.
        client
            .update_provider(MAIN, json!({ "model_context_windows": {} }))
            .await;
        wait_for_root_window(&client, None).await;
        client.turn(ROOT_MAILBOX, GARDEN_THIRD_PROMPT).await;
        let latest = latest_assembly(&client, 3).await;
        assert_eq!(latest["model_provider"], json!(MAIN), "{latest}");
        assert_eq!(latest["model_context_window"], json!(8_192), "{latest}");
        assert_eq!(latest["model_window_source"], json!("fallback"), "{latest}");
    })
    .await;
}

// ---------------------------------------------------------------------------
// Every turn is logged under its task, and indexed by line
// ---------------------------------------------------------------------------

const PLAN_PATH: &str = "notes/plan.md";
const PLAN_TEXT: &str = "Step one: water the seedlings.\nStep two: label the trays.\n";
/// `git hash-object` of [`PLAN_TEXT`].
const PLAN_BLOB: &str = "eea8a7d39d0a25fd06266426aefcacca83d9ebb1";
const PLAN_PROMPT: &str = "read the greenhouse plan";
const PLAN_DIGEST: &str = "The user asked for the greenhouse plan.";
const PLAN_CONCLUSION: &str = "The plan has two steps. Watering comes first.";
const PLAN_FOLLOW_UP: &str = "is notes/plan.md still current?";
const PLAN_FOLLOW_UP_DIGEST: &str = "The user asked whether the plan is current.";

/// The root agent's one task directory, `.agent/tasks/active/<task>`.
fn root_task_dir(home: &FixtureHome) -> PathBuf {
    let active = home.home().join(".agent/tasks/active");
    let dirs: Vec<PathBuf> = std::fs::read_dir(&active)
        .unwrap_or_else(|e| panic!("{active:?}: {e}"))
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| path.is_dir())
        .collect();
    assert_eq!(dirs.len(), 1, "one task directory: {dirs:?}");
    dirs[0].clone()
}

/// Every line of the task's turn log, parsed.
fn turn_log(dir: &Path) -> Vec<Value> {
    std::fs::read_to_string(dir.join("llm-turns.jsonl"))
        .expect("the turn log")
        .lines()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("{line}: {e}")))
        .collect()
}

/// The entries of the task's turn index.
fn turn_entries(dir: &Path) -> Vec<Value> {
    let yaml = std::fs::read_to_string(dir.join("turn-index.yaml")).expect("the turn index");
    let index: Value = serde_yml::from_str(&yaml).expect("the turn index parses");
    index["turns"].as_array().cloned().unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn turns_are_logged_under_their_task_and_indexed_by_line() {
    let home = memory_home(
        &[],
        &[(MAIN, entry(MAIN, MAIN_HOST, &[]))],
        &["provider: main"],
    );
    let plan = home.home().join(PLAN_PATH);
    std::fs::create_dir_all(plan.parent().expect("a parent")).expect("the notes directory");
    std::fs::write(&plan, PLAN_TEXT).expect("the plan");
    let peer = &Peer::with_reads(
        &[
            (PLAN_PROMPT, PLAN_DIGEST),
            (PLAN_FOLLOW_UP, PLAN_FOLLOW_UP_DIGEST),
        ],
        &[(PLAN_PROMPT, PLAN_PATH, PLAN_CONCLUSION)],
    );
    serve(&home, peer, |client| async move {
        client.turn(ROOT_MAILBOX, PLAN_PROMPT).await;
        client.context_with_turns(Agent::Root, 1).await;
        client.turn(ROOT_MAILBOX, PLAN_FOLLOW_UP).await;
        client.context_with_turns(Agent::Root, 2).await;
    })
    .await;

    // The task layout of PRD §11.2; nothing is written under the memory directory.
    assert!(
        !home.home().join(".agent/memory/tasks").exists(),
        "no task directory under .agent/memory"
    );
    let dir = root_task_dir(&home);
    assert!(dir.join("summary.yaml").is_file(), "{dir:?}");

    // Turn 1 is the prompt, the read call, its result and the conclusion; turn 2 the
    // prompt and the reply.
    let log = turn_log(&dir);
    let shape: Vec<(u64, u64, &str)> = log
        .iter()
        .map(|line| {
            (
                line["turn"].as_u64().expect("turn"),
                line["seq"].as_u64().expect("seq"),
                line["role"].as_str().expect("role"),
            )
        })
        .collect();
    assert_eq!(
        shape,
        [
            (1, 0, "user"),
            (1, 1, "assistant"),
            (1, 2, "tool"),
            (1, 3, "assistant"),
            (2, 0, "user"),
            (2, 1, "assistant"),
        ],
        "{log:#?}"
    );
    assert_eq!(log[0]["content"], json!(PLAN_PROMPT), "{log:#?}");
    assert_eq!(log[1]["tool_calls"][0]["name"], json!("read"), "{log:#?}");
    assert_eq!(log[2]["tool_call_id"], json!(READ_CALL_ID), "{log:#?}");
    assert!(
        log[2]["content"]
            .as_str()
            .is_some_and(|result| result.contains("water the seedlings")),
        "the read result is logged: {log:#?}"
    );
    assert!(log[2].get("l0").is_none(), "a lone read is kept: {log:#?}");
    assert_eq!(log[3]["content"], json!(PLAN_CONCLUSION), "{log:#?}");
    assert_eq!(log[4]["content"], json!(PLAN_FOLLOW_UP), "{log:#?}");
    assert_eq!(log[5]["content"], json!("noted"), "{log:#?}");

    // Each entry locates its turn by line and records what the turn did.
    let turns = turn_entries(&dir);
    assert_eq!(turns.len(), 2, "{turns:#?}");
    let (first, second) = (&turns[0], &turns[1]);
    assert_eq!(first["turn"], json!(1), "{first}");
    assert_eq!(
        first["log_offset"],
        json!({ "start_line": 1, "end_line": 4 }),
        "{first}"
    );
    assert_eq!(
        second["log_offset"],
        json!({ "start_line": 5, "end_line": 6 }),
        "{second}"
    );
    assert_eq!(first["digest"], json!(PLAN_DIGEST), "{first}");
    assert_eq!(first["has_user_instruction"], json!(true), "{first}");
    assert_eq!(first["has_tool_use"], json!(true), "{first}");
    assert_eq!(second["has_tool_use"], json!(false), "{second}");
    assert_eq!(first["content_identifiers"], json!([PLAN_PATH]), "{first}");
    assert_eq!(
        first["read_file_versions"],
        json!([{ "path": PLAN_PATH, "blob_id": PLAN_BLOB }]),
        "{first}"
    );
    assert_eq!(
        first["collapsed_view"],
        json!(format!(
            "[user] \"{PLAN_PROMPT}\"\n[assistant] read(\"{PLAN_PATH}\")\n→ \"The plan has two steps.\""
        )),
        "{first}"
    );
    for field in [
        "tokens_digest",
        "tokens_collapse_excerpt",
        "tokens_l0_processed",
    ] {
        assert!(
            first[field].as_u64().is_some_and(|tokens| tokens > 0),
            "{field}: {first}"
        );
    }
    // Turn 2 names the file turn 1 read: turn 1 gained a reference.
    assert_eq!(first["reference_count"], json!(1), "{first}");
    assert_eq!(second["reference_count"], json!(0), "{second}");
}

// ---------------------------------------------------------------------------
// The last turns are carried whole until a file they read changes
// ---------------------------------------------------------------------------

const STEPS_PROMPT: &str = "how many steps does the plan have?";
const STEPS_DIGEST: &str = "The user asked how many steps the plan has.";
const LABEL_PROMPT: &str = "who labels the trays?";
const LABEL_DIGEST: &str = "The user asked who labels the trays.";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_last_turns_are_carried_whole_until_a_file_they_read_changes() {
    // A window the turns fit in whole (an undeclared `main-chat` gets the 8_192 fallback,
    // whose budget loads digests only).
    let home = memory_home(
        &[],
        &[(
            MAIN,
            entry(
                MAIN,
                MAIN_HOST,
                &["model-context-windows: { main-chat: 1048576 }"],
            ),
        )],
        &["provider: main"],
    );
    let plan = home.home().join(PLAN_PATH);
    std::fs::create_dir_all(plan.parent().expect("a parent")).expect("the notes directory");
    std::fs::write(&plan, PLAN_TEXT).expect("the plan");
    let peer = &Peer::with_reads(
        &[
            (PLAN_PROMPT, PLAN_DIGEST),
            (STEPS_PROMPT, STEPS_DIGEST),
            (LABEL_PROMPT, LABEL_DIGEST),
        ],
        &[(PLAN_PROMPT, PLAN_PATH, PLAN_CONCLUSION)],
    );
    let plan_path = plan.clone();
    serve(&home, peer, |client| async move {
        client.turn(ROOT_MAILBOX, PLAN_PROMPT).await;
        client.context_with_turns(Agent::Root, 1).await;

        // The next turn carries turn 1 whole: the prompt, the read and its result, the reply.
        client.turn(ROOT_MAILBOX, STEPS_PROMPT).await;
        let latest = latest_assembly(&client, 2).await;
        let second = peer.turn_prompt(STEPS_PROMPT);
        let recent = second
            .split_once("# Recent Turns")
            .map(|(_, rest)| rest)
            .unwrap_or_else(|| panic!("no recent turns: {second}"));
        assert!(recent.contains("## Turn 1 · "), "{recent}");
        assert!(recent.contains(&format!("user: {PLAN_PROMPT}")), "{recent}");
        assert!(
            recent.contains(&format!("assistant → read({{\"path\":\"{PLAN_PATH}\"}})")),
            "{recent}"
        );
        assert!(
            recent.contains("water the seedlings"),
            "the result: {recent}"
        );
        assert!(
            recent.contains(&format!("assistant: {PLAN_CONCLUSION}")),
            "{recent}"
        );
        assert!(
            second.find("# Recent Turns") < second.find(STEPS_PROMPT),
            "the history comes before the prompt"
        );
        assert_eq!(latest["history"]["recent_turns"], json!(1), "{latest}");
        assert_eq!(
            latest["history"]["recent_turn_digests"],
            json!(0),
            "{latest}"
        );

        // The plan changes: turn 1 read a version that is gone, so it is carried as its
        // digest; turn 2 read nothing and is carried whole.
        std::fs::write(&plan_path, "Step one: repot the seedlings.\n").expect("edit the plan");
        client.turn(ROOT_MAILBOX, LABEL_PROMPT).await;
        let latest = latest_assembly(&client, 3).await;
        let third = peer.turn_prompt(LABEL_PROMPT);
        let recent = third
            .split_once("# Recent Turns")
            .map(|(_, rest)| rest)
            .unwrap_or_else(|| panic!("no recent turns: {third}"));
        assert!(
            !recent.contains("## Turn 1 · "),
            "turn 1 is stale: {recent}"
        );
        assert!(!third.contains("water the seedlings"), "{third}");
        assert!(recent.contains("## Turn 2 · "), "{recent}");
        assert!(
            recent.contains(&format!("user: {STEPS_PROMPT}")),
            "{recent}"
        );
        let digests = third
            .split_once("# Recent Turn Digests")
            .map(|(_, rest)| rest)
            .unwrap_or_else(|| panic!("no digests: {third}"));
        assert!(digests.contains(PLAN_DIGEST), "{digests}");
        assert_eq!(latest["history"]["recent_turns"], json!(1), "{latest}");
        assert_eq!(
            latest["history"]["recent_turn_digests"],
            json!(1),
            "{latest}"
        );
    })
    .await;
}

// ---------------------------------------------------------------------------
// S6: a turn's later requests carry its reads L0-processed and fit the window
// ---------------------------------------------------------------------------

/// How NEAR AI refuses an input past the model's window (witnessed 2026-11-21 on its vLLM
/// stack): a 400 `invalid_request_error` with no code, the overflow said in the message.
const NEAR_TOO_LONG: &str = r#"{"error":{"message":"This model's maximum context length is 32768 tokens. However, your prompt contains at least 32769 input tokens, which exceeds this limit even without any output tokens. Please reduce the length of the input prompt. (parameter=input_tokens, value=32769)","type":"invalid_request_error","param":null,"code":null}}"#;
const TWICE_PROMPT: &str = "read the greenhouse plan twice to be sure";
const TWICE_DIGEST: &str = "The user asked to read the plan twice.";
const TWICE_CONCLUSION: &str = "Both reads agree. Watering comes first.";

/// The contents of the tool results of a chat body, in order.
fn tool_results(body: &Value) -> Vec<String> {
    messages_of(body)
        .iter()
        .filter(|message| message.get("role").and_then(Value::as_str) == Some("tool"))
        .map(|message| {
            message
                .get("content")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        })
        .collect()
}

/// MODULE-010 S6 — within a turn, a file read again reaches the model once: the next request
/// carries the older result as superseded (PRD §11.3.3 L0), while the turn log keeps both as
/// they were; a request the provider refuses as too long is sent once more without the
/// history, and the turn completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tool_loop_sends_collapsed_reads_and_survives_one_overflow() {
    // A window the first turn fits in whole, so the second turn's seed carries it.
    let home = memory_home(
        &[],
        &[(
            MAIN,
            entry(
                MAIN,
                MAIN_HOST,
                &["model-context-windows: { main-chat: 1048576 }"],
            ),
        )],
        &["provider: main"],
    );
    let plan = home.home().join(PLAN_PATH);
    std::fs::create_dir_all(plan.parent().expect("a parent")).expect("the notes directory");
    std::fs::write(&plan, PLAN_TEXT).expect("the plan");
    let peer = &Peer::with_read_loops(
        &[(PLAN_PROMPT, PLAN_DIGEST), (TWICE_PROMPT, TWICE_DIGEST)],
        &[(PLAN_PROMPT, PLAN_PATH, PLAN_CONCLUSION)],
        &[(TWICE_PROMPT, &[PLAN_PATH, PLAN_PATH], TWICE_CONCLUSION)],
        &[TWICE_PROMPT],
    );
    serve(&home, peer, |client| async move {
        client.turn(ROOT_MAILBOX, PLAN_PROMPT).await;
        client.context_with_turns(Agent::Root, 1).await;
        client.turn(ROOT_MAILBOX, TWICE_PROMPT).await;
        client.context_with_turns(Agent::Root, 2).await;
    })
    .await;

    let requests: Vec<Value> = peer
        .chats()
        .into_iter()
        .filter(|sent| !is_extraction(&sent.body) && last_user(&sent.body).contains(TWICE_PROMPT))
        .map(|sent| sent.body)
        .collect();
    // The read, the read again, the request refused as too long, and its retry.
    assert_eq!(requests.len(), 4, "{requests:#?}");
    assert!(tool_results(&requests[0]).is_empty());
    let second = tool_results(&requests[1]);
    assert!(
        second.len() == 1 && second[0].contains("water the seedlings"),
        "{second:?}"
    );
    // The second read supersedes the first: the plan reaches the model once.
    let refused = tool_results(&requests[2]);
    assert_eq!(
        refused,
        vec![
            format!("[superseded: a later read of {PLAN_PATH} replaces this result]"),
            second[0].clone()
        ]
    );
    assert!(
        contents(&requests[2]).contains("# Recent Turns"),
        "the refused request carried the history"
    );
    // The retry is the same turn, without the history.
    assert!(
        !contents(&requests[3]).contains("# Recent Turns"),
        "{}",
        contents(&requests[3])
    );
    assert_eq!(tool_results(&requests[3]), refused);

    // The turn completed: its log keeps both reads whole, marks the older one, and ends with
    // the conclusion.
    let log = turn_log(&root_task_dir(&home));
    let turn: Vec<&Value> = log.iter().filter(|line| line["turn"] == json!(2)).collect();
    let reads: Vec<&&Value> = turn
        .iter()
        .filter(|line| line["role"] == json!("tool"))
        .collect();
    assert_eq!(reads.len(), 2, "{turn:#?}");
    for line in &reads {
        assert!(
            line["content"]
                .as_str()
                .is_some_and(|content| content.contains("water the seedlings")),
            "{line}"
        );
    }
    assert_eq!(reads[0]["l0"]["action"], json!("superseded"), "{turn:#?}");
    assert_eq!(
        turn.last().expect("a line")["content"],
        json!(TWICE_CONCLUSION),
        "{turn:#?}"
    );
}

// ---------------------------------------------------------------------------
// D4: a deleted agent's task history is archived to its parent
// ---------------------------------------------------------------------------

/// The one directory in `dir`.
fn only_dir(dir: &Path) -> PathBuf {
    let dirs: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{dir:?}: {e}"))
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| path.is_dir())
        .collect();
    assert_eq!(dirs.len(), 1, "one directory in {dir:?}: {dirs:?}");
    dirs[0].clone()
}

/// MODULE-010 D4 (owner decision 2026-11-17) — on the production terminate path, a deleted
/// Child hands its task history to its parent. The helper's turn is logged in its own
/// `.agent/tasks/active/<task>/`. After the delete, that log is in the root's
/// `.agent/tasks/archived-agents/<the helper's id>/active/<task>/`, whole, and the helper's directory
/// holds no history.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deleted_childs_task_history_is_archived_to_its_parent() {
    let home = memory_home(
        &["messaging"],
        &[(
            MAIN,
            entry(MAIN, MAIN_HOST, &["embedding-model: main-embed"]),
        )],
        &["provider: main"],
    );
    let peer = &Peer::new(&[(HELPER_FIRST_PROMPT, HELPER_FIRST_DIGEST)]);
    serve(&home, peer, |client| async move {
        client
            .create_unpinned_child(HELPER, &["fs", "llm", "memory"])
            .await;
    })
    .await;
    give_child_the_default_driver(&home, HELPER);
    let helper_tasks = home.home().join(HELPER).join(".agent/tasks");

    let noted = Arc::new(Mutex::new(None));
    let note = noted.clone();
    let tasks = helper_tasks.clone();
    serve(&home, peer, |client| async move {
        client.child_turn(HELPER_MAILBOX, HELPER_FIRST_PROMPT).await;
        client.context_with_turns(Agent::Child(HELPER), 1).await;
        let helper_id = client
            .listed_id(Agent::Child(HELPER))
            .await
            .expect("the helper");
        // Before the delete: the helper's turn is logged in its own task directory.
        let task = only_dir(&tasks.join("active"));
        let log =
            std::fs::read_to_string(task.join("llm-turns.jsonl")).expect("the helper's turn log");
        assert!(log.contains(HELPER_FIRST_PROMPT), "{log}");
        // A task where an older release kept it, put there after the helper's wiring moved what
        // it found: the delete's archiver moves it over before it archives the history.
        let older = tasks
            .parent()
            .expect("the helper's .agent")
            .join("memory/tasks/task-older");
        std::fs::create_dir_all(&older).expect("the older task");
        std::fs::write(older.join("llm-turns.jsonl"), OLDER_TASK_LOG).expect("its turn log");

        client.delete_child(HELPER).await;
        assert_eq!(client.listed_id(Agent::Child(HELPER)).await, None);
        let task = task
            .file_name()
            .expect("a task directory name")
            .to_os_string();
        *note.lock().unwrap() = Some((helper_id, task, log));
    })
    .await;

    let (helper_id, task, log) = noted.lock().unwrap().clone().expect("noted");
    let archived = home.home().join(".agent/tasks/archived-agents");
    assert_eq!(
        only_dir(&archived).file_name(),
        Some(std::ffi::OsStr::new(&helper_id)),
        "the history is archived under the helper's id"
    );
    let kept = std::fs::read_to_string(
        archived
            .join(&helper_id)
            .join("active")
            .join(&task)
            .join("llm-turns.jsonl"),
    )
    .expect("the archived turn log");
    assert_eq!(kept, log, "the turn log is archived whole");
    let older = std::fs::read_to_string(
        archived
            .join(&helper_id)
            .join("active/task-older/llm-turns.jsonl"),
    )
    .expect("the older release's task, archived");
    assert_eq!(older, OLDER_TASK_LOG);
    assert!(
        !helper_tasks.exists(),
        "the helper's directory holds no history after the delete"
    );
    assert!(
        !helper_tasks
            .parent()
            .expect("the helper's .agent")
            .join("memory/tasks")
            .exists(),
        "nor where an older release kept it"
    );
}

/// The turn log of the task an older release left in the helper's `.agent/memory/tasks/`.
const OLDER_TASK_LOG: &str = "{\"turn\":1}\n";

/// MODULE-010 D4 — a Child whose history could not be archived keeps it. The root's
/// `.agent/tasks/archived-agents` is a file, so the archive fails; after the delete the
/// helper's turn log is still in its own `.agent/tasks/active/<task>/`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deleted_childs_history_stays_when_its_archive_fails() {
    let home = memory_home(
        &["messaging"],
        &[(
            MAIN,
            entry(MAIN, MAIN_HOST, &["embedding-model: main-embed"]),
        )],
        &["provider: main"],
    );
    let peer = &Peer::new(&[(HELPER_FIRST_PROMPT, HELPER_FIRST_DIGEST)]);
    serve(&home, peer, |client| async move {
        client
            .create_unpinned_child(HELPER, &["fs", "llm", "memory"])
            .await;
    })
    .await;
    give_child_the_default_driver(&home, HELPER);
    let helper_tasks = home.home().join(HELPER).join(".agent/tasks");
    let blocked = home.home().join(".agent/tasks/archived-agents");

    let tasks = helper_tasks.clone();
    let block = blocked.clone();
    serve(&home, peer, |client| async move {
        client.child_turn(HELPER_MAILBOX, HELPER_FIRST_PROMPT).await;
        client.context_with_turns(Agent::Child(HELPER), 1).await;
        let task = only_dir(&tasks.join("active"));
        let log =
            std::fs::read_to_string(task.join("llm-turns.jsonl")).expect("the helper's turn log");
        assert!(log.contains(HELPER_FIRST_PROMPT), "{log}");
        std::fs::create_dir_all(block.parent().expect("the root's tasks")).unwrap();
        std::fs::write(&block, b"not a directory").unwrap();

        client.delete_child(HELPER).await;
        assert_eq!(client.listed_id(Agent::Child(HELPER)).await, None);
    })
    .await;

    assert!(blocked.is_file(), "nothing was archived");
    let task = only_dir(&helper_tasks.join("active"));
    let log =
        std::fs::read_to_string(task.join("llm-turns.jsonl")).expect("the helper's turn log stays");
    assert!(log.contains(HELPER_FIRST_PROMPT), "{log}");
}

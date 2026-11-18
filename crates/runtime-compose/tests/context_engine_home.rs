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
//!
//! A turn is awaited to its END — the reply and the whole turn-end pipeline — before
//! anything it sent is looked at, so no request it makes is missed.

use std::future::Future;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
struct Peer {
    /// `(prompt, the digest of its turn)`.
    turns: Vec<(&'static str, &'static str)>,
    /// `(prompt, a fact the extraction of its turn yields)`.
    facts: Vec<(&'static str, &'static str)>,
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
        Arc::new(Self {
            turns: turns.to_vec(),
            facts: facts.to_vec(),
            chats: Mutex::new(Vec::new()),
            embeddings: Mutex::new(Vec::new()),
        })
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
                let content = if is_extraction(&sent.body) {
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

/// `prompt` was never sent for embedding.
fn assert_not_embedded(peer: &Peer, prompt: &str) {
    assert!(
        !peer
            .embedded_texts()
            .iter()
            .any(|input| input.contains(prompt)),
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

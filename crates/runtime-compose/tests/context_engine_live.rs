//! The context engine against a real model service, through the production composition.
//!
//! Opt-in. Every test is `#[ignore]` and reads four variables:
//!
//! - `ADVANCE_LIVE_LLM_ENDPOINT` — the origin of an OpenAI-compatible service
//!   (`/v1/chat/completions` and `/v1/embeddings` are appended), `https://…`.
//! - `ADVANCE_LIVE_LLM_KEY_FILE` — a file holding the API key. The key itself is never
//!   put in a variable, a command line or the output.
//! - `ADVANCE_LIVE_LLM_MODEL` — the chat model id.
//! - `ADVANCE_LIVE_LLM_EMBEDDING_MODEL` — the embedding model id.
//!
//! With none of them set a test prints `LIVE_SKIPPED` and passes; with some set it fails,
//! naming the missing ones.
//!
//! ```text
//! ADVANCE_LIVE_LLM_ENDPOINT=… ADVANCE_LIVE_LLM_KEY_FILE=… ADVANCE_LIVE_LLM_MODEL=… \
//! ADVANCE_LIVE_LLM_EMBEDDING_MODEL=… cargo test -p advance-runtime-compose \
//!     --test context_engine_live -- --ignored --nocapture --test-threads 1
//! ```
//!
//! Everything is `compose()` on a home as `advance init` creates one (a repository) whose
//! root agent declares `memory`, and the LLM
//! egress chain is the production one with the live DNS guard and the live network. A tap
//! between the chain and the network keeps each exchange's host, path, JSON bodies,
//! status and duration — never a header, so never the key. Every prompt is made up:
//! nothing of a person or a project leaves the machine.
//!
//! What a scripted peer cannot show, and these do:
//! - the service takes the requests the engine really makes (the turn, the turn-end
//!   extraction, the embeddings), with the models the entry names;
//! - vectors of a real embedding model rank an earlier turn about the question's subject
//!   above turns about something else, and the model answers from what was recalled —
//!   also after a restart, from the index on disk;
//! - a turn indexed while its agent could not embed is recalled once it can;
//! - a child agent recalls its own turns and nothing of its parent's;
//! - the knowledge a real model extracts from a deleted agent's turn is taken over by its
//!   parent, as history, and recalled by it.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use advance_runtime_compose::test_support::fixture::{FixtureHome, ROOT_MAILBOX};
use advance_runtime_compose::test_support::LlmSecurityOverride;
use advance_shared_types::security_validator::{HttpRequest, HttpResponse, RedirectCheck};
use cap_http::{DefaultSsrfGuard, ExecutorError, HttpExecutor, ReqwestHttpExecutor};
use cap_memory::{RusqliteSqliteIndex, SqliteIndex, TurnIndexRow};
use serde_json::Value;

#[path = "support/context_home.rs"]
mod context_home;
use context_home::{
    contents, give_child_the_default_driver, is_extraction, memory_home, recalled_turns, serve,
    text_of, Agent, Client,
};

/// The longest a turn of a real model, with the turn-end pipeline after it, may take.
const WAIT: Duration = Duration::from_secs(300);

// ---------------------------------------------------------------------------
// The service
// ---------------------------------------------------------------------------

const ENDPOINT: &str = "ADVANCE_LIVE_LLM_ENDPOINT";
const KEY_FILE: &str = "ADVANCE_LIVE_LLM_KEY_FILE";
const MODEL: &str = "ADVANCE_LIVE_LLM_MODEL";
const EMBEDDING_MODEL: &str = "ADVANCE_LIVE_LLM_EMBEDDING_MODEL";

/// The service a run was pointed at. (No `Debug`: it holds the key.)
struct Live {
    endpoint: String,
    key: String,
    chat_model: String,
    embedding_model: String,
}

/// The service the variables name, or `None` (with a `LIVE_SKIPPED` line) when none of
/// them is set.
fn live() -> Option<Live> {
    let names = [ENDPOINT, KEY_FILE, MODEL, EMBEDDING_MODEL];
    let values: Vec<Option<String>> = names
        .iter()
        .map(|name| {
            std::env::var(name)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .collect();
    if values.iter().all(Option::is_none) {
        println!(
            "LIVE_SKIPPED: set {} to call a real model service",
            names.join(", ")
        );
        return None;
    }
    let missing: Vec<&str> = names
        .iter()
        .zip(&values)
        .filter(|(_, value)| value.is_none())
        .map(|(name, _)| *name)
        .collect();
    assert!(missing.is_empty(), "set {} as well", missing.join(", "));
    let mut values = values.into_iter().flatten();
    let (endpoint, key_file, chat_model, embedding_model) = (
        values.next().expect("endpoint"),
        values.next().expect("key file"),
        values.next().expect("chat model"),
        values.next().expect("embedding model"),
    );
    assert!(
        endpoint.starts_with("https://"),
        "{ENDPOINT} is an https origin"
    );
    for id in [&chat_model, &embedding_model] {
        assert!(
            !id.contains(['"', '\\', '\n']),
            "a model id is written into the provider list as it is: {id:?}"
        );
    }
    // Only the kind of a failure is shown: the path is the operator's own.
    let key = std::fs::read_to_string(&key_file)
        .unwrap_or_else(|e| panic!("read the file {KEY_FILE} names: {}", e.kind()))
        .trim()
        .to_string();
    assert!(!key.is_empty(), "the file {KEY_FILE} names is empty");
    Some(Live {
        endpoint: endpoint.trim_end_matches('/').to_string(),
        key,
        chat_model,
        embedding_model,
    })
}

impl Live {
    /// The `llm-providers:` item `id` on the service (openai-chat dialect, cloud-http),
    /// its id and its API key. `embeds`: whether the item names the embedding model.
    fn entry(&self, id: &'static str, embeds: bool) -> (&'static str, String, String) {
        let mut item = format!(
            "  - id: {id}\n    endpoint: {endpoint}\n    api-key-secret: {id}-api-key\n    model-aliases: {{ default: \"{model}\" }}\n    cost-per-mtoken-in: 1.0\n    cost-per-mtoken-out: 2.0\n    rate-limit: {{ requests-per-minute: 1000, tokens-per-minute: 1000000 }}\n    generate-timeout-secs: 120\n",
            endpoint = self.endpoint,
            model = self.chat_model,
        );
        if embeds {
            item.push_str(&format!(
                "    embedding-model: \"{}\"\n",
                self.embedding_model
            ));
        }
        (id, item, self.key.clone())
    }

    fn host(&self) -> &str {
        let rest = self
            .endpoint
            .strip_prefix("https://")
            .unwrap_or(&self.endpoint);
        rest.split('/').next().unwrap_or(rest)
    }
}

// ---------------------------------------------------------------------------
// The tap
// ---------------------------------------------------------------------------

/// One buffered exchange with the model service. No header is kept: the API key travels
/// in one.
#[derive(Clone)]
struct Exchange {
    host: String,
    /// `v1/chat/completions`, `v1/embeddings`.
    path: String,
    request: Value,
    /// `None`: the transport failed before an answer, or the exchange was dropped.
    status: Option<u16>,
    response: Value,
    took: Duration,
    /// The caller stopped waiting (a deadline, a cancelled turn) before an answer came.
    dropped: bool,
}

impl Exchange {
    fn is_embedding(&self) -> bool {
        self.path == "v1/embeddings"
    }

    fn is_chat(&self) -> bool {
        self.path == "v1/chat/completions"
    }

    /// The vector an embedding exchange was answered with, empty when there is none.
    fn vector(&self) -> Vec<f64> {
        self.response
            .pointer("/data/0/embedding")
            .and_then(Value::as_array)
            .map(|vector| vector.iter().filter_map(Value::as_f64).collect())
            .unwrap_or_default()
    }

    /// The text a chat exchange was answered with, empty when there is none (a tool call).
    fn answer(&self) -> String {
        self.response
            .pointer("/choices/0/message/content")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }

    /// The names of the tools a chat exchange was answered with a call of.
    fn tool_calls(&self) -> Vec<String> {
        self.response
            .pointer("/choices/0/message/tool_calls")
            .and_then(Value::as_array)
            .map(|calls| {
                calls
                    .iter()
                    .filter_map(|call| call.pointer("/function/name").and_then(Value::as_str))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// The live network of the LLM egress chain, keeping what crosses it.
struct Tap {
    network: ReqwestHttpExecutor,
    exchanges: Mutex<Vec<Exchange>>,
}

impl Tap {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            network: ReqwestHttpExecutor::new(),
            exchanges: Mutex::new(Vec::new()),
        })
    }

    fn len(&self) -> usize {
        self.exchanges.lock().unwrap().len()
    }

    fn since(&self, from: usize) -> Vec<Exchange> {
        self.exchanges.lock().unwrap()[from..].to_vec()
    }

    /// The live DNS guard and this tap as the DNS and the network of the egress chain.
    fn security(self: &Arc<Self>) -> LlmSecurityOverride {
        LlmSecurityOverride {
            ssrf: Arc::new(DefaultSsrfGuard::new()),
            executor: Arc::clone(self) as Arc<dyn HttpExecutor>,
        }
    }
}

#[async_trait::async_trait]
impl HttpExecutor for Tap {
    async fn execute(
        &self,
        req: &HttpRequest,
        redirect_check: Arc<dyn RedirectCheck>,
    ) -> Result<HttpResponse, ExecutorError> {
        let rest = req.url.strip_prefix("https://").unwrap_or(&req.url);
        let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
        // Kept from the start: an exchange the caller stops waiting for shows as dropped.
        let mut pending = Pending {
            tap: self,
            index: {
                let mut exchanges = self.exchanges.lock().unwrap();
                exchanges.push(Exchange {
                    host: host.to_string(),
                    path: path.to_string(),
                    request: serde_json::from_slice(&req.body).unwrap_or(Value::Null),
                    status: None,
                    response: Value::Null,
                    took: Duration::ZERO,
                    dropped: true,
                });
                exchanges.len() - 1
            },
            started: Instant::now(),
            answered: false,
        };
        let outcome = self.network.execute(req, redirect_check).await;
        {
            let mut exchanges = self.exchanges.lock().unwrap();
            let exchange = &mut exchanges[pending.index];
            if let Ok(answer) = &outcome {
                exchange.status = Some(answer.status);
                exchange.response = serde_json::from_slice(&answer.body).unwrap_or(Value::Null);
            }
            exchange.took = pending.started.elapsed();
            exchange.dropped = false;
        }
        pending.answered = true;
        outcome
    }
}

/// One exchange in flight: when it is dropped before an answer, notes how long it ran.
struct Pending<'a> {
    tap: &'a Tap,
    index: usize,
    started: Instant,
    answered: bool,
}

impl Drop for Pending<'_> {
    fn drop(&mut self) {
        if !self.answered {
            if let Ok(mut exchanges) = self.tap.exchanges.lock() {
                exchanges[self.index].took = self.started.elapsed();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// One turn, and what crossed the network during it
// ---------------------------------------------------------------------------

/// The exchanges of one turn, from its message to the end of its turn-end pipeline.
struct Trace {
    /// The message the turn was started with.
    said: String,
    exchanges: Vec<Exchange>,
}

impl Trace {
    /// The agent's own model requests, in order: the chat requests that carry the turn's
    /// message and are not the turn-end extraction. (A turn makes several when the model
    /// calls a tool. Any other chat request of the turn is the host's own — the
    /// extraction, a consolidation — made on the agent's entry.)
    fn model_requests(&self) -> Vec<&Exchange> {
        self.exchanges
            .iter()
            .filter(|exchange| {
                exchange.is_chat()
                    && !is_extraction(&exchange.request)
                    && contents(&exchange.request).contains(&self.said)
            })
            .collect()
    }

    fn extractions(&self) -> Vec<&Exchange> {
        self.exchanges
            .iter()
            .filter(|exchange| exchange.is_chat() && is_extraction(&exchange.request))
            .collect()
    }

    fn embeddings(&self) -> Vec<&Exchange> {
        self.exchanges
            .iter()
            .filter(|exchange| exchange.is_embedding())
            .collect()
    }

    /// All message contents of the turn's first model request: the assembled context.
    fn prompt(&self) -> String {
        self.model_requests()
            .first()
            .map(|exchange| contents(&exchange.request))
            .unwrap_or_default()
    }

    /// The last text the model answered the agent with.
    fn answer(&self) -> String {
        self.model_requests()
            .iter()
            .rev()
            .map(|exchange| exchange.answer())
            .find(|answer| !answer.trim().is_empty())
            .unwrap_or_default()
    }

    /// The `## Related Turns` items of the assembled context, best first.
    fn recalled(&self) -> Vec<String> {
        recalled_turns(&self.prompt())
            .into_iter()
            .map(str::to_string)
            .collect()
    }

    /// Print what the turn did. Everything shown is made-up text or a number.
    fn report(&self, who: &str) {
        println!("--- {who}: {:?}", self.said);
        for exchange in &self.exchanges {
            let status = match (exchange.status, exchange.dropped) {
                (Some(status), _) => status.to_string(),
                (None, true) => "DROPPED".to_string(),
                (None, false) => "no answer".to_string(),
            };
            let what = if exchange.is_embedding() {
                format!(
                    "embedding [{} dims] of {:?}",
                    exchange.vector().len(),
                    brief(&text_of(&exchange.request, "input"), 70)
                )
            } else if is_extraction(&exchange.request) {
                format!("extraction -> {:?}", brief(&exchange.answer(), 160))
            } else if contents(&exchange.request).contains(&self.said) {
                let calls = exchange.tool_calls();
                if calls.is_empty() {
                    format!(
                        "the agent's request -> {:?}",
                        brief(&exchange.answer(), 160)
                    )
                } else {
                    format!("the agent's request -> calls {}", calls.join(", "))
                }
            } else {
                format!("a host call -> {:?}", brief(&exchange.answer(), 160))
            };
            println!("    {status} {:>6} ms  {what}", exchange.took.as_millis());
        }
        for line in self.recalled() {
            println!("    recalled {}", brief(&line, 150));
        }
    }

    /// The service answered every exchange of the turn. A request it left unanswered
    /// past the entry's timeout is the service's hiccup, not the engine's: the engine
    /// then falls back as designed (a turn digest without the model, and no extraction
    /// for a while), and what this test looks at next would fail for that reason alone.
    fn assert_answered(&self) {
        for exchange in &self.exchanges {
            assert!(
                exchange.status == Some(200),
                "the model service did not answer a request of this turn ({} after {} ms, {}) — \
                 a service hiccup, not an engine defect; run the test again",
                exchange.path,
                exchange.took.as_millis(),
                match (exchange.status, exchange.dropped) {
                    (Some(status), _) => format!("status {status}"),
                    (None, true) => "dropped: no answer before the timeout".to_string(),
                    (None, false) => "the transport failed".to_string(),
                },
            );
        }
    }

    /// Every exchange went to the service's host, a chat one for the chat model and an
    /// embedding one for the embedding model.
    fn assert_asked_of(&self, live: &Live) {
        for exchange in &self.exchanges {
            assert_eq!(
                exchange.host,
                live.host(),
                "a request left for another host"
            );
            let model = text_of(&exchange.request, "model");
            if exchange.is_embedding() {
                assert_eq!(model, live.embedding_model, "an embedding request");
            } else {
                assert!(exchange.is_chat(), "an unexpected path: {}", exchange.path);
                assert_eq!(model, live.chat_model, "a chat request");
            }
        }
    }

    /// The turn was embedded: at least one embedding was asked for, and every one was
    /// answered with a vector of the same length. Returns that length.
    fn assert_embedded(&self) -> usize {
        let lengths: Vec<usize> = self
            .embeddings()
            .iter()
            .map(|exchange| {
                assert_eq!(exchange.status, Some(200), "an embedding request");
                exchange.vector().len()
            })
            .collect();
        let dimensions = *lengths.first().expect("the turn asked for an embedding");
        assert!(dimensions > 0, "an embedding without a vector");
        assert!(
            lengths.iter().all(|length| *length == dimensions),
            "vectors of several lengths: {lengths:?}"
        );
        dimensions
    }
}

/// The first `limit` characters of `text` on one line.
fn brief(text: &str, limit: usize) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= limit {
        flat
    } else {
        format!("{}…", flat.chars().take(limit).collect::<String>())
    }
}

/// Whether `text` names one of `words`, whatever the case.
fn mentions(text: &str, words: &[&str]) -> bool {
    let text = text.to_lowercase();
    words.iter().any(|word| text.contains(&word.to_lowercase()))
}

/// Run a turn of the root agent to its end and return what crossed the network.
async fn root_turn(tap: &Tap, client: &Client, live: &Live, say: &str) -> Trace {
    let from = tap.len();
    client.turn(ROOT_MAILBOX, say).await;
    let trace = Trace {
        said: say.to_string(),
        exchanges: tap.since(from),
    };
    trace.report("root");
    trace.assert_answered();
    trace.assert_asked_of(live);
    trace
}

/// Run a turn of the child at `mailbox` to its end and return what crossed the network.
async fn child_turn(tap: &Tap, client: &Client, live: &Live, mailbox: &str, say: &str) -> Trace {
    let from = tap.len();
    client.child_turn(mailbox, say).await;
    let trace = Trace {
        said: say.to_string(),
        exchanges: tap.since(from),
    };
    trace.report(mailbox);
    trace.assert_answered();
    trace.assert_asked_of(live);
    trace
}

/// The turn rows the home's index holds for `agent_id`, read from disk once the
/// composition is shut down.
fn indexed_turns(home: &FixtureHome, agent_id: &str) -> Vec<TurnIndexRow> {
    RusqliteSqliteIndex::open(home.home().join(".agent/memory/index.sqlite"))
        .expect("the home's index")
        .list_turns_for_agent(agent_id)
}

/// Each of `rows` has a text and a vector of `dimensions` numbers, recorded as coming
/// from the service's embedding model.
fn assert_rows_embedded(rows: &[TurnIndexRow], live: &Live, dimensions: usize) {
    for row in rows {
        println!(
            "    row {}#turn-{} [{} dims, {}] {:?}",
            row.task_id,
            row.turn,
            row.embedding.len(),
            row.embedding_model.as_deref().unwrap_or("no model"),
            brief(&row.digest, 110)
        );
        assert!(!row.digest.trim().is_empty(), "a row without a text");
        assert_eq!(
            row.embedding_model.as_deref(),
            Some(live.embedding_model.as_str()),
            "the model of a stored vector"
        );
        assert_eq!(row.embedding.len(), dimensions, "a stored vector");
    }
}

// ---------------------------------------------------------------------------
// An earlier turn is recalled by what it means
// ---------------------------------------------------------------------------

const NEAR: &str = "near";

const CODENAME_FACT: &str =
    "Please remember this for later: the internal codename of the autumn release is Bluebird-7431.";
const PLANTS_NOTE: &str = "An unrelated note: the office plants are watered every Tuesday morning.";
const LUNCH_NOTE: &str = "Another note: the team lunch has moved to the cafe on Elm Street.";
const CODENAME_QUESTION: &str =
    "What is the internal codename of the autumn release? Answer with the codename only.";
const CODENAME_QUESTION_AGAIN: &str =
    "Remind me, which codename did I give you for the autumn release? Answer with the codename only.";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "calls a real model service; set the ADVANCE_LIVE_LLM_* variables"]
async fn a_real_model_recalls_an_earlier_turn_by_what_it_means() {
    let Some(live) = live() else { return };
    let live = &live;
    let home = memory_home(true, &[], &[live.entry(NEAR, true)], &["provider: near"]);
    let tap = &Tap::new();
    let seen = Arc::new(Mutex::new(None));

    let noted = seen.clone();
    serve(&home, tap.security(), WAIT, |client| async move {
        let fact = root_turn(tap, &client, live, CODENAME_FACT).await;
        client.context_with_turns(Agent::Root, 1).await;
        assert!(
            fact.recalled().is_empty(),
            "nothing to recall on the first turn"
        );
        // The prompt (query side) and the turn's text (index side) were both embedded.
        let dimensions = fact.assert_embedded();
        assert!(
            fact.embeddings().len() >= 2,
            "the prompt and the turn's text are embedded"
        );
        assert_eq!(
            fact.extractions().len(),
            1,
            "the turn-end extraction was asked for once"
        );

        root_turn(tap, &client, live, PLANTS_NOTE).await;
        root_turn(tap, &client, live, LUNCH_NOTE).await;
        client.context_with_turns(Agent::Root, 3).await;

        let question = root_turn(tap, &client, live, CODENAME_QUESTION).await;
        let context = client.context_with_turns(Agent::Root, 4).await;
        assert_eq!(question.assert_embedded(), dimensions);
        let recalled = question.recalled();
        let prompt = question.prompt();
        assert!(
            prompt.contains("- recall: semantic"),
            "the runtime section reports the live route: {prompt}"
        );
        // Of the three earlier turns the one about the codename is the closest to the
        // question — by the vectors of a real embedding model.
        let best = recalled
            .first()
            .unwrap_or_else(|| panic!("the question recalls an earlier turn: {prompt}"));
        assert!(
            mentions(best, &["bluebird", "codename"]),
            "the closest turn is the one about the codename: {recalled:#?}"
        );
        assert!(
            !mentions(best, &["plants", "lunch", "cafe"]),
            "the closest turn is not one about something else: {recalled:#?}"
        );
        assert!(
            mentions(&question.answer(), &["7431"]),
            "the model answers from what the engine gave it: {:?}",
            question.answer()
        );

        assert_eq!(
            context.pointer("/embedding/active"),
            Some(&serde_json::json!(true)),
            "{context}"
        );
        assert_eq!(
            context.pointer("/embedding/model"),
            Some(&serde_json::json!(live.embedding_model)),
            "{context}"
        );
        assert!(
            context
                .pointer("/latest/recall/turns")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                >= 1,
            "{context}"
        );
        let root = client.listed_id(Agent::Root).await.expect("the root");
        *noted.lock().unwrap() = Some((root, dimensions));
    })
    .await;

    // The index on disk: every turn has a text and a vector of the service's model.
    let (root, dimensions) = seen.lock().unwrap().clone().expect("the first start ran");
    let rows = indexed_turns(&home, &root);
    assert_eq!(rows.len(), 4, "one row for each turn");
    assert_rows_embedded(&rows, live, dimensions);

    // A restart: the agent is pinned, so its first prompt is embedded at once, and the
    // turns indexed before the restart are recalled from the index on disk.
    serve(&home, tap.security(), WAIT, |client| async move {
        let again = root_turn(tap, &client, live, CODENAME_QUESTION_AGAIN).await;
        client.context_with_turns(Agent::Root, 5).await;
        assert_eq!(again.assert_embedded(), dimensions);
        let recalled = again.recalled();
        assert!(
            recalled
                .first()
                .is_some_and(|best| mentions(best, &["bluebird", "codename"])),
            "after a restart the closest turn is still one about the codename: {recalled:#?}"
        );
        assert!(
            mentions(&again.answer(), &["7431"]),
            "the model answers from what was indexed before the restart: {:?}",
            again.answer()
        );
    })
    .await;
}

// ---------------------------------------------------------------------------
// A turn indexed before its agent could embed
// ---------------------------------------------------------------------------

/// The same service under an entry that names no embedding model.
const PLAIN: &str = "plain";

const WORKSHOP_FACT: &str =
    "For the record: the quarterly planning workshop will be held in the Juniper room on the fourth floor.";
const BAKERY_NOTE: &str =
    "A separate topic: the bakery on the corner sells sourdough only on Saturdays.";
const WORKSHOP_QUESTION: &str =
    "In which room will the quarterly planning workshop be held? Answer with the room name only.";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "calls a real model service; set the ADVANCE_LIVE_LLM_* variables"]
async fn a_turn_indexed_before_its_agent_could_embed_is_recalled_once_it_can() {
    let Some(live) = live() else { return };
    let live = &live;
    // The agent starts on an entry that serves no embeddings.
    let home = memory_home(
        true,
        &[],
        &[live.entry(PLAIN, false), live.entry(NEAR, true)],
        &["provider: plain"],
    );
    let tap = &Tap::new();
    let seen = Arc::new(Mutex::new(None));

    let noted = seen.clone();
    serve(&home, tap.security(), WAIT, |client| async move {
        let fact = root_turn(tap, &client, live, WORKSHOP_FACT).await;
        client.context_with_turns(Agent::Root, 1).await;
        assert!(
            fact.embeddings().is_empty(),
            "an entry that names no embedding model is asked for none"
        );

        // The agent moves to an entry that embeds. The end of its next turn embeds the
        // first turn's text as well.
        client.pin_root(NEAR).await;
        let note = root_turn(tap, &client, live, BAKERY_NOTE).await;
        client.context_with_turns(Agent::Root, 2).await;
        let dimensions = note.assert_embedded();

        let question = root_turn(tap, &client, live, WORKSHOP_QUESTION).await;
        client.context_with_turns(Agent::Root, 3).await;
        let recalled = question.recalled();
        assert!(
            recalled
                .first()
                .is_some_and(|best| mentions(best, &["juniper", "workshop"])),
            "the turn indexed without a vector is the closest to the question: {recalled:#?}"
        );
        assert!(
            mentions(&question.answer(), &["juniper"]),
            "the model answers from the turn that was caught up: {:?}",
            question.answer()
        );
        let root = client.listed_id(Agent::Root).await.expect("the root");
        *noted.lock().unwrap() = Some((root, dimensions));
    })
    .await;

    let (root, dimensions) = seen.lock().unwrap().clone().expect("the start ran");
    let rows = indexed_turns(&home, &root);
    assert_eq!(rows.len(), 3, "one row for each turn");
    assert_rows_embedded(&rows, live, dimensions);
}

// ---------------------------------------------------------------------------
// A child agent
// ---------------------------------------------------------------------------

const HELPER: &str = "helper";
const HELPER_MAILBOX: &str = "agent:helper";

const BOOK_FACT: &str =
    "A note for you only: the reading club picked 'The Maple Orchard' as its next book.";
const ELEVATOR_FACT: &str = "Keep in mind: the freight elevator is out of service until Thursday.";
const ELEVATOR_QUESTION: &str =
    "Until which day is the freight elevator out of service? Answer with the day only.";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "calls a real model service; set the ADVANCE_LIVE_LLM_* variables"]
async fn a_child_agent_recalls_its_own_turns_and_nothing_of_its_parents() {
    let Some(live) = live() else { return };
    let live = &live;
    // A child is served only on a home whose root declares `messaging`.
    let home = memory_home(
        true,
        &["messaging"],
        &[live.entry(NEAR, true)],
        &["provider: near"],
    );
    let tap = &Tap::new();

    // A built-in template ships no driver, so the child is served from the next start,
    // once a driver is in its territory.
    serve(&home, tap.security(), WAIT, |client| async move {
        client
            .create_child(HELPER, &["fs", "llm", "memory"], NEAR)
            .await;
    })
    .await;
    give_child_the_default_driver(&home, HELPER);

    let seen = Arc::new(Mutex::new(None));
    let noted = seen.clone();
    serve(&home, tap.security(), WAIT, |client| async move {
        let book = root_turn(tap, &client, live, BOOK_FACT).await;
        client.context_with_turns(Agent::Root, 1).await;
        let dimensions = book.assert_embedded();

        let fact = child_turn(tap, &client, live, HELPER_MAILBOX, ELEVATOR_FACT).await;
        client.context_with_turns(Agent::Child(HELPER), 1).await;
        assert_eq!(fact.assert_embedded(), dimensions);

        let question = child_turn(tap, &client, live, HELPER_MAILBOX, ELEVATOR_QUESTION).await;
        let helper = client.context_with_turns(Agent::Child(HELPER), 2).await;
        let recalled = question.recalled();
        assert!(
            recalled
                .first()
                .is_some_and(|best| mentions(best, &["elevator"])),
            "the child recalls its own earlier turn: {recalled:#?}"
        );
        let prompt = question.prompt();
        assert!(
            !mentions(&prompt, &["maple orchard", "reading club"]),
            "nothing of the parent's turn is in the child's context: {prompt}"
        );
        assert!(
            mentions(&question.answer(), &["thursday"]),
            "the child answers from its own earlier turn: {:?}",
            question.answer()
        );
        assert_eq!(
            helper.pointer("/embedding/model"),
            Some(&serde_json::json!(live.embedding_model)),
            "{helper}"
        );

        let root = client.listed_id(Agent::Root).await.expect("the root");
        let child = client
            .listed_id(Agent::Child(HELPER))
            .await
            .expect("the helper");
        *noted.lock().unwrap() = Some((root, child, dimensions));
    })
    .await;

    // Each agent's rows are its own, under its own id.
    let (root, child, dimensions) = seen.lock().unwrap().clone().expect("the second start ran");
    let of_root = indexed_turns(&home, &root);
    let of_child = indexed_turns(&home, &child);
    assert_eq!(of_root.len(), 1, "the root's one turn");
    assert_eq!(of_child.len(), 2, "the child's two turns");
    assert_rows_embedded(&of_root, live, dimensions);
    assert_rows_embedded(&of_child, live, dimensions);
}

/// The knowledge a real model extracts from an agent's turn is kept, as history, when the
/// agent is deleted, and its parent takes it over (owner decision 2026-11-17): after the
/// delete every entry the helper held is the root's, naming the helper, and the helper's id
/// holds none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "calls a real model service; set the ADVANCE_LIVE_LLM_* variables"]
async fn a_deleted_agents_knowledge_is_taken_over_by_its_parent() {
    let Some(live) = live() else { return };
    let live = &live;
    let home = memory_home(
        true,
        &["messaging"],
        &[live.entry(NEAR, true)],
        &["provider: near"],
    );
    let tap = &Tap::new();
    serve(&home, tap.security(), WAIT, |client| async move {
        client
            .create_child(HELPER, &["fs", "llm", "memory"], NEAR)
            .await;
    })
    .await;
    give_child_the_default_driver(&home, HELPER);
    let memory_root = home.home().join(".agent/memory");

    let seen = Arc::new(Mutex::new(None));
    let noted = seen.clone();
    let knowledge_root = memory_root.clone();
    serve(&home, tap.security(), WAIT, |client| async move {
        child_turn(tap, &client, live, HELPER_MAILBOX, ELEVATOR_FACT).await;
        client.context_with_turns(Agent::Child(HELPER), 1).await;
        let root = client.listed_id(Agent::Root).await.expect("the root");
        let helper = client
            .listed_id(Agent::Child(HELPER))
            .await
            .expect("the helper");
        // Before the delete: what the model extracted from the helper's turn is held under
        // the helper's id.
        let held = knowledge_ids(&knowledge_root, &helper);
        assert!(
            !held.is_empty(),
            "the model extracted no knowledge from the helper's turn"
        );
        client.delete_child(HELPER).await;
        assert_eq!(client.listed_id(Agent::Child(HELPER)).await, None);
        *noted.lock().unwrap() = Some((root, helper, held));
    })
    .await;

    // The composition is shut down, its last pass over the helper's records with it: read
    // the home's knowledge as it is on disk.
    let (root, helper, held) = seen.lock().unwrap().clone().expect("the second start ran");
    let store =
        cap_memory::MemoryStore::open(&memory_root, cap_memory::DEFAULT_MAX_ACTIVE_PER_AGENT)
            .expect("the home's knowledge");
    assert!(
        store.list(&helper).is_empty(),
        "the deleted agent's id holds no knowledge: {:#?}",
        store.list(&helper)
    );
    let of_root = store.list(&root);
    let from = format!("{}{helper}", cap_memory::FROM_AGENT_TAG_PREFIX);
    for id in &held {
        let entry = of_root
            .iter()
            .find(|entry| &entry.id == id)
            .unwrap_or_else(|| panic!("the root holds the helper's entry {id}: {of_root:#?}"));
        assert_eq!(entry.agent_id, root);
        assert!(
            entry.tags.contains(&from),
            "the entry names the helper: {:?}",
            entry.tags
        );
    }
    assert!(
        of_root
            .iter()
            .any(|entry| mentions(&entry.content, &["elevator"])),
        "what the helper learned about the elevator is the root's now: {of_root:#?}"
    );
    // The root recalls it as its own: what a guest's `recall` serves from.
    let recalled = store.recall(&root, "elevator", 10);
    assert!(
        recalled.iter().any(|entry| held.contains(&entry.id)),
        "the root recalls what the helper learned about the elevator: {recalled:#?}"
    );
    eprintln!(
        "LIVE hand-over: the root holds the helper's {} entries and recalls {} of them",
        held.len(),
        recalled
            .iter()
            .filter(|entry| held.contains(&entry.id))
            .count()
    );
}

/// The ids of the knowledge entries `agent` holds, as its file in the home's store at
/// `memory_root` has them — read while the composition runs: the file, not a second store.
fn knowledge_ids(memory_root: &std::path::Path, agent: &str) -> Vec<String> {
    let file = memory_root
        .join(cap_memory::persistence::slug(agent))
        .join(cap_memory::persistence::KNOWLEDGE_JSONL_FILENAME);
    std::fs::read_to_string(file)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|entry| entry["id"].as_str().map(str::to_string))
        .collect()
}

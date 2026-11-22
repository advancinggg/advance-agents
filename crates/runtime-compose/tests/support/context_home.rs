//! Shared by the context-engine composition tests: a home whose root agent declares
//! `memory` and runs the default driver, the production composition serving it, an
//! operator session on its Client API, and readers of what a model request carries.
//!
//! Included by each test binary: `#[path = "support/context_home.rs"] mod context_home;`.
#![allow(dead_code)]

use std::future::Future;
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use advance_runtime_compose::test_support::fixture::inference::provider_yaml;
use advance_runtime_compose::test_support::fixture::{
    mint_session, CapDecl, FixtureDriver, FixtureHome, FixtureHomeSpec, Http,
};
use advance_runtime_compose::test_support::{
    ComposeFailpoints, ComposeProbe, LlmSecurityOverride, MemoryComposeLog,
};
use advance_runtime_compose::{compose, ComposeOptions, MasterKeyInput, Zeroizing};
use advance_scheduler::TurnOutcome;
use advance_shared_types::mailbox::{Message, MessageKind};
use cap_llm::LlmGateway;
use cap_secrets::{FileSecretStorage, SecretStore};
use futures::FutureExt;
use serde_json::{json, Value};

/// The default driver a new home is created with (`advance_home::create::create`).
pub const CALLABLES_CORE: &[u8] =
    include_bytes!("../../../runtime/tests/fixtures/guest-rust-callables.core.wasm");

const POLL: Duration = Duration::from_millis(50);

/// How long a stream's reader waits, once its terminal has arrived, for the seqs before it
/// it has not read yet — the app's grace (`ClientAPIClient.terminalGraceNanoseconds`).
const TERMINAL_GRACE: Duration = Duration::from_millis(1500);

/// The longest a composition may take to shut down: it waits for the last pass over the
/// records of an agent deleted while it was serving.
const SHUTDOWN_WAIT: Duration = Duration::from_secs(120);

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

/// The master key every home of this test process is composed with and its API keys
/// stored under ([`seed_api_key`]). Random per process: a key that a run killed before
/// its clean-up leaves in a home's `.advance/secrets.json` cannot be read with anything
/// in the repository.
fn master_key() -> [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    *KEY.get_or_init(rand::random)
}

/// Every API key a home of this process was given ([`seed_api_key`]): what the compose
/// log is cleaned of before it is printed ([`redacted`]).
fn seeded_keys() -> &'static Mutex<Vec<String>> {
    static KEYS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    KEYS.get_or_init(|| Mutex::new(Vec::new()))
}

/// The shortest part of an API key [`redacted`] removes from a line.
const KEY_PART: usize = 12;

/// `line` with every API key this process seeded removed — whole, and any part of it
/// [`KEY_PART`] characters long or longer (a service echoing a key back in an error
/// may echo part of it).
fn redacted(line: &str) -> String {
    let mut line = line.to_string();
    let keys = seeded_keys().lock().unwrap_or_else(PoisonError::into_inner);
    for key in keys.iter().filter(|key| !key.is_empty()) {
        line = line.replace(key.as_str(), "[an API key]");
        let chars: Vec<char> = key.chars().collect();
        for part in chars.windows(KEY_PART) {
            let part: String = part.iter().collect();
            if line.contains(&part) {
                return "[withheld: the line carries part of an API key]".to_string();
            }
        }
    }
    line
}

// ---------------------------------------------------------------------------
// What a model request carries
// ---------------------------------------------------------------------------

/// The string at `key` of a request or response body, empty when there is none.
pub fn text_of(body: &Value, key: &str) -> String {
    body.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Every message content of a chat body, joined.
pub fn contents(body: &Value) -> String {
    body.get("messages")
        .and_then(Value::as_array)
        .map(|messages| {
            messages
                .iter()
                .filter_map(|message| message.get("content").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

/// The turn-end memory extraction request (`memory_extractor::LlmBatchExtractor`).
pub fn is_extraction(body: &Value) -> bool {
    contents(body).contains("memory-extraction assistant")
}

/// The turns an assembled prompt recalls: the items of the `## Related Turns` list of its
/// `# Recalled Context` section, one `- {id} ({score}) — {digest}` line each, best first.
/// Empty when the prompt has no such section. (A digest also shows in the task summary
/// and the recent-turn digests of a prompt, recalled or not — only this list says it was
/// recalled.)
pub fn recalled_turns(prompt: &str) -> Vec<&str> {
    let Some((_, section)) = prompt.split_once("# Recalled Context") else {
        return Vec::new();
    };
    let Some((_, turns)) = section.split_once("## Related Turns\n") else {
        return Vec::new();
    };
    turns
        .lines()
        .take_while(|line| line.starts_with("- "))
        .collect()
}

/// Whether `prompt` recalls the turn whose digest is `digest`.
pub fn recalls(prompt: &str, digest: &str) -> bool {
    recalled_turns(prompt)
        .iter()
        .any(|turn| turn.contains(digest))
}

// ---------------------------------------------------------------------------
// The home and the composition
// ---------------------------------------------------------------------------

/// Store `value` as the API key of the provider entry `id` (its `api-key-secret` is
/// `{id}-api-key`), under this process's master key.
pub fn seed_api_key(home: &Path, id: &str, value: &str) {
    seeded_keys()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(value.to_string());
    let storage = Arc::new(
        FileSecretStorage::open(home.join(".advance/secrets.json")).expect("open secrets.json"),
    );
    SecretStore::new(Zeroizing::new(master_key()), storage)
        .store(&format!("{id}-api-key"), value)
        .expect("store the API key");
}

/// A home whose root agent declares `fs` + `llm` + `memory` and `more`, runs the default
/// driver and has `entries` as its provider list: `(id, its llm-providers item, its API
/// key)` each. `agent_llm` is the agent's `llm:` block body (one `key: value` per item),
/// empty for none. `git`: whether the home is a repository, as a home `advance init`
/// creates is — without one the turn-end consolidation cannot commit, so it is tried
/// again (one more model call) at the end of every turn.
pub fn memory_home(
    git: bool,
    more: &[&'static str],
    entries: &[(&str, String, String)],
    agent_llm: &[&str],
) -> FixtureHome {
    let items: Vec<&str> = entries.iter().map(|(_, item, _)| item.as_str()).collect();
    let home = FixtureHome::new(FixtureHomeSpec {
        capabilities: ["fs", "llm", "memory"]
            .iter()
            .chain(more)
            .copied()
            .map(CapDecl::Granted)
            .collect(),
        driver: FixtureDriver::Core(CALLABLES_CORE),
        git,
        providers_yaml: Some(provider_yaml::llm_providers_block(&items)),
    })
    .expect("fixture home");
    for (id, _, key) in entries {
        seed_api_key(home.home(), id, key);
    }
    if !agent_llm.is_empty() {
        let path = home.home().join(".agent/config.yaml");
        let mut yaml = std::fs::read_to_string(&path).expect("agent config");
        yaml.push_str("llm:\n");
        for line in agent_llm {
            yaml.push_str(&format!("  {line}\n"));
        }
        std::fs::write(&path, yaml).expect("write the agent config");
    }
    home
}

/// Put the default driver in the territory of the child `handle`: a built-in template
/// ships none, so a child created from one is served from the next start on.
pub fn give_child_the_default_driver(home: &FixtureHome, handle: &str) {
    std::fs::write(
        home.home().join(handle).join(".agent/behavior.wasm"),
        CALLABLES_CORE,
    )
    .expect("the child's driver");
}

/// Compose `home` as the daemon does, with `security` as the DNS and the network of the
/// LLM egress chain (every other link of the chain is the production one); run `body`
/// against the live Client API, each wait of its [`Client`] bounded by `wait`; then shut
/// the composition down — even when `body` panicked, within [`SHUTDOWN_WAIT`]. When
/// `body` panicked or the shutdown failed, print what the composition logged (cleaned of
/// API keys) and fail with the first of the two.
pub async fn serve<F, Fut>(
    home: &FixtureHome,
    security: LlmSecurityOverride,
    wait: Duration,
    body: F,
) where
    F: FnOnce(Client) -> Fut,
    Fut: Future<Output = ()>,
{
    let log = MemoryComposeLog::new();
    let probe = Arc::new(ComposeProbe::new());
    let options = ComposeOptions::daemon(home.home().to_path_buf(), Arc::new(log.clone()))
        .with_state_root(home.state_root().to_path_buf())
        .with_master_key(MasterKeyInput::Provided(Zeroizing::new(master_key())))
        .with_failpoints(ComposeFailpoints {
            probe: Some(probe.clone()),
            llm_security: Some(security),
            ..ComposeFailpoints::default()
        });
    // A hang guard. A full parallel run composes many homes at once; one took over 180 s.
    let rt = tokio::time::timeout(Duration::from_secs(600), compose(options, Vec::new()))
        .await
        .expect("compose in time")
        .expect("compose");
    let endpoint = rt.client_api().expect("client api");
    let client = Client {
        addr: endpoint.socket_addr,
        token: mint_session(&endpoint),
        probe,
        wait,
    };
    let outcome = AssertUnwindSafe(body(client)).catch_unwind().await;
    let shutdown = tokio::time::timeout(SHUTDOWN_WAIT, rt.shutdown()).await;
    if outcome.is_err() || !matches!(shutdown, Ok(Ok(()))) {
        for line in log.lines() {
            eprintln!("compose log [{}] {}", line.key, redacted(&line.text));
        }
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
    match shutdown {
        Ok(shut_down) => shut_down.expect("shutdown"),
        Err(_) => panic!("the composition did not shut down within {SHUTDOWN_WAIT:?}"),
    }
}

/// An operator session on the composition's Client API, and the composition's probe.
pub struct Client {
    addr: SocketAddr,
    token: String,
    probe: Arc<ComposeProbe>,
    /// The longest a turn, with the turn-end pipeline after it, may take.
    wait: Duration,
}

impl Client {
    /// Run a turn of the child at `mailbox` with `payload` as its message, to its END —
    /// the whole turn-end pipeline has returned — and require that it completed. The
    /// Client API, `POST /msg` and the channels all address the root agent only — a
    /// child is messaged by another agent — so the message is published through the
    /// ingress those share, addressed to the child. Nobody is replied to.
    pub async fn child_turn(&self, mailbox: &str, payload: &str) {
        let record = self.probe.record();
        let children = record
            .perchild_manager
            .and_then(|manager| manager.upgrade())
            .expect("a home with `messaging` serves children");
        let ingress = record
            .execution_ingress
            .and_then(|ingress| ingress.upgrade())
            .expect("a home with `messaging` has the protected ingress");
        let id = format!("context-home-{}", nanos());
        ingress
            .publish_for_test(Message {
                id: id.clone(),
                kind: MessageKind::User,
                from: "user:client-api".to_string(),
                to: mailbox.to_string(),
                payload: payload.as_bytes().to_vec(),
                context: None,
                timestamp: SystemTime::now(),
                origin: None,
            })
            .expect("publish the child's turn");
        let deadline = Instant::now() + self.wait;
        let outcome = loop {
            if let Some(outcome) = children.child_turn_end(mailbox, &id) {
                break outcome;
            }
            assert!(
                Instant::now() < deadline,
                "the turn of {mailbox} on message {id} did not end within {:?}",
                self.wait
            );
            tokio::time::sleep(POLL).await;
        };
        assert_eq!(
            outcome,
            TurnOutcome::Completed,
            "the turn of {mailbox} on message {id}"
        );
    }

    /// Send `payload` to the root agent at `mailbox`, wait until its turn ran to its
    /// END — the whole turn-end pipeline has returned, so every request the turn makes
    /// has been made — and require that it completed and failed in nothing.
    pub async fn turn(&self, mailbox: &str, payload: &str) {
        self.turn_message(mailbox, payload).await;
    }

    /// [`Self::turn`], answering the id of the message the turn executed.
    pub async fn turn_message(&self, mailbox: &str, payload: &str) -> String {
        let id = self.send_message(mailbox, payload).await;
        self.await_message_turn(&id).await;
        id
    }

    /// Send `payload` to the root agent at `mailbox` as a Client API message, answering
    /// its id at once, before its turn runs.
    pub async fn send_message(&self, mailbox: &str, payload: &str) -> String {
        let key = format!("context-home-{}", nanos());
        let sent = Http::post(self.addr, "/client/messages")
            .session(&self.token)
            .idempotency_key(key)
            .json(json!({ "to": mailbox, "payload": payload }))
            .await;
        assert_eq!(sent.status, 200, "send: {:?}", sent.body);
        sent.body
            .pointer("/data/message_id")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("message_id missing: {:?}", sent.body))
            .to_owned()
    }

    /// Wait until the turn of message `id` ran to its END, and require that it completed
    /// and failed in nothing.
    pub async fn await_message_turn(&self, id: &str) {
        let deadline = Instant::now() + self.wait;
        let outcome = loop {
            // How THIS message's turn ended: the message status reads the agent's state,
            // which an earlier turn may have set.
            if let Some(outcome) = self.probe.root_turn_outcome(&id) {
                break outcome;
            }
            if Instant::now() >= deadline {
                let status = self.get(&format!("/client/messages/{id}")).await;
                panic!(
                    "message {id} did not settle within {:?}: {status}",
                    self.wait
                );
            }
            tokio::time::sleep(POLL).await;
        };
        let status = self.get(&format!("/client/messages/{id}")).await;
        assert_eq!(
            outcome,
            TurnOutcome::Completed,
            "the turn of message {id}: {status}"
        );
        assert!(
            status.get("failure_class").is_none(),
            "the turn failed: {status}"
        );
    }

    /// Message `id`'s reply stream, read as a client reads it while the turn runs: the
    /// message status polled until it names a stream key, then the stream read page by
    /// page from its first seq until its terminal has arrived and every seq before it has
    /// been read — or, the terminal come, [`TERMINAL_GRACE`] has passed (started again
    /// whenever a page brings text), for a stream whose tail the hub still holds (one that
    /// could begin a secret, on a stream whose terminal is not complete or whose text the hub
    /// dropped some of; MODULE-020-T24-h): the caller then finds the last item read short of
    /// the terminal's seq. The last page
    /// comes back with every item read. A stream the hub no longer serves fails: the hub lets
    /// an ended stream go 30 s after its terminal.
    pub async fn read_message_stream(&self, id: &str) -> advance_client_api::LlmDeltaPage {
        let deadline = Instant::now() + self.wait;
        let mut grace_ends: Option<Instant> = None;
        let key = loop {
            let status = self.get(&format!("/client/messages/{id}")).await;
            if let Some(key) = status.get("stream_key").and_then(Value::as_str) {
                break key.to_owned();
            }
            assert!(
                Instant::now() < deadline,
                "message {id} named no stream within {:?}: {status}",
                self.wait
            );
            tokio::time::sleep(POLL).await;
        };
        let mut read = Vec::new();
        let mut read_to = 0;
        loop {
            let mut page = self.delta_page(&key, read_to);
            assert!(
                !page.absent,
                "the hub no longer serves stream {key} of message {id}"
            );
            let before = read_to;
            if let Some(last) = page.deltas.last() {
                read_to = last.to_seq + 1;
            }
            read.append(&mut page.deltas);
            if page.page_limit_reached && read_to > before {
                continue;
            }
            if !page.page_limit_reached && page.terminal.as_ref().is_some_and(|t| read_to >= t.seq)
            {
                page.deltas = read;
                return page;
            }
            if !page.page_limit_reached && page.terminal.is_some() {
                if read_to > before {
                    grace_ends = None;
                }
                let ends = *grace_ends.get_or_insert_with(|| Instant::now() + TERMINAL_GRACE);
                if Instant::now() >= ends {
                    page.deltas = read;
                    return page;
                }
            }
            assert!(
                Instant::now() < deadline,
                "stream {key} of message {id} did not end within {:?}: {page:?}",
                self.wait
            );
            tokio::time::sleep(POLL).await;
        }
    }

    /// A page of the delta stream `stream_key` from `from_seq`, as the hub serves it to a
    /// client that subscribes to it.
    pub fn delta_page(&self, stream_key: &str, from_seq: u64) -> advance_client_api::LlmDeltaPage {
        self.probe
            .record()
            .llm_delta_hub
            .and_then(|hub| hub.upgrade())
            .expect("a home declaring `llm` has a delta hub")
            .read_page(stream_key, from_seq)
    }

    /// The composition's LLM gateway.
    pub fn gateway(&self) -> Arc<LlmGateway> {
        self.probe
            .record()
            .llm_gateway
            .and_then(|gateway| gateway.upgrade())
            .expect("a home declaring `llm` has a gateway")
    }

    /// `data` of a 200 answer.
    pub async fn get(&self, path: &str) -> Value {
        let resp = Http::get(self.addr, path.to_string())
            .session(&self.token)
            .send()
            .await;
        assert_eq!(resp.status, 200, "GET {path}: {:?}", resp.body);
        resp.body.get("data").cloned().unwrap_or(Value::Null)
    }

    /// The status a GET of `path` is answered with.
    pub async fn status_of(&self, path: &str) -> u16 {
        Http::get(self.addr, path.to_string())
            .session(&self.token)
            .send()
            .await
            .status
    }

    /// Create a child of the root agent from a built-in template, pinned to `provider`.
    pub async fn create_child(&self, handle: &str, capabilities: &[&str], provider: &str) {
        self.create(
            handle,
            json!({
                "agent_id": handle,
                "template_ref": "explorer",
                "capabilities": capabilities,
                "llm": { "provider": provider },
            }),
        )
        .await;
    }

    /// Create a child of the root agent from a built-in template, pinned to no entry:
    /// every entry of the home is open to it.
    pub async fn create_unpinned_child(&self, handle: &str, capabilities: &[&str]) {
        self.create(
            handle,
            json!({
                "agent_id": handle,
                "template_ref": "explorer",
                "capabilities": capabilities,
            }),
        )
        .await;
    }

    async fn create(&self, handle: &str, request: Value) {
        let created = Http::post(self.addr, "/client/agents")
            .session(&self.token)
            .idempotency_key(format!("create-{handle}"))
            .json(request)
            .await;
        assert_eq!(created.status, 200, "create {handle}: {:?}", created.body);
    }

    /// Pin the root agent to `provider` (`POST /client/agents/{agent_id}:update`). The pin
    /// applies to the agent's next model call; nothing is restarted.
    pub async fn pin_root(&self, provider: &str) {
        let agents = self.get("/client/agents").await;
        let handle = agents
            .get("agents")
            .and_then(Value::as_array)
            .and_then(|agents| {
                agents
                    .iter()
                    .find(|listed| listed.get("kind").and_then(Value::as_str) == Some("root"))
            })
            .and_then(|root| root.get("agent_id").and_then(Value::as_str))
            .unwrap_or_else(|| panic!("the root agent is not listed: {agents}"))
            .to_owned();
        let updated = Http::post(self.addr, format!("/client/agents/{handle}:update"))
            .session(&self.token)
            .idempotency_key(format!("pin-root-{provider}"))
            .json(json!({ "llm": { "provider": provider } }))
            .await;
        assert_eq!(
            updated.status, 200,
            "pin the root agent to {provider}: {:?}",
            updated.body
        );
    }

    /// Update the provider entry `id` (`POST /client/providers/{id}:update`) with `body`.
    /// The edit reaches the running config through its watcher; nothing is restarted.
    pub async fn update_provider(&self, id: &str, body: Value) {
        let updated = Http::post(self.addr, format!("/client/providers/{id}:update"))
            .session(&self.token)
            .idempotency_key(format!("update-{id}-{}", nanos()))
            .json(body)
            .await;
        assert_eq!(updated.status, 200, "update {id}: {:?}", updated.body);
    }

    /// The immutable id the agents family lists for `agent` — the id its index rows are
    /// written under — or `None` when the agent is not listed.
    pub async fn listed_id(&self, agent: Agent) -> Option<String> {
        let agents = self.get("/client/agents").await;
        agents
            .get("agents")
            .and_then(Value::as_array)
            .and_then(|agents| {
                agents.iter().find(|listed| match agent {
                    Agent::Root => listed.get("kind").and_then(Value::as_str) == Some("root"),
                    Agent::Child(handle) => {
                        listed.get("agent_id").and_then(Value::as_str) == Some(handle)
                    }
                })
            })
            .and_then(|listed| listed.get("id").and_then(Value::as_str))
            .map(str::to_owned)
    }

    /// The context inspection of `agent` (`GET /client/agents/{agent_id}/context`),
    /// addressed by the immutable id the agents family lists for it.
    pub async fn context(&self, agent: Agent) -> Value {
        let id = self
            .listed_id(agent)
            .await
            .unwrap_or_else(|| panic!("{agent:?} is not listed"));
        self.get(&format!("/client/agents/{id}/context")).await
    }

    /// Delete the child `handle` (`POST /client/agents/{agent_id}:delete`): the terminate
    /// cascade, then the de-registration.
    pub async fn delete_child(&self, handle: &str) {
        let deleted = Http::post(self.addr, format!("/client/agents/{handle}:delete"))
            .session(&self.token)
            .idempotency_key(format!("delete-{handle}-{}", nanos()))
            .json(Value::Null)
            .await;
        assert_eq!(deleted.status, 200, "delete {handle}: {:?}", deleted.body);
    }

    /// `agent`'s context inspection once its index holds `turns` turn rows. (After
    /// [`Self::turn`] / [`Self::child_turn`] it does already: those return at the turn's
    /// end.)
    pub async fn context_with_turns(&self, agent: Agent, turns: u64) -> Value {
        let deadline = Instant::now() + self.wait;
        loop {
            let context = self.context(agent).await;
            if context.pointer("/index/turns").and_then(Value::as_u64) == Some(turns) {
                return context;
            }
            assert!(
                Instant::now() < deadline,
                "{agent:?} did not index {turns} turn(s) within {:?}: {context}",
                self.wait
            );
            tokio::time::sleep(POLL).await;
        }
    }
}

/// An agent of the home, as the Client API lists it.
#[derive(Clone, Copy, Debug)]
pub enum Agent {
    Root,
    /// By handle.
    Child(&'static str),
}

fn nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

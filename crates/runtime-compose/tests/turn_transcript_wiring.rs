//! Host turn transcript, prompt-once, turn-failure and system-message witnesses over the
//! production composition.
//!
//! The model is a scripted chat-completions peer standing in for the network inside the
//! production LLM egress chain (`ComposeFailpoints::llm_security`): credential injection,
//! leak scan, rate limit and events stay the production ones, and everything else is
//! `compose()` on a real home.
//!
//! - A default-scaffold home (`fs` + `llm`, no `messaging`, the default driver) answers a
//!   tool call in round one and sends the call and its result back in round two, with the
//!   user prompt exactly once in each round.
//! - A message whose turn ends in an error carries `failure_class` once the turn has ended:
//!   `provider-error` after a failed model call, `agent-error` without one. A turn that
//!   replied carries none. Unprotected and protected (`messaging`) homes alike.
//! - `system-messages: merge` reaches the wire as one leading system message.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use advance_runtime_compose::test_support::fixture::inference::provider_yaml;
use advance_runtime_compose::test_support::fixture::{
    ext_probe_core, llm_noerr_core, mint_session, CapDecl, FixtureDriver, FixtureExtension,
    FixtureHome, FixtureHomeSpec, Http, FIXTURE_MASTER_KEY, ROOT_MAILBOX,
};
use advance_runtime_compose::test_support::{
    ComposeFailpoints, ComposeProbe, LlmSecurityOverride, MemoryComposeLog,
};
use advance_runtime_compose::{
    compose, ComposeExtension, ComposeOptions, MasterKeyInput, Zeroizing,
};
use advance_shared_types::security_validator::{HttpRequest, HttpResponse, RedirectCheck};
use cap_http::{DefaultSsrfGuard, ExecutorError, HttpExecutor, MockResolver};
use cap_secrets::{FileSecretStorage, SecretStore};
use futures::FutureExt;
use serde_json::{json, Value};

/// The default driver a new home is created with (`advance_home::create::create`).
const CALLABLES_CORE: &[u8] =
    include_bytes!("../../runtime/tests/fixtures/guest-rust-callables.core.wasm");

const PEER_HOST: &str = "llm.example.test";
const PEER_ENDPOINT: &str = "https://llm.example.test";
const CHAT_URL: &str = "https://llm.example.test/v1/chat/completions";
const PROVIDER_ID: &str = "scripted";
const API_KEY_SECRET: &str = "scripted-api-key";
const TOOL_CALL_ID: &str = "call_round_one";
const NOTE_PATH: &str = "note.md";
const NOTE_TEXT: &str = "written in round one";
const FINAL_TEXT: &str = "the note is written";
const WAIT: Duration = Duration::from_secs(90);
const POLL: Duration = Duration::from_millis(50);

fn write_args() -> String {
    json!({ "path": NOTE_PATH, "content": NOTE_TEXT }).to_string()
}

// ---------------------------------------------------------------------------
// The scripted peer
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Script {
    /// A request that offers `write` and carries no tool result asks for one `write`
    /// call; any other request is answered in text.
    ToolLoop,
    /// Every chat request is refused with this HTTP status.
    Refuse(u16),
}

#[derive(Clone)]
struct Hold {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

impl Hold {
    async fn entered(&self) {
        tokio::time::timeout(WAIT, self.entered.notified())
            .await
            .expect("the turn reaches the model");
    }

    fn release(&self) {
        self.release.notify_one();
    }
}

struct ScriptedPeer {
    script: Mutex<Script>,
    bodies: Mutex<Vec<Value>>,
    hold: Mutex<Option<Hold>>,
}

impl ScriptedPeer {
    fn new(script: Script) -> Arc<Self> {
        Arc::new(Self {
            script: Mutex::new(script),
            bodies: Mutex::new(Vec::new()),
            hold: Mutex::new(None),
        })
    }

    fn set_script(&self, script: Script) {
        *self.script.lock().unwrap() = script;
    }

    /// Every chat-completions body the peer received, in arrival order.
    fn chat_bodies(&self) -> Vec<Value> {
        self.bodies.lock().unwrap().clone()
    }

    /// The bodies of the guest's tool-loop rounds (each offers the host catalog).
    fn round_bodies(&self) -> Vec<Value> {
        self.chat_bodies()
            .into_iter()
            .filter(|body| offers_tool(body, "write"))
            .collect()
    }

    /// The next chat request waits inside the peer until [`Hold::release`].
    fn hold_next(&self) -> Hold {
        let hold = Hold {
            entered: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
        };
        *self.hold.lock().unwrap() = Some(hold.clone());
        hold
    }

    fn security(self: &Arc<Self>) -> LlmSecurityOverride {
        let resolver = MockResolver::new().with(
            PEER_HOST,
            vec!["8.8.8.8".parse::<IpAddr>().expect("public address")],
        );
        LlmSecurityOverride {
            ssrf: Arc::new(DefaultSsrfGuard::with_resolver(Box::new(resolver))),
            executor: Arc::clone(self) as Arc<dyn HttpExecutor>,
        }
    }
}

#[async_trait::async_trait]
impl HttpExecutor for ScriptedPeer {
    async fn execute(
        &self,
        req: &HttpRequest,
        _redirect_check: Arc<dyn RedirectCheck>,
    ) -> Result<HttpResponse, ExecutorError> {
        if req.url != CHAT_URL {
            return Ok(json_response(
                404,
                json!({ "error": { "message": "not scripted" } }),
            ));
        }
        let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        self.bodies.lock().unwrap().push(body.clone());
        let hold = self.hold.lock().unwrap().take();
        if let Some(hold) = hold {
            hold.entered.notify_one();
            hold.release.notified().await;
        }
        let script = *self.script.lock().unwrap();
        Ok(match script {
            Script::Refuse(status) => json_response(
                status,
                json!({ "error": { "message": "scripted refusal", "type": "invalid_request_error" } }),
            ),
            Script::ToolLoop if !carries_tool_result(&body) && offers_tool(&body, "write") => {
                json_response(
                    200,
                    json!({
                        "id": "chatcmpl-round-one",
                        "object": "chat.completion",
                        "model": "scripted-model",
                        "choices": [{
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": null,
                                "tool_calls": [{
                                    "id": TOOL_CALL_ID,
                                    "type": "function",
                                    "function": { "name": "write", "arguments": write_args() }
                                }]
                            },
                            "finish_reason": "tool_calls"
                        }],
                        "usage": { "prompt_tokens": 11, "completion_tokens": 6 }
                    }),
                )
            }
            Script::ToolLoop => json_response(
                200,
                json!({
                    "id": "chatcmpl-text",
                    "object": "chat.completion",
                    "model": "scripted-model",
                    "choices": [{
                        "index": 0,
                        "message": { "role": "assistant", "content": FINAL_TEXT },
                        "finish_reason": "stop"
                    }],
                    "usage": { "prompt_tokens": 20, "completion_tokens": 4 }
                }),
            ),
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

fn messages(body: &Value) -> Vec<Value> {
    body.get("messages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn offers_tool(body: &Value, name: &str) -> bool {
    body.get("tools")
        .and_then(Value::as_array)
        .is_some_and(|tools| {
            tools
                .iter()
                .any(|tool| tool.pointer("/function/name").and_then(Value::as_str) == Some(name))
        })
}

fn carries_tool_result(body: &Value) -> bool {
    messages(body)
        .iter()
        .any(|message| message.get("role").and_then(Value::as_str) == Some("tool"))
}

fn user_messages_with(body: &Value, text: &str) -> usize {
    messages(body)
        .iter()
        .filter(|message| {
            message.get("role").and_then(Value::as_str) == Some("user")
                && message.get("content").and_then(Value::as_str) == Some(text)
        })
        .count()
}

fn role_of(message: &Value) -> &str {
    message.get("role").and_then(Value::as_str).unwrap_or("")
}

// ---------------------------------------------------------------------------
// Homes and composition
// ---------------------------------------------------------------------------

/// The scripted `llm-providers` entry (openai-chat dialect, cloud-http), as one YAML
/// mapping without the list dash.
fn scripted_entry_mapping(extra: &str) -> String {
    format!(
        "id: {PROVIDER_ID}\nendpoint: {PEER_ENDPOINT}\napi-key-secret: {API_KEY_SECRET}\nmodel-aliases: {{ default: scripted-model }}\ncost-per-mtoken-in: 1.0\ncost-per-mtoken-out: 2.0\nrate-limit: {{ requests-per-minute: 1000, tokens-per-minute: 1000000 }}\n{extra}"
    )
}

/// The same entry as one item of a `llm-providers:` list.
fn scripted_entry_item(extra: &str) -> String {
    let mut item = String::new();
    for (i, line) in scripted_entry_mapping(extra).lines().enumerate() {
        item.push_str(if i == 0 { "  - " } else { "    " });
        item.push_str(line);
        item.push('\n');
    }
    item
}

/// Store the scripted entry's API key in the home's File secret store under the key the
/// composition is given.
fn seed_api_key(home: &Path) {
    let storage = Arc::new(
        FileSecretStorage::open(home.join(".advance/secrets.json")).expect("open secrets.json"),
    );
    SecretStore::new(Zeroizing::new(FIXTURE_MASTER_KEY), storage)
        .store(API_KEY_SECRET, "scripted-key-value")
        .expect("store the API key");
}

/// A home exactly as `advance_home::create::create` writes it (starter runtime config, `fs` +
/// `llm` agent config, the default driver), plus the scripted entry selected as the
/// default provider and its key.
struct ScaffoldHome {
    _parent: tempfile::TempDir,
    _state: tempfile::TempDir,
    home: PathBuf,
    state_root: PathBuf,
}

impl ScaffoldHome {
    fn new(extra_entry_keys: &str) -> Self {
        let parent = tempfile::tempdir().expect("parent dir");
        let state = tempfile::tempdir().expect("state dir");
        advance_home::create::create(parent.path(), "home").expect("create a default home");
        let home = std::fs::canonicalize(parent.path().join("home")).expect("home path");
        let state_root = std::fs::canonicalize(state.path()).expect("state path");
        assert_eq!(
            std::fs::read_to_string(home.join(".agent/config.yaml")).expect("agent config"),
            advance_home::AGENT_CONFIG_STARTER,
            "the default agent config declares fs + llm and no messaging"
        );
        assert_eq!(
            std::fs::read(home.join(".agent/behavior.wasm")).expect("default driver"),
            CALLABLES_CORE,
            "the default driver is the callables guest"
        );
        let entry: serde_yml::Value =
            serde_yml::from_str(&scripted_entry_mapping(extra_entry_keys)).expect("entry yaml");
        advance_home::upsert_provider_entry(&home, entry, advance_home::UpsertMode::Create)
            .expect("add the scripted entry");
        advance_home::select_provider(&home, PROVIDER_ID).expect("select the scripted entry");
        seed_api_key(&home);
        Self {
            _parent: parent,
            _state: state,
            home,
            state_root,
        }
    }

    fn options(&self, peer: &Arc<ScriptedPeer>) -> ComposeOptions {
        ComposeOptions::daemon(self.home.clone(), Arc::new(MemoryComposeLog::new()))
            .with_state_root(self.state_root.clone())
            .with_master_key(MasterKeyInput::Provided(Zeroizing::new(FIXTURE_MASTER_KEY)))
            .with_failpoints(ComposeFailpoints {
                probe: Some(Arc::new(ComposeProbe::new())),
                llm_security: Some(peer.security()),
                ..ComposeFailpoints::default()
            })
    }
}

/// A fixture home whose provider list is the scripted entry alone.
fn fixture_home(caps: &[&'static str], driver: FixtureDriver) -> FixtureHome {
    let home = FixtureHome::new(FixtureHomeSpec {
        capabilities: caps.iter().copied().map(CapDecl::Granted).collect(),
        driver,
        git: false,
        providers_yaml: Some(provider_yaml::llm_providers_block(&[scripted_entry_item(
            "",
        )
        .as_str()])),
    })
    .expect("fixture home");
    seed_api_key(home.home());
    home
}

fn fixture_options(home: &FixtureHome, peer: &Arc<ScriptedPeer>) -> ComposeOptions {
    let probe = Arc::new(ComposeProbe::new());
    home.options(Arc::new(MemoryComposeLog::new()), Arc::clone(&probe))
        .with_failpoints(ComposeFailpoints {
            probe: Some(probe),
            llm_security: Some(peer.security()),
            ..ComposeFailpoints::default()
        })
}

/// Compose, run `body` against the live Client API, then shut the composition down even
/// when `body` panicked and re-raise the panic: a failed assertion reports instead of
/// hanging in the test runtime's drop, which waits on the live composition's workers.
async fn serve<F, Fut>(options: ComposeOptions, extensions: Vec<Arc<dyn ComposeExtension>>, body: F)
where
    F: FnOnce(Client) -> Fut,
    Fut: Future<Output = ()>,
{
    let rt = tokio::time::timeout(Duration::from_secs(180), compose(options, extensions))
        .await
        .expect("compose in time")
        .expect("compose");
    let endpoint = rt.client_api().expect("client api");
    let client = Client {
        addr: endpoint.socket_addr,
        token: mint_session(&endpoint),
    };
    let outcome = AssertUnwindSafe(body(client)).catch_unwind().await;
    rt.shutdown().await.expect("shutdown");
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

// ---------------------------------------------------------------------------
// Client API helpers
// ---------------------------------------------------------------------------

/// An operator session on the composition's Client API.
struct Client {
    addr: SocketAddr,
    token: String,
}

impl Client {
    async fn send(&self, payload: &str) -> String {
        let key = format!(
            "turn-wiring-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let sent = Http::post(self.addr, "/client/messages")
            .session(&self.token)
            .idempotency_key(key)
            .json(json!({ "to": ROOT_MAILBOX, "payload": payload }))
            .await;
        assert_eq!(sent.status, 200, "send: {:?}", sent.body);
        sent.body
            .pointer("/data/message_id")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("message_id missing: {:?}", sent.body))
            .to_owned()
    }

    async fn status(&self, message_id: &str) -> Value {
        let resp = Http::get(self.addr, format!("/client/messages/{message_id}"))
            .session(&self.token)
            .send()
            .await;
        assert_eq!(resp.status, 200, "status: {:?}", resp.body);
        resp.body.get("data").cloned().unwrap_or(Value::Null)
    }

    /// Poll the message status until it settles: replied, or a failure class is present.
    async fn settled(&self, message_id: &str) -> Value {
        let deadline = Instant::now() + WAIT;
        loop {
            let data = self.status(message_id).await;
            if reply_state(&data) == "replied" || data.get("failure_class").is_some() {
                return data;
            }
            assert!(
                Instant::now() < deadline,
                "message {message_id} did not settle within {WAIT:?}: {data}"
            );
            tokio::time::sleep(POLL).await;
        }
    }
}

fn failure_class(data: &Value) -> Option<&str> {
    data.get("failure_class").and_then(Value::as_str)
}

fn reply_state(data: &Value) -> &str {
    data.get("reply_state")
        .and_then(Value::as_str)
        .unwrap_or("")
}

// ---------------------------------------------------------------------------
// Host transcript and prompt-once
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_default_home_sends_the_tool_call_and_its_result_back_in_round_two() {
    const PROMPT: &str = "write a note for me";
    let home = ScaffoldHome::new("");
    let peer = ScriptedPeer::new(Script::ToolLoop);
    let note = home.home.join(NOTE_PATH);
    serve(home.options(&peer), Vec::new(), |client| async move {
        let id = client.send(PROMPT).await;
        let data = client.settled(&id).await;
        assert_eq!(
            (reply_state(&data), failure_class(&data)),
            ("replied", None),
            "{data}"
        );

        let rounds = peer.round_bodies();
        assert_eq!(
            rounds.len(),
            2,
            "round one asks for the call, round two answers: {rounds:#?}"
        );
        let (one, two) = (messages(&rounds[0]), messages(&rounds[1]));
        assert_eq!(
            user_messages_with(&rounds[0], PROMPT),
            1,
            "round one carries the prompt once: {one:#?}"
        );
        assert_eq!(
            one.last().map(role_of),
            Some("user"),
            "round one ends with the prompt: {one:#?}"
        );

        // Round two continues round one: the same messages, then the call and its result.
        assert!(two.len() >= one.len(), "round two: {two:#?}");
        assert_eq!(&two[..one.len()], &one[..], "round two: {two:#?}");
        let tail = &two[one.len()..];
        assert_eq!(tail.len(), 2, "the call and its result: {tail:#?}");
        assert_eq!(role_of(&tail[0]), "assistant", "{tail:#?}");
        assert_eq!(
            tail[0].pointer("/tool_calls/0/id").and_then(Value::as_str),
            Some(TOOL_CALL_ID),
            "{tail:#?}"
        );
        assert_eq!(
            tail[0]
                .pointer("/tool_calls/0/function/name")
                .and_then(Value::as_str),
            Some("write"),
            "{tail:#?}"
        );
        assert_eq!(
            tail[0]
                .pointer("/tool_calls/0/function/arguments")
                .and_then(Value::as_str),
            Some(write_args().as_str()),
            "{tail:#?}"
        );
        assert_eq!(role_of(&tail[1]), "tool", "{tail:#?}");
        assert_eq!(
            tail[1].get("tool_call_id").and_then(Value::as_str),
            Some(TOOL_CALL_ID),
            "{tail:#?}"
        );
        assert_eq!(
            user_messages_with(&rounds[1], PROMPT),
            1,
            "round two does not repeat the prompt: {two:#?}"
        );
        assert_eq!(
            std::fs::read_to_string(&note).expect("the note"),
            NOTE_TEXT,
            "the call ran through the production dispatcher"
        );

        // The next message starts a new scope: nothing of the first turn is replayed.
        let before = peer.round_bodies().len();
        let id = client.send("write another note").await;
        let data = client.settled(&id).await;
        assert_eq!(reply_state(&data), "replied", "{data}");
        let next = peer.round_bodies();
        let first_round = messages(&next[before]);
        assert!(
            !first_round
                .iter()
                .any(|message| role_of(message) == "tool" || message.get("tool_calls").is_some()),
            "a new turn starts without the previous transcript: {first_round:#?}"
        );
    })
    .await;
}

// ---------------------------------------------------------------------------
// Failure classes
// ---------------------------------------------------------------------------

/// A refused model call ends the callables guest's turn in an error: the message reports
/// `provider-error`, but only once the turn has ended. A later turn that replies carries
/// no class, and the failed message keeps its own.
async fn provider_error_once_the_turn_has_ended(options: ComposeOptions, peer: Arc<ScriptedPeer>) {
    let hold = peer.hold_next();
    serve(options, Vec::new(), |client| async move {
        let failed = client.send("this call is refused").await;
        hold.entered().await;
        let in_flight = client.status(&failed).await;
        assert_eq!(
            (reply_state(&in_flight), failure_class(&in_flight)),
            ("none", None),
            "no class while the turn is in flight: {in_flight}"
        );
        hold.release();
        let ended = client.settled(&failed).await;
        assert_eq!(
            (reply_state(&ended), failure_class(&ended)),
            ("none", Some("provider-error")),
            "{ended}"
        );

        peer.set_script(Script::ToolLoop);
        let replied = client.send("write a note for me").await;
        let data = client.settled(&replied).await;
        assert_eq!(
            (reply_state(&data), failure_class(&data)),
            ("replied", None),
            "{data}"
        );
        // `reply_state` is the agent's (its last turn replied); the class is the message's.
        let again = client.status(&failed).await;
        assert_eq!(
            (reply_state(&again), failure_class(&again)),
            ("replied", Some("provider-error")),
            "{again}"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unprotected_home_reports_provider_error_once_the_failed_turn_has_ended() {
    let home = ScaffoldHome::new("");
    let peer = ScriptedPeer::new(Script::Refuse(401));
    provider_error_once_the_turn_has_ended(home.options(&peer), peer).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_protected_home_reports_provider_error_once_the_failed_turn_has_ended() {
    let home = fixture_home(
        &["fs", "llm", "messaging"],
        FixtureDriver::Core(CALLABLES_CORE),
    );
    let peer = ScriptedPeer::new(Script::Refuse(401));
    provider_error_once_the_turn_has_ended(fixture_options(&home, &peer), peer).await;
}

/// A guest trap with no model call is `agent-error`; a turn of the same guest that
/// replies carries no class.
async fn a_trap_reports_agent_error(caps: &[&'static str]) {
    let home = fixture_home(caps, FixtureDriver::Core(ext_probe_core()));
    let peer = ScriptedPeer::new(Script::ToolLoop);
    let options = fixture_options(&home, &peer);
    serve(
        options,
        vec![FixtureExtension::standard().arc()],
        |client| async move {
            let trapped = client.send("trap").await;
            let data = client.settled(&trapped).await;
            assert_eq!(
                (reply_state(&data), failure_class(&data)),
                ("none", Some("agent-error")),
                "{data}"
            );

            let replied = client.send("plain after").await;
            let data = client.settled(&replied).await;
            assert_eq!(
                (reply_state(&data), failure_class(&data)),
                ("replied", None),
                "{data}"
            );
            assert!(peer.chat_bodies().is_empty(), "no model call was made");
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unprotected_trap_without_a_model_failure_reports_agent_error() {
    a_trap_reports_agent_error(&["fs", "fixture.probe"]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_protected_trap_without_a_model_failure_reports_agent_error() {
    a_trap_reports_agent_error(&["fs", "fixture.probe", "messaging"]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_turn_that_replies_after_a_failed_model_call_carries_no_failure_class() {
    let home = fixture_home(&["fs", "llm"], FixtureDriver::Core(llm_noerr_core()));
    let peer = ScriptedPeer::new(Script::Refuse(401));
    let options = fixture_options(&home, &peer);
    serve(options, Vec::new(), |client| async move {
        let id = client.send("llm:hello").await;
        let data = client.settled(&id).await;
        assert_eq!(
            (reply_state(&data), failure_class(&data)),
            ("replied", None),
            "{data}"
        );
        assert_eq!(
            peer.chat_bodies().len(),
            1,
            "the one model call was refused"
        );
    })
    .await;
}

// ---------------------------------------------------------------------------
// System-message merge
// ---------------------------------------------------------------------------

/// One tool-loop turn on a default-scaffold home whose scripted entry carries
/// `extra_entry_keys`; the bodies of its rounds with the home path written as `<home>`.
async fn tool_loop_rounds(extra_entry_keys: &str) -> Vec<Value> {
    let home = ScaffoldHome::new(extra_entry_keys);
    let peer = ScriptedPeer::new(Script::ToolLoop);
    let options = home.options(&peer);
    serve(options, Vec::new(), |client| async move {
        let id = client.send("write a note for me").await;
        let data = client.settled(&id).await;
        assert_eq!(
            (reply_state(&data), failure_class(&data)),
            ("replied", None),
            "{data}"
        );
    })
    .await;
    let path = home.home.display().to_string();
    peer.round_bodies()
        .into_iter()
        .map(|body| {
            serde_json::from_str(&body.to_string().replace(&path, "<home>")).expect("body json")
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn system_messages_merge_reaches_the_wire_as_one_leading_system_message() {
    // `separate` and an entry without the key build byte-identical bodies (the provider
    // knob tests); this witness puts the merged form next to the default one.
    let (absent, merged) = tokio::join!(
        tool_loop_rounds(""),
        tool_loop_rounds("system-messages: merge\n"),
    );
    assert_eq!(absent.len(), 2, "{absent:#?}");

    let one = messages(&absent[0]);
    let systems = one
        .iter()
        .filter(|message| role_of(message) == "system")
        .count();
    assert!(
        systems > 1,
        "the assembled context carries several system messages: {one:#?}"
    );

    assert_eq!(merged.len(), 2, "{merged:#?}");
    for (round, (merged_body, absent_body)) in merged.iter().zip(&absent).enumerate() {
        let sent = messages(merged_body);
        let original = messages(absent_body);
        let mut expected = vec![json!({
            "role": "system",
            "content": original
                .iter()
                .filter(|message| role_of(message) == "system")
                .map(|message| message.get("content").and_then(Value::as_str).unwrap_or(""))
                .collect::<Vec<_>>()
                .join("\n\n"),
        })];
        expected.extend(
            original
                .iter()
                .filter(|message| role_of(message) != "system")
                .cloned(),
        );
        assert_eq!(sent, expected, "round {}", round + 1);
        let mut rest = merged_body.clone();
        let mut rest_absent = absent_body.clone();
        rest.as_object_mut().expect("body").remove("messages");
        rest_absent
            .as_object_mut()
            .expect("body")
            .remove("messages");
        assert_eq!(
            rest,
            rest_absent,
            "only the messages differ (round {})",
            round + 1
        );
    }
}

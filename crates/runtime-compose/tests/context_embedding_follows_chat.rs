//! Embedding follows the agent's chat provider — witnessed on the PRODUCTION
//! context wiring.
//!
//! One real `LlmGateway` serves three agents, each pinned to its own provider by
//! its `llm:` policy. Everything the daemon wires per agent is the real thing:
//! `build_context_assembler_for_agent_production` (the builder
//! `try_spawn_agent_loop` and the child loops call), the agent's
//! `AgentEmbedding` wiring, `GatewayMemoryEmbedder`, `SqliteIndexRecall` over a
//! shared index and the Client API `ContextInspectAdapter`. Only the upstream
//! HTTP peer is a double, and it records every request that leaves the gateway.
//!
//! What must hold:
//! - an agent's prompt and turn text are embedded ONLY by the provider that agent
//!   chats with, with that provider's embedding model;
//! - an agent whose chat provider serves no embeddings sends its text nowhere;
//! - stored vectors are compared only with a query of the same model;
//! - all of it follows the live policy: re-pinning an agent applies to its next
//!   turn, with no rebuild of the assembler or the gateway.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use advance_client_api::ContextInspectProvider;
use advance_runtime::config::RuntimeConfig;
use advance_runtime_compose::context_inspect::{
    gateway_embedding_posture, ContextInspectAdapter, ContextSnapshotStore,
};
use advance_runtime_compose::context_wiring::{
    build_context_assembler_for_agent_production, live_embedding_model, AgentEmbedding,
    EmptyAgentTree, EmptyCallableInventory, EmptyDecomposition, FixedHostFnInventory,
    GatewayMemoryEmbedder, ProductionAssemblerParts,
};
use advance_shared_types::agent_tree::{AgentState, AgentStatus};
use advance_shared_types::context::{AssemblyContext, ContextAssembler, LlmMessage};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{Message, MessageKind};
use advance_shared_types::security_validator::{
    HttpCapability, HttpError, HttpRequest, HttpResponse, HttpSecurityChain,
};
use advance_shared_types::traits::EventBusEmit;
use async_trait::async_trait;
use cap_llm::{AgentLlmPolicy, AgentLlmPolicySource, LlmGateway};
use cap_memory::{Embedder, InMemorySqliteIndex, MemoryStore, SqliteIndex, TurnIndexRow};

// ── the doubled upstream ──

/// One request that left the gateway.
#[derive(Clone, Debug, PartialEq)]
struct Sent {
    /// The agent the security chain was asked to act for.
    agent: String,
    url: String,
    model: String,
    input: String,
}

/// Answers `/v1/embeddings` with a vector that depends only on the HOST, in the
/// SAME dimension for every host — so a test cannot pass by a dimension mismatch.
#[derive(Default)]
struct Upstream {
    sent: Mutex<Vec<Sent>>,
    /// Runs once, while the next request is being served.
    during_next: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Upstream {
    fn sent(&self) -> Vec<Sent> {
        self.sent.lock().unwrap().clone()
    }
    fn take(&self) -> Vec<Sent> {
        std::mem::take(&mut *self.sent.lock().unwrap())
    }
    fn during_next_request(&self, f: impl FnOnce() + Send + 'static) {
        *self.during_next.lock().unwrap() = Some(Box::new(f));
    }
}

#[async_trait]
impl HttpSecurityChain for Upstream {
    async fn execute(
        &self,
        agent_id: &str,
        req: HttpRequest,
        _cap: &HttpCapability,
    ) -> Result<HttpResponse, HttpError> {
        let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
        self.sent.lock().unwrap().push(Sent {
            agent: agent_id.to_string(),
            url: req.url.clone(),
            model: body["model"].as_str().unwrap_or_default().to_string(),
            input: body["input"].as_str().unwrap_or_default().to_string(),
        });
        let during = self.during_next.lock().unwrap().take();
        if let Some(during) = during {
            during();
        }
        let vector = if req.url.starts_with("https://alpha.example.test") {
            [1.0, 0.0]
        } else {
            [0.0, 1.0]
        };
        Ok(HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: serde_json::to_vec(&serde_json::json!({ "data": [{ "embedding": vector }] }))
                .expect("answer serializes"),
        })
    }
}

/// Every event the gateway emits.
#[derive(Default)]
struct Bus(Mutex<Vec<Event>>);

impl EventBusEmit for Bus {
    fn emit(&self, event: Event) {
        self.0.lock().unwrap().push(event);
    }
}

/// The per-agent `llm:` policies; they can change while the daemon runs.
#[derive(Default)]
struct Policies(Mutex<HashMap<String, AgentLlmPolicy>>);

impl Policies {
    fn pin(&self, agent: &str, provider: &str) {
        self.0.lock().unwrap().insert(
            agent.into(),
            AgentLlmPolicy {
                provider: Some(provider.into()),
                ..Default::default()
            },
        );
    }
}

impl AgentLlmPolicySource for Policies {
    fn policy_for(&self, agent_id: &str) -> Option<AgentLlmPolicy> {
        self.0.lock().unwrap().get(agent_id).cloned()
    }
}

// ── the composition under test ──

const ALPHA: &str = "https://alpha.example.test/v1/embeddings";
const BETA: &str = "https://beta.example.test/v1/embeddings";

/// A stored vector equally close to BOTH providers' answers (`[1, 0]` and
/// `[0, 1]`): only the model a row is bound to decides whether a query may be
/// compared with it.
const NEAR_BOTH: [f32; 2] = [1.0, 1.0];

/// `alpha` and `beta` name an embedding model; `gamma` chats only.
fn config() -> RuntimeConfig {
    serde_yml::from_str(
        r#"
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false
llm-providers:
  - id: alpha
    endpoint: https://alpha.example.test
    api-key-secret: alpha-api-key
    embedding-model: alpha-embed
    model-aliases:
      default: alpha-chat
    cost-per-mtoken-in: 1.0
    cost-per-mtoken-out: 2.0
  - id: beta
    endpoint: https://beta.example.test
    api-key-secret: beta-api-key
    embedding-model: beta-embed
    model-aliases:
      default: beta-chat
    cost-per-mtoken-in: 1.0
    cost-per-mtoken-out: 2.0
  - id: gamma
    endpoint: https://gamma.example.test
    api-key-secret: gamma-api-key
    model-aliases:
      default: gamma-chat
    cost-per-mtoken-in: 1.0
    cost-per-mtoken-out: 2.0
cron:
  max_jitter_ratio: 0.1
git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10
secrets:
  master-key-source: env-var
  env-var-name: EMBED_FOLLOWS_CHAT_MASTER_KEY
post-processor:
  llm-model: alpha-chat
  llm-failure-cooldown-seconds: 600
"#,
    )
    .expect("runtime config parses")
}

struct Rig {
    gateway: Arc<LlmGateway>,
    upstream: Arc<Upstream>,
    bus: Arc<Bus>,
    policies: Arc<Policies>,
    index: Arc<InMemorySqliteIndex>,
    reports: Arc<ContextSnapshotStore>,
}

impl Rig {
    fn new() -> Self {
        let upstream = Arc::new(Upstream::default());
        let bus = Arc::new(Bus::default());
        let policies = Arc::new(Policies::default());
        policies.pin("root", "alpha");
        policies.pin("researcher", "beta");
        policies.pin("writer", "gamma");
        let gateway = Arc::new(
            LlmGateway::new(
                Arc::new(cap_llm::StaticConfig(Arc::new(config()))),
                Arc::clone(&upstream) as Arc<dyn HttpSecurityChain>,
                Arc::new(cap_llm::PreflightAllowBudget),
                Arc::clone(&bus) as Arc<dyn EventBusEmit>,
                Arc::new(cap_llm::NoopRepetition),
                "root".to_string(),
            )
            .with_agent_policy(Arc::clone(&policies) as Arc<dyn AgentLlmPolicySource>),
        );
        Self {
            gateway,
            upstream,
            bus,
            policies,
            index: Arc::new(InMemorySqliteIndex::default()),
            reports: Arc::new(ContextSnapshotStore::new()),
        }
    }

    /// The production assembler of one agent, wired as the daemon wires it.
    fn assembler(&self, agent: &str) -> Arc<dyn ContextAssembler> {
        let aliases = vec![agent.to_string(), format!("agent:{agent}")];
        self.reports.register_aliases(&aliases);
        build_context_assembler_for_agent_production(ProductionAssemblerParts {
            event_bus: Arc::new(cap_llm::DiscardEventBus),
            callable_inventory: Arc::new(EmptyCallableInventory),
            host_fn_inventory: Arc::new(FixedHostFnInventory::from_names(&[])),
            agent_tree: Arc::new(EmptyAgentTree),
            memory: Some(Arc::new(MemoryStore::new())),
            write_agent_id: agent,
            query_aliases: &aliases,
            memory_root: None,
            skills_agent_root: None,
            decomposition: Arc::new(EmptyDecomposition),
            pack_skills: None,
            identity_agent_root: None,
            embedding: Some(AgentEmbedding::over_gateway(
                Arc::clone(&self.gateway),
                agent,
            )),
            sqlite_index: Some(Arc::clone(&self.index) as Arc<dyn SqliteIndex + Send + Sync>),
            runtime_info: Some(advance_context_engine::RuntimeInfoView {
                runtime_version: "0.0.0-test".into(),
                memory_enabled: true,
                // Deliberately stale: the builder must re-read it per assembly.
                embedding_enabled: false,
                ..Default::default()
            }),
            report_sink: Some(Arc::clone(&self.reports) as _),
            light_llm: None,
            native_tools: None,
        })
    }

    /// The Client API context inspector, wired as the daemon wires it.
    fn inspector(&self) -> ContextInspectAdapter {
        ContextInspectAdapter::new(
            Arc::clone(&self.reports),
            gateway_embedding_posture(Arc::clone(&self.gateway)),
            Some(Arc::clone(&self.index) as Arc<dyn SqliteIndex + Send + Sync>),
            "root",
        )
    }

    /// Seed one past turn of `agent` whose vector came from `model`.
    fn seed_turn(
        &self,
        agent: &str,
        turn: u32,
        digest: &str,
        vector: [f32; 2],
        model: Option<&str>,
    ) {
        self.index.upsert_turn(TurnIndexRow {
            agent_id: agent.into(),
            task_id: format!("_agent-{agent}"),
            turn,
            digest: digest.into(),
            embedding: vector.to_vec(),
            embedding_model: model.map(str::to_string),
            reference_count: 0,
            updated_at: format!("2026-11-17T00:00:{turn:02}Z"),
        });
    }

    fn llm_events(&self) -> Vec<(String, String, String)> {
        self.bus
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e.event_type.clone(),
                    e.agent_id.clone(),
                    e.payload["provider_id"]
                        .as_str()
                        .or(e.payload["provider"].as_str())
                        .unwrap_or_default()
                        .to_string(),
                )
            })
            .collect()
    }
}

fn turn(agent: &str, prompt: &str) -> AssemblyContext {
    let routing_id = format!("agent:{agent}");
    AssemblyContext {
        agent_id: routing_id.clone(),
        task_id: None,
        message: Message {
            id: "m-1".into(),
            kind: MessageKind::User,
            from: "user:test".into(),
            to: routing_id.clone(),
            payload: Vec::new(),
            context: None,
            timestamp: SystemTime::UNIX_EPOCH,
            origin: None,
        },
        prompt: prompt.into(),
        model: "claude-3-5-sonnet-20241022".into(),
        turn_buffer: Vec::<LlmMessage>::new(),
        prior_state: AgentState {
            agent_id: routing_id,
            status: AgentStatus::Active,
            current_task_id: None,
            current_run_id: None,
            iteration: 0,
            turn_counter: 0,
            last_handle_message_at: None,
        },
    }
}

fn prompt_text(messages: &[LlmMessage]) -> String {
    messages
        .iter()
        .map(|m| m.content.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

fn sent(agent: &str, url: &str, model: &str, input: &str) -> Sent {
    Sent {
        agent: agent.into(),
        url: url.into(),
        model: model.into(),
        input: input.into(),
    }
}

// ── the query side: prompt embedding + recall ──

/// Two agents on two providers: each prompt is embedded once, by that agent's own
/// chat provider with that provider's model, and recall reads only the rows whose
/// vector came from that same model.
#[tokio::test]
async fn each_agents_prompt_is_embedded_only_by_its_own_chat_provider() {
    let rig = Rig::new();
    // Every seeded vector points the SAME way as the alpha answer, so only the
    // model binding can keep a row out.
    rig.seed_turn(
        "root",
        1,
        "root turn embedded by alpha",
        [1.0, 0.0],
        Some("alpha-embed"),
    );
    rig.seed_turn(
        "root",
        2,
        "root turn embedded by beta",
        [1.0, 0.0],
        Some("beta-embed"),
    );
    rig.seed_turn(
        "researcher",
        1,
        "researcher turn embedded by beta",
        [0.0, 1.0],
        Some("beta-embed"),
    );
    rig.seed_turn(
        "researcher",
        2,
        "researcher turn embedded by alpha",
        [0.0, 1.0],
        Some("alpha-embed"),
    );

    let root = rig.assembler("root");
    let researcher = rig.assembler("researcher");

    let assembled = root
        .assemble(turn("root", "what did root deploy?"))
        .await
        .expect("root assembles");
    assert_eq!(
        rig.upstream.take(),
        vec![sent("root", ALPHA, "alpha-embed", "what did root deploy?")],
        "one request, to root's chat provider only"
    );
    let text = prompt_text(&assembled.messages);
    assert!(text.contains("# Recalled Context"), "{text}");
    assert!(text.contains("root turn embedded by alpha"), "{text}");
    assert!(
        !text.contains("root turn embedded by beta"),
        "a vector of another model is never compared with the query: {text}"
    );
    assert!(
        text.contains("- recall: semantic"),
        "the runtime section reads the live route, not the value fixed at spawn: {text}"
    );

    let assembled = researcher
        .assemble(turn("researcher", "what did the researcher find?"))
        .await
        .expect("researcher assembles");
    assert_eq!(
        rig.upstream.take(),
        vec![sent(
            "researcher",
            BETA,
            "beta-embed",
            "what did the researcher find?"
        )],
        "one request, to the researcher's chat provider only"
    );
    let text = prompt_text(&assembled.messages);
    assert!(text.contains("researcher turn embedded by beta"), "{text}");
    assert!(
        !text.contains("researcher turn embedded by alpha"),
        "{text}"
    );
    assert!(!text.contains("root turn"), "another agent's rows: {text}");

    // The events name the agent whose text it was and the provider that served it.
    assert_eq!(
        rig.llm_events(),
        vec![
            ("llm.request".into(), "root".into(), "alpha".into()),
            ("llm.response".into(), "root".into(), "alpha".into()),
            ("llm.request".into(), "researcher".into(), "beta".into()),
            ("llm.response".into(), "researcher".into(), "beta".into()),
        ]
    );

    // The inspector reports each agent's own posture and its recall.
    let inspector = rig.inspector();
    let root_view = inspector.snapshot("root").expect("root is known");
    assert!(root_view.embedding.active);
    assert_eq!(root_view.embedding.model.as_deref(), Some("alpha-embed"));
    let latest = root_view.latest.expect("root assembled");
    assert!(latest.recall.attempted);
    assert_eq!(latest.recall.turns, 1);
    let researcher_view = inspector.snapshot("agent:researcher").expect("known");
    assert_eq!(
        researcher_view.embedding.model.as_deref(),
        Some("beta-embed")
    );
    assert_eq!(researcher_view.latest.expect("assembled").recall.turns, 1);
}

/// An agent whose chat provider serves no embeddings: its prompt is sent NOWHERE —
/// not to the two other entries that could embed it — the turn still assembles,
/// and the runtime section says recall is off.
#[tokio::test]
async fn an_agent_on_a_chat_only_provider_sends_its_prompt_nowhere() {
    let rig = Rig::new();
    rig.seed_turn(
        "writer",
        1,
        "writer turn from an earlier provider",
        [1.0, 0.0],
        Some("alpha-embed"),
    );
    let writer = rig.assembler("writer");

    let assembled = writer
        .assemble(turn("writer", "a private draft"))
        .await
        .expect("the turn assembles without an embedding");
    assert_eq!(rig.upstream.sent(), Vec::<Sent>::new(), "nothing may leave");
    assert!(
        rig.llm_events().is_empty(),
        "no llm.* event without a request"
    );
    let text = prompt_text(&assembled.messages);
    assert!(text.contains("a private draft"), "the prompt still arrives");
    assert!(!text.contains("# Recalled Context"), "{text}");
    assert!(
        text.contains("- recall: disabled (no embedding model is available to this agent)"),
        "{text}"
    );

    let view = rig.inspector().snapshot("writer").expect("writer is known");
    assert!(!view.embedding.active);
    assert_eq!(view.embedding.model, None);
    assert!(!view.latest.expect("assembled").recall.attempted);
}

/// The route is resolved per call from the live policy: re-pinning the agent
/// applies to its NEXT turn on the same assembler and the same gateway, and the
/// rows it can recall are those of the model it embeds with now.
#[tokio::test]
async fn re_pinning_an_agent_moves_its_embedding_on_the_next_turn() {
    let rig = Rig::new();
    rig.seed_turn(
        "writer",
        1,
        "writer turn embedded by alpha",
        NEAR_BOTH,
        Some("alpha-embed"),
    );
    rig.seed_turn(
        "writer",
        2,
        "writer turn embedded by beta",
        NEAR_BOTH,
        Some("beta-embed"),
    );
    // A row written before vectors carried a model. Its vector is as close to the
    // query as the others and has the same dimension, yet no query of a known
    // model may be compared with it: nothing says which model it came from. (The
    // turn end embeds such a row again — `Components::heal_vectors`.)
    rig.seed_turn("writer", 3, "writer turn of unknown model", NEAR_BOTH, None);
    let writer = rig.assembler("writer");
    let inspector = rig.inspector();

    writer
        .assemble(turn("writer", "first"))
        .await
        .expect("assembles");
    assert!(rig.upstream.take().is_empty(), "gamma serves no embeddings");
    assert_eq!(live_embedding_model(&rig.gateway, "writer"), None);

    rig.policies.pin("writer", "alpha");
    let assembled = writer
        .assemble(turn("writer", "second"))
        .await
        .expect("assembles");
    assert_eq!(
        rig.upstream.take(),
        vec![sent("writer", ALPHA, "alpha-embed", "second")]
    );
    let text = prompt_text(&assembled.messages);
    assert!(text.contains("writer turn embedded by alpha"), "{text}");
    assert!(!text.contains("writer turn embedded by beta"), "{text}");
    assert!(
        !text.contains("writer turn of unknown model"),
        "a vector of no recorded model is compared with no query: {text}"
    );
    assert!(text.contains("- recall: semantic"), "{text}");
    assert_eq!(
        inspector
            .snapshot("writer")
            .unwrap()
            .embedding
            .model
            .as_deref(),
        Some("alpha-embed")
    );

    rig.policies.pin("writer", "beta");
    let assembled = writer
        .assemble(turn("writer", "third"))
        .await
        .expect("assembles");
    assert_eq!(
        rig.upstream.take(),
        vec![sent("writer", BETA, "beta-embed", "third")]
    );
    let text = prompt_text(&assembled.messages);
    assert!(text.contains("writer turn embedded by beta"), "{text}");
    assert!(!text.contains("writer turn embedded by alpha"), "{text}");
    assert!(!text.contains("writer turn of unknown model"), "{text}");
    assert_eq!(
        inspector
            .snapshot("writer")
            .unwrap()
            .embedding
            .model
            .as_deref(),
        Some("beta-embed")
    );

    // Back on the chat-only provider: no request, no recall — on the same assembler.
    rig.policies.pin("writer", "gamma");
    let assembled = writer
        .assemble(turn("writer", "fourth"))
        .await
        .expect("assembles");
    assert!(rig.upstream.take().is_empty());
    let text = prompt_text(&assembled.messages);
    assert!(!text.contains("# Recalled Context"), "{text}");
    assert!(text.contains("- recall: disabled"), "{text}");
    assert!(!inspector.snapshot("writer").unwrap().embedding.active);
}

/// The route is resolved per call, so it can move WHILE a turn is being
/// assembled. The query vector is still compared only with rows of the model that
/// produced it — never with rows of the model the route names a moment later.
#[tokio::test]
async fn a_route_change_during_a_turn_does_not_mix_models() {
    let rig = Rig::new();
    rig.seed_turn(
        "writer",
        1,
        "writer turn embedded by alpha",
        NEAR_BOTH,
        Some("alpha-embed"),
    );
    rig.seed_turn(
        "writer",
        2,
        "writer turn embedded by beta",
        NEAR_BOTH,
        Some("beta-embed"),
    );
    rig.policies.pin("writer", "alpha");
    let writer = rig.assembler("writer");

    // The agent is re-pinned while alpha is serving this turn's embedding request.
    let policies = Arc::clone(&rig.policies);
    rig.upstream
        .during_next_request(move || policies.pin("writer", "beta"));
    let assembled = writer
        .assemble(turn("writer", "mid-turn"))
        .await
        .expect("assembles");

    assert_eq!(
        rig.upstream.take(),
        vec![sent("writer", ALPHA, "alpha-embed", "mid-turn")]
    );
    assert_eq!(
        live_embedding_model(&rig.gateway, "writer").as_deref(),
        Some("beta-embed"),
        "the route has moved on"
    );
    let text = prompt_text(&assembled.messages);
    assert!(
        text.contains("writer turn embedded by alpha"),
        "the query came from alpha-embed: {text}"
    );
    assert!(
        !text.contains("writer turn embedded by beta"),
        "an alpha-embed query is never compared with beta-embed rows: {text}"
    );

    // The next turn embeds on beta and reads beta's rows.
    let assembled = writer
        .assemble(turn("writer", "next turn"))
        .await
        .expect("assembles");
    assert_eq!(
        rig.upstream.take(),
        vec![sent("writer", BETA, "beta-embed", "next turn")]
    );
    let text = prompt_text(&assembled.messages);
    assert!(text.contains("writer turn embedded by beta"), "{text}");
    assert!(!text.contains("writer turn embedded by alpha"), "{text}");
}

// ── the write side: the post-processor's embedder ──

/// The turn-end embedder of each agent follows that agent's chat provider too,
/// names the model of every vector, and makes no request for an agent that has
/// no route.
#[tokio::test]
async fn the_turn_end_embedder_follows_the_agents_chat_provider() {
    let rig = Rig::new();

    let researcher = GatewayMemoryEmbedder::new(Arc::clone(&rig.gateway), "researcher");
    assert_eq!(researcher.current_model().as_deref(), Some("beta-embed"));
    let (vector, model) = researcher
        .embed_recorded("the researcher's turn digest")
        .await
        .expect("embeds");
    assert_eq!(vector, vec![0.0, 1.0]);
    assert_eq!(model.as_deref(), Some("beta-embed"));
    assert_eq!(
        rig.upstream.take(),
        vec![sent(
            "researcher",
            BETA,
            "beta-embed",
            "the researcher's turn digest"
        )]
    );

    let writer = GatewayMemoryEmbedder::new(Arc::clone(&rig.gateway), "writer");
    assert_eq!(writer.current_model(), None);
    let (vector, model) = writer
        .embed_recorded("the writer's turn digest")
        .await
        .expect("no route is not an error");
    assert!(vector.is_empty());
    assert_eq!(model, None);
    assert!(
        rig.upstream.take().is_empty(),
        "the writer's turn text must not reach alpha or beta"
    );

    // The same embedder follows a re-pin without being rebuilt.
    rig.policies.pin("writer", "alpha");
    assert_eq!(writer.current_model().as_deref(), Some("alpha-embed"));
    let (vector, model) = writer.embed_recorded("later digest").await.expect("embeds");
    assert_eq!(vector, vec![1.0, 0.0]);
    assert_eq!(model.as_deref(), Some("alpha-embed"));
    assert_eq!(
        rig.upstream.take(),
        vec![sent("writer", ALPHA, "alpha-embed", "later digest")]
    );
}

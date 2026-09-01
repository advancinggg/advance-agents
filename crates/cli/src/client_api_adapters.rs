//! Production adapters from host observation/grant surfaces to CONTRACT-190.

use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::SystemTime;

use advance_client_api::{
    BoundGrantApprovalPort, BoundHistoryPage, BoundHistoryReadPort, ClientAgentTreeNode, ClientApi,
    ClientCursorCodec, ClientEventProvider, ClientMcpEntry, ClientMessageAck, ClientMessageStatus,
    ClientRunMutation, ClientRunSummary, ClientSkillEntry, ClientToolEntry, ClientToolInventory,
    LlmDeltaHub, MessagingProvider, NormalizedEventFilter, ProviderError, RawEventRow,
    RunControlProvider, ToolsProvider,
};
use advance_event_bus::{EventFilter, ObservabilityReadApi, ReadApiError, ReadCursor, ReadEvent};
use advance_messaging::{MailboxStore, Message, MessageKind, MsgError};
use advance_run_manager::{RunId, RunManager};
use advance_shared_types::agent_tree::{AgentKind, AgentStatus};
use advance_shared_types::run::{RunError, TaskRunStatus};
use advance_shared_types::security_validator::LeakDetector;
use advance_shared_types::sensitive_observation::{
    CanonicalCapParam, ObservationNode, SensitiveObservationRedactor,
};
use advance_shared_types::traits::{AgentTreeSnapshot, CallableInventoryReader};

pub use crate::execution_turn_ingress::ExecutionTurnIngress;
use crate::observation_carriers::ObservationCarrierStore;
use crate::observation_projection::Contract219EventProjector;
use crate::reply::ReplyRegistry;

const HISTORY_LIMIT: usize = 100;
const REDACTED: &str = "[REDACTED]";

enum EventReadRequest {
    Latest {
        reply: mpsc::Sender<Result<Option<String>, ProviderError>>,
    },
    Query {
        filter: EventFilter,
        limit: usize,
        reply: mpsc::Sender<Result<Vec<RawEventRow>, ProviderError>>,
    },
    Drain {
        after: Option<String>,
        limit: usize,
        idle: std::time::Duration,
        reply: mpsc::Sender<Result<Vec<RawEventRow>, ProviderError>>,
    },
}

/// Production sync facade over the same C219-projected EventBus read handle.
/// This powers the public WebSocket dashboard; it never receives the raw
/// execution event because EventBus stores/broadcasts only the projected copy.
pub struct Contract185EventAdapter {
    requests: mpsc::Sender<EventReadRequest>,
    retention_days: u32,
}

impl Contract185EventAdapter {
    pub fn new(read: Arc<dyn ObservabilityReadApi>, retention_days: u32) -> Result<Self, String> {
        let (requests, receiver) = mpsc::channel::<EventReadRequest>();
        std::thread::Builder::new()
            .name("advance-client-events".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(_) => return,
                };
                while let Ok(request) = receiver.recv() {
                    match request {
                        EventReadRequest::Latest { reply } => {
                            let result = runtime
                                .block_on(read.query(&EventFilter::default(), 1))
                                .map(|rows| rows.into_iter().next().map(|row| row.cursor.0))
                                .map_err(map_read_error);
                            let _ = reply.send(result);
                        }
                        EventReadRequest::Query {
                            filter,
                            limit,
                            reply,
                        } => {
                            let result = runtime
                                .block_on(read.query(&filter, limit))
                                .map(|rows| rows.into_iter().map(raw_event_row).collect())
                                .map_err(map_read_error);
                            let _ = reply.send(result);
                        }
                        EventReadRequest::Drain {
                            after,
                            limit,
                            idle,
                            reply,
                        } => {
                            let result = runtime.block_on(async {
                                let mut stream = read
                                    .resume(after.map(ReadCursor), EventFilter::default())
                                    .await
                                    .map_err(map_read_error)?;
                                let mut rows = Vec::new();
                                while rows.len() < limit {
                                    match tokio::time::timeout(idle, stream.recv()).await {
                                        Ok(Ok(Some(row))) => rows.push(raw_event_row(row)),
                                        Ok(Ok(None)) | Err(_) => break,
                                        Ok(Err(error)) => return Err(map_read_error(error)),
                                    }
                                }
                                Ok(rows)
                            });
                            let _ = reply.send(result);
                        }
                    }
                }
            })
            .map_err(|error| format!("spawn client event bridge: {error}"))?;
        Ok(Self {
            requests,
            retention_days,
        })
    }
}

impl ClientEventProvider for Contract185EventAdapter {
    fn retention_days(&self) -> u32 {
        self.retention_days
    }

    fn latest_raw_event_id(&self) -> Result<Option<String>, ProviderError> {
        let (reply, response) = mpsc::channel();
        self.requests
            .send(EventReadRequest::Latest { reply })
            .map_err(|_| ProviderError::Unavailable("event worker stopped".to_owned()))?;
        response
            .recv()
            .map_err(|_| ProviderError::Unavailable("event worker stopped".to_owned()))?
    }

    fn query_history(
        &self,
        filter: &NormalizedEventFilter,
        limit: usize,
    ) -> Result<Vec<RawEventRow>, ProviderError> {
        let (reply, response) = mpsc::channel();
        self.requests
            .send(EventReadRequest::Query {
                filter: normalized_filter(filter),
                limit,
                reply,
            })
            .map_err(|_| ProviderError::Unavailable("event worker stopped".to_owned()))?;
        response
            .recv()
            .map_err(|_| ProviderError::Unavailable("event worker stopped".to_owned()))?
    }

    fn drain_stream(
        &self,
        after_raw_id: Option<&str>,
        scan_ceiling: usize,
        idle_ms: u64,
    ) -> Result<Vec<RawEventRow>, ProviderError> {
        let (reply, response) = mpsc::channel();
        self.requests
            .send(EventReadRequest::Drain {
                after: after_raw_id.map(str::to_owned),
                limit: scan_ceiling,
                idle: std::time::Duration::from_millis(idle_ms),
                reply,
            })
            .map_err(|_| ProviderError::Unavailable("event worker stopped".to_owned()))?;
        response
            .recv()
            .map_err(|_| ProviderError::Unavailable("event worker stopped".to_owned()))?
    }
}

fn normalized_filter(filter: &NormalizedEventFilter) -> EventFilter {
    EventFilter {
        event_type_prefix: filter.event_type.clone(),
        agent_id: filter.agent_id.clone(),
        run_id: filter.run_id.clone(),
        trace_id: filter.trace_id.clone(),
        since: filter.since.clone(),
    }
}

fn raw_event_row(read: ReadEvent) -> RawEventRow {
    RawEventRow {
        raw_id: read.cursor.0,
        event_type: read.event.event_type.clone(),
        timestamp: read.event.timestamp,
        agent_id: read.event.agent_id.clone(),
        run_id: read.event.run_id.clone(),
        trace_id: read.event.trace_id.clone(),
        payload: read.event.payload.clone(),
    }
}

fn map_read_error(error: ReadApiError) -> ProviderError {
    match error {
        ReadApiError::CursorNotFound(_) => ProviderError::NotFound("event cursor".to_owned()),
        ReadApiError::BadFilter(_) => ProviderError::InvalidState("event filter".to_owned()),
        ReadApiError::Db(_) => ProviderError::Unavailable("event database".to_owned()),
    }
}

struct HistoryQuery {
    filter: EventFilter,
    reply: mpsc::Sender<Result<Vec<ReadEvent>, ProviderError>>,
}

/// Synchronous CONTRACT-190 adapter over CONTRACT-185's async read port. A
/// dedicated runtime thread avoids nested-runtime blocking in Axum handlers.
pub struct Contract219HistoryAdapter {
    queries: mpsc::Sender<HistoryQuery>,
    projector: Arc<Contract219EventProjector>,
    carriers: Arc<ObservationCarrierStore>,
}

impl Contract219HistoryAdapter {
    pub fn new(
        read: Arc<dyn ObservabilityReadApi>,
        projector: Arc<Contract219EventProjector>,
        carriers: Arc<ObservationCarrierStore>,
    ) -> Result<Self, String> {
        let (queries, receiver) = mpsc::channel::<HistoryQuery>();
        std::thread::Builder::new()
            .name("advance-client-history".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(_) => return,
                };
                while let Ok(query) = receiver.recv() {
                    let result = runtime
                        .block_on(read.query(&query.filter, HISTORY_LIMIT))
                        .map_err(|error| ProviderError::Unavailable(error.to_string()));
                    let _ = query.reply.send(result);
                }
            })
            .map_err(|error| format!("spawn client history bridge: {error}"))?;
        Ok(Self {
            queries,
            projector,
            carriers,
        })
    }

    fn history(
        &self,
        task_id: Option<&str>,
        run_id: Option<&str>,
        cursor: Option<&str>,
    ) -> Result<BoundHistoryPage, ProviderError> {
        let (reply, response) = mpsc::channel();
        self.queries
            .send(HistoryQuery {
                filter: EventFilter {
                    run_id: run_id.map(str::to_owned),
                    ..EventFilter::default()
                },
                reply,
            })
            .map_err(|_| ProviderError::Unavailable("history worker stopped".to_owned()))?;
        let events = response
            .recv()
            .map_err(|_| ProviderError::Unavailable("history worker stopped".to_owned()))??;
        let mut documents = Vec::new();
        let mut cursor_seen = cursor.is_none();
        for read in events {
            let event = read.event.as_ref();
            if task_id.is_some_and(|expected| event.task_id.as_deref() != Some(expected)) {
                continue;
            }
            if !cursor_seen {
                if cursor == Some(event.id.as_str()) {
                    cursor_seen = true;
                }
                continue;
            }
            let carrier = match self
                .carriers
                .get(&event.id)
                .map_err(ProviderError::Unavailable)?
            {
                Some(carrier) => carrier,
                None => continue,
            };
            let payload = history_payload(event);
            let bound = self
                .projector
                .bind_persisted_history(&carrier, ObservationNode::Object(Vec::new()), payload)
                .map_err(ProviderError::Unavailable)?;
            documents.push(bound);
        }
        if !cursor_seen {
            return Err(ProviderError::NotFound("history cursor".to_owned()));
        }
        Ok(BoundHistoryPage::from_bound_documents(documents, None))
    }
}

impl BoundHistoryReadPort for Contract219HistoryAdapter {
    fn task_history_bound(
        &self,
        task_id: &str,
        cursor: Option<&str>,
    ) -> Result<BoundHistoryPage, ProviderError> {
        self.history(Some(task_id), None, cursor)
    }

    fn run_history_bound(
        &self,
        run_id: &str,
        cursor: Option<&str>,
    ) -> Result<BoundHistoryPage, ProviderError> {
        self.history(None, Some(run_id), cursor)
    }
}

fn history_payload(event: &advance_event_bus::Event) -> ObservationNode {
    let value = |key: &str| {
        event
            .payload
            .get("result")
            .and_then(|result| result.get("named_params"))
            .and_then(|params| params.get(key))
            .and_then(serde_json::Value::as_str)
            .unwrap_or(REDACTED)
            .to_owned()
    };
    ObservationNode::Object(vec![
        (
            "event_id".to_owned(),
            ObservationNode::String(event.id.clone()),
        ),
        (
            "occurred_at".to_owned(),
            ObservationNode::String(event.timestamp.to_rfc3339()),
        ),
        (
            "kind".to_owned(),
            ObservationNode::String(event.event_type.clone()),
        ),
        (
            "summary".to_owned(),
            ObservationNode::String("observability event".to_owned()),
        ),
        (
            "params".to_owned(),
            ObservationNode::CanonicalCapParams(
                ["api_key", "event_type", "id", "run_id"]
                    .into_iter()
                    .map(|key| CanonicalCapParam {
                        key: key.to_owned(),
                        value: ObservationNode::String(value(key)),
                    })
                    .collect(),
            ),
        ),
    ])
}

pub use crate::grant_adapter::Contract219GrantAdapter;

/// Must match `commands::start::DEFAULT_MSG_AGENT_ID` (avoid a start↔adapters cycle).
const SERVE_LOOP_AGENT: &str = "agent:default";

const MAX_TRACKED_CLIENT_MESSAGES: usize = 4096;

/// Bounded send ledger so `GET /client/messages/{id}` cannot grow without
/// bound for the daemon lifetime. Oldest ids evict first.
struct TrackedSends {
    by_id: HashMap<String, String>,
    order: VecDeque<String>,
}

impl TrackedSends {
    fn new() -> Self {
        Self {
            by_id: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn insert(&mut self, message_id: String, to: String) {
        if self.by_id.contains_key(&message_id) {
            return;
        }
        while self.order.len() >= MAX_TRACKED_CLIENT_MESSAGES {
            if let Some(old) = self.order.pop_front() {
                self.by_id.remove(&old);
            }
        }
        self.order.push_back(message_id.clone());
        self.by_id.insert(message_id, to);
    }

    fn get(&self, message_id: &str) -> Option<&String> {
        self.by_id.get(message_id)
    }
}

/// CLI-served CONTRACT-190 messaging port: deliver a User message onto the
/// same mailbox the root serve loop recvs (POST `/msg` generate path).
pub struct ServeLoopMessagingProvider {
    store: Arc<MailboxStore>,
    ingress: Option<Arc<ExecutionTurnIngress>>,
    replies: Arc<ReplyRegistry>,
    counter: AtomicU64,
    sent: Mutex<TrackedSends>,
}

impl ServeLoopMessagingProvider {
    pub fn new(
        store: Arc<MailboxStore>,
        ingress: Option<Arc<ExecutionTurnIngress>>,
        replies: Arc<ReplyRegistry>,
    ) -> Self {
        Self {
            store,
            ingress,
            replies,
            counter: AtomicU64::new(0),
            sent: Mutex::new(TrackedSends::new()),
        }
    }

    #[cfg(feature = "test-support")]
    pub fn for_test(store: Arc<MailboxStore>, replies: Arc<ReplyRegistry>) -> Self {
        Self::new(store, None, replies)
    }
}

pub fn install_serve_loop_messaging(
    api: ClientApi,
    store: Arc<MailboxStore>,
    ingress: Option<Arc<ExecutionTurnIngress>>,
    replies: Arc<ReplyRegistry>,
) -> ClientApi {
    api.with_messaging_provider(Arc::new(ServeLoopMessagingProvider::new(
        store, ingress, replies,
    )))
}

impl MessagingProvider for ServeLoopMessagingProvider {
    fn send(&self, to: &str, payload: &[u8]) -> Result<ClientMessageAck, ProviderError> {
        if to != SERVE_LOOP_AGENT {
            return Err(ProviderError::NotFound("target".to_owned()));
        }
        let message_id = format!("cmsg-{}", self.counter.fetch_add(1, Ordering::SeqCst));
        let msg = Message {
            id: message_id.clone(),
            kind: MessageKind::User,
            from: "user:client-api".to_string(),
            to: to.to_string(),
            payload: payload.to_vec(),
            context: None,
            timestamp: SystemTime::now(),
            origin: None,
        };
        let delivery = match self.ingress.as_deref() {
            Some(ingress) => ingress.publish(msg),
            None => self
                .store
                .get_or_create(to)
                .and_then(|mailbox| mailbox.deliver(msg)),
        };
        delivery.map_err(|e| match e {
            MsgError::MailboxFull => ProviderError::Unavailable("mailbox_full".to_owned()),
            MsgError::InvalidPayload(_) => ProviderError::TooLarge("payload".to_owned()),
            _ => ProviderError::Unavailable("deliver".to_owned()),
        })?;
        self.replies.clear_last_outbound(to);
        self.replies.note_pending_message(to, &message_id);
        self.sent
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(message_id.clone(), to.to_string());
        Ok(ClientMessageAck {
            message_id,
            to: to.to_string(),
            delivery_state: "delivered".to_string(),
        })
    }

    fn message_status(&self, message_id: &str) -> Result<ClientMessageStatus, ProviderError> {
        let to = self
            .sent
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(message_id)
            .cloned()
            .ok_or_else(|| ProviderError::NotFound("message".to_owned()))?;
        let reply_state = match self.replies.last_outbound(&to) {
            Some(true) => "replied",
            _ => "none",
        };
        Ok(ClientMessageStatus {
            message_id: message_id.to_string(),
            stream_key: self.replies.stream_key_for_message(message_id),
            to,
            from: "user:client-api".to_string(),
            delivery_state: "delivered".to_string(),
            reply_state: reply_state.to_string(),
        })
    }
}

/// Optional slots for the shared first-party Client API compose (CLI + SUT).
#[derive(Default)]
pub struct FirstPartyClientCompose {
    pub run: Option<Arc<dyn RunControlProvider>>,
    pub mailbox: Option<Arc<MailboxStore>>,
    pub(crate) ingress: Option<Arc<ExecutionTurnIngress>>,
    pub replies: Option<Arc<ReplyRegistry>>,
    pub history: Option<Arc<dyn BoundHistoryReadPort>>,
    pub events: Option<Arc<dyn ClientEventProvider>>,
    pub cursor: Option<Arc<dyn ClientCursorCodec>>,
    pub redactor: Option<Arc<SensitiveObservationRedactor>>,
    pub leak_detector: Option<Arc<dyn LeakDetector>>,
    pub grants: Option<Arc<dyn BoundGrantApprovalPort>>,
    pub tools: Option<Arc<dyn ToolsProvider>>,
    pub llm_delta_hub: Option<Arc<LlmDeltaHub>>,
}

pub fn compose_first_party_client(mut api: ClientApi, parts: FirstPartyClientCompose) -> ClientApi {
    if let Some(run) = parts.run {
        api = api.with_run_provider(run);
    }
    if let (Some(store), Some(replies)) = (parts.mailbox, parts.replies) {
        api = install_serve_loop_messaging(api, store, parts.ingress, replies);
    }
    if let Some(history) = parts.history {
        api = api.with_bound_history_provider(history);
    }
    if let Some(events) = parts.events {
        api = api.with_event_provider(events);
    }
    if let Some(cursor) = parts.cursor {
        api = api.with_cursor_codec(cursor);
    }
    if let Some(redactor) = parts.redactor {
        api = api.with_observation_redactor(redactor);
    }
    if let Some(detector) = parts.leak_detector {
        api = api.with_leak_detector(detector);
    }
    if let Some(grants) = parts.grants {
        api = api.with_bound_grant_provider(grants);
    }
    if let Some(tools) = parts.tools {
        api = api.with_tools_provider(tools);
    }
    if let Some(hub) = parts.llm_delta_hub {
        api = api.with_llm_delta_hub(hub);
    }
    api
}

/// Install a tools provider only when a real inventory Arc is present.
/// `skill_root` is the cap-skills provider root (`<workspace>/.agent`); the
/// bounded walk appends `.agent/skills`, matching `DiskSkillSummaryReader`.
pub fn install_tools_if_real(
    api: &ClientApi,
    inventory: Option<Arc<dyn CallableInventoryReader>>,
    skill_root: Option<PathBuf>,
) {
    let Some(inventory) = inventory else {
        return;
    };
    api.install_tools_provider(Arc::new(InventoryToolsProvider::new(
        inventory,
        SERVE_LOOP_AGENT,
        skill_root,
    )));
}

const MAX_VISIBLE_SKILLS: usize = 256;
const MAX_SKILL_READ_BYTES: u64 = 96 * 1024;

fn read_regular_capped(path: &Path, max_bytes: u64) -> Option<String> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() || meta.len() > max_bytes {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    let mut buf = String::new();
    file.take(max_bytes).read_to_string(&mut buf).ok()?;
    Some(buf)
}

fn client_provenance(raw: Option<&str>) -> String {
    match raw.unwrap_or("imported") {
        "AgentCreated" | "agent_created" => "agent_created".to_owned(),
        _ => "imported".to_owned(),
    }
}

fn client_trust(raw: Option<&str>) -> String {
    match raw.unwrap_or("untrusted") {
        "Trusted" | "trusted" => "trusted".to_owned(),
        _ => "untrusted".to_owned(),
    }
}

/// Flat `key: scalar` meta only. Rejects YAML anchors/aliases (`&` / `*`)
/// and flow/nested documents so a planted `.meta.yaml` cannot expand in-process.
fn parse_skill_meta(raw: &str) -> Option<(String, u32, String, String)> {
    if raw.contains('&') || raw.contains('*') {
        return None;
    }
    let mut skill_id = None;
    let mut version = 0u32;
    let mut provenance = None;
    let mut trust_level = None;
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            return None;
        };
        let key = key.trim();
        let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
        if key.is_empty()
            || value.starts_with('{')
            || value.starts_with('[')
            || value.starts_with('|')
            || value.starts_with('>')
        {
            return None;
        }
        match key {
            "skill_id" => skill_id = Some(value.to_owned()),
            "version" => version = value.parse().unwrap_or(0),
            "provenance" => provenance = Some(value.to_owned()),
            "trust_level" => trust_level = Some(value.to_owned()),
            _ => {}
        }
    }
    Some((
        skill_id?,
        version,
        client_provenance(provenance.as_deref()),
        client_trust(trust_level.as_deref()),
    ))
}

fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|meta| meta.file_type().is_dir())
        .unwrap_or(false)
}

/// Bounded skill-dir walk. Same layout and caps as `DiskSkillSummaryReader`
/// — not `SkillStorage::list_active()`. The `.agent` and `.agent/skills`
/// roots must be real directories (symlink roots are skipped). Leaf files
/// use stat-before-open; `DirEntry::file_type` skips symlink children.
fn list_client_skills(skill_root: &Path) -> Vec<ClientSkillEntry> {
    let agent_dir = skill_root.join(".agent");
    if !is_real_dir(&agent_dir) {
        return Vec::new();
    }
    let skills_root = agent_dir.join("skills");
    if !is_real_dir(&skills_root) {
        return Vec::new();
    }
    let entries = match std::fs::read_dir(&skills_root) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for (visited, entry) in entries.enumerate() {
        if visited >= MAX_VISIBLE_SKILLS {
            break;
        }
        let Ok(entry) = entry else {
            continue;
        };
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let Some(skill_id) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let dir = entry.path();
        let Some(_content) = read_regular_capped(&dir.join("SKILL.md"), MAX_SKILL_READ_BYTES)
        else {
            continue;
        };
        let Some(meta_raw) = read_regular_capped(&dir.join(".meta.yaml"), MAX_SKILL_READ_BYTES)
        else {
            continue;
        };
        let Some((meta_id, version, provenance, trust_level)) = parse_skill_meta(&meta_raw) else {
            continue;
        };
        if meta_id != skill_id {
            continue;
        }
        out.push(ClientSkillEntry {
            skill_id,
            version,
            provenance,
            trust_level,
        });
    }
    out
}

pub struct InventoryToolsProvider {
    inventory: Arc<dyn CallableInventoryReader>,
    mapped_agent: String,
    skill_root: Option<PathBuf>,
}

impl InventoryToolsProvider {
    pub fn new(
        inventory: Arc<dyn CallableInventoryReader>,
        mapped_agent: impl Into<String>,
        skill_root: Option<PathBuf>,
    ) -> Self {
        Self {
            inventory,
            mapped_agent: mapped_agent.into(),
            skill_root,
        }
    }
}

impl ToolsProvider for InventoryToolsProvider {
    fn inventory(&self, _principal_id: &str) -> Result<ClientToolInventory, ProviderError> {
        let agent = &self.mapped_agent;
        let wasm = self
            .inventory
            .list_wasm_tools(agent)
            .into_iter()
            .map(|t| ClientToolEntry {
                name: t.name,
                description: t.description,
            })
            .collect();
        let mcp = self
            .inventory
            .list_mcp_tools(agent)
            .into_iter()
            .map(|t| ClientMcpEntry {
                name: t.name,
                description: t.description,
                server_id: t.server_id,
            })
            .collect();
        let skills = self
            .skill_root
            .as_deref()
            .map(list_client_skills)
            .unwrap_or_default();
        Ok(ClientToolInventory { wasm, mcp, skills })
    }
}

enum RunControlJob {
    Pause {
        id: RunId,
        reply: mpsc::Sender<Result<(), RunError>>,
    },
    Cancel {
        id: RunId,
        reply: mpsc::Sender<Result<(), RunError>>,
    },
}

pub struct RunManagerRunControl {
    mgr: Arc<RunManager>,
    tree: Option<Arc<dyn AgentTreeSnapshot>>,
    jobs: mpsc::Sender<RunControlJob>,
}

impl RunManagerRunControl {
    pub fn new(mgr: Arc<RunManager>, tree: Option<Arc<dyn AgentTreeSnapshot>>) -> Self {
        let (jobs, receiver) = mpsc::channel();
        let worker = Arc::clone(&mgr);
        let _ = std::thread::Builder::new()
            .name("advance-client-run-control".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(_) => return,
                };
                while let Ok(job) = receiver.recv() {
                    match job {
                        RunControlJob::Pause { id, reply } => {
                            let _ = reply
                                .send(runtime.block_on(worker.pause_run(&id, "manual".to_owned())));
                        }
                        RunControlJob::Cancel { id, reply } => {
                            let _ = reply.send(
                                runtime.block_on(worker.cancel_run(&id, "manual".to_owned())),
                            );
                        }
                    }
                }
            });
        Self { mgr, tree, jobs }
    }

    fn submit_job(
        &self,
        job: impl FnOnce(mpsc::Sender<Result<(), RunError>>) -> RunControlJob,
    ) -> Result<(), ProviderError> {
        let (reply, response) = mpsc::channel();
        self.jobs
            .send(job(reply))
            .map_err(|_| ProviderError::Unavailable("run".to_owned()))?;
        response
            .recv()
            .map_err(|_| ProviderError::Unavailable("run".to_owned()))?
            .map_err(Self::map_err)
    }

    fn parse_id(run_id: &str) -> Result<RunId, ProviderError> {
        RunId::from_string(run_id.to_string())
            .map_err(|_| ProviderError::NotFound("run".to_owned()))
    }

    fn status_of(&self, run_id: &str) -> Result<String, ProviderError> {
        self.mgr
            .list_runs()
            .into_iter()
            .find(|r| r.id.as_ref() == run_id)
            .map(|r| run_status_name(&r.status).to_owned())
            .ok_or_else(|| ProviderError::NotFound("run".to_owned()))
    }

    fn map_err(error: RunError) -> ProviderError {
        match error {
            RunError::NotFound(_) => ProviderError::NotFound("run".to_owned()),
            RunError::InvalidState(_) => ProviderError::InvalidState("run".to_owned()),
            RunError::PermissionDenied(_) => ProviderError::Forbidden("run".to_owned()),
            RunError::AlreadyExists(_) | RunError::BudgetExceeded(_) => {
                ProviderError::Unavailable("run".to_owned())
            }
        }
    }
}

impl RunControlProvider for RunManagerRunControl {
    fn list_runs(&self) -> Result<Vec<ClientRunSummary>, ProviderError> {
        Ok(self
            .mgr
            .list_runs()
            .into_iter()
            .map(|run| ClientRunSummary {
                run_id: run.id.to_string(),
                task_id: run.task_id,
                controller_agent: run.controller_agent,
                status: run_status_name(&run.status).to_owned(),
                iteration: run.iteration,
                token_used: run.budget.token_used,
                token_limit: run.budget.token_limit,
                cost_usd: run.budget.cost_usd,
                cost_usd_limit: run.budget.cost_limit,
                created_at: run.created_at.to_rfc3339(),
                updated_at: run.updated_at.to_rfc3339(),
            })
            .collect())
    }

    fn agent_tree(&self) -> Result<Vec<ClientAgentTreeNode>, ProviderError> {
        let Some(tree) = &self.tree else {
            return Ok(Vec::new());
        };
        Ok(tree
            .snapshot()
            .nodes
            .into_iter()
            .map(|node| ClientAgentTreeNode {
                id: node.id.0,
                kind: agent_kind_name(&node.kind).to_owned(),
                parent: node.parent.map(|p| p.0),
                status: agent_status_name(&node.status).to_owned(),
                template_ref: node.template_ref,
            })
            .collect())
    }

    fn pause(
        &self,
        run_id: &str,
        _reason: Option<&str>,
    ) -> Result<ClientRunMutation, ProviderError> {
        let id = Self::parse_id(run_id)?;
        self.submit_job(|reply| RunControlJob::Pause { id, reply })?;
        Ok(ClientRunMutation {
            run_id: run_id.to_owned(),
            status: self.status_of(run_id)?,
            emitted_event_ids: Vec::new(),
        })
    }

    fn resume(
        &self,
        run_id: &str,
        reason: Option<&str>,
    ) -> Result<ClientRunMutation, ProviderError> {
        let id = Self::parse_id(run_id)?;
        let reason = reason.unwrap_or("manual").to_owned();
        self.mgr.resume_run(&id, reason).map_err(Self::map_err)?;
        Ok(ClientRunMutation {
            run_id: run_id.to_owned(),
            status: self.status_of(run_id)?,
            emitted_event_ids: Vec::new(),
        })
    }

    fn cancel(
        &self,
        run_id: &str,
        _reason: Option<&str>,
    ) -> Result<ClientRunMutation, ProviderError> {
        let id = Self::parse_id(run_id)?;
        self.submit_job(|reply| RunControlJob::Cancel { id, reply })?;
        Ok(ClientRunMutation {
            run_id: run_id.to_owned(),
            status: self.status_of(run_id)?,
            emitted_event_ids: Vec::new(),
        })
    }
}

fn run_status_name(status: &TaskRunStatus) -> &'static str {
    match status {
        TaskRunStatus::Active => "active",
        TaskRunStatus::Suspended => "suspended",
        TaskRunStatus::Paused => "paused",
        TaskRunStatus::Completed => "completed",
        TaskRunStatus::Failed(_) => "failed",
        TaskRunStatus::Cancelled(_) => "cancelled",
    }
}

fn agent_kind_name(kind: &AgentKind) -> &'static str {
    match kind {
        AgentKind::Root => "root",
        AgentKind::Child => "child",
        AgentKind::Sub => "sub",
    }
}

fn agent_status_name(status: &AgentStatus) -> &'static str {
    match status {
        AgentStatus::Active => "active",
        AgentStatus::Paused => "paused",
        AgentStatus::Terminated => "terminated",
        AgentStatus::Failed => "failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_skill_meta_rejects_yaml_aliases() {
        assert!(parse_skill_meta("a: &a [*a]\nskill_id: bomb\nversion: 1\n").is_none());
        assert!(parse_skill_meta(
            "skill_id: echo-skill\nversion: 3\nprovenance: Imported\ntrust_level: Trusted\n"
        )
        .is_some());
    }

    #[test]
    fn tracked_sends_evicts_oldest() {
        let mut sent = TrackedSends::new();
        for i in 0..=MAX_TRACKED_CLIENT_MESSAGES {
            sent.insert(format!("cmsg-{i}"), "agent:default".to_owned());
        }
        assert!(sent.get("cmsg-0").is_none());
        assert!(sent
            .get(&format!("cmsg-{MAX_TRACKED_CLIENT_MESSAGES}"))
            .is_some());
        assert_eq!(sent.by_id.len(), MAX_TRACKED_CLIENT_MESSAGES);
    }
}

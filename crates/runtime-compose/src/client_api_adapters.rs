//! Production adapters from host observation/grant surfaces to CONTRACT-190.

use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::SystemTime;

use advance_client_api::{
    AgentAdminProvider, BoundGrantApprovalPort, BoundHistoryPage, BoundHistoryReadPort,
    ClientAgentTreeNode, ClientApi, ClientCursorCodec, ClientEventProvider, ClientMcpEntry,
    ClientMessageAck, ClientMessageStatus, ClientRunMutation, ClientRunSummary, ClientSkillEntry,
    ClientToolEntry, ClientToolInventory, CostProvider, EntityProvider, LlmDeltaHub,
    MessagingProvider, NormalizedEventFilter, PackAdminProvider, ProviderAdminProvider,
    ProviderError, RawEventRow, RunControlProvider, SecretsAdminProvider, ToolsProvider,
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

/// One adapter's worker thread and its job queue. The adapter submits through it; an
/// owner shutting the composition down closes the queue (the thread then finishes the job
/// in hand and exits) and joins the thread once it has finished, never blocking on it.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "name and thread are read by the composition's ordered teardown"
    )
)]
pub(crate) struct AdapterWorker<J> {
    name: &'static str,
    jobs: Mutex<Option<mpsc::Sender<J>>>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl<J: Send + 'static> AdapterWorker<J> {
    /// Start the thread `name` running `body` over the job queue.
    fn spawn(
        name: &'static str,
        body: impl FnOnce(mpsc::Receiver<J>) + Send + 'static,
    ) -> std::io::Result<Arc<Self>> {
        let (jobs, receiver) = mpsc::channel::<J>();
        let thread = std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || body(receiver))?;
        Ok(Arc::new(Self {
            name,
            jobs: Mutex::new(Some(jobs)),
            thread: Mutex::new(Some(thread)),
        }))
    }

    /// As [`Self::spawn`]; when no thread can be started, a worker that refuses every job
    /// (each submit takes the adapter's existing send-failure answer).
    fn spawn_or_closed(
        name: &'static str,
        body: impl FnOnce(mpsc::Receiver<J>) + Send + 'static,
    ) -> Arc<Self> {
        Self::spawn(name, body).unwrap_or_else(|_| {
            Arc::new(Self {
                name,
                jobs: Mutex::new(None),
                thread: Mutex::new(None),
            })
        })
    }

    /// Queue `job`; `Err(job)` once the queue is closed or the thread is gone.
    fn submit(&self, job: J) -> Result<(), J> {
        let sender = self.jobs.lock().unwrap_or_else(|e| e.into_inner()).clone();
        match sender {
            Some(sender) => sender.send(job).map_err(|mpsc::SendError(job)| job),
            None => Err(job),
        }
    }
}

/// Shutdown control over an [`AdapterWorker`], independent of its job type.
pub(crate) trait WorkerControl: Send + Sync {
    /// The thread name.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "read by the composition's ordered teardown")
    )]
    fn name(&self) -> &'static str;
    /// Close the job queue: the thread finishes the job in hand and exits.
    fn close(&self);
    /// Join the thread iff it has finished (never blocks); `true` when it is joined now
    /// or was never started / already joined.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "read by the composition's ordered teardown")
    )]
    fn try_join(&self) -> bool;
}

impl<J: Send + 'static> WorkerControl for AdapterWorker<J> {
    fn name(&self) -> &'static str {
        self.name
    }

    fn close(&self) {
        drop(self.jobs.lock().unwrap_or_else(|e| e.into_inner()).take());
    }

    fn try_join(&self) -> bool {
        let mut thread = self.thread.lock().unwrap_or_else(|e| e.into_inner());
        match thread.as_ref() {
            None => true,
            Some(handle) if handle.is_finished() => {
                if let Some(handle) = thread.take() {
                    let _ = handle.join();
                }
                true
            }
            Some(_) => false,
        }
    }
}

/// Registers `worker` with an owner's tracked list.
fn track<J: Send + 'static>(
    worker: &Arc<AdapterWorker<J>>,
    workers: &mut Vec<Arc<dyn WorkerControl>>,
) {
    workers.push(Arc::clone(worker) as Arc<dyn WorkerControl>);
}

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
    worker: Arc<AdapterWorker<EventReadRequest>>,
    retention_days: u32,
}

impl Contract185EventAdapter {
    pub fn new(read: Arc<dyn ObservabilityReadApi>, retention_days: u32) -> Result<Self, String> {
        Self::new_tracked(read, retention_days, &mut Vec::new())
    }

    /// As [`Self::new`], also registering the worker thread with `workers`.
    pub(crate) fn new_tracked(
        read: Arc<dyn ObservabilityReadApi>,
        retention_days: u32,
        workers: &mut Vec<Arc<dyn WorkerControl>>,
    ) -> Result<Self, String> {
        let worker = AdapterWorker::spawn(
            "advance-client-events",
            move |receiver: mpsc::Receiver<EventReadRequest>| {
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
            },
        )
        .map_err(|error| format!("spawn client event bridge: {error}"))?;
        track(&worker, workers);
        Ok(Self {
            worker,
            retention_days,
        })
    }
}

impl Drop for Contract185EventAdapter {
    /// Only closes the queue (the thread then exits on its own): a last-`Arc` drop on a
    /// runtime worker never blocks on a join.
    fn drop(&mut self) {
        self.worker.close();
    }
}

impl ClientEventProvider for Contract185EventAdapter {
    fn retention_days(&self) -> u32 {
        self.retention_days
    }

    fn latest_raw_event_id(&self) -> Result<Option<String>, ProviderError> {
        let (reply, response) = mpsc::channel();
        self.worker
            .submit(EventReadRequest::Latest { reply })
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
        self.worker
            .submit(EventReadRequest::Query {
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
        self.worker
            .submit(EventReadRequest::Drain {
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
    worker: Arc<AdapterWorker<HistoryQuery>>,
    projector: Arc<Contract219EventProjector>,
    carriers: Arc<ObservationCarrierStore>,
}

impl Contract219HistoryAdapter {
    pub fn new(
        read: Arc<dyn ObservabilityReadApi>,
        projector: Arc<Contract219EventProjector>,
        carriers: Arc<ObservationCarrierStore>,
    ) -> Result<Self, String> {
        Self::new_tracked(read, projector, carriers, &mut Vec::new())
    }

    /// As [`Self::new`], also registering the worker thread with `workers`.
    pub(crate) fn new_tracked(
        read: Arc<dyn ObservabilityReadApi>,
        projector: Arc<Contract219EventProjector>,
        carriers: Arc<ObservationCarrierStore>,
        workers: &mut Vec<Arc<dyn WorkerControl>>,
    ) -> Result<Self, String> {
        let worker = AdapterWorker::spawn(
            "advance-client-history",
            move |receiver: mpsc::Receiver<HistoryQuery>| {
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
            },
        )
        .map_err(|error| format!("spawn client history bridge: {error}"))?;
        track(&worker, workers);
        Ok(Self {
            worker,
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
        self.worker
            .submit(HistoryQuery {
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

impl Drop for Contract219HistoryAdapter {
    /// Only closes the queue (the thread then exits on its own): never blocks on a join.
    fn drop(&mut self) {
        self.worker.close();
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

/// The root serve key when no identity is composed (harness / unit fixtures): the mailbox of
/// the default root handle `root`. Production composes the resolved `agent:<handle>` instead
/// (`WiringHandles::root_mailbox_id`).
const SERVE_LOOP_AGENT: &str = "agent:root";

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
    /// The served root mailbox key (`agent:<handle>`), the only accepted `to`.
    serve_agent: String,
}

impl ServeLoopMessagingProvider {
    pub fn new(
        store: Arc<MailboxStore>,
        ingress: Option<Arc<ExecutionTurnIngress>>,
        replies: Arc<ReplyRegistry>,
        serve_agent: impl Into<String>,
    ) -> Self {
        Self {
            store,
            ingress,
            replies,
            counter: AtomicU64::new(0),
            sent: Mutex::new(TrackedSends::new()),
            serve_agent: serve_agent.into(),
        }
    }

    #[cfg(feature = "test-support")]
    pub fn for_test(store: Arc<MailboxStore>, replies: Arc<ReplyRegistry>) -> Self {
        Self::new(store, None, replies, SERVE_LOOP_AGENT)
    }
}

pub fn install_serve_loop_messaging(
    api: ClientApi,
    store: Arc<MailboxStore>,
    ingress: Option<Arc<ExecutionTurnIngress>>,
    replies: Arc<ReplyRegistry>,
    serve_agent: &str,
) -> ClientApi {
    api.with_messaging_provider(Arc::new(ServeLoopMessagingProvider::new(
        store,
        ingress,
        replies,
        serve_agent,
    )))
}

impl MessagingProvider for ServeLoopMessagingProvider {
    fn send(&self, to: &str, payload: &[u8]) -> Result<ClientMessageAck, ProviderError> {
        if to != self.serve_agent {
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
    /// The root serve key (`agent:<handle>`) the messaging provider accepts as `to`; `None`
    /// (a harness composition) ⇒ the default handle's key `agent:root`.
    pub serve_agent: Option<String>,
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
    /// CONTRACT-190 agents family (agent CRUD + template listing) over the shared agent tree.
    pub agents: Option<Arc<dyn AgentAdminProvider>>,
    /// CONTRACT-190 costs family (per-agent / per-provider LLM spend) over the bus's durable
    /// cost ledger.
    pub costs: Option<Arc<dyn CostProvider>>,
    /// CONTRACT-190 packs family (installed packs / install / uninstall) over the production
    /// pack registry.
    pub packs: Option<Arc<dyn PackAdminProvider>>,
    /// CONTRACT-190 providers family (LLM provider entries + key custody) over the shared
    /// `llm-providers` writer and the daemon's live secret store.
    pub providers: Option<Arc<dyn ProviderAdminProvider>>,
    /// Secrets family: the home's secrets mode
    /// (File vs keychain-sync) over the runtime-config.yaml `secrets:` block.
    pub secrets: Option<Arc<dyn SecretsAdminProvider>>,
    /// CONTRACT-190 schema + entities families (entity-data lane E3) over the production
    /// `DataStore` (the `data` host tool's store).
    pub entities: Option<Arc<dyn EntityProvider>>,
}

pub fn compose_first_party_client(mut api: ClientApi, parts: FirstPartyClientCompose) -> ClientApi {
    if let Some(run) = parts.run {
        api = api.with_run_provider(run);
    }
    if let (Some(store), Some(replies)) = (parts.mailbox, parts.replies) {
        api = install_serve_loop_messaging(
            api,
            store,
            parts.ingress,
            replies,
            parts.serve_agent.as_deref().unwrap_or(SERVE_LOOP_AGENT),
        );
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
    if let Some(agents) = parts.agents {
        api = api.with_agent_provider(agents);
    }
    if let Some(costs) = parts.costs {
        api = api.with_cost_provider(costs);
    }
    if let Some(packs) = parts.packs {
        api = api.with_pack_provider(packs);
    }
    if let Some(providers) = parts.providers {
        api = api.with_provider_admin(providers);
    }
    if let Some(secrets) = parts.secrets {
        api = api.with_secrets_provider(secrets);
    }
    if let Some(entities) = parts.entities {
        api = api.with_entity_provider(entities);
    }
    api
}

/// Install a tools provider only when a real inventory Arc is present.
/// `skill_root` is the cap-skills provider root (`<workspace>/.agent`); the
/// bounded walk appends `.agent/skills`, matching `DiskSkillSummaryReader`.
pub fn install_tools_if_real(
    api: &ClientApi,
    inventory: Option<Arc<dyn CallableInventoryReader>>,
    mapped_agent: &str,
    skill_root: Option<PathBuf>,
) {
    let Some(inventory) = inventory else {
        return;
    };
    api.install_tools_provider(Arc::new(InventoryToolsProvider::new(
        inventory,
        mapped_agent,
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
    jobs: Arc<AdapterWorker<RunControlJob>>,
}

impl RunManagerRunControl {
    pub fn new(mgr: Arc<RunManager>, tree: Option<Arc<dyn AgentTreeSnapshot>>) -> Self {
        Self::new_tracked(mgr, tree, &mut Vec::new())
    }

    /// As [`Self::new`], also registering the worker thread with `workers`.
    pub(crate) fn new_tracked(
        mgr: Arc<RunManager>,
        tree: Option<Arc<dyn AgentTreeSnapshot>>,
        workers: &mut Vec<Arc<dyn WorkerControl>>,
    ) -> Self {
        let worker = Arc::clone(&mgr);
        let jobs = AdapterWorker::spawn_or_closed(
            "advance-client-run-control",
            move |receiver: mpsc::Receiver<RunControlJob>| {
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
            },
        );
        track(&jobs, workers);
        Self { mgr, tree, jobs }
    }

    fn submit_job(
        &self,
        job: impl FnOnce(mpsc::Sender<Result<(), RunError>>) -> RunControlJob,
    ) -> Result<(), ProviderError> {
        let (reply, response) = mpsc::channel();
        self.jobs
            .submit(job(reply))
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

impl Drop for RunManagerRunControl {
    /// Only closes the queue (the thread then exits on its own): never blocks on a join.
    fn drop(&mut self) {
        self.jobs.close();
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

    fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !done() {
            assert!(
                std::time::Instant::now() < until,
                "timed out waiting for {what}"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    #[test]
    fn module_001_ac30_adapter_worker_close_drains_then_try_join_reports_the_exit() {
        let sum = Arc::new(AtomicU64::new(0));
        let seen = Arc::clone(&sum);
        let worker = AdapterWorker::<u64>::spawn("t111-adapter", move |rx| {
            while let Ok(n) = rx.recv() {
                seen.fetch_add(n, Ordering::SeqCst);
            }
        })
        .expect("spawn");
        assert_eq!(worker.name(), "t111-adapter");
        for n in [1, 2, 3] {
            assert!(worker.submit(n).is_ok());
        }
        assert!(!worker.try_join(), "the thread is still waiting for jobs");
        worker.close();
        wait_for("the worker thread to exit", || worker.try_join());
        assert_eq!(
            sum.load(Ordering::SeqCst),
            6,
            "queued jobs ran before the exit"
        );
        assert!(matches!(worker.submit(4), Err(4)), "closed: refused");
        assert!(worker.try_join(), "joined stays joined");
    }

    #[test]
    fn module_001_ac30_adapter_worker_try_join_never_blocks_on_a_busy_thread() {
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let worker = AdapterWorker::<()>::spawn("t111-busy", move |rx| {
            while rx.recv().is_ok() {
                let _ = entered_tx.send(());
                let _ = release_rx.recv();
            }
        })
        .expect("spawn");
        assert!(worker.submit(()).is_ok());
        entered_rx.recv().expect("job in hand");
        worker.close();
        let begun = std::time::Instant::now();
        assert!(!worker.try_join(), "busy: not joined");
        assert!(
            begun.elapsed() < std::time::Duration::from_millis(50),
            "try_join returned at once"
        );
        release_tx.send(()).unwrap();
        wait_for("the busy thread to exit", || worker.try_join());
    }

    #[test]
    fn module_001_ac30_spawn_or_closed_refuses_without_a_thread() {
        let worker = AdapterWorker::<u8> {
            name: "t111-none",
            jobs: Mutex::new(None),
            thread: Mutex::new(None),
        };
        assert!(matches!(worker.submit(7), Err(7)));
        assert!(worker.try_join(), "no thread: nothing to wait for");
    }

    struct NoopBus;
    impl advance_shared_types::traits::EventBusEmit for NoopBus {
        fn emit(&self, _event: advance_shared_types::event::Event) {}
    }

    #[test]
    fn module_001_ac30_run_control_adapter_drop_closes_its_tracked_worker() {
        let mgr = RunManager::new_arc(Arc::new(NoopBus));
        let mut workers: Vec<Arc<dyn WorkerControl>> = Vec::new();
        let adapter = RunManagerRunControl::new_tracked(mgr, None, &mut workers);
        assert_eq!(workers.len(), 1);
        assert_eq!(workers[0].name(), "advance-client-run-control");
        assert!(!workers[0].try_join(), "the thread waits for jobs");
        // The last adapter reference drops while the tracked list still holds the worker:
        // the drop closes the queue and returns without joining.
        let begun = std::time::Instant::now();
        drop(adapter);
        assert!(begun.elapsed() < std::time::Duration::from_millis(50));
        wait_for("the run-control thread to exit", || workers[0].try_join());
    }

    #[test]
    fn tracked_sends_evicts_oldest() {
        let mut sent = TrackedSends::new();
        for i in 0..=MAX_TRACKED_CLIENT_MESSAGES {
            sent.insert(format!("cmsg-{i}"), "agent:root".to_owned());
        }
        assert!(sent.get("cmsg-0").is_none());
        assert!(sent
            .get(&format!("cmsg-{MAX_TRACKED_CLIENT_MESSAGES}"))
            .is_some());
        assert_eq!(sent.by_id.len(), MAX_TRACKED_CLIENT_MESSAGES);
    }
}

//! Production adapters from host observation/grant surfaces to CONTRACT-190.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::SystemTime;

use advance_client_api::{
    BoundGrantApprovalPort, BoundGrantMutation, BoundHistoryPage, BoundHistoryReadPort,
    BoundMutationOutcome, ClientApi, ClientEventProvider, ClientMessageAck, ClientMessageStatus,
    MessagingProvider, NormalizedEventFilter, ProviderClientDoneReceipt, ProviderError,
    ProviderMutationRecovery, ProviderPrepareOutcome, RawEventRow,
};
use advance_event_bus::{EventFilter, ObservabilityReadApi, ReadApiError, ReadCursor, ReadEvent};
use advance_messaging::{MailboxStore, Message, MessageKind, MsgError};
use advance_shared_types::sensitive_observation::{CanonicalCapParam, ObservationNode};
use cap_grant::{GrantApprovalIntake, GrantTtl};

use crate::execution_turn_ingress::ExecutionTurnIngress;
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

/// Read adapter for the real CONTRACT-123 intake. Mutation methods remain
/// unavailable until the separately-scoped durable Order-5 provider is bound;
/// they fail closed rather than bypassing prepare/recovery semantics.
pub struct Contract219GrantAdapter {
    intake: Arc<GrantApprovalIntake>,
    projector: Arc<Contract219EventProjector>,
}

impl Contract219GrantAdapter {
    pub fn new(
        intake: Arc<GrantApprovalIntake>,
        projector: Arc<Contract219EventProjector>,
    ) -> Self {
        Self { intake, projector }
    }
}

impl BoundGrantApprovalPort for Contract219GrantAdapter {
    fn list_pending_bound(
        &self,
    ) -> Result<
        Vec<advance_shared_types::sensitive_observation::BoundObservationDocument>,
        ProviderError,
    > {
        self.intake
            .list_pending()
            .into_iter()
            .map(|pending| {
                let params = match pending.params {
                    Some(params) => ObservationNode::CanonicalCapParams(
                        params
                            .into_iter()
                            .map(|param| CanonicalCapParam {
                                key: param.key,
                                value: ObservationNode::String(param.value),
                            })
                            .collect(),
                    ),
                    None => ObservationNode::Null,
                };
                let root = ObservationNode::Object(vec![
                    (
                        "kind".to_owned(),
                        ObservationNode::String("pending_grant".to_owned()),
                    ),
                    (
                        "request_id".to_owned(),
                        ObservationNode::String(pending.request_id),
                    ),
                    (
                        "decision_revision".to_owned(),
                        ObservationNode::String("A".repeat(247)),
                    ),
                    (
                        "caller_id".to_owned(),
                        ObservationNode::String(pending.caller.clone()),
                    ),
                    (
                        "capability".to_owned(),
                        ObservationNode::String(pending.capability),
                    ),
                    ("params".to_owned(), params),
                    ("ttl".to_owned(), ttl_node(pending.ttl)),
                    (
                        "justification".to_owned(),
                        pending
                            .justification
                            .map(ObservationNode::String)
                            .unwrap_or(ObservationNode::Null),
                    ),
                ]);
                self.projector
                    .bind_pending_grant(&pending.caller, root)
                    .map_err(ProviderError::Unavailable)
            })
            .collect()
    }

    fn prepare_mutation_bound(
        &self,
        _mutation_id: [u8; 32],
        _request_fingerprint: [u8; 32],
        _mutation: BoundGrantMutation,
    ) -> ProviderPrepareOutcome {
        ProviderPrepareOutcome::Rejected(ProviderError::Unavailable(
            "durable grant mutation provider is not composed".to_owned(),
        ))
    }

    fn verify_recovery_ticket_bound(
        &self,
        _mutation_id: [u8; 32],
        _request_fingerprint: [u8; 32],
        _operation_tag: u8,
        _recovery: &ProviderMutationRecovery,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::Unavailable(
            "durable grant mutation provider is not composed".to_owned(),
        ))
    }

    fn execute_prepared_bound(&self, _recovery: &ProviderMutationRecovery) -> BoundMutationOutcome {
        BoundMutationOutcome::Rejected(ProviderError::Unavailable(
            "durable grant mutation provider is not composed".to_owned(),
        ))
    }

    fn recover_mutation_bound(&self, _recovery: &ProviderMutationRecovery) -> BoundMutationOutcome {
        BoundMutationOutcome::Rejected(ProviderError::Unavailable(
            "durable grant mutation provider is not composed".to_owned(),
        ))
    }

    fn acknowledge_client_done_bound(
        &self,
        _done: &ProviderClientDoneReceipt,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::Unavailable(
            "durable grant mutation provider is not composed".to_owned(),
        ))
    }
}

fn ttl_node(ttl: GrantTtl) -> ObservationNode {
    let fields = match ttl {
        GrantTtl::Once => vec![("kind", "once")],
        GrantTtl::Lifecycle => vec![("kind", "lifecycle")],
        GrantTtl::Persistent => vec![("kind", "persistent")],
        GrantTtl::Duration(milliseconds) => {
            return ObservationNode::Object(vec![
                (
                    "kind".to_owned(),
                    ObservationNode::String("duration".to_owned()),
                ),
                (
                    "milliseconds_u64".to_owned(),
                    ObservationNode::String(milliseconds.to_string()),
                ),
            ])
        }
        GrantTtl::Until(at) => {
            return ObservationNode::Object(vec![
                (
                    "kind".to_owned(),
                    ObservationNode::String("until".to_owned()),
                ),
                ("at".to_owned(), ObservationNode::String(at.to_rfc3339())),
            ])
        }
    };
    ObservationNode::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), ObservationNode::String(value.to_owned())))
            .collect(),
    )
}

/// Must match `commands::start::DEFAULT_MSG_AGENT_ID` (avoid a start↔adapters cycle).
const SERVE_LOOP_AGENT: &str = "agent:default";

/// CLI-served CONTRACT-190 messaging port: deliver a User message onto the
/// same mailbox the root serve loop recvs (POST `/msg` generate path).
pub struct ServeLoopMessagingProvider {
    store: Arc<MailboxStore>,
    ingress: Option<Arc<ExecutionTurnIngress>>,
    replies: Arc<ReplyRegistry>,
    counter: AtomicU64,
    sent: Mutex<HashMap<String, String>>,
}

impl ServeLoopMessagingProvider {
    pub(crate) fn new(
        store: Arc<MailboxStore>,
        ingress: Option<Arc<ExecutionTurnIngress>>,
        replies: Arc<ReplyRegistry>,
    ) -> Self {
        Self {
            store,
            ingress,
            replies,
            counter: AtomicU64::new(0),
            sent: Mutex::new(HashMap::new()),
        }
    }

    #[cfg(feature = "test-support")]
    pub fn for_test(store: Arc<MailboxStore>, replies: Arc<ReplyRegistry>) -> Self {
        Self::new(store, None, replies)
    }
}

pub(crate) fn install_serve_loop_messaging(
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

//! MODULE-020 client-api foundation slice (m020-s1).
//!
//! A **transport-agnostic** implementation of the public Client API contract surfaces:
//! - **CONTRACT-190** `PublicClientApi` — [`ClientEnvelope`] (data-XOR-error), deterministic
//!   error codes, list cursor pagination, reserve-before-execute idempotency, and
//!   `unsupported_api_version` fail-closed.
//! - **CONTRACT-193** `ClientSessionAuth` — sessions (login/refresh/logout), single-operator
//!   local-first bootstrap, CSRF for browser mutations, same-origin/CORS policy, and
//!   loopback-only default bind (enforced at admission).
//! - **CONTRACT-192** `ClientSdkContract` — a schemars-derived JSON schema, a schema-hash
//!   manifest, and conformance vectors (see [`schema`]).
//!
//! [`transport`] is the thin public HTTP/WebSocket adapter: it maps sockets into the same
//! request pipeline and serves the embedded Web Console without importing owner-module internals.
//! Provider-backed endpoint families (runs/messages/grants) and the CONTRACT-191 event
//! stream/history sync facade remain transport-independent.

pub mod api;
pub mod audit;
pub mod auth;
pub mod clock;
pub mod config;
pub mod cursor;
pub mod deltas;
pub mod durable_idempotency;
pub mod envelope;
pub mod events;
pub mod idempotency;
pub mod messages;
pub mod pagination;
pub mod projection;
pub mod provider;
pub mod providers;
pub mod request;
pub mod routes;
pub mod runs;
pub mod schema;
pub mod session;
pub mod tools;
pub mod transport;
pub mod version;

pub use api::{ClientApi, ClientMutationContext, HandlerCtx, HandlerResponse, HandlerSpec};
pub use audit::{AuditEvent, AuditSink, NoopSink};
pub use clock::{Clock, SystemClock};
pub use config::ClientApiConfig;
pub use cursor::{
    AeadClientCursorCodec, ClientCursorCodec, CursorClock, CursorEntropy, CursorKeyCustody,
    MemoryCursorKeyCustody, OpenedSeal, OsCursorEntropy, SealPurpose, SystemCursorClock,
};
pub use deltas::{
    open_delta_cursor, resolve_stream_request, seal_delta_cursor, DeltaHoldSplit, DeltaObserver,
    DeltaPumpExit, DeltaPumpExitObserver, DeltaSubscriberPermit, DeltaTiming, HubEvent,
    LlmDeltaCursor, LlmDeltaHub, LlmDeltaItem, LlmDeltaPage, LlmDeltaStreamRequest,
    LlmDeltaTerminal, LlmDeltaUsage, LlmDeltaWirePage, ReauthDeadline, DELTA_CURSOR_STREAM_DOMAIN,
    LLM_DELTA_ABSENT_NOTE,
};
pub use envelope::{ClientEnvelope, ClientError, ClientErrorCode, ClientWarning, API_VERSION};
pub use events::{
    stream_id_for_filter, ClientEvent, ClientEventCursor, ClientEventFilter, ClientEventPage,
    ClientEventPriority, ClientEventProvider, ClientEventStreamRequest, ClientEventsRequest,
    ClientScalar, EventConcurrency, NormalizedEventFilter, RawEventRow,
};
pub use messages::{ClientMessageAck, ClientMessageStatus, ClientSendMessageRequest};
pub use pagination::{Cursor, Page};
pub use provider::{MessagingProvider, ProviderError, RunControlProvider, ToolsProvider};
pub use providers::grants::{
    BoundGrantApprovalPort, BoundGrantMutation, BoundMutationOutcome, ClientCapParam,
    ClientGrantApproveRequest, ClientGrantDecision, ClientGrantDenyRequest,
    ClientGrantNarrowRequest, ClientGrantRevokeRequest, ClientGrantRevokeResult, ClientGrantTtl,
    ClientPendingGrant, ClientPresetApplyRequest, ClientPresetApplyResult,
    ProviderClientDoneReceipt, ProviderMutationRecovery, ProviderPrepareOutcome,
};
pub use providers::history::{
    BoundHistoryPage, BoundHistoryReadPort, ClientHistoryEntry, ClientHistoryResponse,
};
pub use request::{ClientRequest, Method};
pub use runs::{ClientAgentTreeNode, ClientRunMutation, ClientRunSummary};
pub use session::{ClientSession, Platform, Principal, Scope};
pub use tools::{ClientMcpEntry, ClientSkillEntry, ClientToolEntry, ClientToolInventory};
pub use transport::{client_api_router, ClientApiServer, CLIENT_WS_PROTOCOL};

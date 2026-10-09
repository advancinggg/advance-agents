//! Extension Client API families (ADR 2026-10-03 D2(a); CONTRACT-244 hook into CONTRACT-190).
//!
//! A composer builds one [`RouteBook`] before the Client API is bound, hands each extension a
//! [`ClientFamilyRegistrar`] for its `client_families` callback, then calls [`RouteBook::finish`].
//! The resulting [`ExtensionFamilies`] is installed into the `ClientApi` inside the bind factory
//! (which cannot fail) with [`ExtensionFamilies::install`]. An extension never sees the `ClientApi`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use advance_shared_types::security_validator::LeakDetector;
use serde_json::Value;
use tokio::sync::Semaphore;

use crate::api::{ClientApi, HandlerCtx, HandlerSpec};
use crate::audit::NoopSink;
use crate::clock::{Clock, SystemClock};
use crate::config::ClientApiConfig;
use crate::cursor::{
    ClientCursorCodec, ExtensionSealDomain, OpenedSeal, SealPurpose, SEAL_TAG_RAW_ID,
};
use crate::envelope::{ClientError, ClientErrorCode, ClientWarning};
use crate::idempotency::IdempotencyStore;
use crate::providers::grants::scan_client_text;
use crate::request::Method;
use crate::routes::{family_of, RouteTableEntry, TRANSPORT_STREAM_PATHS};
use crate::session::Scope;

/// `family_of` of a path with no first segment.
pub const RESERVED_ROOT_LABEL: &str = "root";

/// The static floor of OSS family labels (ADR D2(a)). A unit test keeps it equal to the labels of
/// every OSS route (`oss_route_table()`) plus `session` (session ops are dispatched before route lookup).
pub const RESERVED_FAMILY_FLOOR: &[&str] = &[
    "session",
    "health",
    "runs",
    "messages",
    "tools",
    "events",
    "grants",
    "presets",
    "tasks",
    "llm",
    "agents",
    "agent-templates",
    "packs",
    "costs",
    "providers",
    "secrets",
    "schema",
    "entities",
];

/// A mutation route must require at least one of these (the full operator set contains all four).
pub const WRITE_CLASS_SCOPES: [Scope; 4] = [
    Scope::ControlRuns,
    Scope::SendMessages,
    Scope::ApproveGrants,
    Scope::WriteEntities,
];

/// Requested default per-extension budget; the effective default is clamped to the server caps.
pub const DEFAULT_DISPATCH_PERMITS: u32 = 16;
pub const DEFAULT_IDEMPOTENCY_RECORDS: usize = 1_000;

const POINTER_FIELD_MAX: usize = 256;
const POLL_POINTER_MAX: usize = 128;

/// GET read + WebSocket poll adapter at one exact path (MODULE-001-AC-33).
#[non_exhaustive]
pub struct PollStreamSpec {
    /// The GET read registered at the same path (session + scope rules apply).
    pub handler: HandlerSpec,
    /// RFC 6901 pointer of the cursor inside a success `data`; the adapter writes the same pointer
    /// into the next poll's request body (creating objects along the way).
    pub cursor: &'static str,
    pub emit: PollEmit,
}

impl PollStreamSpec {
    pub fn new(handler: HandlerSpec, cursor: &'static str, emit: PollEmit) -> Self {
        Self {
            handler,
            cursor,
            emit,
        }
    }
}

/// When a poll frame is sent after the seed (the seed is always sent).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PollEmit {
    /// Send a poll frame only when `data[pointer]` is a non-empty array.
    NonEmptyArrayAt(&'static str),
}

/// Why [`ClientFamilyRegistrar::poll_stream`] refused a registration.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PollStreamDefect {
    TemplatedPath,
    InvalidCursorPointer,
    InvalidEmitPointer,
    HandlerNotRead,
}

impl std::fmt::Display for PollStreamDefect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PollStreamDefect::TemplatedPath => write!(f, "templated path"),
            PollStreamDefect::InvalidCursorPointer => write!(f, "invalid cursor pointer"),
            PollStreamDefect::InvalidEmitPointer => write!(f, "invalid emit pointer"),
            PollStreamDefect::HandlerNotRead => write!(f, "handler is not a GET read"),
        }
    }
}

/// One accepted poll stream, keyed by exact path on [`ClientApi`].
pub(crate) struct PollStreamEntry {
    #[allow(dead_code)]
    pub(crate) extension: &'static str,
    pub(crate) cursor: &'static str,
    pub(crate) emit: PollEmit,
    pub(crate) dispatch: Arc<Semaphore>,
}

fn check_poll_pointer(pointer: &str) -> bool {
    if pointer.len() > POLL_POINTER_MAX || !pointer.starts_with('/') {
        return false;
    }
    let rest = &pointer[1..];
    if rest.is_empty() {
        return false;
    }
    for token in rest.split('/') {
        if token.is_empty() {
            return false;
        }
        let bytes = token.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'~' {
                if i + 1 >= bytes.len() || (bytes[i + 1] != b'0' && bytes[i + 1] != b'1') {
                    return false;
                }
                i += 2;
            } else {
                i += 1;
            }
        }
    }
    true
}

/// Every OSS route, read from a scratch `ClientApi` built with `with_parts` (no environment read).
pub fn oss_route_table() -> Vec<RouteTableEntry> {
    ClientApi::with_parts(
        ClientApiConfig::default(),
        "operator",
        Arc::new(SystemClock),
        Arc::new(NoopSink),
    )
    .route_table()
}

/// The fixed client-facing message of an error code, used for every error an extension handler returns.
pub fn fixed_error_message(code: &ClientErrorCode) -> &'static str {
    match code {
        ClientErrorCode::UnsupportedApiVersion => "unsupported api version",
        ClientErrorCode::IdempotencyConflict => "idempotency key used for a different request",
        ClientErrorCode::IdempotencyRequired => "missing idempotency key",
        ClientErrorCode::IdempotencyCapacity => "idempotency capacity exhausted",
        ClientErrorCode::ModuleUnavailable => "provider unavailable",
        ClientErrorCode::UnknownRoute => "no route",
        ClientErrorCode::ProjectionRejected => "client projection rejected",
        ClientErrorCode::RequestTooLarge => "request too large",
        ClientErrorCode::StreamBackpressure => "stream backpressure",
        ClientErrorCode::NotFound => "resource not found",
        ClientErrorCode::Unauthenticated => "missing session",
        ClientErrorCode::ReplyNotAuthorized => "reply not authorized",
        ClientErrorCode::SessionExpired => "session expired",
        ClientErrorCode::InvalidState => "operation not valid for the resource's current state",
        ClientErrorCode::CsrfRequired | ClientErrorCode::CsrfInvalid => "csrf",
        ClientErrorCode::Forbidden => "insufficient scope",
        ClientErrorCode::AlreadyExists => "resource already exists",
        ClientErrorCode::OriginNotAllowed => "origin not allowed",
        ClientErrorCode::InvalidRequest => "invalid request",
        ClientErrorCode::RemoteBindForbidden => "non-loopback peer",
        ClientErrorCode::Unknown => "provider unavailable",
        ClientErrorCode::InvalidBootstrapCode => "invalid bootstrap code",
        ClientErrorCode::IdempotencyInProgress => "in progress",
    }
}

/// `"GET"` / `"POST"` (log and refusal texts). A free fn: `Method` is a schema type and is not edited.
pub fn method_label(method: Method) -> &'static str {
    match method {
        Method::Get => "GET",
        Method::Post => "POST",
    }
}

fn fixed(code: ClientErrorCode) -> ClientError {
    ClientError::new(code.clone(), fixed_error_message(&code))
}

fn composer_id_ok(id: &str) -> bool {
    let mut chars = id.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    let rest = chars.as_str();
    rest.len() <= 31
        && rest
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn is_token(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    let rest = chars.as_str();
    rest.len() <= 63
        && rest.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | ':' | '-')
        })
}

fn shape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            if let Some(rel) = text[i + 1..].find('}') {
                out.push_str("{}");
                i += rel + 2;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn route_text(method: Method, path: &str) -> String {
    format!("{} {path}", method_label(method))
}

fn first_segment<'a>(path: &'a str) -> &'a str {
    path.strip_prefix("/client/")
        .unwrap_or(path)
        .split('/')
        .next()
        .unwrap_or("")
}

fn first_segment_is_param(path: &str) -> bool {
    first_segment(path).starts_with('{')
}

fn literal_ok(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

fn param_name_ok(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    let rest = chars.as_str();
    rest.len() <= 63
        && rest
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn verb_ok(verb: &str) -> bool {
    literal_ok(verb)
}

fn split_head_verb(seg: &str) -> (&str, Option<&str>) {
    match seg.find(':') {
        Some(i) => (&seg[..i], Some(&seg[i + 1..])),
        None => (seg, None),
    }
}

fn parse_exact_param_head(head: &str) -> Option<&str> {
    let rest = head.strip_prefix('{')?;
    let name = rest.strip_suffix('}')?;
    Some(name)
}

fn check_path_grammar(text: &str, max_path_len: usize) -> Result<(), PathDefect> {
    let Some(rest) = text.strip_prefix("/client/") else {
        return Err(PathDefect::NotUnderClient);
    };
    if text.len() > max_path_len {
        return Err(PathDefect::TooLong {
            len: text.len(),
            max: max_path_len,
        });
    }
    let segs: Vec<&str> = rest.split('/').collect();
    let mut seen_params: HashSet<&str> = HashSet::new();
    for (i, seg) in segs.iter().enumerate() {
        if seg.is_empty() {
            return Err(PathDefect::EmptySegment { index: i });
        }
        if *seg == "." || *seg == ".." {
            return Err(PathDefect::DotSegment { index: i });
        }
        if seg.contains('%') {
            return Err(PathDefect::PercentSegment { index: i });
        }
        let last = i + 1 == segs.len();
        if !last && seg.contains(':') {
            return Err(PathDefect::VerbNotFinal { index: i });
        }
        let (head, verb) = if last {
            split_head_verb(seg)
        } else {
            (*seg, None)
        };
        if let Some(verb) = verb {
            if !verb_ok(verb) {
                return Err(PathDefect::InvalidVerb { index: i });
            }
        }
        if let Some(name) = parse_exact_param_head(head) {
            if !param_name_ok(name) {
                return Err(PathDefect::InvalidParamName { index: i });
            }
            if !seen_params.insert(name) {
                return Err(PathDefect::DuplicateParamName {
                    name: name.to_string(),
                });
            }
        } else if head.contains('{') || head.contains('}') {
            return Err(PathDefect::InvalidParamName { index: i });
        } else if !literal_ok(head) {
            return Err(PathDefect::InvalidSegment { index: i });
        }
    }
    Ok(())
}

fn specificity_rank(template: &str) -> Vec<u8> {
    template
        .split('/')
        .map(|seg| {
            if let Some(rest) = seg.strip_prefix('{') {
                if let Some(close) = rest.find('}') {
                    let after = &rest[close + 1..];
                    if after.starts_with(':') {
                        return 1;
                    }
                    return 2;
                }
                return 2;
            }
            0
        })
        .collect()
}

fn escape_pointer_token(s: &str) -> String {
    s.replace('~', "~0").replace('/', "~1")
}

/// `pointer`, cut to at most [`POINTER_FIELD_MAX`] bytes with a trailing `…`. The cut backs off
/// to a character boundary: object keys are extension text and may be non-ASCII.
fn cap_pointer(pointer: &str) -> String {
    if pointer.len() <= POINTER_FIELD_MAX {
        return pointer.to_string();
    }
    let ellipsis = "…";
    let mut keep = POINTER_FIELD_MAX.saturating_sub(ellipsis.len());
    while !pointer.is_char_boundary(keep) {
        keep -= 1;
    }
    format!("{}{ellipsis}", &pointer[..keep])
}

fn scan_success_body(
    data: &mut Value,
    detector: &dyn LeakDetector,
    warnings: &mut Vec<ClientWarning>,
) -> Result<(), ClientError> {
    fn walk(
        value: &mut Value,
        pointer: &mut String,
        detector: &dyn LeakDetector,
        warnings: &mut Vec<ClientWarning>,
    ) -> Result<(), ClientError> {
        match value {
            Value::String(s) => {
                let field = if pointer.is_empty() {
                    "/".to_string()
                } else {
                    cap_pointer(pointer)
                };
                scan_client_text(s, detector, &field, true, warnings)
            }
            Value::Array(arr) => {
                for (i, item) in arr.iter_mut().enumerate() {
                    let mark = pointer.len();
                    pointer.push('/');
                    pointer.push_str(&i.to_string());
                    walk(item, pointer, detector, warnings)?;
                    pointer.truncate(mark);
                }
                Ok(())
            }
            Value::Object(map) => {
                let keys: Vec<String> = map.keys().cloned().collect();
                for k in keys {
                    let mark = pointer.len();
                    pointer.push('/');
                    pointer.push_str(&escape_pointer_token(&k));
                    if let Some(v) = map.get_mut(&k) {
                        walk(v, pointer, detector, warnings)?;
                    }
                    pointer.truncate(mark);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    let mut pointer = String::new();
    walk(data, &mut pointer, detector, warnings)
}

fn filter_details(details: Vec<String>) -> (Vec<String>, usize) {
    let mut kept = Vec::new();
    let mut dropped = 0;
    for d in details {
        if kept.len() < 8 && is_token(&d) {
            kept.push(d);
        } else {
            dropped += 1;
        }
    }
    (kept, dropped)
}

fn filter_warnings(
    warnings: &mut Vec<ClientWarning>,
    detector: &dyn LeakDetector,
    extension: &'static str,
    method: Method,
    route: &str,
    hooks: &Arc<dyn ExtensionRouteHooks>,
) {
    let original = std::mem::take(warnings);
    let mut kept = Vec::new();
    let mut scan_extra = Vec::new();
    let mut dropped = 0usize;
    for mut w in original {
        if !is_token(&w.code) {
            dropped += 1;
            continue;
        }
        match scan_client_text(&mut w.message, detector, "warning", true, &mut scan_extra) {
            Ok(()) => kept.push(w),
            Err(_) => dropped += 1,
        }
    }
    *warnings = kept;
    warnings.append(&mut scan_extra);
    if dropped > 0 {
        hooks.event(&ExtensionRouteEvent::WarningsDropped {
            extension,
            method,
            route: route.to_string(),
            count: dropped,
        });
    }
}

fn normalize_error(
    mut e: ClientError,
    extension: &'static str,
    method: Method,
    route: &str,
    hooks: &Arc<dyn ExtensionRouteHooks>,
) -> ClientError {
    if matches!(e.code, ClientErrorCode::Unknown) {
        hooks.event(&ExtensionRouteEvent::UnknownCodeRemapped {
            extension,
            method,
            route: route.to_string(),
        });
        return fixed(ClientErrorCode::ModuleUnavailable);
    }
    e.message = fixed_error_message(&e.code).to_string();
    let (kept, dropped) = filter_details(std::mem::take(&mut e.details));
    e.details = kept;
    if dropped > 0 {
        hooks.event(&ExtensionRouteEvent::DetailsDropped {
            extension,
            method,
            route: route.to_string(),
            count: dropped,
        });
    }
    e
}

fn wrap(
    extension: &'static str,
    method: Method,
    route_text: String,
    spec: HandlerSpec,
    scan: ResponseScan,
    detector: Arc<dyn LeakDetector>,
    gate: ExtensionRouteGate,
    hooks: Arc<dyn ExtensionRouteHooks>,
) -> HandlerSpec {
    let inner = spec.func.clone();
    let mut wrapped = spec;
    wrapped.func = Arc::new(move |ctx: &HandlerCtx| {
        if gate.is_closed() {
            return Err(fixed(ClientErrorCode::ModuleUnavailable));
        }
        match std::panic::catch_unwind(AssertUnwindSafe(|| inner(ctx))) {
            Err(_) => {
                hooks.event(&ExtensionRouteEvent::HandlerPanicked {
                    extension,
                    method,
                    route: route_text.clone(),
                });
                Err(fixed(ClientErrorCode::ModuleUnavailable))
            }
            Ok(Err(e)) => Err(normalize_error(e, extension, method, &route_text, &hooks)),
            Ok(Ok(mut resp)) => {
                filter_warnings(
                    &mut resp.warnings,
                    detector.as_ref(),
                    extension,
                    method,
                    &route_text,
                    &hooks,
                );
                if let ResponseScan::Scan = scan {
                    if let Err(rejected) =
                        scan_success_body(&mut resp.data, detector.as_ref(), &mut resp.warnings)
                    {
                        if let Some(m) = ctx.mutation.as_ref() {
                            let _ = m.mark_provider_entry();
                        }
                        return Err(rejected);
                    }
                }
                Ok(resp)
            }
        }
    });
    wrapped
}

/// One per composition. Closed once the composition begins shutting down; from then on every
/// installed extension route answers `module_unavailable` before auth. Cheap to clone.
#[derive(Clone, Debug, Default)]
pub struct ExtensionRouteGate {
    closed: Arc<AtomicBool>,
}

impl ExtensionRouteGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Idempotent. `store(true, SeqCst)`.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    /// `load(SeqCst)`.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

/// Diagnostics sink the composer supplies. client-api never prints.
pub trait ExtensionRouteHooks: Send + Sync + 'static {
    fn event(&self, event: &ExtensionRouteEvent);
}

/// Drops events (unit tests, non-composer users).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoExtensionRouteHooks;

impl ExtensionRouteHooks for NoExtensionRouteHooks {
    fn event(&self, _: &ExtensionRouteEvent) {}
}

/// `route` is always the REGISTERED text (exact path or template), never the concrete request path.
/// No variant carries extension-controlled runtime text.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtensionRouteEvent {
    /// The handler panicked; the request answered `module_unavailable` "provider unavailable".
    HandlerPanicked {
        extension: &'static str,
        method: Method,
        route: String,
    },
    /// An error carried `details` entries that are not stable tokens, or more than 8 tokens; `count` were dropped.
    DetailsDropped {
        extension: &'static str,
        method: Method,
        route: String,
        count: usize,
    },
    /// Warnings with a non-token `code`, or whose message the leak scan blocked, were dropped.
    WarningsDropped {
        extension: &'static str,
        method: Method,
        route: String,
        count: usize,
    },
    /// The handler returned `ClientErrorCode::Unknown` (never produced by this server); answered `module_unavailable`.
    UnknownCodeRemapped {
        extension: &'static str,
        method: Method,
        route: String,
    },
    /// Emitted once per opted-out route at install: the success body is not leak-scanned.
    ScanOptOut {
        extension: &'static str,
        method: Method,
        route: String,
        reason: &'static str,
    },
}

/// What the composer owns and lends to every extension (present on every home).
#[derive(Clone)]
pub struct ExtensionServiceParts {
    pub leak_detector: Arc<dyn LeakDetector>,
    pub clock: Arc<dyn Clock>,
    pub cursor_codec: Arc<dyn ClientCursorCodec>,
}

/// `ClientFamilyRegistrar::services()`.
#[derive(Clone)]
pub struct ExtensionServices {
    extension: &'static str,
    leak_detector: Arc<dyn LeakDetector>,
    clock: Arc<dyn Clock>,
    cursors: ExtensionCursorCodec,
}

impl ExtensionServices {
    pub fn extension(&self) -> &'static str {
        self.extension
    }
    pub fn leak_detector(&self) -> &Arc<dyn LeakDetector> {
        &self.leak_detector
    }
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }
    pub fn cursors(&self) -> &ExtensionCursorCodec {
        &self.cursors
    }
    /// `scan_client_text(text, detector, field, strip_cf = true, warnings)`.
    pub fn scan_client_text(
        &self,
        text: &mut String,
        field: &str,
        warnings: &mut Vec<ClientWarning>,
    ) -> Result<(), ClientError> {
        scan_client_text(text, self.leak_detector.as_ref(), field, true, warnings)
    }
}

/// The composer's cursor codec, fixed to `SealPurpose::Extension(<this extension>)` and the raw-id tag.
#[derive(Clone)]
pub struct ExtensionCursorCodec {
    purpose: SealPurpose,
    inner: Arc<dyn ClientCursorCodec>,
}

impl ExtensionCursorCodec {
    /// Seal `raw_id` (≤ 256 UTF-8 bytes) for `stream_id`. Errors: `module_unavailable` (codec text).
    pub fn seal(&self, stream_id: &str, raw_id: &str) -> Result<String, ClientError> {
        self.inner
            .seal(self.purpose, stream_id, SEAL_TAG_RAW_ID, raw_id.as_bytes())
    }
    /// Open a token minted by `seal` for the same `stream_id`. Errors: `not_found`.
    pub fn open(&self, stream_id: &str, token: &str) -> Result<String, ClientError> {
        match self.inner.open(self.purpose, stream_id, token) {
            Ok(OpenedSeal::RawId(id)) => Ok(id),
            _ => Err(fixed(ClientErrorCode::NotFound)),
        }
    }
}

/// Per-extension dispatch-permit pool and idempotency-store capacity (both separate from OSS).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FamilyBudget {
    pub dispatch_permits: u32,
    pub idempotency_records: usize,
}

impl FamilyBudget {
    pub const fn new(dispatch_permits: u32, idempotency_records: usize) -> Self {
        Self {
            dispatch_permits,
            idempotency_records,
        }
    }
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ResponseScan {
    /// Every string leaf of a success `data` passes `scan_client_text` (default).
    #[default]
    Scan,
    /// Recorded opt-out: no scan of the success body. `reason`: non-empty after trim, ≤ 200 bytes, no control chars.
    OptOut { reason: &'static str },
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RouteOptions {
    pub response_scan: ResponseScan,
}

impl RouteOptions {
    pub const fn scanned() -> Self {
        Self {
            response_scan: ResponseScan::Scan,
        }
    }
    pub const fn skip_response_scan(reason: &'static str) -> Self {
        Self {
            response_scan: ResponseScan::OptOut { reason },
        }
    }
}

/// One refusal. `route` = `"<METHOD> <path or template>"`, or `"budget"` for budget refusals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteRefusal {
    pub extension: &'static str,
    pub route: String,
    pub reason: RouteRefusalReason,
}

impl RouteRefusal {
    pub fn is_budget_refusal(&self) -> bool {
        matches!(
            self.reason,
            RouteRefusalReason::InvalidBudget { .. } | RouteRefusalReason::BudgetAlreadySet
        )
    }
}

impl std::fmt::Display for RouteRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_budget_refusal() {
            write!(
                f,
                "extension {}: family budget refused: {}",
                self.extension, self.reason
            )
        } else {
            write!(
                f,
                "extension {}: route {} refused: {}",
                self.extension, self.route, self.reason
            )
        }
    }
}

impl std::error::Error for RouteRefusal {}

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteRefusalReason {
    InvalidPath(PathDefect),
    ParamInExactPath,
    ParameterisedFirstSegment,
    ReservedPath,
    ReservedLabel {
        label: String,
    },
    LabelOwnedByOtherExtension {
        label: String,
        owner: &'static str,
    },
    DuplicateRoute {
        shape: String,
        of: DuplicateOf,
    },
    PostNotMutationOrPostRead,
    GetMutation,
    MutationAndPostRead,
    NoSession,
    NoScope,
    MutationWithoutWriteScope,
    ScanOptOutWithoutReason,
    InvalidBudget {
        field: &'static str,
        value: u64,
        max: u64,
    },
    BudgetAlreadySet,
    PollStream(PollStreamDefect),
}

impl std::fmt::Display for RouteRefusalReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteRefusalReason::InvalidPath(d) => write!(f, "non-canonical path: {d}"),
            RouteRefusalReason::ParamInExactPath => {
                write!(
                    f,
                    "an exact route cannot contain a {{parameter}}; use route_templated"
                )
            }
            RouteRefusalReason::ParameterisedFirstSegment => {
                write!(
                    f,
                    "the first segment after /client/ must be a literal family label"
                )
            }
            RouteRefusalReason::ReservedPath => write!(f, "reserved transport stream path"),
            RouteRefusalReason::ReservedLabel { label } => {
                write!(f, "reserved family label `{label}`")
            }
            RouteRefusalReason::LabelOwnedByOtherExtension { label, owner } => {
                write!(f, "family label `{label}` is owned by extension {owner}")
            }
            RouteRefusalReason::DuplicateRoute { shape, of } => match of {
                DuplicateOf::Oss => {
                    write!(f, "duplicate route shape {shape} (already registered by OSS)")
                }
                DuplicateOf::Extension(x) => write!(
                    f,
                    "duplicate route shape {shape} (already registered by extension {x})"
                ),
            },
            RouteRefusalReason::MutationAndPostRead => {
                write!(f, "a route cannot be both a mutation and a post-read")
            }
            RouteRefusalReason::PostNotMutationOrPostRead => {
                write!(
                    f,
                    "a POST route must be HandlerSpec::mutation* or HandlerSpec::post_read*"
                )
            }
            RouteRefusalReason::GetMutation => write!(f, "a GET route cannot be a mutation"),
            RouteRefusalReason::NoSession => write!(f, "the route must require a session"),
            RouteRefusalReason::NoScope => write!(f, "the route must require at least one scope"),
            RouteRefusalReason::MutationWithoutWriteScope => write!(
                f,
                "a mutation must require one of control_runs, send_messages, approve_grants, write_entities"
            ),
            RouteRefusalReason::ScanOptOutWithoutReason => write!(
                f,
                "a response-scan opt-out needs a reason (1-200 bytes, no control characters)"
            ),
            RouteRefusalReason::InvalidBudget { field, value, max } => {
                write!(f, "{field}={value} outside 1..={max}")
            }
            RouteRefusalReason::BudgetAlreadySet => write!(f, "the family budget is already set"),
            RouteRefusalReason::PollStream(d) => write!(f, "poll stream: {d}"),
        }
    }
}

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathDefect {
    NotUnderClient,
    TooLong { len: usize, max: usize },
    EmptySegment { index: usize },
    DotSegment { index: usize },
    PercentSegment { index: usize },
    InvalidSegment { index: usize },
    InvalidParamName { index: usize },
    DuplicateParamName { name: String },
    VerbNotFinal { index: usize },
    InvalidVerb { index: usize },
}

impl std::fmt::Display for PathDefect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathDefect::NotUnderClient => write!(f, "path is not under /client/"),
            PathDefect::TooLong { len, max } => write!(f, "path is {len} bytes, max {max}"),
            PathDefect::EmptySegment { index } => write!(f, "empty segment at index {index}"),
            PathDefect::DotSegment { index } => write!(f, "dot segment at index {index}"),
            PathDefect::PercentSegment { index } => {
                write!(f, "percent-encoded segment at index {index}")
            }
            PathDefect::InvalidSegment { index } => write!(f, "invalid segment at index {index}"),
            PathDefect::InvalidParamName { index } => {
                write!(f, "invalid parameter name at index {index}")
            }
            PathDefect::DuplicateParamName { name } => {
                write!(f, "duplicate parameter name `{name}`")
            }
            PathDefect::VerbNotFinal { index } => {
                write!(f, "verb not on the final segment (index {index})")
            }
            PathDefect::InvalidVerb { index } => write!(f, "invalid verb at index {index}"),
        }
    }
}

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DuplicateOf {
    Oss,
    Extension(&'static str),
}

struct RecordedRoute {
    method: Method,
    path: String,
    templated: bool,
    spec: HandlerSpec,
    options: RouteOptions,
    poll_stream: bool,
}

struct PendingPollStream {
    path: String,
    cursor: &'static str,
    emit: PollEmit,
}

struct ExtensionRecord {
    extension: &'static str,
    services: ExtensionServices,
    routes: Vec<RecordedRoute>,
    poll_streams: Vec<PendingPollStream>,
    budget: Option<FamilyBudget>,
    refusal: Option<RouteRefusal>,
}

/// The recording registrar state across all extensions of one composition.
pub struct RouteBook {
    max_path_len: usize,
    max_dispatch: u32,
    max_records: usize,
    ttl_ms: u64,
    oss_shapes: HashSet<(Method, String)>,
    reserved_labels: HashSet<String>,
    reserved_paths: HashSet<String>,
    label_owner: BTreeMap<String, &'static str>,
    ext_shapes: HashMap<(Method, String), &'static str>,
    extensions: Vec<ExtensionRecord>,
    gate: ExtensionRouteGate,
    hooks: Arc<dyn ExtensionRouteHooks>,
    parts: ExtensionServiceParts,
    check_reserved_labels: bool,
    check_label_ownership: bool,
}

impl RouteBook {
    pub fn new(
        config: &ClientApiConfig,
        parts: ExtensionServiceParts,
        gate: ExtensionRouteGate,
        hooks: Arc<dyn ExtensionRouteHooks>,
    ) -> Self {
        let max_dispatch = config.max_concurrent_dispatch.clamp(1, 65_536) as u32;
        let oss = oss_route_table();
        let mut oss_shapes = HashSet::new();
        let mut reserved_labels = HashSet::new();
        reserved_labels.insert(RESERVED_ROOT_LABEL.to_string());
        for label in RESERVED_FAMILY_FLOOR {
            reserved_labels.insert((*label).to_string());
        }
        for e in &oss {
            oss_shapes.insert((e.method, shape(&e.path)));
            reserved_labels.insert(family_of(&e.path));
        }
        for p in TRANSPORT_STREAM_PATHS {
            reserved_labels.insert(family_of(p));
        }
        let reserved_paths = TRANSPORT_STREAM_PATHS
            .iter()
            .map(|p| (*p).to_string())
            .collect();
        Self {
            max_path_len: config.max_path_len,
            max_dispatch,
            max_records: config.idempotency_store_cap,
            ttl_ms: config.idempotency_ttl_ms,
            oss_shapes,
            reserved_labels,
            reserved_paths,
            label_owner: BTreeMap::new(),
            ext_shapes: HashMap::new(),
            extensions: Vec::new(),
            gate,
            hooks,
            parts,
            check_reserved_labels: true,
            check_label_ownership: true,
        }
    }

    /// Opens (first call: creates) the record of `extension`; registration order = first-open order.
    /// `extension` is a composer-validated id; no id refusal exists.
    pub fn registrar(&mut self, extension: &'static str) -> ClientFamilyRegistrar<'_> {
        debug_assert!(
            composer_id_ok(extension),
            "composer-validated extension id `{extension}`"
        );
        if let Some(index) = self
            .extensions
            .iter()
            .position(|e| e.extension == extension)
        {
            return ClientFamilyRegistrar { book: self, index };
        }
        let services = ExtensionServices {
            extension,
            leak_detector: Arc::clone(&self.parts.leak_detector),
            clock: Arc::clone(&self.parts.clock),
            cursors: ExtensionCursorCodec {
                purpose: SealPurpose::Extension(ExtensionSealDomain::new(extension)),
                inner: Arc::clone(&self.parts.cursor_codec),
            },
        };
        self.extensions.push(ExtensionRecord {
            extension,
            services,
            routes: Vec::new(),
            poll_streams: Vec::new(),
            budget: None,
            refusal: None,
        });
        let index = self.extensions.len() - 1;
        ClientFamilyRegistrar { book: self, index }
    }

    /// The first refusal recorded for `extension`, if any (sticky).
    pub fn refusal(&self, extension: &str) -> Option<&RouteRefusal> {
        self.extensions
            .iter()
            .find(|e| e.extension == extension)
            .and_then(|e| e.refusal.as_ref())
    }

    /// Wraps every accepted route and builds the budgets. Err = the first recorded refusal (registration order).
    pub fn finish(self) -> Result<ExtensionFamilies, RouteRefusal> {
        if let Some(r) = self.extensions.iter().find_map(|e| e.refusal.clone()) {
            return Err(r);
        }
        let mut exact = Vec::new();
        let mut templated = Vec::new();
        let mut report = Vec::new();
        let mut scan_opt_outs = Vec::new();
        let mut budgets = Vec::new();
        let mut poll_streams = HashMap::new();
        for rec in &self.extensions {
            let mut labels: BTreeMap<String, ()> = BTreeMap::new();
            for route in &rec.routes {
                labels.insert(family_of(&route.path), ());
                let wrapped = wrap(
                    rec.extension,
                    route.method,
                    route.path.clone(),
                    route.spec.clone(),
                    route.options.response_scan,
                    Arc::clone(&rec.services.leak_detector),
                    self.gate.clone(),
                    Arc::clone(&self.hooks),
                );
                report.push(ExtensionRouteInfo {
                    extension: rec.extension,
                    method: route.method,
                    path: route.path.clone(),
                    templated: route.templated,
                    response_scan: route.options.response_scan,
                    poll_stream: route.poll_stream,
                });
                if let ResponseScan::OptOut { reason } = route.options.response_scan {
                    scan_opt_outs.push(ExtensionRouteEvent::ScanOptOut {
                        extension: rec.extension,
                        method: route.method,
                        route: route.path.clone(),
                        reason,
                    });
                }
                if route.templated {
                    templated.push((route.method, route.path.clone(), wrapped));
                } else {
                    exact.push((route.method, route.path.clone(), wrapped));
                }
            }
            if rec.routes.is_empty() {
                continue;
            }
            let permits = rec
                .budget
                .map_or(DEFAULT_DISPATCH_PERMITS.min(self.max_dispatch), |b| {
                    b.dispatch_permits
                });
            let records = rec
                .budget
                .map_or(DEFAULT_IDEMPOTENCY_RECORDS.min(self.max_records), |b| {
                    b.idempotency_records
                });
            let dispatch = Arc::new(Semaphore::new(permits as usize));
            budgets.push(Arc::new(ExtensionBudget {
                extension: rec.extension,
                labels: labels.into_keys().collect(),
                dispatch: Arc::clone(&dispatch),
                dispatch_permits: permits,
                idempotency: IdempotencyStore::new(self.ttl_ms, records),
            }));
            for pending in &rec.poll_streams {
                poll_streams.insert(
                    pending.path.clone(),
                    Arc::new(PollStreamEntry {
                        extension: rec.extension,
                        cursor: pending.cursor,
                        emit: pending.emit,
                        dispatch: Arc::clone(&dispatch),
                    }),
                );
            }
        }
        templated.sort_by(|a, b| specificity_rank(&a.1).cmp(&specificity_rank(&b.1)));
        Ok(ExtensionFamilies {
            exact,
            templated,
            budgets,
            report,
            scan_opt_outs,
            poll_streams,
            gate: self.gate,
            hooks: self.hooks,
        })
    }

    /// Test seam: relax the label rules so the duplicate-by-shape rule can be witnessed on its own.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn with_label_rules_for_test(
        mut self,
        reserved_labels: bool,
        label_ownership: bool,
    ) -> Self {
        self.check_reserved_labels = reserved_labels;
        self.check_label_ownership = label_ownership;
        self
    }
}

/// Handed to one extension's `client_families`. Never exposes the `ClientApi`.
pub struct ClientFamilyRegistrar<'a> {
    book: &'a mut RouteBook,
    index: usize,
}

impl<'a> ClientFamilyRegistrar<'a> {
    pub fn extension(&self) -> &'static str {
        self.book.extensions[self.index].extension
    }

    pub fn services(&self) -> &ExtensionServices {
        &self.book.extensions[self.index].services
    }

    pub fn route(
        &mut self,
        method: Method,
        path: &str,
        spec: HandlerSpec,
    ) -> Result<(), RouteRefusal> {
        self.route_with(method, path, spec, RouteOptions::scanned())
    }

    pub fn route_templated(
        &mut self,
        method: Method,
        template: &str,
        spec: HandlerSpec,
    ) -> Result<(), RouteRefusal> {
        self.route_templated_with(method, template, spec, RouteOptions::scanned())
    }

    pub fn route_with(
        &mut self,
        method: Method,
        path: &str,
        spec: HandlerSpec,
        options: RouteOptions,
    ) -> Result<(), RouteRefusal> {
        self.record(method, path, spec, options, false)
    }

    pub fn route_templated_with(
        &mut self,
        method: Method,
        template: &str,
        spec: HandlerSpec,
        options: RouteOptions,
    ) -> Result<(), RouteRefusal> {
        self.record(method, template, spec, options, true)
    }

    /// GET + WebSocket poll adapter at an exact path (MODULE-001-AC-33).
    pub fn poll_stream(&mut self, path: &str, spec: PollStreamSpec) -> Result<(), RouteRefusal> {
        if let Some(r) = self.book.extensions[self.index].refusal.clone() {
            return Err(r);
        }
        let ext = self.book.extensions[self.index].extension;
        let text = route_text(Method::Get, path);
        let fail =
            |this: &mut Self, reason: RouteRefusalReason| Err(this.refuse(text.clone(), reason));

        if let Err(d) = check_path_grammar(path, self.book.max_path_len) {
            return fail(self, RouteRefusalReason::InvalidPath(d));
        }
        if path.contains('{') {
            return fail(
                self,
                RouteRefusalReason::PollStream(PollStreamDefect::TemplatedPath),
            );
        }
        if first_segment_is_param(path) {
            return fail(self, RouteRefusalReason::ParameterisedFirstSegment);
        }
        if self.book.reserved_paths.contains(path) {
            return fail(self, RouteRefusalReason::ReservedPath);
        }
        let label = family_of(path);
        if self.book.check_reserved_labels && self.book.reserved_labels.contains(&label) {
            return fail(self, RouteRefusalReason::ReservedLabel { label });
        }
        if self.book.check_label_ownership {
            if let Some(owner) = self.book.label_owner.get(&label) {
                if *owner != ext {
                    return fail(
                        self,
                        RouteRefusalReason::LabelOwnedByOtherExtension {
                            label,
                            owner: *owner,
                        },
                    );
                }
            }
        }
        let shaped = shape(path);
        let key = (Method::Get, shaped.clone());
        if self.book.oss_shapes.contains(&key) {
            return fail(
                self,
                RouteRefusalReason::DuplicateRoute {
                    shape: shaped,
                    of: DuplicateOf::Oss,
                },
            );
        }
        if let Some(owner) = self.book.ext_shapes.get(&key) {
            return fail(
                self,
                RouteRefusalReason::DuplicateRoute {
                    shape: shaped,
                    of: DuplicateOf::Extension(*owner),
                },
            );
        }
        if !check_poll_pointer(spec.cursor) {
            return fail(
                self,
                RouteRefusalReason::PollStream(PollStreamDefect::InvalidCursorPointer),
            );
        }
        match spec.emit {
            PollEmit::NonEmptyArrayAt(pointer) if !check_poll_pointer(pointer) => {
                return fail(
                    self,
                    RouteRefusalReason::PollStream(PollStreamDefect::InvalidEmitPointer),
                );
            }
            PollEmit::NonEmptyArrayAt(_) => {}
        }
        if spec.handler.is_mutation || spec.handler.post_read {
            return fail(
                self,
                RouteRefusalReason::PollStream(PollStreamDefect::HandlerNotRead),
            );
        }
        if !spec.handler.requires_session {
            return fail(self, RouteRefusalReason::NoSession);
        }
        if spec.handler.required_scopes.is_empty() {
            return fail(self, RouteRefusalReason::NoScope);
        }

        self.book.label_owner.insert(label, ext);
        self.book.ext_shapes.insert(key, ext);
        self.book.extensions[self.index].routes.push(RecordedRoute {
            method: Method::Get,
            path: path.to_string(),
            templated: false,
            spec: spec.handler,
            options: RouteOptions::scanned(),
            poll_stream: true,
        });
        self.book.extensions[self.index]
            .poll_streams
            .push(PendingPollStream {
                path: path.to_string(),
                cursor: spec.cursor,
                emit: spec.emit,
            });
        Ok(())
    }

    /// At most once per extension; without it the effective default applies.
    pub fn set_budget(&mut self, budget: FamilyBudget) -> Result<(), RouteRefusal> {
        if let Some(r) = self.book.extensions[self.index].refusal.clone() {
            return Err(r);
        }
        if self.book.extensions[self.index].budget.is_some() {
            return Err(self.refuse("budget".into(), RouteRefusalReason::BudgetAlreadySet));
        }
        let max_d = u64::from(self.book.max_dispatch);
        let value_d = u64::from(budget.dispatch_permits);
        if budget.dispatch_permits < 1 || budget.dispatch_permits > self.book.max_dispatch {
            return Err(self.refuse(
                "budget".into(),
                RouteRefusalReason::InvalidBudget {
                    field: "dispatch_permits",
                    value: value_d,
                    max: max_d,
                },
            ));
        }
        let max_r = self.book.max_records as u64;
        let value_r = budget.idempotency_records as u64;
        if budget.idempotency_records < 1 || budget.idempotency_records > self.book.max_records {
            return Err(self.refuse(
                "budget".into(),
                RouteRefusalReason::InvalidBudget {
                    field: "idempotency_records",
                    value: value_r,
                    max: max_r,
                },
            ));
        }
        self.book.extensions[self.index].budget = Some(budget);
        Ok(())
    }

    fn refuse(&mut self, route: String, reason: RouteRefusalReason) -> RouteRefusal {
        let r = RouteRefusal {
            extension: self.book.extensions[self.index].extension,
            route,
            reason,
        };
        self.book.extensions[self.index].refusal = Some(r.clone());
        r
    }

    fn record(
        &mut self,
        method: Method,
        path: &str,
        spec: HandlerSpec,
        options: RouteOptions,
        templated: bool,
    ) -> Result<(), RouteRefusal> {
        if let Some(r) = self.book.extensions[self.index].refusal.clone() {
            return Err(r);
        }
        let ext = self.book.extensions[self.index].extension;
        let text = route_text(method, path);
        let fail =
            |this: &mut Self, reason: RouteRefusalReason| Err(this.refuse(text.clone(), reason));

        if let Err(d) = check_path_grammar(path, self.book.max_path_len) {
            return fail(self, RouteRefusalReason::InvalidPath(d));
        }
        if !templated && path.contains('{') {
            return fail(self, RouteRefusalReason::ParamInExactPath);
        }
        if first_segment_is_param(path) {
            return fail(self, RouteRefusalReason::ParameterisedFirstSegment);
        }
        if self.book.reserved_paths.contains(path) {
            return fail(self, RouteRefusalReason::ReservedPath);
        }
        let label = family_of(path);
        if self.book.check_reserved_labels && self.book.reserved_labels.contains(&label) {
            return fail(self, RouteRefusalReason::ReservedLabel { label });
        }
        if self.book.check_label_ownership {
            if let Some(owner) = self.book.label_owner.get(&label) {
                if *owner != ext {
                    return fail(
                        self,
                        RouteRefusalReason::LabelOwnedByOtherExtension {
                            label,
                            owner: *owner,
                        },
                    );
                }
            }
        }
        let shaped = shape(path);
        let key = (method, shaped.clone());
        if self.book.oss_shapes.contains(&key) {
            return fail(
                self,
                RouteRefusalReason::DuplicateRoute {
                    shape: shaped,
                    of: DuplicateOf::Oss,
                },
            );
        }
        if let Some(owner) = self.book.ext_shapes.get(&key) {
            return fail(
                self,
                RouteRefusalReason::DuplicateRoute {
                    shape: shaped,
                    of: DuplicateOf::Extension(*owner),
                },
            );
        }
        if spec.is_mutation && spec.post_read {
            return fail(self, RouteRefusalReason::MutationAndPostRead);
        }
        if method == Method::Post && !spec.is_mutation && !spec.post_read {
            return fail(self, RouteRefusalReason::PostNotMutationOrPostRead);
        }
        if method == Method::Get && spec.is_mutation {
            return fail(self, RouteRefusalReason::GetMutation);
        }
        if !spec.requires_session {
            return fail(self, RouteRefusalReason::NoSession);
        }
        if spec.required_scopes.is_empty() {
            return fail(self, RouteRefusalReason::NoScope);
        }
        if spec.is_mutation
            && !spec
                .required_scopes
                .iter()
                .any(|s| WRITE_CLASS_SCOPES.contains(s))
        {
            return fail(self, RouteRefusalReason::MutationWithoutWriteScope);
        }
        if let ResponseScan::OptOut { reason } = options.response_scan {
            let trimmed = reason.trim();
            if trimmed.is_empty() || trimmed.len() > 200 || trimmed.chars().any(|c| c.is_control())
            {
                return fail(self, RouteRefusalReason::ScanOptOutWithoutReason);
            }
        }

        self.book.label_owner.insert(label, ext);
        self.book.ext_shapes.insert(key, ext);
        self.book.extensions[self.index].routes.push(RecordedRoute {
            method,
            path: path.to_string(),
            templated,
            spec,
            options,
            poll_stream: false,
        });
        Ok(())
    }
}

/// Validated, wrapped, ready to install. `Send + 'static`.
pub struct ExtensionFamilies {
    exact: Vec<(Method, String, HandlerSpec)>,
    templated: Vec<(Method, String, HandlerSpec)>,
    budgets: Vec<Arc<ExtensionBudget>>,
    report: Vec<ExtensionRouteInfo>,
    scan_opt_outs: Vec<ExtensionRouteEvent>,
    poll_streams: HashMap<String, Arc<PollStreamEntry>>,
    gate: ExtensionRouteGate,
    hooks: Arc<dyn ExtensionRouteHooks>,
}

impl ExtensionFamilies {
    pub fn empty() -> Self {
        Self {
            exact: Vec::new(),
            templated: Vec::new(),
            budgets: Vec::new(),
            report: Vec::new(),
            scan_opt_outs: Vec::new(),
            poll_streams: HashMap::new(),
            gate: ExtensionRouteGate::new(),
            hooks: Arc::new(NoExtensionRouteHooks),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.templated.is_empty()
    }

    pub fn report(&self) -> &[ExtensionRouteInfo] {
        &self.report
    }

    /// Infallible. Called inside the bind factory between `compose_first_party_client` and `Arc::new(api)`.
    /// A no-op when empty.
    pub fn install(self, api: &mut ClientApi) {
        if self.is_empty() {
            return;
        }
        let mut budgets = HashMap::new();
        for b in &self.budgets {
            for label in &b.labels {
                budgets.insert(label.clone(), Arc::clone(b));
            }
        }
        for event in &self.scan_opt_outs {
            self.hooks.event(event);
        }
        api.install_extension_parts(InstalledExtensionParts {
            exact: self.exact,
            templated: self.templated,
            budgets,
            report: self.report,
            poll_streams: self.poll_streams,
            gate: self.gate,
        });
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn wrapped_spec(&self, method: Method, path: &str) -> Option<HandlerSpec> {
        self.exact
            .iter()
            .chain(self.templated.iter())
            .find(|(m, p, _)| *m == method && p == path)
            .map(|(_, _, spec)| spec.clone())
    }
}

/// Read-only record of one installed extension route (`ClientApi::extension_route_report`).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionRouteInfo {
    pub extension: &'static str,
    pub method: Method,
    pub path: String,
    pub templated: bool,
    pub response_scan: ResponseScan,
    pub poll_stream: bool,
}

/// Read-only budget state (`ClientApi::extension_budget_stats`).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionBudgetStats {
    pub extension: &'static str,
    pub labels: Vec<String>,
    pub dispatch_permits: u32,
    pub dispatch_available: usize,
    pub idempotency_cap: usize,
    pub idempotency_records: usize,
}

pub(crate) struct ExtensionBudget {
    pub(crate) extension: &'static str,
    pub(crate) labels: Vec<String>,
    pub(crate) dispatch: Arc<Semaphore>,
    pub(crate) dispatch_permits: u32,
    pub(crate) idempotency: IdempotencyStore,
}

pub(crate) struct InstalledExtensionParts {
    pub(crate) exact: Vec<(Method, String, HandlerSpec)>,
    pub(crate) templated: Vec<(Method, String, HandlerSpec)>,
    pub(crate) budgets: HashMap<String, Arc<ExtensionBudget>>,
    pub(crate) report: Vec<ExtensionRouteInfo>,
    pub(crate) poll_streams: HashMap<String, Arc<PollStreamEntry>>,
    pub(crate) gate: ExtensionRouteGate,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use crate::api::HandlerResponse;
    use crate::cursor::{
        AeadClientCursorCodec, MemoryCursorKeyCustody, OsCursorEntropy, SystemCursorClock,
    };
    use crate::provider::ProviderError;
    use crate::request::ClientRequest;
    use crate::routes::PATH_LOGIN;
    use crate::session::{ClientSession, Platform, Principal};
    use advance_shared_types::security_validator::{ScanContext, ScanResult};
    use serde_json::json;

    #[derive(Default)]
    struct RecordingHooks {
        events: Mutex<Vec<ExtensionRouteEvent>>,
    }

    impl ExtensionRouteHooks for RecordingHooks {
        fn event(&self, event: &ExtensionRouteEvent) {
            self.events.lock().expect("hooks").push(event.clone());
        }
    }

    struct StubDetector;

    impl LeakDetector for StubDetector {
        fn scan(&self, text: &str, _context: ScanContext) -> ScanResult {
            if text.contains("AKIA") || text.contains("BLOCK") {
                ScanResult::Blocked { findings: vec![] }
            } else if text.contains("Bearer ") || text.contains("REDACT") {
                ScanResult::Redacted {
                    redacted: "[REDACTED]".into(),
                    findings: vec![],
                }
            } else if text.contains("WARN") {
                ScanResult::Warned { findings: vec![] }
            } else {
                ScanResult::Clean
            }
        }
        fn scan_headers(&self, _headers: &[(String, String)]) -> ScanResult {
            ScanResult::Clean
        }
    }

    fn parts_and_hooks() -> (
        ExtensionServiceParts,
        Arc<RecordingHooks>,
        ExtensionRouteGate,
    ) {
        let hooks = Arc::new(RecordingHooks::default());
        let gate = ExtensionRouteGate::new();
        let parts = ExtensionServiceParts {
            leak_detector: Arc::new(StubDetector),
            clock: Arc::new(SystemClock),
            cursor_codec: Arc::new(AeadClientCursorCodec::new(
                Arc::new(MemoryCursorKeyCustody::new_for_tests()),
                Arc::new(SystemCursorClock),
                Arc::new(OsCursorEntropy),
                30,
            )),
        };
        (parts, hooks, gate)
    }

    fn book() -> (RouteBook, Arc<RecordingHooks>, ExtensionRouteGate) {
        let (parts, hooks, gate) = parts_and_hooks();
        let book = RouteBook::new(
            &ClientApiConfig::default(),
            parts,
            gate.clone(),
            Arc::clone(&hooks) as Arc<dyn ExtensionRouteHooks>,
        );
        (book, hooks, gate)
    }

    fn book_cfg(cfg: &ClientApiConfig) -> (RouteBook, Arc<RecordingHooks>, ExtensionRouteGate) {
        let (parts, hooks, gate) = parts_and_hooks();
        let book = RouteBook::new(
            cfg,
            parts,
            gate.clone(),
            Arc::clone(&hooks) as Arc<dyn ExtensionRouteHooks>,
        );
        (book, hooks, gate)
    }

    fn read_ok() -> HandlerSpec {
        HandlerSpec::read(true, |_| Ok(json!({ "ok": true })))
            .with_scopes(vec![Scope::ReadInventory])
    }

    fn mutation_ok() -> HandlerSpec {
        HandlerSpec::mutation(true, |_| Ok(json!({ "ok": true })))
            .with_scopes(vec![Scope::WriteEntities])
    }

    fn mint(api: &ClientApi, token: &str, scopes: Vec<Scope>, csrf: Option<&str>) {
        api.sessions().insert(
            token.to_string(),
            ClientSession {
                session_id: format!("sess-{token}"),
                principal: Principal::operator("operator"),
                platform: Platform::Mac,
                scopes,
                csrf_token: csrf.map(str::to_string),
                expires_at: u64::MAX,
            },
            0,
        );
    }

    #[test]
    fn module_001_ac31_reserved_floor_equals_oss_family_labels() {
        let mut from_oss: Vec<String> = oss_route_table()
            .into_iter()
            .map(|e| family_of(&e.path))
            .collect();
        from_oss.push(family_of(PATH_LOGIN));
        from_oss.sort();
        from_oss.dedup();
        let mut floor: Vec<&str> = RESERVED_FAMILY_FLOOR.to_vec();
        floor.sort();
        assert_eq!(floor.len(), 18);
        assert_eq!(
            floor,
            from_oss.iter().map(String::as_str).collect::<Vec<_>>()
        );
    }

    #[test]
    fn module_001_ac31_scratch_and_live_route_tables_match() {
        // The reserved floor comes from a default-config scratch `ClientApi`; the composition
        // builds the live one with allowed origins or in-process admission, and either value of
        // the deltas flag. The two tables must agree under each.
        let mut configs = Vec::new();
        let mut cfg = ClientApiConfig::default();
        cfg.allowed_origins = vec!["http://127.0.0.1:1".into()];
        configs.push(cfg);
        let mut cfg = ClientApiConfig::default();
        cfg.session_admission = crate::config::SessionAdmission::InProcessOnly;
        configs.push(cfg);
        for llm_deltas_enabled in [false, true] {
            let mut cfg = ClientApiConfig::default();
            cfg.llm_deltas_enabled = llm_deltas_enabled;
            configs.push(cfg);
        }
        for cfg in configs {
            let label = format!(
                "{:?}, origins {:?}, deltas {}",
                cfg.session_admission, cfg.allowed_origins, cfg.llm_deltas_enabled
            );
            let live =
                ClientApi::with_parts(cfg, "operator", Arc::new(SystemClock), Arc::new(NoopSink))
                    .route_table();
            assert_eq!(oss_route_table(), live, "{label}");
        }
    }

    #[test]
    fn module_001_ac31_canonical_path_grammar_table() {
        let max = 512;
        let accept = [
            "/client/x",
            "/client/x-y_1/{id}",
            "/client/x:verb",
            "/client/x/{id}:verb",
            "/client/x/y/{a}/{b}",
        ];
        for p in accept {
            assert_eq!(check_path_grammar(p, max), Ok(()), "accept {p}");
        }
        let refuse: &[(&str, PathDefect)] = &[
            ("/client", PathDefect::NotUnderClient),
            ("/client/", PathDefect::EmptySegment { index: 0 }),
            ("client/x", PathDefect::NotUnderClient),
            ("/clientx/y", PathDefect::NotUnderClient),
            ("/client/x/", PathDefect::EmptySegment { index: 1 }),
            ("/client/x//y", PathDefect::EmptySegment { index: 1 }),
            ("/client/./x", PathDefect::DotSegment { index: 0 }),
            ("/client/x/..", PathDefect::DotSegment { index: 1 }),
            ("/client/x/%41", PathDefect::PercentSegment { index: 1 }),
            ("/client/X", PathDefect::InvalidSegment { index: 0 }),
            ("/client/x.y", PathDefect::InvalidSegment { index: 0 }),
            ("/client/x/é", PathDefect::InvalidSegment { index: 1 }),
            ("/client/x:v/y", PathDefect::VerbNotFinal { index: 0 }),
            ("/client/x:V", PathDefect::InvalidVerb { index: 0 }),
            ("/client/x::v", PathDefect::InvalidVerb { index: 0 }),
            ("/client/x/{}", PathDefect::InvalidParamName { index: 1 }),
            ("/client/x/{Id}", PathDefect::InvalidParamName { index: 1 }),
            ("/client/x/{1a}", PathDefect::InvalidParamName { index: 1 }),
            ("/client/x/a{b}", PathDefect::InvalidParamName { index: 1 }),
            ("/client/x/{a}b", PathDefect::InvalidParamName { index: 1 }),
            (
                "/client/x/{a}/{a}",
                PathDefect::DuplicateParamName { name: "a".into() },
            ),
            ("/client/x/:v", PathDefect::InvalidSegment { index: 1 }),
        ];
        for (p, want) in refuse {
            assert_eq!(check_path_grammar(p, max), Err(want.clone()), "refuse {p}");
        }
        let long = format!("/client/{}", "a".repeat(505));
        assert_eq!(long.len(), 513);
        assert_eq!(
            check_path_grammar(&long, max),
            Err(PathDefect::TooLong { len: 513, max: 512 })
        );
    }

    #[test]
    fn module_001_ac31_refusal_reasons_in_check_order() {
        {
            let (mut book, _, _) = book();
            let mut r = book.registrar("ext");
            let err = r
                .route(Method::Get, "/client/runs/x", read_ok())
                .unwrap_err();
            assert!(
                matches!(err.reason, RouteRefusalReason::ReservedLabel { ref label } if label == "runs")
            );
        }
        {
            let (mut book, _, _) = book();
            let mut r = book.registrar("ext");
            let spec =
                HandlerSpec::read(false, |_| Ok(json!({}))).with_scopes(vec![Scope::ReadInventory]);
            let err = r.route(Method::Post, "/client/ext/x", spec).unwrap_err();
            assert_eq!(err.reason, RouteRefusalReason::PostNotMutationOrPostRead);
        }
        {
            let (mut book, _, _) = book();
            let mut r = book.registrar("ext");
            let err = r
                .route(Method::Get, "/client/events/stream", read_ok())
                .unwrap_err();
            assert_eq!(err.reason, RouteRefusalReason::ReservedPath);
        }
        {
            let (mut book, _, _) = book();
            let mut r = book.registrar("ext");
            let spec = HandlerSpec::read(false, |_| Ok(json!({})));
            let err = r.route(Method::Get, "/client/X", spec).unwrap_err();
            assert!(matches!(
                err.reason,
                RouteRefusalReason::InvalidPath(PathDefect::InvalidSegment { index: 0 })
            ));
        }
    }

    #[test]
    fn module_001_ac31_duplicate_shape_against_oss_isolated() {
        let (book, _, _) = book();
        let mut book = book.with_label_rules_for_test(false, true);
        let mut r = book.registrar("ext");
        let err = r
            .route_templated(Method::Post, "/client/runs/{x}:pause", mutation_ok())
            .unwrap_err();
        assert_eq!(
            err.reason,
            RouteRefusalReason::DuplicateRoute {
                shape: "/client/runs/{}:pause".into(),
                of: DuplicateOf::Oss,
            }
        );
    }

    #[test]
    fn module_001_ac31_duplicate_shape_against_other_extension_isolated() {
        let (book, _, _) = book();
        let mut book = book.with_label_rules_for_test(true, false);
        {
            let mut a = book.registrar("a-ext");
            a.route_templated(Method::Get, "/client/a/{id}", read_ok())
                .unwrap();
        }
        let mut b = book.registrar("b-ext");
        let err = b
            .route_templated(Method::Get, "/client/a/{name}", read_ok())
            .unwrap_err();
        assert_eq!(
            err.reason,
            RouteRefusalReason::DuplicateRoute {
                shape: "/client/a/{}".into(),
                of: DuplicateOf::Extension("a-ext"),
            }
        );
    }

    #[test]
    fn module_001_ac31_refused_route_does_not_claim_label() {
        let (mut book, _, _) = book();
        {
            let mut a = book.registrar("a-ext");
            let spec = HandlerSpec::read(true, |_| Ok(json!({})));
            let err = a.route(Method::Get, "/client/foo/x", spec).unwrap_err();
            assert_eq!(err.reason, RouteRefusalReason::NoScope);
        }
        let mut b = book.registrar("b-ext");
        b.route(Method::Get, "/client/foo/y", read_ok()).unwrap();
    }

    #[test]
    fn module_001_ac31_registrar_sticky_after_first_refusal() {
        let (mut book, _, _) = book();
        let mut r = book.registrar("ext");
        let first = r
            .route(Method::Get, "/client/runs/x", read_ok())
            .unwrap_err();
        let second = r
            .route(Method::Get, "/client/ext/ok", read_ok())
            .unwrap_err();
        assert_eq!(first, second);
    }

    #[test]
    fn module_001_ac31_budget_bounds() {
        {
            let (mut book, _, _) = book();
            let mut r = book.registrar("ext");
            let err = r.set_budget(FamilyBudget::new(0, 4)).unwrap_err();
            assert_eq!(
                err.reason,
                RouteRefusalReason::InvalidBudget {
                    field: "dispatch_permits",
                    value: 0,
                    max: 64,
                }
            );
        }
        {
            let (mut book, _, _) = book();
            let mut r = book.registrar("ext");
            r.set_budget(FamilyBudget::new(1, 1)).unwrap();
            let err = r.set_budget(FamilyBudget::new(1, 1)).unwrap_err();
            assert_eq!(err.reason, RouteRefusalReason::BudgetAlreadySet);
        }
        {
            let (mut book, _, _) = book();
            let mut r = book.registrar("ext");
            let err = r.set_budget(FamilyBudget::new(1, 0)).unwrap_err();
            assert_eq!(
                err.reason,
                RouteRefusalReason::InvalidBudget {
                    field: "idempotency_records",
                    value: 0,
                    max: 10_000,
                }
            );
        }
    }

    #[test]
    fn module_001_ac31_registrar_reopen_returns_same_record() {
        let (mut book, _, _) = book();
        {
            let mut r = book.registrar("a-ext");
            r.route(Method::Get, "/client/a/status", read_ok()).unwrap();
        }
        {
            let mut r = book.registrar("a-ext");
            let err = r
                .route(Method::Get, "/client/a/status", read_ok())
                .unwrap_err();
            assert!(matches!(
                err.reason,
                RouteRefusalReason::DuplicateRoute { .. }
            ));
        }
        assert!(book.refusal("a-ext").is_some());
    }

    #[test]
    fn module_001_ac31_write_scope_rule_accepts_operator_default() {
        let (mut book, _, _) = book();
        let mut r = book.registrar("ext");
        let spec =
            HandlerSpec::mutation(true, |_| Ok(json!({}))).with_scopes(Scope::operator_default());
        r.route(Method::Post, "/client/ext/x", spec).unwrap();
    }

    #[test]
    fn module_001_ac31_refusal_display_forms() {
        let route = RouteRefusal {
            extension: "e",
            route: "GET /client/x".into(),
            reason: RouteRefusalReason::NoScope,
        };
        assert_eq!(
            route.to_string(),
            "extension e: route GET /client/x refused: the route must require at least one scope"
        );
        let budget = RouteRefusal {
            extension: "e",
            route: "budget".into(),
            reason: RouteRefusalReason::BudgetAlreadySet,
        };
        assert_eq!(
            budget.to_string(),
            "extension e: family budget refused: the family budget is already set"
        );
    }

    #[test]
    fn module_001_ac31_default_budget_clamped_to_config() {
        {
            let mut cfg = ClientApiConfig::default();
            cfg.max_concurrent_dispatch = 1;
            cfg.idempotency_store_cap = 10;
            let (mut book, _, _) = book_cfg(&cfg);
            {
                let mut r = book.registrar("ext");
                r.route(Method::Get, "/client/ext/status", read_ok())
                    .unwrap();
            }
            let families = book.finish().unwrap();
            let mut api =
                ClientApi::with_parts(cfg, "operator", Arc::new(SystemClock), Arc::new(NoopSink));
            families.install(&mut api);
            let stats = api.extension_budget_stats();
            assert_eq!(stats[0].dispatch_permits, 1);
            assert_eq!(stats[0].idempotency_cap, 10);
        }

        {
            let (mut book, _, _) = book();
            {
                let mut r = book.registrar("ext");
                r.route(Method::Get, "/client/ext/status", read_ok())
                    .unwrap();
            }
            let families = book.finish().unwrap();
            let mut api = ClientApi::with_parts(
                ClientApiConfig::default(),
                "operator",
                Arc::new(SystemClock),
                Arc::new(NoopSink),
            );
            families.install(&mut api);
            let stats = api.extension_budget_stats();
            assert_eq!(stats[0].dispatch_permits, 16);
            assert_eq!(stats[0].idempotency_cap, 1_000);
        }
    }

    #[test]
    fn module_001_ac31_fixed_error_message_covers_every_known_code() {
        for code_str in ClientErrorCode::known_codes() {
            let code: ClientErrorCode = serde_json::from_value(json!(code_str)).unwrap();
            assert!(
                !fixed_error_message(&code).is_empty(),
                "empty text for {code_str}"
            );
        }
        let variants = [
            ProviderError::NotFound("x".into()),
            ProviderError::NotAuthorized("x".into()),
            ProviderError::InvalidState("x".into()),
            ProviderError::Forbidden("x".into()),
            ProviderError::TooLarge("x".into()),
            ProviderError::Unavailable("x".into()),
            ProviderError::AlreadyExists("x".into()),
            ProviderError::InvalidRequest("x".into()),
            ProviderError::UnknownProvider("x".into()),
            ProviderError::PlatformUnsupported("x".into()),
            ProviderError::AuthSourceMismatch("x".into()),
        ];
        for v in variants {
            let e = v.into_client_error();
            assert_eq!(e.message, fixed_error_message(&e.code));
        }
    }

    #[test]
    fn module_001_ac31_handler_errors_get_fixed_text_and_token_details() {
        let (mut book, hooks, _) = book();
        {
            let mut r = book.registrar("ext");
            let spec = HandlerSpec::read(true, |_| {
                let mut details = Vec::new();
                for i in 0..10 {
                    details.push(format!("tok{i}"));
                    if i == 0 || i == 1 {
                        details.push("Bad Token".into());
                    }
                }
                Err(ClientError::new(ClientErrorCode::NotFound, "secret 42").with_details(details))
            })
            .with_scopes(vec![Scope::ReadInventory]);
            r.route(Method::Get, "/client/ext/err", spec).unwrap();
            r.route(
                Method::Get,
                "/client/ext/unknown",
                HandlerSpec::read(true, |_| {
                    Err(ClientError::new(ClientErrorCode::Unknown, "nope"))
                })
                .with_scopes(vec![Scope::ReadInventory]),
            )
            .unwrap();
        }
        let families = book.finish().unwrap();
        let mut api = ClientApi::with_parts(
            ClientApiConfig::default(),
            "operator",
            Arc::new(SystemClock),
            Arc::new(NoopSink),
        );
        families.install(&mut api);
        mint(&api, "tok", vec![Scope::ReadInventory], None);
        let env = api.handle(ClientRequest::get("/client/ext/err").with_session("tok"));
        let err = env.error.unwrap();
        assert_eq!(err.code, ClientErrorCode::NotFound);
        assert_eq!(err.message, "resource not found");
        assert_eq!(
            err.details,
            vec!["tok0", "tok1", "tok2", "tok3", "tok4", "tok5", "tok6", "tok7"]
        );
        let dropped = hooks
            .events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                ExtensionRouteEvent::DetailsDropped { count, .. } => Some(*count),
                _ => None,
            })
            .sum::<usize>();
        assert_eq!(dropped, 4);

        let env = api.handle(ClientRequest::get("/client/ext/unknown").with_session("tok"));
        let err = env.error.unwrap();
        assert_eq!(err.code, ClientErrorCode::ModuleUnavailable);
        assert_eq!(err.message, "provider unavailable");
        assert!(hooks.events.lock().unwrap().iter().any(|e| matches!(
            e,
            ExtensionRouteEvent::UnknownCodeRemapped {
                route,
                ..
            } if route == "/client/ext/unknown"
        )));
    }

    #[test]
    fn module_001_ac31_success_scan_walks_every_string_leaf() {
        let (mut book, _, _) = book();
        {
            let mut r = book.registrar("ext");
            r.route(
                Method::Get,
                "/client/ext/nested",
                HandlerSpec::read(true, |_| {
                    Ok(json!({
                        "a~b": { "k/h": ["ok", "REDACT"] },
                        "deep": { "x": { "y": "BLOCK" } }
                    }))
                })
                .with_scopes(vec![Scope::ReadInventory]),
            )
            .unwrap();
            r.route(
                Method::Get,
                "/client/ext/top",
                HandlerSpec::read(true, |_| Ok(json!("hello")))
                    .with_scopes(vec![Scope::ReadInventory]),
            )
            .unwrap();
            r.route_with(
                Method::Get,
                "/client/ext/raw",
                HandlerSpec::read(true, |_| Ok(json!({ "note": "BLOCK" })))
                    .with_scopes(vec![Scope::ReadInventory]),
                RouteOptions::skip_response_scan("fixture: skip"),
            )
            .unwrap();
        }
        let families = book.finish().unwrap();
        let mut api = ClientApi::with_parts(
            ClientApiConfig::default(),
            "operator",
            Arc::new(SystemClock),
            Arc::new(NoopSink),
        );
        families.install(&mut api);
        mint(&api, "tok", vec![Scope::ReadInventory], None);

        let env = api.handle(ClientRequest::get("/client/ext/nested").with_session("tok"));
        assert_eq!(env.error.unwrap().code, ClientErrorCode::ProjectionRejected);

        let env = api.handle(ClientRequest::get("/client/ext/top").with_session("tok"));
        assert_eq!(env.data.unwrap(), json!("hello"));

        let env = api.handle(ClientRequest::get("/client/ext/raw").with_session("tok"));
        assert_eq!(env.data.unwrap()["note"], json!("BLOCK"));
    }

    #[test]
    fn module_001_ac31_success_scan_caps_a_long_multibyte_pointer_at_a_char_boundary() {
        // `/a` then two-byte characters: the cut for the ellipsis (byte 253) falls inside one.
        let key = format!("a{}", "é".repeat(200));
        let pointer = format!("/{key}");
        let cut = POINTER_FIELD_MAX - "…".len();
        assert!(pointer.len() > POINTER_FIELD_MAX && !pointer.is_char_boundary(cut));
        let capped = cap_pointer(&pointer);
        assert!(capped.len() <= POINTER_FIELD_MAX, "{} bytes", capped.len());
        let kept = capped.strip_suffix('…').expect("ellipsis");
        assert_eq!(kept.len(), cut - 1);
        assert!(pointer.starts_with(kept));
        assert_eq!(cap_pointer("/short"), "/short");

        let (mut book, hooks, _) = book();
        {
            let mut r = book.registrar("ext");
            let body = json!({ key.clone(): "REDACT" });
            r.route(
                Method::Get,
                "/client/ext/long",
                HandlerSpec::read(true, move |_| Ok(body.clone()))
                    .with_scopes(vec![Scope::ReadInventory]),
            )
            .unwrap();
        }
        let families = book.finish().unwrap();
        let mut api = ClientApi::with_parts(
            ClientApiConfig::default(),
            "operator",
            Arc::new(SystemClock),
            Arc::new(NoopSink),
        );
        families.install(&mut api);
        mint(&api, "tok", vec![Scope::ReadInventory], None);
        let env = api.handle(ClientRequest::get("/client/ext/long").with_session("tok"));
        assert!(env.error.is_none(), "{:?}", env.error);
        assert_eq!(
            env.data.as_ref().unwrap()[key.as_str()],
            json!("[REDACTED]")
        );
        let warning = env
            .warnings
            .iter()
            .find(|w| w.code == "sensitive_value_redacted")
            .expect("redaction warning");
        assert_eq!(
            warning.message,
            format!("sensitive value redacted at {capped}")
        );
        assert!(hooks.events.lock().unwrap().is_empty());
    }

    #[test]
    fn module_001_ac31_extension_warnings_filtered() {
        let (mut book, hooks, _) = book();
        {
            let mut r = book.registrar("ext");
            r.route(
                Method::Get,
                "/client/ext/w",
                HandlerSpec::read_with_warnings(true, |_| {
                    Ok(HandlerResponse::with_warnings(
                        json!({ "ok": true }),
                        vec![
                            ClientWarning::new("ok_token", "fine"),
                            ClientWarning::new("Bad Code", "nope"),
                            ClientWarning::new("blocked_msg", "AKIASECRET"),
                        ],
                    ))
                })
                .with_scopes(vec![Scope::ReadInventory]),
            )
            .unwrap();
        }
        let families = book.finish().unwrap();
        let mut api = ClientApi::with_parts(
            ClientApiConfig::default(),
            "operator",
            Arc::new(SystemClock),
            Arc::new(NoopSink),
        );
        families.install(&mut api);
        mint(&api, "tok", vec![Scope::ReadInventory], None);
        let env = api.handle(ClientRequest::get("/client/ext/w").with_session("tok"));
        assert!(env.is_ok());
        assert!(env.warnings.iter().any(|w| w.code == "ok_token"));
        assert!(!env.warnings.iter().any(|w| w.code == "Bad Code"));
        assert!(!env.warnings.iter().any(|w| w.code == "blocked_msg"));
        assert!(hooks
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, ExtensionRouteEvent::WarningsDropped { count: 2, .. })));
    }

    #[test]
    fn module_001_ac31_templated_extension_routes_install_most_specific_first() {
        let (mut book, _, _) = book();
        {
            let mut r = book.registrar("ext");
            r.route_templated(
                Method::Get,
                "/client/ext/{id}",
                HandlerSpec::read(true, |_| Ok(json!({ "kind": "plain" })))
                    .with_scopes(vec![Scope::ReadInventory]),
            )
            .unwrap();
            r.route_templated(
                Method::Get,
                "/client/ext/{id}:pause",
                HandlerSpec::read(true, |_| Ok(json!({ "kind": "pause" })))
                    .with_scopes(vec![Scope::ReadInventory]),
            )
            .unwrap();
        }
        let families = book.finish().unwrap();
        let mut api = ClientApi::with_parts(
            ClientApiConfig::default(),
            "operator",
            Arc::new(SystemClock),
            Arc::new(NoopSink),
        );
        families.install(&mut api);
        mint(&api, "tok", vec![Scope::ReadInventory], None);
        let env = api.handle(ClientRequest::get("/client/ext/abc:pause").with_session("tok"));
        assert_eq!(env.data.unwrap()["kind"], json!("pause"));
        let env = api.handle(ClientRequest::get("/client/ext/abc").with_session("tok"));
        assert_eq!(env.data.unwrap()["kind"], json!("plain"));
    }

    #[test]
    fn module_001_ac31_route_gate_close_is_idempotent_and_shared() {
        let gate = ExtensionRouteGate::new();
        let clone = gate.clone();
        assert!(!gate.is_closed());
        gate.close();
        assert!(clone.is_closed());
        gate.close();
        assert!(gate.is_closed());
        assert!(!ExtensionRouteGate::new().is_closed());
    }
}

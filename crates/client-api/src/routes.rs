//! CONTRACT-190 — the in-scope route table.
//!
//! The foundation slice serves the session family (login/refresh/logout) + `/client/health` as
//! LIVE handlers. Provider-backed families (runs/messages/tools/events/grants/history) are all
//! routed here; only `devices` is not routed — an unrecognized path resolves to `unknown_route`
//! with no provider call.

use crate::request::Method;

pub const PATH_LOGIN: &str = "/client/session/login";
pub const PATH_REFRESH: &str = "/client/session/refresh";
pub const PATH_LOGOUT: &str = "/client/session/logout";
pub const PATH_HEALTH: &str = "/client/health";

/// A session-family operation (handled specially — these establish/mutate the session itself).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionOp {
    Login,
    Refresh,
    Logout,
}

/// Classify a request as a session-family op, if it is one.
pub fn session_op(method: Method, path: &str) -> Option<SessionOp> {
    match (method, path) {
        (Method::Post, PATH_LOGIN) => Some(SessionOp::Login),
        (Method::Post, PATH_REFRESH) => Some(SessionOp::Refresh),
        (Method::Post, PATH_LOGOUT) => Some(SessionOp::Logout),
        _ => None,
    }
}

/// The resource family for a path (used for idempotency scoping + audit labels). Returns the
/// first segment after `/client/` (e.g. `session`, `health`, `runs`). Works for templated paths too
/// (`/client/runs/{id}:pause` → `runs`), so mutation idempotency scoping is unaffected.
pub fn family_of(path: &str) -> String {
    let trimmed = path.strip_prefix("/client/").unwrap_or(path);
    let seg = trimmed.split('/').next().unwrap_or("");
    if seg.is_empty() {
        "root".to_string()
    } else {
        seg.to_string()
    }
}

// ── m020-s2 provider-family paths ─────────────────────────────────────────────────────────────

/// Exact (non-templated) provider-family paths.
pub const PATH_RUNS: &str = "/client/runs";
pub const PATH_RUNS_TREE: &str = "/client/runs/tree";
pub const PATH_MESSAGES: &str = "/client/messages";
pub const PATH_TOOLS: &str = "/client/tools";
/// m020-s3 CONTRACT-191 historical query (GET, body/null DTO).
pub const PATH_EVENTS: &str = "/client/events";
/// m020-s3 CONTRACT-191 stream poll facade (GET, body/null DTO).
pub const PATH_EVENTS_STREAM: &str = "/client/events/stream";
pub const PATH_GRANTS_PENDING: &str = "/client/grants/pending";
/// Tee T2 (CONTRACT-235) LLM token-delta WebSocket subscription route.
pub const PATH_LLM_DELTAS_STREAM: &str = "/client/llm/deltas/stream";
/// Templated provider-family route patterns (see [`RoutePattern`]).
pub const TPL_RUN_PAUSE: &str = "/client/runs/{run_id}:pause";
pub const TPL_RUN_RESUME: &str = "/client/runs/{run_id}:resume";
pub const TPL_RUN_CANCEL: &str = "/client/runs/{run_id}:cancel";
pub const TPL_MESSAGE_GET: &str = "/client/messages/{message_id}";
pub const TPL_GRANT_APPROVE: &str = "/client/grants/pending/{request_id}:approve";
pub const TPL_GRANT_DENY: &str = "/client/grants/pending/{request_id}:deny";
pub const TPL_GRANT_NARROW: &str = "/client/grants/pending/{request_id}:narrow";
pub const TPL_GRANT_REVOKE: &str = "/client/grants/{grant_id}:revoke";
pub const TPL_PRESET_APPLY: &str = "/client/presets/{preset}:apply";
pub const TPL_TASK_HISTORY: &str = "/client/tasks/{task_id}/history";
pub const TPL_RUN_HISTORY: &str = "/client/runs/{run_id}/history";
/// One segment of a templated route.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seg {
    /// A fixed segment (e.g. `client`, `runs`).
    Literal(String),
    /// `{name}` — matches any non-empty segment, binding `name`.
    Param(String),
    /// `{name}:suffix` — matches `value:suffix` (value non-empty), binding `name` = value.
    ParamSuffix { name: String, suffix: String },
}

/// A templated route pattern (e.g. `/client/runs/{run_id}:pause`, `/client/messages/{message_id}`).
///
/// Matched ONLY after an exact-path miss (see `ClientApi::handle`), so the FROZEN s1 gate order is
/// preserved and s3/s4 can register more templated families the same way. The matcher is
/// segment-structural (no regex), so an over-long path is already bounded by the pre-routing
/// `max_path_len` gate.
#[derive(Debug, Clone)]
pub struct RoutePattern {
    segs: Vec<Seg>,
}

impl RoutePattern {
    /// Parse a template. Per segment: `{name}` → [`Seg::Param`]; `{name}:suffix` →
    /// [`Seg::ParamSuffix`]; anything else → [`Seg::Literal`]. The FULL string is split (no leading-
    /// slash trimming), so the leading empty segment becomes a `Literal("")` a request path must also
    /// carry — i.e. only the canonical `/client/...` form matches (a non-canonical `//client/...` or
    /// slashless `client/...` path does NOT match, so it can never route under a mismatched
    /// idempotency/audit family).
    pub fn parse(template: &str) -> RoutePattern {
        let segs = template
            .split('/')
            .map(|s| {
                if let Some(rest) = s.strip_prefix('{') {
                    if let Some(close) = rest.find('}') {
                        let name = rest[..close].to_string();
                        let after = &rest[close + 1..];
                        return if after.is_empty() {
                            Seg::Param(name)
                        } else {
                            Seg::ParamSuffix {
                                name,
                                suffix: after.to_string(),
                            }
                        };
                    }
                }
                Seg::Literal(s.to_string())
            })
            .collect();
        RoutePattern { segs }
    }

    /// Match a concrete path, returning the bound `(name, value)` params (in template order) on
    /// success. The FULL path is split (no leading-slash trimming — see [`parse`](RoutePattern::parse)),
    /// so only the canonical `/client/...` form matches. Segment count must match exactly; every
    /// param binds a non-empty value.
    pub fn matches(&self, path: &str) -> Option<Vec<(String, String)>> {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() != self.segs.len() {
            return None;
        }
        let mut params = Vec::new();
        for (seg, part) in self.segs.iter().zip(parts.iter()) {
            match seg {
                Seg::Literal(l) => {
                    if l != part {
                        return None;
                    }
                }
                Seg::Param(name) => {
                    if part.is_empty() {
                        return None;
                    }
                    params.push((name.clone(), (*part).to_string()));
                }
                Seg::ParamSuffix { name, suffix } => {
                    let val = part.strip_suffix(suffix.as_str())?;
                    if val.is_empty() {
                        return None;
                    }
                    params.push((name.clone(), val.to_string()));
                }
            }
        }
        Some(params)
    }
}

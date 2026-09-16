//! CONTRACT-190 costs family — the operator-facing LLM spend attribution surface
//! (lane cost-attribution, 2026-09-16).
//!
//! Routes (family `costs`, all reads on `Scope::ReadRuns`, GET with a body/null DTO like the
//! events family):
//! - `GET /client/costs/agents`                    per-agent totals
//! - `GET /client/costs/agents/{agent_id}`         one agent: total + split by provider
//! - `GET /client/costs/providers`                 per-provider totals
//! - `GET /client/costs/providers/{provider_id}`   one provider: total + split by agent
//!
//! The authoritative numbers live in the runtime (MODULE-019's durable ledger over the persisted
//! `llm.response` rows): only the runtime sees provider responses and owns the attribution rule
//! (a call is billed to the agent whose turn made it, and to the resolved provider id). This
//! family PROJECTS that ledger; it never recomputes cost from rates.
//!
//! Every request is validated HERE before the provider is consulted: id charset, RFC 3339 window
//! bounds, `since <= until`. An unknown agent/provider id is NOT an error — the ledger does not
//! know the agent tree, so it answers the zero aggregate (clients that need existence use
//! `/client/agents/{id}`).

use chrono::{DateTime, SecondsFormat, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::agents::validate_agent_id;
use crate::api::{ClientApi, HandlerSpec};
use crate::envelope::{ClientError, ClientErrorCode};
use crate::provider::{provider_or_unavailable, CostProviderSlot, ProviderError};
use crate::request::Method;
use crate::routes;
use crate::session::Scope;

/// Provider id bound: `^[A-Za-z0-9_.:-]{1,64}$` (config `llm-providers[].id` values are
/// kebab/dotted identifiers such as `anthropic`, `openai-compatible`, `local.ollama`).
pub const MAX_PROVIDER_ID_LEN: usize = 64;
/// Bound on a window bound string (an RFC 3339 timestamp is ~20–35 chars).
pub const MAX_TIMESTAMP_LEN: usize = 64;

// ── DTOs (CONTRACT-192 schema components) ────────────────────────────────────────────────────

/// The optional body of every costs-family GET: a half-open window `[since, until)`. A `null`
/// body means all retained history. Bounds are honoured at second granularity (floored /
/// ceiled), so a window can only include MORE rows than requested, never fewer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientCostQuery {
    /// RFC 3339 inclusive lower bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    /// RFC 3339 exclusive upper bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
}

/// The window a response was computed over (normalized RFC 3339 UTC, `null` = unbounded).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientCostWindow {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
}

/// Aggregate spend. Mirrors the runtime `RunCost` shape.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ClientCostTotals {
    /// Raw input tokens (pre-cache).
    pub tokens_in: u64,
    pub tokens_out: u64,
    /// USD at the provider rates configured in the runtime.
    pub cost_usd: f64,
    /// Number of `llm.response` events folded in.
    pub request_count: u32,
}

/// One agent's totals (`GET /client/costs/agents`, and the `by_agent` split of a provider).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ClientAgentCostEntry {
    pub agent_id: String,
    pub totals: ClientCostTotals,
}

/// One provider's totals (`GET /client/costs/providers`, and the `by_provider` split of an
/// agent). `provider_id` is `unknown` for calls recorded before the runtime carried it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ClientProviderCostEntry {
    pub provider_id: String,
    pub totals: ClientCostTotals,
}

/// `GET /client/costs/agents/{agent_id}`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ClientAgentCostReport {
    pub agent_id: String,
    pub totals: ClientCostTotals,
    /// Ordered by `cost_usd` descending, then provider id.
    pub by_provider: Vec<ClientProviderCostEntry>,
    pub window: ClientCostWindow,
}

/// `GET /client/costs/providers/{provider_id}`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ClientProviderCostReport {
    pub provider_id: String,
    pub totals: ClientCostTotals,
    /// Ordered by `cost_usd` descending, then agent id.
    pub by_agent: Vec<ClientAgentCostEntry>,
    pub window: ClientCostWindow,
}

/// `GET /client/costs/agents`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ClientAgentCostList {
    /// Ordered by `cost_usd` descending, then agent id.
    pub agents: Vec<ClientAgentCostEntry>,
    pub window: ClientCostWindow,
}

/// `GET /client/costs/providers`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ClientProviderCostList {
    /// Ordered by `cost_usd` descending, then provider id.
    pub providers: Vec<ClientProviderCostEntry>,
    pub window: ClientCostWindow,
}

// ── Validation ───────────────────────────────────────────────────────────────────────────────

fn invalid(message: &'static str) -> ClientError {
    ClientError::new(ClientErrorCode::InvalidRequest, message)
}

/// `^[A-Za-z0-9_.:-]{1,64}$`.
pub fn validate_provider_id(id: &str) -> Result<(), ClientError> {
    if id.is_empty()
        || id.len() > MAX_PROVIDER_ID_LEN
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
    {
        return Err(invalid("invalid provider id"));
    }
    Ok(())
}

fn parse_bound(raw: &str, which: &'static str) -> Result<DateTime<Utc>, ClientError> {
    if raw.len() > MAX_TIMESTAMP_LEN {
        return Err(invalid(which));
    }
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| invalid(which))
}

/// A validated, normalized window (UTC). Produced from [`ClientCostQuery`]; passed to the
/// provider so adapters never re-parse client strings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ValidatedCostWindow {
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
}

impl ValidatedCostWindow {
    /// The client-facing echo of the window (RFC 3339 UTC, second precision).
    pub fn to_client(&self) -> ClientCostWindow {
        let fmt = |dt: DateTime<Utc>| dt.to_rfc3339_opts(SecondsFormat::Secs, true);
        ClientCostWindow {
            since: self.since.map(fmt),
            until: self.until.map(fmt),
        }
    }
}

/// Parse + validate the window body: each bound RFC 3339 and bounded, `since <= until`.
pub fn validate_cost_query(query: &ClientCostQuery) -> Result<ValidatedCostWindow, ClientError> {
    let since = query
        .since
        .as_deref()
        .map(|s| parse_bound(s, "invalid since bound"))
        .transpose()?;
    let until = query
        .until
        .as_deref()
        .map(|s| parse_bound(s, "invalid until bound"))
        .transpose()?;
    if let (Some(s), Some(u)) = (since, until) {
        if s > u {
            return Err(invalid("since must not be after until"));
        }
    }
    Ok(ValidatedCostWindow { since, until })
}

fn parse_query(body: &Value) -> Result<ValidatedCostWindow, ClientError> {
    if body.is_null() {
        return Ok(ValidatedCostWindow::default());
    }
    // serde accepts a positional sequence for a struct (`[]` → all defaults); only an object is
    // a well-formed window body.
    if !body.is_object() {
        return Err(invalid("invalid cost query body"));
    }
    let query: ClientCostQuery =
        serde_json::from_value(body.clone()).map_err(|_| invalid("invalid cost query body"))?;
    validate_cost_query(&query)
}

// ── Handlers ─────────────────────────────────────────────────────────────────────────────────

/// Register the costs routes, capturing the shared provider slot so a builder can inject the
/// concrete provider AFTER registration. Routes are always registered; an absent provider yields
/// `module_unavailable` (never `unknown_route`).
pub(crate) fn register(api: &mut ClientApi, slot: CostProviderSlot) {
    // GET /client/costs/agents — per-agent totals.
    let s = slot.clone();
    api.register(
        Method::Get,
        routes::PATH_COSTS_AGENTS,
        HandlerSpec::read(true, move |ctx| {
            let window = parse_query(&ctx.body)?;
            let provider = provider_or_unavailable(&s)?;
            let agents = provider
                .agent_totals(&window)
                .map_err(ProviderError::into_client_error)?;
            let list = ClientAgentCostList {
                agents,
                window: window.to_client(),
            };
            Ok(serde_json::to_value(list).expect("ClientAgentCostList serializes"))
        })
        .with_scopes(vec![Scope::ReadRuns]),
    );

    // GET /client/costs/providers — per-provider totals.
    let s = slot.clone();
    api.register(
        Method::Get,
        routes::PATH_COSTS_PROVIDERS,
        HandlerSpec::read(true, move |ctx| {
            let window = parse_query(&ctx.body)?;
            let provider = provider_or_unavailable(&s)?;
            let providers = provider
                .provider_totals(&window)
                .map_err(ProviderError::into_client_error)?;
            let list = ClientProviderCostList {
                providers,
                window: window.to_client(),
            };
            Ok(serde_json::to_value(list).expect("ClientProviderCostList serializes"))
        })
        .with_scopes(vec![Scope::ReadRuns]),
    );

    // GET /client/costs/agents/{agent_id} — one agent + split by provider.
    let s = slot.clone();
    api.register_templated(
        Method::Get,
        routes::TPL_COSTS_AGENT_GET,
        HandlerSpec::read(true, move |ctx| {
            let agent_id = ctx.path_param("agent_id")?;
            validate_agent_id(&agent_id)?;
            let window = parse_query(&ctx.body)?;
            let provider = provider_or_unavailable(&s)?;
            let report = provider
                .agent_report(&agent_id, &window)
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(report).expect("ClientAgentCostReport serializes"))
        })
        .with_scopes(vec![Scope::ReadRuns]),
    );

    // GET /client/costs/providers/{provider_id} — one provider + split by agent.
    let s = slot;
    api.register_templated(
        Method::Get,
        routes::TPL_COSTS_PROVIDER_GET,
        HandlerSpec::read(true, move |ctx| {
            let provider_id = ctx.path_param("provider_id")?;
            validate_provider_id(&provider_id)?;
            let window = parse_query(&ctx.body)?;
            let provider = provider_or_unavailable(&s)?;
            let report = provider
                .provider_report(&provider_id, &window)
                .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(report).expect("ClientProviderCostReport serializes"))
        })
        .with_scopes(vec![Scope::ReadRuns]),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_id_charset() {
        for ok in [
            "anthropic",
            "openai-compatible",
            "local.ollama",
            "mesh:node-1",
            "p_1",
        ] {
            assert!(validate_provider_id(ok).is_ok(), "{ok:?}");
        }
        for bad in ["", " ", "a b", "a/b", "ü", "a\0"] {
            assert!(validate_provider_id(bad).is_err(), "{bad:?}");
        }
        assert!(validate_provider_id(&"x".repeat(64)).is_ok());
        assert!(validate_provider_id(&"x".repeat(65)).is_err());
    }

    #[test]
    fn window_parses_and_orders() {
        let q = ClientCostQuery {
            since: Some("2026-09-01T00:00:00Z".into()),
            until: Some("2026-10-01T00:00:00+02:00".into()),
        };
        let w = validate_cost_query(&q).unwrap();
        assert_eq!(
            w.to_client(),
            ClientCostWindow {
                since: Some("2026-09-01T00:00:00Z".into()),
                until: Some("2026-09-30T22:00:00Z".into()),
            }
        );
        let flipped = ClientCostQuery {
            since: q.until.clone(),
            until: q.since.clone(),
        };
        assert_eq!(
            validate_cost_query(&flipped).unwrap_err().code,
            ClientErrorCode::InvalidRequest
        );
        for bad in ["2026-09-01", "yesterday", "", "2026-09-01T00:00:00"] {
            let q = ClientCostQuery {
                since: Some(bad.into()),
                until: None,
            };
            assert!(validate_cost_query(&q).is_err(), "{bad:?}");
        }
        let long = ClientCostQuery {
            since: Some("2".repeat(MAX_TIMESTAMP_LEN + 1)),
            until: None,
        };
        assert!(validate_cost_query(&long).is_err());
        assert_eq!(
            validate_cost_query(&ClientCostQuery::default()).unwrap(),
            ValidatedCostWindow::default()
        );
    }

    #[test]
    fn query_body_rejects_unknown_fields() {
        let body = serde_json::json!({ "since": "2026-09-01T00:00:00Z", "extra": 1 });
        assert!(parse_query(&body).is_err());
        assert!(parse_query(&Value::Null).is_ok());
        assert!(parse_query(&serde_json::json!([])).is_err());
        assert!(parse_query(&serde_json::json!({})).is_ok());
    }
}

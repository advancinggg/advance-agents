//! CONTRACT-190 run-control family (m020-s2, AC-07).
//!
//! `GET /client/runs` (list), `GET /client/runs/tree` (read-only agent-tree view — implementation-
//! defined under CONTRACT-190's family floor, §3.6), and `POST /client/runs/{run_id}:pause|:resume|
//! :cancel` (mutations). Run CREATION is intentionally NOT served — `POST /client/runs` resolves to
//! `unknown_route`; runs are created via the messaging/submit surfaces and appear in `GET /client/runs`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::api::{ClientApi, HandlerSpec};
use crate::provider::{provider_or_unavailable, ProviderError, RunProviderSlot};
use crate::request::Method;
use crate::routes;
use crate::session::Scope;

/// A run-list row, projected from the host-side `Run`/`BudgetState` (no internal-only fields).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientRunSummary {
    pub run_id: String,
    pub task_id: String,
    pub controller_agent: String,
    /// `active | suspended | paused | completed | failed | cancelled`.
    pub status: String,
    pub iteration: u32,
    pub token_used: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_limit: Option<u64>,
    pub cost_usd: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_usd_limit: Option<f64>,
    /// RFC3339.
    pub created_at: String,
    /// RFC3339.
    pub updated_at: String,
}

/// The result of a run mutation (pause/resume/cancel): the resulting status + the ids of the
/// `run.*` events the mutation emitted.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientRunMutation {
    pub run_id: String,
    pub status: String,
    pub emitted_event_ids: Vec<String>,
}

/// A read-only agent-tree node, projected from the MODULE-005 `AgentTreeSnapshot` (no
/// `workspace_path`/`capabilities` leak).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientAgentTreeNode {
    pub id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_ref: Option<String>,
}

#[derive(Clone, Copy)]
enum RunAction {
    Pause,
    Resume,
    Cancel,
}

/// Register the run-control routes, capturing the shared provider slot in each closure so a builder
/// can inject the concrete provider AFTER registration. An absent slot yields `module_unavailable`.
pub(crate) fn register(api: &mut ClientApi, slot: RunProviderSlot) {
    // GET /client/runs — list runs visible to the caller. In this transport-agnostic slice the list
    // is returned in full (next_cursor omitted — see the handler body); the documented cursor/limit/
    // status query parameters are honored by the HTTP transport (Wave-25), not the in-process core.
    let s = slot.clone();
    api.register(
        Method::Get,
        routes::PATH_RUNS,
        HandlerSpec::read(true, move |_ctx| {
            let provider = provider_or_unavailable(&s)?;
            let runs = provider
                .list_runs()
                .map_err(ProviderError::into_client_error)?;
            // Full list in the transport-agnostic core: `next_cursor` is OMITTED (there is no next
            // page), matching the optional `next_cursor?: string` DTO — never serialized as null.
            Ok(json!({ "runs": runs }))
        })
        .with_scopes(vec![Scope::ReadRuns]),
    );

    // GET /client/runs/tree — read-only agent-tree view (rides AC-07).
    let s = slot.clone();
    api.register(
        Method::Get,
        routes::PATH_RUNS_TREE,
        HandlerSpec::read(true, move |_ctx| {
            let provider = provider_or_unavailable(&s)?;
            let nodes = provider
                .agent_tree()
                .map_err(ProviderError::into_client_error)?;
            Ok(json!({ "nodes": nodes }))
        })
        .with_scopes(vec![Scope::ReadRuns]),
    );

    register_mut(api, &slot, routes::TPL_RUN_PAUSE, RunAction::Pause);
    register_mut(api, &slot, routes::TPL_RUN_RESUME, RunAction::Resume);
    register_mut(api, &slot, routes::TPL_RUN_CANCEL, RunAction::Cancel);
}

fn register_mut(api: &mut ClientApi, slot: &RunProviderSlot, template: &str, action: RunAction) {
    let s = slot.clone();
    api.register_templated(
        Method::Post,
        template,
        // A mutation: the pipeline enforces ControlRuns (after auth, before the idempotency gate),
        // then the envelope-level idempotency key + CSRF. The run-mutation body carries only an
        // optional `reason`.
        HandlerSpec::mutation(true, move |ctx| {
            let run_id = ctx.path_param("run_id")?;
            let reason = ctx.body.get("reason").and_then(|v| v.as_str());
            let provider = provider_or_unavailable(&s)?;
            let mutation = match action {
                RunAction::Pause => provider.pause(&run_id, reason),
                RunAction::Resume => provider.resume(&run_id, reason),
                RunAction::Cancel => provider.cancel(&run_id, reason),
            }
            .map_err(ProviderError::into_client_error)?;
            Ok(serde_json::to_value(mutation).expect("ClientRunMutation serializes"))
        })
        .with_scopes(vec![Scope::ControlRuns]),
    );
}

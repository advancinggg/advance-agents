//! `agent-skills` host-function registration — MODULE-017 Slice C.
//!
//! Wires 8 of the canonical `agent-skills` WIT methods into the runtime
//! `HostRegistry`:
//!
//! - `propose-skill-draft`
//! - `propose-skill-patch`
//! - `update-skill-draft`
//! - `activate-skill`
//! - `rollback-skill`
//! - `delete-skill`
//! - `list-skill-candidates`
//! - `resolve-skill-candidate`
//!
//! Each handler holds `Arc<dyn SkillStoreProvider>` and resolves the
//! `SkillStore` per-invocation via `provider.get(&ctx.agent_id).await`
//! (NOT cached at construction — preserves the path to a future multi-agent
//! provider per MODULE-017 §3.6 known gap (b)).
//!
//! ## GrantCheck note
//!
//! Capability authorization is enforced one layer up at
//! `CapabilityInjector::inject` (mirrors the SB-22 cap-tools precedent for
//! `agent-tools`). The host function is registered under capability
//! `"skills"`; agents whose grant set does not include `skills` cannot reach
//! these handlers in the first place.
//!
//! ## elevate_trust is NOT registered
//!
//! `SkillStore::elevate_trust` is an admin-only Rust API surface; it is NOT
//! registered as a host_fn. SC-19 confirms `registry.lookup` for
//! `(advance:runtime/agent-skills@0.1.0, elevate-skill-trust)` returns `None`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use advance_runtime::host_registry::{
    HostCallContext, HostCallError, HostFunctionHandler, HostFunctionSpec, HostRegistry,
};
use wasmtime::component::Val;

use crate::error::{SkillError, WitSkillError};
use crate::lifecycle::SkillCandidate;
use crate::persistence_phase::{Initiator, SkillPersistenceCoordinator};
use crate::provider::SkillStoreProvider;
use crate::turn_runtime::SkillTurnRuntime;

const NAMESPACE: &str = "advance:runtime/agent-skills@0.1.0";
const CAPABILITY: &str = "skills";

/// Hard upper bound on `propose-skill-draft` / `propose-skill-patch` /
/// `update-skill-draft` content. Mirrors `lifecycle::MAX_CONTENT_LEN`; the
/// fail-fast decoder check (SC-46) short-circuits before security_scan.
const MAX_CONTENT_BYTES: usize = 50_000;

// ─────────────────────────────────────────────────────────────────────
// Val decoding helpers
// ─────────────────────────────────────────────────────────────────────

fn decode_string(val: &Val) -> Result<&str, HostCallError> {
    match val {
        Val::String(s) => Ok(s.as_str()),
        _ => Err(HostCallError::HandlerError(
            "expected string parameter".to_string(),
        )),
    }
}

fn decode_owned_string(val: &Val) -> Result<String, HostCallError> {
    decode_string(val).map(|s| s.to_string())
}

fn decode_list_string(val: &Val) -> Result<Vec<String>, HostCallError> {
    match val {
        Val::List(items) => items
            .iter()
            .map(|v| match v {
                Val::String(s) => Ok(s.clone()),
                _ => Err(HostCallError::HandlerError(
                    "expected list<string>".to_string(),
                )),
            })
            .collect(),
        _ => Err(HostCallError::HandlerError(
            "expected list<string> parameter".to_string(),
        )),
    }
}

fn decode_u32(val: &Val) -> Result<u32, HostCallError> {
    match val {
        Val::U32(v) => Ok(*v),
        _ => Err(HostCallError::HandlerError(
            "expected u32 parameter".to_string(),
        )),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Val encoding helpers
// ─────────────────────────────────────────────────────────────────────

/// Encode a `WitSkillError` as `Val::Variant`. `ContentTooLarge` is the
/// only payloadless arm per PRD §9.12 line 3704.
fn encode_skill_error(err: &WitSkillError) -> Val {
    let case = err.case().to_string();
    match err.payload() {
        Some(p) => Val::Variant(case, Some(Box::new(Val::String(p.to_string())))),
        None => Val::Variant(case, None),
    }
}

fn encode_result_string(r: Result<String, SkillError>) -> Val {
    match r {
        Ok(s) => Val::Result(Ok(Some(Box::new(Val::String(s))))),
        Err(e) => Val::Result(Err(Some(Box::new(encode_skill_error(&e.to_wit_variant()))))),
    }
}

fn encode_result_unit(r: Result<(), SkillError>) -> Val {
    match r {
        Ok(()) => Val::Result(Ok(None)),
        Err(e) => Val::Result(Err(Some(Box::new(encode_skill_error(&e.to_wit_variant()))))),
    }
}

/// Encode a `skill-candidate` record matching the WIT shape in
/// `runtime/wit/advance.wit:267-272`.
fn encode_skill_candidate(c: &SkillCandidate) -> Val {
    Val::Record(vec![
        (
            "candidate-id".to_string(),
            Val::String(c.candidate_id.clone()),
        ),
        ("skill-name".to_string(), Val::String(c.name.clone())),
        (
            // The cap-memory/cap-skills `SkillCandidate` struct carries only
            // {candidate_id, name, description}; the WIT `source-task-ids` /
            // `timestamp` fields are not modelled, so they are emitted empty.
            "source-task-ids".to_string(),
            Val::List(Vec::new()),
        ),
        ("timestamp".to_string(), Val::String(String::new())),
    ])
}

fn encode_result_candidate_list(r: Result<Vec<SkillCandidate>, SkillError>) -> Val {
    match r {
        Ok(items) => {
            let list = items.iter().map(encode_skill_candidate).collect();
            Val::Result(Ok(Some(Box::new(Val::List(list)))))
        }
        Err(e) => Val::Result(Err(Some(Box::new(encode_skill_error(&e.to_wit_variant()))))),
    }
}

/// Encode a `candidate-result` record matching the WIT shape in
/// `runtime/wit/advance.wit:282-285` (slice wave6-laneB). `accept` carries the new
/// draft-id; `dismiss` carries the empty string.
fn encode_candidate_result(cr: &crate::lifecycle::CandidateResult) -> Val {
    Val::Record(vec![
        (
            "candidate-id".to_string(),
            Val::String(cr.candidate_id.clone()),
        ),
        ("draft-id".to_string(), Val::String(cr.draft_id.clone())),
    ])
}

fn encode_result_candidate_result(r: Result<crate::lifecycle::CandidateResult, SkillError>) -> Val {
    match r {
        Ok(cr) => Val::Result(Ok(Some(Box::new(encode_candidate_result(&cr))))),
        // The resolve surface speaks of CANDIDATES, not skills: emit a
        // candidate-specific not-found payload (rather than the generic
        // `SkillNotFound → "skill not found"` projection). Other error classes
        // (e.g. an internal store error) use the standard WIT projection.
        Err(SkillError::SkillNotFound(_)) => Val::Result(Err(Some(Box::new(encode_skill_error(
            &WitSkillError::NotFound("candidate not found".to_string()),
        ))))),
        Err(e) => Val::Result(Err(Some(Box::new(encode_skill_error(&e.to_wit_variant()))))),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Handlers
// ─────────────────────────────────────────────────────────────────────

/// Resolve the per-agent `SkillStore` from the provider. Maps
/// `Err(SkillError)` (provider-side, e.g. unknown agent) into the WIT
/// `skill-error` projection so the agent observes the same shape as any
/// other handler-internal failure.
async fn resolve_store(
    provider: &Arc<dyn SkillStoreProvider>,
    agent_id: &str,
) -> Result<Arc<tokio::sync::Mutex<crate::lifecycle::SkillStore>>, SkillError> {
    provider.get(agent_id).await
}

macro_rules! resolve_or_error {
    ($provider:expr, $agent_id:expr, $encode:expr) => {{
        match resolve_store($provider, $agent_id).await {
            Ok(s) => s,
            Err(e) => return Ok(vec![$encode(Err(e))]),
        }
    }};
}

pub struct ProposeSkillDraftHandler {
    pub provider: Arc<dyn SkillStoreProvider>,
    pub turn_runtime: Option<Arc<SkillTurnRuntime>>,
}

impl HostFunctionHandler for ProposeSkillDraftHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let provider = Arc::clone(&self.provider);
        let turn_runtime = self.turn_runtime.clone();
        Box::pin(async move {
            if params.len() < 3 {
                return Err(HostCallError::HandlerError(
                    "propose-skill-draft: expected 3 params".to_string(),
                ));
            }
            let name = decode_owned_string(&params[0])?;
            let content = decode_owned_string(&params[1])?;
            // SC-46 fail-fast at decoder: oversized content → ContentTooLarge
            // BEFORE the SkillStore even sees the payload.
            if content.len() > MAX_CONTENT_BYTES {
                return Ok(vec![encode_result_string(Err(
                    SkillError::ContentTooLarge(content.len()),
                ))]);
            }
            let tags = decode_list_string(&params[2])?;
            if let Some(runtime) = turn_runtime {
                if runtime.is_active_for(&ctx.agent_id).await {
                    let r = runtime.stage_propose_draft(name, content, tags).await;
                    return Ok(vec![encode_result_string(r)]);
                }
            }
            let store = resolve_or_error!(&provider, &ctx.agent_id, encode_result_string);
            let s = store.lock().await;
            let r = s.propose_draft(name, content, tags).await;
            Ok(vec![encode_result_string(r)])
        })
    }
}

pub struct ProposeSkillPatchHandler {
    pub provider: Arc<dyn SkillStoreProvider>,
    pub turn_runtime: Option<Arc<SkillTurnRuntime>>,
}

impl HostFunctionHandler for ProposeSkillPatchHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let provider = Arc::clone(&self.provider);
        let turn_runtime = self.turn_runtime.clone();
        Box::pin(async move {
            if params.len() < 3 {
                return Err(HostCallError::HandlerError(
                    "propose-skill-patch: expected 3 params".to_string(),
                ));
            }
            let skill_id = decode_owned_string(&params[0])?;
            let content = decode_owned_string(&params[1])?;
            if content.len() > MAX_CONTENT_BYTES {
                return Ok(vec![encode_result_string(Err(
                    SkillError::ContentTooLarge(content.len()),
                ))]);
            }
            let reason = decode_owned_string(&params[2])?;
            if let Some(runtime) = turn_runtime {
                if runtime.is_active_for(&ctx.agent_id).await {
                    let r = runtime
                        .stage_propose_patch(&skill_id, content, reason)
                        .await;
                    return Ok(vec![encode_result_string(r)]);
                }
            }
            let store = resolve_or_error!(&provider, &ctx.agent_id, encode_result_string);
            let s = store.lock().await;
            let r = s.propose_patch(&skill_id, content, reason).await;
            Ok(vec![encode_result_string(r)])
        })
    }
}

pub struct UpdateSkillDraftHandler {
    pub provider: Arc<dyn SkillStoreProvider>,
    pub turn_runtime: Option<Arc<SkillTurnRuntime>>,
}

impl HostFunctionHandler for UpdateSkillDraftHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let provider = Arc::clone(&self.provider);
        let turn_runtime = self.turn_runtime.clone();
        Box::pin(async move {
            if params.len() < 2 {
                return Err(HostCallError::HandlerError(
                    "update-skill-draft: expected 2 params".to_string(),
                ));
            }
            let draft_id = decode_owned_string(&params[0])?;
            let content = decode_owned_string(&params[1])?;
            if content.len() > MAX_CONTENT_BYTES {
                return Ok(vec![encode_result_unit(Err(SkillError::ContentTooLarge(
                    content.len(),
                )))]);
            }
            if let Some(runtime) = turn_runtime {
                if runtime.is_active_for(&ctx.agent_id).await {
                    let r = runtime.stage_update_draft(&draft_id, content).await;
                    return Ok(vec![encode_result_unit(r)]);
                }
            }
            let store = resolve_or_error!(&provider, &ctx.agent_id, encode_result_unit);
            let s = store.lock().await;
            let r = s.update_draft(&draft_id, content).await;
            Ok(vec![encode_result_unit(r)])
        })
    }
}

pub struct ActivateSkillHandler {
    pub provider: Arc<dyn SkillStoreProvider>,
    /// Wave-10 Lane C (076): when `Some`, a successful activate routes through
    /// the coordinator → `skill.activated` event + a `commit_type: turn` commit,
    /// instead of the event-less provider-store path. The coordinator is bound
    /// to one agent; a mismatched `ctx.agent_id` is rejected with `SkillNotFound`
    /// (mirrors `SingleAgentSkillStoreProvider::get`) WITHOUT pre-locking — the
    /// coordinator locks the shared store internally, so pre-locking would
    /// deadlock. `None` ⇒ exact pre-Wave-10 behavior.
    pub coordinator: Option<Arc<SkillPersistenceCoordinator>>,
    pub turn_runtime: Option<Arc<SkillTurnRuntime>>,
}

impl HostFunctionHandler for ActivateSkillHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let provider = Arc::clone(&self.provider);
        let coordinator = self.coordinator.clone();
        let turn_runtime = self.turn_runtime.clone();
        Box::pin(async move {
            if params.is_empty() {
                return Err(HostCallError::HandlerError(
                    "activate-skill: expected 1 param".to_string(),
                ));
            }
            let draft_id = decode_owned_string(&params[0])?;
            if let Some(runtime) = turn_runtime {
                if runtime.is_active_for(&ctx.agent_id).await {
                    let r = runtime.stage_activate(draft_id).await;
                    return Ok(vec![encode_result_string(r)]);
                }
            }
            if let Some(coord) = coordinator {
                if ctx.agent_id != coord.agent_id() {
                    return Ok(vec![encode_result_string(Err(SkillError::SkillNotFound(
                        format!("unknown agent: {}", ctx.agent_id),
                    )))]);
                }
                let r = coord
                    .activate_skill_with_persistence(
                        Initiator::Agent {
                            id: ctx.agent_id.clone(),
                        },
                        &draft_id,
                        "",
                    )
                    .await
                    .map(|a| a.skill_id);
                return Ok(vec![encode_result_string(r)]);
            }
            let store = resolve_or_error!(&provider, &ctx.agent_id, encode_result_string);
            let s = store.lock().await;
            let r = s.activate(&draft_id).await;
            Ok(vec![encode_result_string(r)])
        })
    }
}

pub struct RollbackSkillHandler {
    pub provider: Arc<dyn SkillStoreProvider>,
    /// Wave-10 Lane C (077): when `Some`, the agent-callable rollback routes
    /// through the coordinator → `skill.rolled_back` event + version restore +
    /// `commit_type: turn` commit. Same agent-id guard + no-pre-lock contract as
    /// `ActivateSkillHandler`. `None` ⇒ exact pre-Wave-10 (event-less) behavior.
    pub coordinator: Option<Arc<SkillPersistenceCoordinator>>,
    pub turn_runtime: Option<Arc<SkillTurnRuntime>>,
}

impl HostFunctionHandler for RollbackSkillHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let provider = Arc::clone(&self.provider);
        let coordinator = self.coordinator.clone();
        let turn_runtime = self.turn_runtime.clone();
        Box::pin(async move {
            if params.len() < 2 {
                return Err(HostCallError::HandlerError(
                    "rollback-skill: expected 2 params".to_string(),
                ));
            }
            let skill_id = decode_owned_string(&params[0])?;
            let version = decode_u32(&params[1])?;
            if let Some(runtime) = turn_runtime {
                if runtime.is_active_for(&ctx.agent_id).await {
                    let r = runtime.stage_rollback(skill_id, version).await;
                    return Ok(vec![encode_result_unit(r)]);
                }
            }
            if let Some(coord) = coordinator {
                if ctx.agent_id != coord.agent_id() {
                    return Ok(vec![encode_result_unit(Err(SkillError::SkillNotFound(
                        format!("unknown agent: {}", ctx.agent_id),
                    )))]);
                }
                let r = coord
                    .rollback_skill_with_persistence(
                        Initiator::Agent {
                            id: ctx.agent_id.clone(),
                        },
                        &skill_id,
                        version,
                        "",
                    )
                    .await
                    .map(|_| ());
                return Ok(vec![encode_result_unit(r)]);
            }
            let store = resolve_or_error!(&provider, &ctx.agent_id, encode_result_unit);
            let s = store.lock().await;
            let r = s.rollback(&skill_id, version).await;
            Ok(vec![encode_result_unit(r)])
        })
    }
}

pub struct DeleteSkillHandler {
    pub provider: Arc<dyn SkillStoreProvider>,
    pub turn_runtime: Option<Arc<SkillTurnRuntime>>,
}

impl HostFunctionHandler for DeleteSkillHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let provider = Arc::clone(&self.provider);
        let turn_runtime = self.turn_runtime.clone();
        Box::pin(async move {
            if params.is_empty() {
                return Err(HostCallError::HandlerError(
                    "delete-skill: expected 1 param".to_string(),
                ));
            }
            let skill_id = decode_owned_string(&params[0])?;
            if let Some(runtime) = turn_runtime {
                if runtime.is_active_for(&ctx.agent_id).await {
                    let r = runtime.stage_delete(skill_id).await;
                    return Ok(vec![encode_result_unit(r)]);
                }
            }
            let store = resolve_or_error!(&provider, &ctx.agent_id, encode_result_unit);
            let s = store.lock().await;
            let r = s.delete(&skill_id).await;
            Ok(vec![encode_result_unit(r)])
        })
    }
}

pub struct ListSkillCandidatesHandler {
    pub provider: Arc<dyn SkillStoreProvider>,
}

impl HostFunctionHandler for ListSkillCandidatesHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        _params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let provider = Arc::clone(&self.provider);
        Box::pin(async move {
            let store = resolve_or_error!(&provider, &ctx.agent_id, encode_result_candidate_list);
            let s = store.lock().await;
            let r = s.list_skill_candidates().await;
            Ok(vec![encode_result_candidate_list(r)])
        })
    }
}

pub struct ResolveSkillCandidateHandler {
    pub provider: Arc<dyn SkillStoreProvider>,
    pub turn_runtime: Option<Arc<SkillTurnRuntime>>,
}

impl HostFunctionHandler for ResolveSkillCandidateHandler {
    fn call(
        &self,
        ctx: HostCallContext,
        params: Vec<Val>,
        _results_len: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Val>, HostCallError>> + Send + 'static>> {
        let provider = Arc::clone(&self.provider);
        let turn_runtime = self.turn_runtime.clone();
        Box::pin(async move {
            if params.is_empty() {
                return Err(HostCallError::HandlerError(
                    "resolve-skill-candidate: expected at least 1 param".to_string(),
                ));
            }
            let candidate_id = decode_owned_string(&params[0])?;
            // Require + decode the `candidate-action` enum (Adversarial r3 W5).
            // slice wave6-laneB: the resolver now BRANCHES on it (accept proposes a
            // draft; dismiss does not).
            if params.len() < 2 {
                return Err(HostCallError::HandlerError(
                    "resolve-skill-candidate: missing candidate-action parameter".to_string(),
                ));
            }
            let action = match &params[1] {
                Val::Enum(s) | Val::String(s) if s == "accept" => {
                    crate::lifecycle::CandidateAction::Accept
                }
                Val::Enum(s) | Val::String(s) if s == "dismiss" => {
                    crate::lifecycle::CandidateAction::Dismiss
                }
                _ => {
                    return Err(HostCallError::HandlerError(
                        "resolve-skill-candidate: candidate-action must be accept|dismiss"
                            .to_string(),
                    ));
                }
            };
            if let Some(runtime) = turn_runtime {
                if runtime.is_active_for(&ctx.agent_id).await {
                    return Ok(vec![encode_result_candidate_result(
                        runtime.stage_resolve_candidate(&candidate_id, action).await,
                    )]);
                }
            }
            let store = {
                match resolve_store(&provider, &ctx.agent_id).await {
                    Ok(s) => s,
                    Err(e) => {
                        return Ok(vec![Val::Result(Err(Some(Box::new(encode_skill_error(
                            &e.to_wit_variant(),
                        )))))]);
                    }
                }
            };
            let s = store.lock().await;
            // slice wave6-laneB: wired to the cap-memory candidate store — append the
            // terminal event + (on accept) propose a draft, and encode the WIT
            // `candidate-result`. The Slice-C `unreachable!()` Ok-arm is gone.
            Ok(vec![encode_result_candidate_result(
                s.resolve_skill_candidate(&candidate_id, action).await,
            )])
        })
    }
}

// ─────────────────────────────────────────────────────────────────────
// Registration
// ─────────────────────────────────────────────────────────────────────

/// Register all 8 `agent-skills` methods under capability `"skills"`.
///
/// **GrantCheck enforcement** lives one layer up at
/// `CapabilityInjector::inject` (mirrors the cap-tools / cap-llm precedent).
/// Agents whose grant set excludes `"skills"` never reach these handlers.
///
/// `idempotent: false` is the default — skill state mutations are not
/// idempotent at the agent-observable boundary (a second activate of the
/// same draft observes `DraftNotFound`).
///
/// **`elevate-skill-trust` is intentionally NOT registered** — `elevate_trust`
/// is an admin-only Rust API surface. See SC-19 for the lookup-absence test.
pub fn register_agent_skills(registry: &dyn HostRegistry, provider: Arc<dyn SkillStoreProvider>) {
    register_agent_skills_inner(registry, provider, None, None);
}

/// Wave-10 Lane C: register the 8 `agent-skills` methods with `activate-skill` +
/// `rollback-skill` routed through the per-agent `SkillPersistenceCoordinator`
/// (076/077 emitters — `skill.activated` / `skill.rolled_back` + `commit_type:
/// turn`). The other 6 handlers are provider-only, identical to
/// `register_agent_skills`. The cli composition root calls this when `skills` is
/// declared AND a git commit queue is available; otherwise it calls the plain
/// `register_agent_skills` (no commits/events — DORMANT, byte-identical to today).
pub fn register_agent_skills_with_lifecycle(
    registry: &dyn HostRegistry,
    provider: Arc<dyn SkillStoreProvider>,
    coordinator: Arc<SkillPersistenceCoordinator>,
) {
    register_agent_skills_inner(registry, provider, Some(coordinator), None);
}

pub fn register_agent_skills_with_turn_runtime(
    registry: &dyn HostRegistry,
    provider: Arc<dyn SkillStoreProvider>,
    coordinator: Arc<SkillPersistenceCoordinator>,
    turn_runtime: Arc<SkillTurnRuntime>,
) {
    register_agent_skills_inner(registry, provider, Some(coordinator), Some(turn_runtime));
}

/// Shared registration body. `coordinator: None` ⇒ the event-less Slice-C path
/// (public `register_agent_skills`); `Some` ⇒ activate/rollback route through it.
fn register_agent_skills_inner(
    registry: &dyn HostRegistry,
    provider: Arc<dyn SkillStoreProvider>,
    coordinator: Option<Arc<SkillPersistenceCoordinator>>,
    turn_runtime: Option<Arc<SkillTurnRuntime>>,
) {
    // The 6 provider-only handlers (unchanged).
    let provider_only: &[(
        &str,
        fn(
            Arc<dyn SkillStoreProvider>,
            Option<Arc<SkillTurnRuntime>>,
        ) -> Arc<dyn HostFunctionHandler>,
    )] = &[
        ("propose-skill-draft", |p, t| {
            Arc::new(ProposeSkillDraftHandler {
                provider: p,
                turn_runtime: t,
            })
        }),
        ("propose-skill-patch", |p, t| {
            Arc::new(ProposeSkillPatchHandler {
                provider: p,
                turn_runtime: t,
            })
        }),
        ("update-skill-draft", |p, t| {
            Arc::new(UpdateSkillDraftHandler {
                provider: p,
                turn_runtime: t,
            })
        }),
        ("delete-skill", |p, t| {
            Arc::new(DeleteSkillHandler {
                provider: p,
                turn_runtime: t,
            })
        }),
        ("list-skill-candidates", |p, _t| {
            Arc::new(ListSkillCandidatesHandler { provider: p })
        }),
        ("resolve-skill-candidate", |p, t| {
            Arc::new(ResolveSkillCandidateHandler {
                provider: p,
                turn_runtime: t,
            })
        }),
    ];
    for (name, make_handler) in provider_only {
        registry.register(HostFunctionSpec {
            capability: CAPABILITY.to_string(),
            namespace: NAMESPACE.to_string(),
            name: name.to_string(),
            handler: make_handler(Arc::clone(&provider), turn_runtime.clone()),
            idempotent: false,
        });
    }

    // activate-skill + rollback-skill carry the optional lifecycle coordinator.
    registry.register(HostFunctionSpec {
        capability: CAPABILITY.to_string(),
        namespace: NAMESPACE.to_string(),
        name: "activate-skill".to_string(),
        handler: Arc::new(ActivateSkillHandler {
            provider: Arc::clone(&provider),
            coordinator: coordinator.clone(),
            turn_runtime: turn_runtime.clone(),
        }),
        idempotent: false,
    });
    registry.register(HostFunctionSpec {
        capability: CAPABILITY.to_string(),
        namespace: NAMESPACE.to_string(),
        name: "rollback-skill".to_string(),
        handler: Arc::new(RollbackSkillHandler {
            provider: Arc::clone(&provider),
            coordinator,
            turn_runtime,
        }),
        idempotent: false,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::SingleAgentSkillStoreProvider;
    use advance_runtime::host_registry::InMemoryHostRegistry;
    use tempfile::TempDir;

    fn ctx_for(agent_id: &str, function: &str) -> HostCallContext {
        HostCallContext {
            agent_id: agent_id.to_string(),
            trace_id: "t-0".to_string(),
            turn_id: None,
            capability: CAPABILITY.to_string(),
            function: format!("{NAMESPACE}::{function}"),
            run_id: None,
            iteration: None,
        }
    }

    fn valid_content(name: &str) -> String {
        format!("---\nname: {name}\ndescription: x\n---\n# {name}\n")
    }

    fn make_provider() -> (TempDir, Arc<dyn SkillStoreProvider>) {
        let dir = TempDir::new().unwrap();
        let provider: Arc<dyn SkillStoreProvider> = Arc::new(SingleAgentSkillStoreProvider::new(
            "alice",
            dir.path().to_path_buf(),
        ));
        (dir, provider)
    }

    fn lookup<'a>(registry: &'a InMemoryHostRegistry, name: &str) -> Option<HostFunctionSpec> {
        registry
            .lookup(CAPABILITY)
            .into_iter()
            .find(|spec| spec.namespace == NAMESPACE && spec.name == name)
    }

    /// SC-45: all 8 methods registered under capability `skills`, namespace
    /// `advance:runtime/agent-skills@0.1.0`.
    #[tokio::test]
    async fn sc_45_all_eight_methods_registered() {
        let (_dir, provider) = make_provider();
        let registry = InMemoryHostRegistry::new();
        register_agent_skills(&registry, provider);
        let specs = registry.lookup(CAPABILITY);
        assert_eq!(specs.len(), 8);
        for expected in [
            "propose-skill-draft",
            "propose-skill-patch",
            "update-skill-draft",
            "activate-skill",
            "rollback-skill",
            "delete-skill",
            "list-skill-candidates",
            "resolve-skill-candidate",
        ] {
            assert!(
                specs
                    .iter()
                    .any(|s| s.namespace == NAMESPACE && s.name == expected),
                "expected {expected} to be registered"
            );
        }
    }

    /// SC-19: `elevate-skill-trust` is NOT registered as a host_fn.
    #[tokio::test]
    async fn sc_19_elevate_trust_not_a_host_fn() {
        let (_dir, provider) = make_provider();
        let registry = InMemoryHostRegistry::new();
        register_agent_skills(&registry, provider);
        assert!(
            lookup(&registry, "elevate-skill-trust").is_none(),
            "elevate-skill-trust must NOT be a registered host_fn"
        );
    }

    /// SC-36: `propose-skill-draft` Val round-trip.
    #[tokio::test]
    async fn sc_36_propose_draft_round_trip() {
        let (_dir, provider) = make_provider();
        let registry = InMemoryHostRegistry::new();
        register_agent_skills(&registry, provider);
        let spec = lookup(&registry, "propose-skill-draft").unwrap();
        let out = spec
            .handler
            .call(
                ctx_for("alice", "propose-skill-draft"),
                vec![
                    Val::String("foo".into()),
                    Val::String(valid_content("foo")),
                    Val::List(vec![Val::String("t".into())]),
                ],
                1,
            )
            .await
            .unwrap();
        assert_eq!(out.len(), 1);
        match &out[0] {
            Val::Result(Ok(Some(boxed))) => match boxed.as_ref() {
                Val::String(s) => assert_eq!(s, "foo"),
                _ => panic!("expected Val::String draft-id"),
            },
            other => panic!("expected Result Ok, got {other:?}"),
        }
    }

    /// SC-37: `propose-skill-patch` Val round-trip (requires existing active).
    #[tokio::test]
    async fn sc_37_propose_patch_round_trip() {
        let (_dir, provider) = make_provider();
        let registry = InMemoryHostRegistry::new();
        register_agent_skills(&registry, provider.clone());

        // Seed via propose+activate.
        let store = provider.get("alice").await.unwrap();
        let d = store
            .lock()
            .await
            .propose_draft("foo".into(), valid_content("foo"), vec![])
            .await
            .unwrap();
        store.lock().await.activate(&d).await.unwrap();

        let spec = lookup(&registry, "propose-skill-patch").unwrap();
        let out = spec
            .handler
            .call(
                ctx_for("alice", "propose-skill-patch"),
                vec![
                    Val::String("foo".into()),
                    Val::String(valid_content("foo-patched")),
                    Val::String("reason".into()),
                ],
                1,
            )
            .await
            .unwrap();
        assert!(matches!(out[0], Val::Result(Ok(Some(_)))));
    }

    /// SC-38: `update-skill-draft` Val round-trip.
    #[tokio::test]
    async fn sc_38_update_draft_round_trip() {
        let (_dir, provider) = make_provider();
        let registry = InMemoryHostRegistry::new();
        register_agent_skills(&registry, provider.clone());

        // Seed a draft.
        let store = provider.get("alice").await.unwrap();
        store
            .lock()
            .await
            .propose_draft("foo".into(), valid_content("foo"), vec![])
            .await
            .unwrap();

        let spec = lookup(&registry, "update-skill-draft").unwrap();
        let out = spec
            .handler
            .call(
                ctx_for("alice", "update-skill-draft"),
                vec![
                    Val::String("foo".into()),
                    Val::String(valid_content("foo-updated")),
                ],
                1,
            )
            .await
            .unwrap();
        assert!(matches!(out[0], Val::Result(Ok(None))));
    }

    /// SC-39: `activate-skill` Val round-trip.
    #[tokio::test]
    async fn sc_39_activate_round_trip() {
        let (_dir, provider) = make_provider();
        let registry = InMemoryHostRegistry::new();
        register_agent_skills(&registry, provider.clone());

        let store = provider.get("alice").await.unwrap();
        store
            .lock()
            .await
            .propose_draft("foo".into(), valid_content("foo"), vec![])
            .await
            .unwrap();

        let spec = lookup(&registry, "activate-skill").unwrap();
        let out = spec
            .handler
            .call(
                ctx_for("alice", "activate-skill"),
                vec![Val::String("foo".into())],
                1,
            )
            .await
            .unwrap();
        match &out[0] {
            Val::Result(Ok(Some(boxed))) => match boxed.as_ref() {
                Val::String(s) => assert_eq!(s, "foo"),
                _ => panic!("expected skill-id string"),
            },
            other => panic!("expected Ok result, got {other:?}"),
        }
    }

    /// SC-40: `rollback-skill` Val round-trip.
    #[tokio::test]
    async fn sc_40_rollback_round_trip() {
        let (_dir, provider) = make_provider();
        let registry = InMemoryHostRegistry::new();
        register_agent_skills(&registry, provider.clone());

        let store = provider.get("alice").await.unwrap();
        let d1 = store
            .lock()
            .await
            .propose_draft("foo".into(), valid_content("foo-v1"), vec![])
            .await
            .unwrap();
        store.lock().await.activate(&d1).await.unwrap();
        let d2 = store
            .lock()
            .await
            .propose_draft("foo".into(), valid_content("foo-v2"), vec![])
            .await
            .unwrap();
        store.lock().await.activate(&d2).await.unwrap();

        let spec = lookup(&registry, "rollback-skill").unwrap();
        let out = spec
            .handler
            .call(
                ctx_for("alice", "rollback-skill"),
                vec![Val::String("foo".into()), Val::U32(1)],
                1,
            )
            .await
            .unwrap();
        assert!(matches!(out[0], Val::Result(Ok(None))));
    }

    /// SC-41: `delete-skill` Val round-trip.
    #[tokio::test]
    async fn sc_41_delete_round_trip() {
        let (_dir, provider) = make_provider();
        let registry = InMemoryHostRegistry::new();
        register_agent_skills(&registry, provider.clone());

        let store = provider.get("alice").await.unwrap();
        let d = store
            .lock()
            .await
            .propose_draft("foo".into(), valid_content("foo"), vec![])
            .await
            .unwrap();
        store.lock().await.activate(&d).await.unwrap();

        let spec = lookup(&registry, "delete-skill").unwrap();
        let out = spec
            .handler
            .call(
                ctx_for("alice", "delete-skill"),
                vec![Val::String("foo".into())],
                1,
            )
            .await
            .unwrap();
        assert!(matches!(out[0], Val::Result(Ok(None))));
    }

    /// SC-42: `list-skill-candidates` returns an empty list when the provider has
    /// NO `candidate_dir` wired (the preserved stub path — `make_provider` does
    /// not set one; slice wave6-laneB keeps this non-regression).
    #[tokio::test]
    async fn sc_42_list_candidates_empty() {
        let (_dir, provider) = make_provider();
        let registry = InMemoryHostRegistry::new();
        register_agent_skills(&registry, provider);

        let spec = lookup(&registry, "list-skill-candidates").unwrap();
        let out = spec
            .handler
            .call(ctx_for("alice", "list-skill-candidates"), vec![], 1)
            .await
            .unwrap();
        match &out[0] {
            Val::Result(Ok(Some(boxed))) => match boxed.as_ref() {
                Val::List(items) => {
                    assert!(items.is_empty(), "unset candidate_dir → empty (stub path)")
                }
                _ => panic!("expected list"),
            },
            other => panic!("expected Ok list, got {other:?}"),
        }
    }

    /// SC-43: `resolve-skill-candidate(unknown-id)` → not-found.
    #[tokio::test]
    async fn sc_43_resolve_unknown_candidate_not_found() {
        let (_dir, provider) = make_provider();
        let registry = InMemoryHostRegistry::new();
        register_agent_skills(&registry, provider);

        let spec = lookup(&registry, "resolve-skill-candidate").unwrap();
        let out = spec
            .handler
            .call(
                ctx_for("alice", "resolve-skill-candidate"),
                vec![
                    Val::String("never-issued".into()),
                    Val::Enum("accept".into()),
                ],
                1,
            )
            .await
            .unwrap();
        match &out[0] {
            Val::Result(Err(Some(boxed))) => match boxed.as_ref() {
                Val::Variant(case, Some(payload)) => {
                    assert_eq!(case, "not-found");
                    match payload.as_ref() {
                        Val::String(s) => {
                            assert!(s.contains("candidate"), "payload mentions candidate: {s}");
                        }
                        _ => panic!("expected string payload"),
                    }
                }
                _ => panic!("expected not-found variant"),
            },
            other => panic!("expected Err result, got {other:?}"),
        }
    }

    /// SC-46: oversized `propose-skill-draft` content → ContentTooLarge
    /// AT THE DECODER (fails fast before security_scan).
    #[tokio::test]
    async fn sc_46_oversized_content_fails_at_decoder() {
        let (_dir, provider) = make_provider();
        let registry = InMemoryHostRegistry::new();
        register_agent_skills(&registry, provider);

        let spec = lookup(&registry, "propose-skill-draft").unwrap();
        let oversized = "x".repeat(MAX_CONTENT_BYTES + 100);
        let out = spec
            .handler
            .call(
                ctx_for("alice", "propose-skill-draft"),
                vec![
                    Val::String("foo".into()),
                    Val::String(oversized),
                    Val::List(vec![]),
                ],
                1,
            )
            .await
            .unwrap();
        match &out[0] {
            Val::Result(Err(Some(boxed))) => match boxed.as_ref() {
                Val::Variant(case, payload) => {
                    assert_eq!(case, "content-too-large");
                    assert!(
                        payload.is_none(),
                        "content-too-large is the only payloadless variant"
                    );
                }
                _ => panic!("expected variant"),
            },
            other => panic!("expected Err, got {other:?}"),
        }
    }

    /// SC-47: GrantCheck rustdoc presence — compile-time check via
    /// re-exporting the constants below. (The note appears in
    /// `register_agent_skills` rustdoc above.)
    #[test]
    fn sc_47_grant_check_constants_exposed() {
        assert_eq!(CAPABILITY, "skills");
        assert_eq!(NAMESPACE, "advance:runtime/agent-skills@0.1.0");
    }

    /// Unknown-agent path returns `not-found` (provider rejects).
    #[tokio::test]
    async fn unknown_agent_returns_not_found() {
        let (_dir, provider) = make_provider();
        let registry = InMemoryHostRegistry::new();
        register_agent_skills(&registry, provider);

        let spec = lookup(&registry, "propose-skill-draft").unwrap();
        let out = spec
            .handler
            .call(
                ctx_for("not-alice", "propose-skill-draft"),
                vec![
                    Val::String("foo".into()),
                    Val::String(valid_content("foo")),
                    Val::List(vec![]),
                ],
                1,
            )
            .await
            .unwrap();
        match &out[0] {
            Val::Result(Err(Some(boxed))) => match boxed.as_ref() {
                Val::Variant(case, _) => assert_eq!(case, "not-found"),
                _ => panic!("expected variant"),
            },
            other => panic!("expected Err, got {other:?}"),
        }
    }

    /// SC-48 (Wave-10 Lane C regression): `register_agent_skills` (the public
    /// 2-arg form → `coordinator: None`) is byte-preserved. The added optional
    /// `coordinator` field does not change the None path: activate still routes
    /// through the provider store and returns Ok(skill-id), event-less. Locks
    /// the non-regression of the Slice-C behavior for non-fs / non-git agents.
    #[tokio::test]
    async fn sc_48_activate_without_coordinator_unchanged() {
        let (_dir, provider) = make_provider();
        let registry = InMemoryHostRegistry::new();
        register_agent_skills(&registry, provider.clone());

        let store = provider.get("alice").await.unwrap();
        store
            .lock()
            .await
            .propose_draft("foo".into(), valid_content("foo"), vec![])
            .await
            .unwrap();

        let spec = lookup(&registry, "activate-skill").unwrap();
        let out = spec
            .handler
            .call(
                ctx_for("alice", "activate-skill"),
                vec![Val::String("foo".into())],
                1,
            )
            .await
            .unwrap();
        match &out[0] {
            Val::Result(Ok(Some(boxed))) => match boxed.as_ref() {
                Val::String(s) => assert_eq!(s, "foo"),
                _ => panic!("expected skill-id string"),
            },
            other => panic!("expected Ok result (None-coordinator path), got {other:?}"),
        }
    }
}

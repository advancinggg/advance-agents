//! CONTRACT-190 grant family over the bound CONTRACT-123 port.

use std::sync::Arc;

use advance_shared_types::security_validator::{LeakDetector, ScanContext, ScanResult};
use advance_shared_types::sensitive_observation::{
    BoundObservationDocument, CanonicalCapParam, ObservationDocument, ObservationNode,
    SensitiveObservationRedactor,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::api::{ClientApi, HandlerCtx, HandlerResponse, HandlerSpec};
use crate::envelope::API_VERSION;
use crate::envelope::{ClientError, ClientErrorCode, ClientWarning};
use crate::provider::{
    provider_or_unavailable, BoundGrantProviderSlot, LeakDetectorSlot, ObservationRedactorSlot,
    ProviderError,
};
use crate::providers::Projectable;
use crate::request::Method;
use crate::routes;
use crate::session::Scope;

const RECOVERY_TICKET_LEN: usize = 167;
const DONE_RECEIPT_LEN: usize = 283;
const MAX_DENY_REASON_BYTES: usize = 1_024;
const MAX_NARROW_PARAMS: usize = 64;
const MAX_PARAM_KEY_BYTES: usize = 256;
const MAX_PARAM_VALUE_BYTES: usize = 4_096;
const MAX_PARAMS_TOTAL_BYTES: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientCapParam {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientGrantTtl {
    Once,
    Lifecycle,
    Persistent,
    Duration { milliseconds_u64: String },
    Until { at: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientPendingGrant {
    pub request_id: String,
    pub decision_revision: String,
    pub caller_id: String,
    pub capability: String,
    pub params: Option<Vec<ClientCapParam>>,
    pub ttl: ClientGrantTtl,
    pub justification: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientGrantApproveRequest {
    pub decision_revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientGrantDenyRequest {
    pub decision_revision: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientGrantNarrowRequest {
    pub decision_revision: String,
    pub params: Vec<ClientCapParam>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientGrantRevokeRequest {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientPresetApplyRequest {
    pub target_agent_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientGrantDecision {
    pub request_id: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientGrantRevokeResult {
    pub grant_id: String,
    pub status: String,
    pub revoked_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClientPresetApplyResult {
    pub preset: String,
    pub target_agent_id: String,
    pub status: String,
    pub created_grant_ids: Vec<String>,
}

pub enum BoundGrantMutation {
    Approve {
        request_id: String,
        decision_revision: String,
    },
    Deny {
        request_id: String,
        decision_revision: String,
        reason: String,
    },
    Narrow {
        request_id: String,
        decision_revision: String,
        params: Vec<ClientCapParam>,
    },
    Revoke {
        grant_id: String,
    },
    ApplyPreset {
        target_agent_id: String,
        preset: String,
    },
}

pub(crate) struct CanonicalGrantRequest {
    pub route_template: &'static str,
    pub path_params: Vec<(String, String)>,
    pub body_schema_tag: u16,
    pub typed_body: Vec<u8>,
}

/// Validate and encode the closed grant mutation before an idempotency reservation is admitted.
/// This is deliberately the same parser used by the route handler, so malformed revisions,
/// unknown fields, and bounded-list failures cannot create a durable Pending row.
pub(crate) fn canonical_grant_request(
    path: &str,
    body: &Value,
) -> Result<CanonicalGrantRequest, ClientError> {
    fn put_text(output: &mut Vec<u8>, value: &str) -> Result<(), ClientError> {
        let len = u32::try_from(value.len()).map_err(|_| invalid_body("invalid grant body"))?;
        output.extend_from_slice(&len.to_be_bytes());
        output.extend_from_slice(value.as_bytes());
        Ok(())
    }

    let (template, body_schema_tag, typed_body) = if path.ends_with(":approve") {
        let request: ClientGrantApproveRequest = strict_body(body, "invalid grant approval body")?;
        validate_decision_revision(&request.decision_revision)?;
        let mut encoded = Vec::new();
        put_text(&mut encoded, &request.decision_revision)?;
        (routes::TPL_GRANT_APPROVE, 1, encoded)
    } else if path.ends_with(":deny") {
        let request: ClientGrantDenyRequest = strict_body(body, "invalid grant denial body")?;
        if request.reason.is_empty() || request.reason.len() > MAX_DENY_REASON_BYTES {
            return Err(invalid_body("invalid grant denial body"));
        }
        validate_decision_revision(&request.decision_revision)?;
        let mut encoded = Vec::new();
        put_text(&mut encoded, &request.decision_revision)?;
        put_text(&mut encoded, &request.reason)?;
        (routes::TPL_GRANT_DENY, 2, encoded)
    } else if path.ends_with(":narrow") {
        let request: ClientGrantNarrowRequest = strict_body(body, "invalid grant narrow body")?;
        validate_decision_revision(&request.decision_revision)?;
        validate_params(&request.params)?;
        let mut encoded = Vec::new();
        put_text(&mut encoded, &request.decision_revision)?;
        encoded.extend_from_slice(&(request.params.len() as u32).to_be_bytes());
        for param in request.params {
            put_text(&mut encoded, &param.key)?;
            put_text(&mut encoded, &param.value)?;
        }
        (routes::TPL_GRANT_NARROW, 3, encoded)
    } else if path.ends_with(":revoke") {
        parse_empty_body(body)?;
        (routes::TPL_GRANT_REVOKE, 0, Vec::new())
    } else if path.ends_with(":apply") {
        let request: ClientPresetApplyRequest = strict_body(body, "invalid preset body")?;
        if request.target_agent_id.is_empty() || request.target_agent_id.len() > 256 {
            return Err(invalid_body("invalid preset body"));
        }
        let mut encoded = Vec::new();
        put_text(&mut encoded, &request.target_agent_id)?;
        (routes::TPL_PRESET_APPLY, 5, encoded)
    } else {
        return Err(invalid_body("invalid grant route"));
    };
    let path_params = crate::routes::RoutePattern::parse(template)
        .matches(path)
        .ok_or_else(|| invalid_body("invalid grant route"))?;
    Ok(CanonicalGrantRequest {
        route_template: template,
        path_params,
        body_schema_tag,
        typed_body,
    })
}

impl BoundGrantMutation {
    pub fn operation_tag(&self) -> u8 {
        match self {
            Self::Approve { .. } => 1,
            Self::Deny { .. } => 2,
            Self::Narrow { .. } => 3,
            Self::Revoke { .. } => 4,
            Self::ApplyPreset { .. } => 5,
        }
    }
}

/// Fixed provider-authenticated recovery ticket.  No Clone/Serde implementation exists.
pub struct ProviderMutationRecovery {
    bytes: [u8; RECOVERY_TICKET_LEN],
}

impl ProviderMutationRecovery {
    pub fn from_provider_bytes(bytes: [u8; RECOVERY_TICKET_LEN]) -> Result<Self, ProviderError> {
        let key_epoch = u32::from_be_bytes(bytes[3..7].try_into().expect("fixed slice"));
        if bytes[0] != 1
            || bytes[1] != 1
            || !(1..=5).contains(&bytes[2])
            || key_epoch == 0
            || bytes[103..135].iter().all(|byte| *byte == 0)
        {
            return Err(ProviderError::InvalidState(
                "invalid provider recovery ticket".into(),
            ));
        }
        Ok(Self { bytes })
    }

    pub fn as_provider_bytes(&self) -> &[u8; RECOVERY_TICKET_LEN] {
        &self.bytes
    }
}

impl std::fmt::Debug for ProviderMutationRecovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProviderMutationRecovery(<opaque>)")
    }
}

/// Fixed post-manifest M020 Done receipt.  It is management-only and never a route DTO.
pub struct ProviderClientDoneReceipt {
    bytes: [u8; DONE_RECEIPT_LEN],
}

impl ProviderClientDoneReceipt {
    pub(crate) fn from_repository_bytes(bytes: [u8; DONE_RECEIPT_LEN]) -> Self {
        Self { bytes }
    }

    pub fn as_provider_bytes(&self) -> &[u8; DONE_RECEIPT_LEN] {
        &self.bytes
    }
}

impl std::fmt::Debug for ProviderClientDoneReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProviderClientDoneReceipt(<opaque>)")
    }
}

pub enum ProviderPrepareOutcome {
    Prepared(ProviderMutationRecovery),
    Rejected(ProviderError),
}

pub enum BoundMutationOutcome {
    Committed(BoundObservationDocument),
    Rejected(ProviderError),
    OutcomeUnknown(ProviderMutationRecovery),
}

pub trait BoundGrantApprovalPort: Send + Sync {
    fn list_pending_bound(&self) -> Result<Vec<BoundObservationDocument>, ProviderError>;

    fn prepare_mutation_bound(
        &self,
        mutation_id: [u8; 32],
        request_fingerprint: [u8; 32],
        mutation: BoundGrantMutation,
    ) -> ProviderPrepareOutcome;

    fn verify_recovery_ticket_bound(
        &self,
        mutation_id: [u8; 32],
        request_fingerprint: [u8; 32],
        operation_tag: u8,
        recovery: &ProviderMutationRecovery,
    ) -> Result<(), ProviderError>;

    fn execute_prepared_bound(&self, recovery: &ProviderMutationRecovery) -> BoundMutationOutcome;

    fn recover_mutation_bound(&self, recovery: &ProviderMutationRecovery) -> BoundMutationOutcome;

    fn acknowledge_client_done_bound(
        &self,
        done: &ProviderClientDoneReceipt,
    ) -> Result<(), ProviderError>;
}

struct GrantSlots {
    provider: BoundGrantProviderSlot,
    redactor: ObservationRedactorSlot,
    detector: LeakDetectorSlot,
}

pub(crate) fn register(
    api: &mut ClientApi,
    provider: BoundGrantProviderSlot,
    redactor: ObservationRedactorSlot,
    detector: LeakDetectorSlot,
) {
    let slots = Arc::new(GrantSlots {
        provider,
        redactor,
        detector,
    });

    let list = Arc::clone(&slots);
    api.register(
        Method::Get,
        routes::PATH_GRANTS_PENDING,
        HandlerSpec::read_with_warnings(true, move |_ctx| list_pending(&list))
            .with_scopes(vec![Scope::ApproveGrants]),
    );

    register_decision(
        api,
        &slots,
        routes::TPL_GRANT_APPROVE,
        DecisionAction::Approve,
    );
    register_decision(api, &slots, routes::TPL_GRANT_DENY, DecisionAction::Deny);
    register_decision(
        api,
        &slots,
        routes::TPL_GRANT_NARROW,
        DecisionAction::Narrow,
    );

    let revoke = Arc::clone(&slots);
    api.register_templated(
        Method::Post,
        routes::TPL_GRANT_REVOKE,
        HandlerSpec::mutation_with_warnings(true, move |ctx| {
            let grant_id = ctx.path_param("grant_id")?;
            parse_empty_body(&ctx.body)?;
            mutate(
                ctx,
                &revoke,
                BoundGrantMutation::Revoke { grant_id },
                MutationResponse::Revoke,
            )
        })
        .with_scopes(vec![Scope::ApproveGrants]),
    );

    let preset = Arc::clone(&slots);
    api.register_templated(
        Method::Post,
        routes::TPL_PRESET_APPLY,
        HandlerSpec::mutation_with_warnings(true, move |ctx| {
            let preset_name = ctx.path_param("preset")?;
            let body: ClientPresetApplyRequest = strict_body(&ctx.body, "invalid preset body")?;
            if body.target_agent_id.is_empty() {
                return Err(invalid_body("invalid preset body"));
            }
            mutate(
                ctx,
                &preset,
                BoundGrantMutation::ApplyPreset {
                    target_agent_id: body.target_agent_id,
                    preset: preset_name,
                },
                MutationResponse::Preset,
            )
        })
        .with_scopes(vec![Scope::ApproveGrants]),
    );
}

#[derive(Clone, Copy)]
enum DecisionAction {
    Approve,
    Deny,
    Narrow,
}

fn register_decision(
    api: &mut ClientApi,
    slots: &Arc<GrantSlots>,
    template: &str,
    action: DecisionAction,
) {
    let slots = Arc::clone(slots);
    api.register_templated(
        Method::Post,
        template,
        HandlerSpec::mutation_with_warnings(true, move |ctx| {
            let request_id = ctx.path_param("request_id")?;
            let mutation = match action {
                DecisionAction::Approve => {
                    let body: ClientGrantApproveRequest =
                        strict_body(&ctx.body, "invalid grant approval body")?;
                    validate_decision_revision(&body.decision_revision)?;
                    BoundGrantMutation::Approve {
                        request_id,
                        decision_revision: body.decision_revision,
                    }
                }
                DecisionAction::Deny => {
                    let body: ClientGrantDenyRequest =
                        strict_body(&ctx.body, "invalid grant denial body")?;
                    if body.reason.is_empty() || body.reason.len() > MAX_DENY_REASON_BYTES {
                        return Err(invalid_body("invalid grant denial body"));
                    }
                    validate_decision_revision(&body.decision_revision)?;
                    BoundGrantMutation::Deny {
                        request_id,
                        decision_revision: body.decision_revision,
                        reason: body.reason,
                    }
                }
                DecisionAction::Narrow => {
                    let body: ClientGrantNarrowRequest =
                        strict_body(&ctx.body, "invalid grant narrow body")?;
                    validate_decision_revision(&body.decision_revision)?;
                    validate_params(&body.params)?;
                    BoundGrantMutation::Narrow {
                        request_id,
                        decision_revision: body.decision_revision,
                        params: body.params,
                    }
                }
            };
            mutate(ctx, &slots, mutation, MutationResponse::Decision)
        })
        .with_scopes(vec![Scope::ApproveGrants]),
    );
}

fn list_pending(slots: &GrantSlots) -> Result<HandlerResponse, ClientError> {
    let provider = provider_or_unavailable(&slots.provider)?;
    let redactor = provider_or_unavailable(&slots.redactor)?;
    let detector = provider_or_unavailable(&slots.detector)?;
    let documents = provider
        .list_pending_bound()
        .map_err(ProviderError::into_client_error)?;

    let mut requests = Vec::with_capacity(documents.len());
    let mut warnings = Vec::new();
    for bound in documents {
        let document = Projectable::<ClientPendingGrant>::from_bound(bound).redact(&redactor)?;
        let mut request = decode_pending(&document)?;
        scan_pending(&mut request, detector.as_ref(), &mut warnings)?;
        requests.push(request);
    }
    Ok(HandlerResponse::with_warnings(
        json!({ "requests": requests }),
        warnings,
    ))
}

#[derive(Clone, Copy)]
pub(crate) enum MutationResponse {
    Decision,
    Revoke,
    Preset,
}

fn mutate(
    ctx: &HandlerCtx,
    slots: &GrantSlots,
    mutation: BoundGrantMutation,
    response_kind: MutationResponse,
) -> Result<HandlerResponse, ClientError> {
    let admitted = ctx.mutation.as_ref().ok_or_else(|| {
        ClientError::new(
            ClientErrorCode::ModuleUnavailable,
            "mutation correlation unavailable",
        )
    })?;
    let provider = provider_or_unavailable(&slots.provider)?;
    let redactor = provider_or_unavailable(&slots.redactor)?;
    let detector = provider_or_unavailable(&slots.detector)?;
    let operation_tag = mutation.operation_tag();
    let mutation_id = admitted.mutation_id();
    let fingerprint = admitted.request_fingerprint();

    admitted.mark_provider_entry()?;
    let recovery = match provider.prepare_mutation_bound(mutation_id, fingerprint, mutation) {
        ProviderPrepareOutcome::Prepared(recovery) => recovery,
        ProviderPrepareOutcome::Rejected(error) => return Err(error.into_client_error()),
    };
    provider
        .verify_recovery_ticket_bound(mutation_id, fingerprint, operation_tag, &recovery)
        .map_err(ProviderError::into_client_error)?;
    admitted.store_prepared_ticket(&recovery)?;

    admitted.mark_recovering(None)?;
    let outcome = match provider.execute_prepared_bound(&recovery) {
        BoundMutationOutcome::OutcomeUnknown(next) => {
            provider
                .verify_recovery_ticket_bound(mutation_id, fingerprint, operation_tag, &next)
                .map_err(ProviderError::into_client_error)?;
            admitted.mark_recovering(Some(&next))?;
            provider.recover_mutation_bound(&next)
        }
        outcome => outcome,
    };
    let bound = match outcome {
        BoundMutationOutcome::Committed(document) => {
            admitted.mark_provider_terminal();
            document
        }
        BoundMutationOutcome::Rejected(error) => {
            admitted.mark_provider_terminal();
            return Err(error.into_client_error());
        }
        BoundMutationOutcome::OutcomeUnknown(next) => {
            provider
                .verify_recovery_ticket_bound(mutation_id, fingerprint, operation_tag, &next)
                .map_err(ProviderError::into_client_error)?;
            admitted.mark_recovering(Some(&next))?;
            return Err(ClientError::new(
                ClientErrorCode::ModuleUnavailable,
                "provider outcome recovery pending",
            ));
        }
    };
    project_mutation_document(bound, redactor.as_ref(), detector.as_ref(), response_kind)
}

pub(crate) fn project_mutation_document(
    bound: BoundObservationDocument,
    redactor: &SensitiveObservationRedactor,
    detector: &dyn LeakDetector,
    response_kind: MutationResponse,
) -> Result<HandlerResponse, ClientError> {
    let document = Projectable::<Value>::from_bound(bound).redact(redactor)?;
    let mut warnings = Vec::new();
    let data = match response_kind {
        MutationResponse::Decision => {
            let decision = decode_decision(&document)?;
            serde_json::to_value(decision).expect("decision serializes")
        }
        MutationResponse::Revoke => {
            let result = decode_revoke(&document)?;
            serde_json::to_value(result).expect("revoke serializes")
        }
        MutationResponse::Preset => {
            let mut result = decode_preset(&document)?;
            scan_text(
                &mut result.target_agent_id,
                detector,
                "target_agent_id",
                false,
                &mut warnings,
            )?;
            serde_json::to_value(result).expect("preset serializes")
        }
    };
    Ok(HandlerResponse::with_warnings(data, warnings))
}

pub(crate) fn decode_canonical_grant_mutation(
    bytes: &[u8],
) -> Result<(BoundGrantMutation, MutationResponse), ClientError> {
    struct Reader<'a> {
        bytes: &'a [u8],
        at: usize,
    }
    impl<'a> Reader<'a> {
        fn take(&mut self, len: usize) -> Result<&'a [u8], ClientError> {
            let end = self
                .at
                .checked_add(len)
                .filter(|end| *end <= self.bytes.len())
                .ok_or_else(projection_error)?;
            let value = &self.bytes[self.at..end];
            self.at = end;
            Ok(value)
        }
        fn u16(&mut self) -> Result<u16, ClientError> {
            Ok(u16::from_be_bytes(
                self.take(2)?.try_into().map_err(|_| projection_error())?,
            ))
        }
        fn u32(&mut self) -> Result<u32, ClientError> {
            Ok(u32::from_be_bytes(
                self.take(4)?.try_into().map_err(|_| projection_error())?,
            ))
        }
        fn text(&mut self) -> Result<String, ClientError> {
            let len = self.u32()? as usize;
            String::from_utf8(self.take(len)?.to_vec()).map_err(|_| projection_error())
        }
        fn finish(&self) -> Result<(), ClientError> {
            if self.at == self.bytes.len() {
                Ok(())
            } else {
                Err(projection_error())
            }
        }
    }

    let mut reader = Reader { bytes, at: 0 };
    if reader.take(1)? != [1] || reader.text()? != API_VERSION || reader.text()? != "POST" {
        return Err(projection_error());
    }
    let route = reader.text()?;
    let path_count = reader.u32()? as usize;
    if path_count != 1 {
        return Err(projection_error());
    }
    let path_name = reader.text()?;
    let path_value = reader.text()?;
    if reader.u32()? != 0 {
        return Err(projection_error());
    }
    let body_tag = reader.u16()?;
    let body_len = reader.u32()? as usize;
    let body = reader.take(body_len)?;
    reader.finish()?;
    let mut body = Reader { bytes: body, at: 0 };
    let decoded = match (route.as_str(), path_name.as_str(), body_tag) {
        (routes::TPL_GRANT_APPROVE, "request_id", 1) => {
            let revision = body.text()?;
            validate_decision_revision(&revision)?;
            (
                BoundGrantMutation::Approve {
                    request_id: path_value,
                    decision_revision: revision,
                },
                MutationResponse::Decision,
            )
        }
        (routes::TPL_GRANT_DENY, "request_id", 2) => {
            let revision = body.text()?;
            let reason = body.text()?;
            validate_decision_revision(&revision)?;
            if reason.is_empty() || reason.len() > MAX_DENY_REASON_BYTES {
                return Err(projection_error());
            }
            (
                BoundGrantMutation::Deny {
                    request_id: path_value,
                    decision_revision: revision,
                    reason,
                },
                MutationResponse::Decision,
            )
        }
        (routes::TPL_GRANT_NARROW, "request_id", 3) => {
            let revision = body.text()?;
            validate_decision_revision(&revision)?;
            let count = body.u32()? as usize;
            if count > MAX_NARROW_PARAMS {
                return Err(projection_error());
            }
            let mut params = Vec::with_capacity(count);
            for _ in 0..count {
                params.push(ClientCapParam {
                    key: body.text()?,
                    value: body.text()?,
                });
            }
            validate_params(&params)?;
            (
                BoundGrantMutation::Narrow {
                    request_id: path_value,
                    decision_revision: revision,
                    params,
                },
                MutationResponse::Decision,
            )
        }
        (routes::TPL_GRANT_REVOKE, "grant_id", 0) if body_len == 0 => (
            BoundGrantMutation::Revoke {
                grant_id: path_value,
            },
            MutationResponse::Revoke,
        ),
        (routes::TPL_PRESET_APPLY, "preset", 5) => (
            BoundGrantMutation::ApplyPreset {
                target_agent_id: body.text()?,
                preset: path_value,
            },
            MutationResponse::Preset,
        ),
        _ => return Err(projection_error()),
    };
    body.finish()?;
    Ok(decoded)
}

fn strict_body<T: for<'de> Deserialize<'de>>(
    body: &Value,
    message: &'static str,
) -> Result<T, ClientError> {
    serde_json::from_value(body.clone()).map_err(|_| invalid_body(message))
}

fn parse_empty_body(body: &Value) -> Result<(), ClientError> {
    if body.is_null() || body.as_object().is_some_and(|object| object.is_empty()) {
        Ok(())
    } else {
        Err(invalid_body("invalid grant revoke body"))
    }
}

fn invalid_body(message: &'static str) -> ClientError {
    ClientError::new(ClientErrorCode::ProjectionRejected, message)
}

fn validate_decision_revision(revision: &str) -> Result<(), ClientError> {
    if revision.len() != 247 {
        return Err(invalid_body("invalid decision revision"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(revision)
        .map_err(|_| invalid_body("invalid decision revision"))?;
    if bytes.len() != 185 || URL_SAFE_NO_PAD.encode(&bytes) != revision {
        return Err(invalid_body("invalid decision revision"));
    }
    Ok(())
}

fn validate_params(params: &[ClientCapParam]) -> Result<(), ClientError> {
    if params.len() > MAX_NARROW_PARAMS {
        return Err(invalid_body("invalid grant narrow body"));
    }
    let mut total = 0usize;
    for param in params {
        if param.key.is_empty()
            || param.key.len() > MAX_PARAM_KEY_BYTES
            || param.value.len() > MAX_PARAM_VALUE_BYTES
        {
            return Err(invalid_body("invalid grant narrow body"));
        }
        total = total
            .checked_add(param.key.len())
            .and_then(|value| value.checked_add(param.value.len()))
            .ok_or_else(|| invalid_body("invalid grant narrow body"))?;
    }
    if total > MAX_PARAMS_TOTAL_BYTES {
        return Err(invalid_body("invalid grant narrow body"));
    }
    Ok(())
}

fn projection_error() -> ClientError {
    ClientError::new(
        ClientErrorCode::ProjectionRejected,
        "provider document schema rejected",
    )
}

fn decode_pending(document: &ObservationDocument) -> Result<ClientPendingGrant, ClientError> {
    let values = exact_object(
        document.provider_root().ok_or_else(projection_error)?,
        &[
            "kind",
            "request_id",
            "decision_revision",
            "caller_id",
            "capability",
            "params",
            "ttl",
            "justification",
        ],
    )?;
    expect_string(values[0], "pending_grant")?;
    Ok(ClientPendingGrant {
        request_id: string(values[1])?,
        decision_revision: string(values[2])?,
        caller_id: string(values[3])?,
        capability: string(values[4])?,
        params: nullable_params(values[5])?,
        ttl: decode_ttl(values[6])?,
        justification: nullable_string(values[7])?,
    })
}

fn decode_decision(document: &ObservationDocument) -> Result<ClientGrantDecision, ClientError> {
    let values = exact_object(
        document.provider_root().ok_or_else(projection_error)?,
        &["kind", "request_id", "status"],
    )?;
    expect_string(values[0], "grant_decision")?;
    let status = string(values[2])?;
    if !matches!(status.as_str(), "approved" | "denied" | "narrowed") {
        return Err(projection_error());
    }
    Ok(ClientGrantDecision {
        request_id: string(values[1])?,
        status,
    })
}

fn decode_revoke(document: &ObservationDocument) -> Result<ClientGrantRevokeResult, ClientError> {
    let values = exact_object(
        document.provider_root().ok_or_else(projection_error)?,
        &["kind", "grant_id", "status", "revoked_count"],
    )?;
    expect_string(values[0], "grant_revoke")?;
    expect_string(values[2], "revoked")?;
    Ok(ClientGrantRevokeResult {
        grant_id: string(values[1])?,
        status: "revoked".into(),
        revoked_count: u64_number(values[3])?,
    })
}

fn decode_preset(document: &ObservationDocument) -> Result<ClientPresetApplyResult, ClientError> {
    let values = exact_object(
        document.provider_root().ok_or_else(projection_error)?,
        &[
            "kind",
            "preset",
            "target_agent_id",
            "status",
            "created_grant_ids",
        ],
    )?;
    expect_string(values[0], "preset_apply")?;
    expect_string(values[3], "applied")?;
    let ids = match values[4] {
        ObservationNode::Array(values) => values.iter().map(string).collect::<Result<_, _>>()?,
        _ => return Err(projection_error()),
    };
    Ok(ClientPresetApplyResult {
        preset: string(values[1])?,
        target_agent_id: string(values[2])?,
        status: "applied".into(),
        created_grant_ids: ids,
    })
}

fn decode_ttl(node: &ObservationNode) -> Result<ClientGrantTtl, ClientError> {
    let ObservationNode::Object(fields) = node else {
        return Err(projection_error());
    };
    match fields.as_slice() {
        [(kind, ObservationNode::String(value))] if kind == "kind" => match value.as_str() {
            "once" => Ok(ClientGrantTtl::Once),
            "lifecycle" => Ok(ClientGrantTtl::Lifecycle),
            "persistent" => Ok(ClientGrantTtl::Persistent),
            _ => Err(projection_error()),
        },
        [(kind, ObservationNode::String(value)), (name, ObservationNode::String(milliseconds))]
            if kind == "kind" && value == "duration" && name == "milliseconds_u64" =>
        {
            let parsed = milliseconds
                .parse::<u64>()
                .map_err(|_| projection_error())?;
            if parsed.to_string() != *milliseconds {
                return Err(projection_error());
            }
            Ok(ClientGrantTtl::Duration {
                milliseconds_u64: milliseconds.clone(),
            })
        }
        [(kind, ObservationNode::String(value)), (name, ObservationNode::String(at))]
            if kind == "kind" && value == "until" && name == "at" =>
        {
            chrono::DateTime::parse_from_rfc3339(at).map_err(|_| projection_error())?;
            Ok(ClientGrantTtl::Until { at: at.clone() })
        }
        _ => Err(projection_error()),
    }
}

fn exact_object<'a>(
    node: &'a ObservationNode,
    names: &[&str],
) -> Result<Vec<&'a ObservationNode>, ClientError> {
    let ObservationNode::Object(fields) = node else {
        return Err(projection_error());
    };
    if fields.len() != names.len()
        || fields
            .iter()
            .zip(names)
            .any(|((actual, _), expected)| actual != expected)
    {
        return Err(projection_error());
    }
    Ok(fields.iter().map(|(_, value)| value).collect())
}

fn string(node: &ObservationNode) -> Result<String, ClientError> {
    match node {
        ObservationNode::String(value) => Ok(value.clone()),
        _ => Err(projection_error()),
    }
}

fn expect_string(node: &ObservationNode, expected: &str) -> Result<(), ClientError> {
    match node {
        ObservationNode::String(value) if value == expected => Ok(()),
        _ => Err(projection_error()),
    }
}

fn nullable_string(node: &ObservationNode) -> Result<Option<String>, ClientError> {
    match node {
        ObservationNode::Null => Ok(None),
        ObservationNode::String(value) => Ok(Some(value.clone())),
        _ => Err(projection_error()),
    }
}

fn nullable_params(node: &ObservationNode) -> Result<Option<Vec<ClientCapParam>>, ClientError> {
    match node {
        ObservationNode::Null => Ok(None),
        ObservationNode::CanonicalCapParams(values) => Ok(Some(
            values.iter().map(cap_param).collect::<Result<_, _>>()?,
        )),
        _ => Err(projection_error()),
    }
}

fn cap_param(param: &CanonicalCapParam) -> Result<ClientCapParam, ClientError> {
    Ok(ClientCapParam {
        key: param.key.clone(),
        value: string(&param.value)?,
    })
}

fn u64_number(node: &ObservationNode) -> Result<u64, ClientError> {
    match node {
        ObservationNode::Number(value) => {
            let number = value.parse::<u64>().map_err(|_| projection_error())?;
            if number.to_string() == *value {
                Ok(number)
            } else {
                Err(projection_error())
            }
        }
        _ => Err(projection_error()),
    }
}

fn scan_pending(
    pending: &mut ClientPendingGrant,
    detector: &dyn LeakDetector,
    warnings: &mut Vec<ClientWarning>,
) -> Result<(), ClientError> {
    if let Some(justification) = pending.justification.as_mut() {
        scan_text(justification, detector, "justification", true, warnings)?;
    }
    if let Some(params) = pending.params.as_mut() {
        for (index, param) in params.iter_mut().enumerate() {
            scan_text(
                &mut param.value,
                detector,
                &format!("params[{index}].value"),
                false,
                warnings,
            )?;
        }
    }
    Ok(())
}

pub(crate) fn scan_text(
    text: &mut String,
    detector: &dyn LeakDetector,
    field: &str,
    strip_cf: bool,
    warnings: &mut Vec<ClientWarning>,
) -> Result<(), ClientError> {
    if strip_cf {
        let (display, removed) = strip_format_controls(text);
        *text = display;
        if removed > 0 {
            warnings.push(ClientWarning::new(
                "unicode_format_removed",
                format!("format controls removed from {field}; count={removed}"),
            ));
        }
    }
    match detector.scan(text, ScanContext::LogOutput) {
        ScanResult::Clean => Ok(()),
        ScanResult::Redacted { redacted, .. } => {
            *text = redacted;
            warnings.push(ClientWarning::new(
                "sensitive_value_redacted",
                format!("sensitive value redacted at {field}"),
            ));
            Ok(())
        }
        ScanResult::Warned { .. } => {
            warnings.push(ClientWarning::new(
                "sensitive_value_warning",
                format!("sensitive value warning at {field}"),
            ));
            Ok(())
        }
        ScanResult::Blocked { .. } => Err(ClientError::new(
            ClientErrorCode::ProjectionRejected,
            "client projection rejected",
        )),
    }
}

fn strip_format_controls(text: &str) -> (String, usize) {
    let mut removed = 0usize;
    let display = text
        .chars()
        .filter(|character| {
            let cp = *character as u32;
            let is_format = matches!(cp,
                0x00AD | 0x061C | 0x06DD | 0x070F | 0x0890..=0x0891 | 0x08E2 |
                0x180E | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 |
                0x2066..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD |
                0x13430..=0x1343F | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A |
                0xE0001 | 0xE0020..=0xE007F
            );
            if is_format {
                removed += 1;
                false
            } else {
                true
            }
        })
        .collect();
    (display, removed)
}

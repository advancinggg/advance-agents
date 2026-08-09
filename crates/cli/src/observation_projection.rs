//! CONTRACT-219 composition for EventBus observation output.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use advance_event_bus::{Event, ObservationProjection, ObservationProjector};
use advance_scheduler::sensitive_params::RegistrySensitiveParamProvider;
use advance_shared_types::contract218_previsible::{
    AgentPublicationResult, PrevisibleProofIssuerRole,
};
use advance_shared_types::observation_identity::{
    AgentObservationIdentityRegistrar, HostEmitterId, HostObservationIdentityRegistrar,
    IssuedObservationSourceHandle, ObservationIdentityAuthority,
    ObservationIdentityPersistenceSealer, PersistedObservationBinding,
    PersistedObservationIdentity, SensitiveParamCatalog,
};
use advance_shared_types::sensitive_observation::{
    BoundObservationDocument, CanonicalCapParam, CanonicalContainerDeclaration,
    CanonicalContainerKind, ObservationAssociationRoleFactory, ObservationAssociationRoleParts,
    ObservationDocument, ObservationEventAssociationIssuer, ObservationNode,
    ObservationPathSegment, ObservationProviderDtoAssociationIssuer, ObservationSchemaDocumentKind,
    ObservationSchemaManifest, ObservationSchemaRoot, RedactionDisposition,
    SensitiveObservationRedactor, STRUCTURAL_EVENT_SCHEMA_ID,
};
use cap_http::DefaultSensitiveObservationRedactor;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::observation_carriers::ObservationCarrierStore;

const LEGACY3_RESULT_SCHEMA: &str = "advance.run-completed.legacy3-sensitive.v1";
pub const LEGACY3_HISTORY_SCHEMA: &str = "advance.client.history.legacy3.v1";
pub const LEGACY3_PENDING_GRANT_SCHEMA: &str = "advance.client.pending-grant.legacy3.v1";

/// Production C219 boundary. The non-clone issuer and sealed redactor stay in
/// this object; callers can only refresh authenticated sources or request an
/// EventBus projection.
pub struct Contract219EventProjector {
    provider: Arc<RegistrySensitiveParamProvider>,
    ready_issuer: Arc<PrevisibleProofIssuerRole>,
    event_issuer: Arc<ObservationEventAssociationIssuer>,
    provider_issuer: Arc<ObservationProviderDtoAssociationIssuer>,
    redactor: Arc<SensitiveObservationRedactor>,
    carrier_store: Arc<ObservationCarrierStore>,
    sources: RwLock<HashMap<String, IssuedObservationSourceHandle>>,
}

impl std::fmt::Debug for Contract219EventProjector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Contract219EventProjector(<sealed C218/C219 authority>)")
    }
}

impl Contract219EventProjector {
    pub async fn build(
        provider: Arc<RegistrySensitiveParamProvider>,
        ready_issuer: Arc<PrevisibleProofIssuerRole>,
        boot_id: [u8; 16],
        carrier_store: Arc<ObservationCarrierStore>,
    ) -> Result<Arc<Self>, String> {
        let mut association_key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(association_key.as_mut());
        if association_key.as_ref() == &[0; 32] {
            return Err("CSPRNG returned a zero CONTRACT-219 association key".to_owned());
        }
        let roles = ObservationAssociationRoleFactory::new_at_composition(
            association_key,
            boot_id,
            vec![
                legacy3_result_schema()?,
                legacy3_history_schema()?,
                legacy3_pending_grant_schema()?,
            ],
        )
        .map_err(|error| format!("construct CONTRACT-219 roles: {error}"))?
        .split_once()
        .map_err(|error| format!("split CONTRACT-219 roles: {error}"))?;
        let ObservationAssociationRoleParts {
            event_issuer,
            provider_issuer,
            verifier,
            provider: association_provider,
        } = roles;

        let catalog: Arc<dyn SensitiveParamCatalog> = provider.clone();
        let authority: Arc<dyn ObservationIdentityAuthority> = provider.clone();
        let redactor = DefaultSensitiveObservationRedactor::new(catalog, authority)
            .bind(association_provider, verifier)
            .map_err(|error| format!("bind CONTRACT-219 redactor: {error}"))?;
        let projector = Arc::new(Self {
            provider,
            ready_issuer,
            event_issuer: Arc::new(event_issuer),
            provider_issuer: Arc::new(provider_issuer),
            redactor: Arc::new(redactor),
            carrier_store,
            sources: RwLock::new(HashMap::new()),
        });

        for emitter in [
            HostEmitterId::Runtime,
            HostEmitterId::RetentionSweeper,
            HostEmitterId::PackManager,
        ] {
            projector
                .provider
                .register_host(emitter)
                .map_err(|error| format!("register C219 host {emitter:?}: {error:?}"))?;
        }
        projector.refresh_sources().await?;
        Ok(projector)
    }

    pub fn redactor(&self) -> Arc<SensitiveObservationRedactor> {
        Arc::clone(&self.redactor)
    }

    /// Reconstruct a persisted authority carrier and bind a typed public
    /// history document. Authority is still verified only by the sealed
    /// redactor; decoding here grants no capability.
    pub fn bind_persisted_history(
        &self,
        carrier: &[u8],
        envelope: ObservationNode,
        payload: ObservationNode,
    ) -> Result<BoundObservationDocument, String> {
        let persisted = PersistedObservationIdentity::decode_unverified_canonical(carrier)
            .map_err(|error| format!("decode C218 history carrier: {error:?}"))?;
        let observed = persisted.persisted_binding();
        let document = self
            .event_issuer
            .stamp_persisted_event(
                &persisted,
                &observed,
                LEGACY3_HISTORY_SCHEMA,
                envelope,
                payload,
            )
            .map_err(|error| format!("stamp C219 history document: {error}"))?;
        self.event_issuer
            .bind_persisted_event(persisted, observed, document)
            .map_err(|error| format!("bind C219 history document: {error}"))
    }

    /// Bind one CONTRACT-123 pending-grant DTO to the exact caller identity.
    pub fn bind_pending_grant(
        &self,
        exact_caller_id: &str,
        root: ObservationNode,
    ) -> Result<BoundObservationDocument, String> {
        let identity = self.mint_live_identity_for(exact_caller_id)?;
        let (subject, document) = self
            .provider_issuer
            .stamp_live_provider_dto(identity, LEGACY3_PENDING_GRANT_SCHEMA, root)
            .map_err(|error| format!("stamp C219 pending-grant DTO: {error}"))?;
        self.provider_issuer
            .bind_live_provider_dto(subject, document)
            .map_err(|error| format!("bind C219 pending-grant DTO: {error}"))
    }

    /// Register and publish a live agent identity before its first event. The
    /// provider's journal makes a repeated operation/id pair idempotent.
    pub async fn register_agent(&self, exact_agent_id: &str) -> Result<(), String> {
        let operation_id = format!("contract219-agent-{}", uuid::Uuid::new_v4().simple());
        self.provider
            .begin_agent_registration(&operation_id, exact_agent_id)
            .map_err(|error| format!("begin C219 agent registration: {error:?}"))?;
        let activation = self
            .provider
            .activate_agent_unpublished(&operation_id)
            .map_err(|error| format!("activate C219 agent identity: {error:?}"))?;
        let receipts = self
            .ready_issuer
            .issue_composition_ready_receipts(&activation)
            .map_err(|error| format!("collect C219 ready receipts: {error:?}"))?;
        let ready = self
            .ready_issuer
            .issue_ready_proof(&activation, receipts)
            .map_err(|error| format!("issue C219 ready proof: {error:?}"))?;
        let mut result = self.provider.publish_agent_activation(activation, ready);
        loop {
            result = match result {
                AgentPublicationResult::Published(_) => break,
                AgentPublicationResult::Rejected(_) => {
                    return Err("C219 agent publication was rejected".to_owned())
                }
                AgentPublicationResult::OutcomeUnknown(recovery) => {
                    self.provider.recover_agent_publication(recovery)
                }
            };
        }
        self.refresh_sources().await
    }

    pub async fn refresh_sources(&self) -> Result<(), String> {
        let receipt = self
            .provider
            .issue_completed_hydration_receipt()
            .await
            .map_err(|error| format!("issue C218 hydration receipt: {error}"))?;
        let issued = self
            .provider
            .reissue_boot_sources(&receipt)
            .map_err(|error| format!("reissue C218 observation sources: {error:?}"))?;
        let mut next = HashMap::with_capacity(issued.len());
        for source in issued {
            if next
                .insert(source.canonical_id().to_owned(), source)
                .is_some()
            {
                return Err("duplicate C218 source id during hydration".to_owned());
            }
        }
        *self
            .sources
            .write()
            .map_err(|_| "C219 source table lock is poisoned".to_owned())? = next;
        Ok(())
    }

    fn mint_live_identity_for(
        &self,
        exact_id: &str,
    ) -> Result<advance_shared_types::observation_identity::TrustedObservationIdentity, String>
    {
        let sources = self
            .sources
            .read()
            .map_err(|_| "C219 source table lock is poisoned".to_owned())?;
        let source = sources
            .get(exact_id)
            .ok_or_else(|| "unknown C219 observation source".to_owned())?;
        self.provider
            .mint_live_identity(source.handle())
            .map_err(|error| format!("mint C218 live identity: {error:?}"))
    }

    fn project_bound(&self, event: &Event) -> Result<Event, String> {
        let identity = self.mint_live_identity_for(&event.agent_id)?;

        let canonical_event = serde_json::to_vec(event)
            .map_err(|error| format!("encode safe event digest: {error}"))?;
        let safe_digest: [u8; 32] = Sha256::digest(canonical_event).into();
        let persisted_binding =
            PersistedObservationBinding::new(event.id.clone(), event.id.clone(), safe_digest)
                .map_err(|error| format!("construct C218 persisted binding: {error:?}"))?;
        let persisted = self
            .provider
            .seal_persisted_identity(&identity, &persisted_binding)
            .map_err(|error| format!("seal C218 persisted identity: {error:?}"))?;

        let (schema, payload) = if let Some(payload) = legacy3_payload_node(&event.payload) {
            (LEGACY3_RESULT_SCHEMA, payload)
        } else {
            (STRUCTURAL_EVENT_SCHEMA_ID, json_to_node(&event.payload)?)
        };
        let envelope_value = event_envelope_value(event)?;
        let envelope = json_to_node(&envelope_value)?;
        let (lease, document) = self
            .event_issuer
            .stamp_live_event(identity, schema, envelope, payload)
            .map_err(|error| format!("stamp C219 live event: {error}"))?;
        let bound = self
            .event_issuer
            .bind_live_final_event(&lease, safe_digest, document)
            .map_err(|error| format!("bind C219 live event: {error}"))?;
        match self.redactor.redact_bound_observation(bound) {
            RedactionDisposition::Redacted(document) => {
                let projected = event_from_document(event, document)?;
                self.carrier_store
                    .put(&event.id, persisted.canonical_bytes())
                    .map_err(|error| format!("persist C218 observation carrier: {error}"))?;
                Ok(projected)
            }
            RedactionDisposition::Blocked { reason } => {
                Err(format!("C219 redaction blocked: {reason:?}"))
            }
        }
    }
}

impl ObservationProjector for Contract219EventProjector {
    fn project(&self, event: &Event) -> ObservationProjection {
        match self.project_bound(event) {
            Ok(projected) if projected == *event => ObservationProjection::Unchanged,
            Ok(projected) => ObservationProjection::Redacted(projected),
            Err(_) => ObservationProjection::Blocked,
        }
    }
}

fn legacy3_result_schema() -> Result<ObservationSchemaManifest, String> {
    let member = |name: &str| ObservationPathSegment::Member(name.to_owned());
    let named = |path: Vec<ObservationPathSegment>, keys: &[&str]| {
        CanonicalContainerDeclaration::new(
            ObservationSchemaRoot::EventPayload,
            path,
            CanonicalContainerKind::NamedParams,
            keys.iter().map(|value| (*value).to_owned()).collect(),
        )
        .map_err(|error| format!("construct C219 named schema declaration: {error}"))
    };
    let cap = CanonicalContainerDeclaration::new(
        ObservationSchemaRoot::EventPayload,
        vec![member("result"), member("cap_params")],
        CanonicalContainerKind::CapParams,
        vec!["api_key".to_owned(), "id".to_owned()],
    )
    .map_err(|error| format!("construct C219 cap schema declaration: {error}"))?;
    ObservationSchemaManifest::new(
        LEGACY3_RESULT_SCHEMA.to_owned(),
        ObservationSchemaDocumentKind::Event,
        vec![
            named(
                vec![member("result"), member("named_params")],
                &["api_key", "event_type", "id", "run_id"],
            )?,
            named(
                vec![
                    member("result"),
                    member("nested"),
                    ObservationPathSegment::Index(0),
                    member("named_params"),
                ],
                &["api_key"],
            )?,
            cap,
        ],
    )
    .map_err(|error| format!("construct C219 event schema: {error}"))
}

fn legacy3_history_schema() -> Result<ObservationSchemaManifest, String> {
    ObservationSchemaManifest::new(
        LEGACY3_HISTORY_SCHEMA.to_owned(),
        ObservationSchemaDocumentKind::Event,
        vec![CanonicalContainerDeclaration::new(
            ObservationSchemaRoot::EventPayload,
            vec![ObservationPathSegment::Member("params".to_owned())],
            CanonicalContainerKind::CapParams,
            vec![
                "api_key".to_owned(),
                "event_type".to_owned(),
                "id".to_owned(),
                "run_id".to_owned(),
            ],
        )
        .map_err(|error| format!("construct C219 history schema declaration: {error}"))?],
    )
    .map_err(|error| format!("construct C219 history schema: {error}"))
}

fn legacy3_pending_grant_schema() -> Result<ObservationSchemaManifest, String> {
    ObservationSchemaManifest::new(
        LEGACY3_PENDING_GRANT_SCHEMA.to_owned(),
        ObservationSchemaDocumentKind::ProviderDto,
        vec![CanonicalContainerDeclaration::new(
            ObservationSchemaRoot::ProviderRoot,
            vec![ObservationPathSegment::Member("params".to_owned())],
            CanonicalContainerKind::CapParams,
            vec!["api_key".to_owned()],
        )
        .map_err(|error| format!("construct C219 pending-grant schema declaration: {error}"))?],
    )
    .map_err(|error| format!("construct C219 pending-grant schema: {error}"))
}

fn legacy3_payload_node(payload: &serde_json::Value) -> Option<ObservationNode> {
    let mut root = json_to_node(payload).ok()?;
    let ObservationNode::Object(root_members) = &mut root else {
        return None;
    };
    let result = member_mut(root_members, "result")?;
    let ObservationNode::Object(result_members) = result else {
        return None;
    };

    let named = member_mut(result_members, "named_params")?;
    let ObservationNode::Object(named_members) = named else {
        return None;
    };
    if member_keys(named_members) != ["api_key", "event_type", "id", "run_id"] {
        return None;
    }
    *named = ObservationNode::CanonicalNamedParams(std::mem::take(named_members));

    let nested = member_mut(result_members, "nested")?;
    let ObservationNode::Array(nested_values) = nested else {
        return None;
    };
    let ObservationNode::Object(first_nested) = nested_values.get_mut(0)? else {
        return None;
    };
    let nested_named = member_mut(first_nested, "named_params")?;
    let ObservationNode::Object(nested_named_members) = nested_named else {
        return None;
    };
    if member_keys(nested_named_members) != ["api_key"] {
        return None;
    }
    *nested_named = ObservationNode::CanonicalNamedParams(std::mem::take(nested_named_members));

    let cap = member_mut(result_members, "cap_params")?;
    let ObservationNode::Array(cap_values) = cap else {
        return None;
    };
    let mut canonical = Vec::with_capacity(cap_values.len());
    for value in std::mem::take(cap_values) {
        let ObservationNode::Object(mut fields) = value else {
            return None;
        };
        let key = match take_member(&mut fields, "key")? {
            ObservationNode::String(value) => value,
            _ => return None,
        };
        let value = take_member(&mut fields, "value")?;
        if !fields.is_empty() {
            return None;
        }
        canonical.push(CanonicalCapParam { key, value });
    }
    canonical.sort_by(|left, right| left.key.as_bytes().cmp(right.key.as_bytes()));
    if canonical
        .iter()
        .map(|entry| entry.key.as_str())
        .collect::<Vec<_>>()
        != ["api_key", "id"]
    {
        return None;
    }
    *cap = ObservationNode::CanonicalCapParams(canonical);
    Some(root)
}

fn event_envelope_value(event: &Event) -> Result<serde_json::Value, String> {
    let mut value = serde_json::to_value(event)
        .map_err(|error| format!("encode C219 event envelope: {error}"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "Event did not encode as an object".to_owned())?;
    object.remove("payload");
    Ok(value)
}

fn event_from_document(original: &Event, document: ObservationDocument) -> Result<Event, String> {
    let (_, payload) = document
        .event_parts()
        .ok_or_else(|| "C219 redactor returned a non-event document".to_owned())?;
    let mut event = original.clone();
    event.payload = node_to_json(payload)?;
    Ok(event)
}

fn json_to_node(value: &serde_json::Value) -> Result<ObservationNode, String> {
    Ok(match value {
        serde_json::Value::Null => ObservationNode::Null,
        serde_json::Value::Bool(value) => ObservationNode::Bool(*value),
        serde_json::Value::Number(value) => ObservationNode::Number(value.to_string()),
        serde_json::Value::String(value) => ObservationNode::String(value.clone()),
        serde_json::Value::Array(values) => ObservationNode::Array(
            values
                .iter()
                .map(json_to_node)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        serde_json::Value::Object(values) => {
            let mut members = values
                .iter()
                .map(|(key, value)| Ok((key.clone(), json_to_node(value)?)))
                .collect::<Result<Vec<_>, String>>()?;
            members.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
            ObservationNode::Object(members)
        }
    })
}

fn node_to_json(node: &ObservationNode) -> Result<serde_json::Value, String> {
    Ok(match node {
        ObservationNode::Null => serde_json::Value::Null,
        ObservationNode::Bool(value) => serde_json::Value::Bool(*value),
        ObservationNode::Number(value) => serde_json::from_str(value)
            .map_err(|error| format!("decode canonical C219 number: {error}"))?,
        ObservationNode::String(value) => serde_json::Value::String(value.clone()),
        ObservationNode::Array(values) => serde_json::Value::Array(
            values
                .iter()
                .map(node_to_json)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        ObservationNode::Object(values) | ObservationNode::CanonicalNamedParams(values) => {
            let mut object = serde_json::Map::new();
            for (key, value) in values {
                if object.insert(key.clone(), node_to_json(value)?).is_some() {
                    return Err("duplicate key in C219 redacted output".to_owned());
                }
            }
            serde_json::Value::Object(object)
        }
        ObservationNode::CanonicalCapParams(values) => serde_json::Value::Array(
            values
                .iter()
                .map(|entry| {
                    Ok(serde_json::json!({
                        "key": entry.key,
                        "value": node_to_json(&entry.value)?,
                    }))
                })
                .collect::<Result<Vec<_>, String>>()?,
        ),
    })
}

fn member_mut<'a>(
    members: &'a mut [(String, ObservationNode)],
    name: &str,
) -> Option<&'a mut ObservationNode> {
    members
        .iter_mut()
        .find_map(|(key, value)| (key == name).then_some(value))
}

fn take_member(
    members: &mut Vec<(String, ObservationNode)>,
    name: &str,
) -> Option<ObservationNode> {
    let index = members.iter().position(|(key, _)| key == name)?;
    Some(members.remove(index).1)
}

fn member_keys<const N: usize>(members: &[(String, ObservationNode)]) -> [&str; N] {
    std::array::from_fn(|index| {
        members
            .get(index)
            .map(|entry| entry.0.as_str())
            .unwrap_or("")
    })
}

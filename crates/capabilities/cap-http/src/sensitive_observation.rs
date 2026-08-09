//! Default MODULE-012 implementation for the sealed CONTRACT-219 callable.
//!
//! This is intentionally build-and-hold: the constructor consumes the M012-only provider and
//! verifier roles, but this crate does not wire either issuer into EventBus, CONTRACT-123, or CLI.

use std::collections::HashSet;
use std::sync::Arc;

use advance_shared_types::observation_identity::{
    ObservationIdentityAuthority, SensitiveParamCatalog,
};
use advance_shared_types::sensitive_observation::{
    redacted_marker, validate_redacted_output, AuthorityValidatedObservation, CanonicalCapParam,
    Contract219ProviderRole, ObservationAssociationError, ObservationAssociationVerifierRole,
    ObservationDocument, ObservationNode, RedactionBlockReason, RedactionDisposition,
    SensitiveObservationRedactor, VerifiedBoundObservationDocument,
};

/// Concrete M012 provider.  It never exposes either CONTRACT-218 port or a preverified snapshot;
/// the only public result is the sealed shared-types callable.
pub struct DefaultSensitiveObservationRedactor {
    catalog: Arc<dyn SensitiveParamCatalog>,
    authority: Arc<dyn ObservationIdentityAuthority>,
}

impl std::fmt::Debug for DefaultSensitiveObservationRedactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DefaultSensitiveObservationRedactor(<sealed C218 ports>)")
    }
}

impl DefaultSensitiveObservationRedactor {
    pub fn new(
        catalog: Arc<dyn SensitiveParamCatalog>,
        authority: Arc<dyn ObservationIdentityAuthority>,
    ) -> Self {
        Self { catalog, authority }
    }

    /// Consume the two matching M012-only roles and erase this implementation behind the sealed
    /// CONTRACT-219 callable.  A role from another boot/factory is rejected by shared-types.
    pub fn bind(
        self,
        provider: Contract219ProviderRole,
        verifier: ObservationAssociationVerifierRole,
    ) -> Result<SensitiveObservationRedactor, ObservationAssociationError> {
        let catalog = Arc::clone(&self.catalog);
        let authority = Arc::clone(&self.authority);
        provider.bind_once(verifier, move |verified| {
            redact_verified(verified, catalog.as_ref(), authority.as_ref())
        })
    }
}

fn redact_verified(
    verified: VerifiedBoundObservationDocument,
    catalog: &dyn SensitiveParamCatalog,
    authority: &dyn ObservationIdentityAuthority,
) -> RedactionDisposition {
    // The shared typestate exposes no authority lookup before this full-tree Pass A succeeds.
    let pass_a = match verified.validate_pass_a() {
        Ok(value) => value,
        Err(reason) => return RedactionDisposition::Blocked { reason },
    };
    let authorized = match pass_a.verify_authority(catalog, authority) {
        Ok(value) => value,
        Err(reason) => return RedactionDisposition::Blocked { reason },
    };
    redact_authorized(authorized)
}

fn redact_authorized(authorized: AuthorityValidatedObservation) -> RedactionDisposition {
    let scope = authorized.scope();
    let names: HashSet<String> = authorized.sensitive_names().iter().cloned().collect();
    let document = redact_document(authorized.into_document(), &names);
    match validate_redacted_output(&document, scope) {
        Ok(()) => RedactionDisposition::Redacted(document),
        Err(RedactionBlockReason::ScopeMismatch) => RedactionDisposition::Blocked {
            reason: RedactionBlockReason::ScopeMismatch,
        },
        Err(_) => RedactionDisposition::Blocked {
            reason: RedactionBlockReason::OutputTooLarge,
        },
    }
}

fn redact_document(
    document: ObservationDocument,
    sensitive_names: &HashSet<String>,
) -> ObservationDocument {
    match document.event_parts() {
        Some((envelope, payload)) => document
            .replace_event_parts(
                redact_node(envelope, sensitive_names),
                redact_node(payload, sensitive_names),
            )
            .expect("typed event remains an event"),
        None => document
            .replace_provider_root(redact_node(
                document
                    .provider_root()
                    .expect("typed document is either Event or ProviderDto"),
                sensitive_names,
            ))
            .expect("typed provider document remains a provider document"),
    }
}

fn redact_node(node: &ObservationNode, sensitive_names: &HashSet<String>) -> ObservationNode {
    match node {
        ObservationNode::Null => ObservationNode::Null,
        ObservationNode::Bool(value) => ObservationNode::Bool(*value),
        ObservationNode::Number(value) => ObservationNode::Number(value.clone()),
        ObservationNode::String(value) => ObservationNode::String(value.clone()),
        ObservationNode::Array(values) => ObservationNode::Array(
            values
                .iter()
                .map(|value| redact_node(value, sensitive_names))
                .collect(),
        ),
        ObservationNode::Object(values) => ObservationNode::Object(
            values
                .iter()
                .map(|(name, value)| {
                    // Ordinary structural names are never declaration-selected.
                    (name.clone(), redact_node(value, sensitive_names))
                })
                .collect(),
        ),
        ObservationNode::CanonicalNamedParams(values) => ObservationNode::CanonicalNamedParams(
            values
                .iter()
                .map(|(name, value)| {
                    let redacted = if sensitive_names.contains(name) {
                        ObservationNode::String(redacted_marker().to_owned())
                    } else {
                        redact_node(value, sensitive_names)
                    };
                    (name.clone(), redacted)
                })
                .collect(),
        ),
        ObservationNode::CanonicalCapParams(values) => ObservationNode::CanonicalCapParams(
            values
                .iter()
                .map(|parameter| CanonicalCapParam {
                    key: parameter.key.clone(),
                    value: if sensitive_names.contains(&parameter.key) {
                        ObservationNode::String(redacted_marker().to_owned())
                    } else {
                        redact_node(&parameter.value, sensitive_names)
                    },
                })
                .collect(),
        ),
    }
}

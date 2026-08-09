use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use advance_shared_types::contract218_previsible::{
    PersistedIdentityKeyringRole, PrevisibleProofVerifierRole, SigningKeyCapability,
    VerificationKeyCapability,
};
use advance_shared_types::observation_identity::{
    AuthenticatedObservationSourceHandle, ObservationIdentityAuthority, ObservationIdentityClaims,
    ObservationIdentityClass, PersistedObservationBinding, PersistedObservationIdentity,
    SensitiveParamCatalog, SensitiveParamCatalogError, SensitiveParamDeclaration,
    SensitiveParamSnapshot, SourceBindingDigest, TrustedObservationIdentity,
};
use advance_shared_types::sensitive_observation::{
    BoundObservationDocument, CanonicalCapParam, CanonicalContainerDeclaration,
    CanonicalContainerKind, ObservationAssociationError, ObservationAssociationRoleParts,
    ObservationDocument, ObservationEventAssociationIssuer, ObservationNode,
    ObservationPathSegment, ObservationProviderDtoAssociationIssuer, ObservationSchemaDocumentKind,
    ObservationSchemaManifest, ObservationSchemaRoot, RedactionBlockReason, RedactionDisposition,
    SensitiveObservationRedactor,
};
use advance_shared_types::test_support::{
    contract218_roles, live_final_observation_fixture, live_ingress_observation_fixture,
    observation_association_roles, persisted_event_observation_fixture,
    persisted_identity_keyring_role, provider_dto_observation_fixture,
};
use cap_http::DefaultSensitiveObservationRedactor;

const EVENT_ROOT_SCHEMA: &str = "test.event.root-params.v1";
const EVENT_MIXED_SCHEMA: &str = "test.event.mixed-params.v1";
const PROVIDER_ROOT_SCHEMA: &str = "test.provider.root-params.v1";
const PROVIDER_EXPANSION_SCHEMA: &str = "test.provider.expansion.v1";

#[derive(Clone, Copy)]
enum MockMode {
    Valid,
    Unknown,
    Stale,
    ScopeMismatch,
    WrongSnapshotNames,
}

struct MockC218Ports {
    provider: Arc<PrevisibleProofVerifierRole>,
    keyring: PersistedIdentityKeyringRole,
    signing: SigningKeyCapability,
    verification: VerificationKeyCapability,
    snapshot: SensitiveParamSnapshot,
    mode: MockMode,
    verify_calls: AtomicUsize,
}

impl MockC218Ports {
    fn fail_if_configured(&self) -> Result<(), SensitiveParamCatalogError> {
        match self.mode {
            MockMode::Valid | MockMode::WrongSnapshotNames => Ok(()),
            MockMode::Unknown => Err(SensitiveParamCatalogError::UnknownIdentity),
            MockMode::Stale => Err(SensitiveParamCatalogError::StaleIdentity),
            MockMode::ScopeMismatch => Err(SensitiveParamCatalogError::ScopeMismatch),
        }
    }

    fn response_snapshot(&self) -> SensitiveParamSnapshot {
        let mut snapshot = self.snapshot.clone();
        if matches!(self.mode, MockMode::WrongSnapshotNames) {
            snapshot.names = Arc::from(["wrong_name".to_owned()]);
        }
        snapshot
    }
}

impl SensitiveParamCatalog for MockC218Ports {
    fn lookup(
        &self,
        canonical_component_id: &str,
    ) -> Result<SensitiveParamSnapshot, SensitiveParamCatalogError> {
        self.fail_if_configured()?;
        if canonical_component_id != self.snapshot.canonical_component_id {
            return Err(SensitiveParamCatalogError::UnknownIdentity);
        }
        Ok(self.response_snapshot())
    }

    fn verify(
        &self,
        identity: &TrustedObservationIdentity,
    ) -> Result<SensitiveParamSnapshot, SensitiveParamCatalogError> {
        self.verify_calls.fetch_add(1, Ordering::SeqCst);
        self.fail_if_configured()?;
        self.provider
            .verify_live_identity(identity, &self.snapshot.claims())?;
        Ok(self.response_snapshot())
    }

    fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        tokio::sync::watch::channel(self.snapshot.revision).1
    }
}

impl ObservationIdentityAuthority for MockC218Ports {
    fn mint_live_identity(
        &self,
        source: &AuthenticatedObservationSourceHandle,
    ) -> Result<TrustedObservationIdentity, SensitiveParamCatalogError> {
        self.provider.mint_live_identity(source)
    }

    fn rehydrate_persisted_identity(
        &self,
        persisted: &PersistedObservationIdentity,
    ) -> Result<TrustedObservationIdentity, SensitiveParamCatalogError> {
        self.fail_if_configured()?;
        self.keyring
            .rehydrate_persisted_identity(&self.verification, persisted)
    }

    fn verify_persisted_binding(
        &self,
        identity: &TrustedObservationIdentity,
        persisted: &PersistedObservationIdentity,
        observed: &PersistedObservationBinding,
    ) -> Result<SensitiveParamSnapshot, SensitiveParamCatalogError> {
        self.verify_calls.fetch_add(1, Ordering::SeqCst);
        self.fail_if_configured()?;
        self.keyring.verify_persisted_identity(
            &self.verification,
            identity,
            persisted,
            observed,
            &self.snapshot.claims(),
        )?;
        Ok(self.response_snapshot())
    }

    fn resolve_retained_source_binding(
        &self,
        digest: &SourceBindingDigest,
    ) -> Result<ObservationIdentityClaims, SensitiveParamCatalogError> {
        self.fail_if_configured()?;
        let claims = self.snapshot.claims();
        if self.provider.source_binding_digest(&claims)? != *digest {
            return Err(SensitiveParamCatalogError::UnknownIdentity);
        }
        Ok(claims)
    }
}

fn c218_fixture(
    names: Vec<String>,
    mode: MockMode,
) -> (Arc<MockC218Ports>, TrustedObservationIdentity) {
    let (_, mut verifier, _, _, _) =
        contract218_roles([0x11; 16], [0x22; 16], 1, [0x33; 32], [0x44; 32]).unwrap();
    let declaration = SensitiveParamDeclaration::component(names).unwrap();
    let claims = ObservationIdentityClaims {
        exact_id: "component-a".into(),
        expected_class: ObservationIdentityClass::Component,
        incarnation: 7,
        declaration_digest: declaration
            .digest_for("component-a", ObservationIdentityClass::Component, 7)
            .unwrap(),
    };
    let snapshot = verifier
        .issue_snapshot(claims.clone(), declaration.names().to_vec(), 9)
        .unwrap();
    let handle = verifier.issue_live_source(claims).unwrap();
    let identity = verifier.mint_live_identity(&handle).unwrap();
    let keyring =
        persisted_identity_keyring_role(&mut verifier, [0x11; 16], 1, [0x44; 32], [1; 32]).unwrap();
    let signing = keyring.signing_key_capability().unwrap();
    let verification = keyring.verification_key_capability(1).unwrap();
    let verifier = Arc::new(verifier);
    (
        Arc::new(MockC218Ports {
            provider: verifier,
            keyring,
            signing,
            verification,
            snapshot,
            mode,
            verify_calls: AtomicUsize::new(0),
        }),
        identity,
    )
}

fn contract219(
    ports: Arc<MockC218Ports>,
) -> (
    ObservationEventAssociationIssuer,
    ObservationProviderDtoAssociationIssuer,
    SensitiveObservationRedactor,
) {
    contract219_with_schemas(ports, common_schemas())
}

fn contract219_with_schemas(
    ports: Arc<MockC218Ports>,
    schemas: Vec<ObservationSchemaManifest>,
) -> (
    ObservationEventAssociationIssuer,
    ObservationProviderDtoAssociationIssuer,
    SensitiveObservationRedactor,
) {
    let ObservationAssociationRoleParts {
        event_issuer,
        provider_issuer,
        verifier,
        provider,
    } = observation_association_roles([0x55; 32], [0x66; 16], schemas).unwrap();
    let catalog: Arc<dyn SensitiveParamCatalog> = ports.clone();
    let authority: Arc<dyn ObservationIdentityAuthority> = ports;
    let redactor = DefaultSensitiveObservationRedactor::new(catalog, authority)
        .bind(provider, verifier)
        .unwrap();
    (event_issuer, provider_issuer, redactor)
}

fn schema(
    id: &str,
    kind: ObservationSchemaDocumentKind,
    declarations: Vec<CanonicalContainerDeclaration>,
) -> ObservationSchemaManifest {
    ObservationSchemaManifest::new(id.into(), kind, declarations).unwrap()
}

fn declaration(
    root: ObservationSchemaRoot,
    path: Vec<ObservationPathSegment>,
    kind: CanonicalContainerKind,
    keys: &[&str],
) -> CanonicalContainerDeclaration {
    CanonicalContainerDeclaration::new(
        root,
        path,
        kind,
        keys.iter().map(|key| (*key).to_owned()).collect(),
    )
    .unwrap()
}

fn common_schemas() -> Vec<ObservationSchemaManifest> {
    vec![
        event_root_schema(),
        event_mixed_schema(),
        provider_root_schema(),
    ]
}

fn event_root_schema() -> ObservationSchemaManifest {
    schema(
        EVENT_ROOT_SCHEMA,
        ObservationSchemaDocumentKind::Event,
        vec![declaration(
            ObservationSchemaRoot::EventPayload,
            vec![],
            CanonicalContainerKind::NamedParams,
            &["api_key"],
        )],
    )
}

fn event_mixed_schema() -> ObservationSchemaManifest {
    schema(
        EVENT_MIXED_SCHEMA,
        ObservationSchemaDocumentKind::Event,
        vec![
            declaration(
                ObservationSchemaRoot::EventPayload,
                vec![ObservationPathSegment::Index(1)],
                CanonicalContainerKind::NamedParams,
                &["api_key"],
            ),
            declaration(
                ObservationSchemaRoot::EventPayload,
                vec![ObservationPathSegment::Index(2)],
                CanonicalContainerKind::CapParams,
                &["api_key"],
            ),
        ],
    )
}

fn provider_root_schema() -> ObservationSchemaManifest {
    schema(
        PROVIDER_ROOT_SCHEMA,
        ObservationSchemaDocumentKind::ProviderDto,
        vec![declaration(
            ObservationSchemaRoot::ProviderRoot,
            vec![],
            CanonicalContainerKind::NamedParams,
            &["api_key"],
        )],
    )
}

fn event_envelope() -> ObservationNode {
    ObservationNode::Object(vec![
        ("id".into(), ObservationNode::String("evt-1".into())),
        (
            "event_type".into(),
            ObservationNode::String("test.event".into()),
        ),
        ("run_id".into(), ObservationNode::String("run-1".into())),
    ])
}

fn event_document(payload: ObservationNode) -> ObservationDocument {
    ObservationDocument::event(event_envelope(), payload)
}

fn bind_live_ingress_document(
    issuer: &ObservationEventAssociationIssuer,
    identity: &TrustedObservationIdentity,
    manifest: Option<&ObservationSchemaManifest>,
    envelope: ObservationNode,
    payload: ObservationNode,
) -> Result<BoundObservationDocument, ObservationAssociationError> {
    let (lease, document) =
        live_ingress_observation_fixture(issuer, identity, manifest, envelope, payload)?;
    issuer.bind_live_ingress(&lease, document)
}

fn bind_live_ingress_payload(
    issuer: &ObservationEventAssociationIssuer,
    identity: &TrustedObservationIdentity,
    manifest: Option<&ObservationSchemaManifest>,
    payload: ObservationNode,
) -> Result<BoundObservationDocument, ObservationAssociationError> {
    bind_live_ingress_document(issuer, identity, manifest, event_envelope(), payload)
}

fn bind_live_final_payload(
    issuer: &ObservationEventAssociationIssuer,
    identity: &TrustedObservationIdentity,
    manifest: Option<&ObservationSchemaManifest>,
    safe_event_digest: [u8; 32],
    payload: ObservationNode,
) -> Result<BoundObservationDocument, ObservationAssociationError> {
    let (lease, document) =
        live_final_observation_fixture(issuer, identity, manifest, event_envelope(), payload)?;
    issuer.bind_live_final_event(&lease, safe_event_digest, document)
}

fn bind_provider_dto(
    issuer: &ObservationProviderDtoAssociationIssuer,
    identity: &TrustedObservationIdentity,
    manifest: Option<&ObservationSchemaManifest>,
    root: ObservationNode,
) -> Result<BoundObservationDocument, ObservationAssociationError> {
    let (subject, document) = provider_dto_observation_fixture(issuer, identity, manifest, root)?;
    issuer.bind_live_provider_dto(subject, document)
}

fn nested_arrays(wrappers: usize) -> ObservationNode {
    let mut node = ObservationNode::Null;
    for _ in 0..wrappers {
        node = ObservationNode::Array(vec![node]);
    }
    node
}

#[test]
fn pass_a_rejects_hidden_duplicates_before_redaction() {
    let (ports, identity) = c218_fixture(vec!["api_key".into()], MockMode::Valid);
    let (issuer, _, redactor) = contract219(Arc::clone(&ports));
    let hidden_duplicate = ObservationNode::CanonicalNamedParams(vec![(
        "api_key".into(),
        ObservationNode::Object(vec![
            ("dup".into(), ObservationNode::String("a".into())),
            ("dup".into(), ObservationNode::String("b".into())),
        ]),
    )]);
    let bound = bind_live_ingress_payload(
        &issuer,
        &identity,
        Some(&event_root_schema()),
        hidden_duplicate,
    )
    .unwrap();
    assert_eq!(
        redactor.redact_bound_observation(bound),
        RedactionDisposition::Blocked {
            reason: RedactionBlockReason::MalformedShape
        }
    );
    assert_eq!(ports.verify_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn depth_32_accepts_33_rejects() {
    let (ports, identity) = c218_fixture(vec![], MockMode::Valid);
    let (issuer, _, redactor) = contract219(ports);
    let exact = bind_live_ingress_payload(&issuer, &identity, None, nested_arrays(31)).unwrap();
    assert!(matches!(
        redactor.redact_bound_observation(exact),
        RedactionDisposition::Redacted(_)
    ));
    assert!(matches!(
        bind_live_ingress_payload(&issuer, &identity, None, nested_arrays(32)),
        Err(ObservationAssociationError::Codec(_))
    ));
}

#[test]
fn nodes_4096_accepts_4097_rejects() {
    let (ports, identity) = c218_fixture(vec![], MockMode::Valid);
    let (issuer, _, _) = contract219(ports);
    // event_document envelope Object + its three String leaves (4), payload Array (1), N leaves.
    assert!(bind_live_ingress_payload(
        &issuer,
        &identity,
        None,
        ObservationNode::Array(vec![ObservationNode::Null; 4_091]),
    )
    .is_ok());
    assert!(matches!(
        bind_live_ingress_payload(
            &issuer,
            &identity,
            None,
            ObservationNode::Array(vec![ObservationNode::Null; 4_092]),
        ),
        Err(ObservationAssociationError::Codec(_))
    ));
}

#[test]
fn event_payload_envelope_total_boundaries_and_plus_one() {
    let (ports, identity) = c218_fixture(vec![], MockMode::Valid);
    let (issuer, _, _) = contract219(ports);
    // Canonical String is tag + u32 length + bytes.  The Event codec charges its 10-byte
    // document/partition header to the envelope, yielding the exact 4,096 + 65,536 boundary.
    assert!(bind_live_ingress_document(
        &issuer,
        &identity,
        None,
        ObservationNode::String("e".repeat(4_081)),
        ObservationNode::String("p".repeat(65_531)),
    )
    .is_ok());
    assert!(bind_live_ingress_document(
        &issuer,
        &identity,
        None,
        ObservationNode::String("e".repeat(4_082)),
        ObservationNode::String("p".repeat(65_531)),
    )
    .is_err());
    assert!(bind_live_ingress_document(
        &issuer,
        &identity,
        None,
        ObservationNode::String("e".repeat(4_081)),
        ObservationNode::String("p".repeat(65_532)),
    )
    .is_err());
}

#[test]
fn provider_dto_65536_and_plus_one() {
    let (ports, identity) = c218_fixture(vec![], MockMode::Valid);
    let (_, issuer, _) = contract219(ports);
    assert!(bind_provider_dto(
        &issuer,
        &identity,
        None,
        ObservationNode::String("p".repeat(65_529)),
    )
    .is_ok());
    assert!(bind_provider_dto(
        &issuer,
        &identity,
        None,
        ObservationNode::String("p".repeat(65_530)),
    )
    .is_err());
}

#[test]
fn ordinary_structural_names_are_unchanged() {
    let (ports, identity) = c218_fixture(
        vec!["id".into(), "event_type".into(), "run_id".into()],
        MockMode::Valid,
    );
    let (issuer, _, redactor) = contract219(ports);
    let payload = ObservationNode::Object(vec![
        ("id".into(), ObservationNode::String("payload-id".into())),
        (
            "event_type".into(),
            ObservationNode::String("payload-type".into()),
        ),
        (
            "run_id".into(),
            ObservationNode::String("payload-run".into()),
        ),
    ]);
    let original = event_document(payload.clone());
    let expected = original.clone();
    let bound = bind_live_ingress_payload(&issuer, &identity, None, payload).unwrap();
    assert_eq!(
        redactor.redact_bound_observation(bound),
        RedactionDisposition::Redacted(expected)
    );
}

#[test]
fn exact_schema_paths_reject_downgrade_missing_extra_and_wrong_kind_before_authority() {
    let (ports, identity) = c218_fixture(vec!["api_key".into()], MockMode::Valid);
    let (issuer, _, redactor) = contract219(Arc::clone(&ports));
    let invalid_payloads = [
        // A declared canonical path disguised as an ordinary object is a
        // downgrade, not ordinary structural data.
        ObservationNode::Object(vec![(
            "api_key".into(),
            ObservationNode::String("leak".into()),
        )]),
        ObservationNode::CanonicalNamedParams(vec![]),
        ObservationNode::CanonicalNamedParams(vec![
            ("api_key".into(), ObservationNode::String("secret".into())),
            ("extra".into(), ObservationNode::String("unexpected".into())),
        ]),
        ObservationNode::CanonicalCapParams(vec![CanonicalCapParam {
            key: "api_key".into(),
            value: ObservationNode::String("wrong-kind".into()),
        }]),
    ];
    for payload in invalid_payloads {
        let bound =
            bind_live_ingress_payload(&issuer, &identity, Some(&event_root_schema()), payload)
                .unwrap();
        assert_eq!(
            redactor.redact_bound_observation(bound),
            RedactionDisposition::Blocked {
                reason: RedactionBlockReason::SchemaMismatch,
            }
        );
    }

    // An undeclared canonical container is equally invalid at an ordinary
    // structural path.
    let bound = bind_live_ingress_payload(
        &issuer,
        &identity,
        None,
        ObservationNode::CanonicalNamedParams(vec![(
            "api_key".into(),
            ObservationNode::String("leak".into()),
        )]),
    )
    .unwrap();
    assert_eq!(
        redactor.redact_bound_observation(bound),
        RedactionDisposition::Blocked {
            reason: RedactionBlockReason::SchemaMismatch,
        }
    );
    assert_eq!(ports.verify_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn cross_schema_structural_downgrade_rejects_before_authority_lookup() {
    let (ports, identity) = c218_fixture(vec!["api_key".into()], MockMode::Valid);
    let (issuer, _, _redactor) = contract219(Arc::clone(&ports));
    let declared_payload = ObservationNode::CanonicalNamedParams(vec![(
        "api_key".into(),
        ObservationNode::String("secret".into()),
    )]);
    let (declared_lease, declared_document) = live_ingress_observation_fixture(
        &issuer,
        &identity,
        Some(&event_root_schema()),
        event_envelope(),
        declared_payload,
    )
    .unwrap();
    let (structural_lease, structural_document) = live_ingress_observation_fixture(
        &issuer,
        &identity,
        None,
        event_envelope(),
        ObservationNode::Object(vec![(
            "api_key".into(),
            ObservationNode::String("looks-sensitive".into()),
        )]),
    )
    .unwrap();

    assert!(matches!(
        issuer.bind_live_ingress(&declared_lease, structural_document),
        Err(ObservationAssociationError::InvalidProof)
    ));
    assert!(matches!(
        issuer.bind_live_ingress(&structural_lease, declared_document),
        Err(ObservationAssociationError::InvalidProof)
    ));
    assert_eq!(ports.verify_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn known_empty_authority_cannot_release_foreign_sensitive_document() {
    let (empty_ports, empty_identity) = c218_fixture(vec![], MockMode::Valid);
    let (sensitive_ports, sensitive_identity) =
        c218_fixture(vec!["api_key".into()], MockMode::Valid);
    let (issuer, provider_issuer, _redactor) = contract219(Arc::clone(&empty_ports));
    let schema = event_root_schema();
    let (empty_lease, _empty_document) = live_ingress_observation_fixture(
        &issuer,
        &empty_identity,
        Some(&schema),
        event_envelope(),
        ObservationNode::CanonicalNamedParams(vec![(
            "api_key".into(),
            ObservationNode::String("known-empty-owner".into()),
        )]),
    )
    .unwrap();
    let (_sensitive_lease, foreign_sensitive_document) = live_ingress_observation_fixture(
        &issuer,
        &sensitive_identity,
        Some(&schema),
        event_envelope(),
        ObservationNode::CanonicalNamedParams(vec![(
            "api_key".into(),
            ObservationNode::String("foreign-secret".into()),
        )]),
    )
    .unwrap();

    assert!(matches!(
        issuer.bind_live_ingress(&empty_lease, foreign_sensitive_document),
        Err(ObservationAssociationError::InvalidProof)
    ));

    let provider_schema = provider_root_schema();
    let (empty_subject, _empty_provider_document) = provider_dto_observation_fixture(
        &provider_issuer,
        &empty_identity,
        Some(&provider_schema),
        ObservationNode::CanonicalNamedParams(vec![(
            "api_key".into(),
            ObservationNode::String("known-empty-owner".into()),
        )]),
    )
    .unwrap();
    let (_sensitive_subject, foreign_provider_document) = provider_dto_observation_fixture(
        &provider_issuer,
        &sensitive_identity,
        Some(&provider_schema),
        ObservationNode::CanonicalNamedParams(vec![(
            "api_key".into(),
            ObservationNode::String("foreign-provider-secret".into()),
        )]),
    )
    .unwrap();
    assert!(matches!(
        provider_issuer.bind_live_provider_dto(empty_subject, foreign_provider_document),
        Err(ObservationAssociationError::InvalidProof)
    ));
    assert_eq!(empty_ports.verify_calls.load(Ordering::SeqCst), 0);
    assert_eq!(sensitive_ports.verify_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn snapshot_names_must_recompute_the_bound_declaration_digest() {
    let (ports, identity) = c218_fixture(vec!["api_key".into()], MockMode::WrongSnapshotNames);
    let (issuer, _, redactor) = contract219(Arc::clone(&ports));
    let bound = bind_live_ingress_payload(
        &issuer,
        &identity,
        Some(&event_root_schema()),
        ObservationNode::CanonicalNamedParams(vec![(
            "api_key".into(),
            ObservationNode::String("secret".into()),
        )]),
    )
    .unwrap();
    assert_eq!(
        redactor.redact_bound_observation(bound),
        RedactionDisposition::Blocked {
            reason: RedactionBlockReason::UnknownIdentity,
        }
    );
    assert_eq!(ports.verify_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn only_canonical_named_and_cap_params_redact() {
    let (ports, identity) = c218_fixture(vec!["api_key".into()], MockMode::Valid);
    let (issuer, _, redactor) = contract219(ports);
    let payload = ObservationNode::Array(vec![
        ObservationNode::Object(vec![(
            "api_key".into(),
            ObservationNode::String("ordinary-secret".into()),
        )]),
        ObservationNode::CanonicalNamedParams(vec![(
            "api_key".into(),
            ObservationNode::String("named-secret".into()),
        )]),
        ObservationNode::CanonicalCapParams(vec![CanonicalCapParam {
            key: "api_key".into(),
            value: ObservationNode::String("cap-secret".into()),
        }]),
    ]);
    let bound = bind_live_ingress_payload(&issuer, &identity, Some(&event_mixed_schema()), payload)
        .unwrap();
    let RedactionDisposition::Redacted(redacted) = redactor.redact_bound_observation(bound) else {
        panic!("valid typed document must redact");
    };
    let (_, ObservationNode::Array(values)) = redacted.event_parts().unwrap() else {
        panic!("payload shape preserved");
    };
    assert_eq!(
        values[0],
        ObservationNode::Object(vec![(
            "api_key".into(),
            ObservationNode::String("ordinary-secret".into())
        )])
    );
    assert_eq!(
        values[1],
        ObservationNode::CanonicalNamedParams(vec![(
            "api_key".into(),
            ObservationNode::String("[REDACTED]".into())
        )])
    );
    assert_eq!(
        values[2],
        ObservationNode::CanonicalCapParams(vec![CanonicalCapParam {
            key: "api_key".into(),
            value: ObservationNode::String("[REDACTED]".into())
        }])
    );
}

#[test]
fn unknown_class_stale_scope_all_block() {
    for (mode, reason) in [
        (MockMode::Unknown, RedactionBlockReason::UnknownIdentity),
        (MockMode::Stale, RedactionBlockReason::UnknownIdentity),
        (MockMode::ScopeMismatch, RedactionBlockReason::ScopeMismatch),
    ] {
        let (ports, identity) = c218_fixture(vec!["api_key".into()], mode);
        let (issuer, _, redactor) = contract219(ports);
        let bound = bind_live_ingress_payload(
            &issuer,
            &identity,
            Some(&event_root_schema()),
            ObservationNode::CanonicalNamedParams(vec![(
                "api_key".into(),
                ObservationNode::String("secret".into()),
            )]),
        )
        .unwrap();
        assert_eq!(
            redactor.redact_bound_observation(bound),
            RedactionDisposition::Blocked { reason }
        );
    }
}

#[test]
fn replacement_expansion_is_remeasured_and_blocks_without_partial_output() {
    let sensitive_name = "secretkey";
    let (ports, identity) = c218_fixture(vec![sensitive_name.into()], MockMode::Valid);
    let mut schemas = common_schemas();
    let expansion_schema = schema(
        PROVIDER_EXPANSION_SCHEMA,
        ObservationSchemaDocumentKind::ProviderDto,
        (0..2_047)
            .map(|index| {
                declaration(
                    ObservationSchemaRoot::ProviderRoot,
                    vec![ObservationPathSegment::Index(index)],
                    CanonicalContainerKind::NamedParams,
                    &[sensitive_name],
                )
            })
            .collect(),
    );
    schemas.push(expansion_schema.clone());
    let (_, issuer, redactor) = contract219_with_schemas(ports, schemas);
    let containers = (0..2_047)
        .map(|_| {
            ObservationNode::CanonicalNamedParams(vec![(
                sensitive_name.into(),
                ObservationNode::String("x".into()),
            )])
        })
        .collect();
    let bound = bind_provider_dto(
        &issuer,
        &identity,
        Some(&expansion_schema),
        ObservationNode::Array(containers),
    )
    .unwrap();
    assert_eq!(
        redactor.redact_bound_observation(bound),
        RedactionDisposition::Blocked {
            reason: RedactionBlockReason::OutputTooLarge
        }
    );
}

#[test]
fn all_four_scopes_use_the_mock_c218_ports() {
    let (ports, identity) = c218_fixture(vec!["api_key".into()], MockMode::Valid);
    let (event_issuer, provider_issuer, redactor) = contract219(Arc::clone(&ports));
    let payload = || {
        ObservationNode::CanonicalNamedParams(vec![(
            "api_key".into(),
            ObservationNode::String("secret".into()),
        )])
    };

    let ingress = bind_live_ingress_payload(
        &event_issuer,
        &identity,
        Some(&event_root_schema()),
        payload(),
    )
    .unwrap();
    assert!(matches!(
        redactor.redact_bound_observation(ingress),
        RedactionDisposition::Redacted(_)
    ));

    let final_event = bind_live_final_payload(
        &event_issuer,
        &identity,
        Some(&event_root_schema()),
        [0x77; 32],
        payload(),
    )
    .unwrap();
    assert!(matches!(
        redactor.redact_bound_observation(final_event),
        RedactionDisposition::Redacted(_)
    ));

    let binding =
        PersistedObservationBinding::new("evt-1".into(), "evt-1".into(), [0x88; 32]).unwrap();
    let persisted = ports
        .keyring
        .seal_persisted_identity(&ports.signing, &identity, &binding)
        .unwrap();
    let persisted_document = persisted_event_observation_fixture(
        &event_issuer,
        &persisted,
        &binding,
        Some(&event_root_schema()),
        event_envelope(),
        payload(),
    )
    .unwrap();
    let persisted_event = event_issuer
        .bind_persisted_event(persisted, binding, persisted_document)
        .unwrap();
    assert!(matches!(
        redactor.redact_bound_observation(persisted_event),
        RedactionDisposition::Redacted(_)
    ));

    let provider = bind_provider_dto(
        &provider_issuer,
        &identity,
        Some(&provider_root_schema()),
        payload(),
    )
    .unwrap();
    assert!(matches!(
        redactor.redact_bound_observation(provider),
        RedactionDisposition::Redacted(_)
    ));
    assert_eq!(ports.verify_calls.load(Ordering::SeqCst), 4);
}

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use serde_json::json;
use sha2::{Digest, Sha256};

use advance_client_api::durable_idempotency::{
    DurableIdempotencyConfig, DurableIdempotencyError, DurableIdempotencyRepository,
    IdempotencyAnchor,
};
use advance_client_api::{
    BoundGrantApprovalPort, BoundGrantMutation, BoundHistoryPage, BoundHistoryReadPort,
    BoundMutationOutcome, ClientApi, ClientApiConfig, ClientApiServer, ClientErrorCode,
    ClientRequest, ClientSession, Platform, Principal, ProviderClientDoneReceipt, ProviderError,
    ProviderMutationRecovery, ProviderPrepareOutcome, Scope,
};
use advance_shared_types::contract218_previsible::PrevisibleProofVerifierRole;
use advance_shared_types::observation_identity::{
    AuthenticatedObservationSourceHandle, ObservationIdentityAuthority, ObservationIdentityClaims,
    ObservationIdentityClass, PersistedObservationBinding, PersistedObservationIdentity,
    SensitiveParamCatalog, SensitiveParamCatalogError, SensitiveParamDeclaration,
    SensitiveParamSnapshot, SourceBindingDigest, TrustedObservationIdentity,
};
use advance_shared_types::security_validator::{LeakDetector, ScanContext, ScanResult};
use advance_shared_types::sensitive_observation::{
    BoundObservationDocument, CanonicalCapParam, CanonicalContainerDeclaration,
    CanonicalContainerKind, ObservationAssociationRoleParts, ObservationEventAssociationIssuer,
    ObservationNode, ObservationPathSegment, ObservationProviderDtoAssociationIssuer,
    ObservationSchemaDocumentKind, ObservationSchemaManifest, ObservationSchemaRoot,
};
use advance_shared_types::test_support::{
    contract218_roles, corrupt_bound_proof_byte, live_final_observation_fixture,
    observation_association_roles, provider_dto_observation_fixture,
};
use cap_http::DefaultSensitiveObservationRedactor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

const PROVIDER_SCHEMA: &str = "test.client.pending-grant.v1";
const HISTORY_SCHEMA: &str = "test.client.history.v1";

struct C218Ports {
    verifier: Arc<PrevisibleProofVerifierRole>,
    snapshot: SensitiveParamSnapshot,
}

impl SensitiveParamCatalog for C218Ports {
    fn lookup(&self, id: &str) -> Result<SensitiveParamSnapshot, SensitiveParamCatalogError> {
        if id == self.snapshot.canonical_component_id {
            Ok(self.snapshot.clone())
        } else {
            Err(SensitiveParamCatalogError::UnknownIdentity)
        }
    }

    fn verify(
        &self,
        identity: &TrustedObservationIdentity,
    ) -> Result<SensitiveParamSnapshot, SensitiveParamCatalogError> {
        self.verifier
            .verify_live_identity(identity, &self.snapshot.claims())?;
        Ok(self.snapshot.clone())
    }

    fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        tokio::sync::watch::channel(self.snapshot.revision).1
    }
}

impl ObservationIdentityAuthority for C218Ports {
    fn mint_live_identity(
        &self,
        source: &AuthenticatedObservationSourceHandle,
    ) -> Result<TrustedObservationIdentity, SensitiveParamCatalogError> {
        self.verifier.mint_live_identity(source)
    }

    fn rehydrate_persisted_identity(
        &self,
        _persisted: &PersistedObservationIdentity,
    ) -> Result<TrustedObservationIdentity, SensitiveParamCatalogError> {
        Err(SensitiveParamCatalogError::InvalidCarrier)
    }

    fn verify_persisted_binding(
        &self,
        _identity: &TrustedObservationIdentity,
        _persisted: &PersistedObservationIdentity,
        _observed: &PersistedObservationBinding,
    ) -> Result<SensitiveParamSnapshot, SensitiveParamCatalogError> {
        Err(SensitiveParamCatalogError::InvalidCarrier)
    }

    fn resolve_retained_source_binding(
        &self,
        digest: &SourceBindingDigest,
    ) -> Result<ObservationIdentityClaims, SensitiveParamCatalogError> {
        let claims = self.snapshot.claims();
        if self.verifier.source_binding_digest(&claims)? == *digest {
            Ok(claims)
        } else {
            Err(SensitiveParamCatalogError::UnknownIdentity)
        }
    }
}

struct TestDetector {
    blocked: Option<&'static str>,
}

impl LeakDetector for TestDetector {
    fn scan(&self, text: &str, _context: ScanContext) -> ScanResult {
        if self.blocked.is_some_and(|needle| text.contains(needle)) {
            ScanResult::Blocked { findings: vec![] }
        } else {
            ScanResult::Clean
        }
    }

    fn scan_headers(&self, _headers: &[(String, String)]) -> ScanResult {
        ScanResult::Clean
    }
}

struct Prepared {
    fingerprint: [u8; 32],
    operation_tag: u8,
    response: ObservationNode,
    outcome_unknown: bool,
}

struct GrantProvider {
    issuer: Arc<ObservationProviderDtoAssociationIssuer>,
    identity: TrustedObservationIdentity,
    pending_schema: ObservationSchemaManifest,
    prepared: Mutex<HashMap<[u8; 32], Prepared>>,
    lists: AtomicUsize,
    prepares: AtomicUsize,
    executes: AtomicUsize,
    acknowledgements: AtomicUsize,
    resolve_unknown: std::sync::atomic::AtomicBool,
    revision: String,
    parameter_value: String,
}

impl GrantProvider {
    fn bind(
        &self,
        root: ObservationNode,
        manifest: Option<&ObservationSchemaManifest>,
    ) -> BoundObservationDocument {
        let (subject, document) =
            provider_dto_observation_fixture(&self.issuer, &self.identity, manifest, root).unwrap();
        self.issuer
            .bind_live_provider_dto(subject, document)
            .unwrap()
    }

    fn ticket(
        &self,
        mutation_id: [u8; 32],
        fingerprint: [u8; 32],
        operation_tag: u8,
    ) -> ProviderMutationRecovery {
        let mut bytes = [0u8; 167];
        bytes[0] = 1;
        bytes[1] = 1;
        bytes[2] = operation_tag;
        bytes[3..7].copy_from_slice(&1u32.to_be_bytes());
        bytes[7..39].copy_from_slice(&mutation_id);
        bytes[39..71].copy_from_slice(&fingerprint);
        bytes[71..103].copy_from_slice(&Sha256::digest(mutation_id));
        bytes[103..135].fill(0x44);
        bytes[135..167].fill(0x55);
        ProviderMutationRecovery::from_provider_bytes(bytes).unwrap()
    }
}

impl BoundGrantApprovalPort for GrantProvider {
    fn list_pending_bound(&self) -> Result<Vec<BoundObservationDocument>, ProviderError> {
        self.lists.fetch_add(1, Ordering::SeqCst);
        let root = ObservationNode::Object(vec![
            (
                "kind".into(),
                ObservationNode::String("pending_grant".into()),
            ),
            (
                "request_id".into(),
                ObservationNode::String("request-a".into()),
            ),
            (
                "decision_revision".into(),
                ObservationNode::String(self.revision.clone()),
            ),
            (
                "caller_id".into(),
                ObservationNode::String("component-a".into()),
            ),
            (
                "capability".into(),
                ObservationNode::String("fs.read".into()),
            ),
            (
                "params".into(),
                ObservationNode::CanonicalCapParams(vec![CanonicalCapParam {
                    key: "path".into(),
                    value: ObservationNode::String(self.parameter_value.clone()),
                }]),
            ),
            (
                "ttl".into(),
                ObservationNode::Object(vec![
                    ("kind".into(), ObservationNode::String("duration".into())),
                    (
                        "milliseconds_u64".into(),
                        ObservationNode::String(u64::MAX.to_string()),
                    ),
                ]),
            ),
            (
                "justification".into(),
                ObservationNode::String("approve\u{202e}deny".into()),
            ),
        ]);
        Ok(vec![self.bind(root, Some(&self.pending_schema))])
    }

    fn prepare_mutation_bound(
        &self,
        mutation_id: [u8; 32],
        request_fingerprint: [u8; 32],
        mutation: BoundGrantMutation,
    ) -> ProviderPrepareOutcome {
        self.prepares.fetch_add(1, Ordering::SeqCst);
        let operation_tag = mutation.operation_tag();
        if matches!(
            &mutation,
            BoundGrantMutation::Approve { request_id, .. } if request_id == "reject"
        ) {
            return ProviderPrepareOutcome::Rejected(ProviderError::InvalidState(
                "provider rejected".into(),
            ));
        }
        let outcome_unknown = matches!(
            &mutation,
            BoundGrantMutation::Approve { request_id, .. } if request_id == "unknown"
        );
        let response = match mutation {
            BoundGrantMutation::Approve { request_id, .. } => decision(request_id, "approved"),
            BoundGrantMutation::Deny { request_id, .. } => decision(request_id, "denied"),
            BoundGrantMutation::Narrow { request_id, .. } => decision(request_id, "narrowed"),
            BoundGrantMutation::Revoke { grant_id } => ObservationNode::Object(vec![
                (
                    "kind".into(),
                    ObservationNode::String("grant_revoke".into()),
                ),
                ("grant_id".into(), ObservationNode::String(grant_id)),
                ("status".into(), ObservationNode::String("revoked".into())),
                ("revoked_count".into(), ObservationNode::Number("3".into())),
            ]),
            BoundGrantMutation::ApplyPreset {
                target_agent_id,
                preset,
            } => ObservationNode::Object(vec![
                (
                    "kind".into(),
                    ObservationNode::String("preset_apply".into()),
                ),
                ("preset".into(), ObservationNode::String(preset)),
                (
                    "target_agent_id".into(),
                    ObservationNode::String(target_agent_id),
                ),
                ("status".into(), ObservationNode::String("applied".into())),
                (
                    "created_grant_ids".into(),
                    ObservationNode::Array(vec![
                        ObservationNode::String("grant-1".into()),
                        ObservationNode::String("grant-2".into()),
                    ]),
                ),
            ]),
        };
        self.prepared.lock().unwrap().insert(
            mutation_id,
            Prepared {
                fingerprint: request_fingerprint,
                operation_tag,
                response,
                outcome_unknown,
            },
        );
        ProviderPrepareOutcome::Prepared(self.ticket(
            mutation_id,
            request_fingerprint,
            operation_tag,
        ))
    }

    fn verify_recovery_ticket_bound(
        &self,
        mutation_id: [u8; 32],
        request_fingerprint: [u8; 32],
        operation_tag: u8,
        recovery: &ProviderMutationRecovery,
    ) -> Result<(), ProviderError> {
        let bytes = recovery.as_provider_bytes();
        let row = self
            .prepared
            .lock()
            .unwrap()
            .get(&mutation_id)
            .map(|row| (row.fingerprint, row.operation_tag))
            .ok_or_else(|| ProviderError::NotFound("prepared".into()))?;
        if bytes[7..39] == mutation_id
            && bytes[39..71] == request_fingerprint
            && bytes[2] == operation_tag
            && row == (request_fingerprint, operation_tag)
        {
            Ok(())
        } else {
            Err(ProviderError::InvalidState("ticket association".into()))
        }
    }

    fn execute_prepared_bound(&self, recovery: &ProviderMutationRecovery) -> BoundMutationOutcome {
        self.executes.fetch_add(1, Ordering::SeqCst);
        let mutation_id: [u8; 32] = recovery.as_provider_bytes()[7..39].try_into().unwrap();
        let (response, fingerprint, operation_tag, outcome_unknown) = {
            let rows = self.prepared.lock().unwrap();
            let row = rows.get(&mutation_id).unwrap();
            (
                row.response.clone(),
                row.fingerprint,
                row.operation_tag,
                row.outcome_unknown,
            )
        };
        if outcome_unknown && !self.resolve_unknown.load(Ordering::SeqCst) {
            return BoundMutationOutcome::OutcomeUnknown(self.ticket(
                mutation_id,
                fingerprint,
                operation_tag,
            ));
        }
        BoundMutationOutcome::Committed(self.bind(response, None))
    }

    fn recover_mutation_bound(&self, recovery: &ProviderMutationRecovery) -> BoundMutationOutcome {
        self.execute_prepared_bound(recovery)
    }

    fn acknowledge_client_done_bound(
        &self,
        _done: &ProviderClientDoneReceipt,
    ) -> Result<(), ProviderError> {
        self.acknowledgements.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn decision(request_id: String, status: &str) -> ObservationNode {
    ObservationNode::Object(vec![
        (
            "kind".into(),
            ObservationNode::String("grant_decision".into()),
        ),
        ("request_id".into(), ObservationNode::String(request_id)),
        ("status".into(), ObservationNode::String(status.into())),
    ])
}

struct HistoryProvider {
    issuer: Arc<ObservationEventAssociationIssuer>,
    identity: TrustedObservationIdentity,
    schema: ObservationSchemaManifest,
    summary: String,
    calls: AtomicUsize,
    tamper_second: bool,
    parameter_value: String,
}

impl HistoryProvider {
    fn event(&self, event_id: &str, summary: &str, digest: [u8; 32]) -> BoundObservationDocument {
        let payload = ObservationNode::Object(vec![
            ("event_id".into(), ObservationNode::String(event_id.into())),
            (
                "occurred_at".into(),
                ObservationNode::String(Utc::now().to_rfc3339()),
            ),
            (
                "kind".into(),
                ObservationNode::String("run.completed".into()),
            ),
            ("summary".into(), ObservationNode::String(summary.into())),
            (
                "params".into(),
                ObservationNode::CanonicalCapParams(vec![CanonicalCapParam {
                    key: "token".into(),
                    value: ObservationNode::String(self.parameter_value.clone()),
                }]),
            ),
        ]);
        let (lease, document) = live_final_observation_fixture(
            &self.issuer,
            &self.identity,
            Some(&self.schema),
            ObservationNode::Object(vec![]),
            payload,
        )
        .unwrap();
        self.issuer
            .bind_live_final_event(&lease, digest, document)
            .unwrap()
    }

    fn page(&self) -> BoundHistoryPage {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let first = self.event("event-1", "first-safe", [0x76; 32]);
        let mut second = self.event("event-2", &self.summary, [0x77; 32]);
        if self.tamper_second {
            corrupt_bound_proof_byte(&mut second, 145);
        }
        BoundHistoryPage::from_bound_documents(vec![first, second], Some("next-1".into()))
    }
}

impl BoundHistoryReadPort for HistoryProvider {
    fn task_history_bound(
        &self,
        _task_id: &str,
        _cursor: Option<&str>,
    ) -> Result<BoundHistoryPage, ProviderError> {
        Ok(self.page())
    }

    fn run_history_bound(
        &self,
        _run_id: &str,
        _cursor: Option<&str>,
    ) -> Result<BoundHistoryPage, ProviderError> {
        Ok(self.page())
    }
}

struct Fixture {
    api: ClientApi,
    grants: Arc<GrantProvider>,
    history: Arc<HistoryProvider>,
}

fn fixture(blocked: Option<&'static str>, summary: &str) -> Fixture {
    fixture_inner(blocked, summary, false, None)
}

fn fixture_with_tamper(
    blocked: Option<&'static str>,
    summary: &str,
    tamper_second: bool,
) -> Fixture {
    fixture_inner(blocked, summary, tamper_second, None)
}

fn fixture_inner(
    blocked: Option<&'static str>,
    summary: &str,
    tamper_second: bool,
    durable: Option<Arc<DurableIdempotencyRepository>>,
) -> Fixture {
    fixture_inner_with_sensitive(blocked, summary, tamper_second, durable, None)
}

fn fixture_inner_with_sensitive(
    blocked: Option<&'static str>,
    summary: &str,
    tamper_second: bool,
    durable: Option<Arc<DurableIdempotencyRepository>>,
    sensitive_value: Option<&str>,
) -> Fixture {
    let (_, verifier, _, _, _) =
        contract218_roles([0x11; 16], [0x22; 16], 1, [0x33; 32], [0x44; 32]).unwrap();
    let declaration_names = if sensitive_value.is_some() {
        vec!["path".to_owned(), "token".to_owned()]
    } else {
        Vec::new()
    };
    let declaration = SensitiveParamDeclaration::component(declaration_names.clone()).unwrap();
    let claims = ObservationIdentityClaims {
        exact_id: "component-a".into(),
        expected_class: ObservationIdentityClass::Component,
        incarnation: 7,
        declaration_digest: declaration
            .digest_for("component-a", ObservationIdentityClass::Component, 7)
            .unwrap(),
    };
    let snapshot = verifier
        .issue_snapshot(claims.clone(), declaration_names, 1)
        .unwrap();
    let grant_handle = verifier.issue_live_source(claims.clone()).unwrap();
    let history_handle = verifier.issue_live_source(claims).unwrap();
    let grant_identity = verifier.mint_live_identity(&grant_handle).unwrap();
    let history_identity = verifier.mint_live_identity(&history_handle).unwrap();
    let ports = Arc::new(C218Ports {
        verifier: Arc::new(verifier),
        snapshot,
    });

    let provider_schema = provider_schema();
    let history_schema = history_schema();
    let ObservationAssociationRoleParts {
        event_issuer,
        provider_issuer,
        verifier,
        provider,
    } = observation_association_roles(
        [0x55; 32],
        [0x66; 16],
        vec![provider_schema.clone(), history_schema.clone()],
    )
    .unwrap();
    let catalog: Arc<dyn SensitiveParamCatalog> = ports.clone();
    let authority: Arc<dyn ObservationIdentityAuthority> = ports;
    let redactor = Arc::new(
        DefaultSensitiveObservationRedactor::new(catalog, authority)
            .bind(provider, verifier)
            .unwrap(),
    );
    let revision = URL_SAFE_NO_PAD.encode([0x88; 185]);
    assert_eq!(revision.len(), 247);
    let grants = Arc::new(GrantProvider {
        issuer: Arc::new(provider_issuer),
        identity: grant_identity,
        pending_schema: provider_schema,
        prepared: Mutex::new(HashMap::new()),
        lists: AtomicUsize::new(0),
        prepares: AtomicUsize::new(0),
        executes: AtomicUsize::new(0),
        acknowledgements: AtomicUsize::new(0),
        resolve_unknown: std::sync::atomic::AtomicBool::new(false),
        revision,
        parameter_value: sensitive_value.unwrap_or("/safe").to_owned(),
    });
    let history = Arc::new(HistoryProvider {
        issuer: Arc::new(event_issuer),
        identity: history_identity,
        schema: history_schema,
        summary: summary.into(),
        calls: AtomicUsize::new(0),
        tamper_second,
        parameter_value: sensitive_value.unwrap_or("safe").to_owned(),
    });
    let detector: Arc<dyn LeakDetector> = Arc::new(TestDetector { blocked });
    let mut api = ClientApi::new(ClientApiConfig::default())
        .with_bound_grant_provider(grants.clone())
        .with_bound_history_provider(history.clone())
        .with_observation_redactor(redactor)
        .with_leak_detector(detector);
    if let Some(repository) = durable {
        api = api.with_durable_idempotency(repository);
    }
    api.sessions().insert(
        "tok".into(),
        ClientSession {
            session_id: "session".into(),
            principal: Principal::operator("operator"),
            platform: Platform::Mac,
            scopes: Scope::operator_default(),
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );
    Fixture {
        api,
        grants,
        history,
    }
}

#[derive(Default)]
struct TestAnchor {
    bytes: Mutex<Option<Vec<u8>>>,
}

impl IdempotencyAnchor for TestAnchor {
    fn load(&self) -> Result<Option<Vec<u8>>, DurableIdempotencyError> {
        Ok(self.bytes.lock().unwrap().clone())
    }

    fn compare_and_swap(
        &self,
        expected: Option<&[u8]>,
        replacement: &[u8],
    ) -> Result<(), DurableIdempotencyError> {
        let mut bytes = self.bytes.lock().unwrap();
        let matches = match (expected, bytes.as_deref()) {
            (None, None) => true,
            (Some(expected), Some(actual)) => expected == actual,
            _ => false,
        };
        if !matches {
            return Err(DurableIdempotencyError::AnchorConflict);
        }
        *bytes = Some(replacement.to_vec());
        Ok(())
    }
}

fn durable_repository(path: PathBuf, anchor: Arc<TestAnchor>) -> Arc<DurableIdempotencyRepository> {
    DurableIdempotencyRepository::open(
        DurableIdempotencyConfig {
            database_path: path,
            confined_relative_path: "idempotency.db".into(),
            workspace_master_key: Zeroizing::new([0x91; 32]),
            key_epoch: NonZeroU32::new(1).unwrap(),
            scope_key_epoch: NonZeroU32::new(2).unwrap(),
            payload_key_epoch: NonZeroU32::new(3).unwrap(),
        },
        anchor,
    )
    .unwrap()
}

fn provider_schema() -> ObservationSchemaManifest {
    ObservationSchemaManifest::new(
        PROVIDER_SCHEMA.into(),
        ObservationSchemaDocumentKind::ProviderDto,
        vec![CanonicalContainerDeclaration::new(
            ObservationSchemaRoot::ProviderRoot,
            vec![ObservationPathSegment::Member("params".into())],
            CanonicalContainerKind::CapParams,
            vec!["path".into()],
        )
        .unwrap()],
    )
    .unwrap()
}

fn history_schema() -> ObservationSchemaManifest {
    ObservationSchemaManifest::new(
        HISTORY_SCHEMA.into(),
        ObservationSchemaDocumentKind::Event,
        vec![CanonicalContainerDeclaration::new(
            ObservationSchemaRoot::EventPayload,
            vec![ObservationPathSegment::Member("params".into())],
            CanonicalContainerKind::CapParams,
            vec!["token".into()],
        )
        .unwrap()],
    )
    .unwrap()
}

async fn public_get(port: u16, path: &str, token: Option<&str>) -> String {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect public Client API");
    let authorization = token
        .map(|value| format!("Authorization: Bearer {value}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{authorization}Connection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    let response = String::from_utf8(bytes).expect("UTF-8 HTTP response");
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    response
        .split_once("\r\n\r\n")
        .expect("HTTP response body")
        .1
        .to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t10_public_history_and_approval_http_are_bound_and_redacted_for_console() {
    const SENTINEL: &str = "legacy3-raw-secret-7f3a";
    let fx = fixture_inner_with_sensitive(None, "completed", false, None, Some(SENTINEL));
    let server = ClientApiServer::bind(Arc::new(fx.api), 0)
        .await
        .expect("public Client API server");
    let port = server.local_addr().port();

    let grants = public_get(port, "/client/grants/pending", Some("tok")).await;
    let history = public_get(port, "/client/tasks/task-a/history", Some("tok")).await;
    let console = public_get(port, "/app.js", None).await;

    for (surface, body) in [("approval", &grants), ("history", &history)] {
        assert!(
            body.contains("[REDACTED]"),
            "{surface} must mask the parameter: {body}"
        );
        assert!(
            !body.contains(SENTINEL),
            "{surface} leaked the guest sentinel: {body}"
        );
    }
    assert!(
        grants.contains("request-a"),
        "approval structural id is preserved"
    );
    assert!(
        history.contains("event-2"),
        "history structural event id is preserved"
    );
    assert!(
        console.contains("textContent"),
        "console renders through the safe DOM sink"
    );
    assert!(console.contains("/client/grants/pending"));
    assert!(console.contains("/client/${kind}/${id}/history"));
    assert!(!console.contains(SENTINEL));
    assert!(!console.contains("/query"));

    server.shutdown().await.unwrap();
}

#[test]
fn t17_grant_routes_preserve_wire_shape_revision_and_fingerprint() {
    let fx = fixture(None, "run\u{202e}done");
    let listed = fx
        .api
        .handle(ClientRequest::get("/client/grants/pending").with_session("tok"));
    assert!(listed.is_ok(), "{:?}", listed.error);
    let data = listed.data.unwrap();
    assert_eq!(data["requests"][0]["params"][0]["value"], "/safe");
    assert_eq!(
        data["requests"][0]["ttl"]["milliseconds_u64"],
        u64::MAX.to_string()
    );
    assert_eq!(data["requests"][0]["justification"], "approvedeny");
    assert!(listed
        .warnings
        .iter()
        .any(|warning| warning.code == "unicode_format_removed"));

    let revision = fx.grants.revision.clone();
    let approve = || {
        ClientRequest::post(
            "/client/grants/pending/request-a:approve",
            json!({ "decision_revision": revision }),
        )
        .with_session("tok")
        .with_idempotency_key("decision-key")
    };
    let first = fx.api.handle(approve());
    assert!(first.is_ok(), "{:?}", first.error);
    assert_eq!(first.data.unwrap()["status"], "approved");
    let replay = fx.api.handle(approve());
    assert!(replay.is_ok());
    assert_eq!(fx.grants.prepares.load(Ordering::SeqCst), 1);
    assert_eq!(fx.grants.executes.load(Ordering::SeqCst), 1);

    let conflict = fx.api.handle(
        ClientRequest::post(
            "/client/grants/pending/request-a:deny",
            json!({ "decision_revision": fx.grants.revision, "reason": "no" }),
        )
        .with_session("tok")
        .with_idempotency_key("decision-key"),
    );
    assert_eq!(
        conflict.error_code(),
        Some(ClientErrorCode::IdempotencyConflict)
    );
    assert_eq!(fx.grants.prepares.load(Ordering::SeqCst), 1);
}

#[test]
fn t17_invalid_revision_rejects_before_provider() {
    let fx = fixture(None, "safe");
    let response = fx.api.handle(
        ClientRequest::post(
            "/client/grants/pending/request-a:approve",
            json!({ "decision_revision": "not-canonical" }),
        )
        .with_session("tok")
        .with_idempotency_key("bad-revision"),
    );
    assert_eq!(
        response.error_code(),
        Some(ClientErrorCode::ProjectionRejected)
    );
    assert_eq!(fx.grants.prepares.load(Ordering::SeqCst), 0);
}

#[test]
fn t17_provider_entered_rejection_is_terminal_and_replayed() {
    let fx = fixture(None, "safe");
    let request = || {
        ClientRequest::post(
            "/client/grants/pending/reject:approve",
            json!({ "decision_revision": fx.grants.revision }),
        )
        .with_session("tok")
        .with_idempotency_key("provider-rejection")
    };
    let first = fx.api.handle(request());
    assert_eq!(first.error_code(), Some(ClientErrorCode::InvalidState));
    let replay = fx.api.handle(request());
    assert_eq!(replay.error_code(), Some(ClientErrorCode::InvalidState));
    assert_eq!(fx.grants.prepares.load(Ordering::SeqCst), 1);
    assert!(replay
        .warnings
        .iter()
        .any(|warning| warning.code == "idempotent_replay"));
}

#[test]
fn t17_unknown_provider_outcome_retains_the_recovery_reservation() {
    let fx = fixture(None, "safe");
    let request = || {
        ClientRequest::post(
            "/client/grants/pending/unknown:approve",
            json!({ "decision_revision": fx.grants.revision }),
        )
        .with_session("tok")
        .with_idempotency_key("provider-unknown")
    };
    let first = fx.api.handle(request());
    assert_eq!(first.error_code(), Some(ClientErrorCode::ModuleUnavailable));
    let retry = fx.api.handle(request());
    assert_eq!(
        retry.error_code(),
        Some(ClientErrorCode::IdempotencyInProgress)
    );
    assert_eq!(fx.grants.prepares.load(Ordering::SeqCst), 1);
    assert_eq!(fx.grants.executes.load(Ordering::SeqCst), 2);
}

#[test]
fn t23_durable_grant_route_anchors_all_phases_and_replays_without_provider() {
    let dir = tempfile::tempdir().unwrap();
    let anchor = Arc::new(TestAnchor::default());
    let repository = durable_repository(dir.path().join("idempotency.db"), anchor);
    let fx = fixture_inner(None, "safe", false, Some(repository.clone()));
    let revision = fx.grants.revision.clone();
    let request = || {
        ClientRequest::post(
            "/client/grants/pending/request-a:approve",
            json!({ "decision_revision": revision }),
        )
        .with_session("tok")
        .with_idempotency_key("durable-approve")
    };
    let first = fx.api.handle(request());
    assert!(first.is_ok(), "{:?}", first.error);
    assert_eq!(first.data.unwrap()["status"], "approved");
    assert_eq!(repository.committed_sequence(), 5);
    assert_eq!(fx.grants.prepares.load(Ordering::SeqCst), 1);
    assert_eq!(fx.grants.executes.load(Ordering::SeqCst), 1);
    assert_eq!(fx.grants.acknowledgements.load(Ordering::SeqCst), 1);
    assert!(repository.recovery_rows().unwrap().is_empty());

    let replay = fx.api.handle(request());
    assert!(replay.is_ok());
    assert_eq!(replay.data.unwrap()["status"], "approved");
    assert_eq!(repository.committed_sequence(), 5);
    assert_eq!(fx.grants.prepares.load(Ordering::SeqCst), 1);
    assert_eq!(fx.grants.executes.load(Ordering::SeqCst), 1);
    assert!(replay
        .warnings
        .iter()
        .any(|warning| warning.code == "idempotent_replay"));

    fx.api.recover_durable_grants().unwrap();
    assert_eq!(repository.committed_sequence(), 5);
    assert_eq!(fx.grants.prepares.load(Ordering::SeqCst), 1);
    assert_eq!(fx.grants.executes.load(Ordering::SeqCst), 1);
    assert_eq!(fx.grants.acknowledgements.load(Ordering::SeqCst), 2);
}

#[test]
fn t23_durable_invalid_revision_rejects_before_reservation() {
    let dir = tempfile::tempdir().unwrap();
    let anchor = Arc::new(TestAnchor::default());
    let repository = durable_repository(dir.path().join("idempotency.db"), anchor);
    let fx = fixture_inner(None, "safe", false, Some(repository.clone()));

    let response = fx.api.handle(
        ClientRequest::post(
            "/client/grants/pending/request-a:approve",
            json!({ "decision_revision": "not-a-valid-revision" }),
        )
        .with_session("tok")
        .with_idempotency_key("durable-invalid-revision"),
    );

    assert_eq!(
        response.error_code(),
        Some(ClientErrorCode::ProjectionRejected)
    );
    assert_eq!(repository.committed_sequence(), 0);
    assert_eq!(fx.grants.prepares.load(Ordering::SeqCst), 0);
    assert!(repository.recovery_rows().unwrap().is_empty());
}

#[test]
fn t23_boot_reconciliation_recovers_unknown_terminal_before_retry() {
    let dir = tempfile::tempdir().unwrap();
    let anchor = Arc::new(TestAnchor::default());
    let repository = durable_repository(dir.path().join("idempotency.db"), anchor);
    let fx = fixture_inner(None, "safe", false, Some(repository.clone()));
    let request = || {
        ClientRequest::post(
            "/client/grants/pending/unknown:approve",
            json!({ "decision_revision": fx.grants.revision }),
        )
        .with_session("tok")
        .with_idempotency_key("durable-unknown")
    };
    let first = fx.api.handle(request());
    assert_eq!(first.error_code(), Some(ClientErrorCode::ModuleUnavailable));
    assert_eq!(repository.recovery_rows().unwrap().len(), 1);
    assert_eq!(repository.committed_sequence(), 6);

    fx.grants.resolve_unknown.store(true, Ordering::SeqCst);
    fx.api.recover_durable_grants().unwrap();
    assert!(repository.recovery_rows().unwrap().is_empty());
    assert_eq!(repository.committed_sequence(), 7);
    assert_eq!(fx.grants.acknowledgements.load(Ordering::SeqCst), 1);

    let replay = fx.api.handle(request());
    assert!(replay.is_ok(), "{:?}", replay.error);
    assert_eq!(replay.data.unwrap()["status"], "approved");
    assert_eq!(fx.grants.prepares.load(Ordering::SeqCst), 1);
    assert_eq!(fx.grants.executes.load(Ordering::SeqCst), 3);
}

#[test]
fn t18_history_is_individually_bound_redacted_and_unicode_safe() {
    let fx = fixture(None, "run\u{2067}completed");
    let response = fx
        .api
        .handle(ClientRequest::get("/client/tasks/task-a/history").with_session("tok"));
    assert!(response.is_ok(), "{:?}", response.error);
    assert_eq!(
        response.data.unwrap()["entries"][1]["summary"],
        "runcompleted"
    );
    assert!(response
        .warnings
        .iter()
        .any(|warning| warning.code == "unicode_format_removed"));
}

#[test]
fn t22_blocked_second_gate_rejects_the_complete_history_page() {
    let fx = fixture(Some("BLOCK"), "safe-BLOCK-sentinel");
    let response = fx
        .api
        .handle(ClientRequest::get("/client/runs/run-a/history").with_session("tok"));
    assert_eq!(
        response.error_code(),
        Some(ClientErrorCode::ProjectionRejected)
    );
    assert!(response.data.is_none());
    let encoded = serde_json::to_string(&response).unwrap();
    assert!(!encoded.contains("BLOCK"));
    assert!(!encoded.contains("event-1"));
}

#[test]
fn t17_t18_scope_gates_run_before_provider_access() {
    let fx = fixture(None, "safe");
    fx.api.sessions().insert(
        "read-only".into(),
        ClientSession {
            session_id: "read-only".into(),
            principal: Principal::operator("reader"),
            platform: Platform::Mac,
            scopes: vec![Scope::ReadRuns],
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );
    let grant = fx
        .api
        .handle(ClientRequest::get("/client/grants/pending").with_session("read-only"));
    assert_eq!(grant.error_code(), Some(ClientErrorCode::Forbidden));
    assert_eq!(fx.grants.lists.load(Ordering::SeqCst), 0);

    fx.api.sessions().insert(
        "grant-only".into(),
        ClientSession {
            session_id: "grant-only".into(),
            principal: Principal::operator("approver"),
            platform: Platform::Mac,
            scopes: vec![Scope::ApproveGrants],
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );
    let history = fx
        .api
        .handle(ClientRequest::get("/client/tasks/task-a/history").with_session("grant-only"));
    assert_eq!(history.error_code(), Some(ClientErrorCode::Forbidden));
    assert_eq!(fx.history.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn t21_justification_block_rejects_pending_page() {
    let fx = fixture(Some("approvedeny"), "safe");
    let response = fx
        .api
        .handle(ClientRequest::get("/client/grants/pending").with_session("tok"));
    assert_eq!(
        response.error_code(),
        Some(ClientErrorCode::ProjectionRejected)
    );
    let encoded = serde_json::to_string(&response).unwrap();
    assert!(!encoded.contains("approvedeny"));
    assert!(!encoded.contains("request-a"));
}

#[test]
fn t21_c219_redacts_declared_param_before_scan() {
    let fx = fixture_inner_with_sensitive(
        Some("param-block-needle"),
        "safe",
        false,
        None,
        Some("param-block-needle"),
    );
    let response = fx
        .api
        .handle(ClientRequest::get("/client/grants/pending").with_session("tok"));
    assert!(response.is_ok(), "{:?}", response.error);
    let encoded = serde_json::to_string(&response).unwrap();
    assert!(!encoded.contains("param-block-needle"));
    assert!(encoded.contains("[REDACTED]"));
    assert!(encoded.contains("requests"));
}

#[test]
fn t18_tampered_second_association_rejects_the_complete_page() {
    let fx = fixture_with_tamper(None, "second-safe", true);
    let response = fx
        .api
        .handle(ClientRequest::get("/client/tasks/task-a/history").with_session("tok"));
    assert_eq!(
        response.error_code(),
        Some(ClientErrorCode::ProjectionRejected)
    );
    let encoded = serde_json::to_string(&response).unwrap();
    assert!(!encoded.contains("event-1"));
    assert!(!encoded.contains("event-2"));
}

//! Live MODULE-020-AC-09 grant mutations (T17 / T21 / T23).

use std::num::NonZeroU32;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use advance_cli::client_api_adapters::Contract219GrantAdapter;
use advance_cli::contract218_bootstrap::bootstrap_contract218;
use advance_cli::observation_carriers::ObservationCarrierStore;
use advance_cli::observation_projection::Contract219EventProjector;
use advance_client_api::durable_idempotency::{
    DurableIdempotencyConfig, DurableIdempotencyError, DurableIdempotencyRepository,
    IdempotencyAnchor,
};
use advance_client_api::{
    BoundGrantApprovalPort, BoundGrantMutation, BoundMutationOutcome, ClientApi, ClientApiConfig,
    ClientCapParam, ClientErrorCode, ClientRequest, ClientSession, Platform, Principal,
    ProviderError,
    ProviderMutationRecovery, ProviderPrepareOutcome, Scope,
};
use advance_shared_types::sensitive_observation::{ObservationNode, RedactionDisposition};
use advance_database::{R2d2SqliteIndexHandle, SqliteIndexHandle};
use advance_scheduler::registry::ComponentRegistry;
use advance_scheduler::types::ComponentSubmitConfig;
use advance_scheduler::{ComponentSubmitApi, InMemoryComponentSubmitApi};
use advance_shared_types::component::ComponentType;
use advance_shared_types::event::Event;
use advance_shared_types::traits::{EventBusEmit, LeakDetector};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use cap_grant::{
    CapParam, ChannelApprovalDecision, ChannelApprovalPort, ChannelApprovalRequest, Grant,
    GrantApprovalIntake, GrantId, GrantIssuer, GrantProvenance, GrantSqliteIndex, GrantStatus,
    GrantStore, GrantTtl, PresetRegistry, SubsetValidator, SubsetValidatorImpl,
};
use cap_http::canonical_facade::canonical_scan_text;
use cap_http::DefaultLeakDetector;
use chrono::{TimeZone, Utc};
use serde_json::json;
use zeroize::Zeroizing;

const SENTINEL: &str = "legacy3-raw-secret-7f3a";
const BLOCK_JUSTIFICATION: &str = "-----BEGIN RSA PRIVATE KEY-----";
const REDACT_BEARER: &str = "Bearer eyJhbGciOiJIUzI1NiJ9.r48redact";

struct CountingBus {
    intake_approves: AtomicUsize,
    preset_applies: AtomicUsize,
}

impl EventBusEmit for CountingBus {
    fn emit(&self, event: Event) {
        if event.event_type == "resolver.invoked"
            && event.payload.get("decision").and_then(|value| value.as_str()) == Some("approve")
            && event.payload.get("resolver_type").and_then(|value| value.as_str())
                == Some("GrantApprovalIntake")
        {
            self.intake_approves.fetch_add(1, Ordering::SeqCst);
        }
        if event.event_type == "preset.applied" {
            self.preset_applies.fetch_add(1, Ordering::SeqCst);
        }
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

struct CountingPort {
    inner: Arc<Contract219GrantAdapter>,
    prepares: AtomicUsize,
    lists: AtomicUsize,
}

impl BoundGrantApprovalPort for CountingPort {
    fn list_pending_bound(
        &self,
    ) -> Result<
        Vec<advance_shared_types::sensitive_observation::BoundObservationDocument>,
        ProviderError,
    > {
        self.lists.fetch_add(1, Ordering::SeqCst);
        self.inner.list_pending_bound()
    }

    fn prepare_mutation_bound(
        &self,
        mutation_id: [u8; 32],
        request_fingerprint: [u8; 32],
        mutation: BoundGrantMutation,
    ) -> ProviderPrepareOutcome {
        self.prepares.fetch_add(1, Ordering::SeqCst);
        self.inner
            .prepare_mutation_bound(mutation_id, request_fingerprint, mutation)
    }

    fn verify_recovery_ticket_bound(
        &self,
        mutation_id: [u8; 32],
        request_fingerprint: [u8; 32],
        operation_tag: u8,
        recovery: &ProviderMutationRecovery,
    ) -> Result<(), ProviderError> {
        self.inner.verify_recovery_ticket_bound(
            mutation_id,
            request_fingerprint,
            operation_tag,
            recovery,
        )
    }

    fn execute_prepared_bound(&self, recovery: &ProviderMutationRecovery) -> BoundMutationOutcome {
        self.inner.execute_prepared_bound(recovery)
    }

    fn recover_mutation_bound(&self, recovery: &ProviderMutationRecovery) -> BoundMutationOutcome {
        self.inner.recover_mutation_bound(recovery)
    }

    fn acknowledge_client_done_bound(
        &self,
        done: &advance_client_api::ProviderClientDoneReceipt,
    ) -> Result<(), ProviderError> {
        self.inner.acknowledge_client_done_bound(done)
    }
}

struct Live {
    store: Arc<GrantStore>,
    intake: Arc<GrantApprovalIntake>,
    projector: Arc<Contract219EventProjector>,
    adapter: Arc<Contract219GrantAdapter>,
    api: ClientApi,
    intake_approves: Arc<CountingBus>,
}

async fn live_new() -> Live {
    live_inner(None).await
}

async fn live_inner(durable: Option<Arc<DurableIdempotencyRepository>>) -> Live {
    let workspace = tempfile::tempdir().expect("workspace");
    let registry = Arc::new(
        ComponentRegistry::open_in(workspace.path(), "components.db")
            .await
            .expect("registry"),
    );
    let runtime = bootstrap_contract218(workspace.path(), registry)
        .await
        .expect("C218 bootstrap");
    let carriers = Arc::new(
        ObservationCarrierStore::open(workspace.path()).expect("observation carrier store"),
    );
    let projector = Contract219EventProjector::build(
        Arc::clone(&runtime.provider),
        Arc::clone(&runtime.ready_issuer),
        runtime.boot_id,
        Arc::clone(&carriers),
    )
    .await
    .expect("C219 projector");

    for agent in ["caller-none", "caller-empty", "agent-key", "agent-grantee"] {
        projector
            .register_agent(agent)
            .await
            .unwrap_or_else(|error| panic!("register {agent}: {error}"));
    }

    let submit = InMemoryComponentSubmitApi::new().with_observation_provider(
        Arc::clone(&runtime.provider),
        Arc::clone(&runtime.ready_issuer),
    );
    submit
        .submit_component(
            "agent-key",
            component("comp-key", vec!["api_key".to_owned()]),
        )
        .await
        .expect("submit key component");
    submit
        .submit_component("agent-grantee", component("grantee-comp", Vec::new()))
        .await
        .expect("submit grantee component");
    projector.refresh_sources().await.expect("refresh sources");

    let sqlite: Arc<dyn SqliteIndexHandle> =
        Arc::new(R2d2SqliteIndexHandle::new_in_memory().expect("grant sqlite"));
    let grant_index = GrantSqliteIndex::new(sqlite);
    grant_index.ensure_schema().expect("grant schema");
    let intake_approves = Arc::new(CountingBus {
        intake_approves: AtomicUsize::new(0),
        preset_applies: AtomicUsize::new(0),
    });
    let bus: Arc<dyn EventBusEmit> = Arc::clone(&intake_approves) as Arc<dyn EventBusEmit>;
    let store = Arc::new(GrantStore::new(grant_index, Arc::clone(&bus)));
    let validator: Arc<dyn SubsetValidator> = Arc::new(SubsetValidatorImpl::new());
    let mut presets = PresetRegistry::with_builtins();
    let yaml = r#"
name: live-custom
resolver-chain:
  - AutoDeny
default-ttl: lifecycle
grants:
  - capability: fs
    params:
      - key: read-paths
        value: /tmp/a/*
    ttl: lifecycle
  - capability: fs
    params:
      - key: read-paths
        value: /tmp/b/*
    ttl: lifecycle
"#;
    let value: serde_yml::Value = serde_yml::from_str(yaml).expect("parse custom preset");
    presets
        .load_custom_value(&value)
        .expect("custom preset loads");
    let intake = Arc::new(GrantApprovalIntake::new(
        Arc::clone(&store),
        validator,
        Arc::new(presets),
        bus,
    ));
    let adapter = Arc::new(Contract219GrantAdapter::new(
        Arc::clone(&intake),
        Arc::clone(&projector),
    ));
    let detector: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let mut api = ClientApi::new(ClientApiConfig::default())
        .with_bound_grant_provider(adapter.clone())
        .with_observation_redactor(projector.redactor())
        .with_leak_detector(detector);
    if let Some(repository) = durable {
        api = api.with_durable_idempotency(repository);
    }
    api.sessions().insert(
        "tok".to_owned(),
        ClientSession {
            session_id: "session".to_owned(),
            principal: Principal::operator("operator"),
            platform: Platform::Web,
            scopes: Scope::operator_default(),
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );
    Live {
        store,
        intake,
        projector,
        adapter,
        api,
        intake_approves,
    }
}

fn component(id: &str, sensitive: Vec<String>) -> ComponentSubmitConfig {
    ComponentSubmitConfig {
        id: id.to_owned(),
        component_type: ComponentType::Task,
        binary: Vec::new(),
        capabilities: Vec::new(),
        output_dir: None,
        trigger: None,
        restart_policy: None,
        delay: None,
        initial_grants: None,
        preset: None,
        retry: None,
        sensitive_params: sensitive,
    }
}

fn park(
    intake: &GrantApprovalIntake,
    request_id: &str,
    caller: &str,
    params: Option<Vec<CapParam>>,
    ttl: GrantTtl,
    justification: Option<&str>,
) {
    intake
        .request_approval(ChannelApprovalRequest {
            request_id: request_id.to_owned(),
            caller: caller.to_owned(),
            capability: "http".to_owned(),
            params,
            ttl,
            justification: justification.map(ToOwned::to_owned),
        })
        .expect("park pending");
}

fn api_key_params() -> Option<Vec<CapParam>> {
    Some(vec![CapParam {
        key: "api_key".to_owned(),
        value: SENTINEL.to_owned(),
    }])
}

fn until_ttl() -> GrantTtl {
    GrantTtl::Until(Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap())
}

fn listed_pending_ids(api: &ClientApi) -> Vec<String> {
    let listed = api.handle(ClientRequest::get("/client/grants/pending").with_session("tok"));
    assert!(listed.is_ok(), "{:?}", listed.error);
    let data = listed.data.unwrap();
    data["requests"]
        .as_array()
        .expect("requests")
        .iter()
        .map(|row| row["request_id"].as_str().expect("request_id").to_owned())
        .collect()
}

fn listed_revision(api: &ClientApi, request_id: &str) -> String {
    let listed = api.handle(ClientRequest::get("/client/grants/pending").with_session("tok"));
    assert!(listed.is_ok(), "{:?}", listed.error);
    let data = listed.data.unwrap();
    data["requests"]
        .as_array()
        .expect("requests")
        .iter()
        .find(|row| row["request_id"] == request_id)
        .expect("request present")["decision_revision"]
        .as_str()
        .expect("revision")
        .to_owned()
}

fn grant(
    id: &str,
    grantee: &str,
    paths: &str,
    provenance: GrantProvenance,
) -> Grant {
    Grant {
        id: GrantId::new(id),
        grantee: grantee.to_owned(),
        capability: "fs".to_owned(),
        params: vec![CapParam {
            key: "read-paths".to_owned(),
            value: paths.to_owned(),
        }],
        ttl: GrantTtl::Lifecycle,
        issuer: GrantIssuer::Admin,
        provenance,
        status: GrantStatus::Active,
        created_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        expires_at: None,
    }
}

fn write_nocache(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write;
    use std::os::unix::io::AsRawFd;
    let mut file = std::fs::File::create(path).expect("create nocache journal");
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_NOCACHE, 1) };
    assert_eq!(rc, 0, "F_NOCACHE");
    file.write_all(bytes).expect("write nocache journal");
    file.sync_all().expect("sync nocache journal");
}

fn vnode_page_resident(path: &std::path::Path, offset: u64) -> bool {
    use std::os::unix::io::AsRawFd;
    let file = std::fs::File::open(path).expect("open for mincore");
    let len = file.metadata().expect("mincore meta").len();
    assert!(offset < len, "mincore offset {offset} is past len {len}");
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    let map_len = ((len + page - 1) / page) * page;
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            map_len as usize,
            libc::PROT_READ,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED, "mmap journal for mincore");
    let page_off = (offset / page) * page;
    let mut status: libc::c_char = 0;
    let rc = unsafe { libc::mincore(ptr.add(page_off as usize), page as usize, &mut status) };
    unsafe { libc::munmap(ptr, map_len as usize) };
    assert_eq!(rc, 0, "mincore");
    status as u8 & 1 == 1
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t17_live_list_lossless() {
    let live = live_new().await;
    park(
        &live.intake,
        "none-once",
        "caller-none",
        None,
        GrantTtl::Once,
        None,
    );
    park(
        &live.intake,
        "empty-life",
        "caller-empty",
        Some(Vec::new()),
        GrantTtl::Lifecycle,
        Some("review"),
    );
    park(
        &live.intake,
        "key-persist",
        "comp-key",
        api_key_params(),
        GrantTtl::Persistent,
        Some("key review"),
    );
    park(
        &live.intake,
        "none-duration",
        "caller-none",
        None,
        GrantTtl::Duration(1_000),
        None,
    );
    park(
        &live.intake,
        "none-until",
        "caller-none",
        None,
        until_ttl(),
        Some("until"),
    );

    let listed = live
        .api
        .handle(ClientRequest::get("/client/grants/pending").with_session("tok"));
    assert!(listed.is_ok(), "{:?}", listed.error);
    let data = listed.data.as_ref().unwrap();
    let requests = data["requests"].as_array().expect("requests");
    assert_eq!(requests.len(), 5);
    let callers: Vec<_> = requests
        .iter()
        .map(|row| row["caller_id"].as_str().unwrap().to_owned())
        .collect();
    assert!(callers.contains(&"caller-none".to_owned()));
    assert!(callers.contains(&"caller-empty".to_owned()));
    assert!(callers.contains(&"comp-key".to_owned()));
    let kinds: Vec<_> = requests
        .iter()
        .map(|row| row["ttl"]["kind"].as_str().unwrap().to_owned())
        .collect();
    for expected in ["once", "lifecycle", "persistent", "duration", "until"] {
        assert!(kinds.contains(&expected.to_owned()), "{kinds:?}");
    }
    let none = requests
        .iter()
        .find(|row| row["request_id"] == "none-once")
        .unwrap();
    assert!(none["params"].is_null());
    let empty = requests
        .iter()
        .find(|row| row["request_id"] == "empty-life")
        .unwrap();
    assert_eq!(empty["params"].as_array().unwrap().len(), 0);
    let key = requests
        .iter()
        .find(|row| row["request_id"] == "key-persist")
        .unwrap();
    assert_eq!(key["params"][0]["value"], "[REDACTED]");
    for row in requests {
        assert_eq!(
            row["decision_revision"].as_str().unwrap().len(),
            247,
            "{}",
            row["request_id"]
        );
        assert_eq!(row["capability"], "http");
    }
    let duration = requests
        .iter()
        .find(|row| row["request_id"] == "none-duration")
        .unwrap();
    assert_eq!(duration["ttl"]["milliseconds_u64"], "1000");
    assert!(none["justification"].is_null());
    assert_eq!(empty["justification"], "review");
    assert_eq!(key["justification"], "key review");
    let until = requests
        .iter()
        .find(|row| row["request_id"] == "none-until")
        .unwrap();
    assert_eq!(until["justification"], "until");
    assert_eq!(until["ttl"]["at"], "2027-01-01T00:00:00Z");
    for row in requests {
        assert!(row.get("grant_id").is_none(), "{row}");
    }
    let encoded = serde_json::to_string(&listed).unwrap();
    assert!(!encoded.contains("created_at"));
    assert!(!encoded.contains(SENTINEL));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t17_live_approve_deny_narrow() {
    let live = live_new().await;
    park(
        &live.intake,
        "approve-me",
        "caller-none",
        None,
        GrantTtl::Once,
        None,
    );
    park(
        &live.intake,
        "deny-me",
        "caller-empty",
        Some(Vec::new()),
        GrantTtl::Once,
        None,
    );
    park(
        &live.intake,
        "narrow-me",
        "caller-none",
        Some(vec![CapParam {
            key: "allowlist".to_owned(),
            value: "https://example.com/*".to_owned(),
        }]),
        GrantTtl::Once,
        None,
    );

    let approve_rev = listed_revision(&live.api, "approve-me");
    let approved = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/approve-me:approve",
            json!({ "decision_revision": approve_rev }),
        )
        .with_session("tok")
        .with_idempotency_key("approve-1"),
    );
    assert!(approved.is_ok(), "{:?}", approved.error);
    assert_eq!(approved.data.unwrap()["status"], "approved");
    assert_eq!(
        live.intake.decision("approve-me"),
        ChannelApprovalDecision::Approved
    );
    assert_eq!(
        ChannelApprovalPort::take_approved(&*live.intake, "approve-me"),
        Some(None)
    );
    let after_approve = listed_pending_ids(&live.api);
    assert!(
        !after_approve.iter().any(|id| id == "approve-me"),
        "{after_approve:?}"
    );
    assert!(
        after_approve.iter().any(|id| id == "deny-me"),
        "{after_approve:?}"
    );
    assert!(
        after_approve.iter().any(|id| id == "narrow-me"),
        "{after_approve:?}"
    );

    let deny_rev = listed_revision(&live.api, "deny-me");
    let denied = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/deny-me:deny",
            json!({ "decision_revision": deny_rev, "reason": "no" }),
        )
        .with_session("tok")
        .with_idempotency_key("deny-1"),
    );
    assert!(denied.is_ok(), "{:?}", denied.error);
    assert_eq!(denied.data.unwrap()["status"], "denied");
    assert_eq!(
        live.intake.decision("deny-me"),
        ChannelApprovalDecision::Denied("no".to_owned())
    );
    let after_deny = listed_pending_ids(&live.api);
    assert!(
        !after_deny.iter().any(|id| id == "approve-me"),
        "{after_deny:?}"
    );
    assert!(
        !after_deny.iter().any(|id| id == "deny-me"),
        "{after_deny:?}"
    );
    assert!(
        after_deny.iter().any(|id| id == "narrow-me"),
        "{after_deny:?}"
    );

    let narrow_rev = listed_revision(&live.api, "narrow-me");
    let bad = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/narrow-me:narrow",
            json!({
                "decision_revision": narrow_rev,
                "params": [{ "key": "allowlist", "value": "https://evil.example/*" }]
            }),
        )
        .with_session("tok")
        .with_idempotency_key("narrow-bad"),
    );
    assert_eq!(bad.error_code(), Some(ClientErrorCode::InvalidState));
    assert_eq!(live.intake.list_pending().len(), 1);

    let counting = Arc::new(CountingPort {
        inner: Arc::clone(&live.adapter),
        prepares: AtomicUsize::new(0),
        lists: AtomicUsize::new(0),
    });
    let detector: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let counting_api = ClientApi::new(ClientApiConfig::default())
        .with_bound_grant_provider(counting.clone())
        .with_observation_redactor(live.projector.redactor())
        .with_leak_detector(detector);
    counting_api.sessions().insert(
        "tok".to_owned(),
        ClientSession {
            session_id: "session".to_owned(),
            principal: Principal::operator("operator"),
            platform: Platform::Web,
            scopes: Scope::operator_default(),
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );
    let empty_reason = counting_api.handle(
        ClientRequest::post(
            "/client/grants/pending/narrow-me:deny",
            json!({ "decision_revision": listed_revision(&counting_api, "narrow-me"), "reason": "" }),
        )
        .with_session("tok")
        .with_idempotency_key("empty-reason"),
    );
    assert_eq!(
        empty_reason.error_code(),
        Some(ClientErrorCode::ProjectionRejected)
    );

    let oversize_reason = counting_api.handle(
        ClientRequest::post(
            "/client/grants/pending/narrow-me:deny",
            json!({
                "decision_revision": listed_revision(&counting_api, "narrow-me"),
                "reason": "x".repeat(1_025)
            }),
        )
        .with_session("tok")
        .with_idempotency_key("oversize-reason"),
    );
    assert_eq!(
        oversize_reason.error_code(),
        Some(ClientErrorCode::ProjectionRejected)
    );
    assert_eq!(counting.prepares.load(Ordering::SeqCst), 0);
    assert_eq!(live.intake.list_pending().len(), 1);

    let good = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/narrow-me:narrow",
            json!({
                "decision_revision": listed_revision(&live.api, "narrow-me"),
                "params": [{ "key": "allowlist", "value": "https://example.com/api/*" }]
            }),
        )
        .with_session("tok")
        .with_idempotency_key("narrow-ok"),
    );
    assert!(good.is_ok(), "{:?}", good.error);
    assert_eq!(good.data.unwrap()["status"], "narrowed");
    assert_eq!(
        live.intake.decision("narrow-me"),
        ChannelApprovalDecision::Approved
    );
    assert_eq!(
        ChannelApprovalPort::take_approved(&*live.intake, "narrow-me"),
        Some(Some(vec![CapParam {
            key: "allowlist".to_owned(),
            value: "https://example.com/api/*".to_owned(),
        }]))
    );
    assert!(live.intake.list_pending().is_empty());
    assert!(
        listed_pending_ids(&live.api).is_empty(),
        "GET /client/grants/pending must omit decided ids"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t17_live_revoke() {
    let live = live_new().await;
    live.store
        .insert_dynamic(grant(
            "root-1",
            "grantee-comp",
            "/tmp/*",
            GrantProvenance::Requested,
        ))
        .expect("root");
    live.store
        .insert_dynamic(grant(
            "child-1",
            "grantee-comp",
            "/tmp/a/*",
            GrantProvenance::Delegated(GrantId::new("root-1")),
        ))
        .expect("child");

    let revoked = live.api.handle(
        ClientRequest::post("/client/grants/root-1:revoke", json!({}))
            .with_session("tok")
            .with_idempotency_key("revoke-1"),
    );
    assert!(revoked.is_ok(), "{:?}", revoked.error);
    assert_eq!(revoked.data.unwrap()["revoked_count"], 2);
    assert_eq!(
        live.store.get("root-1").map(|grant| grant.status),
        Some(GrantStatus::Revoked)
    );
    assert_eq!(
        live.store.get("child-1").map(|grant| grant.status),
        Some(GrantStatus::Revoked)
    );

    let missing = live.api.handle(
        ClientRequest::post("/client/grants/missing:revoke", json!({}))
            .with_session("tok")
            .with_idempotency_key("revoke-missing"),
    );
    assert_eq!(missing.error_code(), Some(ClientErrorCode::NotFound));

    live.store
        .insert(grant(
            "static:grantee-comp:fs",
            "grantee-comp",
            "/policy/*",
            GrantProvenance::StaticConfig,
        ))
        .expect("static");
    live.store
        .insert(grant(
            "policy-root-1",
            "grantee-comp",
            "/etc/*",
            GrantProvenance::StaticConfig,
        ))
        .expect("static-unprefixed");
    for (grant_id, ik) in [
        ("static:grantee-comp:fs", "revoke-static"),
        ("policy-root-1", "revoke-static-unprefixed"),
    ] {
        let static_revoke = live.api.handle(
            ClientRequest::post(
                format!("/client/grants/{grant_id}:revoke"),
                json!({}),
            )
            .with_session("tok")
            .with_idempotency_key(ik),
        );
        assert_eq!(
            static_revoke.error_code(),
            Some(ClientErrorCode::NotFound),
            "{grant_id}"
        );
        let stored = live.store.get(grant_id).expect(grant_id);
        assert_eq!(stored.status, GrantStatus::Active, "{grant_id}");
        assert!(
            matches!(stored.provenance, GrantProvenance::StaticConfig),
            "{grant_id}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t17_live_preset() {
    let live = live_new().await;
    live.store
        .insert_dynamic(grant(
            "cover-a",
            "grantee-comp",
            "/tmp/a/*",
            GrantProvenance::Requested,
        ))
        .expect("cover a");
    live.store
        .insert_dynamic(grant(
            "cover-b",
            "grantee-comp",
            "/tmp/b/*",
            GrantProvenance::Requested,
        ))
        .expect("cover b");

    let restrict = live.api.handle(
        ClientRequest::post(
            "/client/presets/restrict:apply",
            json!({ "target_agent_id": "grantee-comp" }),
        )
        .with_session("tok")
        .with_idempotency_key("preset-restrict"),
    );
    assert!(restrict.is_ok(), "{:?}", restrict.error);
    assert!(restrict.data.unwrap()["created_grant_ids"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        live.store.get("cover-a").map(|grant| grant.status),
        Some(GrantStatus::Revoked)
    );
    assert_eq!(
        live.store.get("cover-b").map(|grant| grant.status),
        Some(GrantStatus::Revoked)
    );
    assert_eq!(
        live.store
            .list_by_grantee("grantee-comp")
            .into_iter()
            .filter(|grant| grant.status == GrantStatus::Active)
            .count(),
        0
    );

    live.store
        .insert_dynamic(grant(
            "cover-a2",
            "grantee-comp",
            "/tmp/a/*",
            GrantProvenance::Requested,
        ))
        .expect("cover a2");
    live.store
        .insert_dynamic(grant(
            "cover-b2",
            "grantee-comp",
            "/tmp/b/*",
            GrantProvenance::Requested,
        ))
        .expect("cover b2");
    let custom = live.api.handle(
        ClientRequest::post(
            "/client/presets/live-custom:apply",
            json!({ "target_agent_id": "grantee-comp" }),
        )
        .with_session("tok")
        .with_idempotency_key("preset-custom"),
    );
    assert!(custom.is_ok(), "{:?}", custom.error);
    let ids = custom.data.unwrap()["created_grant_ids"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(ids.len(), 2);
    let first = live
        .store
        .get(ids[0].as_str().expect("first created id"))
        .expect("first created grant");
    let second = live
        .store
        .get(ids[1].as_str().expect("second created id"))
        .expect("second created grant");
    assert_eq!(
        first.params.first().map(|param| param.value.as_str()),
        Some("/tmp/a/*")
    );
    assert_eq!(
        second.params.first().map(|param| param.value.as_str()),
        Some("/tmp/b/*")
    );
    let first_id = ids[0].as_str().expect("first created id");
    let second_id = ids[1].as_str().expect("second created id");
    assert_ne!(first_id, "cover-a2");
    assert_ne!(first_id, "cover-b2");
    assert_ne!(second_id, "cover-a2");
    assert_ne!(second_id, "cover-b2");
    assert!(matches!(
        first.provenance,
        GrantProvenance::Preset(ref name) if name == "live-custom"
    ));
    assert!(matches!(
        second.provenance,
        GrantProvenance::Preset(ref name) if name == "live-custom"
    ));
    assert_ne!(
        live.store.get("cover-a2").map(|grant| grant.status),
        Some(GrantStatus::Active)
    );
    assert_ne!(
        live.store.get("cover-b2").map(|grant| grant.status),
        Some(GrantStatus::Active)
    );

    let unknown = live.api.handle(
        ClientRequest::post(
            "/client/presets/no-such:apply",
            json!({ "target_agent_id": "grantee-comp" }),
        )
        .with_session("tok")
        .with_idempotency_key("preset-unknown"),
    );
    assert_eq!(unknown.error_code(), Some(ClientErrorCode::NotFound));
    let active: Vec<String> = live
        .store
        .list_by_grantee("grantee-comp")
        .into_iter()
        .filter(|grant| grant.status == GrantStatus::Active)
        .map(|grant| grant.id.as_str().to_owned())
        .collect();
    assert_eq!(active.len(), 2);
    assert!(active.contains(&first_id.to_owned()), "{active:?}");
    assert!(active.contains(&second_id.to_owned()), "{active:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t17_rev_stale() {
    let live = live_new().await;
    park(
        &live.intake,
        "rev-a",
        "caller-none",
        None,
        GrantTtl::Once,
        None,
    );
    park(
        &live.intake,
        "rev-b",
        "caller-empty",
        Some(Vec::new()),
        GrantTtl::Once,
        None,
    );
    let rev_a = listed_revision(&live.api, "rev-a");
    let rev_b = listed_revision(&live.api, "rev-b");

    park(
        &live.intake,
        "rev-a",
        "caller-none",
        None,
        GrantTtl::Once,
        None,
    );
    let replaced = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/rev-a:approve",
            json!({ "decision_revision": rev_a }),
        )
        .with_session("tok")
        .with_idempotency_key("replaced"),
    );
    assert_eq!(replaced.error_code(), Some(ClientErrorCode::InvalidState));
    assert_eq!(live.intake.list_pending().len(), 2);

    let omit = live.api.handle(
        ClientRequest::post("/client/grants/pending/rev-a:approve", json!({}))
            .with_session("tok")
            .with_idempotency_key("omit"),
    );
    assert_eq!(
        omit.error_code(),
        Some(ClientErrorCode::ProjectionRejected)
    );

    let swapped = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/rev-a:approve",
            json!({ "decision_revision": rev_b }),
        )
        .with_session("tok")
        .with_idempotency_key("swap"),
    );
    assert_eq!(swapped.error_code(), Some(ClientErrorCode::InvalidState));

    let rev_a = listed_revision(&live.api, "rev-a");
    let swapped_b = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/rev-b:approve",
            json!({ "decision_revision": rev_a }),
        )
        .with_session("tok")
        .with_idempotency_key("swap-b"),
    );
    assert_eq!(swapped_b.error_code(), Some(ClientErrorCode::InvalidState));

    let forged_a = live
        .adapter
        .test_revision_binding_foreign_request("rev-a", "rev-b")
        .expect("forged A revision");
    let bind_a = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/rev-a:approve",
            json!({ "decision_revision": forged_a }),
        )
        .with_session("tok")
        .with_idempotency_key("bind-a"),
    );
    assert_eq!(bind_a.error_code(), Some(ClientErrorCode::InvalidState));

    let forged_b = live
        .adapter
        .test_revision_binding_foreign_request("rev-b", "rev-a")
        .expect("forged B revision");
    let bind_b = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/rev-b:approve",
            json!({ "decision_revision": forged_b }),
        )
        .with_session("tok")
        .with_idempotency_key("bind-b"),
    );
    assert_eq!(bind_b.error_code(), Some(ClientErrorCode::InvalidState));

    let doc_tampered = live
        .adapter
        .test_revision_tampered_document_digest("rev-a")
        .expect("document-digest tamper");
    let bind_doc = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/rev-a:approve",
            json!({ "decision_revision": doc_tampered }),
        )
        .with_session("tok")
        .with_idempotency_key("bind-doc"),
    );
    assert_eq!(bind_doc.error_code(), Some(ClientErrorCode::InvalidState));

    for (offset, ik) in [(1usize, "bind-boot"), (57, "bind-source"), (89, "bind-fp")] {
        let field_tampered = live
            .adapter
            .test_revision_tampered_field("rev-a", offset)
            .expect("field remac");
        let bind_field = live.api.handle(
            ClientRequest::post(
                "/client/grants/pending/rev-a:approve",
                json!({ "decision_revision": field_tampered }),
            )
            .with_session("tok")
            .with_idempotency_key(ik),
        );
        assert_eq!(
            bind_field.error_code(),
            Some(ClientErrorCode::InvalidState),
            "{ik}"
        );
    }

    let mut raw = URL_SAFE_NO_PAD.decode(&rev_a).expect("revision");
    let last = raw.len() - 1;
    raw[last] ^= 1;
    let tampered = URL_SAFE_NO_PAD.encode(&raw);
    let tamper = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/rev-a:approve",
            json!({ "decision_revision": tampered }),
        )
        .with_session("tok")
        .with_idempotency_key("tamper"),
    );
    assert_eq!(tamper.error_code(), Some(ClientErrorCode::InvalidState));

    for (offset, ik) in [
        (1usize, "deny-boot"),
        (57, "deny-source"),
        (89, "deny-fp"),
        (121, "deny-doc"),
    ] {
        let deny_remac = live
            .adapter
            .test_revision_tampered_field("rev-a", offset)
            .expect("deny remac");
        let deny_stale = live.api.handle(
            ClientRequest::post(
                "/client/grants/pending/rev-a:deny",
                json!({ "decision_revision": deny_remac, "reason": "no" }),
            )
            .with_session("tok")
            .with_idempotency_key(ik),
        );
        assert_eq!(
            deny_stale.error_code(),
            Some(ClientErrorCode::InvalidState),
            "{ik}"
        );
    }

    for (offset, ik) in [
        (1usize, "narrow-boot"),
        (57, "narrow-source"),
        (89, "narrow-fp"),
        (121, "narrow-doc"),
    ] {
        let narrow_remac = live
            .adapter
            .test_revision_tampered_field("rev-b", offset)
            .expect("narrow remac");
        let narrow_stale = live.api.handle(
            ClientRequest::post(
                "/client/grants/pending/rev-b:narrow",
                json!({ "decision_revision": narrow_remac, "params": [] }),
            )
            .with_session("tok")
            .with_idempotency_key(ik),
        );
        assert_eq!(
            narrow_stale.error_code(),
            Some(ClientErrorCode::InvalidState),
            "{ik}"
        );
    }
    assert_eq!(live.intake.list_pending().len(), 2);
    let pending_ids = live_pending_ids(&live.intake);
    assert!(pending_ids.iter().any(|id| id == "rev-a"));
    assert!(pending_ids.iter().any(|id| id == "rev-b"));

    let ok = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/rev-a:approve",
            json!({ "decision_revision": rev_a }),
        )
        .with_session("tok")
        .with_idempotency_key("ok"),
    );
    assert!(ok.is_ok(), "{:?}", ok.error);
    assert_eq!(ok.data.as_ref().unwrap()["status"], "approved");
    assert_eq!(
        live.intake.decision("rev-a"),
        ChannelApprovalDecision::Approved
    );
    assert_eq!(
        live.intake.decision("rev-b"),
        ChannelApprovalDecision::Pending
    );
    let remaining = live_pending_ids(&live.intake);
    assert_eq!(remaining, vec!["rev-b".to_owned()]);
    assert_eq!(listed_pending_ids(&live.api), vec!["rev-b".to_owned()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t17_idem_neg() {
    let live = live_new().await;
    park(
        &live.intake,
        "idem-a",
        "caller-none",
        None,
        GrantTtl::Once,
        None,
    );
    let revision = listed_revision(&live.api, "idem-a");
    let counting = Arc::new(CountingPort {
        inner: Arc::clone(&live.adapter),
        prepares: AtomicUsize::new(0),
        lists: AtomicUsize::new(0),
    });
    let detector: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let api = ClientApi::new(ClientApiConfig::default())
        .with_bound_grant_provider(counting.clone())
        .with_observation_redactor(live.projector.redactor())
        .with_leak_detector(detector);
    api.sessions().insert(
        "tok".to_owned(),
        ClientSession {
            session_id: "session".to_owned(),
            principal: Principal::operator("operator"),
            platform: Platform::Web,
            scopes: Scope::operator_default(),
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );

    let mut first_version = ClientRequest::post(
        "/client/grants/pending/idem-a:approve",
        json!({ "decision_revision": revision }),
    )
    .with_session("tok")
    .with_idempotency_key("version-first");
    first_version.api_version = "1999-01-01".to_owned();
    let first_unsupported = api.handle(first_version);
    assert_eq!(
        first_unsupported.error_code(),
        Some(ClientErrorCode::UnsupportedApiVersion)
    );
    assert_eq!(counting.prepares.load(Ordering::SeqCst), 0);

    let first = api.handle(
        ClientRequest::post(
            "/client/grants/pending/idem-a:approve",
            json!({ "decision_revision": revision }),
        )
        .with_session("tok")
        .with_idempotency_key("same-key"),
    );
    assert!(first.is_ok(), "{:?}", first.error);
    let conflict = api.handle(
        ClientRequest::post(
            "/client/grants/pending/idem-a:deny",
            json!({ "decision_revision": revision, "reason": "no" }),
        )
        .with_session("tok")
        .with_idempotency_key("same-key"),
    );
    assert_eq!(
        conflict.error_code(),
        Some(ClientErrorCode::IdempotencyConflict)
    );

    let mut versioned = ClientRequest::post(
        "/client/grants/pending/idem-a:approve",
        json!({ "decision_revision": revision }),
    )
    .with_session("tok")
    .with_idempotency_key("same-key");
    versioned.api_version = "1999-01-01".to_owned();
    let unsupported = api.handle(versioned);
    assert_eq!(
        unsupported.error_code(),
        Some(ClientErrorCode::UnsupportedApiVersion)
    );
    assert_eq!(counting.prepares.load(Ordering::SeqCst), 1);

    park(
        &live.intake,
        "idem-b",
        "caller-empty",
        Some(Vec::new()),
        GrantTtl::Once,
        None,
    );
    park(
        &live.intake,
        "idem-c",
        "caller-none",
        None,
        GrantTtl::Once,
        None,
    );
    let rev_b = listed_revision(&api, "idem-b");
    let rev_c = listed_revision(&api, "idem-c");
    let first_b = api.handle(
        ClientRequest::post(
            "/client/grants/pending/idem-b:approve",
            json!({ "decision_revision": rev_b }),
        )
        .with_session("tok")
        .with_idempotency_key("a-to-b"),
    );
    assert!(first_b.is_ok(), "{:?}", first_b.error);
    let prepares_after_b = counting.prepares.load(Ordering::SeqCst);
    let a_to_b = api.handle(
        ClientRequest::post(
            "/client/grants/pending/idem-c:approve",
            json!({ "decision_revision": rev_c }),
        )
        .with_session("tok")
        .with_idempotency_key("a-to-b"),
    );
    assert_eq!(
        a_to_b.error_code(),
        Some(ClientErrorCode::IdempotencyConflict)
    );
    assert_eq!(counting.prepares.load(Ordering::SeqCst), prepares_after_b);
    assert_eq!(
        live.intake.decision("idem-c"),
        ChannelApprovalDecision::Pending
    );
    assert_eq!(
        live.intake.decision("idem-b"),
        ChannelApprovalDecision::Approved
    );
    assert!(live_pending_ids(&live.intake)
        .iter()
        .any(|id| id == "idem-c"));

    park(
        &live.intake,
        "idem-reason",
        "caller-none",
        None,
        GrantTtl::Once,
        None,
    );
    let rev_reason = listed_revision(&api, "idem-reason");
    let deny_a = api.handle(
        ClientRequest::post(
            "/client/grants/pending/idem-reason:deny",
            json!({ "decision_revision": rev_reason, "reason": "no" }),
        )
        .with_session("tok")
        .with_idempotency_key("reason-key"),
    );
    assert!(deny_a.is_ok(), "{:?}", deny_a.error);
    let deny_b = api.handle(
        ClientRequest::post(
            "/client/grants/pending/idem-reason:deny",
            json!({ "decision_revision": rev_reason, "reason": "yes" }),
        )
        .with_session("tok")
        .with_idempotency_key("reason-key"),
    );
    assert_eq!(
        deny_b.error_code(),
        Some(ClientErrorCode::IdempotencyConflict)
    );

    park(
        &live.intake,
        "idem-params",
        "comp-key",
        api_key_params(),
        GrantTtl::Once,
        None,
    );
    let rev_params = listed_revision(&api, "idem-params");
    let narrow_a = api.handle(
        ClientRequest::post(
            "/client/grants/pending/idem-params:narrow",
            json!({
                "decision_revision": rev_params,
                "params": [{ "key": "api_key", "value": SENTINEL }]
            }),
        )
        .with_session("tok")
        .with_idempotency_key("params-key"),
    );
    assert!(narrow_a.is_ok(), "{:?}", narrow_a.error);
    let narrow_b = api.handle(
        ClientRequest::post(
            "/client/grants/pending/idem-params:narrow",
            json!({
                "decision_revision": rev_params,
                "params": [{ "key": "api_key", "value": "other-secret" }]
            }),
        )
        .with_session("tok")
        .with_idempotency_key("params-key"),
    );
    assert_eq!(
        narrow_b.error_code(),
        Some(ClientErrorCode::IdempotencyConflict)
    );

    park(
        &live.intake,
        "idem-path",
        "caller-none",
        None,
        GrantTtl::Once,
        None,
    );
    let rev_path = listed_revision(&api, "idem-path");
    let path_first = api.handle(
        ClientRequest::post(
            "/client/grants/pending/idem-path:approve",
            json!({ "decision_revision": rev_path }),
        )
        .with_session("tok")
        .with_idempotency_key("other-path"),
    );
    assert!(path_first.is_ok(), "{:?}", path_first.error);
    let path_other = api.handle(
        ClientRequest::post("/client/grants/missing-grant:revoke", json!({}))
            .with_session("tok")
            .with_idempotency_key("other-path"),
    );
    assert_eq!(
        path_other.error_code(),
        Some(ClientErrorCode::IdempotencyConflict)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t17_scope() {
    let live = live_new().await;
    park(
        &live.intake,
        "scope-parked",
        "caller-none",
        None,
        GrantTtl::Once,
        None,
    );
    let counting = Arc::new(CountingPort {
        inner: Arc::clone(&live.adapter),
        prepares: AtomicUsize::new(0),
        lists: AtomicUsize::new(0),
    });
    let detector: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let api = ClientApi::new(ClientApiConfig::default())
        .with_bound_grant_provider(counting.clone())
        .with_observation_redactor(live.projector.redactor())
        .with_leak_detector(detector);
    api.sessions().insert(
        "no-grants".to_owned(),
        ClientSession {
            session_id: "no-grants".to_owned(),
            principal: Principal::operator("reader"),
            platform: Platform::Web,
            scopes: vec![Scope::ReadRuns],
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );
    let denied = api.handle(ClientRequest::get("/client/grants/pending").with_session("no-grants"));
    assert_eq!(denied.error_code(), Some(ClientErrorCode::Forbidden));
    assert_eq!(counting.prepares.load(Ordering::SeqCst), 0);
    assert_eq!(counting.lists.load(Ordering::SeqCst), 0);
    assert!(live_pending_ids(&live.intake)
        .iter()
        .any(|id| id == "scope-parked"));
    let dummy_rev = "A".repeat(247);
    for (index, (path, body)) in [
        (
            "/client/grants/pending/x:approve",
            json!({ "decision_revision": dummy_rev }),
        ),
        (
            "/client/grants/pending/x:deny",
            json!({ "decision_revision": dummy_rev, "reason": "no" }),
        ),
        (
            "/client/grants/pending/x:narrow",
            json!({
                "decision_revision": dummy_rev,
                "params": [{ "key": "api_key", "value": SENTINEL }]
            }),
        ),
        ("/client/grants/x:revoke", json!({})),
        (
            "/client/presets/restrict:apply",
            json!({ "target_agent_id": "x" }),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let denied = api.handle(
            ClientRequest::post(path, body)
                .with_session("no-grants")
                .with_idempotency_key(format!("scope-deny-{index}")),
        );
        assert_eq!(
            denied.error_code(),
            Some(ClientErrorCode::Forbidden),
            "{path}"
        );
        assert_eq!(
            counting.prepares.load(Ordering::SeqCst),
            0,
            "{path} must not reach provider"
        );
        assert_eq!(
            counting.lists.load(Ordering::SeqCst),
            0,
            "{path} must not list"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t17_live_list_survives_sibling_shapes() {
    let live = live_new().await;
    park(
        &live.intake,
        "visible-none",
        "caller-none",
        None,
        GrantTtl::Once,
        None,
    );
    park(
        &live.intake,
        "visible-fs",
        "caller-none",
        Some(vec![CapParam {
            key: "read-paths".to_owned(),
            value: "/tmp/*".to_owned(),
        }]),
        GrantTtl::Once,
        None,
    );
    park(
        &live.intake,
        "ghost-caller",
        "ghost-agent",
        None,
        GrantTtl::Once,
        None,
    );
    park(
        &live.intake,
        "visible-fs-pair",
        "caller-none",
        Some(vec![
            CapParam {
                key: "write-paths".to_owned(),
                value: "/tmp/w/*".to_owned(),
            },
            CapParam {
                key: "read-paths".to_owned(),
                value: "/tmp/r/*".to_owned(),
            },
        ]),
        GrantTtl::Once,
        None,
    );
    park(
        &live.intake,
        "blocked-fs",
        "caller-none",
        Some(vec![CapParam {
            key: "read-paths".to_owned(),
            value: BLOCK_JUSTIFICATION.to_owned(),
        }]),
        GrantTtl::Once,
        None,
    );
    park(
        &live.intake,
        "hidden-token",
        "caller-none",
        Some(vec![CapParam {
            key: "token".to_owned(),
            value: "credential".to_owned(),
        }]),
        GrantTtl::Once,
        None,
    );
    park(
        &live.intake,
        "unknown-keys",
        "caller-none",
        Some(vec![CapParam {
            key: "not-a-registered-shape".to_owned(),
            value: "x".to_owned(),
        }]),
        GrantTtl::Once,
        None,
    );
    let listed = live
        .api
        .handle(ClientRequest::get("/client/grants/pending").with_session("tok"));
    assert!(listed.is_ok(), "{:?}", listed.error);
    let requests = listed.data.as_ref().unwrap()["requests"]
        .as_array()
        .expect("requests");
    let ids: Vec<_> = requests
        .iter()
        .map(|row| row["request_id"].as_str().unwrap().to_owned())
        .collect();
    assert!(ids.contains(&"visible-none".to_owned()), "{ids:?}");
    assert!(ids.contains(&"visible-fs".to_owned()), "{ids:?}");
    assert!(ids.contains(&"visible-fs-pair".to_owned()), "{ids:?}");
    assert!(ids.contains(&"blocked-fs".to_owned()), "{ids:?}");
    assert!(!ids.contains(&"ghost-caller".to_owned()), "{ids:?}");
    assert!(!ids.contains(&"hidden-token".to_owned()), "{ids:?}");
    assert!(!ids.contains(&"unknown-keys".to_owned()), "{ids:?}");
    let visible_fs = requests
        .iter()
        .find(|row| row["request_id"] == "visible-fs")
        .expect("visible-fs");
    assert_eq!(visible_fs["params"][0]["key"], "read-paths");
    assert_eq!(visible_fs["params"][0]["value"], "/tmp/*");
    let pair = requests
        .iter()
        .find(|row| row["request_id"] == "visible-fs-pair")
        .expect("visible-fs-pair");
    let pair_params = pair["params"].as_array().expect("pair params");
    let write = pair_params
        .iter()
        .find(|param| param["key"] == "write-paths")
        .expect("write-paths");
    let read = pair_params
        .iter()
        .find(|param| param["key"] == "read-paths")
        .expect("read-paths");
    assert_eq!(write["value"], "/tmp/w/*");
    assert_eq!(read["value"], "/tmp/r/*");
    let encoded = serde_json::to_string(&listed).unwrap();
    assert!(!encoded.contains(BLOCK_JUSTIFICATION));
    let blocked = requests
        .iter()
        .find(|row| row["request_id"] == "blocked-fs")
        .expect("blocked-fs");
    assert_eq!(blocked["params"][0]["key"], "read-paths");
    assert_eq!(blocked["params"][0]["value"], "[REDACTED]");

    let blocked_rev = listed_revision(&live.api, "blocked-fs");
    let approved = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/blocked-fs:approve",
            json!({ "decision_revision": blocked_rev }),
        )
        .with_session("tok")
        .with_idempotency_key("block-approve"),
    );
    assert_eq!(approved.error_code(), Some(ClientErrorCode::InvalidState));
    assert_eq!(
        live.intake.decision("blocked-fs"),
        ChannelApprovalDecision::Pending
    );
    let narrowed = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/blocked-fs:narrow",
            json!({
                "decision_revision": blocked_rev,
                "params": [{ "key": "read-paths", "value": "/tmp/*" }]
            }),
        )
        .with_session("tok")
        .with_idempotency_key("block-narrow"),
    );
    assert_eq!(narrowed.error_code(), Some(ClientErrorCode::InvalidState));
    assert_eq!(
        live.intake.decision("blocked-fs"),
        ChannelApprovalDecision::Pending
    );
    let denied = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/blocked-fs:deny",
            json!({ "decision_revision": blocked_rev, "reason": "blocked-param" }),
        )
        .with_session("tok")
        .with_idempotency_key("block-deny"),
    );
    assert!(denied.is_ok(), "{:?}", denied.error);
    let after_deny = listed_pending_ids(&live.api);
    assert!(
        !after_deny.iter().any(|id| id == "blocked-fs"),
        "{after_deny:?}"
    );
    assert!(
        after_deny.iter().any(|id| id == "visible-none"),
        "{after_deny:?}"
    );
    assert!(
        after_deny.iter().any(|id| id == "visible-fs"),
        "{after_deny:?}"
    );
    assert!(
        after_deny.iter().any(|id| id == "visible-fs-pair"),
        "{after_deny:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t17_revoke_without_c219_source() {
    let live = live_new().await;
    live.store
        .insert_dynamic(grant(
            "ghost-1",
            "ghost-grantee",
            "/tmp/*",
            GrantProvenance::Requested,
        ))
        .expect("ghost grant");
    let revoked = live.api.handle(
        ClientRequest::post("/client/grants/ghost-1:revoke", json!({}))
            .with_session("tok")
            .with_idempotency_key("revoke-ghost"),
    );
    assert_eq!(
        revoked.error_code(),
        Some(ClientErrorCode::ModuleUnavailable)
    );
    assert_eq!(
        live.intake
            .snapshot_grant("ghost-1")
            .map(|grant| grant.status),
        Some(GrantStatus::Active)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t17_preset_without_c219_source() {
    let live = live_new().await;
    live.store
        .insert_dynamic(grant(
            "ghost-preset-1",
            "ghost-preset",
            "/tmp/*",
            GrantProvenance::Requested,
        ))
        .expect("ghost preset grant");
    park(
        &live.intake,
        "ghost-preset-pending",
        "ghost-preset",
        None,
        GrantTtl::Once,
        None,
    );
    let restrict = live.api.handle(
        ClientRequest::post(
            "/client/presets/restrict:apply",
            json!({ "target_agent_id": "ghost-preset" }),
        )
        .with_session("tok")
        .with_idempotency_key("preset-ghost"),
    );
    assert_eq!(
        restrict.error_code(),
        Some(ClientErrorCode::ModuleUnavailable)
    );
    assert_eq!(
        live.intake
            .snapshot_grant("ghost-preset-1")
            .map(|grant| grant.status),
        Some(GrantStatus::Active)
    );
    assert_eq!(
        live.intake.decision("ghost-preset-pending"),
        ChannelApprovalDecision::Pending
    );
    assert!(
        live_pending_ids(&live.intake)
            .iter()
            .any(|id| id == "ghost-preset-pending"),
        "ghost pending must remain listed, not deleted"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t21_live_justification_block() {
    let live = live_new().await;
    park(
        &live.intake,
        "blocked",
        "comp-key",
        api_key_params(),
        GrantTtl::Once,
        Some(BLOCK_JUSTIFICATION),
    );
    let listed = live
        .api
        .handle(ClientRequest::get("/client/grants/pending").with_session("tok"));
    assert_eq!(
        listed.error_code(),
        Some(ClientErrorCode::ProjectionRejected)
    );
    assert!(listed.data.is_none());
    let encoded = serde_json::to_string(&listed).unwrap();
    assert!(!encoded.contains(BLOCK_JUSTIFICATION));
    assert!(!encoded.contains(SENTINEL));
    assert!(!encoded.contains("requests"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t21_live_c219_redacts_pem_before_scan() {
    let live = live_new().await;
    park(
        &live.intake,
        "redacted-pem",
        "comp-key",
        Some(vec![CapParam {
            key: "api_key".to_owned(),
            value: BLOCK_JUSTIFICATION.to_owned(),
        }]),
        GrantTtl::Once,
        Some("safe"),
    );
    let listed = live
        .api
        .handle(ClientRequest::get("/client/grants/pending").with_session("tok"));
    assert!(listed.is_ok(), "{:?}", listed.error);
    let row = listed.data.as_ref().unwrap()["requests"]
        .as_array()
        .expect("requests")
        .iter()
        .find(|row| row["request_id"] == "redacted-pem")
        .expect("redacted-pem row");
    assert_eq!(row["params"][0]["value"], "[REDACTED]");
    let encoded = serde_json::to_string(&listed).unwrap();
    assert!(!encoded.contains(BLOCK_JUSTIFICATION));
    assert!(encoded.contains("requests"));
    let revision = listed_revision(&live.api, "redacted-pem");
    let approved = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/redacted-pem:approve",
            json!({ "decision_revision": revision }),
        )
        .with_session("tok")
        .with_idempotency_key("c219-api-key-approve"),
    );
    assert!(approved.is_ok(), "{:?}", approved.error);
    assert_eq!(
        live.intake.decision("redacted-pem"),
        ChannelApprovalDecision::Approved
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t23_fresh_adapter() {
    let workspace = tempfile::tempdir().expect("workspace");
    let journal = workspace.path().join("grant.journal");
    let db = workspace.path().join("idempotency.db");
    let master = Zeroizing::new([0x91u8; 32]);
    let ticket_ikm = [0x42u8; 32];
    let repo = DurableIdempotencyRepository::open(
        DurableIdempotencyConfig {
            database_path: db,
            confined_relative_path: "idempotency.db".into(),
            workspace_master_key: master.clone(),
            key_epoch: NonZeroU32::new(1).unwrap(),
            scope_key_epoch: NonZeroU32::new(2).unwrap(),
            payload_key_epoch: NonZeroU32::new(3).unwrap(),
        },
        Arc::new(TestAnchor::default()),
    )
    .expect("durable repo");
    let store_instance = repo.store_instance_id();

    let base = live_new().await;
    park(
        &base.intake,
        "t23-a",
        "caller-none",
        None,
        GrantTtl::Once,
        None,
    );
    park(
        &base.intake,
        "t23-b",
        "caller-empty",
        Some(Vec::new()),
        GrantTtl::Once,
        None,
    );

    let first = Arc::new(
        Contract219GrantAdapter::with_recovery(
            Arc::clone(&base.intake),
            Arc::clone(&base.projector),
            journal.clone(),
            ticket_ikm,
            store_instance,
            master.clone(),
        )
        .expect("first recovery adapter"),
    );
    let detector: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let api = ClientApi::new(ClientApiConfig::default())
        .with_bound_grant_provider(first.clone())
        .with_observation_redactor(base.projector.redactor())
        .with_leak_detector(detector)
        .with_durable_idempotency(Arc::clone(&repo));
    api.sessions().insert(
        "tok".to_owned(),
        ClientSession {
            session_id: "session".to_owned(),
            principal: Principal::operator("operator"),
            platform: Platform::Web,
            scopes: Scope::operator_default(),
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );
    let rev_a = listed_revision(&api, "t23-a");
    let rev_b = listed_revision(&api, "t23-b");
    let first_done = api.handle(
        ClientRequest::post(
            "/client/grants/pending/t23-a:approve",
            json!({ "decision_revision": rev_a }),
        )
        .with_session("tok")
        .with_idempotency_key("t23-a"),
    );
    assert!(first_done.is_ok(), "{:?}", first_done.error);
    assert_eq!(
        first_done.data.as_ref().unwrap()["status"],
        "approved"
    );
    assert_eq!(
        base.intake.decision("t23-a"),
        ChannelApprovalDecision::Approved
    );
    let first_data = first_done.data.clone();
    let after_first = listed_pending_ids(&api);
    assert!(
        !after_first.iter().any(|id| id == "t23-a"),
        "{after_first:?}"
    );
    assert!(
        after_first.iter().any(|id| id == "t23-b"),
        "{after_first:?}"
    );

    drop(api);
    drop(first);
    let second = Arc::new(
        Contract219GrantAdapter::with_recovery(
            Arc::clone(&base.intake),
            Arc::clone(&base.projector),
            journal.clone(),
            ticket_ikm,
            store_instance,
            master.clone(),
        )
        .expect("second recovery adapter"),
    );
    let detector: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let api2 = ClientApi::new(ClientApiConfig::default())
        .with_bound_grant_provider(second.clone())
        .with_observation_redactor(base.projector.redactor())
        .with_leak_detector(detector)
        .with_durable_idempotency(Arc::clone(&repo));
    api2.sessions().insert(
        "tok".to_owned(),
        ClientSession {
            session_id: "session".to_owned(),
            principal: Principal::operator("operator"),
            platform: Platform::Web,
            scopes: Scope::operator_default(),
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );
    api2.recover_durable_grants().expect("recover durable");
    let replay = api2.handle(
        ClientRequest::post(
            "/client/grants/pending/t23-a:approve",
            json!({ "decision_revision": rev_a }),
        )
        .with_session("tok")
        .with_idempotency_key("t23-a"),
    );
    assert!(replay.is_ok(), "{:?}", replay.error);
    assert_eq!(replay.data, first_data);
    let after_replay = listed_pending_ids(&api2);
    assert!(
        !after_replay.iter().any(|id| id == "t23-a"),
        "{after_replay:?}"
    );
    assert!(
        after_replay.iter().any(|id| id == "t23-b"),
        "{after_replay:?}"
    );

    let prep = Arc::new(
        Contract219GrantAdapter::with_recovery(
            Arc::clone(&base.intake),
            Arc::clone(&base.projector),
            journal.clone(),
            ticket_ikm,
            store_instance,
            master.clone(),
        )
        .expect("prepare adapter"),
    );
    let ticket = match prep.prepare_mutation_bound(
        [0x11; 32],
        [0x22; 32],
        BoundGrantMutation::Approve {
            request_id: "t23-b".to_owned(),
            decision_revision: rev_b.clone(),
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare failed: {error:?}"),
    };
    prep.verify_recovery_ticket_bound([0x11; 32], [0x22; 32], 1, &ticket)
        .expect("verify after prepare");
    drop(prep);

    let recovered = Arc::new(
        Contract219GrantAdapter::with_recovery(
            Arc::clone(&base.intake),
            Arc::clone(&base.projector),
            journal,
            ticket_ikm,
            store_instance,
            master,
        )
        .expect("recover adapter"),
    );
    recovered
        .verify_recovery_ticket_bound([0x11; 32], [0x22; 32], 1, &ticket)
        .expect("verify after reload");
    let writes_before = base.intake_approves.intake_approves.load(Ordering::SeqCst);
    assert_eq!(
        base.intake.decision("t23-b"),
        ChannelApprovalDecision::Pending
    );
    match recovered.recover_mutation_bound(&ticket) {
        BoundMutationOutcome::Committed(bound) => {
            let document = match base.projector.redactor().redact_bound_observation(bound) {
                RedactionDisposition::Redacted(document) => document,
                RedactionDisposition::Blocked { .. } => panic!("t23-b projection blocked"),
            };
            let ObservationNode::Object(fields) = document
                .provider_root()
                .expect("t23-b provider root")
            else {
                panic!("t23-b root is not an object");
            };
            let status = fields.iter().find(|(key, _)| key == "status").map(|(_, value)| value);
            assert!(
                matches!(status, Some(ObservationNode::String(value)) if value == "approved"),
                "t23-b bound status"
            );
            let request_id = fields
                .iter()
                .find(|(key, _)| key == "request_id")
                .map(|(_, value)| value);
            assert!(
                matches!(request_id, Some(ObservationNode::String(value)) if value == "t23-b"),
                "t23-b bound request_id"
            );
        }
        BoundMutationOutcome::Rejected(error) => panic!("recover rejected: {error:?}"),
        BoundMutationOutcome::OutcomeUnknown(_) => panic!("recover unknown"),
    }
    assert_eq!(
        base.intake.decision("t23-b"),
        ChannelApprovalDecision::Approved
    );
    assert_eq!(
        base.intake_approves.intake_approves.load(Ordering::SeqCst),
        writes_before + 1
    );
    assert!(live_pending_ids(&base.intake)
        .into_iter()
        .all(|id| id != "t23-b"));
    let detector: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let recover_api = ClientApi::new(ClientApiConfig::default())
        .with_bound_grant_provider(recovered)
        .with_observation_redactor(base.projector.redactor())
        .with_leak_detector(detector);
    recover_api.sessions().insert(
        "tok".to_owned(),
        ClientSession {
            session_id: "session".to_owned(),
            principal: Principal::operator("operator"),
            platform: Platform::Web,
            scopes: Scope::operator_default(),
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );
    let after_recover = listed_pending_ids(&recover_api);
    assert!(
        !after_recover.iter().any(|id| id == "t23-a"),
        "{after_recover:?}"
    );
    assert!(
        !after_recover.iter().any(|id| id == "t23-b"),
        "{after_recover:?}"
    );
}

fn live_pending_ids(intake: &GrantApprovalIntake) -> Vec<String> {
    intake
        .list_pending()
        .into_iter()
        .map(|pending| pending.request_id)
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t23_reject_then_recover() {
    let workspace = tempfile::tempdir().expect("workspace");
    let journal = workspace.path().join("grant.journal");
    let live = live_new().await;
    park(
        &live.intake,
        "t23-reject",
        "caller-none",
        None,
        GrantTtl::Once,
        None,
    );
    let adapter = Contract219GrantAdapter::with_recovery(
        Arc::clone(&live.intake),
        Arc::clone(&live.projector),
        journal.clone(),
        [0x42; 32],
        [0x11; 16],
        Zeroizing::new([0x91; 32]),
    )
    .expect("recovery adapter");
    let ticket = match adapter.prepare_mutation_bound(
        [0x51; 32],
        [0x52; 32],
        BoundGrantMutation::Approve {
            request_id: "t23-reject".to_owned(),
            decision_revision: "not-a-revision".to_owned(),
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare failed: {error:?}"),
    };
    adapter
        .verify_recovery_ticket_bound([0x51; 32], [0x52; 32], 1, &ticket)
        .expect("verify after prepare");
    match adapter.execute_prepared_bound(&ticket) {
        BoundMutationOutcome::Rejected(ProviderError::InvalidState(_)) => {}
        BoundMutationOutcome::Rejected(_) => panic!("expected invalid_state reject"),
        BoundMutationOutcome::Committed(_) => panic!("execute committed"),
        BoundMutationOutcome::OutcomeUnknown(_) => panic!("execute unknown"),
    }
    adapter
        .verify_recovery_ticket_bound([0x51; 32], [0x52; 32], 1, &ticket)
        .expect("verify after reject");
    drop(adapter);

    let reloaded = Contract219GrantAdapter::with_recovery(
        Arc::clone(&live.intake),
        Arc::clone(&live.projector),
        journal,
        [0x42; 32],
        [0x11; 16],
        Zeroizing::new([0x91; 32]),
    )
    .expect("reload adapter");
    reloaded
        .verify_recovery_ticket_bound([0x51; 32], [0x52; 32], 1, &ticket)
        .expect("verify after reload");
    match reloaded.recover_mutation_bound(&ticket) {
        BoundMutationOutcome::Rejected(ProviderError::InvalidState(_)) => {}
        BoundMutationOutcome::Rejected(_) => panic!("expected invalid_state after reload"),
        BoundMutationOutcome::Committed(_) => panic!("recover committed"),
        BoundMutationOutcome::OutcomeUnknown(_) => panic!("recover unknown"),
    }
    assert_eq!(
        live.intake.decision("t23-reject"),
        ChannelApprovalDecision::Pending
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t23_ticket_neg() {
    let live = live_new().await;
    park(
        &live.intake,
        "ticket-a",
        "caller-none",
        None,
        GrantTtl::Once,
        None,
    );
    let revision = listed_revision(&live.api, "ticket-a");
    let ticket = match live.adapter.prepare_mutation_bound(
        [0x33; 32],
        [0x44; 32],
        BoundGrantMutation::Approve {
            request_id: "ticket-a".to_owned(),
            decision_revision: revision,
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare: {error:?}"),
    };

    let mut zero = *ticket.as_provider_bytes();
    zero[103..135].fill(0);
    assert!(ProviderMutationRecovery::from_provider_bytes(zero).is_err());

    let mut mac = *ticket.as_provider_bytes();
    mac[166] ^= 1;
    let tampered_mac = ProviderMutationRecovery::from_provider_bytes(mac).unwrap();
    assert!(live
        .adapter
        .verify_recovery_ticket_bound([0x33; 32], [0x44; 32], 1, &tampered_mac)
        .is_err());

    let tampered_digest = live.adapter.test_recovery_mac_valid_digest_tamper(&ticket);
    assert!(live
        .adapter
        .verify_recovery_ticket_bound([0x33; 32], [0x44; 32], 1, &tampered_digest)
        .is_err());

    let mut mutation = *ticket.as_provider_bytes();
    mutation[7] ^= 1;
    let tampered_id = ProviderMutationRecovery::from_provider_bytes(mutation).unwrap();
    assert!(live
        .adapter
        .verify_recovery_ticket_bound([0x33; 32], [0x44; 32], 1, &tampered_id)
        .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t23_new_rejects_do_not_retain_prepared_rows() {
    let live = live_new().await;
    assert_eq!(live.adapter.test_journal_row_count(), 0);
    let ticket = match live.adapter.prepare_mutation_bound(
        [0x61; 32],
        [0x62; 32],
        BoundGrantMutation::Approve {
            request_id: "missing".to_owned(),
            decision_revision: "not-a-revision".to_owned(),
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare: {error:?}"),
    };
    assert_eq!(live.adapter.test_journal_row_count(), 1);
    match live.adapter.prepare_mutation_bound(
        [0x61; 32],
        [0x62; 32],
        BoundGrantMutation::Approve {
            request_id: "other-missing".to_owned(),
            decision_revision: "not-a-revision".to_owned(),
        },
    ) {
        ProviderPrepareOutcome::Rejected(ProviderError::InvalidState(_)) => {}
        ProviderPrepareOutcome::Rejected(error) => panic!("expected invalid_state remint: {error:?}"),
        ProviderPrepareOutcome::Prepared(_) => {
            panic!("same mutation_id+fingerprint+tag must not remint a different intent")
        }
    }
    assert_eq!(live.adapter.test_journal_row_count(), 1);
    match live.adapter.prepare_mutation_bound(
        [0x61; 32],
        [0x62; 32],
        BoundGrantMutation::Approve {
            request_id: "missing".to_owned(),
            decision_revision: "other-revision".to_owned(),
        },
    ) {
        ProviderPrepareOutcome::Rejected(ProviderError::InvalidState(_)) => {}
        ProviderPrepareOutcome::Rejected(error) => {
            panic!("expected invalid_state remint revision: {error:?}")
        }
        ProviderPrepareOutcome::Prepared(_) => {
            panic!("same request_id must not remint a different decision_revision")
        }
    }
    assert_eq!(live.adapter.test_journal_row_count(), 1);
    let deny_ticket = match live.adapter.prepare_mutation_bound(
        [0x63; 32],
        [0x64; 32],
        BoundGrantMutation::Deny {
            request_id: "missing-deny".to_owned(),
            decision_revision: "not-a-revision".to_owned(),
            reason: "first-reason".to_owned(),
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare deny: {error:?}"),
    };
    assert_eq!(live.adapter.test_journal_row_count(), 2);
    match live.adapter.prepare_mutation_bound(
        [0x63; 32],
        [0x64; 32],
        BoundGrantMutation::Deny {
            request_id: "missing-deny".to_owned(),
            decision_revision: "not-a-revision".to_owned(),
            reason: "second-reason".to_owned(),
        },
    ) {
        ProviderPrepareOutcome::Rejected(ProviderError::InvalidState(_)) => {}
        ProviderPrepareOutcome::Rejected(error) => {
            panic!("expected invalid_state remint deny reason: {error:?}")
        }
        ProviderPrepareOutcome::Prepared(_) => {
            panic!("same request_id+revision must not remint a different deny reason")
        }
    }
    assert_eq!(live.adapter.test_journal_row_count(), 2);
    let narrow_ticket = match live.adapter.prepare_mutation_bound(
        [0x65; 32],
        [0x66; 32],
        BoundGrantMutation::Narrow {
            request_id: "missing-narrow".to_owned(),
            decision_revision: "not-a-revision".to_owned(),
            params: vec![ClientCapParam {
                key: "allowlist".to_owned(),
                value: "/tmp/a/*".to_owned(),
            }],
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare narrow: {error:?}"),
    };
    assert_eq!(live.adapter.test_journal_row_count(), 3);
    match live.adapter.prepare_mutation_bound(
        [0x65; 32],
        [0x66; 32],
        BoundGrantMutation::Narrow {
            request_id: "missing-narrow".to_owned(),
            decision_revision: "not-a-revision".to_owned(),
            params: vec![ClientCapParam {
                key: "allowlist".to_owned(),
                value: "/tmp/b/*".to_owned(),
            }],
        },
    ) {
        ProviderPrepareOutcome::Rejected(ProviderError::InvalidState(_)) => {}
        ProviderPrepareOutcome::Rejected(error) => {
            panic!("expected invalid_state remint narrow params: {error:?}")
        }
        ProviderPrepareOutcome::Prepared(_) => {
            panic!("same request_id+revision must not remint different narrow params")
        }
    }
    assert_eq!(live.adapter.test_journal_row_count(), 3);
    let preset_ticket = match live.adapter.prepare_mutation_bound(
        [0x67; 32],
        [0x68; 32],
        BoundGrantMutation::ApplyPreset {
            preset: "restrict".to_owned(),
            target_agent_id: "no-such-agent".to_owned(),
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare preset: {error:?}"),
    };
    assert_eq!(live.adapter.test_journal_row_count(), 4);
    match live.adapter.prepare_mutation_bound(
        [0x67; 32],
        [0x68; 32],
        BoundGrantMutation::ApplyPreset {
            preset: "restrict".to_owned(),
            target_agent_id: "other-agent".to_owned(),
        },
    ) {
        ProviderPrepareOutcome::Rejected(ProviderError::InvalidState(_)) => {}
        ProviderPrepareOutcome::Rejected(error) => {
            panic!("expected invalid_state remint preset target: {error:?}")
        }
        ProviderPrepareOutcome::Prepared(_) => {
            panic!("same preset name must not remint a different target_agent_id")
        }
    }
    match live.adapter.prepare_mutation_bound(
        [0x67; 32],
        [0x68; 32],
        BoundGrantMutation::ApplyPreset {
            preset: "custom".to_owned(),
            target_agent_id: "no-such-agent".to_owned(),
        },
    ) {
        ProviderPrepareOutcome::Rejected(ProviderError::InvalidState(_)) => {}
        ProviderPrepareOutcome::Rejected(error) => {
            panic!("expected invalid_state remint preset name: {error:?}")
        }
        ProviderPrepareOutcome::Prepared(_) => {
            panic!("same target_agent_id must not remint a different preset name")
        }
    }
    assert_eq!(live.adapter.test_journal_row_count(), 4);
    let subject_ticket = match live.adapter.prepare_mutation_bound(
        [0x69; 32],
        [0x6a; 32],
        BoundGrantMutation::Approve {
            request_id: "missing-subject".to_owned(),
            decision_revision: "not-a-revision".to_owned(),
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare subject: {error:?}"),
    };
    assert_eq!(live.adapter.test_journal_row_count(), 5);
    park(
        &live.intake,
        "missing-subject",
        "caller-alpha",
        None,
        GrantTtl::Once,
        None,
    );
    match live.adapter.prepare_mutation_bound(
        [0x69; 32],
        [0x6a; 32],
        BoundGrantMutation::Approve {
            request_id: "missing-subject".to_owned(),
            decision_revision: "not-a-revision".to_owned(),
        },
    ) {
        ProviderPrepareOutcome::Rejected(ProviderError::InvalidState(_)) => {}
        ProviderPrepareOutcome::Rejected(error) => {
            panic!("expected invalid_state remint subject: {error:?}")
        }
        ProviderPrepareOutcome::Prepared(_) => {
            panic!("same request fields must not remint after prepare_subject changes")
        }
    }
    assert_eq!(live.adapter.test_journal_row_count(), 5);
    let revoke_ticket = match live.adapter.prepare_mutation_bound(
        [0x6b; 32],
        [0x6c; 32],
        BoundGrantMutation::Revoke {
            grant_id: "grant-a".to_owned(),
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare revoke: {error:?}"),
    };
    assert_eq!(live.adapter.test_journal_row_count(), 6);
    match live.adapter.prepare_mutation_bound(
        [0x6b; 32],
        [0x6c; 32],
        BoundGrantMutation::Revoke {
            grant_id: "grant-b".to_owned(),
        },
    ) {
        ProviderPrepareOutcome::Rejected(ProviderError::InvalidState(_)) => {}
        ProviderPrepareOutcome::Rejected(error) => {
            panic!("expected invalid_state remint revoke grant_id: {error:?}")
        }
        ProviderPrepareOutcome::Prepared(_) => {
            panic!("same mutation_id+fingerprint+tag must not remint a different grant_id")
        }
    }
    assert_eq!(live.adapter.test_journal_row_count(), 6);
    let revoke_subject_ticket = match live.adapter.prepare_mutation_bound(
        [0x6d; 32],
        [0x6e; 32],
        BoundGrantMutation::Revoke {
            grant_id: "rev-subject".to_owned(),
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare revoke subject: {error:?}"),
    };
    assert_eq!(live.adapter.test_journal_row_count(), 7);
    live.store
        .insert_dynamic(grant(
            "rev-subject",
            "grantee-comp",
            "/tmp/rev-subject/*",
            GrantProvenance::Requested,
        ))
        .expect("insert rev-subject");
    match live.adapter.prepare_mutation_bound(
        [0x6d; 32],
        [0x6e; 32],
        BoundGrantMutation::Revoke {
            grant_id: "rev-subject".to_owned(),
        },
    ) {
        ProviderPrepareOutcome::Rejected(ProviderError::InvalidState(_)) => {}
        ProviderPrepareOutcome::Rejected(error) => {
            panic!("expected invalid_state remint revoke subject: {error:?}")
        }
        ProviderPrepareOutcome::Prepared(_) => {
            panic!("same grant_id must not remint after prepare_subject becomes Some")
        }
    }
    assert_eq!(live.adapter.test_journal_row_count(), 7);
    live.store
        .insert_dynamic(grant(
            "rev-ab",
            "grantee-alpha",
            "/tmp/rev-ab/*",
            GrantProvenance::Requested,
        ))
        .expect("insert rev-ab alpha");
    let revoke_ab_ticket = match live.adapter.prepare_mutation_bound(
        [0x6f; 32],
        [0x70; 32],
        BoundGrantMutation::Revoke {
            grant_id: "rev-ab".to_owned(),
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare revoke A→B: {error:?}"),
    };
    assert_eq!(live.adapter.test_journal_row_count(), 8);
    assert_eq!(
        "grantee-alpha".len(),
        "grantee-gamma".len(),
        "A→B remint must keep subject UTF-8 length equal so a subject_len-only digest still remints"
    );
    live.store
        .insert_dynamic(grant(
            "rev-ab",
            "grantee-gamma",
            "/tmp/rev-ab/*",
            GrantProvenance::Requested,
        ))
        .expect("upsert rev-ab gamma");
    match live.adapter.prepare_mutation_bound(
        [0x6f; 32],
        [0x70; 32],
        BoundGrantMutation::Revoke {
            grant_id: "rev-ab".to_owned(),
        },
    ) {
        ProviderPrepareOutcome::Rejected(ProviderError::InvalidState(_)) => {}
        ProviderPrepareOutcome::Rejected(error) => {
            panic!("expected invalid_state remint revoke subject A→B: {error:?}")
        }
        ProviderPrepareOutcome::Prepared(_) => {
            panic!("same grant_id must not remint after equal-length prepare_subject Some(alpha)→Some(gamma)")
        }
    }
    assert_eq!(live.adapter.test_journal_row_count(), 8);
    match live.adapter.execute_prepared_bound(&ticket) {
        BoundMutationOutcome::Rejected(ProviderError::NotFound(_)) => {}
        BoundMutationOutcome::Rejected(error) => panic!("unexpected reject: {error:?}"),
        BoundMutationOutcome::Committed(_) => panic!("execute committed"),
        BoundMutationOutcome::OutcomeUnknown(_) => panic!("execute unknown"),
    }
    match live.adapter.execute_prepared_bound(&deny_ticket) {
        BoundMutationOutcome::Rejected(ProviderError::NotFound(_))
        | BoundMutationOutcome::Rejected(ProviderError::InvalidState(_)) => {}
        BoundMutationOutcome::Rejected(error) => panic!("unexpected deny reject: {error:?}"),
        BoundMutationOutcome::Committed(_) => panic!("deny execute committed"),
        BoundMutationOutcome::OutcomeUnknown(_) => panic!("deny execute unknown"),
    }
    match live.adapter.execute_prepared_bound(&narrow_ticket) {
        BoundMutationOutcome::Rejected(ProviderError::NotFound(_))
        | BoundMutationOutcome::Rejected(ProviderError::InvalidState(_)) => {}
        BoundMutationOutcome::Rejected(error) => panic!("unexpected narrow reject: {error:?}"),
        BoundMutationOutcome::Committed(_) => panic!("narrow execute committed"),
        BoundMutationOutcome::OutcomeUnknown(_) => panic!("narrow execute unknown"),
    }
    match live.adapter.execute_prepared_bound(&preset_ticket) {
        BoundMutationOutcome::Rejected(ProviderError::Unavailable(_))
        | BoundMutationOutcome::Rejected(ProviderError::NotFound(_))
        | BoundMutationOutcome::Rejected(ProviderError::InvalidState(_)) => {}
        BoundMutationOutcome::Rejected(error) => panic!("unexpected preset reject: {error:?}"),
        BoundMutationOutcome::Committed(_) => panic!("preset execute committed"),
        BoundMutationOutcome::OutcomeUnknown(_) => panic!("preset execute unknown"),
    }
    match live.adapter.execute_prepared_bound(&subject_ticket) {
        BoundMutationOutcome::Rejected(ProviderError::NotFound(_))
        | BoundMutationOutcome::Rejected(ProviderError::InvalidState(_))
        | BoundMutationOutcome::Rejected(ProviderError::Unavailable(_)) => {}
        BoundMutationOutcome::Rejected(error) => panic!("unexpected subject reject: {error:?}"),
        BoundMutationOutcome::Committed(_) => panic!("subject execute committed"),
        BoundMutationOutcome::OutcomeUnknown(_) => panic!("subject execute unknown"),
    }
    match live.adapter.execute_prepared_bound(&revoke_ticket) {
        BoundMutationOutcome::Rejected(ProviderError::NotFound(_))
        | BoundMutationOutcome::Rejected(ProviderError::InvalidState(_)) => {}
        BoundMutationOutcome::Rejected(error) => panic!("unexpected revoke reject: {error:?}"),
        BoundMutationOutcome::Committed(_) => panic!("revoke execute committed"),
        BoundMutationOutcome::OutcomeUnknown(_) => panic!("revoke execute unknown"),
    }
    match live.adapter.execute_prepared_bound(&revoke_subject_ticket) {
        BoundMutationOutcome::Rejected(_) | BoundMutationOutcome::Committed(_) => {}
        BoundMutationOutcome::OutcomeUnknown(_) => panic!("revoke subject execute unknown"),
    }
    match live.adapter.execute_prepared_bound(&revoke_ab_ticket) {
        BoundMutationOutcome::Rejected(_) | BoundMutationOutcome::Committed(_) => {}
        BoundMutationOutcome::OutcomeUnknown(_) => panic!("revoke A→B execute unknown"),
    }
    assert_eq!(live.adapter.test_journal_row_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t23_concurrent_preset_execute_applies_once() {
    let live = live_new().await;
    live.store
        .insert_dynamic(grant(
            "cover-conc-a",
            "grantee-comp",
            "/tmp/a/*",
            GrantProvenance::Requested,
        ))
        .expect("cover a");
    live.store
        .insert_dynamic(grant(
            "cover-conc-b",
            "grantee-comp",
            "/tmp/b/*",
            GrantProvenance::Requested,
        ))
        .expect("cover b");
    let workspace = tempfile::tempdir().expect("workspace");
    let journal = workspace.path().join("grant.journal");
    let adapter = Arc::new(
        Contract219GrantAdapter::with_recovery(
            Arc::clone(&live.intake),
            Arc::clone(&live.projector),
            journal,
            [0x71; 32],
            [0x72; 16],
            Zeroizing::new([0x73; 32]),
        )
        .expect("recovery adapter"),
    );
    let ticket = match adapter.prepare_mutation_bound(
        [0x81; 32],
        [0x82; 32],
        BoundGrantMutation::ApplyPreset {
            preset: "live-custom".to_owned(),
            target_agent_id: "grantee-comp".to_owned(),
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare: {error:?}"),
    };
    let first = Arc::clone(&adapter);
    let second = Arc::clone(&adapter);
    let ticket_a =
        ProviderMutationRecovery::from_provider_bytes(*ticket.as_provider_bytes()).unwrap();
    let ticket_b = ticket;
    let left = std::thread::spawn(move || first.execute_prepared_bound(&ticket_a));
    let right = std::thread::spawn(move || second.execute_prepared_bound(&ticket_b));
    for result in [left.join().expect("left"), right.join().expect("right")] {
        match result {
            BoundMutationOutcome::Committed(_) => {}
            BoundMutationOutcome::Rejected(error) => panic!("execute rejected: {error:?}"),
            BoundMutationOutcome::OutcomeUnknown(_) => panic!("execute unknown"),
        }
    }
    assert_eq!(live.intake_approves.preset_applies.load(Ordering::SeqCst), 1);
    assert_eq!(
        live.store
            .list_by_grantee("grantee-comp")
            .into_iter()
            .filter(|grant| grant.status == GrantStatus::Active)
            .count(),
        2
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t23_journal_read_error_fails_closed() {
    let live = live_new().await;
    let workspace = tempfile::tempdir().expect("workspace");
    let journal = workspace.path().join("not-a-file");
    std::fs::create_dir(&journal).expect("directory at journal path");
    let err = Contract219GrantAdapter::with_recovery(
        Arc::clone(&live.intake),
        Arc::clone(&live.projector),
        journal,
        [0x11; 32],
        [0x22; 16],
        Zeroizing::new([0x33; 32]),
    );
    assert!(err.is_err(), "existing unreadable journal must not re-init");

    let device = workspace.path().join("device.journal");
    std::os::unix::fs::symlink("/dev/null", &device).expect("journal symlink to device");
    let device_err = Contract219GrantAdapter::with_recovery(
        Arc::clone(&live.intake),
        Arc::clone(&live.projector),
        device,
        [0x11; 32],
        [0x22; 16],
        Zeroizing::new([0x33; 32]),
    );
    assert!(
        device_err.is_err(),
        "character-device journal must fail closed; skip-is_file then read(/dev/null) would re-init"
    );

    let fifo = workspace.path().join("fifo.journal");
    let mkfifo = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("run mkfifo");
    assert!(mkfifo.success(), "mkfifo {}", fifo.display());
    let fifo_err = Contract219GrantAdapter::with_recovery(
        Arc::clone(&live.intake),
        Arc::clone(&live.projector),
        fifo,
        [0x11; 32],
        [0x22; 16],
        Zeroizing::new([0x33; 32]),
    );
    assert!(
        fifo_err.is_err(),
        "FIFO journal must fail closed; is_symlink-only would see a non-symlink and re-init"
    );

    let oversized = workspace.path().join("oversized.journal");
    Contract219GrantAdapter::with_recovery(
        Arc::clone(&live.intake),
        Arc::clone(&live.projector),
        oversized.clone(),
        [0x11; 32],
        [0x22; 16],
        Zeroizing::new([0x33; 32]),
    )
    .expect("seed a header-valid journal");
    let mut padded = std::fs::read(&oversized).expect("read seeded journal");
    assert!(
        padded.len() < 8 * 1024 * 1024,
        "seeded journal must be under the size cap so padding is the only reject reason"
    );
    padded.resize(8 * 1024 * 1024 + 4 * 1024 * 1024, 0);
    write_nocache(&oversized, &padded);
    let last_offset = padded.len() as u64 - 1;
    let mid_offset = 4 * 1024 * 1024;
    let frontier_offset = 8 * 1024 * 1024;
    assert!(
        !vnode_page_resident(&oversized, 0),
        "F_NOCACHE pad must leave the first page out of cache so a no-open reject cannot fake residency"
    );
    assert!(
        !vnode_page_resident(&oversized, mid_offset),
        "F_NOCACHE pad must leave the mid-window page out of cache"
    );
    assert!(
        !vnode_page_resident(&oversized, frontier_offset),
        "F_NOCACHE pad must leave the take frontier out of cache"
    );
    assert!(
        !vnode_page_resident(&oversized, last_offset),
        "F_NOCACHE pad must leave the last page out of cache so a slurp is visible"
    );
    Contract219GrantAdapter::test_reset_journal_bytes_read();
    let oversized_err = Contract219GrantAdapter::with_recovery(
        Arc::clone(&live.intake),
        Arc::clone(&live.projector),
        oversized.clone(),
        [0x11; 32],
        [0x22; 16],
        Zeroizing::new([0x33; 32]),
    );
    assert!(
        oversized_err.is_err(),
        "header-valid journal larger than MAX_JOURNAL_BYTES must fail closed before load; without the size gate load_journal would accept the seeded header"
    );
    assert_eq!(
        Contract219GrantAdapter::test_journal_bytes_read(),
        8 * 1024 * 1024 + 1,
        "size reject must take(MAX+1); metadata-only reject reads 0; unbounded slurp of the 12MiB pad reads 12MiB"
    );
    assert!(
        vnode_page_resident(&oversized, 0),
        "capped read must actually open and read the file; a metadata reject plus fetch_add(MAX+1) leaves page 0 empty"
    );
    assert!(
        vnode_page_resident(&oversized, mid_offset),
        "take(MAX+1) must fault the mid-window page; prefix-touch of page 0 plus a fake MAX+1 counter leaves 4MiB cold"
    );
    assert!(
        vnode_page_resident(&oversized, frontier_offset),
        "take(MAX+1) must fault the last byte of the cap (offset 8MiB); reading only 4KiB then store(MAX+1) leaves the frontier cold"
    );
    assert!(
        !vnode_page_resident(&oversized, last_offset),
        "capped read must not slurp the 4MiB tail; std::fs::read of the pad faults the last page"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t17_live_bidi_param_is_deny_only() {
    let live = live_new().await;
    park(
        &live.intake,
        "bidi-fs",
        "caller-none",
        Some(vec![CapParam {
            key: "read-paths".to_owned(),
            value: "/tmp/\u{202E}*".to_owned(),
        }]),
        GrantTtl::Once,
        None,
    );
    let revision = listed_revision(&live.api, "bidi-fs");
    let approved = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/bidi-fs:approve",
            json!({ "decision_revision": revision }),
        )
        .with_session("tok")
        .with_idempotency_key("bidi-approve"),
    );
    assert_eq!(approved.error_code(), Some(ClientErrorCode::InvalidState));
    assert_eq!(
        live.intake.decision("bidi-fs"),
        ChannelApprovalDecision::Pending
    );
    let narrowed = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/bidi-fs:narrow",
            json!({
                "decision_revision": revision,
                "params": [{ "key": "read-paths", "value": "/tmp/*" }]
            }),
        )
        .with_session("tok")
        .with_idempotency_key("bidi-narrow"),
    );
    assert_eq!(narrowed.error_code(), Some(ClientErrorCode::InvalidState));
    assert_eq!(
        live.intake.decision("bidi-fs"),
        ChannelApprovalDecision::Pending
    );
    let denied = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/bidi-fs:deny",
            json!({ "decision_revision": revision, "reason": "bidi" }),
        )
        .with_session("tok")
        .with_idempotency_key("bidi-deny"),
    );
    assert!(denied.is_ok(), "{:?}", denied.error);
    assert!(!listed_pending_ids(&live.api)
        .iter()
        .any(|id| id == "bidi-fs"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t17_live_redact_param_is_deny_only() {
    let live = live_new().await;
    park(
        &live.intake,
        "redact-fs",
        "caller-none",
        Some(vec![CapParam {
            key: "read-paths".to_owned(),
            value: REDACT_BEARER.to_owned(),
        }]),
        GrantTtl::Once,
        None,
    );
    park(
        &live.intake,
        "visible-sibling",
        "caller-none",
        Some(vec![CapParam {
            key: "read-paths".to_owned(),
            value: "/tmp/*".to_owned(),
        }]),
        GrantTtl::Once,
        None,
    );
    let listed = live
        .api
        .handle(ClientRequest::get("/client/grants/pending").with_session("tok"));
    assert!(listed.is_ok(), "{:?}", listed.error);
    let encoded = serde_json::to_string(&listed).unwrap();
    assert!(!encoded.contains(REDACT_BEARER), "{encoded}");
    assert!(!encoded.contains("eyJhbGciOiJIUzI1NiJ9"), "{encoded}");
    let requests = listed.data.as_ref().unwrap()["requests"]
        .as_array()
        .expect("requests");
    let redacted = requests
        .iter()
        .find(|row| row["request_id"] == "redact-fs")
        .expect("redact-fs");
    assert_eq!(redacted["params"][0]["key"], "read-paths");
    assert_eq!(redacted["params"][0]["value"], "[REDACTED]");
    let revision = listed_revision(&live.api, "redact-fs");
    let approved = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/redact-fs:approve",
            json!({ "decision_revision": revision }),
        )
        .with_session("tok")
        .with_idempotency_key("redact-approve"),
    );
    assert_eq!(approved.error_code(), Some(ClientErrorCode::InvalidState));
    assert_eq!(
        live.intake.decision("redact-fs"),
        ChannelApprovalDecision::Pending
    );
    let narrowed = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/redact-fs:narrow",
            json!({
                "decision_revision": revision,
                "params": [{ "key": "read-paths", "value": "/tmp/*" }]
            }),
        )
        .with_session("tok")
        .with_idempotency_key("redact-narrow"),
    );
    assert_eq!(narrowed.error_code(), Some(ClientErrorCode::InvalidState));
    assert_eq!(
        live.intake.decision("redact-fs"),
        ChannelApprovalDecision::Pending
    );
    let denied = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/redact-fs:deny",
            json!({ "decision_revision": revision, "reason": "redact-param" }),
        )
        .with_session("tok")
        .with_idempotency_key("redact-deny"),
    );
    assert!(denied.is_ok(), "{:?}", denied.error);
    let after_deny = listed_pending_ids(&live.api);
    assert!(
        !after_deny.iter().any(|id| id == "redact-fs"),
        "{after_deny:?}"
    );
    assert!(
        after_deny.iter().any(|id| id == "visible-sibling"),
        "{after_deny:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t17_live_arabic_number_sign_param_is_deny_only() {
    let live = live_new().await;
    park(
        &live.intake,
        "cf-fs",
        "caller-none",
        Some(vec![CapParam {
            key: "read-paths".to_owned(),
            value: "/tmp/\u{0600}*".to_owned(),
        }]),
        GrantTtl::Once,
        None,
    );
    let revision = listed_revision(&live.api, "cf-fs");
    let approved = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/cf-fs:approve",
            json!({ "decision_revision": revision }),
        )
        .with_session("tok")
        .with_idempotency_key("cf-approve"),
    );
    assert_eq!(approved.error_code(), Some(ClientErrorCode::InvalidState));
    assert_eq!(
        live.intake.decision("cf-fs"),
        ChannelApprovalDecision::Pending
    );
    let narrowed = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/cf-fs:narrow",
            json!({
                "decision_revision": revision,
                "params": [{ "key": "read-paths", "value": "/tmp/*" }]
            }),
        )
        .with_session("tok")
        .with_idempotency_key("cf-narrow"),
    );
    assert_eq!(narrowed.error_code(), Some(ClientErrorCode::InvalidState));
    assert_eq!(
        live.intake.decision("cf-fs"),
        ChannelApprovalDecision::Pending
    );
    let denied = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/cf-fs:deny",
            json!({ "decision_revision": revision, "reason": "arabic-number-sign" }),
        )
        .with_session("tok")
        .with_idempotency_key("cf-deny"),
    );
    assert!(denied.is_ok(), "{:?}", denied.error);
    assert!(!listed_pending_ids(&live.api)
        .iter()
        .any(|id| id == "cf-fs"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t17_live_canonical_scan_classes_are_deny_only() {
    let live = live_new().await;
    let cases = [
        ("mn-fs", "/tmp/\u{0301}*", "mn"),
        ("mn2-fs", "/tmp/\u{0308}*", "mn2"),
        ("me-fs", "/tmp/\u{20DD}*", "me"),
        ("me2-fs", "/tmp/\u{20DE}*", "me2"),
        ("lo-fs", "/tmp/\u{3164}*", "hangul-filler"),
        ("lo2-fs", "/tmp/\u{115F}*", "choseong-filler"),
        ("nfkc-fs", "\u{FF0F}tmp\u{FF0F}*", "fullwidth-slash"),
        ("nfkc2-fs", "/tmp/\u{FF0A}", "fullwidth-asterisk"),
    ];
    for (request_id, value, _) in cases {
        assert_ne!(canonical_scan_text(value), *value, "{request_id}");
        park(
            &live.intake,
            request_id,
            "caller-none",
            Some(vec![CapParam {
                key: "read-paths".to_owned(),
                value: value.to_owned(),
            }]),
            GrantTtl::Once,
            None,
        );
    }
    for (request_id, _, reason) in cases {
        let revision = listed_revision(&live.api, request_id);
        let approved = live.api.handle(
            ClientRequest::post(
                &format!("/client/grants/pending/{request_id}:approve"),
                json!({ "decision_revision": revision }),
            )
            .with_session("tok")
            .with_idempotency_key(&format!("{request_id}-approve")),
        );
        assert_eq!(
            approved.error_code(),
            Some(ClientErrorCode::InvalidState),
            "{request_id}"
        );
        assert_eq!(
            live.intake.decision(request_id),
            ChannelApprovalDecision::Pending,
            "{request_id}"
        );
        let narrowed = live.api.handle(
            ClientRequest::post(
                &format!("/client/grants/pending/{request_id}:narrow"),
                json!({
                    "decision_revision": revision,
                    "params": [{ "key": "read-paths", "value": "/tmp/*" }]
                }),
            )
            .with_session("tok")
            .with_idempotency_key(&format!("{request_id}-narrow")),
        );
        assert_eq!(
            narrowed.error_code(),
            Some(ClientErrorCode::InvalidState),
            "{request_id}"
        );
        assert_eq!(
            live.intake.decision(request_id),
            ChannelApprovalDecision::Pending,
            "{request_id}"
        );
        let denied = live.api.handle(
            ClientRequest::post(
                &format!("/client/grants/pending/{request_id}:deny"),
                json!({ "decision_revision": revision, "reason": reason }),
            )
            .with_session("tok")
            .with_idempotency_key(&format!("{request_id}-deny")),
        );
        assert!(denied.is_ok(), "{request_id} {:?}", denied.error);
        assert!(
            !listed_pending_ids(&live.api)
                .iter()
                .any(|id| id == request_id),
            "{request_id}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t17_live_canonical_stable_non_ascii_path_can_approve() {
    let live = live_new().await;
    const CAFE: &str = "/tmp/caf\u{00E9}/*";
    assert_eq!(canonical_scan_text(CAFE), CAFE);
    assert!(!CAFE.is_ascii());
    park(
        &live.intake,
        "cafe-fs",
        "caller-none",
        Some(vec![CapParam {
            key: "read-paths".to_owned(),
            value: CAFE.to_owned(),
        }]),
        GrantTtl::Once,
        None,
    );
    park(
        &live.intake,
        "visible-sibling",
        "caller-none",
        Some(vec![CapParam {
            key: "read-paths".to_owned(),
            value: "/tmp/*".to_owned(),
        }]),
        GrantTtl::Once,
        None,
    );
    let revision = listed_revision(&live.api, "cafe-fs");
    let approved = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/cafe-fs:approve",
            json!({ "decision_revision": revision }),
        )
        .with_session("tok")
        .with_idempotency_key("cafe-approve"),
    );
    assert!(approved.is_ok(), "{:?}", approved.error);
    assert_eq!(
        live.intake.decision("cafe-fs"),
        ChannelApprovalDecision::Approved
    );
    assert_eq!(
        ChannelApprovalPort::take_approved(&*live.intake, "cafe-fs"),
        Some(None)
    );
    let after = listed_pending_ids(&live.api);
    assert!(!after.iter().any(|id| id == "cafe-fs"), "{after:?}");
    assert!(after.iter().any(|id| id == "visible-sibling"), "{after:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t17_live_narrow_body_is_gated() {
    let live = live_new().await;
    park(
        &live.intake,
        "clean-narrow",
        "caller-none",
        Some(vec![CapParam {
            key: "read-paths".to_owned(),
            value: "/tmp/*".to_owned(),
        }]),
        GrantTtl::Once,
        None,
    );
    let revision = listed_revision(&live.api, "clean-narrow");
    let bidi = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/clean-narrow:narrow",
            json!({
                "decision_revision": revision,
                "params": [{ "key": "read-paths", "value": "/tmp/\u{202E}*" }]
            }),
        )
        .with_session("tok")
        .with_idempotency_key("narrow-bidi-body"),
    );
    assert_eq!(bidi.error_code(), Some(ClientErrorCode::InvalidState));
    assert_eq!(
        live.intake.decision("clean-narrow"),
        ChannelApprovalDecision::Pending
    );
    let bearer = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/clean-narrow:narrow",
            json!({
                "decision_revision": revision,
                "params": [{ "key": "read-paths", "value": REDACT_BEARER }]
            }),
        )
        .with_session("tok")
        .with_idempotency_key("narrow-bearer-body"),
    );
    assert_eq!(bearer.error_code(), Some(ClientErrorCode::InvalidState));
    let second_key = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/clean-narrow:narrow",
            json!({
                "decision_revision": revision,
                "params": [
                    { "key": "read-paths", "value": "/tmp/*" },
                    { "key": "write-paths", "value": "/tmp/\u{202E}*" }
                ]
            }),
        )
        .with_session("tok")
        .with_idempotency_key("narrow-second-key"),
    );
    assert_eq!(second_key.error_code(), Some(ClientErrorCode::InvalidState));
    let second_bearer = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/clean-narrow:narrow",
            json!({
                "decision_revision": revision,
                "params": [
                    { "key": "read-paths", "value": "/tmp/*" },
                    { "key": "write-paths", "value": REDACT_BEARER }
                ]
            }),
        )
        .with_session("tok")
        .with_idempotency_key("narrow-second-bearer"),
    );
    assert_eq!(
        second_bearer.error_code(),
        Some(ClientErrorCode::InvalidState)
    );
    let first_key_pair = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/clean-narrow:narrow",
            json!({
                "decision_revision": revision,
                "params": [
                    { "key": "read-paths", "value": "/tmp/\u{202E}*" },
                    { "key": "write-paths", "value": "/tmp/*" }
                ]
            }),
        )
        .with_session("tok")
        .with_idempotency_key("narrow-first-key"),
    );
    assert_eq!(
        first_key_pair.error_code(),
        Some(ClientErrorCode::InvalidState)
    );
    let first_bearer = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/clean-narrow:narrow",
            json!({
                "decision_revision": revision,
                "params": [
                    { "key": "read-paths", "value": REDACT_BEARER },
                    { "key": "write-paths", "value": "/tmp/*" }
                ]
            }),
        )
        .with_session("tok")
        .with_idempotency_key("narrow-first-bearer"),
    );
    assert_eq!(
        first_bearer.error_code(),
        Some(ClientErrorCode::InvalidState)
    );
    let api_key_body = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/clean-narrow:narrow",
            json!({
                "decision_revision": revision,
                "params": [{ "key": "api_key", "value": REDACT_BEARER }]
            }),
        )
        .with_session("tok")
        .with_idempotency_key("narrow-api-key-bearer"),
    );
    assert_eq!(
        api_key_body.error_code(),
        Some(ClientErrorCode::InvalidState)
    );
    assert_eq!(
        live.intake.decision("clean-narrow"),
        ChannelApprovalDecision::Pending
    );
    let approved = live.api.handle(
        ClientRequest::post(
            "/client/grants/pending/clean-narrow:approve",
            json!({ "decision_revision": revision }),
        )
        .with_session("tok")
        .with_idempotency_key("narrow-body-then-approve"),
    );
    assert!(approved.is_ok(), "{:?}", approved.error);
    assert_eq!(
        live.intake.decision("clean-narrow"),
        ChannelApprovalDecision::Approved
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t17_live_parked_second_key_is_gated() {
    let live = live_new().await;
    let cases = [
        (
            "pair-bearer",
            vec![
                CapParam {
                    key: "read-paths".to_owned(),
                    value: "/tmp/*".to_owned(),
                },
                CapParam {
                    key: "write-paths".to_owned(),
                    value: REDACT_BEARER.to_owned(),
                },
            ],
            "second-key-bearer",
        ),
        (
            "pair-bidi",
            vec![
                CapParam {
                    key: "read-paths".to_owned(),
                    value: "/tmp/*".to_owned(),
                },
                CapParam {
                    key: "write-paths".to_owned(),
                    value: "/tmp/\u{202E}*".to_owned(),
                },
            ],
            "second-key-bidi",
        ),
        (
            "pair-first-bearer",
            vec![
                CapParam {
                    key: "read-paths".to_owned(),
                    value: REDACT_BEARER.to_owned(),
                },
                CapParam {
                    key: "write-paths".to_owned(),
                    value: "/tmp/*".to_owned(),
                },
            ],
            "first-key-bearer",
        ),
        (
            "pair-first-bidi",
            vec![
                CapParam {
                    key: "read-paths".to_owned(),
                    value: "/tmp/\u{202E}*".to_owned(),
                },
                CapParam {
                    key: "write-paths".to_owned(),
                    value: "/tmp/*".to_owned(),
                },
            ],
            "first-key-bidi",
        ),
    ];
    for (request_id, params, _) in &cases {
        park(
            &live.intake,
            request_id,
            "caller-none",
            Some(params.clone()),
            GrantTtl::Once,
            None,
        );
    }
    let listed = live
        .api
        .handle(ClientRequest::get("/client/grants/pending").with_session("tok"));
    assert!(listed.is_ok(), "{:?}", listed.error);
    let encoded = serde_json::to_string(&listed).unwrap();
    assert!(!encoded.contains(REDACT_BEARER), "{encoded}");
    assert!(!encoded.contains("eyJhbGciOiJIUzI1NiJ9"), "{encoded}");
    let requests = listed.data.as_ref().unwrap()["requests"]
        .as_array()
        .expect("requests");
    let pair_bearer = requests
        .iter()
        .find(|row| row["request_id"] == "pair-bearer")
        .expect("pair-bearer");
    let pair_bearer_params = pair_bearer["params"].as_array().expect("pair-bearer params");
    let pair_bearer_write = pair_bearer_params
        .iter()
        .find(|param| param["key"] == "write-paths")
        .expect("pair-bearer write-paths");
    let pair_bearer_read = pair_bearer_params
        .iter()
        .find(|param| param["key"] == "read-paths")
        .expect("pair-bearer read-paths");
    assert_eq!(pair_bearer_read["value"], "/tmp/*");
    assert_eq!(pair_bearer_write["value"], "[REDACTED]");
    let pair_first_bearer = requests
        .iter()
        .find(|row| row["request_id"] == "pair-first-bearer")
        .expect("pair-first-bearer");
    let pair_first_params = pair_first_bearer["params"]
        .as_array()
        .expect("pair-first-bearer params");
    let pair_first_read = pair_first_params
        .iter()
        .find(|param| param["key"] == "read-paths")
        .expect("pair-first-bearer read-paths");
    let pair_first_write = pair_first_params
        .iter()
        .find(|param| param["key"] == "write-paths")
        .expect("pair-first-bearer write-paths");
    assert_eq!(pair_first_read["value"], "[REDACTED]");
    assert_eq!(pair_first_write["value"], "/tmp/*");
    for (request_id, _, reason) in &cases {
        let revision = listed_revision(&live.api, request_id);
        let approved = live.api.handle(
            ClientRequest::post(
                &format!("/client/grants/pending/{request_id}:approve"),
                json!({ "decision_revision": revision }),
            )
            .with_session("tok")
            .with_idempotency_key(&format!("{request_id}-approve")),
        );
        assert_eq!(
            approved.error_code(),
            Some(ClientErrorCode::InvalidState),
            "{request_id}"
        );
        let narrowed = live.api.handle(
            ClientRequest::post(
                &format!("/client/grants/pending/{request_id}:narrow"),
                json!({
                    "decision_revision": revision,
                    "params": [{ "key": "read-paths", "value": "/tmp/*" }]
                }),
            )
            .with_session("tok")
            .with_idempotency_key(&format!("{request_id}-narrow")),
        );
        assert_eq!(
            narrowed.error_code(),
            Some(ClientErrorCode::InvalidState),
            "{request_id}"
        );
        assert_eq!(
            live.intake.decision(request_id),
            ChannelApprovalDecision::Pending,
            "{request_id}"
        );
        let denied = live.api.handle(
            ClientRequest::post(
                &format!("/client/grants/pending/{request_id}:deny"),
                json!({ "decision_revision": revision, "reason": reason }),
            )
            .with_session("tok")
            .with_idempotency_key(&format!("{request_id}-deny")),
        );
        assert!(denied.is_ok(), "{request_id} {:?}", denied.error);
        assert!(
            !listed_pending_ids(&live.api)
                .iter()
                .any(|id| id == request_id),
            "{request_id}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t23_journal_tmp_keeps_full_filename() {
    use std::path::Path;
    assert_eq!(
        Contract219GrantAdapter::test_journal_tmp_path(Path::new("/dir/grant.journal")),
        Path::new("/dir/grant.journal.tmp")
    );
    assert_eq!(
        Contract219GrantAdapter::test_journal_tmp_path(Path::new("/dir/grant.bak")),
        Path::new("/dir/grant.bak.tmp")
    );
    assert_ne!(
        Contract219GrantAdapter::test_journal_tmp_path(Path::new("/dir/grant.journal")),
        Contract219GrantAdapter::test_journal_tmp_path(Path::new("/dir/grant.bak"))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t23_persist_journal_writes_full_filename_tmp() {
    let live = live_new().await;
    let colliding = tempfile::tempdir().expect("colliding stem tmp");
    let colliding_journal = colliding.path().join("grant.journal");
    std::fs::create_dir(colliding.path().join("grant.tmp")).expect("grant.tmp directory");
    let opened = Contract219GrantAdapter::with_recovery(
        Arc::clone(&live.intake),
        Arc::clone(&live.projector),
        colliding_journal.clone(),
        [0x11; 32],
        [0x22; 16],
        Zeroizing::new([0x33; 32]),
    );
    assert!(
        opened.is_ok(),
        "persist must not write grant.tmp: {:?}",
        opened.err()
    );
    assert!(colliding_journal.is_file(), "final journal must land");
    assert!(
        colliding.path().join("grant.tmp").is_dir(),
        "colliding stem directory must stay unused"
    );

    let blocked = tempfile::tempdir().expect("blocked full-name tmp");
    let blocked_journal = blocked.path().join("grant.journal");
    std::fs::create_dir(blocked.path().join("grant.journal.tmp")).expect("grant.journal.tmp dir");
    let err = Contract219GrantAdapter::with_recovery(
        Arc::clone(&live.intake),
        Arc::clone(&live.projector),
        blocked_journal,
        [0x11; 32],
        [0x22; 16],
        Zeroizing::new([0x33; 32]),
    );
    assert!(
        err.is_err(),
        "persist must write grant.journal.tmp so a directory there fails closed"
    );

    let adapter = opened.expect("recovery adapter");
    let journal_hard = colliding.path().join("grant.journal.hard");
    std::fs::hard_link(&colliding_journal, &journal_hard).expect("hard-link journal");
    let hard_before = std::fs::read(&journal_hard).expect("hard-link bytes before persist_all");
    park(
        &live.intake,
        "persist-again",
        "caller-none",
        None,
        GrantTtl::Once,
        None,
    );
    let revision = listed_revision(&live.api, "persist-again");
    match adapter.prepare_mutation_bound(
        [0x71; 32],
        [0x72; 32],
        BoundGrantMutation::Approve {
            request_id: "persist-again".to_owned(),
            decision_revision: revision,
        },
    ) {
        ProviderPrepareOutcome::Prepared(_) => {}
        ProviderPrepareOutcome::Rejected(error) => {
            panic!("persist_all must not write grant.tmp: {error:?}")
        }
    }
    assert!(
        colliding.path().join("grant.tmp").is_dir(),
        "mutation persist must leave the colliding stem directory unused"
    );
    assert!(colliding_journal.is_file());
    assert_eq!(
        std::fs::read(&journal_hard).expect("hard-link bytes after persist_all"),
        hard_before,
        "File::create on the regular journal path would truncate the hard link"
    );
    assert_ne!(
        std::fs::read(&colliding_journal).expect("journal after persist_all"),
        hard_before,
        "persist_all must replace the journal inode so the hard link keeps the previous frame"
    );

    let persist_backing = colliding.path().join("persist-backing.dat");
    std::fs::write(&persist_backing, b"").expect("empty persist backing");
    std::fs::remove_file(&colliding_journal).expect("remove init journal");
    std::os::unix::fs::symlink(&persist_backing, &colliding_journal)
        .expect("symlink journal for persist_all");
    park(
        &live.intake,
        "persist-rename",
        "caller-none",
        None,
        GrantTtl::Once,
        None,
    );
    let persist_revision = listed_revision(&live.api, "persist-rename");
    match adapter.prepare_mutation_bound(
        [0x73; 32],
        [0x74; 32],
        BoundGrantMutation::Approve {
            request_id: "persist-rename".to_owned(),
            decision_revision: persist_revision,
        },
    ) {
        ProviderPrepareOutcome::Prepared(_) => {}
        ProviderPrepareOutcome::Rejected(error) => {
            panic!("persist_all must rename over the symlink: {error:?}")
        }
    }
    assert!(
        std::fs::symlink_metadata(&colliding_journal)
            .expect("persist journal metadata")
            .file_type()
            .is_file(),
        "persist_all must rename onto the final path, not overwrite in place"
    );
    assert_eq!(
        std::fs::read(&persist_backing).expect("persist backing"),
        b"",
        "in-place write would follow the symlink and replace the backing"
    );

    let persist_blocked = tempfile::tempdir().expect("blocked persist_all tmp");
    let persist_blocked_journal = persist_blocked.path().join("grant.journal");
    let persist_adapter = Contract219GrantAdapter::with_recovery(
        Arc::clone(&live.intake),
        Arc::clone(&live.projector),
        persist_blocked_journal,
        [0x11; 32],
        [0x22; 16],
        Zeroizing::new([0x33; 32]),
    )
    .expect("init before blocking persist tmp");
    std::fs::create_dir(persist_blocked.path().join("grant.journal.tmp"))
        .expect("block persist_all tmp");
    park(
        &live.intake,
        "persist-blocked",
        "caller-none",
        None,
        GrantTtl::Once,
        None,
    );
    let blocked_revision = listed_revision(&live.api, "persist-blocked");
    let blocked_rows_before = persist_adapter.test_journal_row_count();
    match persist_adapter.prepare_mutation_bound(
        [0x75; 32],
        [0x76; 32],
        BoundGrantMutation::Approve {
            request_id: "persist-blocked".to_owned(),
            decision_revision: blocked_revision,
        },
    ) {
        ProviderPrepareOutcome::Rejected(_) => {}
        ProviderPrepareOutcome::Prepared(_) => {
            panic!("persist_all must write grant.journal.tmp so a directory there fails closed")
        }
    }
    assert_eq!(
        persist_adapter.test_journal_row_count(),
        blocked_rows_before,
        "persist I/O failure must remove the in-memory Prepared row"
    );

    let linked = tempfile::tempdir().expect("symlink journal");
    let backing = linked.path().join("backing.dat");
    std::fs::write(&backing, b"").expect("empty backing");
    let linked_journal = linked.path().join("grant.journal");
    std::os::unix::fs::symlink(&backing, &linked_journal).expect("symlink journal");
    Contract219GrantAdapter::with_recovery(
        Arc::clone(&live.intake),
        Arc::clone(&live.projector),
        linked_journal.clone(),
        [0x11; 32],
        [0x22; 16],
        Zeroizing::new([0x33; 32]),
    )
    .expect("init must rename tmp over the symlink");
    assert!(
        std::fs::symlink_metadata(&linked_journal)
            .expect("journal metadata")
            .file_type()
            .is_file(),
        "persist must rename onto the final path, not follow the symlink"
    );
    assert_eq!(
        std::fs::read(&backing).expect("backing"),
        b"",
        "direct write through the symlink would replace the backing bytes"
    );

    let tmp_linked = tempfile::tempdir().expect("tmp symlink journal");
    let tmp_victim = tmp_linked.path().join("tmp-victim.dat");
    std::fs::write(&tmp_victim, b"keep-tmp").expect("tmp victim");
    std::os::unix::fs::symlink(&tmp_victim, tmp_linked.path().join("grant.journal.tmp"))
        .expect("symlink journal tmp");
    let tmp_linked_journal = tmp_linked.path().join("grant.journal");
    Contract219GrantAdapter::with_recovery(
        Arc::clone(&live.intake),
        Arc::clone(&live.projector),
        tmp_linked_journal.clone(),
        [0x11; 32],
        [0x22; 16],
        Zeroizing::new([0x33; 32]),
    )
    .expect("init must not follow a journal tmp symlink");
    assert_eq!(
        std::fs::read(&tmp_victim).expect("tmp victim after init"),
        b"keep-tmp",
        "File::create on a tmp symlink would truncate the victim"
    );
    assert!(
        std::fs::symlink_metadata(&tmp_linked_journal)
            .expect("tmp-linked journal metadata")
            .file_type()
            .is_file(),
        "init must land a regular journal file"
    );

    let persist_tmp_victim = colliding.path().join("persist-tmp-victim.dat");
    std::fs::write(&persist_tmp_victim, b"keep-persist-tmp").expect("persist tmp victim");
    let persist_tmp = colliding.path().join("grant.journal.tmp");
    let _ = std::fs::remove_file(&persist_tmp);
    std::os::unix::fs::symlink(&persist_tmp_victim, &persist_tmp)
        .expect("symlink persist_all tmp");
    park(
        &live.intake,
        "persist-tmp-symlink",
        "caller-none",
        None,
        GrantTtl::Once,
        None,
    );
    let persist_tmp_revision = listed_revision(&live.api, "persist-tmp-symlink");
    match adapter.prepare_mutation_bound(
        [0x77; 32],
        [0x78; 32],
        BoundGrantMutation::Approve {
            request_id: "persist-tmp-symlink".to_owned(),
            decision_revision: persist_tmp_revision,
        },
    ) {
        ProviderPrepareOutcome::Prepared(_) => {}
        ProviderPrepareOutcome::Rejected(error) => {
            panic!("persist_all must not follow a journal tmp symlink: {error:?}")
        }
    }
    assert_eq!(
        std::fs::read(&persist_tmp_victim).expect("persist tmp victim"),
        b"keep-persist-tmp",
        "persist_all File::create would follow the tmp symlink and replace the victim"
    );
    assert!(
        std::fs::symlink_metadata(&persist_tmp).is_err(),
        "rename must consume the exclusive tmp file"
    );

    let write_limit = tempfile::tempdir().expect("write-limit journal");
    let write_journal = write_limit.path().join("grant.journal");
    let write_adapter = Contract219GrantAdapter::with_recovery(
        Arc::clone(&live.intake),
        Arc::clone(&live.projector),
        write_journal.clone(),
        [0x51; 32],
        [0x52; 16],
        Zeroizing::new([0x53; 32]),
    )
    .expect("seed write-limit journal");
    let before = std::fs::metadata(&write_journal)
        .expect("seeded write-limit journal")
        .len();
    assert!(
        before < 8 * 1024 * 1024,
        "seeded journal must be under the write cap"
    );
    let write_tmp = Contract219GrantAdapter::test_journal_tmp_path(&write_journal);
    let write_victim = write_limit.path().join("write-limit-victim");
    let deny_chunk = "x".repeat(256 * 1024);
    let lone_grant_id = "g".repeat(6 * 1024 * 1024);
    const FILL_DENIES: u8 = 10;
    const OVERFLOW_EMPTY_PARAMS: usize = 740_000;
    assert!(
        usize::from(FILL_DENIES) * deny_chunk.len() < 8_000_000,
        "filled Deny reasons must stay under 8e6 so a Σreason budget cannot be the overflow trigger"
    );
    let lone_dir = tempfile::tempdir().expect("lone 6MiB revoke journal");
    let lone_journal = lone_dir.path().join("grant.journal");
    let lone_adapter = Contract219GrantAdapter::with_recovery(
        Arc::clone(&live.intake),
        Arc::clone(&live.projector),
        lone_journal.clone(),
        [0x58; 32],
        [0x59; 16],
        Zeroizing::new([0x5a; 32]),
    )
    .expect("seed lone revoke journal");
    match lone_adapter.prepare_mutation_bound(
        [0x5b; 32],
        [0x5c; 32],
        BoundGrantMutation::Revoke {
            grant_id: lone_grant_id,
        },
    ) {
        ProviderPrepareOutcome::Prepared(_) => {}
        ProviderPrepareOutcome::Rejected(error) => {
            panic!("lone 6MiB Revoke frame is under MAX and must persist: {error:?}")
        }
    }
    let lone_len = std::fs::metadata(&lone_journal)
        .expect("lone revoke journal")
        .len();
    assert!(
        lone_len > 5_000_000 && lone_len < 8 * 1024 * 1024,
        "lone 6MiB grant_id must write a frame in (5MiB, 8MiB); grant_id>5e6 or encode_row>5e6 would reject it"
    );
    assert_eq!(lone_adapter.test_journal_row_count(), 1);
    let combo_tmp = Contract219GrantAdapter::test_journal_tmp_path(&lone_journal);
    let combo_victim = lone_dir.path().join("combo-victim");
    std::fs::write(&combo_victim, b"keep-combo").expect("combo victim");
    if combo_tmp.exists() || combo_tmp.symlink_metadata().is_ok() {
        let _ = std::fs::remove_file(&combo_tmp);
    }
    std::os::unix::fs::symlink(&combo_victim, &combo_tmp).expect("tmp symlink before 6MiB+3MiB overflow");
    match lone_adapter.prepare_mutation_bound(
        [0x67; 32],
        [0x68; 32],
        BoundGrantMutation::Deny {
            request_id: "combo-deny".to_owned(),
            decision_revision: "not-a-revision".to_owned(),
            reason: "d".repeat(3 * 1024 * 1024),
        },
    ) {
        ProviderPrepareOutcome::Rejected(ProviderError::Unavailable(_)) => {}
        ProviderPrepareOutcome::Rejected(error) => {
            panic!("6MiB Revoke + 3MiB Deny must fail closed: {error:?}")
        }
        ProviderPrepareOutcome::Prepared(_) => {
            panic!(
                "same-volume 6MiB Revoke + 3MiB Deny is ~9.4MiB / 2 rows / ~3MiB encode_row; rows>31 or Narrow&&rows>1 would still Prepared"
            )
        }
    }
    assert_eq!(
        lone_adapter.test_journal_row_count(),
        1,
        "3MiB Deny stacked on 6MiB Revoke must roll back"
    );
    assert_eq!(
        std::fs::metadata(&lone_journal)
            .expect("journal after combo overflow")
            .len(),
        lone_len
    );
    assert!(
        std::fs::symlink_metadata(&combo_tmp)
            .expect("combo tmp after overflow")
            .file_type()
            .is_symlink(),
        "combo frame reject must happen before create_exclusive_journal_tmp"
    );
    assert_eq!(
        std::fs::read(&combo_victim).expect("combo victim"),
        b"keep-combo"
    );
    let lone_over_dir = tempfile::tempdir().expect("lone oversize revoke journal");
    let lone_over_journal = lone_over_dir.path().join("grant.journal");
    let lone_over_adapter = Contract219GrantAdapter::with_recovery(
        Arc::clone(&live.intake),
        Arc::clone(&live.projector),
        lone_over_journal.clone(),
        [0x69; 32],
        [0x6a; 16],
        Zeroizing::new([0x6b; 32]),
    )
    .expect("seed lone oversize journal");
    let lone_over_before = std::fs::metadata(&lone_over_journal)
        .expect("seeded lone oversize journal")
        .len();
    let lone_over_tmp = Contract219GrantAdapter::test_journal_tmp_path(&lone_over_journal);
    let lone_over_victim = lone_over_dir.path().join("lone-over-victim");
    std::fs::write(&lone_over_victim, b"keep-lone-over").expect("lone-over victim");
    if lone_over_tmp.exists() || lone_over_tmp.symlink_metadata().is_ok() {
        let _ = std::fs::remove_file(&lone_over_tmp);
    }
    std::os::unix::fs::symlink(&lone_over_victim, &lone_over_tmp)
        .expect("tmp symlink before lone 8.1MiB overflow");
    match lone_over_adapter.prepare_mutation_bound(
        [0x6c; 32],
        [0x6d; 32],
        BoundGrantMutation::Revoke {
            grant_id: "g".repeat(8 * 1024 * 1024 + 100 * 1024),
        },
    ) {
        ProviderPrepareOutcome::Rejected(ProviderError::Unavailable(_)) => {}
        ProviderPrepareOutcome::Rejected(error) => {
            panic!("lone 8.1MiB Revoke must fail closed: {error:?}")
        }
        ProviderPrepareOutcome::Prepared(_) => {
            panic!(
                "lone ~8.1MiB Revoke is rows==1 && frame>8MiB; rows>1 && frame>MAX would still Prepared"
            )
        }
    }
    assert_eq!(
        lone_over_adapter.test_journal_row_count(),
        0,
        "lone oversize Revoke must not retain a prepared row"
    );
    assert_eq!(
        std::fs::metadata(&lone_over_journal)
            .expect("journal after lone oversize")
            .len(),
        lone_over_before
    );
    assert!(
        std::fs::symlink_metadata(&lone_over_tmp)
            .expect("lone-over tmp after overflow")
            .file_type()
            .is_symlink(),
        "lone-over frame reject must happen before create_exclusive_journal_tmp"
    );
    assert_eq!(
        std::fs::read(&lone_over_victim).expect("lone-over victim"),
        b"keep-lone-over"
    );
    let lone_narrow_dir = tempfile::tempdir().expect("lone empty-param Narrow journal");
    let lone_narrow_journal = lone_narrow_dir.path().join("grant.journal");
    let lone_narrow_adapter = Contract219GrantAdapter::with_recovery(
        Arc::clone(&live.intake),
        Arc::clone(&live.projector),
        lone_narrow_journal.clone(),
        [0x5d; 32],
        [0x5e; 16],
        Zeroizing::new([0x5f; 32]),
    )
    .expect("seed lone Narrow journal");
    let lone_narrow_params = vec![
        ClientCapParam {
            key: String::new(),
            value: String::new(),
        };
        OVERFLOW_EMPTY_PARAMS
    ];
    match lone_narrow_adapter.prepare_mutation_bound(
        [0x60; 32],
        [0x61; 32],
        BoundGrantMutation::Narrow {
            request_id: "lone-narrow".to_owned(),
            decision_revision: "not-a-revision".to_owned(),
            params: lone_narrow_params,
        },
    ) {
        ProviderPrepareOutcome::Prepared(_) => {}
        ProviderPrepareOutcome::Rejected(error) => {
            panic!("lone 740k-empty-param Narrow frame is under MAX and must persist: {error:?}")
        }
    }
    let lone_narrow_len = std::fs::metadata(&lone_narrow_journal)
        .expect("lone Narrow journal")
        .len();
    assert!(
        lone_narrow_len > 5_000_000 && lone_narrow_len < 8 * 1024 * 1024,
        "lone empty-param Narrow must write a frame in (5MiB, 8MiB); if Narrow / param_count≥740k would reject it"
    );
    assert_eq!(lone_narrow_adapter.test_journal_row_count(), 1);
    let mut last_len = before;
    for filled in 0..FILL_DENIES {
        let mut mutation_id = [0x54u8; 32];
        mutation_id[31] = filled;
        match write_adapter.prepare_mutation_bound(
            mutation_id,
            [0x55; 32],
            BoundGrantMutation::Deny {
                request_id: format!("persist-fill-{filled}"),
                decision_revision: "not-a-revision".to_owned(),
                reason: deny_chunk.clone(),
            },
        ) {
            ProviderPrepareOutcome::Prepared(_) => {
                last_len = std::fs::metadata(&write_journal)
                    .expect("journal after fill row")
                    .len();
            }
            ProviderPrepareOutcome::Rejected(error) => {
                panic!("fill row {filled} must persist under the cap: {error:?}")
            }
        }
    }
    assert_eq!(write_adapter.test_journal_row_count(), usize::from(FILL_DENIES));
    std::fs::write(&write_victim, b"keep-write-limit").expect("write-limit victim");
    if write_tmp.exists() || write_tmp.symlink_metadata().is_ok() {
        let _ = std::fs::remove_file(&write_tmp);
    }
    std::os::unix::fs::symlink(&write_victim, &write_tmp).expect("tmp symlink before overflow persist");
    let overflow_params = vec![
        ClientCapParam {
            key: String::new(),
            value: String::new(),
        };
        OVERFLOW_EMPTY_PARAMS
    ];
    match write_adapter.prepare_mutation_bound(
        [0x57; 32],
        [0x56; 32],
        BoundGrantMutation::Narrow {
            request_id: "persist-overflow".to_owned(),
            decision_revision: "not-a-revision".to_owned(),
            params: overflow_params,
        },
    ) {
        ProviderPrepareOutcome::Rejected(ProviderError::Unavailable(_)) => {}
        ProviderPrepareOutcome::Rejected(error) => {
            panic!("overflow persist must fail closed: {error:?}")
        }
        ProviderPrepareOutcome::Prepared(_) => {
            panic!("persist_journal must reject a multi-row frame larger than MAX_JOURNAL_BYTES; a Σtext>8e6 or grant_id>5e6 gate would not see this empty-param Narrow")
        }
    }
    assert_eq!(
        write_adapter.test_journal_row_count(),
        usize::from(FILL_DENIES),
        "persist size reject must roll back only the overflowing row"
    );
    assert_eq!(
        std::fs::metadata(&write_journal)
            .expect("journal after persist size reject")
            .len(),
        last_len,
        "persist_journal must not replace the filled journal with an oversized frame"
    );
    assert!(
        std::fs::symlink_metadata(&write_tmp)
            .expect("tmp path after persist size reject")
            .file_type()
            .is_symlink(),
        "frame-length reject must happen before create_exclusive_journal_tmp; write_all-then-abandon would remove this symlink"
    );
    assert_eq!(
        std::fs::read(&write_victim).expect("write-limit victim"),
        b"keep-write-limit",
        "persist size reject must not follow or replace the tmp symlink victim"
    );

    let small_dir = tempfile::tempdir().expect("small-row overflow journal");
    let small_journal = small_dir.path().join("grant.journal");
    let small_adapter = Contract219GrantAdapter::with_recovery(
        Arc::clone(&live.intake),
        Arc::clone(&live.projector),
        small_journal.clone(),
        [0x62; 32],
        [0x63; 16],
        Zeroizing::new([0x64; 32]),
    )
    .expect("seed small-row journal");
    let mut small_filled = 0u8;
    let mut small_len = 0;
    loop {
        let mut mutation_id = [0x65u8; 32];
        mutation_id[31] = small_filled;
        let size_before = std::fs::metadata(&small_journal)
            .expect("small-row before fill")
            .len();
        match small_adapter.prepare_mutation_bound(
            mutation_id,
            [0x66; 32],
            BoundGrantMutation::Deny {
                request_id: format!("small-fill-{small_filled}"),
                decision_revision: "not-a-revision".to_owned(),
                reason: deny_chunk.clone(),
            },
        ) {
            ProviderPrepareOutcome::Prepared(_) => {
                let size_after = std::fs::metadata(&small_journal)
                    .expect("small-row after fill")
                    .len();
                let delta = size_after.saturating_sub(size_before);
                small_filled = small_filled.checked_add(1).expect("too many small fill rows");
                small_len = size_after;
                if size_after.saturating_add(delta) > 8 * 1024 * 1024 {
                    break;
                }
            }
            ProviderPrepareOutcome::Rejected(error) => {
                panic!("small fill row {small_filled} must persist under the cap: {error:?}")
            }
        }
        assert!(
            small_filled < 64,
            "256KiB deny rows should approach 8MiB well before 64 prepares"
        );
    }
    assert!(
        small_filled >= 2,
        "small-row overflow needs multiple 256KiB rows so encode_row of the overflowing Deny stays far under 5MiB"
    );
    let small_tmp = Contract219GrantAdapter::test_journal_tmp_path(&small_journal);
    let small_victim = small_dir.path().join("small-row-victim");
    std::fs::write(&small_victim, b"keep-small-row").expect("small-row victim");
    if small_tmp.exists() || small_tmp.symlink_metadata().is_ok() {
        let _ = std::fs::remove_file(&small_tmp);
    }
    std::os::unix::fs::symlink(&small_victim, &small_tmp).expect("tmp symlink before small-row overflow");
    let mut overflow_id = [0x65u8; 32];
    overflow_id[31] = small_filled;
    match small_adapter.prepare_mutation_bound(
        overflow_id,
        [0x66; 32],
        BoundGrantMutation::Deny {
            request_id: format!("small-fill-{small_filled}"),
            decision_revision: "not-a-revision".to_owned(),
            reason: deny_chunk,
        },
    ) {
        ProviderPrepareOutcome::Rejected(ProviderError::Unavailable(_)) => {}
        ProviderPrepareOutcome::Rejected(error) => {
            panic!("small-row overflow persist must fail closed: {error:?}")
        }
        ProviderPrepareOutcome::Prepared(_) => {
            panic!(
                "persist_journal must reject stacked 256KiB Deny frames over MAX; rows>1 && encode_row>5e6 would miss this 256KiB row"
            )
        }
    }
    assert_eq!(
        small_adapter.test_journal_row_count(),
        usize::from(small_filled),
        "small-row overflow must roll back only the overflowing Deny"
    );
    assert_eq!(
        std::fs::metadata(&small_journal)
            .expect("journal after small-row overflow")
            .len(),
        small_len
    );
    assert!(
        std::fs::symlink_metadata(&small_tmp)
            .expect("small-row tmp after overflow")
            .file_type()
            .is_symlink(),
        "small-row frame reject must happen before create_exclusive_journal_tmp"
    );
    assert_eq!(
        std::fs::read(&small_victim).expect("small-row victim"),
        b"keep-small-row"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t23_journal_reloads_all_rows_and_executes_by_mutation_id() {
    let live = live_new().await;
    park(
        &live.intake,
        "row-a",
        "caller-none",
        None,
        GrantTtl::Once,
        None,
    );
    park(
        &live.intake,
        "row-b",
        "caller-empty",
        Some(Vec::new()),
        GrantTtl::Once,
        None,
    );
    let workspace = tempfile::tempdir().expect("multi-row journal");
    let journal = workspace.path().join("grant.journal");
    let ticket_ikm = [0x11u8; 32];
    let store_instance = [0x22u8; 16];
    let master = Zeroizing::new([0x33u8; 32]);
    let first = Arc::new(
        Contract219GrantAdapter::with_recovery(
            Arc::clone(&live.intake),
            Arc::clone(&live.projector),
            journal.clone(),
            ticket_ikm,
            store_instance,
            master.clone(),
        )
        .expect("first recovery adapter"),
    );
    let detector: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let api = ClientApi::new(ClientApiConfig::default())
        .with_bound_grant_provider(first.clone())
        .with_observation_redactor(live.projector.redactor())
        .with_leak_detector(detector);
    api.sessions().insert(
        "tok".to_owned(),
        ClientSession {
            session_id: "session".to_owned(),
            principal: Principal::operator("operator"),
            platform: Platform::Web,
            scopes: Scope::operator_default(),
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );
    let rev_a = listed_revision(&api, "row-a");
    let rev_b = listed_revision(&api, "row-b");
    let ticket_a = match first.prepare_mutation_bound(
        [0x10; 32],
        [0xA1; 32],
        BoundGrantMutation::Approve {
            request_id: "row-a".to_owned(),
            decision_revision: rev_a,
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare row-a: {error:?}"),
    };
    let ticket_b = match first.prepare_mutation_bound(
        [0x20; 32],
        [0xA1; 32],
        BoundGrantMutation::Approve {
            request_id: "row-b".to_owned(),
            decision_revision: rev_b,
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare row-b: {error:?}"),
    };
    assert_eq!(first.test_journal_row_count(), 2);
    drop(api);
    drop(first);
    let reloaded = Arc::new(
        Contract219GrantAdapter::with_recovery(
            Arc::clone(&live.intake),
            Arc::clone(&live.projector),
            journal.clone(),
            ticket_ikm,
            store_instance,
            master.clone(),
        )
        .expect("reload recovery adapter"),
    );
    assert_eq!(
        reloaded.test_journal_row_count(),
        2,
        "persist_all must write the entire map, not only the last-sorted row"
    );
    reloaded
        .verify_recovery_ticket_bound([0x10; 32], [0xA1; 32], 1, &ticket_a)
        .expect("verify row-a after reload");
    reloaded
        .verify_recovery_ticket_bound([0x20; 32], [0xA1; 32], 1, &ticket_b)
        .expect("verify row-b after reload");
    match reloaded.recover_mutation_bound(&ticket_a) {
        BoundMutationOutcome::Committed(_) => {}
        BoundMutationOutcome::Rejected(error) => panic!("recover first-sorted id: {error:?}"),
        BoundMutationOutcome::OutcomeUnknown(_) => panic!("recover first-sorted id unknown"),
    }
    assert_eq!(
        live.intake.decision("row-a"),
        ChannelApprovalDecision::Approved,
        "recover_mutation_bound must use ticket.mutation_id, not last Prepared or shared fingerprint"
    );
    assert_eq!(
        live.intake.decision("row-b"),
        ChannelApprovalDecision::Pending,
        "last-Prepared-after-sort or fingerprint lookup would have approved row-b instead of row-a"
    );
    match reloaded.recover_mutation_bound(&ticket_b) {
        BoundMutationOutcome::Committed(_) => {}
        BoundMutationOutcome::Rejected(error) => panic!("recover last-sorted id: {error:?}"),
        BoundMutationOutcome::OutcomeUnknown(_) => panic!("recover last-sorted id unknown"),
    }
    assert_eq!(
        live.intake.decision("row-b"),
        ChannelApprovalDecision::Approved
    );

    park(
        &live.intake,
        "row-c",
        "caller-none",
        None,
        GrantTtl::Once,
        None,
    );
    park(
        &live.intake,
        "row-d",
        "caller-empty",
        Some(Vec::new()),
        GrantTtl::Once,
        None,
    );
    let detector_reload: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let api_reload = ClientApi::new(ClientApiConfig::default())
        .with_bound_grant_provider(reloaded.clone())
        .with_observation_redactor(live.projector.redactor())
        .with_leak_detector(detector_reload);
    api_reload.sessions().insert(
        "tok".to_owned(),
        ClientSession {
            session_id: "session".to_owned(),
            principal: Principal::operator("operator"),
            platform: Platform::Web,
            scopes: Scope::operator_default(),
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );
    let rev_c = listed_revision(&api_reload, "row-c");
    let rev_d = listed_revision(&api_reload, "row-d");
    let ticket_c = match reloaded.prepare_mutation_bound(
        [0x30; 32],
        [0xC1; 32],
        BoundGrantMutation::Approve {
            request_id: "row-c".to_owned(),
            decision_revision: rev_c,
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare row-c: {error:?}"),
    };
    let ticket_d = match reloaded.prepare_mutation_bound(
        [0x40; 32],
        [0xC1; 32],
        BoundGrantMutation::Approve {
            request_id: "row-d".to_owned(),
            decision_revision: rev_d,
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare row-d: {error:?}"),
    };
    match reloaded.execute_prepared_bound(&ticket_d) {
        BoundMutationOutcome::Committed(_) => {}
        BoundMutationOutcome::Rejected(error) => panic!("execute last-sorted live pair: {error:?}"),
        BoundMutationOutcome::OutcomeUnknown(_) => panic!("execute last-sorted live pair unknown"),
    }
    assert_eq!(
        live.intake.decision("row-d"),
        ChannelApprovalDecision::Approved,
        "execute_prepared_bound must use ticket.mutation_id, not first Prepared or shared fingerprint"
    );
    assert_eq!(
        live.intake.decision("row-c"),
        ChannelApprovalDecision::Pending,
        "first-Prepared-after-sort or fingerprint lookup would have approved row-c instead of row-d"
    );
    match reloaded.execute_prepared_bound(&ticket_c) {
        BoundMutationOutcome::Committed(_) => {}
        BoundMutationOutcome::Rejected(error) => panic!("execute first-sorted live pair: {error:?}"),
        BoundMutationOutcome::OutcomeUnknown(_) => panic!("execute first-sorted live pair unknown"),
    }
    assert_eq!(
        live.intake.decision("row-c"),
        ChannelApprovalDecision::Approved
    );

    park(
        &live.intake,
        "row-e",
        "caller-none",
        None,
        GrantTtl::Once,
        None,
    );
    park(
        &live.intake,
        "row-f",
        "caller-empty",
        Some(Vec::new()),
        GrantTtl::Once,
        None,
    );
    let rev_e = listed_revision(&api_reload, "row-e");
    let rev_f = listed_revision(&api_reload, "row-f");
    let ticket_e = match reloaded.prepare_mutation_bound(
        [0x50; 32],
        [0xE1; 32],
        BoundGrantMutation::Approve {
            request_id: "row-e".to_owned(),
            decision_revision: rev_e,
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare row-e: {error:?}"),
    };
    let ticket_f = match reloaded.prepare_mutation_bound(
        [0x60; 32],
        [0xE1; 32],
        BoundGrantMutation::Approve {
            request_id: "row-f".to_owned(),
            decision_revision: rev_f,
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare row-f: {error:?}"),
    };
    match reloaded.recover_mutation_bound(&ticket_f) {
        BoundMutationOutcome::Committed(_) => {}
        BoundMutationOutcome::Rejected(error) => panic!("recover last-sorted live pair: {error:?}"),
        BoundMutationOutcome::OutcomeUnknown(_) => panic!("recover last-sorted live pair unknown"),
    }
    assert_eq!(
        live.intake.decision("row-f"),
        ChannelApprovalDecision::Approved,
        "recover_mutation_bound must use ticket.mutation_id, not first Prepared after sort"
    );
    assert_eq!(
        live.intake.decision("row-e"),
        ChannelApprovalDecision::Pending,
        "first-Prepared-after-sort recover would have approved row-e instead of row-f"
    );
    match reloaded.recover_mutation_bound(&ticket_e) {
        BoundMutationOutcome::Committed(_) => {}
        BoundMutationOutcome::Rejected(error) => panic!("recover first-sorted leftover: {error:?}"),
        BoundMutationOutcome::OutcomeUnknown(_) => panic!("recover first-sorted leftover unknown"),
    }
    assert_eq!(
        live.intake.decision("row-e"),
        ChannelApprovalDecision::Approved
    );

    park(
        &live.intake,
        "row-g",
        "caller-none",
        None,
        GrantTtl::Once,
        None,
    );
    park(
        &live.intake,
        "row-h",
        "caller-empty",
        Some(Vec::new()),
        GrantTtl::Once,
        None,
    );
    let rev_g = listed_revision(&api_reload, "row-g");
    let rev_h = listed_revision(&api_reload, "row-h");
    let ticket_g = match reloaded.prepare_mutation_bound(
        [0x70; 32],
        [0xF1; 32],
        BoundGrantMutation::Approve {
            request_id: "row-g".to_owned(),
            decision_revision: rev_g,
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare row-g: {error:?}"),
    };
    let ticket_h = match reloaded.prepare_mutation_bound(
        [0x80; 32],
        [0xF1; 32],
        BoundGrantMutation::Approve {
            request_id: "row-h".to_owned(),
            decision_revision: rev_h,
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare row-h: {error:?}"),
    };
    match reloaded.execute_prepared_bound(&ticket_g) {
        BoundMutationOutcome::Committed(_) => {}
        BoundMutationOutcome::Rejected(error) => panic!("execute first-sorted live pair: {error:?}"),
        BoundMutationOutcome::OutcomeUnknown(_) => panic!("execute first-sorted live pair unknown"),
    }
    assert_eq!(
        live.intake.decision("row-g"),
        ChannelApprovalDecision::Approved,
        "execute_prepared_bound must use ticket.mutation_id, not last Prepared after sort"
    );
    assert_eq!(
        live.intake.decision("row-h"),
        ChannelApprovalDecision::Pending,
        "last-Prepared-after-sort execute would have approved row-h instead of row-g"
    );
    match reloaded.execute_prepared_bound(&ticket_h) {
        BoundMutationOutcome::Committed(_) => {}
        BoundMutationOutcome::Rejected(error) => panic!("execute last-sorted leftover: {error:?}"),
        BoundMutationOutcome::OutcomeUnknown(_) => panic!("execute last-sorted leftover unknown"),
    }
    assert_eq!(
        live.intake.decision("row-h"),
        ChannelApprovalDecision::Approved
    );

    park(
        &live.intake,
        "row-i",
        "caller-none",
        None,
        GrantTtl::Once,
        None,
    );
    park(
        &live.intake,
        "row-j",
        "caller-empty",
        Some(Vec::new()),
        GrantTtl::Once,
        None,
    );
    let rev_i = listed_revision(&api_reload, "row-i");
    let rev_j = listed_revision(&api_reload, "row-j");
    let ticket_i = match reloaded.prepare_mutation_bound(
        [0x90; 32],
        [0xB1; 32],
        BoundGrantMutation::Approve {
            request_id: "row-i".to_owned(),
            decision_revision: rev_i,
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare row-i: {error:?}"),
    };
    let ticket_j = match reloaded.prepare_mutation_bound(
        [0xA0; 32],
        [0xB1; 32],
        BoundGrantMutation::Approve {
            request_id: "row-j".to_owned(),
            decision_revision: rev_j,
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare row-j: {error:?}"),
    };
    drop(api_reload);
    drop(reloaded);
    let executed = Arc::new(
        Contract219GrantAdapter::with_recovery(
            Arc::clone(&live.intake),
            Arc::clone(&live.projector),
            journal.clone(),
            ticket_ikm,
            store_instance,
            master.clone(),
        )
        .expect("execute-after-reload adapter"),
    );
    executed
        .verify_recovery_ticket_bound([0x90; 32], [0xB1; 32], 1, &ticket_i)
        .expect("verify row-i after reload");
    executed
        .verify_recovery_ticket_bound([0xA0; 32], [0xB1; 32], 1, &ticket_j)
        .expect("verify row-j after reload");
    match executed.execute_prepared_bound(&ticket_j) {
        BoundMutationOutcome::Committed(_) => {}
        BoundMutationOutcome::Rejected(error) => {
            panic!("execute journal-reloaded last-sorted id: {error:?}")
        }
        BoundMutationOutcome::OutcomeUnknown(_) => {
            panic!("execute journal-reloaded last-sorted id unknown")
        }
    }
    assert_eq!(
        live.intake.decision("row-j"),
        ChannelApprovalDecision::Approved,
        "execute_prepared_bound must apply a journal-reloaded Prepared row by mutation_id"
    );
    assert_eq!(
        live.intake.decision("row-i"),
        ChannelApprovalDecision::Pending,
        "session-only execute or first-Prepared lookup would miss or mis-approve after reload"
    );
    match executed.execute_prepared_bound(&ticket_i) {
        BoundMutationOutcome::Committed(_) => {}
        BoundMutationOutcome::Rejected(error) => {
            panic!("execute journal-reloaded first-sorted leftover: {error:?}")
        }
        BoundMutationOutcome::OutcomeUnknown(_) => {
            panic!("execute journal-reloaded first-sorted leftover unknown")
        }
    }
    assert_eq!(
        live.intake.decision("row-i"),
        ChannelApprovalDecision::Approved
    );

    park(
        &live.intake,
        "row-k",
        "caller-none",
        None,
        GrantTtl::Once,
        None,
    );
    park(
        &live.intake,
        "row-l",
        "caller-empty",
        Some(Vec::new()),
        GrantTtl::Once,
        None,
    );
    let detector_k: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let api_k = ClientApi::new(ClientApiConfig::default())
        .with_bound_grant_provider(executed.clone())
        .with_observation_redactor(live.projector.redactor())
        .with_leak_detector(detector_k);
    api_k.sessions().insert(
        "tok".to_owned(),
        ClientSession {
            session_id: "session".to_owned(),
            principal: Principal::operator("operator"),
            platform: Platform::Web,
            scopes: Scope::operator_default(),
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );
    let rev_k = listed_revision(&api_k, "row-k");
    let rev_l = listed_revision(&api_k, "row-l");
    let ticket_k = match executed.prepare_mutation_bound(
        [0xB0; 32],
        [0xD1; 32],
        BoundGrantMutation::Approve {
            request_id: "row-k".to_owned(),
            decision_revision: rev_k,
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare row-k: {error:?}"),
    };
    let ticket_l = match executed.prepare_mutation_bound(
        [0xC0; 32],
        [0xD1; 32],
        BoundGrantMutation::Approve {
            request_id: "row-l".to_owned(),
            decision_revision: rev_l,
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare row-l: {error:?}"),
    };
    drop(api_k);
    drop(executed);
    let recovered = Arc::new(
        Contract219GrantAdapter::with_recovery(
            Arc::clone(&live.intake),
            Arc::clone(&live.projector),
            journal.clone(),
            ticket_ikm,
            store_instance,
            master.clone(),
        )
        .expect("recover-last-after-reload adapter"),
    );
    recovered
        .verify_recovery_ticket_bound([0xB0; 32], [0xD1; 32], 1, &ticket_k)
        .expect("verify row-k after reload");
    recovered
        .verify_recovery_ticket_bound([0xC0; 32], [0xD1; 32], 1, &ticket_l)
        .expect("verify row-l after reload");
    match recovered.recover_mutation_bound(&ticket_l) {
        BoundMutationOutcome::Committed(_) => {}
        BoundMutationOutcome::Rejected(error) => {
            panic!("recover journal-reloaded last-sorted id: {error:?}")
        }
        BoundMutationOutcome::OutcomeUnknown(_) => {
            panic!("recover journal-reloaded last-sorted id unknown")
        }
    }
    assert_eq!(
        live.intake.decision("row-l"),
        ChannelApprovalDecision::Approved,
        "recover_mutation_bound must use ticket.mutation_id after reload, not first Prepared"
    );
    assert_eq!(
        live.intake.decision("row-k"),
        ChannelApprovalDecision::Pending,
        "first-Prepared recover after reload would have approved row-k instead of row-l"
    );
    match recovered.recover_mutation_bound(&ticket_k) {
        BoundMutationOutcome::Committed(_) => {}
        BoundMutationOutcome::Rejected(error) => {
            panic!("recover journal-reloaded first-sorted leftover: {error:?}")
        }
        BoundMutationOutcome::OutcomeUnknown(_) => {
            panic!("recover journal-reloaded first-sorted leftover unknown")
        }
    }
    assert_eq!(
        live.intake.decision("row-k"),
        ChannelApprovalDecision::Approved
    );

    park(
        &live.intake,
        "row-m",
        "caller-none",
        None,
        GrantTtl::Once,
        None,
    );
    park(
        &live.intake,
        "row-n",
        "caller-empty",
        Some(Vec::new()),
        GrantTtl::Once,
        None,
    );
    let detector_m: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let api_m = ClientApi::new(ClientApiConfig::default())
        .with_bound_grant_provider(recovered.clone())
        .with_observation_redactor(live.projector.redactor())
        .with_leak_detector(detector_m);
    api_m.sessions().insert(
        "tok".to_owned(),
        ClientSession {
            session_id: "session".to_owned(),
            principal: Principal::operator("operator"),
            platform: Platform::Web,
            scopes: Scope::operator_default(),
            csrf_token: None,
            expires_at: u64::MAX,
        },
        0,
    );
    let rev_m = listed_revision(&api_m, "row-m");
    let rev_n = listed_revision(&api_m, "row-n");
    let ticket_m = match recovered.prepare_mutation_bound(
        [0xD0; 32],
        [0xE2; 32],
        BoundGrantMutation::Approve {
            request_id: "row-m".to_owned(),
            decision_revision: rev_m,
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare row-m: {error:?}"),
    };
    let ticket_n = match recovered.prepare_mutation_bound(
        [0xE0; 32],
        [0xE2; 32],
        BoundGrantMutation::Approve {
            request_id: "row-n".to_owned(),
            decision_revision: rev_n,
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare row-n: {error:?}"),
    };
    drop(api_m);
    drop(recovered);
    let executed_first = Arc::new(
        Contract219GrantAdapter::with_recovery(
            Arc::clone(&live.intake),
            Arc::clone(&live.projector),
            journal,
            ticket_ikm,
            store_instance,
            master,
        )
        .expect("execute-first-after-reload adapter"),
    );
    executed_first
        .verify_recovery_ticket_bound([0xD0; 32], [0xE2; 32], 1, &ticket_m)
        .expect("verify row-m after reload");
    executed_first
        .verify_recovery_ticket_bound([0xE0; 32], [0xE2; 32], 1, &ticket_n)
        .expect("verify row-n after reload");
    match executed_first.execute_prepared_bound(&ticket_m) {
        BoundMutationOutcome::Committed(_) => {}
        BoundMutationOutcome::Rejected(error) => {
            panic!("execute journal-reloaded first-sorted id: {error:?}")
        }
        BoundMutationOutcome::OutcomeUnknown(_) => {
            panic!("execute journal-reloaded first-sorted id unknown")
        }
    }
    assert_eq!(
        live.intake.decision("row-m"),
        ChannelApprovalDecision::Approved,
        "execute_prepared_bound must use ticket.mutation_id after reload, not last Prepared"
    );
    assert_eq!(
        live.intake.decision("row-n"),
        ChannelApprovalDecision::Pending,
        "last-Prepared execute after reload would have approved row-n instead of row-m"
    );
    match executed_first.execute_prepared_bound(&ticket_n) {
        BoundMutationOutcome::Committed(_) => {}
        BoundMutationOutcome::Rejected(error) => {
            panic!("execute journal-reloaded last-sorted leftover: {error:?}")
        }
        BoundMutationOutcome::OutcomeUnknown(_) => {
            panic!("execute journal-reloaded last-sorted leftover unknown")
        }
    }
    assert_eq!(
        live.intake.decision("row-n"),
        ChannelApprovalDecision::Approved
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t23_new_preset_terminal_survives_compact() {
    let live = live_new().await;
    live.store
        .insert_dynamic(grant(
            "cover-keep-a",
            "grantee-comp",
            "/tmp/a/*",
            GrantProvenance::Requested,
        ))
        .expect("cover a");
    let ticket = match live.adapter.prepare_mutation_bound(
        [0xA1; 32],
        [0xA2; 32],
        BoundGrantMutation::ApplyPreset {
            preset: "restrict".to_owned(),
            target_agent_id: "grantee-comp".to_owned(),
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("prepare: {error:?}"),
    };
    match live.adapter.execute_prepared_bound(&ticket) {
        BoundMutationOutcome::Committed(_) => {}
        BoundMutationOutcome::Rejected(error) => panic!("first execute rejected: {error:?}"),
        BoundMutationOutcome::OutcomeUnknown(_) => panic!("first execute unknown"),
    }
    assert_eq!(live.intake_approves.preset_applies.load(Ordering::SeqCst), 1);
    assert_eq!(live.adapter.test_journal_row_count(), 1);
    let replay = match live.adapter.prepare_mutation_bound(
        [0xA1; 32],
        [0xA2; 32],
        BoundGrantMutation::ApplyPreset {
            preset: "restrict".to_owned(),
            target_agent_id: "grantee-comp".to_owned(),
        },
    ) {
        ProviderPrepareOutcome::Prepared(ticket) => ticket,
        ProviderPrepareOutcome::Rejected(error) => panic!("replay prepare: {error:?}"),
    };
    match live.adapter.execute_prepared_bound(&replay) {
        BoundMutationOutcome::Committed(_) => {}
        BoundMutationOutcome::Rejected(error) => panic!("replay execute rejected: {error:?}"),
        BoundMutationOutcome::OutcomeUnknown(_) => panic!("replay execute unknown"),
    }
    assert_eq!(live.intake_approves.preset_applies.load(Ordering::SeqCst), 1);
    assert_eq!(live.adapter.test_journal_row_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t17_oversized_justification_does_not_panic_list() {
    let live = live_new().await;
    park(
        &live.intake,
        "huge-just",
        "caller-none",
        None,
        GrantTtl::Once,
        Some(&"x".repeat(70_000)),
    );
    park(
        &live.intake,
        "visible-sibling",
        "caller-none",
        None,
        GrantTtl::Once,
        None,
    );
    let listed = live
        .api
        .handle(ClientRequest::get("/client/grants/pending").with_session("tok"));
    assert!(listed.is_ok(), "{:?}", listed.error);
    let ids: Vec<_> = listed.data.as_ref().unwrap()["requests"]
        .as_array()
        .expect("requests")
        .iter()
        .map(|row| row["request_id"].as_str().unwrap().to_owned())
        .collect();
    assert!(ids.contains(&"visible-sibling".to_owned()), "{ids:?}");
    assert!(!ids.contains(&"huge-just".to_owned()), "{ids:?}");
}


use std::sync::Arc;
use std::time::Duration;

use advance_cli::client_api_adapters::{Contract219GrantAdapter, Contract219HistoryAdapter};
use advance_cli::contract218_bootstrap::bootstrap_contract218;
use advance_cli::observation_carriers::ObservationCarrierStore;
use advance_cli::observation_projection::Contract219EventProjector;
use advance_client_api::{
    ClientApi, ClientApiConfig, ClientRequest, ClientSession, Platform, Principal, Scope,
};
use advance_database::{R2d2SqliteIndexHandle, SqliteIndexHandle};
use advance_event_bus::{Event, EventBus, EventBusConfig};
use advance_scheduler::registry::ComponentRegistry;
use advance_scheduler::types::ComponentSubmitConfig;
use advance_scheduler::{ComponentSubmitApi, InMemoryComponentSubmitApi};
use advance_shared_types::component::ComponentType;
use advance_shared_types::sensitive_observation::{ObservationNode, RedactionDisposition};
use advance_shared_types::traits::{EventBusEmit, LeakDetector};
use cap_grant::{
    CapParam, ChannelApprovalPort, ChannelApprovalRequest, GrantApprovalIntake, GrantSqliteIndex,
    GrantStore, GrantTtl, PresetRegistry, SubsetValidator, SubsetValidatorImpl,
};
use cap_http::DefaultLeakDetector;

const SENTINEL: &str = "legacy3-raw-secret-7f3a";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_c218_c219_carriers_drive_public_history_and_pending_projection() {
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
    projector
        .register_agent("default-agent")
        .await
        .expect("register caller identity");

    let submit = InMemoryComponentSubmitApi::new().with_observation_provider(
        Arc::clone(&runtime.provider),
        Arc::clone(&runtime.ready_issuer),
    );
    submit
        .submit_component(
            "default-agent",
            ComponentSubmitConfig {
                id: "legacy3-sensitive".to_owned(),
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
                sensitive_params: vec![
                    "api_key".to_owned(),
                    "event_type".to_owned(),
                    "id".to_owned(),
                    "run_id".to_owned(),
                ],
            },
        )
        .await
        .expect("anchored component admission");
    projector.refresh_sources().await.expect("source refresh");

    let mut config = EventBusConfig::new(
        workspace.path().join("events-jsonl"),
        workspace.path().join("events.db"),
    );
    config.websocket_addr = "127.0.0.1:0".parse().unwrap();
    config.observation_projector =
        Some(Arc::clone(&projector) as Arc<dyn advance_event_bus::ObservationProjector>);
    let bus = Arc::new(EventBus::new(config).await.expect("EventBus"));
    let read = bus.read_api().expect("production read API");

    let mut event = Event::observability(
        "run.completed",
        "legacy3-sensitive",
        serde_json::json!({
            "result": {
                "named_params": {
                    "api_key": SENTINEL,
                    "event_type": SENTINEL,
                    "id": SENTINEL,
                    "run_id": SENTINEL
                },
                "nested": [{ "named_params": { "api_key": SENTINEL } }],
                "cap_params": [
                    { "key": "id", "value": SENTINEL },
                    { "key": "api_key", "value": SENTINEL }
                ]
            }
        }),
        None,
    );
    event.task_id = Some("task-a".to_owned());
    event.run_id = Some("run-a".to_owned());
    let event_id = event.id.clone();
    bus.emit(event);

    for _ in 0..100 {
        if carriers.get(&event_id).expect("carrier read").is_some()
            && !read
                .query(&Default::default(), 1)
                .await
                .expect("history query")
                .is_empty()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let carrier = carriers
        .get(&event_id)
        .expect("carrier read")
        .expect("projected event carrier");

    let bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    let sqlite: Arc<dyn SqliteIndexHandle> =
        Arc::new(R2d2SqliteIndexHandle::new_in_memory().expect("grant sqlite"));
    let grant_index = GrantSqliteIndex::new(sqlite);
    grant_index.ensure_schema().expect("grant schema");
    let grant_store = Arc::new(GrantStore::new(grant_index, Arc::clone(&bus_dyn)));
    let validator: Arc<dyn SubsetValidator> = Arc::new(SubsetValidatorImpl::new());
    let intake = Arc::new(GrantApprovalIntake::new(
        grant_store,
        validator,
        Arc::new(PresetRegistry::with_builtins()),
        Arc::clone(&bus_dyn),
    ));
    intake
        .request_approval(ChannelApprovalRequest {
            request_id: "request-a".to_owned(),
            caller: "legacy3-sensitive".to_owned(),
            capability: "http".to_owned(),
            params: Some(vec![CapParam {
                key: "api_key".to_owned(),
                value: SENTINEL.to_owned(),
            }]),
            ttl: GrantTtl::Once,
            justification: Some("operator review".to_owned()),
        })
        .expect("park real pending approval");

    let history: Arc<dyn advance_client_api::BoundHistoryReadPort> = Arc::new(
        Contract219HistoryAdapter::new(read, Arc::clone(&projector), Arc::clone(&carriers))
            .expect("history adapter"),
    );
    let grants: Arc<dyn advance_client_api::BoundGrantApprovalPort> = Arc::new(
        Contract219GrantAdapter::new(Arc::clone(&intake), Arc::clone(&projector)),
    );
    let detector: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    let api = ClientApi::new(ClientApiConfig::default())
        .with_bound_history_provider(history)
        .with_bound_grant_provider(grants)
        .with_observation_redactor(projector.redactor())
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

    let history =
        api.handle(ClientRequest::get("/client/tasks/task-a/history").with_session("tok"));
    assert!(
        history.is_ok(),
        "history projection failed: {:?}",
        history.error
    );
    let history_json = serde_json::to_string(&history).unwrap();
    assert!(history_json.contains("[REDACTED]"));
    assert!(history_json.contains(&event_id));
    assert!(!history_json.contains(SENTINEL));

    let pending = api.handle(ClientRequest::get("/client/grants/pending").with_session("tok"));
    assert!(
        pending.is_ok(),
        "pending projection failed: {:?}",
        pending.error
    );
    let pending_json = serde_json::to_string(&pending).unwrap();
    assert!(pending_json.contains("[REDACTED]"));
    assert!(pending_json.contains("request-a"));
    assert!(!pending_json.contains(SENTINEL));

    let mut tampered = carrier;
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let bound = projector
        .bind_persisted_history(
            &tampered,
            ObservationNode::Object(Vec::new()),
            ObservationNode::Object(vec![
                ("event_id".to_owned(), ObservationNode::String(event_id)),
                (
                    "occurred_at".to_owned(),
                    ObservationNode::String("2026-07-14T00:00:00Z".to_owned()),
                ),
                (
                    "kind".to_owned(),
                    ObservationNode::String("run.completed".to_owned()),
                ),
                (
                    "summary".to_owned(),
                    ObservationNode::String("tampered carrier".to_owned()),
                ),
                (
                    "params".to_owned(),
                    ObservationNode::CanonicalCapParams(vec![
                        CanonicalParam::new("api_key"),
                        CanonicalParam::new("event_type"),
                        CanonicalParam::new("id"),
                        CanonicalParam::new("run_id"),
                    ]),
                ),
            ]),
        )
        .expect("tampered carrier remains structurally decodable");
    assert!(matches!(
        projector.redactor().redact_bound_observation(bound),
        RedactionDisposition::Blocked { .. }
    ));

    drop(api);
    drop(intake);
    drop(bus_dyn);
    match Arc::try_unwrap(bus) {
        Ok(bus) => bus.shutdown().await,
        Err(_) => panic!("all EventBus owners must be released"),
    }
}

struct CanonicalParam;

impl CanonicalParam {
    fn new(key: &str) -> advance_shared_types::sensitive_observation::CanonicalCapParam {
        advance_shared_types::sensitive_observation::CanonicalCapParam {
            key: key.to_owned(),
            value: ObservationNode::String("[REDACTED]".to_owned()),
        }
    }
}

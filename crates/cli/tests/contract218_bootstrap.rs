use std::sync::Arc;
use std::time::Duration;

use advance_cli::contract218_bootstrap::bootstrap_contract218;
use advance_cli::observation_carriers::ObservationCarrierStore;
use advance_cli::observation_projection::Contract219EventProjector;
use advance_event_bus::{
    Event, EventBus, EventBusConfig, ObservationProjection, ObservationProjector,
};
use advance_scheduler::registry::ComponentRegistry;
use advance_scheduler::types::ComponentSubmitConfig;
use advance_scheduler::{ComponentSubmitApi, InMemoryComponentSubmitApi};
use advance_shared_types::component::ComponentType;
use advance_shared_types::observation_identity::HostEmitterId;
use advance_shared_types::traits::EventBusEmit;
use futures::StreamExt;
use tokio_tungstenite::tungstenite::Message;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_bootstrap_opens_fresh_and_restarts_from_anchored_custody() {
    let workspace = tempfile::tempdir().expect("workspace");
    let registry = Arc::new(
        ComponentRegistry::open_in(workspace.path(), "components.db")
            .await
            .expect("registry"),
    );

    let first = bootstrap_contract218(workspace.path(), Arc::clone(&registry))
        .await
        .expect("fresh bootstrap");
    first
        .provider
        .issue_completed_hydration_receipt()
        .await
        .expect("fresh provider is hydrated");
    let first_boot = first.boot_id;
    drop(first);
    drop(registry);

    let reopened_registry = Arc::new(
        ComponentRegistry::open_in(workspace.path(), "components.db")
            .await
            .expect("reopened registry"),
    );
    let reopened = bootstrap_contract218(workspace.path(), reopened_registry)
        .await
        .expect("restart bootstrap");
    reopened
        .provider
        .issue_completed_hydration_receipt()
        .await
        .expect("restarted provider is hydrated");
    assert_ne!(reopened.boot_id, first_boot, "each boot must mint a new id");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anchored_component_source_drives_sealed_structural_projection() {
    let workspace = tempfile::tempdir().expect("workspace");
    let registry = Arc::new(
        ComponentRegistry::open_in(workspace.path(), "components.db")
            .await
            .expect("registry"),
    );
    let runtime = bootstrap_contract218(workspace.path(), registry)
        .await
        .expect("bootstrap");
    let projector = Contract219EventProjector::build(
        Arc::clone(&runtime.provider),
        Arc::clone(&runtime.ready_issuer),
        runtime.boot_id,
        Arc::new(ObservationCarrierStore::open(workspace.path()).expect("carrier store")),
    )
    .await
    .expect("projector");
    let api = InMemoryComponentSubmitApi::new().with_observation_provider(
        Arc::clone(&runtime.provider),
        Arc::clone(&runtime.ready_issuer),
    );
    api.submit_component(
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
                "id".to_owned(),
                "event_type".to_owned(),
                "run_id".to_owned(),
            ],
        },
    )
    .await
    .expect("anchored component admission");
    projector.refresh_sources().await.expect("source refresh");

    let event = Event::observability(
        "run.completed",
        "legacy3-sensitive",
        serde_json::json!({
            "result": {
                "named_params": {
                    "api_key": "legacy3-raw-secret-7f3a",
                    "id": "legacy3-raw-secret-7f3a",
                    "event_type": "legacy3-raw-secret-7f3a",
                    "run_id": "legacy3-raw-secret-7f3a"
                },
                "nested": [{"named_params": {"api_key": "legacy3-raw-secret-7f3a"}}],
                "cap_params": [
                    {"key": "api_key", "value": "legacy3-raw-secret-7f3a"},
                    {"key": "id", "value": "legacy3-raw-secret-7f3a"}
                ]
            }
        }),
        None,
    );
    let original_id = event.id.clone();
    let projected = match projector.project(&event) {
        ObservationProjection::Redacted(projected) => projected,
        _ => panic!("sensitive event must produce a redacted projection"),
    };
    let rendered = serde_json::to_string(&projected).expect("projected JSON");
    assert!(!rendered.contains("legacy3-raw-secret-7f3a"));
    assert_eq!(projected.id, original_id, "structural envelope id survives");
    assert_eq!(projected.event_type, "run.completed");
    assert_eq!(
        projected.payload["result"]["named_params"]["api_key"],
        "[REDACTED]"
    );
    assert_eq!(
        projected.payload["result"]["nested"][0]["named_params"]["api_key"],
        "[REDACTED]"
    );
    assert_eq!(
        projected.payload["result"]["cap_params"][0]["value"],
        "[REDACTED]"
    );

    let unknown = Event::observability("run.completed", "unknown", serde_json::json!({}), None);
    assert!(matches!(
        projector.project(&unknown),
        ObservationProjection::Blocked
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restarted_known_empty_agent_and_all_hosts_reach_every_eventbus_sink() {
    let workspace = tempfile::tempdir().expect("workspace");
    let trigger_root = workspace.path().join(".triggers");
    std::fs::create_dir_all(&trigger_root).unwrap();

    let first_registry = Arc::new(
        ComponentRegistry::open_in(&trigger_root, "components.db")
            .await
            .expect("first registry"),
    );
    let first = bootstrap_contract218(workspace.path(), Arc::clone(&first_registry))
        .await
        .expect("first boot");
    let first_boot = first.boot_id;
    drop(first);
    drop(first_registry);

    let restarted_registry = Arc::new(
        ComponentRegistry::open_in(&trigger_root, "components.db")
            .await
            .expect("restarted registry"),
    );
    let restarted = bootstrap_contract218(workspace.path(), restarted_registry)
        .await
        .expect("restarted boot");
    assert_ne!(restarted.boot_id, first_boot);

    let carriers = Arc::new(
        ObservationCarrierStore::open(workspace.path()).expect("observation carrier store"),
    );
    let projector = Contract219EventProjector::build(
        Arc::clone(&restarted.provider),
        Arc::clone(&restarted.ready_issuer),
        restarted.boot_id,
        Arc::clone(&carriers),
    )
    .await
    .expect("restarted projector");
    projector
        .register_agent("ordinary-agent")
        .await
        .expect("ordinary known-empty agent");

    let jsonl_dir = workspace.path().join("events-jsonl");
    let database_path = workspace.path().join("events.db");
    let mut config = EventBusConfig::new(jsonl_dir.clone(), database_path.clone());
    config.websocket_addr = "127.0.0.1:0".parse().unwrap();
    config.observation_projector = Some(Arc::clone(&projector) as Arc<dyn ObservationProjector>);
    let bus = EventBus::new(config).await.expect("EventBus");
    let address = bus.server_addr().expect("EventBus address");
    let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{address}/events"))
        .await
        .expect("EventBus WebSocket");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let sources = [
        "ordinary-agent",
        HostEmitterId::Runtime.canonical_id(),
        HostEmitterId::RetentionSweeper.canonical_id(),
        HostEmitterId::PackManager.canonical_id(),
    ];
    let event_ids: Vec<String> = sources
        .iter()
        .enumerate()
        .map(|(index, source)| {
            let id = format!("known-empty-restart-{index}");
            let mut event = Event::observability(
                "runtime.identity_probe",
                (*source).to_owned(),
                serde_json::json!({"source": source, "known_empty": true}),
                None,
            );
            event.id = id.clone();
            bus.emit(event);
            id
        })
        .collect();

    let websocket = tokio::time::timeout(Duration::from_secs(3), async {
        let mut rendered = String::new();
        while !event_ids.iter().all(|id| rendered.contains(id)) {
            match socket.next().await {
                Some(Ok(Message::Text(text))) => rendered.push_str(&text),
                Some(Ok(_)) => {}
                Some(Err(error)) => panic!("EventBus WebSocket error: {error}"),
                None => panic!("EventBus WebSocket closed"),
            }
        }
        rendered
    })
    .await
    .expect("all known-empty WebSocket frames");

    let mut persisted = false;
    for _ in 0..100 {
        let connection = rusqlite::Connection::open(&database_path).unwrap();
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM events WHERE id LIKE 'known-empty-restart-%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        if count == event_ids.len() as i64 {
            persisted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(persisted, "all known-empty events must reach SQLite");

    let mut jsonl = String::new();
    for _ in 0..100 {
        jsonl = std::fs::read_dir(&jsonl_dir)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
            .collect();
        if event_ids.iter().all(|id| jsonl.contains(id)) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    for id in &event_ids {
        assert!(websocket.contains(id), "WebSocket omitted {id}");
        assert!(jsonl.contains(id), "JSONL omitted {id}");
        assert!(
            carriers.get(id).unwrap().is_some(),
            "C218 carrier omitted {id}"
        );
    }

    // Unknown and forged reserved identities are blocked before every sink.
    for (id, source) in [
        ("blocked-unknown", "unknown-observer"),
        ("blocked-forged-host", "__sys:forged"),
    ] {
        let mut event = Event::observability(
            "runtime.identity_probe",
            source.to_owned(),
            serde_json::json!({"must": "not project"}),
            None,
        );
        event.id = id.to_owned();
        bus.emit(event);
    }
    tokio::time::sleep(Duration::from_millis(150)).await;
    let connection = rusqlite::Connection::open(&database_path).unwrap();
    let blocked: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM events WHERE id LIKE 'blocked-%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(blocked, 0);
    assert!(carriers.get("blocked-unknown").unwrap().is_none());
    assert!(carriers.get("blocked-forged-host").unwrap().is_none());

    bus.shutdown().await;
}

//! SYS-J-66 first-party Client API axis (default-off).

use std::path::Path;
use std::sync::Arc;

use advance_cli::client_api_adapters::{
    compose_first_party_client, Contract185EventAdapter, Contract219GrantAdapter,
    Contract219HistoryAdapter, FirstPartyClientCompose, InventoryToolsProvider,
    RunManagerRunControl,
};
use advance_cli::contract218_bootstrap::bootstrap_contract218;
use advance_cli::observation_carriers::ObservationCarrierStore;
use advance_cli::observation_projection::Contract219EventProjector;
use advance_cli::reply::ReplyRegistry;
use advance_cli::wiring::build_grant_approval_intake;
use advance_client_api::{
    AeadClientCursorCodec, ClientApi, ClientApiConfig, ClientApiServer, ClientCursorCodec,
    MemoryCursorKeyCustody, OsCursorEntropy, SystemCursorClock,
};
use advance_event_bus::{EventBus, EventBusConfig, ObservabilityReadApi};
use advance_messaging::{MailboxStore, OutboundActionSink};
use advance_run_manager::{RunConfig, RunManager};
use advance_scheduler::registry::ComponentRegistry;
use advance_shared_types::mailbox::{DispatchError, Message};
use advance_shared_types::outbound::DeliveryReport;
use advance_shared_types::security_validator::LeakDetector;
use advance_shared_types::traits::{AgentTreeSnapshot, CallableInventoryReader, EventBusEmit};
use cap_grant::{GrantStore, PresetRegistry, SubsetValidator, SubsetValidatorImpl};
use cap_http::DefaultLeakDetector;
use cap_tools::{tool_entries_from_infos, CallableInventory, ToolRegistry};

use crate::CapturingOutboundSink;

pub(crate) const ECHO_TOOL_ID: &str = "echo_tool";
pub(crate) const ECHO_TOOL_WASM: &[u8] =
    include_bytes!("../../capabilities/cap-tools/tests/fixtures/echo_tool.component.wasm");

pub(crate) struct FirstPartyAxis {
    pub bus: Arc<EventBus>,
    pub read_api: Arc<dyn ObservabilityReadApi>,
    pub projector: Arc<Contract219EventProjector>,
    pub carriers: Arc<ObservationCarrierStore>,
    pub leak_detector: Arc<dyn LeakDetector>,
    pub run_manager: Arc<RunManager>,
    pub reply_registry: Arc<ReplyRegistry>,
}

pub(crate) async fn boot_first_party_axis(
    workspace: &Path,
    agent_id: &str,
) -> Result<FirstPartyAxis, String> {
    let trig_root = workspace.join(".triggers");
    std::fs::create_dir_all(&trig_root).map_err(|e| format!("create .triggers: {e}"))?;
    let registry = Arc::new(
        ComponentRegistry::open_in(&trig_root, "components.db")
            .await
            .map_err(|e| format!("open ComponentRegistry: {e}"))?,
    );
    let runtime = bootstrap_contract218(workspace, registry).await?;
    let carriers = Arc::new(ObservationCarrierStore::open(workspace)?);
    let projector = Contract219EventProjector::build(
        Arc::clone(&runtime.provider),
        Arc::clone(&runtime.ready_issuer),
        runtime.boot_id,
        Arc::clone(&carriers),
    )
    .await?;
    projector.register_agent(agent_id).await?;

    let jsonl_dir = workspace.join(".runtime/events/jsonl");
    let db_path = workspace.join(".runtime/events.db");
    std::fs::create_dir_all(&jsonl_dir).map_err(|e| format!("create events jsonl: {e}"))?;
    let mut cfg = EventBusConfig::new(jsonl_dir, db_path);
    cfg.websocket_addr = "127.0.0.1:0".parse().expect("literal");
    let leak_detector: Arc<dyn LeakDetector> = Arc::new(DefaultLeakDetector::new());
    cfg.leak_detector = Some(Arc::clone(&leak_detector));
    cfg.observation_projector = Some(Arc::clone(&projector) as _);

    let bus = EventBus::new(cfg)
        .await
        .map_err(|e| format!("EventBus::new: {e}"))?;
    let bus = Arc::new(bus);
    let read_api = bus
        .read_api()
        .ok_or_else(|| "async EventBus produced no read_api".to_owned())?;
    let event_bus_dyn: Arc<dyn EventBusEmit> = bus.clone();
    let run_manager = RunManager::new_arc(event_bus_dyn);

    Ok(FirstPartyAxis {
        bus,
        read_api,
        projector,
        carriers,
        leak_detector,
        run_manager,
        reply_registry: Arc::new(ReplyRegistry::new()),
    })
}

pub(crate) async fn seed_echo_tool(registry: &cap_tools::LazyToolRegistry) {
    registry
        .register_binary(ECHO_TOOL_ID, ECHO_TOOL_WASM.to_vec())
        .await;
}

pub(crate) async fn unfiltered_inventory(
    registry: &cap_tools::LazyToolRegistry,
) -> Arc<dyn CallableInventoryReader> {
    let listed = ToolRegistry::list(registry).await;
    Arc::new(CallableInventory::new(
        tool_entries_from_infos(listed),
        vec![],
    ))
}

pub(crate) struct FulfillingCaptureSink {
    pub capture: CapturingOutboundSink,
    pub replies: Arc<ReplyRegistry>,
}

#[async_trait::async_trait]
impl OutboundActionSink for FulfillingCaptureSink {
    async fn deliver(
        &self,
        agent_id: &str,
        source: &Message,
        actions: &[advance_messaging::AgentAction],
    ) -> Result<DeliveryReport, DispatchError> {
        let report = self.capture.deliver(agent_id, source, actions).await?;
        let reply = actions.first().map(|a| a.payload.clone());
        self.replies.fulfill(agent_id, reply);
        Ok(report)
    }
}

pub(crate) async fn bind_first_party_client(
    axis: &FirstPartyAxis,
    store: Arc<MailboxStore>,
    tree: Arc<dyn AgentTreeSnapshot>,
    grant_store: Arc<GrantStore>,
    tools: Arc<dyn CallableInventoryReader>,
    agent_id: &str,
) -> Result<ClientApiServer, String> {
    let history = Contract219HistoryAdapter::new(
        Arc::clone(&axis.read_api),
        Arc::clone(&axis.projector),
        Arc::clone(&axis.carriers),
    )?;
    let events = Contract185EventAdapter::new(Arc::clone(&axis.read_api), 30)?;
    let cursor: Arc<dyn ClientCursorCodec> = Arc::new(AeadClientCursorCodec::new(
        Arc::new(MemoryCursorKeyCustody::new_local()),
        Arc::new(SystemCursorClock),
        Arc::new(OsCursorEntropy),
        30,
    ));
    let validator: Arc<dyn SubsetValidator> = Arc::new(SubsetValidatorImpl::new());
    let intake = build_grant_approval_intake(
        grant_store,
        validator,
        Arc::new(PresetRegistry::with_builtins()),
        axis.bus.clone() as Arc<dyn EventBusEmit>,
    );
    let grants = Arc::new(Contract219GrantAdapter::new(
        intake,
        Arc::clone(&axis.projector),
    ));
    let redactor = axis.projector.redactor();
    let mut parts = FirstPartyClientCompose::default();
    parts.run = Some(Arc::new(RunManagerRunControl::new(
        Arc::clone(&axis.run_manager),
        Some(tree),
    )));
    parts.mailbox = Some(store);
    parts.replies = Some(Arc::clone(&axis.reply_registry));
    parts.history = Some(Arc::new(history));
    parts.events = Some(Arc::new(events));
    parts.cursor = Some(cursor);
    parts.redactor = Some(redactor);
    parts.leak_detector = Some(Arc::clone(&axis.leak_detector));
    parts.grants = Some(grants);
    parts.tools = Some(Arc::new(InventoryToolsProvider::new(
        tools,
        agent_id.to_owned(),
        None,
    )));

    ClientApiServer::bind_local_factory(0, move |address| {
        let mut config = ClientApiConfig::default();
        config.allowed_origins = vec![format!("http://{address}")];
        let api = compose_first_party_client(ClientApi::new(config), parts);
        Arc::new(api)
    })
    .await
    .map_err(|e| format!("bind Client API: {e}"))
}

pub(crate) fn run_config() -> RunConfig {
    RunConfig::default()
}

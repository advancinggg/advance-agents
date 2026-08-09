//! CONTRACT-217 → CONTRACT-130 production adapter.
//!
//! The M005 crate owns the WIT boundary and deliberately has no scheduler
//! dependency. This composition-root adapter performs the one full v0.2 decode,
//! applies runnable admission, delegates every scheduler decision to M014, and
//! publishes the committed sensitive-name declaration to the EventBus source.

use std::sync::Arc;

use advance_scheduler::types::{
    ComponentInfo as SchedulerComponentInfo, ComponentState as SchedulerComponentState,
    ComponentSubmitConfig as SchedulerComponentSubmitConfig, SpawnError as SchedulerSpawnError,
};
use advance_scheduler::{ComponentSubmitApi, InMemoryComponentSubmitApi, SubmitSubsetGate};
use advance_shared_types::agent_tree::Capability;
use advance_shared_types::capability::{CapParams, CapabilityId};
use cap_grant::{validate_capability_subset, CapGrantError, Grant, GrantStatus, GrantStore};
use cap_lifecycle::{
    admit_runnable_binary, ComponentId, ComponentInfo, ComponentState, ComponentSubmitConfig,
    ComponentSubmitConfigV2, ComponentSubmitGate, SpawnError,
};

use crate::observation_projection::Contract219EventProjector;
use crate::sensitive_params::RegistrySensitiveParamsSource;

pub struct SchedulerSubmitBridge {
    api: Arc<InMemoryComponentSubmitApi>,
    sensitive_params: Arc<RegistrySensitiveParamsSource>,
    contract219: Option<Arc<Contract219EventProjector>>,
}

impl SchedulerSubmitBridge {
    pub fn new(
        api: Arc<InMemoryComponentSubmitApi>,
        sensitive_params: Arc<RegistrySensitiveParamsSource>,
    ) -> Self {
        Self {
            api,
            sensitive_params,
            contract219: None,
        }
    }

    pub fn with_contract219(mut self, projector: Arc<Contract219EventProjector>) -> Self {
        self.contract219 = Some(projector);
        self
    }

    async fn refresh_contract219(&self) -> Result<(), SpawnError> {
        match self.contract219.as_ref() {
            Some(projector) => projector.refresh_sources().await.map_err(|error| {
                SpawnError::InvalidConfig(format!(
                    "component committed but CONTRACT-219 source refresh failed: {error}"
                ))
            }),
            None => Ok(()),
        }
    }

    fn decode_v2(
        config: ComponentSubmitConfigV2,
    ) -> Result<SchedulerComponentSubmitConfig, SpawnError> {
        let mut canonical = config.into_canonical_json();
        let capabilities = canonical
            .get_mut("capabilities")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or_else(|| SpawnError::InvalidConfig("capabilities must be a list".to_owned()))?;
        for capability in capabilities {
            let object = capability.as_object_mut().ok_or_else(|| {
                SpawnError::InvalidConfig("capability request must be a record".to_owned())
            })?;
            if object.len() != 2
                || !object.contains_key("capability")
                || !object.contains_key("params")
            {
                return Err(SpawnError::InvalidConfig(
                    "capability request has an invalid field set".to_owned(),
                ));
            }
            // CONTRACT-130's current CapRequest carrier has no parameter field.
            // Reject rather than silently losing authority constraints. Empty
            // whole-capability requests remain fully representable.
            if object.get("params").is_some_and(|value| !value.is_null()) {
                return Err(SpawnError::InvalidConfig(
                    "parameterized component capabilities are not representable by CONTRACT-130"
                        .to_owned(),
                ));
            }
            object.remove("params");
        }
        serde_json::from_value(canonical).map_err(|error| {
            SpawnError::InvalidConfig(format!("invalid CONTRACT-217 config: {error}"))
        })
    }

    fn map_error(error: SchedulerSpawnError) -> SpawnError {
        match error {
            SchedulerSpawnError::SubsetViolation(message) => SpawnError::SubsetViolation(message),
            SchedulerSpawnError::AlreadyExists(message) => SpawnError::AlreadyExists(message),
            SchedulerSpawnError::InvalidConfig(message) => SpawnError::InvalidConfig(message),
            SchedulerSpawnError::CapabilityDenied(message) => {
                SpawnError::InvalidConfig(format!("capability denied: {message}"))
            }
            SchedulerSpawnError::ResourceLimit(message) => {
                SpawnError::InvalidConfig(format!("resource limit: {message}"))
            }
        }
    }

    fn map_state(state: SchedulerComponentState) -> ComponentState {
        match state {
            SchedulerComponentState::Pending => ComponentState::Pending,
            SchedulerComponentState::Running => ComponentState::Running,
            SchedulerComponentState::Completed => ComponentState::Completed,
            SchedulerComponentState::Failed(message) => ComponentState::Failed(message),
            SchedulerComponentState::Killed => ComponentState::Killed,
        }
    }

    fn map_info(info: SchedulerComponentInfo) -> ComponentInfo {
        ComponentInfo {
            id: ComponentId(info.id.0),
            component_type: info.component_type.as_str().to_owned(),
            status: Self::map_state(info.status),
            created_at: info.created_at,
        }
    }
}

#[async_trait::async_trait]
impl ComponentSubmitGate for SchedulerSubmitBridge {
    async fn submit_component_v2(
        &self,
        submitter: &str,
        config: ComponentSubmitConfigV2,
    ) -> Result<ComponentId, SpawnError> {
        let config = Self::decode_v2(config)?;
        admit_runnable_binary(&config.binary)?;
        let id = config.id.clone();
        let sensitive_params = config.sensitive_params.clone();
        let result = self
            .api
            .submit_component(submitter, config)
            .await
            .map_err(Self::map_error)?;
        self.sensitive_params
            .publish_component(id, sensitive_params);
        self.refresh_contract219().await?;
        Ok(ComponentId(result.0))
    }

    async fn submit_component(
        &self,
        submitter: &str,
        config: ComponentSubmitConfig,
    ) -> Result<ComponentId, SpawnError> {
        admit_runnable_binary(&config.binary)?;
        let component_type = match config.component_type.as_str() {
            "agent" => advance_shared_types::component::ComponentType::Agent,
            "cron" => advance_shared_types::component::ComponentType::Cron,
            "watcher" => advance_shared_types::component::ComponentType::Watcher,
            "daemon" => advance_shared_types::component::ComponentType::Daemon,
            "task" => advance_shared_types::component::ComponentType::Task,
            other => {
                return Err(SpawnError::InvalidConfig(format!(
                    "unknown component-type: {other}"
                )))
            }
        };
        let scheduler = SchedulerComponentSubmitConfig {
            id: config.id,
            component_type,
            binary: config.binary,
            capabilities: config
                .capabilities
                .into_iter()
                .map(|capability| advance_shared_types::capability::CapRequest {
                    capability: CapabilityId::from(capability),
                })
                .collect(),
            output_dir: config.output_dir,
            trigger: None,
            restart_policy: None,
            delay: None,
            initial_grants: None,
            preset: None,
            retry: None,
            sensitive_params: Vec::new(),
        };
        let result = self
            .api
            .submit_component(submitter, scheduler)
            .await
            .map_err(Self::map_error)?;
        self.refresh_contract219().await?;
        Ok(ComponentId(result.0))
    }

    async fn kill_component(&self, id: &str) -> Result<(), SpawnError> {
        self.api.kill_component(id).await.map_err(Self::map_error)
    }

    async fn component_status(&self, id: &str) -> Result<ComponentState, SpawnError> {
        self.api
            .component_status(id)
            .await
            .map(Self::map_state)
            .map_err(Self::map_error)
    }

    async fn list_components(&self) -> Vec<ComponentInfo> {
        self.api
            .list_components()
            .await
            .into_iter()
            .map(Self::map_info)
            .collect()
    }
}

/// Real submitter-grant subset adapter required by M014 admission rule 5.
pub struct CapGrantSubmitSubsetGate {
    grants: Arc<GrantStore>,
}

impl CapGrantSubmitSubsetGate {
    pub fn new(grants: Arc<GrantStore>) -> Self {
        Self { grants }
    }
}

impl SubmitSubsetGate for CapGrantSubmitSubsetGate {
    fn check(&self, submitter: &str, requested: &[Capability]) -> Result<(), SchedulerSpawnError> {
        let bare = submitter.strip_prefix("agent:").unwrap_or(submitter);
        let mut grants = self.grants.list_by_grantee(submitter);
        if bare != submitter {
            grants.extend(self.grants.list_by_grantee(bare));
        }
        let parent: Vec<Capability> = grants
            .iter()
            .filter(|grant| grant.status == GrantStatus::Active)
            .map(grant_to_capability)
            .collect();
        match validate_capability_subset(&parent, requested) {
            Ok(()) => Ok(()),
            Err(CapGrantError::SubsetViolation(message)) => {
                Err(SchedulerSpawnError::SubsetViolation(message))
            }
            Err(error) => Err(SchedulerSpawnError::SubsetViolation(format!(
                "cap-grant projection error: {error}"
            ))),
        }
    }
}

fn grant_to_capability(grant: &Grant) -> Capability {
    let mut params = serde_json::Map::new();
    for param in &grant.params {
        let tokens: Vec<&str> = param
            .value
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .collect();
        let value = if tokens.len() > 1 {
            serde_json::Value::Array(
                tokens
                    .into_iter()
                    .map(|token| serde_json::Value::String(token.to_owned()))
                    .collect(),
            )
        } else {
            serde_json::Value::String(tokens.first().copied().unwrap_or("").to_owned())
        };
        params.insert(param.key.clone(), value);
    }
    Capability {
        id: CapabilityId::from(grant.capability.as_str()),
        params: if params.is_empty() {
            CapParams::empty()
        } else {
            CapParams::new(serde_json::Value::Object(params))
        },
    }
}

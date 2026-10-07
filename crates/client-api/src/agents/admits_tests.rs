use super::*;
use crate::provider::ProviderError;

struct StubAdmin;

impl AgentAdminProvider for StubAdmin {
    fn list_agents(&self) -> Result<Vec<ClientAgentSummary>, ProviderError> {
        Err(ProviderError::Unavailable("stub".into()))
    }
    fn get_agent(&self, _agent_id: &str) -> Result<ClientAgentDetail, ProviderError> {
        Err(ProviderError::Unavailable("stub".into()))
    }
    fn create_agent(
        &self,
        _request: &ClientCreateAgentRequest,
    ) -> Result<ClientAgentDetail, ProviderError> {
        Err(ProviderError::Unavailable("stub".into()))
    }
    fn update_agent(
        &self,
        _agent_id: &str,
        _request: &ClientUpdateAgentRequest,
    ) -> Result<ClientAgentDetail, ProviderError> {
        Err(ProviderError::Unavailable("stub".into()))
    }
    fn delete_agent(
        &self,
        _agent_id: &str,
        _request: &ClientDeleteAgentRequest,
    ) -> Result<ClientAgentDeleteResult, ProviderError> {
        Err(ProviderError::Unavailable("stub".into()))
    }
    fn list_templates(&self) -> Result<Vec<ClientAgentTemplate>, ProviderError> {
        Err(ProviderError::Unavailable("stub".into()))
    }
}

#[test]
fn module_001_ac31_validators_admit_only_named_dotted_capabilities() {
    let admits = |n: &str| n == "fixture.probe";
    assert!(validate_capabilities_with(&[String::from("fixture.probe")], &admits).is_ok());
    assert_eq!(
        validate_capabilities_with(&[String::from("fixture.x")], &admits)
            .unwrap_err()
            .message,
        "invalid capability id"
    );
    assert_eq!(
        validate_capabilities(&[String::from("a.b")])
            .unwrap_err()
            .message,
        "invalid capability id"
    );
    assert_eq!(
        validate_capabilities(&[String::from("fs"), String::from("fs")])
            .unwrap_err()
            .message,
        "duplicate capability requested"
    );
    assert_eq!(
        validate_capabilities_with(
            &[String::from("fixture.probe"), String::from("fixture.probe")],
            &admits
        )
        .unwrap_err()
        .message,
        "duplicate capability requested"
    );
    let many: Vec<String> = (0..=MAX_REQUESTED_CAPABILITIES)
        .map(|i| format!("c{i}"))
        .collect();
    assert_eq!(
        validate_capabilities(&many).unwrap_err().message,
        "too many capabilities requested"
    );
    assert_eq!(
        validate_capabilities_with(&many, &admits)
            .unwrap_err()
            .message,
        "too many capabilities requested"
    );
    assert!(!StubAdmin.admits_capability_name("fixture.probe"));
    assert!(!StubAdmin.admits_capability_name("a.b"));
}

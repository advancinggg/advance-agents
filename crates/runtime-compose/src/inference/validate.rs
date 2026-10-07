//! Whether an extension may claim a boot-config inference entry.

use advance_runtime::config::{InferenceBackendClass, LlmProviderConfig};

use crate::api::{InferenceRefusal, OssBinding, ProcessPolicy};

/// Pure: may an extension claim `entry` under `processes`? Exhaustive on
/// [`InferenceBackendClass`] so a new class is a compile error here, never a
/// silent claim.
pub(crate) fn classify_claim(
    entry: Option<&LlmProviderConfig>,
    processes: ProcessPolicy,
) -> Result<(), InferenceRefusal> {
    let Some(entry) = entry else {
        return Err(InferenceRefusal::AbsentEntry);
    };
    match entry.backend_class {
        InferenceBackendClass::Local => {
            if entry.sidecar.is_none() {
                Ok(())
            } else if processes == ProcessPolicy::Forbid {
                Err(InferenceRefusal::SidecarUnderForbid)
            } else {
                Err(InferenceRefusal::BoundByOss(OssBinding::LocalSidecar))
            }
        }
        InferenceBackendClass::AgentCli => Err(InferenceRefusal::BoundByOss(OssBinding::AgentCli)),
        InferenceBackendClass::CloudHttp => {
            Err(InferenceRefusal::BoundByOss(OssBinding::CloudWireAdapter))
        }
        InferenceBackendClass::MeshRemote => Err(InferenceRefusal::MeshRemoteEntry),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use advance_runtime::config::RuntimeConfig;

    const BOOT: &str = r#"
wasm:
  max_memory_pages: 1024
  epoch_interruption_ms: 100
  fuel_enabled: false
llm-providers:
  - id: local-ok
    backend-class: local
    endpoint: ""
    api-key-secret: local-ok-key
    model-aliases: { default: m }
    cost-per-mtoken-in: 0.01
    cost-per-mtoken-out: 0.01
  - id: side
    backend-class: local
    endpoint: ""
    api-key-secret: side-key
    model-aliases: { default: m }
    cost-per-mtoken-in: 0.01
    cost-per-mtoken-out: 0.01
    sidecar: { command: /bin/true }
  - id: cli
    backend-class: agent-cli
    api-key-secret: cli-key
    model-aliases: { default: m }
    cost-per-mtoken-in: 0.01
    cost-per-mtoken-out: 0.01
    agent-cli: { vendor: claude, command: /nonexistent/claude }
  - id: cloud-a
    endpoint: "http://127.0.0.1:9/v1"
    api-key-secret: cloud-a-key
    model-aliases: { default: m }
    cost-per-mtoken-in: 0.01
    cost-per-mtoken-out: 0.01
  - id: mesh-stub
    backend-class: mesh-remote
    device-id: dev-1
    api-key-secret: mesh-stub-key
    model-aliases: { default: m }
    cost-per-mtoken-in: 0.01
    cost-per-mtoken-out: 0.01
cron:
  max_jitter_ratio: 0.1
git:
  gc_interval_hours: 24
  max_tracked_file_mb: 10
secrets:
  master-key-source: keychain
  env-var-name: SECRETS_MASTER_KEY
post-processor:
  llm-model: sonnet-light
  llm-failure-cooldown-seconds: 600
"#;

    fn boot() -> RuntimeConfig {
        serde_yml::from_str(BOOT).expect("fixture RuntimeConfig parses")
    }

    fn entry<'a>(cfg: &'a RuntimeConfig, id: &str) -> Option<&'a LlmProviderConfig> {
        cfg.llm_providers.iter().find(|p| p.id == id)
    }

    #[test]
    fn module_001_ac31_classify_claim_matrix() {
        let cfg = boot();
        for policy in [ProcessPolicy::Allow, ProcessPolicy::Forbid] {
            assert_eq!(
                classify_claim(None, policy),
                Err(InferenceRefusal::AbsentEntry)
            );
            assert_eq!(classify_claim(entry(&cfg, "local-ok"), policy), Ok(()));
            assert_eq!(
                classify_claim(entry(&cfg, "cli"), policy),
                Err(InferenceRefusal::BoundByOss(OssBinding::AgentCli))
            );
            assert_eq!(
                classify_claim(entry(&cfg, "cloud-a"), policy),
                Err(InferenceRefusal::BoundByOss(OssBinding::CloudWireAdapter))
            );
            assert_eq!(
                classify_claim(entry(&cfg, "mesh-stub"), policy),
                Err(InferenceRefusal::MeshRemoteEntry)
            );
        }
        assert_eq!(
            classify_claim(entry(&cfg, "side"), ProcessPolicy::Allow),
            Err(InferenceRefusal::BoundByOss(OssBinding::LocalSidecar))
        );
        assert_eq!(
            classify_claim(entry(&cfg, "side"), ProcessPolicy::Forbid),
            Err(InferenceRefusal::SidecarUnderForbid)
        );
    }
}

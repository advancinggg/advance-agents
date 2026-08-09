//! Workflow applier integration tests (Slice B, AC-10).
//!
//! T27-T31 + T33: WorkflowApplier behavior across 3 step types, secret-refs
//! validation, parse errors, XOR validator, FQ-ref grammar.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use advance_pack_manager::{
    McpServerId, PackError, SecretStore, SecretValue, WorkflowApplier, WorkflowContext,
    WorkflowExecutor, WorkflowTrigger,
};

#[derive(Default)]
struct MockExecutor {
    calls: Mutex<Vec<String>>, // step type strings in invocation order
}

impl MockExecutor {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl WorkflowExecutor for MockExecutor {
    fn spawn_child(
        &self,
        template_ref: &str,
        _target_path: &Path,
        _config: &BTreeMap<String, serde_yml::Value>,
    ) -> Result<(), PackError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("spawn-child:{template_ref}"));
        Ok(())
    }
    fn submit_component(
        &self,
        component_ref: &str,
        trigger: &WorkflowTrigger,
    ) -> Result<(), PackError> {
        let tag = match trigger {
            WorkflowTrigger::Schedule(s) => format!("schedule={s}"),
            WorkflowTrigger::TriggerEvent { event_type, .. } => format!("event={event_type}"),
        };
        self.calls
            .lock()
            .unwrap()
            .push(format!("submit-component:{component_ref}:{tag}"));
        Ok(())
    }
    fn register_mcp_server(
        &self,
        config_ref: &str,
        resolved_secrets: &BTreeMap<String, SecretValue>,
    ) -> Result<McpServerId, PackError> {
        let secrets_str: Vec<_> = resolved_secrets
            .iter()
            .map(|(k, v)| format!("{k}={}", v.expose_secret()))
            .collect();
        self.calls.lock().unwrap().push(format!(
            "register-mcp-server:{config_ref}:[{}]",
            secrets_str.join(",")
        ));
        Ok(McpServerId(format!("mock:{config_ref}")))
    }
}

#[derive(Default)]
struct MockSecretStore {
    entries: Mutex<BTreeMap<String, String>>,
}

impl MockSecretStore {
    fn with(entries: &[(&str, &str)]) -> Self {
        let mut m = BTreeMap::new();
        for (k, v) in entries {
            m.insert((*k).into(), (*v).into());
        }
        Self {
            entries: Mutex::new(m),
        }
    }
}

impl SecretStore for MockSecretStore {
    fn get(&self, key: &str) -> Option<SecretValue> {
        self.entries
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .map(SecretValue::new)
    }
}

fn default_ctx() -> WorkflowContext {
    // target_workspace = "/" → any absolute path is allowed under root. Tests
    // that exercise the escape check use a narrower workspace explicitly.
    WorkflowContext {
        admin_id: "admin".into(),
        target_workspace: PathBuf::from("/"),
    }
}

// ───── T27 — 3 step types in declared order ──────────────────────────

#[tokio::test]
async fn t27_workflow_runs_all_3_step_types_in_declared_order() {
    let yaml = r#"name: auto-research
description: test
steps:
  - type: spawn-child
    template: pack@1.0.0/agent-templates/researcher
    target-path: /research-assistant
  - type: submit-component
    ref: pack@1.0.0/components/daily-summary
    schedule: "0 9 * * *"
  - type: register-mcp-server
    config-ref: pack@1.0.0/mcp-servers/brave-search
    secret-refs:
      api-key: brave-api-key
"#;
    let executor = MockExecutor::default();
    let secret_store = MockSecretStore::with(&[("brave-api-key", "REAL-SECRET-VALUE")]);
    let report = WorkflowApplier::apply(yaml, &default_ctx(), &executor, &secret_store).unwrap();
    assert_eq!(
        report.steps_executed,
        vec![
            "spawn-child".to_string(),
            "submit-component".to_string(),
            "register-mcp-server".to_string()
        ]
    );
    let calls = executor.calls();
    assert_eq!(calls.len(), 3);
    assert!(calls[0].starts_with("spawn-child:"));
    assert!(calls[1].starts_with("submit-component:"));
    assert!(calls[2].starts_with("register-mcp-server:"));
    assert!(calls[2].contains("api-key=REAL-SECRET-VALUE"));
}

// ───── T28 — missing secret pre-check ────────────────────────────────

#[tokio::test]
async fn t28_missing_secret_blocks_before_executor_invocation() {
    let yaml = r#"name: wf
steps:
  - type: register-mcp-server
    config-ref: pack@1.0.0/mcp-servers/brave-search
    secret-refs:
      api-key: missing-secret-id
"#;
    let executor = MockExecutor::default();
    let secret_store = MockSecretStore::default(); // empty
    match WorkflowApplier::apply(yaml, &default_ctx(), &executor, &secret_store) {
        Err(PackError::MissingSecret { key }) => assert_eq!(key, "missing-secret-id"),
        other => panic!("expected MissingSecret, got {other:?}"),
    }
    // Executor should NOT have been invoked.
    assert!(executor.calls().is_empty());
}

// ───── T29 — unknown step type ───────────────────────────────────────

// ───── deep-flow-nesting parse-DoS guard (adversarial round 18, crate-wide) ─────

#[tokio::test]
async fn workflow_deep_flow_nesting_rejected_fast() {
    // Adversarial round 18: a pack-shipped `workflows/{name}.yaml` is untrusted; a
    // deep-flow-nested one drives serde_yml super-linear (measured 320 KB → ~83 s; ~15 min
    // at the 1 MiB cap). The crate-wide `yaml_nesting_within_bound` guard — the 5th entry
    // point — rejects it FAST, before serde_yml's O(n²) scan.
    let mut yaml = String::from("name: wf\nsteps: []\nx: ");
    yaml.push_str(&"[".repeat(5_000));
    let executor = MockExecutor::default();
    let secret_store = MockSecretStore::default();
    let start = std::time::Instant::now();
    let r = WorkflowApplier::apply(&yaml, &default_ctx(), &executor, &secret_store);
    assert!(start.elapsed().as_secs() < 2, "guard must reject fast");
    match r {
        Err(PackError::InvalidWorkflow(msg)) => assert!(
            msg.contains("nesting") || msg.contains("deep"),
            "expected nesting rejection, got: {msg}"
        ),
        other => panic!("expected InvalidWorkflow (deep nesting), got {other:?}"),
    }
}

#[tokio::test]
async fn t29_unknown_step_type_rejected() {
    let yaml = r#"name: wf
steps:
  - type: spawn-the-fluffy-bunny
    template: pack@1.0.0/agent-templates/x
    target-path: /x
"#;
    let executor = MockExecutor::default();
    let secret_store = MockSecretStore::default();
    match WorkflowApplier::apply(yaml, &default_ctx(), &executor, &secret_store) {
        Err(PackError::InvalidWorkflow(msg)) => assert!(
            msg.contains("spawn-the-fluffy-bunny") || msg.contains("yaml parse"),
            "expected unknown-type rejection, got: {msg}"
        ),
        other => panic!("expected InvalidWorkflow, got {other:?}"),
    }
}

// ───── T30 — missing required field ──────────────────────────────────

#[tokio::test]
async fn t30_missing_required_field_rejected() {
    // spawn-child without `template` field
    let yaml = r#"name: wf
steps:
  - type: spawn-child
    target-path: /x
"#;
    let executor = MockExecutor::default();
    let secret_store = MockSecretStore::default();
    match WorkflowApplier::apply(yaml, &default_ctx(), &executor, &secret_store) {
        Err(PackError::InvalidWorkflow(msg)) => assert!(
            msg.contains("template") || msg.contains("missing") || msg.contains("yaml parse"),
            "expected missing-field rejection, got: {msg}"
        ),
        other => panic!("expected InvalidWorkflow, got {other:?}"),
    }
}

// ───── T31 — submit-component XOR (schedule vs trigger-event) ────────

#[tokio::test]
async fn t31_submit_component_both_schedule_and_event_rejected() {
    let yaml = r#"name: wf
steps:
  - type: submit-component
    ref: pack@1.0.0/components/x
    schedule: "0 9 * * *"
    trigger-event:
      event-type: component.error
"#;
    let executor = MockExecutor::default();
    let secret_store = MockSecretStore::default();
    match WorkflowApplier::apply(yaml, &default_ctx(), &executor, &secret_store) {
        Err(PackError::InvalidWorkflow(msg)) => assert!(
            msg.contains("exactly one of"),
            "expected XOR rejection, got: {msg}"
        ),
        other => panic!("expected InvalidWorkflow, got {other:?}"),
    }
}

#[tokio::test]
async fn t31_submit_component_neither_schedule_nor_event_rejected() {
    let yaml = r#"name: wf
steps:
  - type: submit-component
    ref: pack@1.0.0/components/x
"#;
    let executor = MockExecutor::default();
    let secret_store = MockSecretStore::default();
    match WorkflowApplier::apply(yaml, &default_ctx(), &executor, &secret_store) {
        Err(PackError::InvalidWorkflow(msg)) => assert!(
            msg.contains("exactly one of"),
            "expected XOR rejection, got: {msg}"
        ),
        other => panic!("expected InvalidWorkflow, got {other:?}"),
    }
}

// ───── T33 — FQ ref grammar (unversioned rejected) ────────────────────

#[tokio::test]
async fn t33_unversioned_template_ref_rejected() {
    let yaml = r#"name: wf
steps:
  - type: spawn-child
    template: pack/agent-templates/researcher
    target-path: /x
"#;
    let executor = MockExecutor::default();
    let secret_store = MockSecretStore::default();
    match WorkflowApplier::apply(yaml, &default_ctx(), &executor, &secret_store) {
        Err(PackError::InvalidWorkflow(msg)) => assert!(
            msg.contains("template invalid") || msg.contains("UnversionedRef"),
            "expected UnversionedRef wrapping, got: {msg}"
        ),
        other => panic!("expected InvalidWorkflow, got {other:?}"),
    }
}

#[tokio::test]
async fn t33_unversioned_component_ref_rejected() {
    let yaml = r#"name: wf
steps:
  - type: submit-component
    ref: pack/components/x
    schedule: "0 9 * * *"
"#;
    let executor = MockExecutor::default();
    let secret_store = MockSecretStore::default();
    match WorkflowApplier::apply(yaml, &default_ctx(), &executor, &secret_store) {
        Err(PackError::InvalidWorkflow(msg)) => assert!(
            msg.contains("ref invalid") || msg.contains("UnversionedRef"),
            "expected UnversionedRef wrapping, got: {msg}"
        ),
        other => panic!("expected InvalidWorkflow, got {other:?}"),
    }
}

#[tokio::test]
async fn t33_unversioned_mcp_config_ref_rejected() {
    let yaml = r#"name: wf
steps:
  - type: register-mcp-server
    config-ref: pack/mcp-servers/x
    secret-refs: {}
"#;
    let executor = MockExecutor::default();
    let secret_store = MockSecretStore::default();
    match WorkflowApplier::apply(yaml, &default_ctx(), &executor, &secret_store) {
        Err(PackError::InvalidWorkflow(msg)) => assert!(
            msg.contains("config-ref invalid") || msg.contains("UnversionedRef"),
            "expected UnversionedRef wrapping, got: {msg}"
        ),
        other => panic!("expected InvalidWorkflow, got {other:?}"),
    }
}

// ───── adversarial: billion-laughs alias ref rejection ───────────────

#[tokio::test]
async fn workflow_rejects_yaml_alias_refs() {
    let yaml = r#"name: wf
a: &a [1, 1, 1]
steps:
  - type: spawn-child
    template: pack@1.0.0/agent-templates/x
    target-path: *a
"#;
    let executor = MockExecutor::default();
    let secret_store = MockSecretStore::default();
    match WorkflowApplier::apply(yaml, &default_ctx(), &executor, &secret_store) {
        Err(PackError::InvalidWorkflow(msg)) => assert!(
            msg.contains("alias") || msg.contains("billion-laughs"),
            "expected alias-ref rejection, got: {msg}"
        ),
        other => panic!("expected InvalidWorkflow, got {other:?}"),
    }
}

// ───── adversarial: target-path traversal rejected ────────────────────

#[tokio::test]
async fn workflow_rejects_target_path_traversal() {
    let yaml = r#"name: wf
steps:
  - type: spawn-child
    template: pack@1.0.0/agent-templates/x
    target-path: "../../etc/passwd"
"#;
    let executor = MockExecutor::default();
    let secret_store = MockSecretStore::default();
    match WorkflowApplier::apply(yaml, &default_ctx(), &executor, &secret_store) {
        Err(PackError::InvalidWorkflow(msg)) => assert!(
            msg.contains("traversal") || msg.contains(".."),
            "expected traversal rejection, got: {msg}"
        ),
        other => panic!("expected InvalidWorkflow, got {other:?}"),
    }
}

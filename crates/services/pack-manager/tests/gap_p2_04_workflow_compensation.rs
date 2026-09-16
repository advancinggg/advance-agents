#![cfg(feature = "gap-p2")]
//! GAP-04 (P2) — workflow compensation on partial failure.
//! See docs/plans/PACK-GAP-CLOSURE.md §3.5. When step i fails, every earlier
//! successful spawn-child / submit-component is compensated in reverse order and the
//! applier returns `PackError::WorkflowStepFailed { step, source, compensated,
//! compensation_failures }`.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use advance_pack_manager::{
    McpServerId, PackError, SecretStore, SecretValue, WorkflowApplier, WorkflowContext,
    WorkflowExecutor, WorkflowTrigger,
};

struct NoSecrets;
impl SecretStore for NoSecrets {
    fn get(&self, _key: &str) -> Option<SecretValue> {
        None
    }
}

/// Records every call; `submit_component` always fails; `terminate_child` fails when
/// `fail_terminate` is set (to exercise `compensation_failures`).
struct FailingSubmit {
    calls: Mutex<Vec<String>>,
    fail_terminate: bool,
}

impl WorkflowExecutor for FailingSubmit {
    fn spawn_child(
        &self,
        template_ref: &str,
        target_path: &Path,
        _config: &BTreeMap<String, serde_yml::Value>,
    ) -> Result<(), PackError> {
        self.calls.lock().unwrap().push(format!(
            "spawn-child:{template_ref}:{}",
            target_path.display()
        ));
        Ok(())
    }
    fn submit_component(
        &self,
        component_ref: &str,
        _trigger: &WorkflowTrigger,
    ) -> Result<(), PackError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("submit-component:{component_ref}"));
        Err(PackError::InvalidWorkflow("scheduler said no".into()))
    }
    fn register_mcp_server(
        &self,
        config_ref: &str,
        _resolved: &BTreeMap<String, SecretValue>,
    ) -> Result<McpServerId, PackError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("register-mcp-server:{config_ref}"));
        Ok(McpServerId(config_ref.to_string()))
    }
    fn terminate_child(&self, target_path: &Path) -> Result<(), PackError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("terminate-child:{}", target_path.display()));
        if self.fail_terminate {
            Err(PackError::InvalidWorkflow("child refuses to die".into()))
        } else {
            Ok(())
        }
    }
}

const TEMPLATE: &str = r#"name: wf
steps:
  - type: spawn-child
    template: pack@1.0.0/agent-templates/researcher
    target-path: /research-assistant
  - type: submit-component
    ref: pack@1.0.0/components/nightly
    schedule: "every-1h"
"#;

#[test]
fn g04_failed_step_compensates_earlier_spawn_in_reverse_order() {
    let exec = FailingSubmit {
        calls: Mutex::new(Vec::new()),
        fail_terminate: false,
    };
    let ctx = WorkflowContext::default();
    let err = WorkflowApplier::apply(TEMPLATE, &ctx, &exec, &NoSecrets)
        .expect_err("submit-component fails → apply fails");
    match err {
        PackError::WorkflowStepFailed {
            step,
            source,
            compensated,
            compensation_failures,
        } => {
            assert!(step.contains("submit-component"), "step = {step}");
            assert!(
                matches!(*source, PackError::InvalidWorkflow(_)),
                "source = {source:?}"
            );
            assert_eq!(
                compensated.len(),
                1,
                "one earlier step to undo: {compensated:?}"
            );
            assert!(compensated[0].starts_with("spawn-child"), "{compensated:?}");
            assert!(
                compensation_failures.is_empty(),
                "{compensation_failures:?}"
            );
        }
        other => panic!("expected WorkflowStepFailed, got {other:?}"),
    }
    let calls = exec.calls.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![
            "spawn-child:pack@1.0.0/agent-templates/researcher:/research-assistant".to_string(),
            "submit-component:pack@1.0.0/components/nightly".to_string(),
            "terminate-child:/research-assistant".to_string(),
        ],
        "compensation runs AFTER the failure, against the spawned child"
    );
}

#[test]
fn g04_compensation_failure_is_reported_not_swallowed() {
    let exec = FailingSubmit {
        calls: Mutex::new(Vec::new()),
        fail_terminate: true,
    };
    let err = WorkflowApplier::apply(TEMPLATE, &WorkflowContext::default(), &exec, &NoSecrets)
        .expect_err("still an error");
    match err {
        PackError::WorkflowStepFailed {
            compensated,
            compensation_failures,
            ..
        } => {
            assert!(
                compensated.is_empty(),
                "nothing was successfully compensated"
            );
            assert_eq!(compensation_failures.len(), 1);
            assert!(
                compensation_failures[0].contains("child refuses to die"),
                "{compensation_failures:?}"
            );
        }
        other => panic!("expected WorkflowStepFailed, got {other:?}"),
    }
}

#[test]
fn g04_success_path_report_is_unchanged() {
    struct AllOk;
    impl WorkflowExecutor for AllOk {
        fn spawn_child(
            &self,
            _: &str,
            _: &Path,
            _: &BTreeMap<String, serde_yml::Value>,
        ) -> Result<(), PackError> {
            Ok(())
        }
        fn submit_component(&self, _: &str, _: &WorkflowTrigger) -> Result<(), PackError> {
            Ok(())
        }
        fn register_mcp_server(
            &self,
            r: &str,
            _: &BTreeMap<String, SecretValue>,
        ) -> Result<McpServerId, PackError> {
            Ok(McpServerId(r.to_string()))
        }
    }
    let report = WorkflowApplier::apply(TEMPLATE, &WorkflowContext::default(), &AllOk, &NoSecrets)
        .expect("all steps succeed");
    assert_eq!(report.steps_executed.len(), 2);
}

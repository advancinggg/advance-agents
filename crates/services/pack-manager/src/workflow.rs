//! Workflow template applier (Slice B, AC-10).
//!
//! Drives 3 workflow step types (spawn-child / submit-component / register-mcp-server)
//! through the `WorkflowExecutor` seam. `secret-refs` resolved through `SecretStore`
//! BEFORE invoking the executor's `register_mcp_server` method.
//!
//! Schema: see MODULE-018 §1.3.4. Per-step `submit-component` uses sibling
//! `schedule` / `trigger-event` fields with post-parse XOR validation
//! (deviates from §19.7 nested-trigger form to avoid serde untagged enum error opacity).
//!
//! Slice B: no automatic transactional rollback on partial failure. If
//! spawn-child succeeds then submit-component fails, the spawned child remains —
//! admin must manually reconcile (per §3.6 known gaps).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::PackError;
use crate::manifest::yaml_has_alias_refs;
use crate::materialize::{McpServerId, WorkflowContext, WorkflowReport};
use crate::registry::parse_fq_ref;

const MAX_TARGET_PATH_LEN: usize = 4096;
const MAX_WORKFLOW_YAML_BYTES: usize = 1024 * 1024;

/// Secret value with redacted `Debug` and no public field access. Production
/// `WorkflowExecutor` impls (M005 / M014 / M017) must call `expose_secret()`
/// explicitly and avoid logging the returned `&str`. The redacted `Debug`
/// prevents accidental plaintext leak through panic backtraces, tracing
/// instrumentation, or audit-trail captures of `BTreeMap<String, SecretValue>`.
/// (Adversarial round 2 Critical 1 fix.)
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Explicit accessor — calling this is the documented opt-in to handling
    /// plaintext secret material. Callers MUST NOT log the returned `&str`.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretValue([REDACTED; {} bytes])", self.0.len())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowTrigger {
    Schedule(String),
    TriggerEvent {
        event_type: String,
        filter: Option<String>,
    },
}

pub trait WorkflowExecutor: Send + Sync {
    fn spawn_child(
        &self,
        template_ref: &str,
        target_path: &Path,
        config: &BTreeMap<String, serde_yml::Value>,
    ) -> Result<(), PackError>;

    fn submit_component(
        &self,
        component_ref: &str,
        trigger: &WorkflowTrigger,
    ) -> Result<(), PackError>;

    fn register_mcp_server(
        &self,
        config_ref: &str,
        resolved_secrets: &BTreeMap<String, SecretValue>,
    ) -> Result<McpServerId, PackError>;
}

pub trait SecretStore: Send + Sync {
    fn get(&self, key: &str) -> Option<SecretValue>;
}

// ───── Workflow YAML schema ────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowTemplate {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub steps: Vec<WorkflowStep>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WorkflowStep {
    SpawnChild {
        template: String,
        #[serde(rename = "target-path")]
        target_path: PathBuf,
        #[serde(default)]
        config: BTreeMap<String, serde_yml::Value>,
    },
    SubmitComponent {
        #[serde(rename = "ref")]
        ref_field: String,
        #[serde(default)]
        schedule: Option<String>,
        #[serde(default, rename = "trigger-event")]
        trigger_event: Option<TriggerEventBody>,
    },
    RegisterMcpServer {
        #[serde(rename = "config-ref")]
        config_ref: String,
        #[serde(default, rename = "secret-refs")]
        secret_refs: BTreeMap<String, String>,
    },
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TriggerEventBody {
    #[serde(rename = "event-type")]
    pub event_type: String,
    #[serde(default)]
    pub filter: Option<String>,
}

// WorkflowContext and WorkflowReport are defined in `materialize.rs` (Slice A
// placeholder shapes used by CONTRACT-171 `MaterializeAction::apply_workflow`).
// Slice B's `WorkflowApplier::apply` consumes the same types via re-export, so
// there is exactly one definition site.

// ───── WorkflowApplier ─────────────────────────────────────────────────

pub struct WorkflowApplier;

impl WorkflowApplier {
    pub fn apply(
        template_yaml: &str,
        ctx: &WorkflowContext,
        executor: &dyn WorkflowExecutor,
        secret_store: &dyn SecretStore,
    ) -> Result<WorkflowReport, PackError> {
        if template_yaml.len() > MAX_WORKFLOW_YAML_BYTES {
            return Err(PackError::InvalidWorkflow(format!(
                "workflow yaml exceeds max {MAX_WORKFLOW_YAML_BYTES} bytes ({} bytes)",
                template_yaml.len()
            )));
        }
        if yaml_has_alias_refs(template_yaml) {
            return Err(PackError::InvalidWorkflow(
                "workflow yaml contains alias references (`*name`) — rejected to prevent \
                 billion-laughs amplification"
                    .into(),
            ));
        }
        // Adversarial round 18 (crate-wide DoS parity — the 5th untrusted serde_yml entry
        // point): bound flow-nesting/indentation depth before serde_yml. A pack-shipped
        // `workflows/{name}.yaml` is attacker-controlled; a deep-flow-nested one drives
        // serde_yml super-linear (measured 320 KB → ~83 s; ~15 min at the 1 MiB cap). See
        // `component_manifest::yaml_nesting_within_bound`.
        if !crate::component_manifest::yaml_nesting_within_bound(template_yaml) {
            return Err(PackError::InvalidWorkflow(
                "workflow yaml nesting/indentation is too deep — rejected to prevent \
                 parse-time resource exhaustion (serde_yml deep-nesting DoS)"
                    .into(),
            ));
        }
        let template: WorkflowTemplate = serde_yml::from_str(template_yaml)
            .map_err(|e| PackError::InvalidWorkflow(format!("yaml parse: {e}")))?;

        let mut report = WorkflowReport::default();
        for (idx, step) in template.steps.iter().enumerate() {
            match step {
                WorkflowStep::SpawnChild {
                    template,
                    target_path,
                    config,
                } => {
                    parse_fq_ref(template).map_err(|e| {
                        PackError::InvalidWorkflow(format!(
                            "step {idx} spawn-child template invalid: {e}"
                        ))
                    })?;
                    validate_target_path(target_path, &ctx.target_workspace, idx)?;
                    executor.spawn_child(template, target_path, config)?;
                    report.steps_executed.push("spawn-child".into());
                }
                WorkflowStep::SubmitComponent {
                    ref_field,
                    schedule,
                    trigger_event,
                } => {
                    parse_fq_ref(ref_field).map_err(|e| {
                        PackError::InvalidWorkflow(format!(
                            "step {idx} submit-component ref invalid: {e}"
                        ))
                    })?;
                    let trigger = match (schedule, trigger_event) {
                        (Some(s), None) => WorkflowTrigger::Schedule(s.clone()),
                        (None, Some(t)) => WorkflowTrigger::TriggerEvent {
                            event_type: t.event_type.clone(),
                            filter: t.filter.clone(),
                        },
                        _ => {
                            return Err(PackError::InvalidWorkflow(format!(
                                "step {idx} submit-component requires exactly one of \
                                 `schedule` or `trigger-event`"
                            )));
                        }
                    };
                    executor.submit_component(ref_field, &trigger)?;
                    report.steps_executed.push("submit-component".into());
                }
                WorkflowStep::RegisterMcpServer {
                    config_ref,
                    secret_refs,
                } => {
                    parse_fq_ref(config_ref).map_err(|e| {
                        PackError::InvalidWorkflow(format!(
                            "step {idx} register-mcp-server config-ref invalid: {e}"
                        ))
                    })?;
                    let mut resolved = BTreeMap::new();
                    for (placeholder, secret_id) in secret_refs {
                        let value = secret_store.get(secret_id).ok_or_else(|| {
                            PackError::MissingSecret {
                                key: secret_id.clone(),
                            }
                        })?;
                        resolved.insert(placeholder.clone(), value);
                    }
                    let _ = executor.register_mcp_server(config_ref, &resolved)?;
                    report.steps_executed.push("register-mcp-server".into());
                }
            }
        }
        Ok(report)
    }
}

fn validate_target_path(
    target_path: &Path,
    target_workspace: &Path,
    step_idx: usize,
) -> Result<(), PackError> {
    let s = target_path.to_str().ok_or_else(|| {
        PackError::InvalidWorkflow(format!("step {step_idx} target-path is not UTF-8"))
    })?;
    if s.is_empty() {
        return Err(PackError::InvalidWorkflow(format!(
            "step {step_idx} target-path is empty"
        )));
    }
    if s.len() > MAX_TARGET_PATH_LEN {
        return Err(PackError::InvalidWorkflow(format!(
            "step {step_idx} target-path exceeds max {MAX_TARGET_PATH_LEN} bytes"
        )));
    }
    if s.contains('\0') {
        return Err(PackError::InvalidWorkflow(format!(
            "step {step_idx} target-path contains null byte"
        )));
    }
    for seg in target_path.components() {
        match seg {
            std::path::Component::ParentDir => {
                return Err(PackError::InvalidWorkflow(format!(
                    "step {step_idx} target-path contains `..` traversal"
                )));
            }
            std::path::Component::CurDir => {
                return Err(PackError::InvalidWorkflow(format!(
                    "step {step_idx} target-path contains `.` (CurDir) segment"
                )));
            }
            _ => {}
        }
    }
    // Absolute-path containment: when target_workspace is set, the absolute path
    // must stay inside it. When target_workspace is empty, an absolute target_path
    // is rejected entirely — empty workspace means "no containment configured",
    // so an absolute path has no safe envelope. Callers wanting to allow absolute
    // paths MUST set `target_workspace` explicitly to opt-in to containment.
    if target_path.is_absolute() {
        if target_workspace.as_os_str().is_empty() {
            return Err(PackError::InvalidWorkflow(format!(
                "step {step_idx} absolute target-path requires non-empty target_workspace"
            )));
        }
        if !target_path.starts_with(target_workspace) {
            return Err(PackError::InvalidWorkflow(format!(
                "step {step_idx} absolute target-path escapes target_workspace"
            )));
        }
    }
    // Footgun documentation (Adversarial round 2 W5): when target_workspace
    // resolves to the filesystem root (e.g. `/`), the `starts_with` check
    // above accepts every absolute path. Callers wiring `WorkflowContext`
    // for any environment that processes ATTACKER-CONTROLLED workflow YAML
    // must set target_workspace to a NARROWER subtree (e.g. the agent's
    // dedicated workspace) — `target_workspace = "/"` disables containment
    // entirely and is only safe for admin-driven local installs where the
    // workflow content is itself trusted. Currently the validator does not
    // reject `/` because the same configuration is legitimately used for
    // full-workspace admin operations.
    Ok(())
}

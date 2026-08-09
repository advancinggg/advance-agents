//! Evaluator Pack component loader foundation (PRD §4.7.4 / MODULE-015 §1.3.3
//! / AC-08+AC-09 foundation — verification deferred per waived_scope).
//!
//! Slice-B scope: ships the trait surface + manifest constraint-surface
//! validator + id-override helper as INDEPENDENT PRIMITIVES. The actual wiring
//! to MODULE-018's `PackRegistry::resolve_pack_component` (CONTRACT-170)
//! happens in a coordinated slice; AC-08/AC-09 verification is withheld this
//! slice to avoid mechanically advancing REQ-073: Partial → Verified via §6.3
//! aggregation (MODULE-018-AC-14 is already passed).
//!
//! **Local type rationale** (MODULE-015 §3.8 dependency-inversion pattern,
//! same as slice-A's IterationCheckpoint/IterationRollback wrapping MODULE-003):
//! `EvaluatorManifest` / `EvaluatorSpec` are auto-loop-LOCAL types, not
//! pack-manager's `PackComponentResolution` directly. The integrated slice
//! translates pack-manager's shapes into these locally-defined ones at the
//! wiring boundary, keeping auto-loop's dependency tree minimal.

use std::path::PathBuf;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use advance_shared_types::capability::CapRequest;

/// Component-yaml subset auto-loop needs for constraint-surface validation.
/// `Vec<CapRequest>` is on `EvaluatorSpec.capabilities` — kept off the
/// manifest because capabilities are runtime grants, not constraint state.
///
/// Validator surface (per PRD §4.7.4 component.yaml constraint table):
/// - `component_type` MUST be `"task"` (one-shot execution).
/// - `has_binary` MUST be true (either `binary` or `behavior-ref` field
///   present — the manifest collapses both into a single boolean).
/// - `trigger_present` MUST be false (AutoLoopDriver controls timing —
///   external triggers rejected).
///
/// Accept-and-ignore at this layer (not represented as manifest state because
/// the validator never inspects them): `restart-policy`, `delay`,
/// `initial-grants`, `preset`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluatorManifest {
    pub component_type: String,
    pub has_binary: bool,
    pub trigger_present: bool,
    /// Raw component.yaml text — kept for observability / debugging. The
    /// validator does NOT parse this; structured fields are pre-extracted
    /// by the wiring slice before calling `validate_constraint_surface`.
    pub raw_yaml: String,
}

/// Resolved evaluator component as the auto-loop driver needs it.
/// `capabilities: Vec<CapRequest>` aligns with pack-manager's
/// `PackComponentResolution.capabilities` type at the wiring boundary.
#[derive(Clone, Debug, PartialEq)]
pub struct EvaluatorSpec {
    pub binary: Vec<u8>,
    pub capabilities: Vec<CapRequest>,
    pub output_dir: PathBuf,
    pub manifest: EvaluatorManifest,
}

/// Reasons an evaluator component fails the constraint-surface check
/// (foundation for AC-08; integrated-loop slice raises this on
/// admission).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConstraintViolation {
    #[error("component-type must be `task` (found `{0}`)")]
    WrongComponentType(String),
    #[error("trigger must be absent (AutoLoopDriver controls timing)")]
    TriggerPresent,
    #[error("at least one of binary/behavior-ref must be present")]
    NoBinary,
}

/// Validator: check the constraint surface declared in PRD §4.7.4
/// component.yaml table. Pure function, no I/O.
pub fn validate_constraint_surface(
    manifest: &EvaluatorManifest,
) -> Result<(), ConstraintViolation> {
    if manifest.component_type != "task" {
        return Err(ConstraintViolation::WrongComponentType(
            manifest.component_type.clone(),
        ));
    }
    if manifest.trigger_present {
        return Err(ConstraintViolation::TriggerPresent);
    }
    if !manifest.has_binary {
        return Err(ConstraintViolation::NoBinary);
    }
    Ok(())
}

/// Compute the runtime-overridden evaluator id per PRD §4.7.4 + MODULE-015
/// §2.11: `auto-eval:{agent-id}:iter-{n}`. This is a component id (NOT a
/// git ref) — colons are intentional.
///
/// Trust boundary: `agent_id` validation (ASCII / no shell-meta / no
/// embedded colons) is UPSTREAM responsibility (MODULE-005 agent-lifecycle
/// at agent-creation time, CONTRACT-041). This helper does NOT re-validate;
/// passing an untrusted `agent_id` here is a caller bug.
pub fn evaluator_id(agent_id: &str, iteration: u32) -> String {
    format!("auto-eval:{agent_id}:iter-{iteration}")
}

/// Errors surfaced by the resolver (foundation surface for the wiring slice).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EvaluatorResolveError {
    #[error("evaluator pack-ref not found: {0}")]
    NotFound(String),
    #[error("evaluator constraint surface violation: {0}")]
    ConstraintViolated(ConstraintViolation),
    #[error("evaluator manifest parse error: {0}")]
    ParseError(String),
}

/// Trait that the integrated-loop slice will implement against MODULE-018's
/// `PackRegistry::resolve_pack_component`. Slice-B ships only the trait
/// surface; the production wiring is part of the coordinated slice that
/// owns REQ-073 closing.
#[async_trait]
pub trait EvaluatorResolver: Send + Sync {
    async fn resolve_evaluator(&self, fq_ref: &str)
        -> Result<EvaluatorSpec, EvaluatorResolveError>;
}

/// Test double / placeholder: always returns NotFound. Slice-B integration
/// tests use this to verify the resolver-IS-NOT-CALLED invariant
/// (AC-19 evidence path in tests/state_machine.rs (o)).
pub struct NoopEvaluatorResolver;

#[async_trait]
impl EvaluatorResolver for NoopEvaluatorResolver {
    async fn resolve_evaluator(
        &self,
        fq_ref: &str,
    ) -> Result<EvaluatorSpec, EvaluatorResolveError> {
        Err(EvaluatorResolveError::NotFound(fq_ref.to_string()))
    }
}

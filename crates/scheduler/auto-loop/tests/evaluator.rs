//! Foundation tests for evaluator Pack component loader (AC-08+AC-09 verification
//! deferred per waived_scope to avoid mechanical REQ-073: Partial → Verified).

use std::path::PathBuf;

use advance_scheduler_auto_loop::{
    evaluator_id, validate_constraint_surface, ConstraintViolation, EvaluatorManifest,
    EvaluatorResolveError, EvaluatorResolver, NoopEvaluatorResolver,
};

fn manifest_task_with_binary() -> EvaluatorManifest {
    EvaluatorManifest {
        component_type: "task".to_string(),
        has_binary: true,
        trigger_present: false,
        raw_yaml: "".to_string(),
    }
}

// ─── (a) evaluator_id format ─────────────────────────────────────────────

#[test]
fn a_evaluator_id_format() {
    assert_eq!(evaluator_id("alice", 0), "auto-eval:alice:iter-0");
    assert_eq!(
        evaluator_id("research-agent", 42),
        "auto-eval:research-agent:iter-42"
    );
}

// ─── (b)-(d) constraint surface rejection cases ──────────────────────────

#[test]
fn b_wrong_component_type_rejected() {
    let m = EvaluatorManifest {
        component_type: "agent".to_string(),
        ..manifest_task_with_binary()
    };
    let err = validate_constraint_surface(&m).unwrap_err();
    match err {
        ConstraintViolation::WrongComponentType(actual) => assert_eq!(actual, "agent"),
        other => panic!("expected WrongComponentType, got {other:?}"),
    }
}

#[test]
fn c_trigger_present_rejected() {
    let m = EvaluatorManifest {
        trigger_present: true,
        ..manifest_task_with_binary()
    };
    assert_eq!(
        validate_constraint_surface(&m),
        Err(ConstraintViolation::TriggerPresent)
    );
}

#[test]
fn d_no_binary_rejected() {
    let m = EvaluatorManifest {
        has_binary: false,
        ..manifest_task_with_binary()
    };
    assert_eq!(
        validate_constraint_surface(&m),
        Err(ConstraintViolation::NoBinary)
    );
}

// ─── (e) accept-and-ignore (the validator never inspects these fields) ──

#[test]
fn e_accept_valid_manifest() {
    // The manifest does NOT carry restart-policy / delay / initial-grants
    // / preset flags by design — those are accept-and-ignore at the wiring
    // layer (the validator never inspects them). A valid manifest with
    // component_type=task + has_binary + !trigger_present passes.
    assert_eq!(
        validate_constraint_surface(&manifest_task_with_binary()),
        Ok(())
    );
}

// ─── (f) NoopEvaluatorResolver test double exists ───────────────────────

#[tokio::test]
async fn f_noop_resolver_returns_not_found() {
    let resolver = NoopEvaluatorResolver;
    let err = resolver
        .resolve_evaluator("research-pack@1.2.0/evaluator-bpb")
        .await
        .unwrap_err();
    match err {
        EvaluatorResolveError::NotFound(r) => {
            assert_eq!(r, "research-pack@1.2.0/evaluator-bpb");
        }
        other => panic!("expected NotFound, got {other:?}"),
    }
}

// ─── EvaluatorSpec construction (smoke test) ────────────────────────────

#[test]
fn evaluator_spec_constructible_with_cap_request_vec() {
    // Confirms the public EvaluatorSpec carries the canonical
    // CapRequest type for capabilities (aligns with pack-manager's
    // PackComponentResolution).
    use advance_scheduler_auto_loop::EvaluatorSpec;
    use advance_shared_types::capability::{CapRequest, CapabilityId};

    let _spec = EvaluatorSpec {
        binary: vec![0u8; 16],
        capabilities: vec![CapRequest {
            capability: CapabilityId::new("agent-fs"),
        }],
        output_dir: PathBuf::from("/tmp/eval-output"),
        manifest: manifest_task_with_binary(),
    };
}

//! AC-04 / AC-05 unit tests — `success_criteria` parse + validate.
//!
//! Every YAML literal is `auto-loop:`-wrapped (the real config-file shape;
//! round-7). The first test pins the verbatim PRD §4.7.4 / MODULE-015
//! §1.3.2 example so a reintroduced kebab-case (round-6) OR a dropped
//! wrapper (round-7) fails loudly.

use advance_scheduler_auto_loop::{AutoLoopError, SuccessCriteria};

// MODULE-015-T04d-slA — spec-canonical pin (round-6 + round-7 regression guard).
#[test]
fn parses_verbatim_spec_example_wrapped_snake_case() {
    // Verbatim PRD §4.7.4 / MODULE-015 §1.3.2: outer `auto-loop:` hyphen,
    // inner snake_case `metric_source`/`output_key`, `predicate: { op: lt }`.
    let yaml = r#"
auto-loop:
  evaluator: research-pack@1.2.0/evaluator-bpb
  objectives:
    - name: val-bpb
      role: primary
      metric_source: { type: file, path: metrics/bpb.json, key: val_bpb }
      predicate: { op: lt }
    - name: code-quality
      role: guardrail
      metric_source: { type: component, output_key: score }
      predicate: { op: gt, threshold: 0.8 }
"#;
    let sc = SuccessCriteria::parse_yaml(yaml).expect("verbatim spec example must parse");
    sc.validate().expect("verbatim spec example must validate");
    assert_eq!(sc.objectives.len(), 2);
    assert!(sc.evaluator.is_some());
}

// MODULE-015-T04-slA — happy path.
#[test]
fn happy_path_one_primary_one_guardrail() {
    let yaml = r#"
auto-loop:
  objectives:
    - name: p
      role: primary
      metric_source: { type: file, path: m.json, key: v }
      predicate: { op: lt }
    - name: g
      role: guardrail
      metric_source: { type: file, path: q.json, key: w }
      predicate: { op: gt, threshold: 0.5 }
"#;
    let sc = SuccessCriteria::parse_yaml(yaml).unwrap();
    assert!(sc.validate().is_ok());
}

// MODULE-015-T04b-slA — zero / two / empty primary.
#[test]
fn zero_primary_is_missing_primary() {
    let yaml = r#"
auto-loop:
  objectives:
    - name: g
      role: guardrail
      metric_source: { type: file, path: q.json, key: w }
      predicate: { op: gt, threshold: 0.5 }
"#;
    let sc = SuccessCriteria::parse_yaml(yaml).unwrap();
    assert!(matches!(sc.validate(), Err(AutoLoopError::MissingPrimary)));
}

#[test]
fn two_primary_is_multiple_primary() {
    let yaml = r#"
auto-loop:
  objectives:
    - name: p1
      role: primary
      metric_source: { type: file, path: a.json, key: v }
      predicate: { op: lt }
    - name: p2
      role: primary
      metric_source: { type: file, path: b.json, key: v }
      predicate: { op: lt }
"#;
    let sc = SuccessCriteria::parse_yaml(yaml).unwrap();
    assert!(matches!(
        sc.validate(),
        Err(AutoLoopError::MultiplePrimary(2))
    ));
}

#[test]
fn empty_objectives_is_missing_primary() {
    let yaml = "auto-loop:\n  objectives: []\n";
    let sc = SuccessCriteria::parse_yaml(yaml).unwrap();
    assert!(matches!(sc.validate(), Err(AutoLoopError::MissingPrimary)));
}

// MODULE-015-T05-slA — component metric_source without evaluator.
#[test]
fn component_without_evaluator_is_missing_evaluator() {
    let yaml = r#"
auto-loop:
  objectives:
    - name: p
      role: primary
      metric_source: { type: component, output_key: score }
      predicate: { op: lt }
"#;
    let sc = SuccessCriteria::parse_yaml(yaml).unwrap();
    assert!(matches!(
        sc.validate(),
        Err(AutoLoopError::MissingEvaluator)
    ));
}

#[test]
fn component_with_evaluator_validates() {
    let yaml = r#"
auto-loop:
  evaluator: pack@1.0.0/eval
  objectives:
    - name: p
      role: primary
      metric_source: { type: component, output_key: score }
      predicate: { op: lt }
"#;
    let sc = SuccessCriteria::parse_yaml(yaml).unwrap();
    assert!(sc.validate().is_ok());
}

// MODULE-015-T05b-slA — inner round-trip (wrapper is input-only).
#[test]
fn inner_round_trip_snake_case_stable() {
    let yaml = r#"
auto-loop:
  objectives:
    - name: p
      role: primary
      metric_source: { type: file, path: m.json, key: v }
      predicate: { op: lt }
"#;
    let sc = SuccessCriteria::parse_yaml(yaml).unwrap();
    let reser = serde_yml::to_string(&sc).unwrap();
    let back: SuccessCriteria = serde_yml::from_str(&reser).unwrap();
    assert_eq!(sc, back);
}

// metric_source variant coverage (#[serde(tag = "type")] discriminator).
#[test]
fn event_metric_source_with_filter_parses() {
    let yaml = r#"
auto-loop:
  objectives:
    - name: p
      role: primary
      metric_source: { type: file, path: m.json, key: v }
      predicate: { op: lt }
    - name: ff
      role: fail_fast
      metric_source:
        type: event
        event_type: component.error
        filter: { component_id: evaluator }
      predicate: { op: gt }
"#;
    let sc = SuccessCriteria::parse_yaml(yaml).unwrap();
    // Slice A does NOT enforce the role × metric_source matrix (AC-06/07
    // deferred) — parsing succeeds; only the exactly-one-primary rule fires.
    assert!(sc.validate().is_ok());
}

// round-6 regression guard: inner kebab `metric-source:` hard-rejected.
#[test]
fn inner_kebab_metric_source_is_hard_parse_error() {
    let yaml = r#"
auto-loop:
  objectives:
    - name: p
      role: primary
      metric-source: { type: file, path: m.json, key: v }
      predicate: { op: lt }
"#;
    assert!(matches!(
        SuccessCriteria::parse_yaml(yaml),
        Err(AutoLoopError::Parse(_))
    ));
}

// round-7 regression guard: a wrapper-less doc is hard-rejected.
#[test]
fn missing_auto_loop_wrapper_is_hard_parse_error() {
    let yaml = r#"
objectives:
  - name: p
    role: primary
    metric_source: { type: file, path: m.json, key: v }
    predicate: { op: lt }
"#;
    assert!(matches!(
        SuccessCriteria::parse_yaml(yaml),
        Err(AutoLoopError::Parse(_))
    ));
}

// >MAX_OBJECTIVES is now rejected at the SERDE BOUNDARY (audit round-1
// fix: deserialize_bounded_objectives), so parse_yaml fails closed before
// any validate() call.
#[test]
fn too_many_objectives_rejected_at_parse_boundary() {
    let mut objs = String::new();
    for i in 0..65 {
        objs.push_str(&format!(
            "    - name: o{i}\n      role: guardrail\n      metric_source: {{ type: file, path: p{i}.json, key: k }}\n      predicate: {{ op: gt, threshold: 0.1 }}\n"
        ));
    }
    let yaml = format!("auto-loop:\n  objectives:\n{objs}");
    assert!(
        matches!(
            SuccessCriteria::parse_yaml(&yaml),
            Err(AutoLoopError::Parse(_))
        ),
        "65 objectives must be rejected at the serde boundary (parse), not deferred to validate()"
    );
}

// validate()'s TooManyObjectives still guards the direct-Rust-construction
// path (someone building SuccessCriteria in code, bypassing parse_yaml).
#[test]
fn too_many_objectives_rejected_by_validate_on_direct_construction() {
    use advance_scheduler_auto_loop::{MetricSource, Objective, Op, Predicate, Role};
    let objectives: Vec<Objective> = (0..65)
        .map(|i| Objective {
            name: format!("o{i}"),
            role: Role::Guardrail,
            metric_source: MetricSource::File {
                path: format!("p{i}.json"),
                key: "k".to_string(),
            },
            predicate: Predicate {
                op: Op::Gt,
                threshold: Some(0.1),
            },
        })
        .collect();
    let sc = SuccessCriteria {
        evaluator: None,
        objectives,
        // Slice-B added 2 optional fields; default to None to preserve
        // the pre-slice-B test semantics. (One-line struct-fixture
        // extension — no semantic test change.)
        per_iteration_budget: None,
        fail_fast: None,
        safety_valve: None,
    };
    assert!(matches!(
        sc.validate(),
        Err(AutoLoopError::TooManyObjectives(65))
    ));
}

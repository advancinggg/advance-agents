//! Lane E1 — structured meta-schema merge, v2 grammar:
//! an extension's aspect block lands in the workspace document, an aspect has exactly one
//! owner, and every field attribute takes part in the identical / conflict decision.

use advance_pack_manager::meta_schema_merge::{
    merge_meta_schema_extension_file_with, MetaSchemaMergeError,
};
use serde_yml::Value;

const AGENDA_YAML: &str =
    include_str!("../../../../packs/agenda/meta-schema-extensions/agenda.yaml");
const BASE: &str = "required:\n  name:\n    type: string\n    auto: filename\noptional:\n  stage:\n    type: [draft, live]\n    default: draft\n";

/// Merge `ext` into a fresh target holding `target_text`; returns the merged text + report.
fn merge(
    target_text: &str,
    ext: &str,
) -> Result<(String, Vec<String>, Vec<String>), MetaSchemaMergeError> {
    let tmp = tempfile::TempDir::new().unwrap();
    let target = tmp.path().join("meta-schema.yaml");
    let source = tmp.path().join("ext.yaml");
    std::fs::write(&target, target_text).unwrap();
    std::fs::write(&source, ext).unwrap();
    let report = merge_meta_schema_extension_file_with(&source, &target, |_| Ok(()))?;
    Ok((
        std::fs::read_to_string(&target).unwrap(),
        report.added,
        report.unchanged,
    ))
}

fn yaml(text: &str) -> Value {
    serde_yml::from_str(text).unwrap()
}

#[test]
fn e1_aspect_block_lands_in_the_target_document() {
    let (merged, added, _) = merge(BASE, AGENDA_YAML).expect("agenda merges into a base schema");
    let v = yaml(&merged);
    assert_eq!(
        v["aspects"]["agenda"]["key"],
        yaml("[status, starts]"),
        "{merged}"
    );
    assert_eq!(
        v["aspects"]["agenda"]["queries"]["day"]["args"]["day"],
        Value::from("datetime")
    );
    assert_eq!(
        v["aspects"]["agenda"]["views"]["board"]["group_by"],
        Value::from("status")
    );
    assert_eq!(
        v["aspects"]["agenda"]["operations"]["shift_series"]["method"],
        Value::from("shift-series")
    );
    let fields = &v["aspects"]["agenda"]["fields"];
    assert_eq!(fields["status"]["transitions"]["done"], yaml("[todo]"));
    assert!(
        fields["due"].get("default").is_none(),
        "no default is invented for a field declared without one"
    );
    assert!(
        v["optional"].get("status").is_none(),
        "aspect fields stay under their aspect, never in the entry vocabulary"
    );
    // The target's own content survives verbatim.
    assert_eq!(v["optional"]["stage"]["default"], Value::from("draft"));
    assert_eq!(v["required"]["name"]["auto"], Value::from("filename"));
    assert!(
        added.contains(&"status".to_string()) && added.len() == 11,
        "{added:?}"
    );
}

#[test]
fn e1_merging_the_same_extension_again_is_idempotent() {
    let (merged, _, _) = merge(BASE, AGENDA_YAML).unwrap();
    let (again, added, unchanged) = merge(&merged, AGENDA_YAML).unwrap();
    assert!(added.is_empty(), "{added:?}");
    assert_eq!(unchanged.len(), 11);
    assert_eq!(yaml(&again), yaml(&merged), "document is a fixed point");
}

#[test]
fn e1_an_aspect_has_exactly_one_owner() {
    let (merged, _, _) = merge(BASE, AGENDA_YAML).unwrap();
    let rival = "aspect: agenda\nkey: [starts]\nfields:\n  starts:\n    type: datetime\n";
    let err = merge(&merged, rival).unwrap_err();
    assert!(
        matches!(err, MetaSchemaMergeError::Conflict { .. }),
        "a second declaration of `agenda` is a conflict, not a merge: {err:?}"
    );
}

#[test]
fn e1_field_attributes_participate_in_the_conflict_decision() {
    let (merged, _, _) = merge(BASE, AGENDA_YAML).unwrap();
    let other = "aspect: other\nkey: [status]\nfields:\n  status:\n    type: [todo, doing, done, cancelled]\n    transitions:\n      todo: [done]\n";
    let err = merge(&merged, other).unwrap_err();
    assert!(
        matches!(&err, MetaSchemaMergeError::Conflict { field, .. } if field == "status"),
        "same type, different transitions: {err:?}"
    );
    // Identical redeclaration (attributes included) is fine: `status` reported unchanged.
    let same = "aspect: other\nkey: [status]\nfields:\n  status:\n    type: [todo, doing, done, cancelled]\n    transitions:\n      todo: [doing, done, cancelled]\n      doing: [todo, done, cancelled]\n      done: [todo]\n      cancelled: [todo]\n";
    let (_, added, unchanged) = merge(&merged, same).unwrap();
    assert!(added.is_empty() && unchanged == vec!["status".to_string()]);
}

#[test]
fn e1_v1_extension_still_merges_and_default_is_optional() {
    let (merged, added, _) = merge(BASE, "optional:\n  priority:\n    type: integer\n").unwrap();
    assert_eq!(added, vec!["priority".to_string()]);
    assert!(yaml(&merged)["optional"]["priority"]
        .get("default")
        .is_none());
    assert!(
        yaml(&merged).get("aspects").is_none(),
        "no aspect block without `aspect:`"
    );
}

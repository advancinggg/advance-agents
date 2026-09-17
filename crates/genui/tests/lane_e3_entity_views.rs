//! Lane E3 — the entity view vocabulary in the GenUI catalog:
//! `Board`, `Calendar` and `EntityForm` are vetted components, and every schema view
//! kind maps to exactly one component so an agent-pushed document and a client view render
//! through the same code.

use advance_genui::views::component_for_view_kind;
use advance_genui::{
    seed_catalog, A2uiVersion, ComponentNode, DocumentId, GenUiDocument, GenUiError, GenUiGate,
};
use serde_json::json;

fn gate() -> GenUiGate {
    GenUiGate::new(true, 262_144, seed_catalog())
}

fn doc(root: Vec<ComponentNode>) -> GenUiDocument {
    GenUiDocument {
        protocol_version: A2uiVersion::V0_9_1,
        document_id: DocumentId("doc-1".into()),
        root,
    }
}

fn node(component: &str, props: serde_json::Value) -> ComponentNode {
    ComponentNode {
        component: component.into(),
        props,
        children: vec![],
    }
}

#[test]
fn e3_board_calendar_and_form_are_vetted_components() {
    let d = doc(vec![
        node(
            "Board",
            json!({
                "title": "Launch",
                "columns": [{ "key": "todo", "label": "To do" }, { "key": "done", "label": "Done" }],
                "cards": [{ "entity_id": "e-1", "column": "todo", "title": "SDK" }]
            }),
        ),
        node(
            "Calendar",
            json!({
                "range": { "start": "2026-09-21T00:00:00Z", "end": "2026-09-28T00:00:00Z" },
                "events": [{ "entity_id": "e-2", "title": "sync", "starts": "2026-09-22T02:00:00Z" }]
            }),
        ),
        node(
            "EntityForm",
            json!({
                "entity_id": "e-1",
                "fields": [
                    { "key": "status", "label": "Status", "type": "enum", "enum": ["todo", "doing", "done", "cancelled"], "value": "todo" },
                    { "key": "due", "label": "Due", "type": "datetime" }
                ],
                "submit_action": { "name": "refresh_data" }
            }),
        ),
    ]);
    gate().admit(&d).expect("all three admit");
}

#[test]
fn e3_new_components_validate_their_props() {
    let missing_columns = doc(vec![node("Board", json!({ "cards": [] }))]);
    assert!(matches!(
        gate().admit(&missing_columns).unwrap_err(),
        GenUiError::InvalidProps { ref component, .. } if component == "Board"
    ));
    let bad_range = doc(vec![node("Calendar", json!({ "events": [] }))]);
    assert!(matches!(
        gate().admit(&bad_range).unwrap_err(),
        GenUiError::InvalidProps { ref component, .. } if component == "Calendar"
    ));
    let no_fields = doc(vec![node(
        "EntityForm",
        json!({ "submit_action": { "name": "refresh_data" } }),
    )]);
    assert!(matches!(
        gate().admit(&no_fields).unwrap_err(),
        GenUiError::InvalidProps { ref component, .. } if component == "EntityForm"
    ));
}

#[test]
fn e3_every_view_kind_maps_to_exactly_one_component() {
    assert_eq!(component_for_view_kind("list"), Some("DataTable"));
    assert_eq!(component_for_view_kind("table"), Some("DataTable"));
    assert_eq!(component_for_view_kind("board"), Some("Board"));
    assert_eq!(component_for_view_kind("calendar"), Some("Calendar"));
    assert_eq!(component_for_view_kind("form"), Some("EntityForm"));
    assert_eq!(component_for_view_kind("gantt"), None);
    for kind in ["list", "table", "board", "calendar", "form"] {
        let name = component_for_view_kind(kind).unwrap();
        assert!(
            seed_catalog().component(name).is_some(),
            "{kind} → {name} must be in the seeded catalog"
        );
    }
}

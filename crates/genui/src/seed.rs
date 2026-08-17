use serde_json::json;

use crate::catalog::{ActionEntry, CatalogEntry, ConfirmMetadata, ConfirmVariant, DefaultCatalog};

pub fn seed_catalog() -> DefaultCatalog {
    DefaultCatalog::new(seed_components(), seed_actions())
}

fn seed_components() -> Vec<CatalogEntry> {
    vec![
        CatalogEntry {
            name: "Text".into(),
            props_schema: json!({
                "type": "object",
                "properties": {
                    "content": { "type": "string" },
                    "format": { "type": "string", "enum": ["plain", "markdown"], "default": "markdown" }
                },
                "required": ["content"]
            }),
            allows_children: false,
            selectable: false,
            description: "Text or markdown block.".into(),
            degradation_fallback: None,
        },
        CatalogEntry {
            name: "Heading".into(),
            props_schema: json!({
                "type": "object",
                "properties": {
                    "content": { "type": "string" },
                    "level": { "type": "integer", "minimum": 1, "maximum": 4, "default": 2 }
                },
                "required": ["content"]
            }),
            allows_children: false,
            selectable: false,
            description: "Section heading (h1-h4).".into(),
            degradation_fallback: None,
        },
        CatalogEntry {
            name: "Button".into(),
            props_schema: json!({
                "type": "object",
                "properties": {
                    "label": { "type": "string" },
                    "action": {
                        "type": "object",
                        "properties": {
                            "name": { "type": "string" },
                            "params": { "type": "object" }
                        },
                        "required": ["name"]
                    },
                    "variant": { "type": "string", "enum": ["default", "primary", "secondary", "outline", "ghost", "destructive"], "default": "default" },
                    "disabled": { "type": "boolean", "default": false }
                },
                "required": ["label", "action"]
            }),
            allows_children: false,
            selectable: true,
            description: "Action button that triggers a catalog action.".into(),
            degradation_fallback: None,
        },
        CatalogEntry {
            name: "Section".into(),
            props_schema: json!({
                "type": "object",
                "properties": {
                    "title": { "type": "string" },
                    "description": { "type": "string" }
                }
            }),
            allows_children: true,
            selectable: false,
            description: "Titled section container.".into(),
            degradation_fallback: None,
        },
        CatalogEntry {
            name: "Row".into(),
            props_schema: json!({
                "type": "object",
                "properties": {
                    "gap": { "type": "string", "enum": ["sm", "md", "lg"], "default": "md" }
                }
            }),
            allows_children: true,
            selectable: false,
            description: "Horizontal flex container.".into(),
            degradation_fallback: None,
        },
        CatalogEntry {
            name: "Column".into(),
            props_schema: json!({
                "type": "object",
                "properties": {
                    "gap": { "type": "string", "enum": ["sm", "md", "lg"], "default": "md" }
                }
            }),
            allows_children: true,
            selectable: false,
            description: "Vertical flex container.".into(),
            degradation_fallback: None,
        },
        CatalogEntry {
            name: "EntityCard".into(),
            props_schema: json!({
                "type": "object",
                "properties": {
                    "entity_id": { "type": "string" },
                    "title": { "type": "string" },
                    "subtitle": { "type": "string" },
                    "show_rating": { "type": "boolean", "default": true },
                    "show_category": { "type": "boolean", "default": true }
                },
                "required": ["entity_id", "title"]
            }),
            allows_children: false,
            selectable: true,
            description: "Entity card displaying an agent, run, pack, or listing.".into(),
            degradation_fallback: None,
        },
        CatalogEntry {
            name: "DataTable".into(),
            props_schema: json!({
                "type": "object",
                "properties": {
                    "title": { "type": "string" },
                    "columns": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "key": { "type": "string" },
                                "label": { "type": "string" },
                                "format": { "type": "string", "enum": ["text", "currency", "date", "number", "badge"] }
                            },
                            "required": ["key", "label"]
                        }
                    },
                    "data": {
                        "type": "array",
                        "items": { "type": "object" }
                    },
                    "empty_message": { "type": "string", "default": "No data available" }
                },
                "required": ["columns"]
            }),
            allows_children: false,
            selectable: true,
            description: "Tabular data with per-column formatting.".into(),
            degradation_fallback: None,
        },
        CatalogEntry {
            name: "TreeView".into(),
            props_schema: json!({
                "type": "object",
                "properties": {
                    "root_node_id": { "type": "string" },
                    "expand_depth": { "type": "integer", "minimum": 1, "maximum": 5, "default": 2 },
                    "nodes": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": { "type": "string" },
                                "label": { "type": "string" },
                                "parent_id": { "type": ["string", "null"] }
                            },
                            "required": ["id", "label"]
                        }
                    }
                },
                "required": ["nodes"]
            }),
            allows_children: false,
            selectable: true,
            description: "Hierarchical tree view of nodes.".into(),
            degradation_fallback: None,
        },
        CatalogEntry {
            name: "Callout".into(),
            props_schema: json!({
                "type": "object",
                "properties": {
                    "message": { "type": "string" },
                    "variant": { "type": "string", "enum": ["info", "success", "warning", "error"], "default": "info" },
                    "dismissible": { "type": "boolean", "default": false }
                },
                "required": ["message"]
            }),
            allows_children: false,
            selectable: false,
            description: "Status callout with severity variant.".into(),
            degradation_fallback: None,
        },
        CatalogEntry {
            name: "Stat".into(),
            props_schema: json!({
                "type": "object",
                "properties": {
                    "label": { "type": "string" },
                    "value": { "type": ["string", "number"] },
                    "format": { "type": "string", "enum": ["number", "currency", "percent"], "default": "number" },
                    "trend": { "type": "string", "enum": ["up", "down", "neutral"] }
                },
                "required": ["label", "value"]
            }),
            allows_children: false,
            selectable: false,
            description: "Single metric tile.".into(),
            degradation_fallback: None,
        },
        CatalogEntry {
            name: "StatGroup".into(),
            props_schema: json!({
                "type": "object",
                "properties": {
                    "columns": { "type": "integer", "minimum": 2, "maximum": 4, "default": 3 }
                }
            }),
            allows_children: true,
            selectable: false,
            description: "Container for Stat tiles.".into(),
            degradation_fallback: None,
        },
    ]
}

fn seed_actions() -> Vec<ActionEntry> {
    vec![
        ActionEntry {
            name: "navigate".into(),
            params_schema: json!({
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"]
            }),
            confirm: None,
        },
        ActionEntry {
            name: "refresh_data".into(),
            params_schema: json!({ "type": "object" }),
            confirm: None,
        },
        ActionEntry {
            name: "copy_to_clipboard".into(),
            params_schema: json!({
                "type": "object",
                "properties": { "text": { "type": "string" } },
                "required": ["text"]
            }),
            confirm: None,
        },
        ActionEntry {
            name: "open_entity".into(),
            params_schema: json!({
                "type": "object",
                "properties": { "entity_id": { "type": "string" } },
                "required": ["entity_id"]
            }),
            confirm: None,
        },
        ActionEntry {
            name: "approve_grant".into(),
            params_schema: json!({
                "type": "object",
                "properties": { "grant_id": { "type": "string" } },
                "required": ["grant_id"]
            }),
            confirm: Some(ConfirmMetadata {
                title: "Approve Grant".into(),
                message: "Are you sure you want to approve this grant?".into(),
                variant: ConfirmVariant::Danger,
            }),
        },
        ActionEntry {
            name: "dismiss".into(),
            params_schema: json!({
                "type": "object",
                "properties": { "id": { "type": "string" } },
                "required": ["id"]
            }),
            confirm: None,
        },
    ]
}

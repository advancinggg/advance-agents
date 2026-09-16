#![cfg(feature = "lane-e2")]
//! Lane E2 — the `data` capability is wired end to end.

use advance_cli::agent_config::KNOWN_CAPABILITIES;
use advance_event_bus::taxonomy::{self, ALL_EVENT_TYPES, TRIGGER_BUS_WHITELIST};
use cap_fs::meta_schema::MetaSchemaLoader;

#[test]
fn e2_data_is_a_known_capability() {
    assert!(
        KNOWN_CAPABILITIES.contains(&"data"),
        "{KNOWN_CAPABILITIES:?}"
    );
}

#[test]
fn e2_meta_schema_accepts_aspect_and_inherit_declarations() {
    let loader = MetaSchemaLoader::from_yaml(
        std::path::PathBuf::from("/nonexistent/meta-schema.yaml"),
        "optional:\n  status:\n    type: string\n    aspect: completion\n    key: true\n  assignee:\n    type: string\n    inherit: true\n",
    )
    .expect("aspect / key / inherit are explicit schema keys, not ignored");
    let s = loader.current();
    assert_eq!(s.optional["status"].aspect.as_deref(), Some("completion"));
    assert!(s.optional["status"].key);
    assert!(s.optional["assignee"].inherit);
    assert!(
        MetaSchemaLoader::from_yaml(
            std::path::PathBuf::from("/nonexistent/x.yaml"),
            "optional:\n  status:\n    type: string\n    aspekt: typo\n",
        )
        .is_err(),
        "unknown field keys are rejected, not silently dropped"
    );
}

#[test]
fn e2_reminder_event_is_registered_but_never_a_trigger() {
    assert_eq!(taxonomy::data::REMINDER_DUE, "data.reminder_due");
    assert!(ALL_EVENT_TYPES.contains(&taxonomy::data::REMINDER_DUE));
    assert!(!TRIGGER_BUS_WHITELIST.contains(&taxonomy::data::REMINDER_DUE));
    assert_eq!(TRIGGER_BUS_WHITELIST.len(), 12);
}

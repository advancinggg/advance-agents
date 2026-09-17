#![cfg(feature = "lane-e1")]
//! Lane E1 — meta-schema v2 grammar (the internal entity-data lane plan §1.4 / §2.3): the shipped
//! `packs/agenda` aspect file is parsed key by key, `default` is optional, unknown keys are
//! rejected, the expression language is closed, and the schema hash is content-addressed.

use std::path::PathBuf;

use advance_shared_types::entity::OrderKey;
use cap_fs::meta_schema::{
    Cmp, DeriveElse, EnsureRule, FieldType, MetaSchema, MetaSchemaError, MetaSchemaLoader,
    OperationBinding, ValueExpr, ViewKind, WhereClause,
};
use chrono::Duration;

const AGENDA_YAML: &str =
    include_str!("../../../../packs/agenda/meta-schema-extensions/agenda.yaml");

fn load(yaml: &str) -> Result<MetaSchema, MetaSchemaError> {
    MetaSchemaLoader::from_yaml(PathBuf::from("/nonexistent/meta-schema.yaml"), yaml)
        .map(|l| (*l.current()).clone())
}

fn agenda() -> MetaSchema {
    load(AGENDA_YAML).expect("agenda.yaml parses")
}

#[test]
fn e1_agenda_fields_parse_with_every_v2_attribute() {
    let s = agenda();
    let aspect = &s.aspects["agenda"];
    assert_eq!(aspect.key, vec!["status".to_string(), "starts".to_string()]);

    let status = &s.optional["status"];
    assert_eq!(
        status.field_type,
        FieldType::EnumString(vec![
            "todo".into(),
            "doing".into(),
            "done".into(),
            "cancelled".into()
        ])
    );
    let transitions = status.transitions.as_ref().expect("transitions declared");
    assert_eq!(transitions["done"], vec!["todo".to_string()]);
    assert_eq!(transitions["todo"].len(), 3);
    assert!(status.default.is_none(), "no default: absent = not an item");

    assert_eq!(s.optional["due"].field_type, FieldType::DateTime);
    assert_eq!(s.optional["exdates"].field_type, FieldType::ListDateTime);
    assert_eq!(s.optional["priority"].field_type, FieldType::Integer);
    assert!(s.optional["assignee"].inherit);
    assert!(!s.optional["due"].inherit);

    let derive = s.optional["completed_at"]
        .derive
        .as_ref()
        .expect("derive declared");
    assert_eq!(
        derive.when.get("status").and_then(|v| v.as_str()),
        Some("done")
    );
    assert_eq!(derive.value, ValueExpr::Now { offset: None });
    assert_eq!(derive.else_, DeriveElse::Unset);

    assert_eq!(
        s.optional["ends"].ensure,
        Some(EnsureRule {
            op: Cmp::Gt,
            field: "starts".into()
        })
    );
    assert_eq!(s.optional.len(), 11, "{:?}", s.optional.keys());
}

#[test]
fn e1_agenda_queries_views_and_operations_parse() {
    let s = agenda();
    let aspect = &s.aspects["agenda"];

    let day = &aspect.queries["day"];
    assert_eq!(day.args["day"], FieldType::DateTime);
    assert_eq!(
        day.any_between,
        Some((
            ValueExpr::Arg {
                name: "day".into(),
                offset: None
            },
            ValueExpr::Arg {
                name: "day".into(),
                offset: Some(Duration::days(1))
            }
        ))
    );
    assert_eq!(
        day.order[0],
        OrderKey {
            field: "starts".into(),
            ascending: true
        }
    );

    let open = &aspect.queries["open"];
    assert_eq!(
        open.where_["status"],
        WhereClause::In(vec!["todo".into(), "doing".into()])
    );
    assert_eq!(
        open.order[1],
        OrderKey {
            field: "priority".into(),
            ascending: false
        }
    );
    let overdue = &aspect.queries["overdue"];
    assert_eq!(
        overdue.where_["due"],
        WhereClause::Cmp(Cmp::Lt, ValueExpr::Now { offset: None })
    );
    let upcoming = &aspect.queries["upcoming"];
    assert_eq!(
        upcoming.any_between.as_ref().map(|w| w.1.clone()),
        Some(ValueExpr::Now {
            offset: Some(Duration::days(7))
        })
    );

    assert_eq!(aspect.views["board"].kind, ViewKind::Board);
    assert_eq!(aspect.views["board"].query.as_deref(), Some("open"));
    assert_eq!(aspect.views["board"].group_by.as_deref(), Some("status"));
    assert_eq!(aspect.views["calendar"].kind, ViewKind::Calendar);
    assert_eq!(aspect.views["list"].kind, ViewKind::List);
    assert_eq!(aspect.views["form"].kind, ViewKind::Form);
    assert!(aspect.views["form"].query.is_none());

    assert_eq!(
        aspect.operations["detach_occurrence"],
        OperationBinding {
            tool: "agenda".into(),
            method: "detach-occurrence".into()
        }
    );
    assert_eq!(aspect.operations.len(), 2);
}

#[test]
fn e1_default_is_optional_and_unknown_keys_are_rejected() {
    let s = load("optional:\n  x:\n    type: string\n").expect("default may be omitted");
    assert!(s.optional["x"].default.is_none());

    for (why, yaml) in [
        (
            "unknown field key",
            "optional:\n  x:\n    type: string\n    aspekt: typo\n",
        ),
        ("unknown top-level key", "widgets: []\noptional: {}\n"),
        ("key without aspect", "key: [status]\noptional: {}\n"),
        ("aspect without key", "aspect: agenda\noptional: {}\n"),
        (
            "transitions on a non-enum",
            "optional:\n  x:\n    type: string\n    transitions:\n      a: [b]\n",
        ),
        (
            "transition to an undeclared variant",
            "optional:\n  x:\n    type: [a, b]\n    transitions:\n      a: [c]\n",
        ),
        (
            "ensure against an undeclared field",
            "optional:\n  x:\n    type: datetime\n    ensure: { gt: nope }\n",
        ),
        (
            "view of an undeclared query",
            "aspect: a\nkey: [x]\noptional:\n  x:\n    type: string\nviews:\n  v: { kind: list, query: missing }\n",
        ),
        (
            "unknown view kind",
            "aspect: a\nkey: [x]\noptional:\n  x:\n    type: string\nviews:\n  v: { kind: gantt }\n",
        ),
    ] {
        assert!(load(yaml).is_err(), "{why} must be rejected: {yaml}");
    }
}

#[test]
fn e1_expression_language_is_closed() {
    let base = "aspect: a\nkey: [x]\noptional:\n  x:\n    type: datetime\nqueries:\n  q:\n";
    for (why, tail) in [
        ("arithmetic other than +/- duration", "    any_between: [$now, $now * 2]\n"),
        ("undeclared arg", "    any_between: [$args.missing, $now]\n"),
        ("unknown variable", "    any_between: [$today, $now]\n"),
        ("bad duration unit", "    any_between: [$now, $now + 3y]\n"),
        (
            "where on an undeclared field",
            "    where: { nope: 1 }\n",
        ),
    ] {
        assert!(
            load(&format!("{base}{tail}")).is_err(),
            "{why} must be rejected: {tail}"
        );
    }
    let ok = load(&format!(
        "{base}    args: {{ from: datetime }}\n    any_between: [$args.from - 30m, $args.from + 2h]\n"
    ))
    .expect("declared arg with duration offsets");
    assert_eq!(
        ok.aspects["a"].queries["q"].any_between.as_ref().unwrap().0,
        ValueExpr::Arg {
            name: "from".into(),
            offset: Some(-Duration::minutes(30))
        }
    );
}

#[test]
fn e1_schema_hash_is_content_addressed() {
    let a = agenda().schema_hash();
    let b = agenda().schema_hash();
    assert_eq!(a, b);
    assert_eq!(a.len(), 64);
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    let changed = load(&AGENDA_YAML.replace("done: [todo]", "done: [todo, doing]"))
        .unwrap()
        .schema_hash();
    assert_ne!(a, changed, "a transition change changes the hash");
}

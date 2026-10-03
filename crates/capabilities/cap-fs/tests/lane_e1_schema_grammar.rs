//! Lane E1 — meta-schema v2 grammar: the shipped
//! `packs/agenda` aspect file is parsed key by key, `default` is optional, unknown keys are
//! rejected, the expression language is closed, and the schema hash is content-addressed.
//! Views carry their columns and order, each aspect its presentation (`display`), and both
//! are checked against the aspect's own fields and views.

use std::path::PathBuf;

use advance_shared_types::entity::OrderKey;
use cap_fs::meta_schema::{
    AspectDisplay, Cmp, DeriveElse, DisplayFormat, EnsureRule, FieldType, MetaSchema,
    MetaSchemaError, MetaSchemaLoader, OperationBinding, Tone, ValueDisplay, ValueExpr,
    ViewDisplay, ViewKind, WhereClause,
};
use chrono::Duration;

const AGENDA_YAML: &str =
    include_str!("../../../../packs/agenda/meta-schema-extensions/agenda.yaml");

/// A pack-form aspect that uses every view and presentation key.
const PRESENTED: &str = "\
aspect: tasks
key: [status]
fields:
  status:
    type: [todo, doing, done, cancelled]
  due:
    type: datetime
  priority:
    type: integer
  assignee:
    type: string
  labels:
    type: list<string>
  estimate:
    type: duration
queries:
  open:
    where: { status: [todo, doing] }
    order: [due asc, priority desc]
  upcoming:
    any_between: [$now, $now + 7d]
    order: [due asc]
views:
  list:
    kind: list
    query: open
    columns: [title, status, due, priority, assignee]
  board:
    kind: board
    query: open
    group_by: status
    order: [priority desc, due asc]
    columns: [title, due, assignee]
  calendar:
    kind: calendar
    query: upcoming
    columns: [title, status]
  form:
    kind: form
    columns: [title, status, due, priority, assignee, labels, estimate]
display:
  label: Tasks
  icon: list-checks
  default_view: list
  view_order: [list, board, calendar]
  views:
    list: { label: Open, icon: list-todo }
    board: { label: Board, icon: kanban }
  fields:
    title: { label: Title }
    updated_at: { format: relative, label: Updated }
    status:
      format: badge
      label: Status
      values:
        todo: { tone: neutral, label: To do }
        doing: { tone: info, label: In progress }
        done: { tone: success, label: Done, icon: check }
        cancelled: { tone: muted }
    due: { format: date, label: Due, icon: calendar }
    priority: { format: priority }
    assignee: { format: person, icon: user }
    labels: { format: tags }
    estimate: { format: duration }
";

/// An aspect with fields of several types and one query; the malformed-presentation cases add
/// their own `views:` and `display:` blocks. `note` belongs to the entry vocabulary.
const BASE: &str = "\
optional:
  note:
    type: string
aspect: t
key: [status]
fields:
  status:
    type: [todo, doing, done]
  due:
    type: datetime
  tags:
    type: list<string>
  owner:
    type: string
  rank:
    type: integer
queries:
  open:
    where: { status: [todo, doing] }
";

/// Well-formed views over [`BASE`]: a list, a board and a form.
const VIEWS: &str = "  l: { kind: list, query: open }\n  b: { kind: board, query: open, group_by: status }\n  f: { kind: form }\n";

/// [`BASE`] plus the given (indented) `views:` and `display:` blocks; an empty block is left out.
fn with_views_and_display(views: &str, display: &str) -> String {
    let mut doc = BASE.to_string();
    if !views.is_empty() {
        doc.push_str("views:\n");
        doc.push_str(views);
    }
    if !display.is_empty() {
        doc.push_str("display:\n");
        doc.push_str(display);
    }
    doc
}

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
    // Aspect fields are namespaced under their aspect: the `.meta.yaml` entry vocabulary
    // (`optional`) is untouched, so an entry `status` and an agenda `status` cannot collide.
    assert!(s.optional.is_empty());
    let fields = &aspect.fields;

    let status = &fields["status"];
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

    assert_eq!(fields["due"].field_type, FieldType::DateTime);
    assert_eq!(fields["exdates"].field_type, FieldType::ListDateTime);
    assert_eq!(fields["priority"].field_type, FieldType::Integer);
    assert!(fields["assignee"].inherit);
    assert!(!fields["due"].inherit);

    let derive = fields["completed_at"]
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
        fields["ends"].ensure,
        Some(EnsureRule {
            op: Cmp::Gt,
            field: "starts".into()
        })
    );
    assert_eq!(fields.len(), 11, "{:?}", fields.keys());
    assert_eq!(s.aspect_field("status"), Some(&fields["status"]));
    assert_eq!(s.record_field("nope"), None);
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
            "aspect: a\nkey: [x]\nfields:\n  x:\n    type: string\nviews:\n  v: { kind: list, query: missing }\n",
        ),
        (
            "unknown view kind",
            "aspect: a\nkey: [x]\nfields:\n  x:\n    type: string\nviews:\n  v: { kind: gantt }\n",
        ),
        (
            "key field not declared",
            "aspect: a\nkey: [nope]\nfields:\n  x:\n    type: string\n",
        ),
        (
            "two aspects disagree on a shared field",
            "aspects:\n  a:\n    key: [x]\n    fields:\n      x:\n        type: string\n  b:\n    key: [x]\n    fields:\n      x:\n        type: integer\n",
        ),
    ] {
        assert!(load(yaml).is_err(), "{why} must be rejected: {yaml}");
    }
}

#[test]
fn e1_expression_language_is_closed() {
    let base = "aspect: a\nkey: [x]\nfields:\n  x:\n    type: datetime\nqueries:\n  q:\n";
    for (why, tail) in [
        (
            "arithmetic other than +/- duration",
            "    any_between: [$now, $now * 2]\n",
        ),
        ("undeclared arg", "    any_between: [$args.missing, $now]\n"),
        ("unknown variable", "    any_between: [$today, $now]\n"),
        ("bad duration unit", "    any_between: [$now, $now + 3y]\n"),
        ("where on an undeclared field", "    where: { nope: 1 }\n"),
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

#[test]
fn e1_views_carry_order_columns_and_presentation() {
    let s = load(PRESENTED).expect("every view and presentation key parses");
    let aspect = &s.aspects["tasks"];

    let board = &aspect.views["board"];
    assert_eq!(board.group_by.as_deref(), Some("status"));
    assert_eq!(
        board.order,
        vec![
            OrderKey {
                field: "priority".into(),
                ascending: false
            },
            OrderKey {
                field: "due".into(),
                ascending: true
            },
        ]
    );
    assert_eq!(board.columns, ["title", "due", "assignee"]);
    let list = &aspect.views["list"];
    assert!(
        list.order.is_empty(),
        "no view order: the query's own applies"
    );
    assert_eq!(
        list.columns,
        ["title", "status", "due", "priority", "assignee"]
    );
    assert_eq!(aspect.views["form"].columns.len(), 7);

    let d = &aspect.display;
    assert_eq!(d.label.as_deref(), Some("Tasks"));
    assert_eq!(d.icon.as_deref(), Some("list-checks"));
    assert_eq!(d.default_view.as_deref(), Some("list"));
    assert_eq!(d.view_order, ["list", "board", "calendar"]);
    assert_eq!(
        d.views["board"],
        ViewDisplay {
            label: Some("Board".into()),
            icon: Some("kanban".into())
        }
    );
    assert!(
        !d.views.contains_key("calendar"),
        "a view may go without a label or icon"
    );

    let status = &d.fields["status"];
    assert_eq!(status.format, Some(DisplayFormat::Badge));
    assert_eq!(status.label.as_deref(), Some("Status"));
    assert_eq!(status.values.len(), 4);
    assert_eq!(status.values["todo"].tone, Some(Tone::Neutral));
    assert_eq!(status.values["doing"].tone, Some(Tone::Info));
    assert_eq!(
        status.values["done"],
        ValueDisplay {
            tone: Some(Tone::Success),
            label: Some("Done".into()),
            icon: Some("check".into())
        }
    );
    assert_eq!(
        status.values["cancelled"],
        ValueDisplay {
            tone: Some(Tone::Muted),
            label: None,
            icon: None
        }
    );
    assert_eq!(d.fields["due"].format, Some(DisplayFormat::Date));
    assert_eq!(d.fields["due"].icon.as_deref(), Some("calendar"));
    assert_eq!(d.fields["priority"].format, Some(DisplayFormat::Priority));
    assert_eq!(d.fields["assignee"].format, Some(DisplayFormat::Person));
    assert_eq!(d.fields["labels"].format, Some(DisplayFormat::Tags));
    assert_eq!(d.fields["estimate"].format, Some(DisplayFormat::Duration));
    assert!(d.fields["priority"].values.is_empty());
    // Promoted columns take presentation too, checked against their fixed types.
    assert_eq!(d.fields["title"].label.as_deref(), Some("Title"));
    assert_eq!(d.fields["updated_at"].format, Some(DisplayFormat::Relative));

    let bare = load("aspect: a\nkey: [x]\nfields:\n  x:\n    type: string\n").unwrap();
    assert_eq!(bare.aspects["a"].display, AspectDisplay::default());
}

#[test]
fn e1_view_presentation_is_rejected_when_malformed() {
    load(&with_views_and_display(VIEWS, "  label: T\n")).expect("the base document parses");

    let many_columns = format!(
        "  l: {{ kind: list, query: open, columns: [{}] }}\n",
        vec!["owner"; 65].join(", ")
    );
    let long_label = format!("  label: {}\n", "x".repeat(65));
    let cases: [(&str, &str, &str, &str); 48] = [
        // Views.
        (
            "a board without group_by",
            "  b: { kind: board, query: open }\n",
            "",
            "a board needs `group_by`",
        ),
        (
            "a board grouped by a non-enum field",
            "  b: { kind: board, query: open, group_by: owner }\n",
            "",
            "a board groups by an enum field",
        ),
        (
            "a board grouped by a promoted column",
            "  b: { kind: board, query: open, group_by: title }\n",
            "",
            "group_by references undeclared field \"title\"",
        ),
        (
            "group_by on a calendar",
            "  c: { kind: calendar, query: open, group_by: status }\n",
            "",
            "a calendar takes no group_by",
        ),
        (
            "group_by on a form",
            "  f: { kind: form, group_by: status }\n",
            "",
            "a form takes no group_by",
        ),
        (
            "a list grouped by a list field",
            "  l: { kind: list, query: open, group_by: tags }\n",
            "",
            "cannot group by the list field tags",
        ),
        (
            "order on a form",
            "  f: { kind: form, order: [due asc] }\n",
            "",
            "a form takes no order",
        ),
        (
            "order on a calendar",
            "  c: { kind: calendar, query: open, order: [due asc] }\n",
            "",
            "a calendar takes no order",
        ),
        (
            "order on an undeclared field",
            "  l: { kind: list, query: open, order: [nope asc] }\n",
            "",
            "order references undeclared field \"nope\"",
        ),
        (
            "order on a field of the entry vocabulary",
            "  l: { kind: list, query: open, order: [note] }\n",
            "",
            "order references undeclared field \"note\"",
        ),
        (
            "more than four order keys",
            "  l: { kind: list, query: open, order: [due, rank, owner, status, title] }\n",
            "",
            "at most 4 order keys, got 5",
        ),
        (
            "the same field ordered twice",
            "  l: { kind: list, query: open, order: [due asc, due desc] }\n",
            "",
            "order lists the field due twice",
        ),
        (
            "a bad order direction",
            "  l: { kind: list, query: open, order: [due up] }\n",
            "",
            "order direction must be asc / desc",
        ),
        (
            "a column listed twice",
            "  l: { kind: list, query: open, columns: [owner, due, owner] }\n",
            "",
            "column owner is listed twice",
        ),
        (
            "more than 64 columns",
            many_columns.as_str(),
            "",
            "at most 64 columns, got 65",
        ),
        (
            "a form editing the entity type",
            "  f: { kind: form, columns: [title, type] }\n",
            "",
            "a form cannot edit type",
        ),
        (
            "a form editing the modification time",
            "  f: { kind: form, columns: [updated_at] }\n",
            "",
            "a form cannot edit updated_at",
        ),
        (
            "an unknown view key",
            "  l: { kind: list, query: open, sort: [due] }\n",
            "",
            "unknown field `sort`",
        ),
        // Presentation.
        (
            "an unknown format",
            VIEWS,
            "  fields:\n    owner: { format: currency }\n",
            "unknown format \"currency\"",
        ),
        (
            "tags on a datetime field",
            VIEWS,
            "  fields:\n    due: { format: tags }\n",
            "format tags does not suit a datetime field",
        ),
        (
            "tags on the promoted updated_at column",
            VIEWS,
            "  fields:\n    updated_at: { format: tags }\n",
            "format tags does not suit a datetime field",
        ),
        (
            "a checkbox on the promoted title column",
            VIEWS,
            "  fields:\n    title: { format: checkbox }\n",
            "format checkbox does not suit a string field",
        ),
        (
            "a color name as a tone",
            VIEWS,
            "  fields:\n    status:\n      values:\n        todo: { tone: red }\n",
            "unknown tone \"red\"",
        ),
        (
            "a color code as a tone",
            VIEWS,
            "  fields:\n    status:\n      values:\n        todo: { tone: \"#00ff00\" }\n",
            "unknown tone \"#00ff00\"",
        ),
        (
            "danger instead of error",
            VIEWS,
            "  fields:\n    status:\n      values:\n        todo: { tone: danger }\n",
            "unknown tone \"danger\"",
        ),
        (
            "values on a non-enum field",
            VIEWS,
            "  fields:\n    owner:\n      values:\n        a: { tone: info }\n",
            "values are only for enum fields; owner is a string field",
        ),
        (
            "values on a promoted column",
            VIEWS,
            "  fields:\n    title:\n      values:\n        a: { label: A }\n",
            "values are only for enum fields; title is a string field",
        ),
        (
            "a value that is not a variant",
            VIEWS,
            "  fields:\n    status:\n      values:\n        blocked: { tone: warning }\n",
            "\"blocked\" is not a variant of status",
        ),
        (
            "presentation of an undeclared field",
            VIEWS,
            "  fields:\n    nope: { label: Nope }\n",
            "fields.nope is not a field of the aspect",
        ),
        (
            "presentation of an entry-vocabulary field",
            VIEWS,
            "  fields:\n    note: { label: Note }\n",
            "fields.note is not a field of the aspect",
        ),
        (
            "presentation of an undeclared view",
            VIEWS,
            "  views:\n    nope: { label: Nope }\n",
            "views.nope is not a declared view",
        ),
        (
            "an undeclared default view",
            VIEWS,
            "  default_view: nope\n",
            "default_view \"nope\" is not a declared view",
        ),
        (
            "a form as the default view",
            VIEWS,
            "  default_view: f\n",
            "default_view f is a form",
        ),
        (
            "view_order naming an undeclared view",
            VIEWS,
            "  view_order: [l, nope]\n",
            "view_order names \"nope\", which is not a declared view",
        ),
        (
            "view_order listing a view twice",
            VIEWS,
            "  view_order: [l, b, l]\n",
            "view_order lists l twice",
        ),
        (
            "a label with a newline",
            VIEWS,
            "  label: \"Ta\\nsks\"\n",
            "label contains the refused character U+000A",
        ),
        (
            "a label with a bidi override",
            VIEWS,
            "  label: \"Ta\\u202Esks\"\n",
            "label contains the refused character U+202E",
        ),
        (
            "a label with markup",
            VIEWS,
            "  views:\n    l: { label: \"<b>Open</b>\" }\n",
            "label contains the refused character U+003C",
        ),
        (
            "a label longer than 64 characters",
            VIEWS,
            long_label.as_str(),
            "label is longer than 64 characters",
        ),
        (
            "a blank label",
            VIEWS,
            "  fields:\n    owner: { label: \" \" }\n",
            "label must not be blank",
        ),
        (
            "a value label with a control character",
            VIEWS,
            "  fields:\n    status:\n      values:\n        todo: { label: \"To\\tdo\" }\n",
            "values.todo: label contains the refused character U+0009",
        ),
        (
            "a capitalized icon",
            VIEWS,
            "  icon: Calendar\n",
            "icon \"Calendar\" must be lowercase",
        ),
        (
            "an icon with a space",
            VIEWS,
            "  fields:\n    status:\n      values:\n        done: { icon: cal endar }\n",
            "icon \"cal endar\" must be lowercase",
        ),
        (
            "an unknown display key",
            VIEWS,
            "  colour: red\n",
            "unknown field `colour`",
        ),
        (
            "an unknown key in a view's presentation",
            VIEWS,
            "  views:\n    l: { order: 1 }\n",
            "unknown field `order`",
        ),
        (
            "an unknown key in a field's presentation",
            VIEWS,
            "  fields:\n    owner: { width: 3 }\n",
            "unknown field `width`",
        ),
        (
            "an unknown key in a value's presentation",
            VIEWS,
            "  fields:\n    status:\n      values:\n        todo: { color: red }\n",
            "unknown field `color`",
        ),
        (
            "an icon on a view that is not declared",
            VIEWS,
            "  views:\n    c: { icon: calendar }\n",
            "views.c is not a declared view",
        ),
    ];
    for (why, views, display, expected) in cases {
        let doc = with_views_and_display(views, display);
        match load(&doc) {
            Ok(_) => panic!("{why} must be rejected:\n{doc}"),
            Err(e) => assert!(
                e.to_string().contains(expected),
                "{why}: expected {expected:?} in: {e}"
            ),
        }
    }

    let err = load("optional:\n  x:\n    type: string\ndisplay:\n  label: X\n").unwrap_err();
    assert!(
        err.to_string().contains("need a top-level `aspect:`"),
        "display without an aspect: {err}"
    );
}

#[test]
fn e1_presentation_changes_the_schema_hash() {
    let base = load(PRESENTED).unwrap().schema_hash();
    assert_eq!(base, load(PRESENTED).unwrap().schema_hash());
    for (why, from, to) in [
        ("a tone", "doing: { tone: info,", "doing: { tone: warning,"),
        (
            "a view's order",
            "order: [priority desc, due asc]",
            "order: [priority asc, due asc]",
        ),
        (
            "the view order",
            "view_order: [list, board, calendar]",
            "view_order: [board, list, calendar]",
        ),
        (
            "the default view",
            "default_view: list",
            "default_view: board",
        ),
        ("the aspect label", "label: Tasks", "label: Work"),
        ("a view icon", "icon: kanban", "icon: columns"),
        (
            "a field format",
            "due: { format: date,",
            "due: { format: datetime,",
        ),
        (
            "a view's columns",
            "columns: [title, due, assignee]",
            "columns: [title, assignee, due]",
        ),
    ] {
        assert_eq!(
            PRESENTED.matches(from).count(),
            1,
            "{why}: the fixture holds {from:?} once"
        );
        let changed = load(&PRESENTED.replace(from, to))
            .unwrap_or_else(|e| panic!("{why}: {e}"))
            .schema_hash();
        assert_ne!(base, changed, "changing {why} changes the hash");
    }
}

#[test]
fn e1_two_aspects_may_present_a_shared_field_differently() {
    let doc = "\
aspects:
  tasks:
    key: [state]
    fields:
      state:
        type: [open, closed]
    display:
      fields:
        state:
          label: Task state
          values:
            open: { tone: info }
  bugs:
    key: [state]
    fields:
      state:
        type: [open, closed]
    display:
      label: Bugs
      fields:
        state:
          format: badge
          values:
            open: { tone: error, label: Open bug }
";
    let s = load(doc).expect("presentation is not part of a shared field's identity");
    let (tasks, bugs) = (&s.aspects["tasks"], &s.aspects["bugs"]);
    assert_eq!(tasks.fields["state"], bugs.fields["state"]);
    assert_eq!(
        tasks.display.fields["state"].values["open"].tone,
        Some(Tone::Info)
    );
    assert_eq!(tasks.display.fields["state"].format, None);
    assert_eq!(
        bugs.display.fields["state"].values["open"].tone,
        Some(Tone::Error)
    );
    assert_eq!(
        bugs.display.fields["state"].format,
        Some(DisplayFormat::Badge)
    );
    assert_eq!(bugs.display.label.as_deref(), Some("Bugs"));
}

#[test]
fn e1_query_and_operation_names_belong_to_one_aspect() {
    let two_aspects = |a_extra: &str, b_extra: &str| {
        format!(
            "aspects:\n  a:\n    key: [x]\n    fields:\n      x:\n        type: string\n{a_extra}  b:\n    key: [y]\n    fields:\n      y:\n        type: string\n{b_extra}"
        )
    };
    let open_a = "    queries:\n      open: { where: { x: a } }\n";
    let open_b = "    queries:\n      open: { where: { y: b } }\n";
    let err = load(&two_aspects(open_a, open_b)).unwrap_err();
    assert!(
        err.to_string()
            .contains("query open is declared by aspects a and b"),
        "{err}"
    );

    let close_a = "    operations:\n      close: { tool: a, method: close }\n";
    let close_b = "    operations:\n      close: { tool: b, method: close }\n";
    let err = load(&two_aspects(close_a, close_b)).unwrap_err();
    assert!(
        err.to_string()
            .contains("operation close is declared by aspects a and b"),
        "{err}"
    );

    // The pack form's aspect takes part as well.
    let with_pack_aspect = format!(
        "{}aspect: c\nkey: [z]\nfields:\n  z:\n    type: string\nqueries:\n  open: {{ where: {{ z: c }} }}\n",
        two_aspects(open_a, "")
    );
    let err = load(&with_pack_aspect).unwrap_err();
    assert!(
        err.to_string()
            .contains("query open is declared by aspects a and c"),
        "{err}"
    );

    // Distinct names parse, and a query may share its name with an operation.
    let s = load(&two_aspects(
        open_a,
        "    queries:\n      mine: { where: { y: b } }\n    operations:\n      open: { tool: b, method: open }\n",
    ))
    .expect("distinct query names");
    assert!(s.aspects["a"].queries.contains_key("open"));
    assert!(s.aspects["b"].operations.contains_key("open"));
}

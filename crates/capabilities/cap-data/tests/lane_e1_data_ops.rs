//! Lane E1 — `DataStore` operations, the `apply` transaction and the `data` host tool over a
//! temp workspace. The schema is the shipped
//! `packs/agenda` aspect; the in-memory `EntityIndex`, a plain-directory `WorkspaceFs`, a fixed
//! clock, a recording event sink and a scripted reducer are the doubles the crate ships under
//! `test-support`.

use std::path::PathBuf;
use std::sync::Arc;

use advance_shared_types::entity::{EntityQuery, OrderKey};
use cap_data::test_support::{
    agenda_schema, AllowAll, DenyAll, DirWorkspaceFs, FixedClock, FsScoped, MemoryEntityIndex,
    RecordingEvents, ScriptedReducer, SequentialIds,
};
use cap_data::{
    DataError, DataStore, DataTool, IdempotencyKey, PatchOp, QueryRequest, Record, Target, Tier,
    MAX_EFFECTS_PER_APPLY, MAX_ITEMS_PER_FILE,
};
use cap_fs::meta_schema::MetaSchemaLoader;
use cap_tools::{HostTool, ToolError};
use serde_json::{json, Value};

const PROJECT: &str = "---\nid: e-01J9K3ZQ7A00000000000000\ntype: project\ntitle: Launch\nassignee: agent:alice\n---\n# Launch\n\nprose stays untouched\n";
const NOW: &str = "2026-09-17T08:00:00Z";

fn store(ws: &tempfile::TempDir) -> (DataStore, Arc<RecordingEvents>) {
    std::fs::write(ws.path().join("launch.md"), PROJECT).unwrap();
    let events = Arc::new(RecordingEvents::default());
    let s = DataStore::new(
        Arc::new(DirWorkspaceFs::new(ws.path().to_path_buf())),
        Arc::new(MemoryEntityIndex::default()),
        agenda_schema(),
        Arc::new(SequentialIds::default()),
        Arc::new(FixedClock::at(NOW)),
    )
    .with_events(events.clone());
    (s, events)
}

async fn open_count(s: &DataStore) -> usize {
    s.query("alice", QueryRequest::named("open", Value::Null))
        .await
        .unwrap()
        .len()
}

fn launch() -> Target {
    Target::Path("launch.md".into())
}

fn item(title: &str, status: &str) -> Record {
    Record::from_json(json!({ "type": "work-item", "title": title, "status": status }))
}

fn read(ws: &tempfile::TempDir) -> String {
    std::fs::read_to_string(ws.path().join("launch.md")).unwrap()
}

// ── create / get ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn e1_create_inline_item_assigns_id_keeps_body_and_emits_one_event() {
    let ws = tempfile::TempDir::new().unwrap();
    let (s, events) = store(&ws);
    let id = s
        .create(
            "alice",
            launch(),
            Record::from_json(json!({
                "type": "work-item", "title": "完成 SDK 再生成", "status": "todo",
                "due": "2026-09-20T18:00:00+08:00"
            })),
        )
        .await
        .expect("create");
    assert!(id.0.starts_with("e-"), "{id:?}");
    let text = read(&ws);
    assert!(
        text.ends_with("# Launch\n\nprose stays untouched\n"),
        "body preserved"
    );
    assert!(
        text.contains("items:\n"),
        "inline item in frontmatter: {text}"
    );

    let row = s
        .get(
            "alice",
            Target::Anchored {
                path: "launch.md".into(),
                id: id.clone(),
            },
        )
        .await
        .unwrap();
    assert_eq!(row.status.as_deref(), Some("todo"));
    assert_eq!(
        row.aspects,
        vec!["agenda".to_string()],
        "status present ⇒ agenda"
    );
    assert_eq!(
        row.fields["assignee"],
        json!("agent:alice"),
        "inherited from the parent file (effective value)"
    );
    let emitted = events.snapshot();
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0].event_type, "data.entity_changed");
    assert_eq!(emitted[0].payload["op"], json!("create"));
    assert_eq!(emitted[0].payload["entity_id"], json!(id.0));
    assert_eq!(emitted[0].payload["path"], json!("launch.md"));
    assert!(emitted[0].payload["commit"].is_string());

    let plain = s
        .create(
            "alice",
            launch(),
            Record::from_json(json!({ "type": "note", "title": "n" })),
        )
        .await
        .unwrap();
    let row = s
        .get(
            "alice",
            Target::Anchored {
                path: "launch.md".into(),
                id: plain,
            },
        )
        .await
        .unwrap();
    assert!(
        row.aspects.is_empty(),
        "neither status nor starts ⇒ not an agenda item"
    );
}

// ── patch: canonical, fail-closed, transitions, derive, ensure ───────────────────────────────

#[tokio::test]
async fn e1_patch_is_field_level_canonical_and_fail_closed() {
    let ws = tempfile::TempDir::new().unwrap();
    let (s, _) = store(&ws);
    let id = s
        .create("alice", launch(), item("t", "todo"))
        .await
        .unwrap();
    let target = Target::Anchored {
        path: "launch.md".into(),
        id,
    };
    s.patch(
        "alice",
        target.clone(),
        vec![PatchOp::Set("status".into(), json!("doing"))],
    )
    .await
    .unwrap();
    let once = read(&ws);
    s.patch(
        "alice",
        target.clone(),
        vec![PatchOp::Set("priority".into(), json!(2))],
    )
    .await
    .unwrap();
    let twice = read(&ws);
    // Inline items are `- key: value` sequences whose keys sit at two spaces.
    assert_eq!(
        once.replace("status: doing\n", "status: doing\n  priority: 2\n")
            .len(),
        twice.len(),
        "nothing else reordered or reformatted: {once} vs {twice}"
    );
    let err = s
        .patch(
            "alice",
            target,
            vec![PatchOp::Set("priority".into(), json!("high"))],
        )
        .await
        .unwrap_err();
    assert!(matches!(err, DataError::Invalid(_)), "{err:?}");
    assert_eq!(
        read(&ws),
        twice,
        "schema violation leaves the file untouched"
    );
}

#[tokio::test]
async fn e1_patch_enforces_transitions_and_derives_completed_at() {
    let ws = tempfile::TempDir::new().unwrap();
    let (s, events) = store(&ws);
    let id = s
        .create("alice", launch(), item("t", "doing"))
        .await
        .unwrap();
    let target = Target::Anchored {
        path: "launch.md".into(),
        id,
    };

    let done = s
        .patch(
            "alice",
            target.clone(),
            vec![PatchOp::Set("status".into(), json!("done"))],
        )
        .await
        .unwrap();
    assert_eq!(
        done.fields["completed_at"],
        json!(NOW),
        "derived from the fixed clock"
    );
    assert!(read(&ws).contains(&format!("completed_at: {NOW}\n")));

    let err = s
        .patch(
            "alice",
            target.clone(),
            vec![PatchOp::Set("status".into(), json!("doing"))],
        )
        .await
        .unwrap_err();
    assert!(
        matches!(&err, DataError::Transition { from, to, .. } if from == "done" && to == "doing"),
        "{err:?}"
    );

    let reopened = s
        .patch(
            "alice",
            target.clone(),
            vec![PatchOp::Set("status".into(), json!("todo"))],
        )
        .await
        .unwrap();
    assert!(
        reopened.fields.get("completed_at").is_none(),
        "`else: unset`"
    );
    assert_eq!(
        events
            .snapshot()
            .iter()
            .filter(|e| e.payload["op"] == json!("patch"))
            .count(),
        2,
        "one event per successful patch, none for the rejected one"
    );
}

#[tokio::test]
async fn e1_ensure_rejects_ends_before_starts() {
    let ws = tempfile::TempDir::new().unwrap();
    let (s, _) = store(&ws);
    let err = s
        .create(
            "alice",
            launch(),
            Record::from_json(json!({
                "type": "meeting", "title": "m",
                "starts": "2026-09-22T10:00:00Z", "ends": "2026-09-22T09:00:00Z"
            })),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, DataError::Invalid(_)), "{err:?}");
    assert_eq!(read(&ws), PROJECT, "nothing written");
}

// ── tiers ────────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn e1_items_cap_forces_promotion() {
    let ws = tempfile::TempDir::new().unwrap();
    let (s, _) = store(&ws);
    for i in 0..MAX_ITEMS_PER_FILE {
        s.create("alice", launch(), item(&format!("t{i}"), "todo"))
            .await
            .unwrap();
    }
    let err = s
        .create("alice", launch(), item("one too many", "todo"))
        .await
        .unwrap_err();
    assert!(matches!(err, DataError::PromoteRequired { .. }), "{err:?}");
}

#[tokio::test]
async fn e1_promote_and_demote_keep_id_and_move_index_path() {
    let ws = tempfile::TempDir::new().unwrap();
    let (s, _) = store(&ws);
    let id = s
        .create("alice", launch(), item("法务对齐", "doing"))
        .await
        .unwrap();
    let file = s
        .promote(
            "alice",
            Target::Anchored {
                path: "launch.md".into(),
                id: id.clone(),
            },
            Tier::File,
        )
        .await
        .expect("promote to file");
    let Target::Path(path) = file.clone() else {
        panic!("expected a file target, got {file:?}")
    };
    assert!(ws.path().join(&path).is_file());
    let parent = read(&ws);
    assert!(
        parent.contains(&format!("id: {}\n", id.0)) && parent.contains("ref: "),
        "parent keeps a ref: {parent}"
    );
    let row = s.get("alice", file.clone()).await.unwrap();
    assert_eq!(row.id, id, "identity survives promotion");
    assert_eq!(row.path, path);

    let back = s.demote("alice", file).await.expect("demote");
    assert!(matches!(back, Target::Anchored { .. }));
    assert!(!ws.path().join(&path).exists());
    assert_eq!(s.get("alice", back).await.unwrap().id, id);
}

// ── queries ──────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn e1_named_and_ad_hoc_queries() {
    let ws = tempfile::TempDir::new().unwrap();
    let (s, _) = store(&ws);
    s.create("alice", launch(), Record::from_json(json!({ "type": "work-item", "title": "soon", "status": "todo", "due": "2026-09-22T09:00:00Z" }))).await.unwrap();
    s.create("alice", launch(), Record::from_json(json!({ "type": "work-item", "title": "later", "status": "todo", "due": "2026-12-01T00:00:00Z" }))).await.unwrap();
    s.create("alice", launch(), Record::from_json(json!({ "type": "meeting", "title": "sync", "starts": "2026-09-22T02:00:00Z", "ends": "2026-09-22T03:00:00Z" }))).await.unwrap();
    s.create(
        "alice",
        launch(),
        Record::from_json(json!({ "type": "work-item", "title": "finished", "status": "done" })),
    )
    .await
    .unwrap();

    let day = s
        .query(
            "alice",
            QueryRequest::named("day", json!({ "day": "2026-09-22" })),
        )
        .await
        .expect("named query");
    let titles: Vec<_> = day.iter().map(|r| r.title.clone().unwrap()).collect();
    assert_eq!(
        titles,
        vec!["sync", "soon"],
        "starts asc then due asc; both kinds in the window"
    );

    let open = s
        .query("alice", QueryRequest::named("open", json!({})))
        .await
        .unwrap();
    assert_eq!(open.len(), 2, "done is excluded by the query's where");

    let mut q = EntityQuery::for_agent("alice");
    q.aspect = Some("agenda".into());
    assert_eq!(
        s.query("alice", QueryRequest::ad_hoc(q))
            .await
            .unwrap()
            .len(),
        4
    );

    let err = s
        .query("alice", QueryRequest::named("nope", json!({})))
        .await
        .unwrap_err();
    assert!(matches!(err, DataError::Invalid(_)), "{err:?}");
    let err = s
        .query("alice", QueryRequest::named("day", json!({})))
        .await
        .unwrap_err();
    assert!(matches!(err, DataError::Invalid(_)), "missing arg: {err:?}");
    let mut q = EntityQuery::for_agent("alice");
    q.limit = 5000;
    assert!(matches!(
        s.query("alice", QueryRequest::ad_hoc(q)).await.unwrap_err(),
        DataError::Invalid(_)
    ));
}

#[tokio::test]
async fn e1_history_walks_the_record_not_the_file() {
    let ws = tempfile::TempDir::new().unwrap();
    let (s, _) = store(&ws);
    let id = s
        .create("alice", launch(), item("t", "todo"))
        .await
        .unwrap();
    let target = Target::Anchored {
        path: "launch.md".into(),
        id,
    };
    s.patch(
        "alice",
        target.clone(),
        vec![PatchOp::Set("status".into(), json!("doing"))],
    )
    .await
    .unwrap();
    s.patch(
        "alice",
        target.clone(),
        vec![PatchOp::Set("status".into(), json!("done"))],
    )
    .await
    .unwrap();
    let versions = s.history("alice", target, 10).await.unwrap();
    let statuses: Vec<_> = versions
        .iter()
        .map(|v| v.record["status"].as_str().unwrap_or("").to_string())
        .collect();
    assert_eq!(
        statuses,
        vec!["done", "doing", "todo"],
        "newest first, one entry per change"
    );
    assert_eq!(
        versions[0].op.as_deref(),
        Some("patch"),
        "the commit trailer names the op"
    );
}

// ── apply: reducer effects in one transaction, idempotent, fail-closed ───────────────────────

fn detach_effects(series: &str, at: &str) -> Value {
    json!({ "effects": [
        { "set": { "target": series, "field": "exdates", "value": [at] } },
        { "create": { "parent": "launch.md", "record": {
            "type": "meeting", "title": "sync (moved)", "starts": "2026-10-06T02:00:00Z", "ends": "2026-10-06T03:00:00Z"
        } } }
    ] })
}

#[tokio::test]
async fn e1_apply_runs_reducer_effects_atomically_and_idempotently() {
    let ws = tempfile::TempDir::new().unwrap();
    let (s, events) = store(&ws);
    let id = s
        .create(
            "alice",
            launch(),
            Record::from_json(json!({
                "type": "meeting", "title": "sync", "starts": "2026-09-21T02:00:00Z",
                "ends": "2026-09-21T03:00:00Z", "repeat": "FREQ=WEEKLY;BYDAY=MO"
            })),
        )
        .await
        .unwrap();
    let series = format!("launch.md#{}", id.0);
    let reducer = Arc::new(
        ScriptedReducer::returning(detach_effects(&series, "2026-10-05T02:00:00Z"))
            .with_tool("skill::agenda"),
    );
    let s = s.with_reducer(reducer.clone());
    let before = events.snapshot().len();

    let result = s
        .apply(
            "alice",
            "detach_occurrence",
            Target::parse(&series).unwrap(),
            json!({ "at": "2026-10-05T02:00:00Z" }),
            Some(IdempotencyKey("k1".into())),
        )
        .await
        .expect("apply");
    assert_eq!(result.rows.len(), 2, "the series and the detached sibling");
    let text = read(&ws);
    assert!(text.contains("exdates:\n"), "{text}");
    assert!(text.contains("sync (moved)"), "{text}");
    assert_eq!(
        events.snapshot().len(),
        before + 1,
        "ONE event for the whole apply"
    );
    let ev = events.snapshot().pop().unwrap();
    assert_eq!(ev.payload["op"], json!("detach_occurrence"));
    assert_eq!(reducer.calls(), 1);
    let input = reducer.last_input().unwrap();
    assert_eq!(input["op"], json!("detach_occurrence"));
    assert_eq!(input["now"], json!(NOW), "clock is injected, never read");
    assert_eq!(input["ids"].as_array().map(|a| a.len()), Some(8));
    assert_eq!(input["self"]["repeat"], json!("FREQ=WEEKLY;BYDAY=MO"));
    assert_eq!(input["args"]["at"], json!("2026-10-05T02:00:00Z"));

    // Replay with the same key returns the recorded result without running the reducer again.
    let replay = s
        .apply(
            "alice",
            "detach_occurrence",
            Target::parse(&series).unwrap(),
            json!({ "at": "2026-10-05T02:00:00Z" }),
            Some(IdempotencyKey("k1".into())),
        )
        .await
        .unwrap();
    assert_eq!(replay, result);
    assert_eq!(reducer.calls(), 1);
    assert_eq!(read(&ws), text);
    // Same key, different request → refused.
    let err = s
        .apply(
            "alice",
            "detach_occurrence",
            Target::parse(&series).unwrap(),
            json!({ "at": "2026-10-12T02:00:00Z" }),
            Some(IdempotencyKey("k1".into())),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, DataError::Invalid(_)), "{err:?}");
}

#[tokio::test]
async fn e1_apply_is_fail_closed() {
    let ws = tempfile::TempDir::new().unwrap();
    let (s, events) = store(&ws);
    let id = s
        .create("alice", launch(), Record::from_json(json!({
            "type": "meeting", "title": "once", "starts": "2026-09-21T02:00:00Z", "ends": "2026-09-21T03:00:00Z"
        })))
        .await
        .unwrap();
    let target = Target::Anchored {
        path: "launch.md".into(),
        id,
    };
    let text = read(&ws);
    let n = events.snapshot().len();

    // No reducer wired at all → the operation is unavailable.
    let err = s
        .apply(
            "alice",
            "detach_occurrence",
            target.clone(),
            json!({}),
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, DataError::OpUnavailable(_)), "{err:?}");

    // Unknown operation name.
    let s = s.with_reducer(Arc::new(
        ScriptedReducer::returning(json!({ "error": "not a repeating event" }))
            .with_tool("skill::agenda"),
    ));
    let err = s
        .apply("alice", "explode", target.clone(), json!({}), None)
        .await
        .unwrap_err();
    assert!(matches!(err, DataError::OpUnavailable(_)), "{err:?}");

    // Reducer reports a precondition failure → typed error, nothing written.
    let err = s
        .apply(
            "alice",
            "detach_occurrence",
            target.clone(),
            json!({ "at": "x" }),
            None,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(&err, DataError::PreconditionFailed { op, reason } if op == "detach_occurrence" && reason.contains("repeating")),
        "{err:?}"
    );

    // Too many effects, and an effect aimed outside the transaction's records.
    let many: Vec<Value> = (0..=MAX_EFFECTS_PER_APPLY)
        .map(|i| json!({ "set": { "target": "launch.md", "field": "title", "value": format!("t{i}") } }))
        .collect();
    let s = s.with_reducer(Arc::new(
        ScriptedReducer::returning(json!({ "effects": many })).with_tool("skill::agenda"),
    ));
    assert!(matches!(
        s.apply(
            "alice",
            "detach_occurrence",
            target.clone(),
            json!({}),
            None
        )
        .await
        .unwrap_err(),
        DataError::Invalid(_)
    ));
    let s = s.with_reducer(Arc::new(
        ScriptedReducer::returning(json!({ "effects": [
            { "set": { "target": "elsewhere.md", "field": "title", "value": "pwned" } }
        ] }))
        .with_tool("skill::agenda"),
    ));
    assert!(matches!(
        s.apply("alice", "detach_occurrence", target, json!({}), None)
            .await
            .unwrap_err(),
        DataError::Forbidden(_)
    ));

    assert_eq!(read(&ws), text, "no failed apply touched the file");
    assert!(!ws.path().join("elsewhere.md").exists());
    assert_eq!(events.snapshot().len(), n, "no event for any failed apply");
}

// ── describe ─────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn e1_describe_reports_aspects_and_operation_availability() {
    let ws = tempfile::TempDir::new().unwrap();
    let (s, _) = store(&ws);
    let d = s.describe("alice").await;
    assert_eq!(d.hash.len(), 64);
    assert_eq!(d.aspects.len(), 1);
    let a = &d.aspects[0];
    assert_eq!(a.name, "agenda");
    assert_eq!(a.key, vec!["status".to_string(), "starts".to_string()]);
    assert_eq!(
        a.fields.len(),
        12,
        "11 declared fields and the presented `title` column"
    );
    let names: Vec<_> = a.queries.iter().map(|q| q.name.as_str()).collect();
    assert_eq!(names, vec!["day", "open", "overdue", "upcoming"]);
    assert_eq!(a.views.len(), 4);
    assert!(
        a.operations.iter().all(|o| !o.available),
        "no reducer, no tool: {:?}",
        a.operations
    );

    let s = s.with_reducer(Arc::new(
        ScriptedReducer::returning(json!({ "effects": [] })).with_tool("skill::agenda"),
    ));
    let d = s.describe("alice").await;
    assert!(d.aspects[0]
        .operations
        .iter()
        .all(|o| o.available && o.tool == "skill::agenda"));
}

fn order_key(field: &str, ascending: bool) -> OrderKey {
    OrderKey {
        field: field.into(),
        ascending,
    }
}

// The agenda pack's views and presentation, as `describe` hands them to clients and agents.
#[tokio::test]
async fn e1_describe_projects_view_presentation() {
    let ws = tempfile::TempDir::new().unwrap();
    let (s, _) = store(&ws);
    let d = s.describe("alice").await;
    let a = &d.aspects[0];
    assert_eq!(a.label.as_deref(), Some("Agenda"));
    assert_eq!(a.icon.as_deref(), Some("calendar-check"));
    assert_eq!(a.default_view.as_deref(), Some("list"));
    assert_eq!(a.view_order, ["list", "board", "calendar"]);

    let query = |name: &str| a.queries.iter().find(|q| q.name == name).unwrap();
    assert_eq!(
        query("open").order,
        [order_key("due", true), order_key("priority", false)]
    );
    assert_eq!(
        query("upcoming").order,
        [order_key("starts", true), order_key("due", true)]
    );

    let view = |name: &str| a.views.iter().find(|v| v.name == name).unwrap();
    let board = view("board");
    assert_eq!(board.group_by.as_deref(), Some("status"));
    assert_eq!(
        board.order,
        [order_key("priority", false), order_key("due", true)]
    );
    assert_eq!(board.columns, ["title", "due", "assignee", "priority"]);
    assert_eq!(
        (board.label.as_deref(), board.icon.as_deref()),
        (Some("Board"), Some("kanban"))
    );
    let calendar = view("calendar");
    assert!(
        calendar.order.is_empty(),
        "the calendar presents its query's own order"
    );
    assert_eq!(calendar.query.as_deref(), Some("upcoming"));
    assert_eq!(
        view("list").columns,
        ["title", "status", "due", "priority", "assignee"]
    );
    assert_eq!(view("form").label.as_deref(), Some("Details"));

    let field = |name: &str| a.fields.iter().find(|f| f.name == name).unwrap();
    let status = field("status")
        .display
        .as_ref()
        .expect("status is presented");
    assert_eq!(status.format.as_deref(), Some("badge"));
    assert_eq!(status.label.as_deref(), Some("Status"));
    let tones: Vec<(&str, Option<&str>)> = status
        .values
        .iter()
        .map(|v| (v.value.as_str(), v.tone.as_deref()))
        .collect();
    assert_eq!(
        tones,
        [
            ("todo", Some("neutral")),
            ("doing", Some("info")),
            ("done", Some("success")),
            ("cancelled", Some("muted")),
        ],
        "values come in the enum's declared order"
    );
    assert_eq!(status.values[2].icon.as_deref(), Some("check"));
    let due = field("due").display.as_ref().unwrap();
    assert_eq!(
        (due.format.as_deref(), due.icon.as_deref()),
        (Some("date"), Some("calendar"))
    );
    assert!(
        field("due").display.as_ref().unwrap().values.is_empty(),
        "values are for enum fields"
    );
    // A promoted column the aspect presents is listed under its fixed type; the others are not.
    let title = field("title");
    assert_eq!(title.r#type, "string");
    assert!(!title.derived && !title.inherit && title.r#enum.is_none());
    assert_eq!(
        title.display.as_ref().unwrap().label.as_deref(),
        Some("Title")
    );
    assert!(a
        .fields
        .iter()
        .all(|f| f.name != "type" && f.name != "updated_at"));
    let names: Vec<&str> = a.fields.iter().map(|f| f.name.as_str()).collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted, "fields are sorted by name");

    // An agent's `data.describe` carries the same presentation, with empty keys left out.
    let tool = DataTool::new(Arc::new(s), Arc::new(AllowAll));
    let out: Value = serde_json::from_slice(
        &tool
            .execute_as("alice", "describe", b"{}")
            .await
            .expect("describe"),
    )
    .unwrap();
    let agenda = &out["aspects"][0];
    assert_eq!(agenda["default_view"], "list");
    assert_eq!(agenda["view_order"], json!(["list", "board", "calendar"]));
    let named = |list: &str, name: &str| -> Value {
        agenda[list]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["name"] == name)
            .cloned()
            .unwrap()
    };
    assert_eq!(
        named("fields", "status")["display"]["values"][3],
        json!({ "value": "cancelled", "tone": "muted", "label": "Cancelled" })
    );
    assert_eq!(
        named("views", "board")["order"],
        json!([
            { "field": "priority", "ascending": false },
            { "field": "due", "ascending": true }
        ])
    );
    let calendar = named("views", "calendar");
    assert!(
        calendar.get("order").is_none(),
        "an empty order is left out: {calendar}"
    );
}

/// A store over an empty workspace whose whole schema is `yaml`.
fn store_over(ws: &tempfile::TempDir, yaml: &str) -> DataStore {
    let schema = MetaSchemaLoader::from_yaml(PathBuf::from("/nonexistent/meta-schema.yaml"), yaml)
        .expect("parses");
    DataStore::new(
        Arc::new(DirWorkspaceFs::new(ws.path().to_path_buf())),
        Arc::new(MemoryEntityIndex::default()),
        Arc::new(schema),
        Arc::new(SequentialIds::default()),
        Arc::new(FixedClock::at(NOW)),
    )
}

// An aspect that presents nothing describes as before: no presentation key is serialized, and
// a field or enum value whose presentation is empty is left out.
#[tokio::test]
async fn e1_describe_leaves_out_presentation_that_is_not_declared() {
    const PLAIN: &str = "\
aspect: tasks
key: [state]
fields:
  state:
    type: [open, shut]
  note:
    type: string
  due:
    type: datetime
queries:
  all: {}
views:
  rows: { kind: list, query: all }
display:
  fields:
    state:
      values:
        open: { tone: info }
        shut: {}
    note: {}
";
    let ws = tempfile::TempDir::new().unwrap();
    let d = store_over(&ws, PLAIN).describe("alice").await;
    let tasks = &d.aspects[0];
    assert_eq!(
        tasks
            .fields
            .iter()
            .map(|f| f.name.as_str())
            .collect::<Vec<_>>(),
        ["due", "note", "state"],
        "no promoted column is presented, so none is listed"
    );

    let out = serde_json::to_value(&d).unwrap();
    let tasks = &out["aspects"][0];
    for key in ["label", "icon", "default_view", "view_order"] {
        assert!(tasks.get(key).is_none(), "{key}: {tasks}");
    }
    assert!(tasks["queries"][0].get("order").is_none(), "{tasks}");
    let rows = &tasks["views"][0];
    for key in ["order", "label", "icon"] {
        assert!(rows.get(key).is_none(), "{key}: {rows}");
    }
    let fields = tasks["fields"].as_array().unwrap();
    assert!(fields[0].get("display").is_none(), "due: {}", fields[0]);
    assert!(
        fields[1].get("display").is_none(),
        "note (empty): {}",
        fields[1]
    );
    assert_eq!(
        fields[2]["display"],
        json!({ "values": [{ "value": "open", "tone": "info" }] }),
        "an empty value is left out"
    );
}

// Each promoted column an aspect presents is listed among its fields under the column's fixed
// type, sorted in with the declared ones: `type` is a string, `updated_at` a datetime the host
// maintains, so it is derived.
#[tokio::test]
async fn e1_describe_lists_presented_promoted_columns_under_their_fixed_types() {
    const COLUMNS: &str = "\
aspect: tasks
key: [state]
fields:
  state:
    type: [open, shut]
  zone:
    type: string
queries:
  all: {}
views:
  rows: { kind: list, query: all }
display:
  fields:
    updated_at: { format: relative }
    type: { label: Kind }
";
    let ws = tempfile::TempDir::new().unwrap();
    let d = store_over(&ws, COLUMNS).describe("alice").await;
    let tasks = &d.aspects[0];
    assert_eq!(
        tasks
            .fields
            .iter()
            .map(|f| f.name.as_str())
            .collect::<Vec<_>>(),
        ["state", "type", "updated_at", "zone"],
        "the presented columns sort in among the declared fields; `title` is not presented"
    );
    let field = |name: &str| tasks.fields.iter().find(|f| f.name == name).unwrap();

    let updated_at = field("updated_at");
    assert_eq!(updated_at.r#type, "datetime");
    assert!(updated_at.derived, "the host maintains `updated_at`");
    assert_eq!(
        updated_at.display.as_ref().unwrap().format.as_deref(),
        Some("relative")
    );

    let kind = field("type");
    assert_eq!(kind.r#type, "string");
    assert!(!kind.derived);
    assert_eq!(
        kind.display.as_ref().unwrap().label.as_deref(),
        Some("Kind")
    );

    for column in [updated_at, kind] {
        assert!(
            !column.inherit
                && column.r#enum.is_none()
                && column.default.is_none()
                && column.transitions.is_none(),
            "a promoted column has no field spec: {column:?}"
        );
    }
}

// ── the `data` host tool ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn e1_data_tool_describes_its_methods_with_schemas() {
    let ws = tempfile::TempDir::new().unwrap();
    let (s, _) = store(&ws);
    let tool = DataTool::new(Arc::new(s), Arc::new(AllowAll));
    let d = tool.describe();
    let names: Vec<_> = d.methods.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "describe", "query", "get", "create", "patch", "delete", "promote", "demote",
            "history", "apply"
        ]
    );
    for m in &d.methods {
        assert!(m.input_schema.is_some(), "{} has an input schema", m.name);
        assert!(m.output_schema.is_some(), "{} has an output schema", m.name);
        let reads = matches!(m.name.as_str(), "describe" | "query" | "get" | "history");
        assert_eq!(m.idempotent, Some(reads), "{}", m.name);
    }
}

#[tokio::test]
async fn e1_data_tool_requires_identity_and_maps_errors() {
    let ws = tempfile::TempDir::new().unwrap();
    let (s, _) = store(&ws);
    let s = Arc::new(s);
    let id = s
        .create("alice", launch(), item("t", "done"))
        .await
        .unwrap();
    let target = format!("launch.md#{}", id.0);
    let tool = DataTool::new(s.clone(), Arc::new(AllowAll));

    let params = serde_json::to_vec(
        &json!({ "target": target, "ops": [{ "set": "status", "value": "todo" }] }),
    )
    .unwrap();
    let out = tool
        .execute_as("alice", "patch", &params)
        .await
        .expect("patch via tool");
    let row: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(row["status"], json!("todo"));

    let err = tool.execute("patch", &params).await.unwrap_err();
    assert!(
        matches!(err, ToolError::PermissionDenied(_)),
        "no identity: {err:?}"
    );

    let bad = serde_json::to_vec(
        &json!({ "target": target, "ops": [{ "set": "status", "value": "done" }] }),
    )
    .unwrap();
    tool.execute_as("alice", "patch", &bad).await.unwrap();
    let again = serde_json::to_vec(
        &json!({ "target": target, "ops": [{ "set": "status", "value": "doing" }] }),
    )
    .unwrap();
    let err = tool.execute_as("alice", "patch", &again).await.unwrap_err();
    assert!(
        matches!(err, ToolError::InputValidationFailed(_)),
        "transition: {err:?}"
    );

    let missing = serde_json::to_vec(&json!({ "target": "launch.md#e-nope" })).unwrap();
    let err = tool.execute_as("alice", "get", &missing).await.unwrap_err();
    assert!(matches!(err, ToolError::NotFound(_)), "{err:?}");

    let apply = serde_json::to_vec(&json!({ "op": "nope", "target": target, "args": {} })).unwrap();
    let err = tool.execute_as("alice", "apply", &apply).await.unwrap_err();
    assert!(
        matches!(err, ToolError::MethodNotFound(_)),
        "unavailable op: {err:?}"
    );

    let denied = DataTool::new(s, Arc::new(DenyAll));
    let err = denied
        .execute_as("alice", "describe", b"{}")
        .await
        .unwrap_err();
    assert!(
        matches!(err, ToolError::PermissionDenied(_)),
        "grant denied: {err:?}"
    );
}

// The tool has no grant family of its own: it asks the caller's `fs` grant for the file each
// method touches, so read-only and path-scoped `fs` grants bind through this door too.
#[tokio::test]
async fn data_tool_is_authorized_by_the_fs_grant_of_the_touched_file() {
    let ws = tempfile::TempDir::new().unwrap();
    let (s, _) = store(&ws);
    let s = Arc::new(s);
    let id = s
        .create("alice", launch(), item("t", "todo"))
        .await
        .unwrap();
    let target = format!("launch.md#{}", id.0);
    let get = serde_json::to_vec(&json!({ "target": target })).unwrap();
    let get_file = serde_json::to_vec(&json!({ "target": "launch.md" })).unwrap();
    let patch = serde_json::to_vec(
        &json!({ "target": target, "ops": [{ "set": "status", "value": "doing" }] }),
    )
    .unwrap();
    let create = serde_json::to_vec(
        &json!({ "parent": "launch.md", "record": { "type": "work-item", "title": "x", "status": "todo" } }),
    )
    .unwrap();
    let query = serde_json::to_vec(&json!({ "query": "open" })).unwrap();
    let promote = serde_json::to_vec(&json!({ "target": target, "to": "file" })).unwrap();
    let denied = |r: Result<Vec<u8>, ToolError>, what: &str| {
        let err = r.expect_err(what);
        assert!(
            matches!(err, ToolError::PermissionDenied(_)),
            "{what}: {err:?}"
        );
    };
    let scoped = |read: &[&str], write: &[&str]| {
        DataTool::new(
            s.clone(),
            Arc::new(FsScoped {
                read: read.iter().map(|p| p.to_string()).collect(),
                write: write.iter().map(|p| p.to_string()).collect(),
            }),
        )
    };

    // Read everywhere, write nowhere: every read works, every write is refused.
    let ro = scoped(&["/"], &[]);
    ro.execute_as("alice", "describe", b"{}")
        .await
        .expect("describe");
    ro.execute_as("alice", "query", &query)
        .await
        .expect("query");
    ro.execute_as("alice", "get", &get)
        .await
        .expect("anchored get");
    ro.execute_as("alice", "get", &get_file)
        .await
        .expect("file get");
    denied(ro.execute_as("alice", "patch", &patch).await, "patch");
    denied(ro.execute_as("alice", "create", &create).await, "create");
    denied(ro.execute_as("alice", "promote", &promote).await, "promote");

    // Confined to another subtree: this file is out of reach, read or write, and the
    // whole-workspace methods need `/`.
    let elsewhere = scoped(&["/notes"], &["/notes"]);
    elsewhere
        .execute_as("alice", "describe", b"{}")
        .await
        .expect("describe needs only the grant");
    denied(
        elsewhere.execute_as("alice", "get", &get_file).await,
        "file get",
    );
    denied(
        elsewhere.execute_as("alice", "get", &get).await,
        "anchored get",
    );
    denied(
        elsewhere.execute_as("alice", "patch", &patch).await,
        "patch",
    );
    denied(
        elsewhere.execute_as("alice", "query", &query).await,
        "query",
    );

    // Confined to the file itself: single-file methods work, multi-file ones do not.
    let here = scoped(&["/launch.md"], &["/launch.md"]);
    here.execute_as("alice", "patch", &patch)
        .await
        .expect("patch");
    here.execute_as("alice", "create", &create)
        .await
        .expect("create");
    denied(here.execute_as("alice", "query", &query).await, "query");
    denied(
        here.execute_as("alice", "promote", &promote).await,
        "promote",
    );

    // A grant of some other family (the retired `data` one included) opens nothing.
    denied(
        DataTool::new(s.clone(), Arc::new(DenyAll))
            .execute_as("alice", "describe", b"{}")
            .await,
        "no fs grant",
    );
}

// The tool covers the whole life of a record: a new file, an inline item, and their removal.
#[tokio::test]
async fn data_tool_creates_a_record_file_and_deletes_records() {
    let ws = tempfile::TempDir::new().unwrap();
    let (s, events) = store(&ws);
    let s = Arc::new(s);
    let tool = DataTool::new(s.clone(), Arc::new(AllowAll));
    let call = |method: &'static str, params: Value| {
        let tool = &tool;
        async move {
            tool.execute_as("alice", method, &serde_json::to_vec(&params).unwrap())
                .await
        }
    };

    let made: Value = serde_json::from_slice(
        &call(
            "create",
            json!({ "path": "review.md", "body": "# Review\n", "record": { "type": "work-item", "title": "review", "status": "todo" } }),
        )
        .await
        .expect("create a record file"),
    )
    .unwrap();
    assert_eq!(made["target"], "review.md");
    let text = std::fs::read_to_string(ws.path().join("review.md")).unwrap();
    assert!(
        text.contains("status: todo") && text.ends_with("# Review\n"),
        "{text}"
    );
    assert!(matches!(
        call(
            "create",
            json!({ "path": "review.md", "record": { "type": "work-item" } })
        )
        .await,
        Err(ToolError::InputValidationFailed(_))
    ));
    assert!(matches!(
        call(
            "create",
            json!({ "path": "notes.txt", "record": { "type": "work-item" } })
        )
        .await,
        Err(ToolError::InputValidationFailed(_))
    ));

    let item: Value = serde_json::from_slice(
        &call(
            "create",
            json!({ "parent": "review.md", "record": { "type": "work-item", "title": "sub", "status": "todo" } }),
        )
        .await
        .unwrap(),
    )
    .unwrap();
    let item_target = item["target"].as_str().unwrap().to_string();
    assert_eq!(open_count(&s).await, 2);

    call("delete", json!({ "target": item_target }))
        .await
        .expect("delete the item");
    assert_eq!(open_count(&s).await, 1);
    assert!(matches!(
        call("delete", json!({ "target": item_target })).await,
        Err(ToolError::NotFound(_))
    ));

    call("delete", json!({ "target": "review.md" }))
        .await
        .expect("delete the file");
    assert!(!ws.path().join("review.md").exists());
    assert_eq!(open_count(&s).await, 0);
    assert_eq!(events.snapshot().last().unwrap().payload["op"], "delete");
}

// A file written or removed outside the store (a raw `fs.write` / `fs.delete`) is picked up
// by `sync_path`, which the fs handlers call.
#[tokio::test]
async fn sync_path_follows_raw_writes_and_deletes() {
    let ws = tempfile::TempDir::new().unwrap();
    let (s, events) = store(&ws);
    assert_eq!(open_count(&s).await, 0);

    std::fs::write(
        ws.path().join("raw.md"),
        "---\nid: e-raw\ntype: work-item\nname: raw\nstatus: todo\n---\nbody\n",
    )
    .unwrap();
    assert_eq!(
        open_count(&s).await,
        0,
        "the index has not seen the raw write"
    );
    s.sync_path("alice", "/raw.md").await;
    assert_eq!(open_count(&s).await, 1);
    assert_eq!(events.snapshot().last().unwrap().payload["op"], "fs_write");

    std::fs::remove_file(ws.path().join("raw.md")).unwrap();
    s.sync_path("alice", "raw.md").await;
    assert_eq!(open_count(&s).await, 0);
    assert_eq!(events.snapshot().last().unwrap().payload["op"], "fs_delete");
}

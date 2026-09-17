//! Lane E1 — `DataStore` operations, the `apply` transaction and the `data` host tool over a
//! temp workspace. The schema is the shipped
//! `packs/agenda` aspect; the in-memory `EntityIndex`, a plain-directory `WorkspaceFs`, a fixed
//! clock, a recording event sink and a scripted reducer are the doubles the crate ships under
//! `test-support`.

use std::sync::Arc;

use advance_shared_types::entity::EntityQuery;
use cap_data::test_support::{
    agenda_schema, AllowAll, DenyAll, DirWorkspaceFs, FixedClock, MemoryEntityIndex,
    RecordingEvents, ScriptedReducer, SequentialIds,
};
use cap_data::{
    DataError, DataStore, DataTool, IdempotencyKey, PatchOp, QueryRequest, Record, Target, Tier,
    MAX_EFFECTS_PER_APPLY, MAX_ITEMS_PER_FILE,
};
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
    assert_eq!(a.fields.len(), 11);
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

// ── the `data` host tool ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn e1_data_tool_describes_nine_methods_with_schemas() {
    let ws = tempfile::TempDir::new().unwrap();
    let (s, _) = store(&ws);
    let tool = DataTool::new(Arc::new(s), Arc::new(AllowAll));
    let d = tool.describe();
    let names: Vec<_> = d.methods.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "describe", "query", "get", "create", "patch", "promote", "demote", "history", "apply"
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

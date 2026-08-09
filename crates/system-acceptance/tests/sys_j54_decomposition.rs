//! Lifecycle-harvest — SYS-J-54 task-decomposition-lifecycle e2e witnesses
//! (SYS-AC-170 / 171 / 242 / 243).
//!
//! Wired system: the shared `lifecycle_support` Cap::Lifecycle fixture — the
//! REAL `register_agent_lifecycle` chain (production WIT dispatch + real
//! `DefaultDecompositionStore` persisting real `decomposition.yaml` files
//! under the caller's tree workspace + real cycle/oversize validation +
//! `task.*` event emission), driven through the registered host fns (the
//! standard harness guest stand-in).
//!
//! **SYS-AC-171 is FLIPPED** (Wave-17 Lane 4, 2026-06-25). All four legs are now
//! witnessed through the wired WIT surface — the heavier full-SUT + RealBus witness
//! is `sys_j54_decomp_update.rs`; this `sys_ac_171_*` test is the always-run baseline
//! (regression coverage of the same product behavior), all driven through the
//! registered host-fns:
//! - update-subtask-status mutates + emits `task.subtask_updated{old→new}`;
//! - `get-decomposition` reads back the FULL `decomposition-state` record — the
//!   lowering now projects `subtasks` WITH status/outcome (not just the goal), so
//!   the mutated status is observable on the wired WIT surface;
//! - re-submitting WITH an existing-id preserves the id (the lift now carries an
//!   optional existing-id through the descriptor wire's 5th `|`-field) while a
//!   submit WITHOUT an id mints a fresh `st-{uuid}`.
//! The store handle `fixture.decomp` is retained only as on-disk/state corroboration
//! (the persisted `decomposition.yaml` + the same-instance `store.get`).

#[path = "lifecycle_support/mod.rs"]
mod lifecycle_support;

use cap_lifecycle::{DecompositionStore, SubtaskStatus};
use lifecycle_support::{err_variant_name, ok_string_list, submit_params, LifecycleFixture};
use wasmtime::component::Val;

const ROOT: &str = "root-a"; // bare id — cap-lifecycle validate_agent_id rejects colons

/// uuid-v4 shape check without a uuid dev-dep: 36 chars, hyphens at
/// 8/13/18/23, hex elsewhere, version nibble `4`.
fn assert_uuid_v4(s: &str) {
    assert_eq!(s.len(), 36, "uuid length: {s}");
    for (i, c) in s.chars().enumerate() {
        match i {
            8 | 13 | 18 | 23 => assert_eq!(c, '-', "hyphen at {i}: {s}"),
            14 => assert_eq!(c, '4', "uuid v4 version nibble: {s}"),
            _ => assert!(c.is_ascii_hexdigit(), "hex at {i}: {s}"),
        }
    }
}

/// Navigate a `get-decomposition` WIT return — `result<option<decomposition-state>, _>` —
/// returning `(goal, status_tag, outcome)` for the subtask whose `subtask-id` == `id`.
/// Binds the read-back to the SPECIFIC subtask (structurally, not a broad string match).
fn wit_subtask_status_outcome(v: &Val, id: &str) -> (String, String, Option<String>) {
    let Val::Result(Ok(Some(opt))) = v else {
        panic!("expected Ok(Some(option)), got {v:?}")
    };
    let Val::Option(Some(state)) = opt.as_ref() else {
        panic!("expected Some(decomposition-state), got {opt:?}")
    };
    let Val::Record(fields) = state.as_ref() else {
        panic!("expected decomposition-state record, got {state:?}")
    };
    let field = |name: &str| fields.iter().find(|(k, _)| k == name).map(|(_, v)| v);
    let goal = match field("goal") {
        Some(Val::String(s)) => s.clone(),
        other => panic!("goal field: {other:?}"),
    };
    let Some(Val::List(subs)) = field("subtasks") else {
        panic!("subtasks list missing")
    };
    let sub = subs
        .iter()
        .find_map(|s| {
            let Val::Record(sf) = s else { return None };
            let sid = sf
                .iter()
                .find(|(k, _)| k == "subtask-id")
                .and_then(|(_, v)| match v {
                    Val::String(x) => Some(x.as_str()),
                    _ => None,
                })?;
            (sid == id).then_some(sf)
        })
        .unwrap_or_else(|| panic!("subtask {id} present in get-decomposition record"));
    let sfield = |name: &str| sub.iter().find(|(k, _)| k == name).map(|(_, v)| v);
    let status = match sfield("status") {
        Some(Val::Variant(tag, _)) => tag.clone(),
        other => panic!("status variant: {other:?}"),
    };
    let outcome = match sfield("outcome") {
        Some(Val::Option(Some(b))) => match b.as_ref() {
            Val::String(s) => Some(s.clone()),
            _ => None,
        },
        Some(Val::Option(None)) => None,
        other => panic!("outcome option: {other:?}"),
    };
    (goal, status, outcome)
}

// ── SYS-AC-170: submit → st-{uuidv4} receipt + task.decomposed + yaml ──────
#[tokio::test]
async fn sys_ac_170_submit_receipt_event_and_yaml_persisted() {
    let fx = LifecycleFixture::new_with_root(ROOT);
    let res = fx
        .call(
            ROOT,
            "submit-decomposition",
            submit_params(
                "task-170",
                "ship the harvest",
                "decompose",
                &[
                    "design|_self|draft the plan".to_string(),
                    "build|worker-b|implement|design".to_string(),
                    "verify|worker-c|test it|build".to_string(),
                ],
            ),
        )
        .await
        .expect("submit-decomposition dispatch ok");

    // Receipt: every non-orphaned title → stable `st-{uuidv4}` subtask id.
    let receipt = ok_string_list(&res[0]);
    assert_eq!(receipt.len(), 3, "all three fresh titles in the receipt");
    for title in ["design", "build", "verify"] {
        let entry = receipt
            .iter()
            .find(|r| r.starts_with(&format!("{title}=")))
            .unwrap_or_else(|| panic!("receipt entry for {title}: {receipt:?}"));
        let id = entry.split('=').nth(1).unwrap();
        assert!(id.starts_with("st-"), "stable st- prefix: {id}");
        assert_uuid_v4(&id[3..]);
    }

    // task.decomposed payload: strategy / subtask_count / assignees.
    let events = fx.events();
    let decomposed: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "task.decomposed")
        .collect();
    assert_eq!(decomposed.len(), 1, "exactly one task.decomposed");
    let e = decomposed[0];
    assert_eq!(e.agent_id, ROOT);
    assert_eq!(e.task_id.as_deref(), Some("task-170"));
    assert_eq!(e.payload["strategy"], "decompose");
    assert_eq!(e.payload["subtask_count"], 3);
    let assignees: Vec<&str> = e.payload["assignees"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(assignees.contains(&"worker-b") && assignees.contains(&"worker-c"));

    // decomposition.yaml persisted under the caller's REAL workspace.
    let yaml_path = fx
        .workspace_of(ROOT)
        .join(".agent/tasks/active/task-170/decomposition.yaml");
    assert!(
        yaml_path.is_file(),
        "decomposition.yaml persisted: {yaml_path:?}"
    );
    let yaml = std::fs::read_to_string(&yaml_path).unwrap();
    assert!(yaml.contains("design") && yaml.contains("build") && yaml.contains("verify"));
}

// ── SYS-AC-171: update → event + read-back; id continuity ──────────────────
#[tokio::test]
async fn sys_ac_171_update_event_readback_and_id_continuity() {
    let fx = LifecycleFixture::new_with_root(ROOT);
    let res = fx
        .call(
            ROOT,
            "submit-decomposition",
            submit_params(
                "task-171",
                "iterate",
                "decompose",
                &[
                    "alpha|_self|do a".to_string(),
                    "beta|_self|do b".to_string(),
                ],
            ),
        )
        .await
        .expect("submit ok");
    let receipt = ok_string_list(&res[0]);
    let alpha_id = receipt
        .iter()
        .find(|r| r.starts_with("alpha="))
        .unwrap()
        .split('=')
        .nth(1)
        .unwrap()
        .to_string();

    // WIT-driven mutation: pending → in-progress with an outcome note.
    let upd = fx
        .call(
            ROOT,
            "update-subtask-status",
            vec![
                Val::String("task-171".into()),
                Val::String(alpha_id.clone()),
                Val::String("in-progress".into()),
                Val::String("started".into()),
            ],
        )
        .await
        .expect("update-subtask-status dispatch ok");
    assert!(
        matches!(&upd[0], Val::Result(Ok(None))),
        "update ok: {:?}",
        upd[0]
    );

    // task.subtask_updated old→new payload.
    let events = fx.events();
    let updated: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "task.subtask_updated")
        .collect();
    assert_eq!(updated.len(), 1, "exactly one task.subtask_updated");
    assert_eq!(updated[0].payload["subtask_id"], alpha_id.as_str());
    assert_eq!(updated[0].payload["old_status"], "pending");
    assert_eq!(updated[0].payload["new_status"], "in-progress");

    // Read-back leg (a): the WIT get-decomposition call now projects the FULL
    // `decomposition-state` record — goal + subtasks WITH status/outcome. Assert
    // both the goal AND alpha's mutated status/outcome are visible on the wired
    // WIT surface (the SYS-AC-171 read-back, not just the goal).
    let got = fx
        .call(
            ROOT,
            "get-decomposition",
            vec![Val::String("task-171".into())],
        )
        .await
        .expect("get-decomposition dispatch ok");
    let (goal, st_status, st_outcome) = wit_subtask_status_outcome(&got[0], &alpha_id);
    assert_eq!(goal, "iterate", "get-decomposition projects the goal");
    assert_eq!(
        st_status, "in-progress",
        "WIT read-back: alpha's mutated status (bound to alpha_id)"
    );
    assert_eq!(
        st_outcome.as_deref(),
        Some("started"),
        "WIT read-back: alpha's mutated outcome (bound to alpha_id)"
    );

    // Read-back leg (b): the SAME store instance the WIT handlers use returns
    // the mutated state; the persisted yaml carries it too.
    let state = fx
        .decomp
        .get(ROOT, "task-171")
        .expect("store get ok")
        .expect("state exists");
    let alpha = state
        .subtasks
        .iter()
        .find(|s| s.subtask_id == alpha_id)
        .expect("alpha subtask");
    assert_eq!(alpha.status, SubtaskStatus::InProgress);
    assert_eq!(alpha.outcome.as_deref(), Some("started"));
    let yaml = std::fs::read_to_string(
        fx.workspace_of(ROOT)
            .join(".agent/tasks/active/task-171/decomposition.yaml"),
    )
    .unwrap();
    assert!(yaml.contains("in-progress"), "mutation persisted to disk");

    // Continuity leg 1 (WIT-driven): re-submit the same titles WITHOUT
    // existing ids → fresh uuids are minted (alpha's id changes).
    let res2 = fx
        .call(
            ROOT,
            "submit-decomposition",
            submit_params(
                "task-171",
                "iterate",
                "decompose",
                &[
                    "alpha|_self|do a".to_string(),
                    "beta|_self|do b".to_string(),
                ],
            ),
        )
        .await
        .expect("re-submit ok");
    let receipt2 = ok_string_list(&res2[0]);
    let alpha_id_2 = receipt2
        .iter()
        .find(|r| r.starts_with("alpha="))
        .unwrap()
        .split('=')
        .nth(1)
        .unwrap()
        .to_string();
    assert_ne!(
        alpha_id_2, alpha_id,
        "no existing-id → fresh st-uuid minted"
    );

    // Continuity leg 2 (WIT-driven): re-submit WITH alpha's existing id via the
    // descriptor's 5th `|`-field → the id is PRESERVED through the wired host-fn.
    // The lift now carries existing_id (was below the WIT bar; the store always
    // supported it). Same store instance, so alpha_id_2 ∈ the prior id-set.
    let res3 = fx
        .call(
            ROOT,
            "submit-decomposition",
            submit_params(
                "task-171",
                "iterate",
                "decompose",
                &[
                    format!("alpha|_self|do a||{alpha_id_2}"),
                    "beta|_self|do b".to_string(),
                ],
            ),
        )
        .await
        .expect("WIT re-submit with existing id ok");
    let receipt3 = ok_string_list(&res3[0]);
    let alpha_kept = receipt3
        .iter()
        .find(|r| r.starts_with("alpha="))
        .unwrap()
        .split('=')
        .nth(1)
        .unwrap()
        .to_string();
    assert_eq!(
        alpha_kept, alpha_id_2,
        "existing-id preserved through the WIT"
    );
}

// ── SYS-AC-242: cyclic plan via the host-fn path → typed rejection ─────────
#[tokio::test]
async fn sys_ac_242_cycle_rejected_no_yaml_no_event() {
    let fx = LifecycleFixture::new_with_root(ROOT);
    let res = fx
        .call(
            ROOT,
            "submit-decomposition",
            submit_params(
                "task-242",
                "cyclic",
                "decompose",
                &["a|_self|p|b".to_string(), "b|_self|p|a".to_string()],
            ),
        )
        .await
        .expect("dispatch ok (typed domain error)");
    assert_eq!(
        err_variant_name(&res[0]),
        "dependency-cycle",
        "typed decomposition-error::dependency-cycle"
    );
    assert!(
        !fx.workspace_of(ROOT)
            .join(".agent/tasks/active/task-242/decomposition.yaml")
            .exists(),
        "no decomposition.yaml persisted on cycle rejection"
    );
    assert_eq!(fx.events().len(), 0, "no event on failed submit");
}

// ── SYS-AC-243: >1 MiB rendered doc via the host-fn path → rejected ────────
#[tokio::test]
async fn sys_ac_243_oversized_rendered_doc_rejected_no_yaml() {
    let fx = LifecycleFixture::new_with_root(ROOT);
    // 256-subtask dense DAG (each subtask depends on every lower-indexed
    // title): resolved st-uuid depends_on lists render to >1 MiB of YAML
    // while every descriptor stays far below the 128 KiB descriptor cap and
    // the 8 MiB aggregate input cap (the crate-level
    // `ac13_oversized_rendered_doc_rejected` shape, driven through WIT).
    let titles: Vec<String> = (0..256).map(|i| format!("t{i:03}")).collect();
    let descriptors: Vec<String> = (0..256)
        .map(|i| format!("{}|_self|p|{}", titles[i], titles[..i].join(",")))
        .collect();
    let err = fx
        .call(
            ROOT,
            "submit-decomposition",
            submit_params("task-243", "big", "decompose", &descriptors),
        )
        .await
        .expect_err("oversized rendered doc is an InvalidConfig host trap");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("internal-error") || msg.contains("decomposition"),
        "host trap from decomposition infra rejection: {msg}"
    );
    assert!(
        !fx.workspace_of(ROOT)
            .join(".agent/tasks/active/task-243/decomposition.yaml")
            .exists(),
        "no oversized decomposition.yaml written"
    );
    assert_eq!(fx.events().len(), 0, "no event on rejected submit");
}

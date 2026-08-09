//! SYS-J-12 (a skill change in a discarded auto iteration is restored on
//! rollback; draft/candidate files persist) system-acceptance witnesses.
//!
//! **Wave-18 Lane 2 re-point** — these drive the PRODUCTION M015→M017
//! `SkillRollback` bridge (`advance_cli::skill_rollback_bridge`) wired over the
//! production cli composition (`AutoWired::build_bridged`: the OnceLock
//! `set_skill_rollback` late-bind + a `SkillPersistenceCoordinator` carrying the
//! record-side `DriverPreActivationObserver`, over ONE disk-backed `SkillStore`
//! + a real `DefaultGitCommitQueue`). The earlier strict-hold (Wave-17) was that
//! production `build_auto_loop_driver` wired NO `SkillRollback` and the witnesses
//! self-installed a test `RecordingRealSkillRollback`; that bridge now SHIPS, so
//! the in-iteration pre-state is recorded ONLY through the production observer
//! (the agent activate path) and the discard restoration runs through the real
//! coordinator on the `Initiator::AutoLoop` micro lane.
//!
//! Disclosed boundaries (MODULE-017 §3.6): the production auto-loop runtime is
//! still DORMANT (no `advance auto start` CLI ingress); the witness drives the
//! production `DefaultAutoLoopDriver` + `default-agent` binding end-to-end — the
//! accepted floor under which the sibling auto SYS-AC (031/032/035) already pass.
//!
//! Flips: SYS-AC-034 / 035 / 036; supports MODULE-017-AC-06 / AC-07.

mod stepd_auto_support;

use advance_scheduler_auto_loop::config::Op;
use advance_scheduler_auto_loop::{AutoLoopDriver, IterationOutcome, IterationStatus};
use git2::Repository;

use stepd_auto_support::{close_ctx, commit_file, primary_criteria, AutoWired, WireOpts};

/// The production cli skills coordinator binds to `DEFAULT_AGENT_ID`; the bridged
/// witness chain mirrors it (the observer session gate + M003 root resolve align).
const AGENT: &str = "default-agent";

/// Does a `[micro] [runtime:auto-loop]`-tagged commit exist in the repo history?
/// The cap-skills coordinator tags AutoLoop-initiated commits this way; its
/// presence proves the discard restoration committed on the micro lane.
fn has_micro_autoloop_commit(repo_dir: &std::path::Path) -> bool {
    let repo = Repository::open(repo_dir).expect("open repo");
    let mut walk = repo.revwalk().expect("revwalk");
    walk.push_head().expect("push head");
    let found = walk.flatten().any(|oid| {
        repo.find_commit(oid)
            .ok()
            .and_then(|c| c.message().map(|m| m.to_string()))
            .map(|m| m.starts_with("[micro] [runtime:auto-loop]"))
            .unwrap_or(false)
    });
    found
}

// SYS-AC-034 (+ MODULE-017-AC-07 dispatch): a skill activated in a discarded
// iteration is restored on rollback — Absent pre-state → delete-skill; Version(n)
// → rollback-skill(id,n). Witnessed via the REAL production bridge + the REAL
// disk-backed store: the store is actually mutated AND a `[micro]` commit lands
// AND the `skill.rolled_back`/`skill.deleted` events fire.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_034_discard_dispatches_real_skill_rollback() {
    let w = AutoWired::build_bridged(WireOpts {
        results: true,
        ..Default::default()
    })
    .await;

    // Baseline (pre-iteration): skill "t" active @ v1, activated BEFORE start so
    // the observer's session gate no-ops (no spurious pre-state recorded).
    assert_eq!(w.coord_activate("t", "t-v1").await, 1, "baseline t @ v1");

    w.driver
        .start(AGENT, primary_criteria(Op::Lt))
        .await
        .expect("start");
    w.driver
        .iteration_start(AGENT, Some(format!("run-{AGENT}")), 1)
        .await
        .expect("iteration_start");

    // In-iteration: "t" modified → v2 (observer records Version(1) for "t");
    // "new" activated (observer records Absent for "new"). Pre-state recorded ONLY
    // through the production coordinator activate path — never a manual call.
    assert_eq!(
        w.coord_activate("t", "t-v2").await,
        2,
        "t @ v2 in-iteration"
    );
    assert_eq!(
        w.coord_activate("new", "new-v1").await,
        1,
        "new @ v1 in-iteration"
    );

    // Sanity: pre-discard the active "t" is the v2 content.
    assert!(
        w.coord_content("t")
            .await
            .expect("t active")
            .contains("t-v2"),
        "pre-discard t is the v2 content"
    );

    let rolled_before = w.bus.event_count("skill.rolled_back");
    let deleted_before = w.bus.event_count("skill.deleted");

    // Discard (no primary metric → discard arm) → apply_discard → the production
    // bridge dispatches rollback(t,1) + delete(new).
    let out = w
        .driver
        .close_iteration(close_ctx(AGENT, 1, None, false))
        .await
        .expect("close discard");
    assert!(matches!(
        out,
        IterationOutcome::Continue {
            status: IterationStatus::Discard,
            ..
        }
    ));

    // REAL store mutated: "t" restored to the v1 CONTENT (rollback bumps the
    // active version but restores the v1 content); "new" deleted.
    let t_after = w.coord_content("t").await.expect("t active after");
    assert!(
        t_after.contains("t-v1") && !t_after.contains("t-v2"),
        "rollback restored the v1 content (got: {t_after})"
    );
    assert_eq!(
        w.coord_version("new").await,
        None,
        "delete made 'new' inactive"
    );

    // Production emit path ran: a skill.rolled_back (for t) + a skill.deleted
    // (for new) fired through the coordinator's real EventBus.
    assert_eq!(
        w.bus.event_count("skill.rolled_back"),
        rolled_before + 1,
        "one skill.rolled_back emitted for the restored t"
    );
    assert_eq!(
        w.bus.event_count("skill.deleted"),
        deleted_before + 1,
        "one skill.deleted emitted for the reverted new"
    );

    // The restoration committed on the micro lane (runtime:auto-loop).
    assert!(
        has_micro_autoloop_commit(w.ws()),
        "the discard restoration produced a [micro] [runtime:auto-loop] commit"
    );
}

// SYS-AC-035: after the discarded iteration, files under .agent/_drafts/ and
// .agent/memory/_skill_candidates.jsonl still exist (EXCLUDED from the
// FullDirectory rollback), while a non-.agent file reverts. This leg is
// bridge-INDEPENDENT (the .agent/** exclusion lives in the M003 FullDirectory
// rollback, not the bridge) — it stays on the legacy `build` (root sentinel),
// re-pointing it would be a harmless no-op.
//
// Discriminating witness for the .agent/** EXCLUSION: the .agent files are in the
// iter-1 checkpoint (committed BEFORE iteration_start) AND MODIFIED after it. If
// rollback included .agent/**, the modification would revert to the checkpoint
// content; the exclusion keeps the POST-checkpoint content. work.txt (non-.agent)
// reverts, proving the rollback ran.
#[tokio::test]
async fn sys_ac_035_drafts_and_candidates_survive_discard() {
    let w = AutoWired::build(WireOpts::default());
    w.driver
        .start("root", primary_criteria(Op::Lt))
        .await
        .expect("start");

    // .agent draft + candidate present in the checkpoint with their OLD content.
    commit_file(w.ws(), ".agent/_drafts/d.txt", b"draft-OLD");
    commit_file(
        w.ws(),
        ".agent/memory/_skill_candidates.jsonl",
        b"{\"candidate\":\"OLD\"}\n",
    );

    w.driver
        .iteration_start("root", Some("run-root".to_string()), 1)
        .await
        .expect("iteration_start");

    // Post-checkpoint: MODIFY the .agent files (NEW content) + a non-.agent file.
    commit_file(w.ws(), ".agent/_drafts/d.txt", b"draft-NEW");
    commit_file(
        w.ws(),
        ".agent/memory/_skill_candidates.jsonl",
        b"{\"candidate\":\"NEW\"}\n",
    );
    commit_file(w.ws(), "work.txt", b"mutated");

    let out = w
        .driver
        .close_iteration(close_ctx("root", 1, None, false))
        .await
        .expect("close discard");
    assert!(matches!(
        out,
        IterationOutcome::Continue {
            status: IterationStatus::Discard,
            ..
        }
    ));

    // EXCLUSION witness: the .agent files keep their POST-checkpoint (NEW) content
    // (rollback skipped them); a rollback that included .agent/** would revert to
    // "OLD". work.txt reverts to the checkpoint baseline (proves rollback ran).
    assert_eq!(
        std::fs::read(w.ws().join(".agent/_drafts/d.txt")).unwrap(),
        b"draft-NEW",
        ".agent/_drafts/ must be EXCLUDED from rollback (keeps post-checkpoint content)"
    );
    assert_eq!(
        std::fs::read(w.ws().join(".agent/memory/_skill_candidates.jsonl")).unwrap(),
        b"{\"candidate\":\"NEW\"}\n",
        "_skill_candidates.jsonl must be EXCLUDED from rollback"
    );
    assert_eq!(
        std::fs::read(w.ws().join("work.txt")).unwrap(),
        b"baseline",
        "the non-.agent file reverts (proves the rollback actually ran)"
    );
}

// SYS-AC-036: post-rollback the reverted skill is no longer active/usable (REAL
// store get → None/SkillNotFound) while the draft/candidate side effects persist
// as accepted. Compound of 034 (Absent→delete via the production bridge) + 035.
#[tokio::test(flavor = "multi_thread")]
async fn sys_ac_036_post_discard_skill_inactive_drafts_persist() {
    let w = AutoWired::build_bridged(WireOpts {
        results: true,
        ..Default::default()
    })
    .await;

    w.driver
        .start(AGENT, primary_criteria(Op::Lt))
        .await
        .expect("start");

    // .agent draft + candidate present in the checkpoint with OLD content.
    commit_file(w.ws(), ".agent/_drafts/d.txt", b"draft-OLD");
    commit_file(
        w.ws(),
        ".agent/memory/_skill_candidates.jsonl",
        b"{\"candidate\":\"OLD\"}\n",
    );

    w.driver
        .iteration_start(AGENT, Some(format!("run-{AGENT}")), 1)
        .await
        .expect("iteration_start");

    // Activate skill "s" THIS iteration (Absent pre-state, via the production
    // observer). Then modify the .agent files (NEW) + a non-.agent file.
    assert_eq!(
        w.coord_activate("s", "s-v1").await,
        1,
        "s activated in-iteration"
    );
    assert!(
        w.coord_version("s").await.is_some(),
        "s active before discard"
    );
    commit_file(w.ws(), ".agent/_drafts/d.txt", b"draft-NEW");
    commit_file(
        w.ws(),
        ".agent/memory/_skill_candidates.jsonl",
        b"{\"candidate\":\"NEW\"}\n",
    );
    commit_file(w.ws(), "work.txt", b"mutated");

    let out = w
        .driver
        .close_iteration(close_ctx(AGENT, 1, None, false))
        .await
        .expect("close discard");
    assert!(matches!(
        out,
        IterationOutcome::Continue {
            status: IterationStatus::Discard,
            ..
        }
    ));

    // REAL post-state: the reverted skill is no longer active/usable.
    assert_eq!(
        w.coord_version("s").await,
        None,
        "post-rollback the activated skill must be inactive"
    );
    // Draft/candidate side effects persist as accepted (EXCLUDED from rollback:
    // they keep their post-checkpoint NEW content, not reverted to OLD).
    assert_eq!(
        std::fs::read(w.ws().join(".agent/_drafts/d.txt")).unwrap(),
        b"draft-NEW",
        ".agent/_drafts/ excluded from rollback (post-checkpoint content survives)"
    );
    assert_eq!(
        std::fs::read(w.ws().join(".agent/memory/_skill_candidates.jsonl")).unwrap(),
        b"{\"candidate\":\"NEW\"}\n",
        "_skill_candidates.jsonl excluded from rollback"
    );
    assert_eq!(std::fs::read(w.ws().join("work.txt")).unwrap(), b"baseline");
}

// MODULE-017-AC-06 (REQ-276): "first activate records pre-state; subsequent do
// not." The auto-loop `SkillTracker::record_pre_activation` is FIRST-INSERT-WINS
// (`entry().or_insert_with`). This witness activates skill "t" TWICE in ONE
// iteration through the PRODUCTION observer (the coordinator activate path) —
// first lifting v1→v2, then v2→v3 — and proves the SECOND observation is IGNORED:
// on discard, "t" is restored to the FIRST recorded version (the v1 CONTENT), NOT
// the second (v2) nor the current (v3).
//
// Wave-18 (re-point): the pre-state now flows through the REAL production
// `DriverPreActivationObserver` (fired inside `activate_skill_with_persistence`),
// NOT a manual `record_skill_pre_activation` call — so this meets the real-WIRED
// e2e floor and FLIPS MODULE-017-AC-06.
#[tokio::test(flavor = "multi_thread")]
async fn ac06_first_insert_wins_subsequent_record_ignored() {
    let w = AutoWired::build_bridged(WireOpts {
        results: true,
        ..Default::default()
    })
    .await;

    // Baseline (pre-iteration): "t" active @ v1.
    assert_eq!(w.coord_activate("t", "t-v1").await, 1, "baseline t @ v1");

    w.driver
        .start(AGENT, primary_criteria(Op::Lt))
        .await
        .expect("start");
    w.driver
        .iteration_start(AGENT, Some(format!("run-{AGENT}")), 1)
        .await
        .expect("iteration_start");

    // FIRST in-iteration activate: "t" v1→v2. The observer records the prior
    // (Version 1) — the first-insert.
    assert_eq!(w.coord_activate("t", "t-v2").await, 2, "t @ v2");
    // SECOND in-iteration activate for the SAME "t": v2→v3. The observer fires
    // again (prior = Version 2) but first-insert-wins ⇒ this MUST be ignored.
    assert_eq!(w.coord_activate("t", "t-v3").await, 3, "t @ v3");

    // Sanity: pre-discard the active "t" is the v3 content.
    assert!(
        w.coord_content("t")
            .await
            .expect("t active")
            .contains("t-v3"),
        "pre-discard t is the v3 content"
    );

    let out = w
        .driver
        .close_iteration(close_ctx(AGENT, 1, None, false))
        .await
        .expect("close discard");
    assert!(matches!(
        out,
        IterationOutcome::Continue {
            status: IterationStatus::Discard,
            ..
        }
    ));

    // First-insert-wins discriminator: "t" restored to the v1 CONTENT (the FIRST
    // recorded pre-state), NOT v2 (the ignored second observation) and NOT v3
    // (the current active at discard).
    let t_after = w.coord_content("t").await.expect("t active after");
    assert!(
        t_after.contains("t-v1") && !t_after.contains("t-v2") && !t_after.contains("t-v3"),
        "first-insert-wins restored the v1 content (got: {t_after})"
    );
}

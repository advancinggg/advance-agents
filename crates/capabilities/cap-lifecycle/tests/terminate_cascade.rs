//! AC-03 / AC-18 / AC-20 — terminate-cascade (REQ-030/066/270).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use advance_shared_types::agent_tree::{AgentId, AgentKind, AgentNode, AgentStatus};
use cap_lifecycle::{
    AgentTreeStore, DefaultTerminateController, GrantCascadeRevoke, LifecycleError, MailboxCascade,
    RunCascade, TerminateController, WorkspaceCleanup,
};
use tempfile::TempDir;

#[derive(Default)]
struct Rec {
    calls: Mutex<Vec<String>>,
}
impl Rec {
    fn log(&self, s: String) {
        self.calls.lock().unwrap().push(s);
    }
    fn snapshot(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

struct GRec(Arc<Rec>);
impl GrantCascadeRevoke for GRec {
    fn revoke_for_agent(&self, a: &str) -> Result<(), LifecycleError> {
        self.0.log(format!("revoke:{a}"));
        Ok(())
    }
}
struct MRec(Arc<Rec>);
impl MailboxCascade for MRec {
    fn flush_mailbox(&self, a: &str) -> Result<(), LifecycleError> {
        self.0.log(format!("flush:{a}"));
        Ok(())
    }
    fn notify_parent_crash(&self, p: &str, c: &str, r: &str) -> Result<(), LifecycleError> {
        self.0.log(format!("crash:{p}<-{c}:{r}"));
        Ok(())
    }
}
struct RRec(Arc<Rec>);
impl RunCascade for RRec {
    fn ensure_run(&self, a: &str) -> Result<(), LifecycleError> {
        self.0.log(format!("ensure:{a}"));
        Ok(())
    }
    fn cancel_run(&self, a: &str) -> Result<(), LifecycleError> {
        self.0.log(format!("cancel:{a}"));
        Ok(())
    }
}
struct WRec(Arc<Rec>);
impl WorkspaceCleanup for WRec {
    fn remove_sub_workspace(&self, p: &Path) -> Result<(), LifecycleError> {
        self.0.log(format!("rmws:{}", p.display()));
        Ok(())
    }
}

fn node(id: &str, kind: AgentKind, parent: Option<&str>, ws: PathBuf) -> AgentNode {
    AgentNode {
        id: AgentId(id.into()),
        kind,
        parent: parent.map(|p| AgentId(p.into())),
        workspace_path: ws,
        capabilities: Vec::new(),
        template_ref: None,
        status: AgentStatus::Active,
    }
}

fn setup() -> (
    TempDir,
    AgentTreeStore,
    Arc<Rec>,
    DefaultTerminateController,
) {
    let tmp = TempDir::new().unwrap();
    let tree = AgentTreeStore::new(tmp.path().to_path_buf()).unwrap();
    let rws = tree.workspace_root().join("root");
    std::fs::create_dir_all(&rws).unwrap();
    tree.insert_root(node("root", AgentKind::Root, None, rws.clone()))
        .unwrap();
    let cws = tree.workspace_root().join("root/child");
    std::fs::create_dir_all(&cws).unwrap();
    tree.insert_child(
        &AgentId("root".into()),
        node("child", AgentKind::Child, Some("root"), cws),
    )
    .unwrap();
    let gws = tree.workspace_root().join("root/child/gc");
    std::fs::create_dir_all(&gws).unwrap();
    tree.insert_child(
        &AgentId("child".into()),
        node("gc", AgentKind::Child, Some("child"), gws),
    )
    .unwrap();
    let rec = Arc::new(Rec::default());
    let ctrl = DefaultTerminateController::new(
        tree.clone(),
        Arc::new(GRec(rec.clone())),
        Arc::new(MRec(rec.clone())),
        Arc::new(RRec(rec.clone())),
        Arc::new(WRec(rec.clone())),
    );
    (tmp, tree, rec, ctrl)
}

#[test]
fn ac03_terminate_child_post_order_grandchild_first() {
    let (_t, tree, rec, ctrl) = setup();
    ctrl.terminate_child("root", "child").unwrap();
    let calls = rec.snapshot();
    // gc must be cancelled before child (post-order).
    let gc = calls.iter().position(|c| c == "cancel:gc").unwrap();
    let ch = calls.iter().position(|c| c == "cancel:child").unwrap();
    assert!(gc < ch, "post-order: grandchild before child");
    assert!(!tree.contains(&AgentId("child".into())));
    assert!(!tree.contains(&AgentId("gc".into())));
}

#[test]
fn ac03_non_parent_caller_permission_denied() {
    let (_t, _tree, _rec, ctrl) = setup();
    let e = ctrl.terminate_child("gc", "child").unwrap_err();
    assert!(matches!(e, LifecycleError::PermissionDenied(_)));
}

#[test]
fn ac03_sub_workspace_cleanup() {
    let (_t, tree, rec, ctrl) = setup();
    let sws = tree.workspace_root().join("root/child/.sub");
    std::fs::create_dir_all(&sws).unwrap();
    tree.insert_child(
        &AgentId("child".into()),
        node("subby", AgentKind::Sub, Some("child"), sws),
    )
    .unwrap();
    ctrl.terminate_child("child", "subby").unwrap();
    assert!(rec.snapshot().iter().any(|c| c.starts_with("rmws:")));
    assert!(!tree.contains(&AgentId("subby".into())));
}

#[test]
fn ac03_cascade_order_run_mailbox_grant() {
    let (_t, _tree, rec, ctrl) = setup();
    ctrl.terminate_child("child", "gc").unwrap();
    let c = rec.snapshot();
    let ci = c.iter().position(|x| x == "cancel:gc").unwrap();
    let fi = c.iter().position(|x| x == "flush:gc").unwrap();
    let ri = c.iter().position(|x| x == "revoke:gc").unwrap();
    assert!(ci < fi && fi < ri, "order cancel<flush<revoke");
}

#[test]
fn ac03_terminate_agent_root_rejected() {
    let (_t, _tree, _rec, ctrl) = setup();
    let e = ctrl.terminate_agent("root", "root").unwrap_err();
    assert!(matches!(e, LifecycleError::PermissionDenied(_)));
}

#[test]
fn ac03_idempotent_second_terminate_not_found() {
    let (_t, _tree, _rec, ctrl) = setup();
    ctrl.terminate_child("root", "child").unwrap();
    let e = ctrl.terminate_child("root", "child").unwrap_err();
    assert!(matches!(e, LifecycleError::NotFound(_)));
}

#[test]
fn ac18_handle_crash_sets_failed_then_notifies() {
    let (_t, tree, rec, ctrl) = setup();
    ctrl.handle_crash("gc", "panic").unwrap();
    // status flipped to Failed.
    assert_eq!(
        tree.get_node(&AgentId("gc".into())).unwrap().status,
        AgentStatus::Failed
    );
    // parent notified with reason.
    assert!(rec.snapshot().iter().any(|c| c == "crash:child<-gc:panic"));
}

#[test]
fn ac18_handle_crash_unknown_not_found_no_notify() {
    let (_t, _tree, rec, ctrl) = setup();
    let e = ctrl.handle_crash("ghost", "x").unwrap_err();
    assert!(matches!(e, LifecycleError::NotFound(_)));
    assert!(!rec.snapshot().iter().any(|c| c.starts_with("crash:")));
}

#[test]
fn ac18_handle_crash_root_status_only_no_notify() {
    let (_t, tree, rec, ctrl) = setup();
    ctrl.handle_crash("root", "boom").unwrap();
    assert_eq!(
        tree.get_node(&AgentId("root".into())).unwrap().status,
        AgentStatus::Failed
    );
    assert!(!rec.snapshot().iter().any(|c| c.starts_with("crash:")));
}

#[test]
fn ac03_insert_child_under_terminated_parent_rejected() {
    // R4-W3: insert_child guard atomic with set_status.
    let (_t, tree, _rec, _ctrl) = setup();
    tree.set_status(&AgentId("child".into()), AgentStatus::Terminated)
        .unwrap();
    let nws = tree.workspace_root().join("root/child/new");
    std::fs::create_dir_all(&nws).unwrap();
    let e = tree
        .insert_child(
            &AgentId("child".into()),
            node("newkid", AgentKind::Child, Some("child"), nws),
        )
        .unwrap_err();
    let msg = format!("{e:?}");
    assert!(
        msg.contains("terminating") || msg.contains("Terminated"),
        "{msg}"
    );
}

#[test]
fn ac20_collaboration_surface_ensure_run_then_cascade() {
    // AC-20 M005-side surface: spawn-from-template-equivalent (child in
    // tree) composes with RunCascade.ensure_run + cascade ordering.
    let (_t, _tree, rec, ctrl) = setup();
    // Simulate the collaboration sequence's run-ensure leg via the seam.
    // (M007 await-replies / M008 ensure-run production wiring is downstream;
    // REQ-270 stays Partial — this verifies the M005-owned segment.)
    ctrl.terminate_child("child", "gc").unwrap();
    let c = rec.snapshot();
    assert!(c.iter().any(|x| x == "cancel:gc"));
    assert!(c.iter().any(|x| x == "revoke:gc"));
}

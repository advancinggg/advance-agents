//! Task-local host-call identity for the grant-check view.

use advance_runtime::host_registry::HostCallContext;
use tokio::task_local;

/// The host-function or native-tool call in progress.
#[derive(Clone, Debug)]
pub struct CallIdentity {
    extension: &'static str,
    agent_id: String,
    function: String,
}

impl CallIdentity {
    /// From the context the injector built (`agent_id` = the calling guest,
    /// `function` = `"{ns}::{name}"`).
    pub fn host_function(extension: &'static str, ctx: &HostCallContext) -> Self {
        Self {
            extension,
            agent_id: ctx.agent_id.clone(),
            function: ctx.function.clone(),
        }
    }

    /// From the trusted agent id `LazyToolRegistry` passes to
    /// `HostTool::execute_as`; `function` = `"tool::{id}/{method}"`.
    pub fn tool(extension: &'static str, agent_id: &str, tool_id: &str, method: &str) -> Self {
        Self {
            extension,
            agent_id: agent_id.to_owned(),
            function: format!("tool::{tool_id}/{method}"),
        }
    }

    pub(crate) fn extension(&self) -> &'static str {
        self.extension
    }

    pub(crate) fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub(crate) fn function(&self) -> &str {
        &self.function
    }
}

task_local! {
    static CURRENT_CALL: CallIdentity;
}

pub fn scope_sync<R>(id: CallIdentity, f: impl FnOnce() -> R) -> R {
    CURRENT_CALL.sync_scope(id, f)
}

pub fn scope<F: std::future::Future>(
    id: CallIdentity,
    fut: F,
) -> impl std::future::Future<Output = F::Output> {
    CURRENT_CALL.scope(id, fut)
}

pub(crate) fn current() -> Option<CallIdentity> {
    CURRENT_CALL.try_with(Clone::clone).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{ExtensionGrantCheck, GrantDecision};
    use crate::extension::set::Revocation;
    use advance_shared_types::capability::CapParams;
    use advance_shared_types::traits::GrantCheck;
    use std::sync::{Arc, Mutex};

    struct RecordingGrants {
        calls: Mutex<Vec<(String, String, String)>>,
    }

    impl GrantCheck for RecordingGrants {
        fn check(
            &self,
            agent_id: &str,
            capability: &str,
            function: &str,
            _params: &CapParams,
        ) -> GrantDecision {
            self.calls.lock().unwrap().push((
                agent_id.to_owned(),
                capability.to_owned(),
                function.to_owned(),
            ));
            GrantDecision::Allow
        }
    }

    fn view(
        extension: &'static str,
        grants: &Arc<RecordingGrants>,
        gate: Revocation,
    ) -> ExtensionGrantCheck {
        ExtensionGrantCheck::new(
            extension,
            Arc::downgrade(&(Arc::clone(grants) as Arc<dyn GrantCheck>)),
            gate,
        )
    }

    #[test]
    fn module_001_ac31_grant_check_scope_rules() {
        let grants = Arc::new(RecordingGrants {
            calls: Mutex::new(Vec::new()),
        });
        let gate = Revocation::new();
        let check_a = view("a", &grants, gate.clone());
        let check_b = view("b", &grants, gate.clone());

        assert_eq!(
            check_a.check("fs", &CapParams::empty()),
            GrantDecision::Deny("no host call in progress".into())
        );
        assert!(grants.calls.lock().unwrap().is_empty());

        let host = CallIdentity::host_function(
            "a",
            &HostCallContext {
                agent_id: "root".into(),
                trace_id: String::new(),
                turn_id: None,
                capability: "fs".into(),
                function: "ns-fs::read".into(),
                run_id: None,
                iteration: None,
            },
        );
        let decision = scope_sync(host, || check_a.check("fs", &CapParams::empty()));
        assert_eq!(decision, GrantDecision::Allow);
        assert_eq!(
            *grants.calls.lock().unwrap(),
            vec![("root".into(), "fs".into(), "ns-fs::read".into())]
        );
        grants.calls.lock().unwrap().clear();

        let tool = CallIdentity::tool("a", "root", "fixture.echo", "call");
        let decision = scope_sync(tool, || check_a.check("tools", &CapParams::empty()));
        assert_eq!(decision, GrantDecision::Allow);
        assert_eq!(
            *grants.calls.lock().unwrap(),
            vec![(
                "root".into(),
                "tools".into(),
                "tool::fixture.echo/call".into()
            )]
        );
        grants.calls.lock().unwrap().clear();

        let host = CallIdentity::host_function(
            "a",
            &HostCallContext {
                agent_id: "root".into(),
                trace_id: String::new(),
                turn_id: None,
                capability: "fs".into(),
                function: "ns-fs::read".into(),
                run_id: None,
                iteration: None,
            },
        );
        let decision = scope_sync(host, || check_b.check("fs", &CapParams::empty()));
        assert_eq!(
            decision,
            GrantDecision::Deny("host call belongs to another extension".into())
        );
        assert!(grants.calls.lock().unwrap().is_empty());

        gate.revoke();
        assert_eq!(
            check_a.check("fs", &CapParams::empty()),
            GrantDecision::Deny("composition stopped".into())
        );

        let live = Revocation::new();
        let check_a = view("a", &grants, live);
        assert_eq!(
            check_a.check("a:b", &CapParams::empty()),
            GrantDecision::Deny("invalid capability".into())
        );
        assert!(grants.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn module_001_ac31_grant_check_scope_survives_await_not_spawned_task() {
        let grants = Arc::new(RecordingGrants {
            calls: Mutex::new(Vec::new()),
        });
        let check_a = view("a", &grants, Revocation::new());
        let id = CallIdentity::host_function(
            "a",
            &HostCallContext {
                agent_id: "root".into(),
                trace_id: String::new(),
                turn_id: None,
                capability: "fs".into(),
                function: "ns-fs::read".into(),
                run_id: None,
                iteration: None,
            },
        );
        let saw_inside = Arc::new(Mutex::new(false));
        let saw_spawned = Arc::new(Mutex::new(true));
        scope(id, async {
            assert!(current().is_some());
            tokio::task::yield_now().await;
            assert!(current().is_some());
            *saw_inside.lock().unwrap() = true;
            let flag = Arc::clone(&saw_spawned);
            tokio::spawn(async move {
                *flag.lock().unwrap() = current().is_some();
            })
            .await
            .unwrap();
            let _ = check_a.check("fs", &CapParams::empty());
        })
        .await;
        assert!(*saw_inside.lock().unwrap());
        assert!(!*saw_spawned.lock().unwrap());
        assert_eq!(grants.calls.lock().unwrap().len(), 1);
    }
}

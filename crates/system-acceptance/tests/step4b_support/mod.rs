//! Backbone Step 4b (2026-06-08) — shared test-side wiring for the
//! await↔run-manager suspend/resume/pause→close witnesses (SYS-AC-015/016/017).
//!
//! Track-H pattern: the witnesses construct the REAL chain test-side —
//! real `RunManager` (MODULE-008) + real `AwaitSessionManagerImpl` +
//! real `AwaitRepliesHandler` + real `AwaitSessionManagerRef` (MODULE-007) + a
//! recording `EventBusEmit` capturing the real M008 `run.*` emissions. The only
//! doubles are the external child peer (`OkDispatcher`, the sanctioned
//! external-peer stand-in) and the guest (we drive the REAL host-fn `call` with a
//! test-constructed `HostCallContext{run_id:Some}`, the exact code path a guest's
//! `await-replies` import resolves to). The `RunManagerSuspendSink` adapter (the
//! composition glue the production daemon will own — R9) lives HERE, test-side.

#![allow(dead_code)]

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;

use advance_messaging::MailboxDispatcher;
use advance_reply_tracker::{
    AwaitRepliesHandler, AwaitSessionManagerImpl, AwaitSessionManagerRef, ManagerOptions,
    RunSuspendSink,
};
use advance_run_manager::{RunConfig, RunId, RunManager};
use advance_runtime::host_registry::HostCallContext;
use advance_shared_types::await_session::{
    AgentAwaitRequest, AwaitRequest, AwaitSessionRef, ReplyResult, ReplyStatus, SessionId,
};
use advance_shared_types::event::Event;
use advance_shared_types::mailbox::{Message, MessageContext, MsgError, NotifyError};
use advance_shared_types::traits::EventBusEmit;
use wasmtime::component::Val;

/// Recording `EventBusEmit` — captures the REAL M008 `run.*` emissions for
/// assertions (the events are genuinely emitted by the real `RunManager`).
#[derive(Default)]
pub struct RecordingEmitter {
    pub events: StdMutex<Vec<Event>>,
}
impl EventBusEmit for RecordingEmitter {
    fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

/// Sanctioned external-peer double: slot dispatch succeeds → the await parks.
pub struct OkDispatcher;
#[async_trait]
impl MailboxDispatcher for OkDispatcher {
    async fn deliver(&self, _t: &str, _m: Message) -> Result<(), MsgError> {
        Ok(())
    }
    async fn reply(&self, _f: &str, _id: &str, _p: Vec<u8>) -> Result<(), MsgError> {
        Ok(())
    }
    async fn notify_agent(
        &self,
        _f: &str,
        _t: &str,
        _p: Vec<u8>,
        _c: Option<MessageContext>,
    ) -> Result<(), NotifyError> {
        Ok(())
    }
}

/// The composition-root ADAPTER: impl the reply-tracker-local `RunSuspendSink`
/// PORT over the real `RunManager` by delegating to `suspend_run` /
/// `resume_run_if_suspended` (the atomic Suspended-only await-completion resume).
/// (Production daemon ownership of this adapter is the R9 follow-up.)
pub struct RunManagerSuspendSink {
    pub rm: Arc<RunManager>,
}
impl RunSuspendSink for RunManagerSuspendSink {
    fn on_await_start(&self, run_id: &str, session_id: &SessionId) -> bool {
        match RunId::from_string(run_id.to_string()) {
            Ok(rid) => self.rm.suspend_run(&rid, &session_id.0).is_ok(),
            Err(_) => false,
        }
    }
    fn on_await_resolve(&self, run_id: &str, _session_id: &SessionId) {
        if let Ok(rid) = RunId::from_string(run_id.to_string()) {
            // ATOMIC await-completion resume: resumes ONLY if the run is still
            // Suspended, so a concurrent pause/cancel that already left Suspended
            // is never clobbered back to Active (closes the resume-vs-pause race).
            // Ok(false) = no-op (run already left Suspended).
            match self
                .rm
                .resume_run_if_suspended(&rid, "await_complete".to_string())
            {
                Ok(true) => {}
                Ok(false) => eprintln!("step4b: resume no-op (run left Suspended)"),
                Err(e) => eprintln!("step4b: resume_run_if_suspended error: {e:?}"),
            }
        }
    }
}

/// The fully-wired real chain for a witness.
pub struct Wired {
    pub rm: Arc<RunManager>,
    pub manager: Arc<AwaitSessionManagerImpl>,
    pub handler: Arc<AwaitRepliesHandler>,
    pub emitter: Arc<RecordingEmitter>,
    pub run_id: RunId,
    pub agent: String,
}

impl Wired {
    /// Build the real chain: AwaitSessionManagerImpl → AwaitSessionManagerRef →
    /// RunManager(.with_await_session_ref) → RunManagerSuspendSink → sink-equipped
    /// AwaitRepliesHandler, plus an Active run via ensure_run.
    pub fn build(agent: &str) -> Self {
        let dispatcher: Arc<dyn MailboxDispatcher> = Arc::new(OkDispatcher);
        let manager = Arc::new(AwaitSessionManagerImpl::new(
            dispatcher,
            ManagerOptions::default(),
        ));

        let aref: Arc<dyn AwaitSessionRef> =
            Arc::new(AwaitSessionManagerRef::new(Arc::clone(&manager)));

        let emitter = Arc::new(RecordingEmitter::default());
        let bus: Arc<dyn EventBusEmit> = Arc::clone(&emitter) as Arc<dyn EventBusEmit>;
        let rm = Arc::new(RunManager::new(bus).with_await_session_ref(aref));

        let run_id = rm
            .ensure_run(agent, agent, RunConfig::default())
            .expect("ensure_run");

        let sink: Arc<dyn RunSuspendSink> = Arc::new(RunManagerSuspendSink {
            rm: Arc::clone(&rm),
        });
        let handler =
            Arc::new(AwaitRepliesHandler::new(Arc::clone(&manager)).with_run_suspend_sink(sink));

        Self {
            rm,
            manager,
            handler,
            emitter,
            run_id,
            agent: agent.to_string(),
        }
    }

    /// `HostCallContext` carrying the session run id (the seam the harness
    /// `call_host_fn*` helpers hardcode to `None`).
    pub fn ctx(&self) -> HostCallContext {
        HostCallContext {
            agent_id: self.agent.clone(),
            trace_id: "tr-step4b".to_string(),
            turn_id: None,
            capability: "messaging".to_string(),
            function: "agent-messaging::await-replies".to_string(),
            run_id: Some(self.run_id.to_string()),
            iteration: None,
        }
    }

    pub fn events_of(&self, event_type: &str) -> Vec<Event> {
        self.emitter
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.event_type == event_type)
            .cloned()
            .collect()
    }

    pub fn event_count(&self, event_type: &str) -> usize {
        self.events_of(event_type).len()
    }

    /// Index of the first event of `event_type` in emission order (or None).
    pub fn first_index_of(&self, event_type: &str) -> Option<usize> {
        self.emitter
            .events
            .lock()
            .unwrap()
            .iter()
            .position(|e| e.event_type == event_type)
    }
}

/// One-agent-slot await-replies WIT params (`list<await-request>`, `await-options`).
pub fn single_slot_params(target: &str, corr: &str) -> Vec<Val> {
    vec![
        Val::List(vec![Val::Variant(
            "agent-request".into(),
            Some(Box::new(Val::Record(vec![
                ("target".into(), Val::String(target.into())),
                ("payload".into(), Val::List(vec![])),
                ("correlation-id".into(), Val::String(corr.into())),
                ("context".into(), Val::Option(None)),
            ]))),
        )]),
        Val::Record(vec![
            ("mode".into(), Val::Variant("all-of".into(), None)),
            ("idle-timeout-secs".into(), Val::Option(None)),
            (
                "on-idle-timeout".into(),
                Val::Variant("return-partial".into(), None),
            ),
            ("keep-losers".into(), Val::Bool(false)),
        ]),
    ]
}

pub fn agent_req(target: &str, corr: &str) -> AwaitRequest {
    AwaitRequest::AgentRequest(AgentAwaitRequest {
        target: target.to_string(),
        payload: vec![],
        correlation_id: corr.to_string(),
        context: None,
    })
}

pub fn completed_reply(slot: u32, source: &str) -> ReplyResult {
    ReplyResult {
        slot,
        source: source.to_string(),
        payload: b"ok".to_vec(),
        status: ReplyStatus::Completed,
        received_at: chrono::Utc::now(),
        task_id: None,
    }
}

/// Real-time poll (robust under parallel test load).
pub async fn wait_until<F: Fn() -> bool>(pred: F, what: &str) {
    for _ in 0..3000 {
        if pred() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("timed out waiting for: {what}");
}

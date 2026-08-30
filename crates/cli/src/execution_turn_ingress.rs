//! Authenticated composition-root ingress for external execution turns.
//!
//! POST and channel adapters hand this type a fully normalized `Message`. It
//! binds host-owned C216 routing facts and publishes through the protected
//! mailbox path; callers never receive admission/publish authority directly.

use std::sync::Arc;

use advance_messaging::{MailboxStore, TurnMailboxDelivery};
use advance_shared_types::await_session::SessionId;
use advance_shared_types::mailbox::{Message, MsgError};
use advance_shared_types::turn_attribution::{QueuedTurnSpec, TurnCompletionOwner};

pub struct ExecutionTurnIngress {
    store: Arc<MailboxStore>,
}

impl ExecutionTurnIngress {
    pub(crate) fn new(store: Arc<MailboxStore>) -> Self {
        Self { store }
    }

    /// Publish one normalized external message as an execution-owned turn.
    /// The `exec_` session namespace and slot zero are reserved by
    /// `MailboxStore::publish_execution_turn`; a fresh host UUID prevents route
    /// aliasing across restarts without accepting any caller-supplied session.
    pub(crate) fn publish(&self, message: Message) -> Result<(), MsgError> {
        let spec = QueuedTurnSpec {
            turn_id: message.id.clone(),
            expected_agent: message.to.clone(),
            parent_agent: message.from.clone(),
            session_id: SessionId(format!("exec_{}", uuid::Uuid::new_v4().simple())),
            slot: 0,
            completion_owner: TurnCompletionOwner::ExecutionBoundary,
            original_task_id: message
                .context
                .as_ref()
                .and_then(|context| context.task_id.clone()),
            original_run_id: message
                .context
                .as_ref()
                .and_then(|context| context.run_id.clone()),
            original_reply_to: message
                .context
                .as_ref()
                .and_then(|context| context.in_reply_to.clone()),
        };
        let target = message.to.clone();
        self.store.publish_execution_turn(TurnMailboxDelivery {
            target,
            message,
            spec,
        })
    }
}

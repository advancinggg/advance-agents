//! Wave-12 Lane B — `MailboxRunInterruptSink`: MODULE-006's concrete impl of
//! the shared-types [`RunInterruptSink`] dependency-inversion port (CONTRACT-182).
//!
//! MODULE-008 crash-recovery (`recover_on_startup`), after emitting the
//! `run.interrupted` event, pushes a synthesized `Message::RunInterrupted`
//! through this sink into the recovered run's controller-agent mailbox. Because
//! [`MessageKind::Control`](advance_shared_types::mailbox::MessageKind::Control)
//! routes to the mailbox high-priority queue, the standard agent-loop
//! `recv → handle-message` path runs the controller's handle-message on it — no
//! new dispatch path. The end-to-end witness (real interruption → controller
//! handle-message) is SYS-AC-121 (SYS-J-37), flipped by a later mainline harvest
//! once `cold_start_recovery` + this sink are wired into `advance start` boot.
//!
//! # Trust posture
//!
//! The sink delivers straight into [`MailboxStore`] via `get_or_create(...)?
//! .deliver(...)`, which enforces the slice-A header/payload/context length
//! caps but does NOT run the dispatcher's `is_safe_id` charset gate (that gate
//! lives in `MailboxDispatcherImpl`, on the guest-reachable send/notify/reply
//! paths, which this host-internal recovery path does not traverse). This is
//! intentional: `controller_agent` is host-supplied by the MODULE-008 recovery
//! walk (read from persisted run state), not guest-influenced — exactly the same
//! provenance as a host-originated system control message. See MODULE-006 §3.8.

use std::sync::Arc;

use advance_shared_types::mailbox::{Message, MsgError, RunInterruptSink};

use crate::mailbox::MailboxStore;

/// Concrete [`RunInterruptSink`] over a per-process [`MailboxStore`]. Construct
/// with the SAME store the agent-loop `StoreMailboxReader` recvs from so the
/// delivered `Message::RunInterrupted` reaches the controller's handle-message.
///
/// # Keying caveat (the SYS-AC-121 harvest MUST reconcile this)
///
/// The message is delivered into `MailboxStore` keyed by the run's
/// `controller_agent` **verbatim** (the dispatcher's `is_safe_id` gate is
/// bypassed — see `deliver_run_interrupted`). The mailbox key MUST be the SAME
/// id form the agent-loop `StoreMailboxReader::recv` polls on. In production
/// `RunManager::ensure_run` may store a **bare** controller id (e.g.
/// `default-agent`) while the agent loop drains the **colon-prefixed**
/// `agent:default` — if those differ, a `RunInterrupted` enqueued under the bare
/// id lands in an ORPHAN mailbox that no loop drains (handle-message never
/// runs). The build-lane witness uses a single matching id so the mechanism is
/// proven; the harvest that wires this into `advance start` MUST ensure the run's
/// `controller_agent` and the agent-loop recv id are the same form (or normalize
/// at the sink) before flipping SYS-AC-121. See MODULE-008 §3.6.
pub struct MailboxRunInterruptSink {
    store: Arc<MailboxStore>,
}

impl MailboxRunInterruptSink {
    pub fn new(store: Arc<MailboxStore>) -> Self {
        Self { store }
    }
}

impl RunInterruptSink for MailboxRunInterruptSink {
    fn deliver_run_interrupted(
        &self,
        controller_agent: &str,
        run_id: &str,
        task_id: &str,
        reason: &str,
    ) -> Result<(), MsgError> {
        let msg = Message::run_interrupted(controller_agent, run_id, task_id, reason);
        // Control kind → high-priority queue; the standard recv pops it first.
        self.store.get_or_create(controller_agent)?.deliver(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use advance_shared_types::mailbox::{ControlMessage, MessageKind};
    use std::num::NonZeroUsize;

    // RIS-U1 — the sink delivers a decodable Control message into the target's
    // mailbox (sync: poll-pops the high-priority queue, no tokio needed).
    #[test]
    fn sink_delivers_decodable_run_interrupted_into_controller_mailbox() {
        let store = Arc::new(MailboxStore::new(NonZeroUsize::new(8).unwrap()));
        let sink = MailboxRunInterruptSink::new(Arc::clone(&store));

        sink.deliver_run_interrupted("agent:controller", "run-7", "task-1", "crash-recovery")
            .expect("delivery succeeds");

        let mb = store
            .get("agent:controller")
            .expect("mailbox created by the sink");
        assert_eq!(mb.depth(), 1, "exactly one message queued");
        let msg = mb
            .poll()
            .expect("Control message poppable from high-priority queue");
        assert_eq!(msg.kind, MessageKind::Control);
        assert_eq!(msg.to, "agent:controller");
        assert_eq!(msg.from, "system");
        let decoded: ControlMessage =
            serde_json::from_slice(&msg.payload).expect("payload decodes");
        assert_eq!(
            decoded,
            ControlMessage::RunInterrupted {
                run_id: "run-7".into(),
                reason: "crash-recovery".into()
            }
        );
    }
}

//! Where the composition's lines go.
//!
//! The composition never writes to stdout or stderr itself: every line it emits —
//! the readiness line, status lines, warnings, and the diagnostics of the tasks
//! and objects it starts — is handed to a [`ComposeLog`]. The `advance` binary's
//! sink writes each line to the stream named by [`ComposeLogLine::stream`], so its
//! output is exactly what `advance start` printed before; an embedder may route
//! the lines anywhere, or drop them with [`NullComposeLog`].

/// The stream a line belongs to when it is printed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LogStream {
    Stdout,
    Stderr,
}

/// One line the composition emits (no trailing newline).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComposeLogLine {
    /// Where `advance start` prints the line.
    pub stream: LogStream,
    /// Stable machine key, one of [`log_keys::ALL`].
    pub key: &'static str,
    /// The exact text `advance start` prints.
    pub text: String,
}

/// Receives every line the composition emits.
pub trait ComposeLog: Send + Sync + 'static {
    /// Every line except the readiness line. Infallible: a sink that cannot write
    /// drops the line.
    fn line(&self, line: &ComposeLogLine);

    /// The readiness line `advance: runtime ready (workspace="…")` (stdout, key
    /// [`log_keys::READY`]). An `Err` stops the composition at that point.
    fn ready(&self, line: &ComposeLogLine) -> std::io::Result<()>;
}

/// Discards every line. Never prints.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullComposeLog;

impl ComposeLog for NullComposeLog {
    fn line(&self, _line: &ComposeLogLine) {}

    fn ready(&self, _line: &ComposeLogLine) -> std::io::Result<()> {
        Ok(())
    }
}

/// The stable key of every line the composition emits.
pub mod log_keys {
    // The daemon composition.
    /// stdout: `advance: runtime ready (workspace="…")`.
    pub const READY: &str = "start.ready";
    /// stdout: channels are configured, so the `POST /msg` listener is not started.
    pub const CHANNELS_POST_MSG_DISABLED: &str = "start.channels_post_msg_disabled";
    /// stderr: the auto-mode scheduler tick loop did not start.
    pub const AUTO_TICK_FAILED: &str = "start.auto_tick_failed";
    /// stdout: the auto-mode scheduler tick loop is running.
    pub const AUTO_TICK_RUNNING: &str = "start.auto_tick_running";
    /// stdout: continuous component reconciliation is wired.
    pub const RECONCILIATION_WIRED: &str = "start.reconciliation_wired";
    /// stderr: the readiness walk did not run.
    pub const READINESS_WALK_FAILED: &str = "start.readiness_walk_failed";
    /// stderr: the readiness walk is skipped (the component registry did not open).
    pub const READINESS_WALK_SKIPPED: &str = "start.readiness_walk_skipped";
    /// stderr: the readiness walk is skipped (the component registry open timed out).
    pub const READINESS_WALK_TIMEOUT: &str = "start.readiness_walk_timeout";
    /// stdout: `advance: shutting down`.
    pub const SHUTTING_DOWN: &str = "start.shutting_down";
    /// stdout: the deployed agent component is loaded and its loop serves messages.
    pub const AGENT_LOOP_WIRED: &str = "start.agent_loop_wired";
    /// stdout: the `POST /msg` listener address.
    pub const MSG_LISTENER: &str = "start.msg_listener";
    /// stderr: the `POST /msg` listener stopped with an error.
    pub const MSG_LISTENER_STOPPED: &str = "start.msg_listener_stopped";
    /// stderr: the durable memory index did not open; the in-memory index is used.
    pub const MEMORY_INDEX_FALLBACK: &str = "start.memory_index_fallback";

    // Channels.
    /// stdout: the channel `/hooks` listener address.
    pub const HOOKS_LISTENER: &str = "channels.hooks_listener";
    /// stderr: the channel `/hooks` listener stopped with an error.
    pub const HOOKS_LISTENER_STOPPED: &str = "channels.hooks_listener_stopped";
    /// stderr: the channel pump rejected an event with an invalid adapter identity.
    pub const PUMP_INVALID_IDENTITY: &str = "channels.pump_invalid_identity";
    /// stderr: the channel pump dropped an event (mailbox publish failed).
    pub const PUMP_DROPPED: &str = "channels.pump_dropped";

    // Agent loops and their observers.
    /// stderr: a crash cascade failed (swallowed).
    pub const CRASH_CASCADE_FAILED: &str = "crash_cascade.handle_crash_failed";
    /// stderr: the auto-tick pending-cancel queue is at its cap.
    pub const AUTO_TICK_PENDING_CANCEL_CAP: &str = "auto_tick.pending_cancel_cap";
    /// stderr: an auto-tick cancel failed.
    pub const AUTO_TICK_CANCEL_FAILED: &str = "auto_tick.cancel_failed";
    /// stderr: an auto-tick settle failed.
    pub const AUTO_TICK_SETTLE_FAILED: &str = "auto_tick.settle_failed";
    /// stderr: recording a completed round failed.
    pub const COMPLETE_ROUND_FAILED: &str = "agent_loop.complete_round_failed";
    /// stderr: a child gets no `fs` grant (the parent's grant is path-restricted).
    pub const PERCHILD_NO_FS_GRANT: &str = "perchild.no_fs_grant";
    /// stderr: a child gets no grant for a capability.
    pub const PERCHILD_NO_GRANT: &str = "perchild.no_grant";
    /// stderr: a child is not served (the runtime is not bound).
    pub const PERCHILD_UNBOUND: &str = "perchild.unbound";
    /// stderr: a child is not served (no driver).
    pub const PERCHILD_NO_DRIVER: &str = "perchild.no_driver";
    /// stderr: a child is not served (its driver did not resolve).
    pub const PERCHILD_DRIVER_RESOLVE_FAILED: &str = "perchild.driver_resolve_failed";
    /// stderr: a child is not served (its driver did not load).
    pub const PERCHILD_LOAD_FAILED: &str = "perchild.load_failed";
    /// stderr: a child is not served (invalid component id).
    pub const PERCHILD_INVALID_COMPONENT_ID: &str = "perchild.invalid_component_id";
    /// stderr: a child is not served (its id collides with an existing agent).
    pub const PERCHILD_COLON_COLLISION: &str = "perchild.colon_collision";
    /// stderr: a turn-end stream settlement panicked off the serve loop.
    pub const REAP_DEFERRED_SETTLE_PANICKED: &str = "reap.deferred_settle_panicked";
    /// stderr: a turn-end stream reap panicked.
    pub const REAP_TURN_END_PANICKED: &str = "reap.turn_end_reap_panicked";
    /// stderr: a `.meta.yaml` entry could not be ensured for a described file.
    pub const VLM_META_ENSURE_FAILED: &str = "vlm.meta_ensure_failed";
    /// stderr: a `.meta.yaml` description update failed.
    pub const VLM_META_UPDATE_FAILED: &str = "vlm.meta_update_failed";
    /// stderr: a `.meta.yaml` write failed.
    pub const VLM_META_WRITE_FAILED: &str = "vlm.meta_write_failed";

    // Packs, data and the component registry.
    /// stderr: a data operation is bound to a tool that is not registered.
    pub const DATA_OP_TOOL_MISSING: &str = "data.op_tool_missing";
    /// stderr: a new pack-apply warning.
    pub const PACKS_WARN: &str = "packs.warn";
    /// stderr: the packs dir changed but its rescan failed.
    pub const PACKS_RESCAN_FAILED: &str = "packs.rescan_failed";
    /// stderr: a component registry reconciliation read failed.
    pub const WALK_REGISTRY_READ_FAILED: &str = "walk.registry_read_failed";

    // Capability wiring.
    /// stderr: the git half of a memory rollback failed.
    pub const ROLLBACK_MEMORY_GIT_FAILED: &str = "wiring.rollback_memory_git_failed";
    /// stderr: secrets were migrated into the synchronized keychain.
    pub const KEYCHAIN_MIGRATED: &str = "wiring.keychain_migrated";
    /// stderr: the memory-rollback git half is not wired (not a git repository).
    pub const ROLLBACK_MEMORY_NOT_REPO: &str = "wiring.rollback_memory_not_repo";
    /// stderr: the memory-rollback git half is not wired (rollback unavailable).
    pub const ROLLBACK_MEMORY_UNAVAILABLE: &str = "wiring.rollback_memory_unavailable";
    /// stderr: the `data` tool is not registered.
    pub const DATA_TOOL_NOT_REGISTERED: &str = "wiring.data_tool_not_registered";
    /// stderr: the Client API history / events adapters are unavailable.
    pub const CLIENT_API_HISTORY_UNAVAILABLE: &str = "wiring.client_api_history_unavailable";
    /// stderr: the Client API and Web Console address.
    pub const CLIENT_API_LISTENING: &str = "wiring.client_api_listening";
    /// stderr: the Client API is unavailable (loopback bind failed).
    pub const CLIENT_API_UNAVAILABLE: &str = "wiring.client_api_unavailable";

    // The ordered shutdown (each only when a bound elapses, a listener fails or a hook
    // panics).
    /// stderr: Client API requests were still running when the drain budget ran out.
    pub const COMPOSE_CLIENT_API_DRAIN_OVERRUN: &str = "compose.client_api_drain_overrun";
    /// stderr: the Client API listener had stopped with an error.
    pub const COMPOSE_CLIENT_API_SERVE_FAILED: &str = "compose.client_api_serve_failed";
    /// stderr: `POST /msg` requests were still running when the drain budget ran out.
    pub const COMPOSE_MSG_LISTENER_DRAIN_OVERRUN: &str = "compose.msg_listener_drain_overrun";
    /// stderr: `/hooks` requests were still running when the drain budget ran out.
    pub const COMPOSE_HOOKS_DRAIN_OVERRUN: &str = "compose.hooks_drain_overrun";
    /// stderr: a ChatGPT token renewal is still finishing (the shutdown waits for it).
    pub const COMPOSE_SIGN_IN_OVERRUN: &str = "compose.sign_in_overrun";
    /// stderr: a thread was still running when its join budget ran out (left detached).
    pub const COMPOSE_THREAD_JOIN_OVERRUN: &str = "compose.thread_join_overrun";
    /// stderr: an extension's shutdown hook did not finish within its bound (abandoned).
    pub const EXT_SHUTDOWN_ABANDONED: &str = "ext.shutdown_abandoned";
    /// stderr: an extension's shutdown hook panicked (the shutdown continues).
    pub const EXT_SHUTDOWN_PANICKED: &str = "ext.shutdown_panicked";
    /// stderr: an extension's `on_started` returned an error (the runtime stays up).
    pub const EXT_ON_STARTED_FAILED: &str = "ext.on_started_failed";
    /// stderr: an extension's `on_started` panicked (the runtime stays up).
    pub const EXT_ON_STARTED_PANICKED: &str = "ext.on_started_panicked";
    /// stderr: a task an extension spawned panicked (the task ended).
    pub const EXT_TASK_PANICKED: &str = "ext.task_panicked";
    /// stderr: extension tasks were still running 5s after cancellation (abandoned).
    pub const EXT_TASKS_ABANDONED: &str = "ext.tasks_abandoned";
    /// stderr: an extension host function panicked (in-band, trap, or in drop).
    pub const EXT_HOST_FUNCTION_PANICKED: &str = "ext.host_function_panicked";
    /// stderr: a PanicAnswer was unusable (wrong arity, wrong type, or it panicked).
    pub const EXT_HOST_FUNCTION_ANSWER_INVALID: &str = "ext.host_function_answer_invalid";
    /// stderr: an extension native tool panicked (the call failed, or in drop).
    pub const EXT_TOOL_PANICKED: &str = "ext.tool_panicked";

    // Objects the daemon does not start, available to embedders.
    /// stdout: an agent reply preview.
    pub const REPLY_AGENT_REPLY: &str = "reply.agent_reply";
    /// stderr: a verified webhook could not fire its trigger.
    pub const WEBHOOK_TRIGGER_SEND_FAILED: &str = "webhook.trigger_send_failed";
    /// stderr: the pre-turn checkpoint was not refreshed.
    pub const ROLLBACK_MARK_PRE_TURN_FAILED: &str = "rollback.mark_pre_turn_failed";
    /// stderr: refreshing the pre-turn checkpoint panicked.
    pub const ROLLBACK_MARK_PRE_TURN_PANICKED: &str = "rollback.mark_pre_turn_panicked";
    /// stderr: no fresh pre-turn checkpoint, so no workspace rollback.
    pub const ROLLBACK_NOT_ARMED: &str = "rollback.not_armed";
    /// stderr: the workspace rollback could not be constructed.
    pub const ROLLBACK_CTOR_FAILED: &str = "rollback.ctor_failed";
    /// stderr: the workspace rollback failed.
    pub const ROLLBACK_REVERT_FAILED: &str = "rollback.revert_failed";
    /// stderr: a `.meta.yaml` is kept because its directory retains content.
    pub const ROLLBACK_SIDECAR_KEPT: &str = "rollback.sidecar_kept";
    /// stderr: a stale `.meta.yaml` could not be removed.
    pub const ROLLBACK_SIDECAR_REMOVE_FAILED: &str = "rollback.sidecar_remove_failed";
    /// stderr: the compensating rollback commit failed.
    pub const ROLLBACK_COMPENSATING_COMMIT_FAILED: &str = "rollback.compensating_commit_failed";

    /// Every key above, in catalogue order.
    pub const ALL: &[&str] = &[
        READY,
        CHANNELS_POST_MSG_DISABLED,
        AUTO_TICK_FAILED,
        AUTO_TICK_RUNNING,
        RECONCILIATION_WIRED,
        READINESS_WALK_FAILED,
        READINESS_WALK_SKIPPED,
        READINESS_WALK_TIMEOUT,
        SHUTTING_DOWN,
        AGENT_LOOP_WIRED,
        MSG_LISTENER,
        MSG_LISTENER_STOPPED,
        MEMORY_INDEX_FALLBACK,
        HOOKS_LISTENER,
        HOOKS_LISTENER_STOPPED,
        PUMP_INVALID_IDENTITY,
        PUMP_DROPPED,
        CRASH_CASCADE_FAILED,
        AUTO_TICK_PENDING_CANCEL_CAP,
        AUTO_TICK_CANCEL_FAILED,
        AUTO_TICK_SETTLE_FAILED,
        COMPLETE_ROUND_FAILED,
        PERCHILD_NO_FS_GRANT,
        PERCHILD_NO_GRANT,
        PERCHILD_UNBOUND,
        PERCHILD_NO_DRIVER,
        PERCHILD_DRIVER_RESOLVE_FAILED,
        PERCHILD_LOAD_FAILED,
        PERCHILD_INVALID_COMPONENT_ID,
        PERCHILD_COLON_COLLISION,
        REAP_DEFERRED_SETTLE_PANICKED,
        REAP_TURN_END_PANICKED,
        VLM_META_ENSURE_FAILED,
        VLM_META_UPDATE_FAILED,
        VLM_META_WRITE_FAILED,
        DATA_OP_TOOL_MISSING,
        PACKS_WARN,
        PACKS_RESCAN_FAILED,
        WALK_REGISTRY_READ_FAILED,
        ROLLBACK_MEMORY_GIT_FAILED,
        KEYCHAIN_MIGRATED,
        ROLLBACK_MEMORY_NOT_REPO,
        ROLLBACK_MEMORY_UNAVAILABLE,
        DATA_TOOL_NOT_REGISTERED,
        CLIENT_API_HISTORY_UNAVAILABLE,
        CLIENT_API_LISTENING,
        CLIENT_API_UNAVAILABLE,
        COMPOSE_CLIENT_API_DRAIN_OVERRUN,
        COMPOSE_CLIENT_API_SERVE_FAILED,
        COMPOSE_MSG_LISTENER_DRAIN_OVERRUN,
        COMPOSE_HOOKS_DRAIN_OVERRUN,
        COMPOSE_SIGN_IN_OVERRUN,
        COMPOSE_THREAD_JOIN_OVERRUN,
        EXT_SHUTDOWN_ABANDONED,
        EXT_SHUTDOWN_PANICKED,
        EXT_ON_STARTED_FAILED,
        EXT_ON_STARTED_PANICKED,
        EXT_TASK_PANICKED,
        EXT_TASKS_ABANDONED,
        EXT_HOST_FUNCTION_PANICKED,
        EXT_HOST_FUNCTION_ANSWER_INVALID,
        EXT_TOOL_PANICKED,
        REPLY_AGENT_REPLY,
        WEBHOOK_TRIGGER_SEND_FAILED,
        ROLLBACK_MARK_PRE_TURN_FAILED,
        ROLLBACK_MARK_PRE_TURN_PANICKED,
        ROLLBACK_NOT_ARMED,
        ROLLBACK_CTOR_FAILED,
        ROLLBACK_REVERT_FAILED,
        ROLLBACK_SIDECAR_KEPT,
        ROLLBACK_SIDECAR_REMOVE_FAILED,
        ROLLBACK_COMPENSATING_COMMIT_FAILED,
    ];
}

#[cfg(test)]
mod tests {
    use super::log_keys;

    #[test]
    fn log_keys_are_unique_and_dotted() {
        let mut seen = std::collections::HashSet::new();
        for key in log_keys::ALL {
            assert!(seen.insert(*key), "duplicate log key {key}");
            let (group, name) = key.split_once('.').expect("key has a group");
            assert!(!group.is_empty() && !name.is_empty(), "malformed key {key}");
            assert!(
                key.chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_' || c == '.'),
                "key {key} is not lower_snake.dotted"
            );
        }
        assert_eq!(log_keys::ALL[0], log_keys::READY);
    }
}

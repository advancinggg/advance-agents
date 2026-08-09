//! `ChannelAdapterRegistry` — channel id → channel-adapter agent id.
//!
//! MODULE-006-internal seam used by `MailboxDispatcherImpl::notify_channel`
//! to resolve which agent-style mailbox a channel's adapter component reads
//! (per MODULE-006-AC-14: adapters have agent-style mailboxes in the runtime,
//! not their own private mailbox). **Not a published CONTRACT** — not
//! promoted to shared-types this slice. Production wiring (registering real
//! adapter agent ids from MODULE-016's channel config) is a follow-on slice;
//! the default [`EmptyChannelAdapterRegistry`] makes `notify_channel` return
//! `NotifyError::InvalidTarget("channel_unknown")` until configured.

use std::collections::HashMap;

use advance_shared_types::mailbox::MsgError;

use crate::id_validation::is_safe_id;

/// Resolve a channel id to its adapter agent id.
pub trait ChannelAdapterRegistry: Send + Sync {
    /// Returns the adapter agent id for `channel_id`, or `None` if unknown.
    fn resolve(&self, channel_id: &str) -> Option<String>;
}

/// Default registry — resolves nothing. `notify_channel` on a dispatcher
/// built with this returns `NotifyError::InvalidTarget("channel_unknown")`.
pub struct EmptyChannelAdapterRegistry;

impl ChannelAdapterRegistry for EmptyChannelAdapterRegistry {
    fn resolve(&self, _channel_id: &str) -> Option<String> {
        None
    }
}

/// Per-process upper bound on registered channel adapters (deterministic
/// operational guarantee).
pub const MAX_CHANNEL_ADAPTERS: usize = 1_024;

/// Static channel→adapter map. Built once at wiring time; immutable lookups.
pub struct StaticChannelAdapterRegistry {
    map: HashMap<String, String>,
}

impl Default for StaticChannelAdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl StaticChannelAdapterRegistry {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Register `channel_id → adapter_agent_id`. Validates a non-empty
    /// `channel_id`, an `is_safe_id` + `agent:`-prefixed adapter id, and the
    /// [`MAX_CHANNEL_ADAPTERS`] cap. Errors are invariant identifiers (PII
    /// discipline).
    pub fn insert(
        &mut self,
        channel_id: impl Into<String>,
        adapter_agent_id: impl Into<String>,
    ) -> Result<(), MsgError> {
        let channel_id = channel_id.into();
        let adapter_agent_id = adapter_agent_id.into();
        if channel_id.is_empty() {
            return Err(MsgError::InvalidTarget("channel_id_empty".into()));
        }
        if !is_safe_id(&adapter_agent_id) || !adapter_agent_id.starts_with("agent:") {
            return Err(MsgError::InvalidTarget("adapter_id_invalid".into()));
        }
        if !self.map.contains_key(&channel_id) && self.map.len() >= MAX_CHANNEL_ADAPTERS {
            return Err(MsgError::CapabilityDenied("registry_full".into()));
        }
        self.map.insert(channel_id, adapter_agent_id);
        Ok(())
    }
}

impl ChannelAdapterRegistry for StaticChannelAdapterRegistry {
    fn resolve(&self, channel_id: &str) -> Option<String> {
        self.map.get(channel_id).cloned()
    }
}

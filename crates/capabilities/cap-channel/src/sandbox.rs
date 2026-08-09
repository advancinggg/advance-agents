//! Per-adapter sandbox capability declarations (MODULE-016 §1.7 + AC-06).
//!
//! [`AdapterCapabilitySet`] is the host-authoritative description of an adapter
//! type's minimum capability set + outbound allowlist. The actual
//! capability-grant decision happens in MODULE-013's `GrantCheck` (CONTRACT-121);
//! cap-channel only declares the minimum set per adapter and consumes the
//! allowlist when building synthetic `HttpCapability` values in
//! [`crate::outbound::OutboundDispatcher`].
//!
//! Slice B ships 4 const presets (telegram / slack / signal / webhook) plus a
//! [`preset_default_deny`] fallback for `AdapterType::Other(*)`.

use std::collections::BTreeSet;

use advance_shared_types::security_validator::Allowlist;

use crate::types::AdapterType;

/// Which [`crate::egress::OutboundTransport`] impl an adapter's outbound replies
/// use (Phase-2 Step-3). `Http` is the only kind in Step-3 (`HttpEgress`);
/// `LocalProcess` / `Push` are designed-for-deferred (iMessage/Signal-local,
/// APNs/FCM — ADR L6). The pump/egress sink selects the transport from this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressKind {
    /// Outbound over the `HttpSecurityChain` (`HttpEgress`). The only kind that
    /// ships in Step-3.
    Http,
}

/// Per-adapter capability set: minimum capabilities + outbound allowlist +
/// egress kind. `BTreeSet` for deterministic ordering in audit logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterCapabilitySet {
    pub adapter: AdapterType,
    pub capabilities: BTreeSet<String>,
    pub outbound_allowlist: Allowlist,
    /// The egress transport selector (Phase-2 Step-3). All Step-3 presets are
    /// `Http`; inbound-only adapters (webhook / default-deny) carry `Http` too
    /// but their empty allowlist denies all egress regardless.
    pub egress_kind: EgressKind,
}

impl AdapterCapabilitySet {
    /// Lookup the host-authoritative preset for an adapter type. Unknown types
    /// (`AdapterType::Other(*)`) get [`preset_default_deny`] (empty cap set +
    /// empty allowlist).
    pub fn preset_for(adapter: &AdapterType) -> Self {
        match adapter {
            AdapterType::Telegram => preset_telegram(),
            AdapterType::Slack => preset_slack(),
            AdapterType::Signal => preset_signal(),
            AdapterType::Webhook => preset_webhook(),
            AdapterType::Other(_) => preset_default_deny(adapter.clone()),
        }
    }

    /// True iff the adapter's capability set is disjoint from the supplied set
    /// of cross-adapter capabilities (e.g. telegram must be disjoint from
    /// {`slack.api`}). Used by audit helpers to verify "no cross-adapter access".
    pub fn is_disjoint_from(&self, forbidden: &BTreeSet<String>) -> bool {
        self.capabilities.is_disjoint(forbidden)
    }
}

fn preset_telegram() -> AdapterCapabilitySet {
    AdapterCapabilitySet {
        adapter: AdapterType::Telegram,
        capabilities: btree_set(&[
            "http.outbound",
            "channel.subscribe",
            "channel.send",
            "notify",
        ]),
        outbound_allowlist: Allowlist {
            patterns: vec!["https://api.telegram.org/".to_string()],
        },
        egress_kind: EgressKind::Http,
    }
}

fn preset_slack() -> AdapterCapabilitySet {
    AdapterCapabilitySet {
        adapter: AdapterType::Slack,
        capabilities: btree_set(&[
            "http.outbound",
            "websocket",
            "channel.subscribe",
            "channel.send",
            "notify",
        ]),
        outbound_allowlist: Allowlist {
            patterns: vec!["https://slack.com/api/".to_string()],
        },
        egress_kind: EgressKind::Http,
    }
}

fn preset_signal() -> AdapterCapabilitySet {
    // Signal's real domain is configurable per the Signal protocol; the
    // placeholder makes the preset shape testable without pinning to a real
    // production endpoint that could go stale.
    AdapterCapabilitySet {
        adapter: AdapterType::Signal,
        capabilities: btree_set(&[
            "http.outbound",
            "channel.subscribe",
            "channel.send",
            "notify",
        ]),
        outbound_allowlist: Allowlist {
            patterns: vec!["https://signal-server.example/".to_string()],
        },
        egress_kind: EgressKind::Http,
    }
}

fn preset_webhook() -> AdapterCapabilitySet {
    // Inbound-only — no legitimate outbound surface, so allowlist is empty
    // (deny-all). If a webhook adapter ever needs to send outbound (e.g. ack
    // back to the webhook origin), a tighter per-adapter set must be added.
    AdapterCapabilitySet {
        adapter: AdapterType::Webhook,
        capabilities: btree_set(&["channel.subscribe", "channel.send", "notify"]),
        outbound_allowlist: Allowlist { patterns: vec![] },
        egress_kind: EgressKind::Http,
    }
}

/// Default-deny preset for unenumerated adapters. Empty capability set + empty
/// outbound allowlist (deny-all). The `subscribe()` path rejects `Other(*)`
/// before this preset would be consumed; the function exists as
/// defense-in-depth.
pub fn preset_default_deny(adapter: AdapterType) -> AdapterCapabilitySet {
    AdapterCapabilitySet {
        adapter,
        capabilities: BTreeSet::new(),
        outbound_allowlist: Allowlist { patterns: vec![] },
        egress_kind: EgressKind::Http,
    }
}

fn btree_set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telegram_preset_has_no_slack_capability() {
        let preset = preset_telegram();
        let forbidden = btree_set(&["slack.api"]);
        assert!(preset.is_disjoint_from(&forbidden));
        assert!(!preset.capabilities.contains("slack.api"));
    }

    #[test]
    fn webhook_preset_has_no_outbound_http() {
        let preset = preset_webhook();
        assert!(!preset.capabilities.contains("http.outbound"));
        assert!(preset.outbound_allowlist.patterns.is_empty());
    }

    #[test]
    fn default_deny_preset_is_empty() {
        let preset = preset_default_deny(AdapterType::Other("discord".into()));
        assert!(preset.capabilities.is_empty());
        assert!(preset.outbound_allowlist.patterns.is_empty());
    }

    #[test]
    fn preset_for_other_routes_to_default_deny() {
        let preset = AdapterCapabilitySet::preset_for(&AdapterType::Other("anything".into()));
        assert!(preset.capabilities.is_empty());
        assert!(preset.outbound_allowlist.patterns.is_empty());
    }

    #[test]
    fn telegram_allowlist_pins_official_api_domain() {
        let preset = preset_telegram();
        assert_eq!(
            preset.outbound_allowlist.patterns,
            vec!["https://api.telegram.org/".to_string()]
        );
    }

    #[test]
    fn slack_preset_includes_websocket() {
        let preset = preset_slack();
        assert!(preset.capabilities.contains("websocket"));
    }
}

//! `DefaultActionValidator` — CONTRACT-113 first impl. MODULE-012 §2.3 + §2.10
//! + §1.5 (Slice D AC-13 amendment).
//!
//! Per the trait's Implementer Invariants
//! (`advance_shared_types::security_validator::ActionValidator`,
//! `crates/shared-types/src/security_validator.rs:130-142`):
//!
//!  1. **Deterministic** — no clock, no I/O, no RNG. Configured thresholds are
//!     taken at construction; identical `(agent_id, actions)` → identical
//!     `Result`. Note: the duplicate-counter `HashMap<&[u8], usize>` below
//!     uses the stdlib's `RandomState` internally for hash bucketing, but
//!     `PartialEq` on `&[u8]` (exact byte comparison) drives bucket-collision
//!     resolution — so the `Result` enum value is invariant under the
//!     per-process `RandomState` seed (only iteration order would vary, and
//!     this impl never iterates the map; it only does `entry().or_insert()`
//!     writes + counter compares, both of which are seed-invariant for the
//!     produced `Result`).
//!  2. **Bounded `O(actions.len())`** — single linear pass with O(1)
//!     amortized HashMap op per action.
//!  3. **Identifier whitelist** — `agent_id` MUST match
//!     `^[A-Za-z0-9_:-]{1,128}$`. This is intentionally broader than
//!     `agent_tree.rs`'s `AgentId` `^[A-Za-z0-9_-]{1,64}$` (per the
//!     Implementer Invariants block above the `AgentId` newtype) and
//!     `skills.rs:15`'s `^[A-Za-z0-9_-]{1,128}$` in two specific ways:
//!       - Length cap = 128 (not 64) — matches skills.rs ceiling.
//!       - `:` allowed — observed in mailbox-test fixtures (e.g.
//!         `agent:parent`, `agent:child` per
//!         `crates/shared-types/tests/mailbox.rs:79-80`) where the canonical
//!         narrow grammar would actually reject those identifiers.
//!         ActionValidator is the post-decode gate; the upstream registration
//!         boundary (MODULE-005 agent-tree) is responsible for the canonical
//!         narrow grammar. ActionValidator's role is to fail-CLOSED on
//!         identifier shapes that nothing upstream would ever produce
//!         (whitespace, control chars, `/`, `\`, `*`, `?`, `<`, `>`, etc.).
//!  4. **Fail-closed** — first violation returns `Err` immediately;
//!     remaining actions are NOT inspected.
//!
//! AC-13 §1.5 amended Slice D: the `RateExceeded(target)` variant is reserved
//! for a future per-target rate-limiter slice (would require an `AgentAction`
//! target hint that does not yet exist — `payload: Vec<u8>` is opaque to
//! MODULE-012 per `mailbox.rs:151-152`). The deterministic, clock-free proxy
//! that the trait surface admits today is **batch-local duplicate-payload
//! burst** detection, returned as
//! `SecurityError::InvalidAction("duplicate-payload burst: ...")`.

use std::collections::HashMap;

use advance_shared_types::mailbox::AgentAction;
use advance_shared_types::security_validator::{ActionValidator, SecurityError};

/// Per §2.10 `security.action_validator.max_message_size`.
pub const DEFAULT_MAX_MESSAGE_SIZE_BYTES: usize = 1 << 20;

/// Per §1.5 AC-13 amendment (Slice D): batch-local duplicate-payload burst
/// threshold. A counter that EXCEEDS this value (strict `>`, not `>=`)
/// triggers `SecurityError::InvalidAction`.
pub const DEFAULT_MAX_DUPLICATE_PAYLOADS: usize = 16;

const MAX_AGENT_ID_LEN: usize = 128;

pub struct DefaultActionValidator {
    max_message_size: usize,
    max_duplicate_payloads: usize,
}

impl DefaultActionValidator {
    pub fn new() -> Self {
        Self::with_thresholds(
            DEFAULT_MAX_MESSAGE_SIZE_BYTES,
            DEFAULT_MAX_DUPLICATE_PAYLOADS,
        )
    }

    pub fn with_thresholds(max_message_size: usize, max_duplicate_payloads: usize) -> Self {
        Self {
            max_message_size,
            max_duplicate_payloads,
        }
    }
}

impl Default for DefaultActionValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl ActionValidator for DefaultActionValidator {
    fn validate(&self, agent_id: &str, actions: &[AgentAction]) -> Result<(), SecurityError> {
        validate_agent_id(agent_id)?;

        let mut seen: HashMap<&[u8], usize> = HashMap::with_capacity(actions.len().min(64));
        for action in actions.iter() {
            if action.payload.len() > self.max_message_size {
                return Err(SecurityError::OversizedMessage);
            }
            let counter = seen.entry(action.payload.as_slice()).or_insert(0);
            *counter += 1;
            if *counter > self.max_duplicate_payloads {
                return Err(SecurityError::InvalidAction(format!(
                    "duplicate-payload burst: {} occurrences exceeds threshold {}",
                    counter, self.max_duplicate_payloads,
                )));
            }
        }
        Ok(())
    }
}

/// Whitelist `agent_id` against `^[A-Za-z0-9_:-]{1,128}$`.
fn validate_agent_id(agent_id: &str) -> Result<(), SecurityError> {
    if agent_id.is_empty() {
        return Err(SecurityError::InvalidAction(
            "agent_id rejected: empty".to_string(),
        ));
    }
    if agent_id.len() > MAX_AGENT_ID_LEN {
        return Err(SecurityError::InvalidAction(format!(
            "agent_id rejected: length {} exceeds {}",
            agent_id.len(),
            MAX_AGENT_ID_LEN,
        )));
    }
    for &b in agent_id.as_bytes() {
        let ok = b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b':';
        if !ok {
            return Err(SecurityError::InvalidAction(format!(
                "agent_id rejected: invalid byte 0x{b:02x}",
            )));
        }
    }
    Ok(())
}

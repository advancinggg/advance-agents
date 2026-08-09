//! AC-13 sub-tests for `DefaultActionValidator` (CONTRACT-113 first impl).
//! Mirrors MODULE-012 §3.3 T13a-T13i (T13f intentionally absent — see Slice D
//! plan / §3.7 history). 13 sub-tests:
//!  - T13a/T13b/T13h2 — oversize boundary cases
//!  - T13c — empty batch
//!  - T13d/T13e/T13e2/T13e3 — agent_id whitelist (reject + accept paths)
//!  - T13g/T13g2/T13g3 — duplicate-burst boundary cases
//!  - T13h — clean batch
//!  - T13i — determinism

use advance_shared_types::mailbox::AgentAction;
use advance_shared_types::security_validator::{ActionValidator, SecurityError};
use cap_http::{
    DefaultActionValidator, DEFAULT_MAX_DUPLICATE_PAYLOADS, DEFAULT_MAX_MESSAGE_SIZE_BYTES,
};

fn small_action(seed: u8) -> AgentAction {
    AgentAction {
        payload: vec![seed, seed.wrapping_add(1), seed.wrapping_add(2)],
    }
}

#[test]
fn t13a_single_oversized_rejected() {
    let v = DefaultActionValidator::new();
    let oversized = AgentAction {
        payload: vec![0u8; DEFAULT_MAX_MESSAGE_SIZE_BYTES + 1],
    };
    let res = v.validate("agent-001", &[oversized]);
    assert_eq!(res, Err(SecurityError::OversizedMessage));
}

#[test]
fn t13b_oversized_midbatch_failfast() {
    let v = DefaultActionValidator::new();
    let mut batch: Vec<AgentAction> = (0..5).map(small_action).collect();
    batch.push(AgentAction {
        payload: vec![0u8; DEFAULT_MAX_MESSAGE_SIZE_BYTES + 1],
    });
    batch.extend((10..15).map(small_action));
    let res = v.validate("agent-001", &batch);
    assert_eq!(res, Err(SecurityError::OversizedMessage));
}

#[test]
fn t13c_empty_batch_ok() {
    let v = DefaultActionValidator::new();
    let res = v.validate("agent-001", &[]);
    assert_eq!(res, Ok(()));
}

#[test]
fn t13d_invalid_agent_id_whitespace() {
    let v = DefaultActionValidator::new();
    let res = v.validate("agent 001", &[small_action(1)]);
    match res {
        Err(SecurityError::InvalidAction(msg)) => {
            assert!(
                msg.contains("agent_id"),
                "msg should mention agent_id, got: {msg}"
            );
        }
        other => panic!("expected InvalidAction, got: {other:?}"),
    }
}

#[test]
fn t13e_invalid_agent_id_too_long() {
    let v = DefaultActionValidator::new();
    let long_id = "a".repeat(129);
    let res = v.validate(&long_id, &[small_action(1)]);
    match res {
        Err(SecurityError::InvalidAction(msg)) => {
            assert!(
                msg.contains("agent_id") && msg.contains("length"),
                "msg should mention agent_id length, got: {msg}",
            );
        }
        other => panic!("expected InvalidAction, got: {other:?}"),
    }
}

#[test]
fn t13e2_invalid_agent_id_empty() {
    let v = DefaultActionValidator::new();
    let res = v.validate("", &[small_action(1)]);
    match res {
        Err(SecurityError::InvalidAction(msg)) => {
            assert!(
                msg.contains("agent_id") && msg.contains("empty"),
                "msg should mention agent_id empty, got: {msg}",
            );
        }
        other => panic!("expected InvalidAction, got: {other:?}"),
    }
}

#[test]
fn t13e3_valid_agent_id_with_colon() {
    // Regression-locks the broader-class decision: `:` MUST be accepted because
    // mailbox tests use `agent:parent`/`agent:child` fixtures (see
    // crates/shared-types/tests/mailbox.rs:79-80).
    let v = DefaultActionValidator::new();
    let res = v.validate("agent:parent", &[small_action(1)]);
    assert_eq!(res, Ok(()));
}

#[test]
fn t13g_duplicate_payload_burst_rejected() {
    let v = DefaultActionValidator::new();
    let dup = AgentAction {
        payload: vec![1u8, 2, 3],
    };
    // 17 > DEFAULT_MAX_DUPLICATE_PAYLOADS (16)
    let batch: Vec<AgentAction> = (0..(DEFAULT_MAX_DUPLICATE_PAYLOADS + 1))
        .map(|_| dup.clone())
        .collect();
    let res = v.validate("agent-001", &batch);
    match res {
        Err(SecurityError::InvalidAction(msg)) => {
            assert!(
                msg.contains("duplicate-payload burst")
                    && msg.contains(&format!("threshold {}", DEFAULT_MAX_DUPLICATE_PAYLOADS)),
                "msg should describe duplicate burst + threshold, got: {msg}",
            );
        }
        other => panic!("expected InvalidAction, got: {other:?}"),
    }
}

#[test]
fn t13g2_distinct_payloads_pass() {
    // 32 distinct payloads, each unique 4-byte value. Even at 32 actions the
    // counter for any single payload is 1, so no false-positive on hash
    // collisions (HashMap<&[u8], usize> uses PartialEq on slices for bucket
    // resolution — distinct payloads cannot collide).
    let v = DefaultActionValidator::new();
    let batch: Vec<AgentAction> = (0u32..32)
        .map(|i| AgentAction {
            payload: i.to_le_bytes().to_vec(),
        })
        .collect();
    let res = v.validate("agent-001", &batch);
    assert_eq!(res, Ok(()));
}

#[test]
fn t13g3_duplicates_at_threshold_pass() {
    // Exactly DEFAULT_MAX_DUPLICATE_PAYLOADS (16) identical payloads.
    // Counter reaches 16 but does NOT exceed 16 — boundary `>` (not `≥`)
    // semantics.
    let v = DefaultActionValidator::new();
    let dup = AgentAction {
        payload: vec![9u8, 9, 9],
    };
    let batch: Vec<AgentAction> = (0..DEFAULT_MAX_DUPLICATE_PAYLOADS)
        .map(|_| dup.clone())
        .collect();
    let res = v.validate("agent-001", &batch);
    assert_eq!(res, Ok(()));
}

#[test]
fn t13h_clean_batch_passes() {
    let v = DefaultActionValidator::new();
    let batch: Vec<AgentAction> = (0..5).map(small_action).collect();
    let res = v.validate("agent-001", &batch);
    assert_eq!(res, Ok(()));
}

#[test]
fn t13h2_payload_at_max_size_passes() {
    // Payload at exactly DEFAULT_MAX_MESSAGE_SIZE_BYTES (1 MiB). `>` (not
    // `≥`) boundary — exact-max payload MUST pass.
    let v = DefaultActionValidator::new();
    let action = AgentAction {
        payload: vec![0u8; DEFAULT_MAX_MESSAGE_SIZE_BYTES],
    };
    let res = v.validate("agent-001", &[action]);
    assert_eq!(res, Ok(()));
}

#[test]
fn t13i_determinism() {
    let v = DefaultActionValidator::new();
    // Mixed batch: a clean prefix + a duplicate (counter 2, well under
    // threshold) — the Result is Ok(()), and calling validate twice on the
    // same input MUST yield the same Result.
    let mixed: Vec<AgentAction> = vec![
        small_action(1),
        small_action(2),
        small_action(1), // payload duplicates first action (counter 2)
        small_action(3),
    ];
    let r1 = v.validate("agent-001", &mixed);
    let r2 = v.validate("agent-001", &mixed);
    assert_eq!(r1, r2);
    assert_eq!(r1, Ok(()));
}

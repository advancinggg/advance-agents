//! AC-06 (REQ-202) — `MessageTrace` records inbound channel messages for
//! reply routing. Trace-primitive tests (T-B07..T-B13). The reply()
//! round-trip is in `reply_routing.rs`.

mod common;

use std::time::{Duration, SystemTime};

use advance_messaging::{MessageTrace, MsgError, MAX_TRACE_ENTRIES};

use crate::common::make_origin;

// T-B07 — record + lookup_full round-trip incl. recipient.
#[test]
fn t_b07_record_lookup_roundtrip() {
    let t = MessageTrace::new();
    let origin = make_origin("m1", "telegram", "telegram:42", "agent:adapter-tg");
    t.record("m1", origin.clone(), "agent:bob").unwrap();
    assert_eq!(t.len(), 1);
    let (got_origin, recipient) = t.lookup_full("m1").expect("entry present");
    assert_eq!(got_origin, origin);
    assert_eq!(recipient, "agent:bob");
    assert_eq!(t.lookup("m1"), Some(origin));
}

// T-B08 — lookup miss → None.
#[test]
fn t_b08_lookup_miss_none() {
    let t = MessageTrace::new();
    assert_eq!(t.lookup("nope"), None);
    assert_eq!(t.lookup_full("nope"), None);
}

// T-B09 — gc evicts an expired entry (recorded_at = now − 8d, ttl 7d).
#[test]
fn t_b09_gc_evicts_expired() {
    let t = MessageTrace::new();
    t.record(
        "m1",
        make_origin("m1", "telegram", "telegram:42", "agent:adapter-tg"),
        "agent:bob",
    )
    .unwrap();
    // recorded_at is host-stamped at ~now. Run gc with a "now" 8 days in
    // the future and a 7-day TTL → the entry is expired.
    let future = SystemTime::now() + Duration::from_secs(8 * 24 * 3600);
    let evicted = t.gc(future, Duration::from_secs(7 * 24 * 3600));
    assert_eq!(evicted, 1);
    assert_eq!(t.lookup("m1"), None);
}

// T-B10 — gc retains a fresh entry.
#[test]
fn t_b10_gc_retains_fresh() {
    let t = MessageTrace::new();
    t.record(
        "m1",
        make_origin("m1", "telegram", "telegram:42", "agent:adapter-tg"),
        "agent:bob",
    )
    .unwrap();
    let evicted = t.gc(SystemTime::now(), Duration::from_secs(7 * 24 * 3600));
    assert_eq!(evicted, 0);
    assert!(t.lookup("m1").is_some());
}

// T-B11 — record empty message_id → InvalidPayload("trace_arg_invalid").
#[test]
fn t_b11_record_empty_id_rejected() {
    let t = MessageTrace::new();
    let err = t
        .record(
            "",
            make_origin("", "telegram", "telegram:42", "agent:adapter-tg"),
            "agent:bob",
        )
        .unwrap_err();
    assert_eq!(err, MsgError::InvalidPayload("trace_arg_invalid".into()));
}

// T-B12 — record bad recipient (not is_safe_id) → same rejection.
#[test]
fn t_b12_record_bad_recipient_rejected() {
    let t = MessageTrace::new();
    let err = t
        .record(
            "m1",
            make_origin("m1", "telegram", "telegram:42", "agent:adapter-tg"),
            "agent:bob\nspoof",
        )
        .unwrap_err();
    assert_eq!(err, MsgError::InvalidPayload("trace_arg_invalid".into()));
}

// T-B13 — at MAX_TRACE_ENTRIES the lowest-seq (first-inserted) entry is
// evicted, not the most-recent. Eviction keys on the monotonic insertion
// `seq`, NOT `recorded_at` (which is host-stamped) — structurally immune to
// clock-skew eviction-targeting.
#[test]
fn t_b13_at_cap_evicts_lowest_seq() {
    let t = MessageTrace::new();
    for i in 0..MAX_TRACE_ENTRIES {
        let id = format!("m{i}");
        t.record(
            &id,
            make_origin(&id, "telegram", "telegram:42", "agent:adapter-tg"),
            "agent:bob",
        )
        .unwrap();
    }
    assert_eq!(t.len(), MAX_TRACE_ENTRIES);
    assert!(t.lookup("m0").is_some());
    // One more insert → first-inserted ("m0", lowest seq) evicted.
    t.record(
        "m_new",
        make_origin("m_new", "telegram", "telegram:42", "agent:adapter-tg"),
        "agent:bob",
    )
    .unwrap();
    assert_eq!(t.len(), MAX_TRACE_ENTRIES);
    assert_eq!(t.lookup("m0"), None, "lowest-seq entry evicted");
    assert!(
        t.lookup(&format!("m{}", MAX_TRACE_ENTRIES - 1)).is_some(),
        "later-inserted entry retained"
    );
    assert!(t.lookup("m_new").is_some(), "new entry present");
}

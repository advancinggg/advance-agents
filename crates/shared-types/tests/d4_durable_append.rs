//! D4 / SD-12b: `DurableEventAppend` as a SEPARATE SIBLING of `EventBusEmit`.
//!
//! BUILT AND HELD. No MODULE-019 §1.5 acceptance criterion declares durable append and
//! this lane mints none — a new AC row would move the ledger denominator and break the
//! zero-net rule. These are unit-level witnesses of the port's shape, and they are not
//! evidence for any acceptance criterion.

use advance_shared_types::event::Event;
use advance_shared_types::traits::{DurableAppendError, DurableEventAppend, EventBusEmit};
use std::sync::Mutex;

struct Sink {
    appended: Mutex<Vec<Event>>,
    emitted: Mutex<Vec<Event>>,
    failing: bool,
}

impl EventBusEmit for Sink {
    fn emit(&self, event: Event) {
        self.emitted.lock().unwrap().push(event);
    }
}

impl DurableEventAppend for Sink {
    fn append_durable(&self, event: Event) -> Result<u64, DurableAppendError> {
        if self.failing {
            return Err(DurableAppendError::Storage("disk full".into()));
        }
        let mut v = self.appended.lock().unwrap();
        v.push(event);
        Ok(v.len() as u64)
    }
}

fn ev(name: &str) -> Event {
    Event::observability(name, "agent-test", serde_json::json!({}), None)
}

/// The two ports are INDEPENDENT: implementing one does not implement the other, and a
/// call to one does not reach the other. Folding them together would let a caller believe
/// an `emit` was durable because the same object happened to offer both.
#[test]
fn t_sd12b_durable_append_is_separate_from_emit() {
    let s = Sink {
        appended: Mutex::new(vec![]),
        emitted: Mutex::new(vec![]),
        failing: false,
    };
    s.emit(ev("a"));
    assert_eq!(s.emitted.lock().unwrap().len(), 1);
    assert_eq!(
        s.appended.lock().unwrap().len(),
        0,
        "emit must NOT be a durable append"
    );

    assert_eq!(s.append_durable(ev("b")).unwrap(), 1);
    assert_eq!(s.appended.lock().unwrap().len(), 1);
    assert_eq!(
        s.emitted.lock().unwrap().len(),
        1,
        "append must NOT emit as a side effect"
    );
}

/// Append is FALLIBLE where emit is infallible — that asymmetry is the reason the two are
/// separate traits rather than one trait with two methods.
#[test]
fn t_sd12b_append_is_fallible_and_reports_why() {
    let s = Sink {
        appended: Mutex::new(vec![]),
        emitted: Mutex::new(vec![]),
        failing: true,
    };
    match s.append_durable(ev("x")) {
        Err(DurableAppendError::Storage(m)) => assert!(m.contains("disk full")),
        other => panic!("expected a typed storage failure, got {other:?}"),
    }
    assert!(
        s.appended.lock().unwrap().is_empty(),
        "a failed append must record nothing"
    );
    assert_eq!(
        DurableAppendError::ShuttingDown.to_string(),
        "durable append refused: sink is shutting down"
    );
}

/// Sequence numbers are monotonic — the ordering guarantee is the whole point of a
/// durable append over a fire-and-forget emit.
#[test]
fn t_sd12b_sequence_numbers_are_monotonic() {
    let s = Sink {
        appended: Mutex::new(vec![]),
        emitted: Mutex::new(vec![]),
        failing: false,
    };
    let seqs: Vec<u64> = (0..5)
        .map(|i| s.append_durable(ev(&format!("e{i}"))).unwrap())
        .collect();
    assert_eq!(seqs, vec![1, 2, 3, 4, 5]);
    assert!(seqs.windows(2).all(|w| w[1] > w[0]));
}

/// Both ports are object-safe: they must be usable as `dyn` behind an `Arc`, or the
/// CONTRACT-180 seam cannot be wired at a composition root at all.
#[test]
fn t_sd12b_both_ports_are_object_safe() {
    let s = std::sync::Arc::new(Sink {
        appended: Mutex::new(vec![]),
        emitted: Mutex::new(vec![]),
        failing: false,
    });
    let _emit: std::sync::Arc<dyn EventBusEmit> = s.clone();
    let _append: std::sync::Arc<dyn DurableEventAppend> = s;
}

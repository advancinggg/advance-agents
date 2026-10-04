//! MODULE-001-AC-30 lower-crate witness: `BreakerSubscriber::shutdown` aborts AND joins the
//! subscriber task, so its `Arc<MailboxStore>` clone is released when the call returns (the
//! `Drop` path only aborts).

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use advance_messaging::{BreakerSubscriber, MailboxStore};
use advance_runtime::circuit_breaker::{CircuitBreakerBus, DefaultCircuitBreakerBus};

const CAPACITY: NonZeroUsize = match NonZeroUsize::new(16) {
    Some(n) => n,
    None => panic!("16 != 0"),
};

#[tokio::test(flavor = "current_thread")]
async fn module_001_ac30_breaker_subscriber_shutdown_joins() {
    let store = Arc::new(MailboxStore::new(CAPACITY));
    let bus: Arc<dyn CircuitBreakerBus> = Arc::new(DefaultCircuitBreakerBus::new());
    // The bus stays alive for the whole test: dropping it would end the task on its own.
    let subscriber = BreakerSubscriber::spawn(Arc::clone(&bus), Arc::clone(&store));
    // Let the task start: it now holds its own store clone, waiting for breaker events.
    tokio::task::yield_now().await;
    assert_eq!(
        Arc::strong_count(&store),
        2,
        "the running task holds the store"
    );

    tokio::time::timeout(Duration::from_secs(2), subscriber.shutdown())
        .await
        .expect("shutdown joined the task");
    assert_eq!(
        Arc::strong_count(&store),
        1,
        "the task's store clone is released once shutdown returns"
    );

    // Non-vacuity: a plain drop only aborts; on this current-thread runtime the aborted
    // task still holds its clone until the scheduler runs it again.
    let dropped = BreakerSubscriber::spawn(Arc::clone(&bus), Arc::clone(&store));
    tokio::task::yield_now().await;
    assert_eq!(Arc::strong_count(&store), 2);
    drop(dropped);
    assert_eq!(
        Arc::strong_count(&store),
        2,
        "abort alone has not released it yet"
    );
    for _ in 0..100 {
        if Arc::strong_count(&store) == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        Arc::strong_count(&store),
        1,
        "released once the runtime ran the abort"
    );
    drop(bus);
}

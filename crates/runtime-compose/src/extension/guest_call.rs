//! The guest export call an agent loop is making, so that a contained extension
//! host-function panic which traps that call can say so to the loop.
//!
//! Only the containment adapter marks a call, and only when a panic left no in-band
//! answer (the call traps). A trap of any other origin — a guest trap, an OSS host
//! function's error, a handler that returns `Err` — leaves the call unmarked.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::task_local;

task_local! {
    static TRAPPED_BY_CONTAINED_PANIC: Arc<AtomicBool>;
}

/// Run one guest export call; also answer whether a contained extension
/// host-function panic trapped it.
///
/// A host function's future is polled inside the poll of `call` (on the guest's
/// fiber, on the same task), so the scope is visible to the containment adapter.
pub(crate) async fn run<F: Future>(call: F) -> (F::Output, bool) {
    let mark = Arc::new(AtomicBool::new(false));
    let output = TRAPPED_BY_CONTAINED_PANIC
        .scope(Arc::clone(&mark), call)
        .await;
    (output, mark.load(Ordering::Acquire))
}

/// Mark the guest call in progress, if any: a contained panic is trapping it.
pub(crate) fn mark_trapped_by_contained_panic() {
    let _ = TRAPPED_BY_CONTAINED_PANIC.try_with(|mark| mark.store(true, Ordering::Release));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn module_001_ac31_guest_call_mark_reaches_only_the_enclosing_call() {
        assert_eq!(run(async { 7 }).await, (7, false));
        assert_eq!(
            run(async {
                mark_trapped_by_contained_panic();
                7
            })
            .await,
            (7, true)
        );
        // Marked across an await point (a host future polled more than once).
        assert_eq!(
            run(async {
                tokio::task::yield_now().await;
                mark_trapped_by_contained_panic();
            })
            .await,
            ((), true)
        );
        // Outside any guest call: nothing to mark, nothing fails.
        mark_trapped_by_contained_panic();
        // A nested call is marked on its own; the outer call is not.
        let (inner, outer) = run(async {
            run(async {
                mark_trapped_by_contained_panic();
            })
            .await
            .1
        })
        .await;
        assert!(inner);
        assert!(!outer);
        // A task spawned from inside the call does not inherit the scope.
        let (spawned, marked) = run(async {
            tokio::spawn(async { mark_trapped_by_contained_panic() })
                .await
                .is_ok()
        })
        .await;
        assert!(spawned);
        assert!(!marked);
    }
}

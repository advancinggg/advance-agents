//! The one place the composition starts an OS thread of its own (the Client API
//! adapter workers, the CONTRACT-218 custody threads, the L6 git bridge): each goes
//! through [`spawn_named`], so every such thread is named and can be accounted for
//! in one place. Test-support builds count the threads still running.

use std::io;
use std::thread::JoinHandle;

/// Start a thread named `name` running `f` (exactly `std::thread::Builder` with a
/// name).
#[cfg(not(feature = "test-support"))]
pub(crate) fn spawn_named<F, T>(name: &str, f: F) -> io::Result<JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    std::thread::Builder::new().name(name.to_owned()).spawn(f)
}

/// Start a thread named `name` running `f` (exactly `std::thread::Builder` with a
/// name), counted in [`live_threads`] until its body returns or unwinds.
#[cfg(feature = "test-support")]
pub(crate) fn spawn_named<F, T>(name: &str, f: F) -> io::Result<JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    spawn_counted(&LIVE_THREADS, name, f)
}

/// [`spawn_named`] counted in `counter` while the thread's body runs.
#[cfg(feature = "test-support")]
fn spawn_counted<F, T>(
    counter: &'static std::sync::atomic::AtomicUsize,
    name: &str,
    f: F,
) -> io::Result<JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Uncounts its thread when the body ends.
    struct Live(&'static AtomicUsize);
    impl Drop for Live {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    counter.fetch_add(1, Ordering::SeqCst);
    let spawned = std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            let _live = Live(counter);
            f()
        });
    if spawned.is_err() {
        // The body never ran, so its guard never existed.
        counter.fetch_sub(1, Ordering::SeqCst);
    }
    spawned
}

#[cfg(feature = "test-support")]
static LIVE_THREADS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// How many threads started through [`spawn_named`] are still running.
#[cfg(feature = "test-support")]
pub(crate) fn live_threads() -> usize {
    LIVE_THREADS.load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A thread is counted while its body runs and uncounted once the body returns or
    /// unwinds (a counter of the test's own: the process-wide one is shared by every
    /// test of this binary).
    #[test]
    fn module_001_ac30_spawned_threads_are_counted_until_their_body_ends() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let handle = spawn_counted(&COUNTER, "rc-thread-count-probe", move || {
            started_tx.send(()).unwrap();
            let _ = release_rx.recv();
        })
        .expect("spawn");
        started_rx.recv().unwrap();
        assert_eq!(
            COUNTER.load(Ordering::SeqCst),
            1,
            "the running thread is counted"
        );
        release_tx.send(()).unwrap();
        handle.join().unwrap();
        assert_eq!(
            COUNTER.load(Ordering::SeqCst),
            0,
            "uncounted once its body returned"
        );

        let panicking = spawn_counted(&COUNTER, "rc-thread-count-panic", || panic!("body panics"))
            .expect("spawn");
        assert!(panicking.join().is_err());
        assert_eq!(
            COUNTER.load(Ordering::SeqCst),
            0,
            "uncounted once it unwound"
        );
    }

    #[test]
    fn module_001_ac30_spawned_thread_carries_its_name_and_result() {
        let handle = spawn_named("rc-thread-name-probe", || {
            std::thread::current().name().map(str::to_owned)
        })
        .expect("spawn");
        assert_eq!(
            handle.join().expect("join").as_deref(),
            Some("rc-thread-name-probe")
        );
    }
}

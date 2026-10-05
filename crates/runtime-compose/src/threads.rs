//! The one place the composition starts an OS thread of its own (the Client API
//! adapter workers, the CONTRACT-218 custody threads, the L6 git bridge): each goes
//! through [`spawn_named`], so every such thread is named and can be accounted for
//! in one place.

use std::io;
use std::thread::JoinHandle;

/// Start a thread named `name` running `f` (exactly `std::thread::Builder` with a
/// name).
pub(crate) fn spawn_named<F, T>(name: &str, f: F) -> io::Result<JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    std::thread::Builder::new().name(name.to_owned()).spawn(f)
}

#[cfg(test)]
mod tests {
    use super::*;

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

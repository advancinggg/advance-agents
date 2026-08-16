//! Process-global multi-thread Tokio runtime for bridge lifecycle.

use std::future::Future;
use std::sync::OnceLock;

use tokio::runtime::Runtime;

static GLOBAL_RT: OnceLock<Runtime> = OnceLock::new();

/// Access the process-global runtime.
pub fn global_rt() -> &'static Runtime {
    GLOBAL_RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("advance-bridge")
            .build()
            .expect("failed to build GLOBAL_RT")
    })
}

/// Drive a future on GLOBAL_RT, safe from inside another Tokio runtime.
/// Uses a dedicated OS thread when already inside Tokio (never block_in_place).
pub fn block_on_global<F, T>(fut: F) -> T
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    if tokio::runtime::Handle::try_current().is_ok() {
        let rt = global_rt();
        std::thread::Builder::new()
            .name("advance-bridge-block".into())
            .spawn(move || rt.block_on(fut))
            .expect("spawn bridge helper thread")
            .join()
            .expect("bridge helper thread panicked")
    } else {
        global_rt().block_on(fut)
    }
}

/// True if currently inside a Tokio runtime.
pub fn in_tokio() -> bool {
    tokio::runtime::Handle::try_current().is_ok()
}

//! MODULE-001-AC-30 — one async entry point whose future is `Send + 'static`, so a host can
//! drive `compose` from any runtime, on any task. Checked by the compiler: the closure below
//! only has to type-check (`tokio::spawn` takes a `Send + 'static` future); it never runs.
//! The library asserts the same at compile time next to `compose` itself.

use advance_runtime_compose::{compose, ComposeOptions, ComposedRuntime, ShutdownHandle};

fn assert_send_sync_static<T: Send + Sync + 'static>() {}

#[test]
fn module_001_ac30_compose_future_is_send_static() {
    let spawn = |options: ComposeOptions| tokio::spawn(compose(options, Vec::new()));
    let _ = spawn;
    // What a host keeps or moves between tasks.
    assert_send_sync_static::<ComposedRuntime>();
    assert_send_sync_static::<ShutdownHandle>();
    assert_send_sync_static::<ComposeOptions>();
}

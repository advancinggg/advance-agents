//! One extension hold, dropped in shutdown step 4 after the graph.

use std::any::Any;
use std::panic::AssertUnwindSafe;
use std::sync::Mutex;

use crate::api::log_keys;
use crate::compose_log::LogHandle;

/// One extension hold. `Send + Sync` for any `H: Send + 'static` (the value
/// sits behind a Mutex), so `HoldStoppers`, `WiringHandles` and `Composition`
/// keep their auto traits.
pub(crate) struct ExtensionHold {
    owner: &'static str,
    log: LogHandle,
    value: Mutex<Option<Box<dyn Any + Send>>>,
}

impl ExtensionHold {
    pub(crate) fn new<H: Send + 'static>(owner: &'static str, hold: H, log: LogHandle) -> Self {
        Self {
            owner,
            log,
            value: Mutex::new(Some(Box::new(hold))),
        }
    }

    #[allow(dead_code)] // unit tests, and later teardown diagnostics
    pub(crate) fn owner(&self) -> &'static str {
        self.owner
    }
}

impl Drop for ExtensionHold {
    fn drop(&mut self) {
        let value = self
            .value
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(v) = value {
            if std::panic::catch_unwind(AssertUnwindSafe(move || drop(v))).is_err() {
                self.log.err(
                    log_keys::EXT_HOLD_DROP_PANICKED,
                    format!(
                        "advance: WARN extension {} hold panicked in drop; continuing",
                        self.owner
                    ),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::MemoryComposeLog;
    use std::cell::Cell;
    use std::sync::Arc;

    const _: () = {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ExtensionHold>();
    };

    struct DropPanic;

    impl Drop for DropPanic {
        fn drop(&mut self) {
            panic!("hold drop panic");
        }
    }

    #[test]
    fn module_001_ac31_hold_requires_only_send_and_is_send_sync() {
        let sink = MemoryComposeLog::new();
        let log = LogHandle::new(Arc::new(sink));
        let hold = ExtensionHold::new("fixture", Cell::new(7u8), log);
        assert_eq!(hold.owner(), "fixture");
        fn is_send_sync<T: Send + Sync>(_: &T) {}
        is_send_sync(&hold);
    }

    #[test]
    fn module_001_ac31_hold_drop_panic_is_caught_and_logged_without_payload() {
        let sink = MemoryComposeLog::new();
        let log = LogHandle::new(Arc::new(sink.clone()));
        let hold = ExtensionHold::new("fixture", DropPanic, log);
        drop(hold);
        assert_eq!(sink.count(log_keys::EXT_HOLD_DROP_PANICKED), 1);
        let line = &sink.lines()[0];
        assert_eq!(
            line.text,
            "advance: WARN extension fixture hold panicked in drop; continuing"
        );
        assert!(
            !line.text.contains("hold drop panic"),
            "log must not carry the panic payload"
        );
    }
}

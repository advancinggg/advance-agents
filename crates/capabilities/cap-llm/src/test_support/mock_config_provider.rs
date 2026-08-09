//! `MockRuntimeConfigProvider` for cap-llm's `#[cfg(test)]` modules.

#![cfg(test)]

use std::sync::{Arc, Mutex, RwLock};

use advance_runtime::config::{RuntimeConfig, RuntimeConfigProvider};
use tokio::sync::mpsc;

pub(crate) struct MockRuntimeConfigProvider {
    pub current: RwLock<Arc<RuntimeConfig>>,
    pub last_error: Mutex<Option<String>>,
}

impl MockRuntimeConfigProvider {
    pub fn new(cfg: RuntimeConfig) -> Self {
        Self {
            current: RwLock::new(Arc::new(cfg)),
            last_error: Mutex::new(None),
        }
    }

    pub fn set_config(&self, cfg: RuntimeConfig) {
        *self.current.write().unwrap() = Arc::new(cfg);
    }
}

impl RuntimeConfigProvider for MockRuntimeConfigProvider {
    fn current(&self) -> Arc<RuntimeConfig> {
        Arc::clone(&self.current.read().unwrap())
    }

    fn subscribe(&self) -> mpsc::Receiver<Arc<RuntimeConfig>> {
        // Always-empty receiver; the gateway uses `current()`-per-call polling.
        let (_tx, rx) = mpsc::channel(1);
        rx
    }

    fn last_error(&self) -> Option<String> {
        self.last_error.lock().unwrap().clone()
    }
}

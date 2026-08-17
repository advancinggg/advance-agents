//! Process-local multi-start registry (workspace key).

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use crate::error::BridgeError;

static REGISTRY: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashSet<PathBuf>> {
    REGISTRY.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Reserve a workspace path; fails if already reserved.
pub fn reserve(workspace: PathBuf) -> Result<(), BridgeError> {
    let mut g = registry()
        .lock()
        .map_err(|_| BridgeError::Internal("registry lock poisoned".into()))?;
    if !g.insert(workspace) {
        return Err(BridgeError::AlreadyRunning);
    }
    Ok(())
}

/// Release a previously reserved workspace.
pub(crate) fn release(workspace: &PathBuf) {
    if let Ok(mut g) = registry().lock() {
        g.remove(workspace);
    }
}

/// RAII reservation: released on drop unless [`Reservation::persist`] is called.
/// Cancel of `start_async` after reserve therefore cannot leak the slot.
pub(crate) struct Reservation {
    path: Option<PathBuf>,
}

impl Reservation {
    pub(crate) fn acquire(workspace: PathBuf) -> Result<Self, BridgeError> {
        reserve(workspace.clone())?;
        Ok(Self {
            path: Some(workspace),
        })
    }

    /// Transfer ownership to [`crate::handle::BridgeInner`]; Drop will not release.
    pub(crate) fn persist(mut self) {
        self.path = None;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            release(&p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn multi_start_same_key() {
        let p = PathBuf::from("/tmp/bridge-registry-test-unique-c210");
        release(&p);
        reserve(p.clone()).unwrap();
        assert!(matches!(
            reserve(p.clone()),
            Err(BridgeError::AlreadyRunning)
        ));
        release(&p);
        reserve(p.clone()).unwrap();
        release(&p);
    }
}

//! UI drivers an extension contributes (ADR 2026-10-28 D2:
//! [`ComposeExtension::ui_drivers`](super::ComposeExtension::ui_drivers)).
//!
//! The composition owns the model-facing `browser__*` / `screen__*` callables
//! (cap-ui); a product owns the drivers — an in-app WebView, the Mac's screen
//! through Accessibility, a mirrored phone — and hands them over here. One
//! driver per surface per composition: a second registration is refused and
//! `compose` fails with [`ComposeError::UiDriver`](super::ComposeError::UiDriver).

use std::fmt;
use std::sync::{Arc, Mutex};

pub use advance_shared_types::ui::{BrowserDriverPort, ScreenDriverPort};

use super::compose_log::ComposeLog;
use super::extension::ExtensionError;
use super::log_keys;
use crate::compose_log::LogHandle;
use crate::extension::ui::UiDriverSlots;

/// Registers an extension's UI drivers. Handed to
/// [`ComposeExtension::ui_drivers`](super::ComposeExtension::ui_drivers) when the
/// home declares `browser` or `screen`.
pub struct UiDriverRegistrar {
    pub(crate) extension: &'static str,
    pub(crate) slots: Arc<Mutex<UiDriverSlots>>,
    pub(crate) refusals: Vec<UiDriverRefusal>,
    pub(crate) registered: usize,
    pub(crate) log: Arc<dyn ComposeLog>,
}

impl UiDriverRegistrar {
    pub fn extension_id(&self) -> &'static str {
        self.extension
    }

    /// The browser family's driver (an in-app WebView: `surface_kind() == "in-app"`).
    pub fn register_browser(
        &mut self,
        driver: Arc<dyn BrowserDriverPort>,
    ) -> Result<(), UiDriverRefusal> {
        let outcome = self
            .slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put_browser(self.extension, driver);
        self.finish("browser", outcome)
    }

    /// The screen family's driver (accessibility-tree text mode in S1).
    pub fn register_screen(
        &mut self,
        driver: Arc<dyn ScreenDriverPort>,
    ) -> Result<(), UiDriverRefusal> {
        let outcome = self
            .slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put_screen(self.extension, driver);
        self.finish("screen", outcome)
    }

    fn finish(
        &mut self,
        surface: &'static str,
        outcome: Result<(), &'static str>,
    ) -> Result<(), UiDriverRefusal> {
        match outcome {
            Ok(()) => {
                self.registered += 1;
                LogHandle::new(Arc::clone(&self.log)).out(
                    log_keys::UI_DRIVER_REGISTERED,
                    format!(
                        "advance: ui driver registered: {surface} (extension {})",
                        self.extension
                    ),
                );
                Ok(())
            }
            Err(held_by) => {
                let refusal = UiDriverRefusal::Duplicate { surface, held_by };
                self.refusals.push(refusal.clone());
                Err(refusal)
            }
        }
    }

    pub(crate) fn first_refusal(&self) -> Option<&UiDriverRefusal> {
        self.refusals.first()
    }
}

/// Why a UI driver registration was refused.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiDriverRefusal {
    /// Another extension already registered a driver for this surface.
    Duplicate {
        surface: &'static str,
        held_by: &'static str,
    },
}

impl fmt::Display for UiDriverRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UiDriverRefusal::Duplicate { surface, held_by } => write!(
                f,
                "ui driver for {surface}: already registered by extension {held_by}"
            ),
        }
    }
}

impl std::error::Error for UiDriverRefusal {}

impl From<UiDriverRefusal> for ExtensionError {
    fn from(refusal: UiDriverRefusal) -> Self {
        Self::new(refusal.to_string())
    }
}

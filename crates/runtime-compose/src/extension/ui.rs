//! The ui-drivers site (ADR 2026-10-28 D2): collect the extensions' drivers, one
//! per surface, after `tools` and before `client_families`.

use std::sync::{Arc, Mutex};

use advance_shared_types::ui::{BrowserDriverPort, ScreenDriverPort};
use cap_ui::UiDrivers;

use crate::api::{ComposeError, ExtensionPhase, UiDriverRegistrar};
use crate::compose_log::LogHandle;
use crate::extension::guard;
use crate::extension::set::ExtensionSet;

/// The drivers registered so far, shared by every extension's registrar.
#[derive(Default)]
pub struct UiDriverSlots {
    browser: Option<(&'static str, Arc<dyn BrowserDriverPort>)>,
    screen: Option<(&'static str, Arc<dyn ScreenDriverPort>)>,
}

impl UiDriverSlots {
    /// `Err(held_by)` when another extension already holds the surface.
    pub(crate) fn put_browser(
        &mut self,
        extension: &'static str,
        driver: Arc<dyn BrowserDriverPort>,
    ) -> Result<(), &'static str> {
        if let Some((held_by, _)) = &self.browser {
            return Err(held_by);
        }
        self.browser = Some((extension, driver));
        Ok(())
    }

    pub(crate) fn put_screen(
        &mut self,
        extension: &'static str,
        driver: Arc<dyn ScreenDriverPort>,
    ) -> Result<(), &'static str> {
        if let Some((held_by, _)) = &self.screen {
            return Err(held_by);
        }
        self.screen = Some((extension, driver));
        Ok(())
    }

    fn take_drivers(&mut self) -> UiDrivers {
        UiDrivers {
            browser: self.browser.take().map(|(_, d)| d),
            screen: self.screen.take().map(|(_, d)| d),
        }
    }
}

impl UiDriverRegistrar {
    pub(crate) fn new(
        extension: &'static str,
        slots: Arc<Mutex<UiDriverSlots>>,
        log: &LogHandle,
    ) -> Self {
        Self {
            extension,
            slots,
            refusals: Vec::new(),
            registered: 0,
            log: log.sink(),
        }
    }
}

/// Call every extension's `ui_drivers` and collect the drivers. The first
/// refusal (a second driver for a surface) fails the composition, as a
/// failed or panicking callback does.
pub(crate) fn run_ui_drivers(
    exts: &ExtensionSet,
    log: &LogHandle,
) -> Result<UiDrivers, ComposeError> {
    let slots = Arc::new(Mutex::new(UiDriverSlots::default()));
    for (id, ext, cx) in exts.iter_with_cx()? {
        let mut reg = UiDriverRegistrar::new(id, Arc::clone(&slots), log);
        let result = guard::run_sync_callback(id, ExtensionPhase::UiDrivers, || {
            ext.ui_drivers(cx, &mut reg)
        })?;
        if let Some(refusal) = reg.first_refusal() {
            return Err(ComposeError::UiDriver {
                extension: id,
                refusal: refusal.clone(),
            });
        }
        if let Err(error) = result {
            return Err(guard::failed(id, ExtensionPhase::UiDrivers, &error));
        }
    }
    let drivers = slots
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take_drivers();
    Ok(drivers)
}

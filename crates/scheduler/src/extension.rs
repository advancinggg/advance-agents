//! `SchedulerExtension` (CONTRACT-133) re-export + `Box<T>` blanket
//! impl to confirm object-safety.
//!
//! No concrete impl ships in Slice A. MODULE-015 provides
//! `AutoLoopDriver` as the first concrete `SchedulerExtension` in its
//! own slice.

use async_trait::async_trait;

use crate::contracts::SchedulerExtension;
use crate::types::{ComponentEvent, SchedulerTick};

/// Blanket impl confirming `SchedulerExtension` is object-safe under
/// `Box<dyn>`. The trait's `#[async_trait]` rewriting of `async fn` to
/// `Pin<Box<dyn Future + Send + '_>>` preserves dyn-compatibility.
#[async_trait]
impl<T: SchedulerExtension + ?Sized> SchedulerExtension for Box<T> {
    fn name(&self) -> &str {
        (**self).name()
    }

    async fn on_tick(&self, tick: SchedulerTick) {
        (**self).on_tick(tick).await
    }

    async fn on_component_event(&self, event: ComponentEvent) {
        (**self).on_component_event(event).await
    }
}

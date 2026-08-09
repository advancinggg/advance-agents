//! `Clock` trait for testable wall-clock dependence (Slice B Round-2 W6 / Round-3 W4).
//!
//! `stats_aggregator`'s rolling 24h window is wall-clock dependent. Tests need to
//! fast-forward 24 hours; production uses `chrono::Utc::now`. The trait
//! abstraction lets tests inject a `MockClock`.

use chrono::{DateTime, Utc};

/// Wall-clock source.
pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

/// Production clock: returns `Utc::now()`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

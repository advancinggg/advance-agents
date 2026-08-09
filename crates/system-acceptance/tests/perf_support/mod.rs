//! Perf-CI lane benchmark support (median-of-N / warm-up / outlier-drop).
//!
//! The original defer reason for the perf-SLO SYS-AC class (195/196/199/234/238/241/245/246
//! plus the Stage-C-added 191/214) was that a plain single-shot wall-clock assertion is not
//! reliably CI-witnessable on a shared, disk-pressured, parallel-worktree host. This module
//! is the methodology the 2026-06-16 /spec adjudication prescribed (SYSTEM-ACCEPTANCE.md:379):
//! **median-of-N over warm samples with the top & bottom outliers dropped**, run `--release`,
//! serial (`--test-threads=1`), in a dedicated `#[ignore]`d binary.
//!
//! WITNESS-FLOOR: the caller's `sample(i)` closure must do all untimed setup BEFORE
//! `Instant::now()` and time ONLY the named product op, returning that single `Duration`.
//! This module never sleeps and never times a whole turn — it only aggregates the caller's
//! per-sample product-op `Duration`s.
//!
//! Disk note: every fixture in the perf lane uses `tempfile::TempDir::new()`, which resolves to
//! `std::env::temp_dir()` — on a Darwin host `/var/folders/.../T`, the INTERNAL APFS volume
//! (`/System/Volumes/Data`), not whatever (possibly slow, external) volume holds the checkout.
//! Pinning the timed fixtures to the internal SSD is what makes the disk-bound rows
//! (234/238/241/246) attemptable.

#![allow(dead_code)] // not every helper is used by every test binary that includes this module

use std::future::Future;
use std::time::Duration;

/// Sampling budget. `trim` = number of samples dropped from EACH end before the median.
pub struct Budget {
    pub warmup: usize,
    pub samples: usize,
    pub trim: usize,
}

impl Budget {
    pub const fn new(warmup: usize, samples: usize, trim: usize) -> Self {
        Self {
            warmup,
            samples,
            trim,
        }
    }
    /// N=11, drop 1 each end, 1 warm-up — for the high-headroom bound rows.
    pub const fn bound() -> Self {
        Self {
            warmup: 1,
            samples: 11,
            trim: 1,
        }
    }
    /// N=21, drop 2 each end, 3 warm-ups — for the tight latency rows (191/195).
    pub const fn tight() -> Self {
        Self {
            warmup: 3,
            samples: 21,
            trim: 2,
        }
    }
    /// median-of-3 with one warm-up — for the expensive-fixture rows (234/246).
    pub const fn small() -> Self {
        Self {
            warmup: 1,
            samples: 3,
            trim: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PerfStats {
    pub median_ms: f64,
    pub p95_ms: f64,
    pub max_ms: f64,
    pub min_ms: f64,
    pub n: usize,         // raw measured sample count (warm-ups excluded)
    pub trimmed_n: usize, // count kept after dropping `trim` from each end
}

impl PerfStats {
    pub fn report(&self, label: &str) {
        println!(
            "[perf] {label}: median={:.3}ms p95={:.3}ms max={:.3}ms min={:.3}ms (n={}, trimmed_n={})",
            self.median_ms, self.p95_ms, self.max_ms, self.min_ms, self.n, self.trimmed_n
        );
    }
}

#[inline]
fn to_ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// Compute stats from already-collected measured durations (warm-ups must already be excluded).
/// median is over the trimmed set (drop `trim` each end); p95/max/min are over the full raw set
/// so an outlier stays visible in the printed report.
pub fn stats_from(mut samples: Vec<Duration>, trim: usize) -> PerfStats {
    assert!(!samples.is_empty(), "perf: no samples collected");
    samples.sort_unstable();
    let n = samples.len();
    let p95_idx = (((n as f64) * 0.95).ceil() as usize)
        .saturating_sub(1)
        .min(n - 1);
    let p95_ms = to_ms(samples[p95_idx]);
    let min_ms = to_ms(samples[0]);
    let max_ms = to_ms(samples[n - 1]);

    let lo = trim.min(n.saturating_sub(1) / 2); // never trim away everything
    let hi = n - lo;
    let trimmed = &samples[lo..hi];
    let tn = trimmed.len();
    let median_ms = if tn % 2 == 1 {
        to_ms(trimmed[tn / 2])
    } else {
        (to_ms(trimmed[tn / 2 - 1]) + to_ms(trimmed[tn / 2])) / 2.0
    };

    PerfStats {
        median_ms,
        p95_ms,
        max_ms,
        min_ms,
        n,
        trimmed_n: tn,
    }
}

/// Run `sample(i)` for `warmup + samples` iterations, discard the warm-ups, and aggregate.
/// `sample(i)` performs its own UNTIMED setup and returns the timed product-op `Duration`.
pub async fn collect<F, Fut>(b: Budget, mut sample: F) -> PerfStats
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = Duration>,
{
    let total = b.warmup + b.samples;
    let mut kept: Vec<Duration> = Vec::with_capacity(b.samples);
    for i in 0..total {
        let d = sample(i).await;
        if i >= b.warmup {
            kept.push(d);
        }
    }
    stats_from(kept, b.trim)
}

//! OSS-7 R3 user-lane latency witness (`#[ignore]`; MODULE-003 §2.13).
//!
//! Run via `scripts/bench/user-lane-latency.sh` on an APFS volume
//! (`ADVANCE_BENCH_DIR`). Not a CI gate. Rows marked gate in MODULE-003 §2.13
//! are recorded from a local APFS run before OSS-9.

mod common;

use std::time::{Duration, Instant};

use cap_fs::operator::WriteIntent;

use common::OperatorHarness;

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn print_row(name: &str, samples: &mut [Duration]) {
    samples.sort();
    let p50 = percentile(samples, 0.50);
    let p99 = percentile(samples, 0.99);
    eprintln!(
        "BENCH {name} n={} p50={:.3}ms p99={:.3}ms max={:.3}ms",
        samples.len(),
        p50.as_secs_f64() * 1000.0,
        p99.as_secs_f64() * 1000.0,
        samples
            .last()
            .map(|d| d.as_secs_f64() * 1000.0)
            .unwrap_or(0.0)
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn bench_save_to_commit_latency_p50_p99() {
    let h = OperatorHarness::open().await;
    let body = vec![b'x'; 10 * 1024];
    let mut samples = Vec::with_capacity(30);
    for i in 0..30 {
        let path = format!("doc-{i}.md");
        let start = Instant::now();
        h.upload(&path, WriteIntent::Create, None, &body)
            .await
            .expect("create");
        samples.push(start.elapsed());
    }
    print_row("commit_user_10KiB", &mut samples);

    let seed = h
        .upload("seed.md", WriteIntent::Create, None, &body)
        .await
        .expect("seed");
    let mut oid = seed.oid.clone();
    let mut edits = Vec::with_capacity(30);
    for i in 0..30 {
        let mut next = body.clone();
        next[0] = b'a'.wrapping_add((i % 26) as u8);
        let start = Instant::now();
        let out = h
            .upload("seed.md", WriteIntent::Edit, oid.clone(), &next)
            .await
            .expect("edit");
        edits.push(start.elapsed());
        oid = out.oid.clone();
    }
    print_row("save_to_commit_10KiB_edit", &mut edits);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn bench_agent_write_during_autosave_backlog() {
    let h = OperatorHarness::open().await;
    let body = vec![b'y'; 4096];
    for i in 0..50 {
        h.upload(&format!("backlog-{i}.md"), WriteIntent::Create, None, &body)
            .await
            .expect("backlog");
    }
    let mut samples = Vec::with_capacity(20);
    for i in 0..20 {
        let start = Instant::now();
        h.upload(&format!("live-{i}.md"), WriteIntent::Create, None, &body)
            .await
            .expect("live");
        samples.push(start.elapsed());
    }
    print_row("fs_write_during_50_commit_backlog", &mut samples);
    let p99 = {
        samples.sort();
        percentile(&samples, 0.99)
    };
    assert!(
        p99 <= Duration::from_millis(500),
        "R3 gate: agent fs.write p99 during 50-commit backlog must be ≤ 500 ms, got {p99:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn bench_longest_write_during_save_version() {
    let h = OperatorHarness::open().await;
    h.upload("v.md", WriteIntent::Create, None, b"seed")
        .await
        .expect("seed");
    let start = Instant::now();
    h.core
        .save_version(
            &common::operator_actor(),
            &cap_fs::operator::FilesSaveVersion {
                title: "bench".into(),
                paths: None,
            },
        )
        .await
        .expect("save-version");
    let elapsed = start.elapsed();
    eprintln!(
        "BENCH save_version_wall {:.3}ms",
        elapsed.as_secs_f64() * 1000.0
    );
    assert!(
        elapsed <= Duration::from_secs(15),
        "R3 gate: longest write during save-version must be ≤ 15 s, got {elapsed:?}"
    );
}

//! OSS-7 R3 user-lane latency witness (`#[ignore]`; MODULE-003 §2.13).
//!
//! Run via `scripts/bench/user-lane-latency.sh` on an APFS volume
//! (`ADVANCE_BENCH_DIR`). Not a CI gate. Rows marked gate in MODULE-003 §2.13
//! are recorded from a local APFS run.
//!
//! Besides the original save/backlog/save-version rows this file measures:
//! 1k and 10k tracked files with every object loose; a 10 000-path
//! `restore_tree`; the delete of a 2 GiB untracked folder. Concurrent
//! `OperatorFiles` uploads stand in for agent `fs.write` during the last two.

mod common;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use advance_git::{
    BlobSource, ChangeRole, PathChange, RepoPath, RestoreScope, RestoreSource, RestoreTreeRequest,
    UserActor, UserCommitLane, UserCommitRequest, UserCommitStatus, UserOpKind,
};
use cap_fs::operator::{
    FileUploadHandle, FileWriteTarget, FilesDelete, FilesDeleteItem, OperatorFiles, WriteIntent,
};

use common::{operator_actor, OperatorHarness};

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
    bench_log(&format!(
        "BENCH {name} n={} p50={:.3}ms p99={:.3}ms max={:.3}ms",
        samples.len(),
        p50.as_secs_f64() * 1000.0,
        p99.as_secs_f64() * 1000.0,
        samples
            .last()
            .map(|d| d.as_secs_f64() * 1000.0)
            .unwrap_or(0.0)
    ));
}

/// cargo test may blank TMPDIR; OperatorHarness::open uses tempfile which honors it.
fn ensure_bench_tmpdir() {
    if let Ok(dir) = std::env::var("ADVANCE_BENCH_DIR") {
        if !dir.is_empty() {
            let p = PathBuf::from(&dir);
            if p.is_dir() {
                std::env::set_var("TMPDIR", p);
            }
        }
    }
}

fn bench_log(msg: &str) {
    eprintln!("{msg}");
    let _ = io::stderr().flush();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn bench_save_to_commit_latency_p50_p99() {
    ensure_bench_tmpdir();
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
    ensure_bench_tmpdir();
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
    ensure_bench_tmpdir();
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
    bench_log(&format!(
        "BENCH save_version_wall {:.3}ms",
        elapsed.as_secs_f64() * 1000.0
    ));
    assert!(
        elapsed <= Duration::from_secs(15),
        "R3 gate: longest write during save-version must be ≤ 15 s, got {elapsed:?}"
    );
}

const R3_WRITE_CAP: Duration = Duration::from_secs(15);
const CORPUS_BODY: usize = 64;
const TEN_KIB: usize = 10 * 1024;
const SAMPLE_N: usize = 30;
const TWO_GIB: u64 = 2 * 1024 * 1024 * 1024;
const CHUNK_FILE_BYTES: u64 = 64 * 1024 * 1024;
const CHUNK_FILES: u32 = 32; // 32 × 64 MiB = 2 GiB

fn corpus_rel(i: usize) -> String {
    format!("corpus/f-{i:05}.md")
}

fn corpus_bytes(i: usize, gen: u8) -> Vec<u8> {
    let mut body = format!("{i:05}-{gen}").into_bytes();
    body.resize(CORPUS_BODY, b'x');
    body
}

fn put_bytes(rel: &str, bytes: Vec<u8>) -> PathChange {
    PathChange::Put {
        path: RepoPath::parse(rel).expect("RepoPath"),
        content: BlobSource::Bytes(bytes),
        role: ChangeRole::Primary,
        executable: None,
        stat: None,
    }
}

fn disable_auto_gc(home: &Path) {
    let repo = git2::Repository::open(home).expect("open repo");
    let mut cfg = repo.config().expect("config");
    cfg.set_i32("gc.auto", 0).expect("gc.auto");
    cfg.set_i32("gc.autoPackLimit", 0)
        .expect("gc.autoPackLimit");
}

struct ObjectCount {
    loose: u64,
    in_pack: u64,
    packs: u64,
}

fn count_objects(home: &Path) -> ObjectCount {
    let out = std::process::Command::new("git")
        .args([
            "-C",
            home.to_str().expect("utf8 home"),
            "count-objects",
            "-v",
        ])
        .output()
        .expect("git count-objects");
    assert!(
        out.status.success(),
        "git count-objects failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let mut loose = 0;
    let mut in_pack = 0;
    let mut packs = 0;
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = v.trim().parse::<u64>().unwrap_or(0);
        match k.trim() {
            "count" => loose = v,
            "in-pack" => in_pack = v,
            "packs" => packs = v,
            _ => {}
        }
    }
    ObjectCount {
        loose,
        in_pack,
        packs,
    }
}

fn print_objects(label: &str, home: &Path) -> ObjectCount {
    let c = count_objects(home);
    bench_log(&format!(
        "BENCH {label} loose={} in_pack={} packs={}",
        c.loose, c.in_pack, c.packs
    ));
    c
}

fn assert_all_loose(label: &str, home: &Path) {
    let c = print_objects(label, home);
    assert_eq!(
        c.in_pack, 0,
        "{label}: objects must stay loose (in-pack={}, packs={})",
        c.in_pack, c.packs
    );
    assert_eq!(c.packs, 0, "{label}: pack files present");
    assert!(c.loose > 0, "{label}: no loose objects");
}

async fn commit_puts(
    h: &OperatorHarness,
    op: UserOpKind,
    changes: Vec<PathChange>,
) -> advance_git::UserCommitOutcome {
    let req = UserCommitRequest {
        actor: UserActor::from_principal_id("advance"),
        op,
        changes,
        correlation_id: Some("oss7-bench".into()),
        provenance: None,
    };
    h.lane
        .commit_user(req)
        .await
        .expect("commit_user rx")
        .expect("commit_user")
}

async fn seed_corpus(h: &OperatorHarness, n: usize) -> String {
    std::fs::create_dir_all(h.home.join("corpus")).expect("corpus dir");
    let mut changes = Vec::with_capacity(n);
    for i in 0..n {
        let rel = corpus_rel(i);
        let body = corpus_bytes(i, 0);
        std::fs::write(h.home.join(&rel), &body).expect("seed file");
        changes.push(put_bytes(&rel, body));
    }
    let start = Instant::now();
    // Create is one Put; a corpus is one Upload of N Puts (≤ MAX_USER_CHANGES).
    let out = commit_puts(h, UserOpKind::Upload, changes).await;
    bench_log(&format!(
        "BENCH seed_corpus n={n} wall={:.3}ms status={:?} sha={:?}",
        start.elapsed().as_secs_f64() * 1000.0,
        out.status,
        out.sha
    ));
    assert_eq!(out.status, UserCommitStatus::Committed);
    out.sha.expect("seed sha")
}

async fn mutate_corpus(h: &OperatorHarness, n: usize) {
    let mut changes = Vec::with_capacity(n);
    for i in 0..n {
        let rel = corpus_rel(i);
        let body = corpus_bytes(i, 1);
        std::fs::write(h.home.join(&rel), &body).expect("mutate file");
        changes.push(put_bytes(&rel, body));
    }
    let start = Instant::now();
    let out = commit_puts(h, UserOpKind::Upload, changes).await;
    bench_log(&format!(
        "BENCH mutate_corpus n={n} wall={:.3}ms status={:?}",
        start.elapsed().as_secs_f64() * 1000.0,
        out.status
    ));
    assert_eq!(out.status, UserCommitStatus::Committed);
}

async fn sample_commit_user_10kib(h: &OperatorHarness, label: &str) {
    let body = vec![b'z'; TEN_KIB];
    let mut samples = Vec::with_capacity(SAMPLE_N);
    for i in 0..SAMPLE_N {
        let path = format!("probe-{label}-{i}.md");
        let start = Instant::now();
        h.upload(&path, WriteIntent::Create, None, &body)
            .await
            .expect("10KiB create");
        samples.push(start.elapsed());
    }
    print_row(&format!("commit_user_10KiB_on_{label}"), &mut samples);
}

struct ProbeSet {
    samples: Mutex<Vec<Duration>>,
    errors: Mutex<Vec<String>>,
    stop: AtomicBool,
}

async fn timed_create(
    core: &OperatorFiles,
    path: &str,
    bytes: &[u8],
) -> Result<Duration, (Duration, String)> {
    let actor = operator_actor();
    let target = FileWriteTarget {
        path: path.into(),
        intent: WriteIntent::Create,
        base_oid: None,
        expected_bytes: Some(bytes.len() as u64),
        batch: None,
    };
    let start = Instant::now();
    let run = async {
        let sink = core
            .begin_upload(&actor, &target)
            .map_err(|e| e.to_string())?;
        std::fs::write(&sink.staging_path, bytes).map_err(|e| e.to_string())?;
        core.finish_upload(
            &actor,
            &target,
            FileUploadHandle {
                token: sink.handle.token,
            },
        )
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    };
    match run.await {
        Ok(()) => Ok(start.elapsed()),
        Err(e) => Err((start.elapsed(), e)),
    }
}

fn spawn_write_probes(
    core: Arc<OperatorFiles>,
    prefix: &'static str,
) -> (Arc<ProbeSet>, tokio::task::JoinHandle<()>) {
    let probes = Arc::new(ProbeSet {
        samples: Mutex::new(Vec::new()),
        errors: Mutex::new(Vec::new()),
        stop: AtomicBool::new(false),
    });
    let running = Arc::clone(&probes);
    let handle = tokio::spawn(async move {
        let body = vec![b'w'; 4096];
        let mut i = 0u32;
        loop {
            let path = format!("{prefix}-{i}.md");
            match timed_create(&core, &path, &body).await {
                Ok(d) => running.samples.lock().expect("samples").push(d),
                Err((d, e)) => {
                    running.errors.lock().expect("errors").push(e);
                    running.samples.lock().expect("samples").push(d);
                }
            }
            if running.stop.load(Ordering::SeqCst) {
                break;
            }
            i = i.saturating_add(1);
            if i > 10_000 {
                break;
            }
        }
    });
    (probes, handle)
}

async fn stop_probes(
    label: &str,
    probes: Arc<ProbeSet>,
    handle: tokio::task::JoinHandle<()>,
) -> Duration {
    probes.stop.store(true, Ordering::SeqCst);
    let _ = handle.await;
    let mut samples = probes.samples.lock().expect("samples").clone();
    let errors = probes.errors.lock().expect("errors").clone();
    if !errors.is_empty() {
        bench_log(&format!(
            "BENCH {label} probe_errors n={} first={}",
            errors.len(),
            errors[0]
        ));
    }
    print_row(&format!("{label}_concurrent_fs_write"), &mut samples);
    samples.into_iter().max().unwrap_or(Duration::ZERO)
}

fn write_untracked_2g(dir: &Path) {
    std::fs::create_dir_all(dir).expect("2g dir");
    let chunk = vec![0xABu8; 1024 * 1024];
    let start = Instant::now();
    let mut total = 0u64;
    for i in 0..CHUNK_FILES {
        let path = dir.join(format!("chunk-{i:02}.bin"));
        let mut f = std::fs::File::create(&path).expect("chunk file");
        let mut written = 0u64;
        while written < CHUNK_FILE_BYTES {
            f.write_all(&chunk).expect("write chunk");
            written += chunk.len() as u64;
        }
        f.sync_all().expect("fsync chunk");
        total += written;
    }
    assert!(
        total >= TWO_GIB,
        "untracked folder is {total} bytes, want ≥ {TWO_GIB}"
    );
    bench_log(&format!(
        "BENCH write_untracked_2g bytes={total} files={CHUNK_FILES} wall={:.3}ms",
        start.elapsed().as_secs_f64() * 1000.0
    ));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn bench_loose_corpus_1k_and_10k() {
    ensure_bench_tmpdir();
    for n in [1_000usize, 10_000] {
        let h = OperatorHarness::open().await;
        disable_auto_gc(&h.home);
        let _sha = seed_corpus(&h, n).await;
        assert_all_loose(&format!("corpus_{n}_after_seed"), &h.home);
        sample_commit_user_10kib(&h, &format!("{n}_loose")).await;
        assert_all_loose(&format!("corpus_{n}_after_samples"), &h.home);
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn bench_rollback_10k_paths_with_concurrent_writes() {
    ensure_bench_tmpdir();
    let n = 10_000usize;
    let h = OperatorHarness::open().await;
    disable_auto_gc(&h.home);
    let origin = seed_corpus(&h, n).await;
    mutate_corpus(&h, n).await;
    let paths: Vec<RepoPath> = (0..n)
        .map(|i| RepoPath::parse(&corpus_rel(i)).expect("path"))
        .collect();
    let (probes, handle) = spawn_write_probes(Arc::clone(&h.core), "r3-rollback");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let req = RestoreTreeRequest {
        actor: UserActor::from_principal_id("advance"),
        source: RestoreSource::Commit(origin),
        scope: RestoreScope::Paths(paths),
        correlation_id: Some("oss7-rollback-10k".into()),
        provenance: None,
    };
    let start = Instant::now();
    let out = h
        .lane
        .restore_tree(req)
        .await
        .expect("restore rx")
        .expect("restore_tree");
    let wall = start.elapsed();
    bench_log(&format!(
        "BENCH restore_tree_10k_paths wall={:.3}ms status={:?} restored={} removed={}",
        wall.as_secs_f64() * 1000.0,
        out.status,
        out.restored_count,
        out.removed_count
    ));
    assert_eq!(out.status, UserCommitStatus::Committed);
    assert_eq!(out.restored_count, n as u32);

    let max_write = stop_probes("rollback_10k", probes, handle).await;
    assert!(
        max_write <= R3_WRITE_CAP,
        "R3 gate: longest agent fs.write during 10k-path rollback must be ≤ 15 s, got {max_write:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn bench_delete_2gb_untracked_with_concurrent_writes() {
    ensure_bench_tmpdir();
    let h = OperatorHarness::open().await;
    // A top-level directory inherits workspace-root protection and cannot be
    // deleted; nest one Normal level so OperatorFiles::delete is allowed.
    let dir_rel = "scratch/untracked-2g";
    write_untracked_2g(&h.home.join(dir_rel));
    let (probes, handle) = spawn_write_probes(Arc::clone(&h.core), "r3-delete2g");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let start = Instant::now();
    h.core
        .delete(
            &operator_actor(),
            &FilesDelete {
                items: vec![FilesDeleteItem {
                    path: dir_rel.into(),
                    base_oid: None,
                }],
                recursive: true,
                include_uncommitted: true,
                confirm_unversioned: true,
            },
        )
        .await
        .expect("delete 2g");
    let wall = start.elapsed();
    bench_log(&format!(
        "BENCH delete_2gb_untracked wall={:.3}ms",
        wall.as_secs_f64() * 1000.0
    ));
    assert!(
        !h.home.join(dir_rel).exists(),
        "untracked 2g folder still on disk"
    );

    let max_write = stop_probes("delete_2gb", probes, handle).await;
    assert!(
        max_write <= R3_WRITE_CAP,
        "R3 gate: longest agent fs.write during 2 GB untracked delete must be ≤ 15 s, got {max_write:?}"
    );
}

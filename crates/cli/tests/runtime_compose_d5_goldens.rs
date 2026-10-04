//! MODULE-001-T111 (1)–(2) / MODULE-001-AC-30 — the no-regression goldens of ADR 2026-10-03 D5
//! for the real `advance start` binary, captured on the pre-lane OSS tree (main 84a82451), before
//! the runtime-compose move. The route-table goldens live in `runtime_compose_d5_route_table.rs`
//! (their own test binary); both binaries share `runtime_compose_d5_common` (homes, golden files,
//! sha256 pins, pending decisions).
//!
//! What each golden pins (files under `tests/goldens/runtime_compose_d5/`):
//! - `start.<home>.stdout.golden` / `start.<home>.stderr.golden` (H1..H6): every byte of each
//!   stream of `advance start`, from spawn until EOF after SIGTERM. H2's SIGTERM outcome is a
//!   pending decision, so its stdout golden stops after `advance: shutting down` and its stderr
//!   golden at SIGTERM; `start.h2_all_capabilities.after_shutdown.golden` (owned by that
//!   decision) holds the outcome, the rest of both streams and the `.runtime` files after exit;
//! - `start.h1_fs_llm.merged.golden`: an H1 run with stderr joined to stdout's pipe, which pins
//!   the order of the lines across the two streams;
//! - `runtime_files.<home>.golden` (H1, H2): bytes and mode of `.runtime/runtime.lock`,
//!   `.runtime/client-api` and `.runtime/selected-provider` while running, and (H1) which of them
//!   remain after exit;
//! - `exit_codes.golden`: the exit status of every run; `exit.<scenario>.golden`: outcome, both
//!   streams and the `.runtime` files of each startup failure (no runtime-config, a malformed
//!   runtime-config, the runtime lock held by a live `advance start`). The failed readiness write
//!   is split the same way as H2: `exit.readiness_write_failure.golden` holds the stderr written
//!   before the readiness line, `exit.readiness_write_failure.after_write.golden` (owned by that
//!   decision) the outcome, the rest of stderr and the `.runtime` files after exit;
//! - `route_probe.<home>.golden` (H1..H5): the full answer of every route of the route table
//!   (status, plus error code + message, or the canonical JSON of `data`, plus warnings), the
//!   session operations, logins from the allowed console Origin and from a foreign Origin, the
//!   CSRF gate, router fallbacks (unknown route, wrong method, non-`/client` paths), the Web
//!   Console assets, representative response headers, both WebSocket routes (seed frames and a
//!   delta subscribe frame carrying a bogus resume cursor) and the `POST /msg` listener.
//!
//! Masks, each applied only after the masked value is checked where it can be checked:
//! - text: the per-run temp root (`<ROOT>`; homes live at `<ROOT>/ws`, `HOME` at `<ROOT>/home`,
//!   `TMPDIR` at `<ROOT>/tmp`), loopback ports (`127.0.0.1:<PORT>`), and the thread id + source
//!   location of a std panic header;
//! - runtime files: the child pid (checked equal to the spawned pid), the RFC 3339 timestamps and
//!   the OS / process-start parts of `platform_uid` (checked against `std::env::consts::OS` and
//!   `ps -o lstart=`); the holder pid named by the lock-held failure (checked equal to the
//!   holder's pid);
//! - probe answers: the closed, named list [`PROBE_MASKS`] (a JSON pointer per probe line whose
//!   value's shape is checked, then replaced by `"<NAME>"`).
//!
//! No golden may contain the package version (the lane bumps it); every golden is checked.
//!
//! Update mode: `ADVANCE_UPDATE_D5_GOLDENS=1` writes every golden and then fails (update mode is
//! never green). Every golden is pinned by sha256 (`BASELINE_GOLDEN_SHA256`, or the entry of the
//! decided outcome in the pending constant that owns it), and the pin is checked before the
//! comparison and before the D5 overlay is applied. A pin is edited in place only by a whole-tree
//! re-capture on a new base, for a golden whose only changed line is its `CAPTURED_ON` header
//! (update mode labels every golden it writes; see `PendingExpectation`). Intended wire changes
//! go through [`D5_CHANGE_MATRIX`] only, and the overlay is checked against the ADR D5 rows
//! derived from each home's declarations, on the route-probe path itself.
//!
//! Runs that compose take one of a few boot slots (spawn until settled), and the harness reads
//! `runtime.lock` only clear of its 30 s in-place heartbeat rewrite.
#![cfg(unix)]

// Shared with `runtime_compose_d5_route_table.rs`; each binary uses a different part of it.
#[allow(dead_code)]
mod runtime_compose_d5_common;

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use advance_client_api::{Method, RouteTableEntry, API_VERSION, CLIENT_WS_PROTOCOL};
use runtime_compose_d5_common::{
    declares, describe, field, golden_path, make_home, method_name, only_captured_on_line_changed,
    output_locked, pending_owner, probe_route_table, read_pinned_golden, replace_field, sha256_hex,
    spawn_lock, spawn_locked, update_mode, ExitOutcome, Goldens, HomeSpec, Masks,
    PendingExpectation, TestHome, BASELINE_GOLDEN_SHA256, CAPTURED_ON, GOLDEN_DIR, H1, H2,
    H2_AFTER_SHUTDOWN_GOLDEN, H2_SIGTERM_AFTER_READINESS, H3, H4, H5, H6, PACKAGE_VERSION,
    PENDING_EXPECTATIONS, PROBE_HOMES, READINESS_AFTER_WRITE_GOLDEN, READINESS_BEFORE_WRITE_GOLDEN,
    READINESS_WRITE_FAILURE, SIGTERM_EXIT_BUDGET_SECS,
};
use serde_json::Value;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::{Message, WebSocket};

// ── Budgets ───────────────────────────────────────────────────────────────────────────────

/// Cold-start budget until the last boot line (first-run engine compile on a cold cache).
const BOOT_TIMEOUT: Duration = Duration::from_secs(180);
/// After the last boot line, both streams must stay silent this long before SIGTERM.
const QUIET_PERIOD: Duration = Duration::from_millis(1500);
/// Upper bound for reaching the quiet period once the last boot line is seen.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a startup-failure run gets to exit on its own.
const FAILURE_EXIT_BUDGET: Duration = Duration::from_secs(180);
/// How long the pipe readers get to reach EOF once the process is gone. A reader still blocked
/// after this means something else holds the pipe open; the run fails instead of hanging.
const READER_EOF_BUDGET: Duration = Duration::from_secs(30);
/// Per-request socket timeout of a route probe (a probe must never hang).
const PROBE_IO_TIMEOUT: Duration = Duration::from_secs(30);

/// The value of every path parameter of a probed templated route.
const PROBE_PARAM: &str = "golden-probe-id";

// ── D5 change matrix overlay for the route-probe goldens ──────────────────────────────────

/// One explicit change of a route-probe golden line (`<KEY> -> <outcome>`, key =
/// `<METHOD> <path>`; `WS <path> <frame>` for the WebSocket lines).
struct D5Change {
    /// Labels of the probe homes the change applies to (`h1_fs_llm`, …).
    homes: &'static [&'static str],
    method: &'static str,
    /// The route as it appears in the golden (template text for a templated route; for a
    /// WebSocket line, the path and the frame name, e.g. `/client/events/stream seed`).
    path: &'static str,
    /// The outcome recorded in the golden. The overlay refuses to apply when the golden says
    /// anything else, so it can only change what it names.
    before: &'static str,
    /// The outcome after the change.
    after: &'static str,
}

/// The route-probe overlay: the ADR 2026-10-03 D5 change matrix, "the intended wire changes for
/// a plain `advance start` (no extension), and nothing else":
///
/// | Route | Home | v0.1.26 | After |
/// |---|---|---|---|
/// | events, events/stream, run / task history | no `lifecycle` | `module_unavailable` | `data` (D4) |
/// | grants/pending | neither `lifecycle` nor `grant`; or `lifecycle` without `grant` | `module_unavailable` | `{requests: []}` |
/// | grants/pending | `grant` without `lifecycle` | `module_unavailable` | unchanged |
/// | tools | no deployed driver, or no `tools` | `module_unavailable` | `data` |
/// | llm/deltas/stream | `llm` without `lifecycle` | pages without a resume cursor | pages carry a resume cursor (the cursor codec is now installed on every home) |
///
/// Empty at the capture: every golden must match exactly. The step that implements D4 adds one
/// entry per (home, line) the table changes, with the `before` text copied from the golden;
/// [`module_001_t111_ac30_d5_overlay_only_adr_rows`] derives the allowed lines from each probe
/// home's declarations ([`d5_targets`]) and, once this list is non-empty, requires it to cover
/// all of them. Row 5 is witnessed by the delta WebSocket subscribe frame that presents a bogus
/// resume cursor: without a cursor codec it is refused `module_unavailable` ("delta cursor
/// unavailable"); with the codec it answers as on H3 (the codec's cursor rejection).
const D5_CHANGE_MATRIX: &[D5Change] = &[];

/// The D5 rows that change a line (row 3 — `grant` without `lifecycle` — changes nothing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum D5Row {
    /// Row 1: events, events/stream (HTTP and the WebSocket seed), run / task history.
    EventsAndHistory,
    /// Row 2: grants/pending answers an empty request list.
    GrantsPending,
    /// Row 4: tools answers its inventory.
    Tools,
    /// Row 5: the delta WebSocket opens resume cursors.
    DeltaCursor,
}

/// The `after` of every row-2 change.
const GRANTS_PENDING_EMPTY: &str = "200 data {\"requests\":[]}";

/// The probe lines `spec`'s home may change under the D5 matrix, derived from its declarations
/// exactly per the ADR rows.
fn d5_targets(spec: &HomeSpec) -> Vec<(D5Row, &'static str, &'static str)> {
    let lifecycle = declares(spec, "lifecycle");
    let grant = declares(spec, "grant");
    let mut out = Vec::new();
    if !lifecycle {
        for (method, path) in [
            ("GET", "/client/events"),
            ("GET", "/client/events/stream"),
            ("WS", "/client/events/stream seed"),
            ("GET", "/client/runs/{run_id}/history"),
            ("GET", "/client/tasks/{task_id}/history"),
        ] {
            out.push((D5Row::EventsAndHistory, method, path));
        }
    }
    let grants_row = match (lifecycle, grant) {
        // Row 2: neither `lifecycle` nor `grant`.
        (false, false) => true,
        // Row 2: `lifecycle` without `grant`.
        (true, false) => true,
        // Row 3: `grant` without `lifecycle` — unchanged.
        (false, true) => false,
        // Both declared: not a D5 row (grants/pending already answers).
        (true, true) => false,
    };
    if grants_row {
        out.push((D5Row::GrantsPending, "GET", "/client/grants/pending"));
    }
    if !spec.driver || !declares(spec, "tools") {
        out.push((D5Row::Tools, "GET", "/client/tools"));
    }
    if declares(spec, "llm") && !lifecycle {
        out.push((
            D5Row::DeltaCursor,
            "WS",
            "/client/llm/deltas/stream subscribe",
        ));
    }
    out
}

/// A change for one home (the matrix entries expanded per home).
#[derive(Debug, Clone, Copy)]
struct HomeChange<'a> {
    home: &'a str,
    method: &'a str,
    path: &'a str,
    before: &'a str,
    after: &'a str,
}

fn expand_matrix(changes: &[D5Change]) -> Vec<HomeChange<'_>> {
    changes
        .iter()
        .flat_map(|c| {
            c.homes.iter().map(move |home| HomeChange {
                home,
                method: c.method,
                path: c.path,
                before: c.before,
                after: c.after,
            })
        })
        .collect()
}

fn apply_overlay(changes: &[HomeChange<'_>], home: &str, golden: &str) -> String {
    let mut lines: Vec<String> = golden.split('\n').map(str::to_string).collect();
    for change in changes.iter().filter(|c| c.home == home) {
        let key = format!("{} {} -> ", change.method, change.path);
        let hits: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.starts_with(&key))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "D5 overlay {} {} on {home}: expected exactly one golden line",
            change.method,
            change.path
        );
        let line = &mut lines[hits[0]];
        let before = &line[key.len()..];
        assert_eq!(
            before, change.before,
            "D5 overlay {} {} on {home}: the golden's captured outcome differs from the overlay's \
             `before`",
            change.method, change.path
        );
        *line = format!("{key}{}", change.after);
    }
    lines.join("\n")
}

/// The captured outcome of `<method> <path>` in `home`'s route-probe golden (pin checked).
fn golden_outcome(home: &str, method: &str, path: &str) -> String {
    let golden = read_pinned_golden(&format!("route_probe.{home}.golden"));
    let key = format!("{method} {path} -> ");
    let hits: Vec<&str> = golden
        .lines()
        .filter_map(|l| l.strip_prefix(key.as_str()))
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "exactly one `{method} {path}` line in route_probe.{home}.golden"
    );
    hits[0].to_string()
}

fn probe_home_by_label(label: &str) -> &'static HomeSpec {
    PROBE_HOMES
        .iter()
        .copied()
        .find(|s| s.label == label)
        .unwrap_or_else(|| panic!("{label} is not a probe home"))
}

/// The ADR D5 rows check of an overlay: every change targets a line its home's declarations put
/// under a row, with the row's `before` / `after` shape and the golden's `before`; no line is
/// changed twice; row 3 never appears; and a non-empty overlay covers every derived line.
fn check_overlay_against_adr(changes: &[HomeChange<'_>]) {
    let mut derived: Vec<(&'static str, D5Row, &'static str, &'static str)> = Vec::new();
    for spec in PROBE_HOMES {
        for (row, method, path) in d5_targets(spec) {
            derived.push((spec.label, row, method, path));
        }
    }
    // Row 3: `grant` without `lifecycle` keeps grants/pending as captured.
    for spec in PROBE_HOMES
        .iter()
        .filter(|s| declares(s, "grant") && !declares(s, "lifecycle"))
    {
        assert!(
            !derived
                .iter()
                .any(|(home, _, _, path)| *home == spec.label && *path == "/client/grants/pending"),
            "row 3: grants/pending on {} is never a D5 target",
            spec.label
        );
        assert!(
            !changes
                .iter()
                .any(|c| c.home == spec.label && c.path == "/client/grants/pending"),
            "row 3: the D5 overlay must not change grants/pending on {} (`grant` without `lifecycle`)",
            spec.label
        );
    }
    // Every derived line records its row's captured "before" shape.
    for (home, row, method, path) in &derived {
        let outcome = golden_outcome(home, method, path);
        let expected = match row {
            D5Row::DeltaCursor => "error module_unavailable ",
            _ => "503 error module_unavailable ",
        };
        assert!(
            outcome.starts_with(expected),
            "D5 row {row:?} target {method} {path} on {home} was captured as {outcome:?}, not \
             {expected:?}…: the row derivation does not match the capture"
        );
    }
    let mut seen = BTreeSet::new();
    for change in changes {
        let spec = probe_home_by_label(change.home);
        assert!(
            seen.insert((change.home, change.method, change.path)),
            "D5 overlay changes {} {} on {} twice",
            change.method,
            change.path,
            change.home
        );
        let row = derived
            .iter()
            .find(|(home, _, method, path)| {
                *home == spec.label && *method == change.method && *path == change.path
            })
            .map(|(_, row, _, _)| *row)
            .unwrap_or_else(|| {
                panic!(
                    "D5 overlay changes {} {} on {}, which no ADR D5 row allows for that home's \
                     declarations",
                    change.method, change.path, change.home
                )
            });
        assert_eq!(
            change.before,
            golden_outcome(change.home, change.method, change.path),
            "D5 overlay {} {} on {}: `before` is not the captured outcome",
            change.method,
            change.path,
            change.home
        );
        match row {
            D5Row::EventsAndHistory | D5Row::Tools => {
                assert!(change.before.starts_with("503 error module_unavailable "));
                let after_prefix = if change.method == "WS" {
                    "101 "
                } else {
                    "200 data "
                };
                assert!(
                    change.after.starts_with(after_prefix),
                    "D5 row {row:?}: {} {} on {} must answer data (`{after_prefix}…`), not {:?}",
                    change.method,
                    change.path,
                    change.home,
                    change.after
                );
            }
            D5Row::GrantsPending => {
                assert!(change.before.starts_with("503 error module_unavailable "));
                assert_eq!(
                    change.after, GRANTS_PENDING_EMPTY,
                    "D5 row 2: grants/pending on {} answers an empty request list",
                    change.home
                );
            }
            D5Row::DeltaCursor => {
                assert!(change.before.starts_with("error module_unavailable "));
                assert_eq!(
                    change.after,
                    golden_outcome(H3.label, change.method, change.path),
                    "D5 row 5: with the cursor codec installed, {} answers the bogus cursor as H3 \
                     (fs, llm, lifecycle) does",
                    change.home
                );
            }
        }
    }
    if !changes.is_empty() {
        let derived_set: BTreeSet<(&str, &str, &str)> = derived
            .iter()
            .map(|(home, _, method, path)| (*home, *method, *path))
            .collect();
        let missing: Vec<_> = derived_set.difference(&seen).collect();
        assert!(
            missing.is_empty(),
            "a non-empty D5 overlay must cover every ADR D5 line; missing: {missing:?}"
        );
    }
}

// ── `advance start` runs ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stream {
    Stdout,
    Stderr,
    /// stdout and stderr on one pipe.
    Merged,
}

/// Everything a run wrote, as raw chunks (one `read_until('\n')` each) in arrival order.
#[derive(Default)]
struct Transcript {
    chunks: Vec<(Stream, Vec<u8>)>,
    last_activity: Option<Instant>,
}

impl Transcript {
    fn text(&self, stream: Stream) -> String {
        let bytes: Vec<u8> = self
            .chunks
            .iter()
            .filter(|(s, _)| *s == stream)
            .flat_map(|(_, b)| b.iter().copied())
            .collect();
        String::from_utf8(bytes).expect("utf-8 output")
    }

    fn has_line(&self, prefix: &str) -> bool {
        self.chunks
            .iter()
            .any(|(_, b)| b.starts_with(prefix.as_bytes()))
    }
}

/// Both streams of a run (or the one merged stream).
struct Streams {
    stdout: String,
    stderr: String,
    merged: String,
}

fn spawn_reader<R: Read + Send + 'static>(
    stream: Stream,
    pipe: R,
    transcript: Arc<Mutex<Transcript>>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut reader = BufReader::new(pipe);
        loop {
            let mut chunk = Vec::new();
            match reader.read_until(b'\n', &mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let mut t = transcript.lock().unwrap_or_else(|e| e.into_inner());
                    t.chunks.push((stream, chunk));
                    t.last_activity = Some(Instant::now());
                }
            }
        }
    })
}

/// Join the reader threads, waiting at most `budget` for them to reach EOF. `false` = some
/// reader is still blocked (its thread is left detached).
fn join_bounded(readers: &mut Vec<JoinHandle<()>>, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    while readers.iter().any(|r| !r.is_finished()) {
        if Instant::now() >= deadline {
            readers.clear();
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    for reader in readers.drain(..) {
        let _ = reader.join();
    }
    true
}

/// The last step of the pre-move boot sequence before `advance start` parks (the readiness
/// walk).
fn boot_complete(t: &Transcript) -> bool {
    t.has_line("advance: continuous component reconciliation wired")
        || t.has_line("advance: readiness walk did not run")
        || t.has_line("advance: skipping readiness walk")
}

/// `advance start`'s stderr line when the component-registry open of its readiness walk runs
/// past the product's 5 s `BOOT_REGISTRY_OPEN_TIMEOUT` (`start.rs`): the run then skips the walk
/// and its streams differ from the goldens because the machine was too loaded, not because of a
/// regression.
const REGISTRY_OPEN_TIMED_OUT: &str = "advance: skipping readiness walk — registry open timed out";

/// Fail with an explicit "environment overloaded" message, instead of a golden diff, when a
/// boot hit the product's registry-open timeout.
fn assert_boot_not_starved(s: &Streams) {
    assert!(
        !s.stderr.contains(REGISTRY_OPEN_TIMED_OUT) && !s.merged.contains(REGISTRY_OPEN_TIMED_OUT),
        "ENVIRONMENT OVERLOADED, not a golden regression: `advance start` hit its 5 s \
         registry-open timeout (BOOT_REGISTRY_OPEN_TIMEOUT) and skipped the readiness walk, so \
         its streams cannot match the goldens. Rerun on a less loaded machine; if it reproduces \
         on an idle machine, the boot path regressed.\nstdout:\n{}\nstderr:\n{}\nmerged:\n{}",
        s.stdout,
        s.stderr,
        s.merged
    );
}

// ── Boot slots ────────────────────────────────────────────────────────────────────────────

/// How many runs of this binary may compose at once (from spawn until they settle or end).
/// Each boot's registry open runs under that 5 s product timeout while every other
/// debug-profile `advance start` competes for the CPU; the cap bounds that load.
fn max_concurrent_boots() -> usize {
    std::thread::available_parallelism()
        .map_or(2, |n| n.get() / 2)
        .clamp(2, 4)
}

/// Busy boot slots, and the condition a freed slot signals.
static BOOT_SLOTS: (Mutex<usize>, Condvar) = (Mutex::new(0), Condvar::new());

/// One of the [`max_concurrent_boots`] slots, released on drop. Taken before the spawn, so the
/// wait for a slot does not count against [`BOOT_TIMEOUT`].
struct BootSlot;

impl BootSlot {
    fn acquire() -> BootSlot {
        let (busy, freed) = &BOOT_SLOTS;
        let mut busy = busy.lock().unwrap_or_else(|e| e.into_inner());
        while *busy >= max_concurrent_boots() {
            busy = freed.wait(busy).unwrap_or_else(|e| e.into_inner());
        }
        *busy += 1;
        BootSlot
    }
}

impl Drop for BootSlot {
    fn drop(&mut self) {
        let (busy, freed) = &BOOT_SLOTS;
        let mut busy = busy.lock().unwrap_or_else(|e| e.into_inner());
        *busy -= 1;
        freed.notify_one();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wiring {
    /// stdout and stderr on their own pipes.
    Separate,
    /// stderr joined to stdout's pipe.
    Merged,
    /// stdout's read end closed right after spawn (the first stdout write gets EPIPE).
    StdoutClosed,
}

/// A spawned `advance` process with its pipe readers. Dropping it kills and reaps the process
/// (if not reaped yet) and joins the readers with a bound.
struct LiveRun {
    child: Child,
    reaped: bool,
    transcript: Arc<Mutex<Transcript>>,
    readers: Vec<JoinHandle<()>>,
    /// Held from spawn until the run settles or ends; `None` for a run that fails before it
    /// composes anything.
    boot_slot: Option<BootSlot>,
}

impl LiveRun {
    /// A run that composes (takes a boot slot first).
    fn start(cmd: Command, wiring: Wiring) -> LiveRun {
        let slot = BootSlot::acquire();
        LiveRun::spawn(cmd, wiring, Some(slot))
    }

    /// A run expected to fail before it composes anything (no boot slot).
    fn start_early_failure(cmd: Command) -> LiveRun {
        LiveRun::spawn(cmd, Wiring::Separate, None)
    }

    fn spawn(mut cmd: Command, wiring: Wiring, boot_slot: Option<BootSlot>) -> LiveRun {
        let transcript = Arc::new(Mutex::new(Transcript::default()));
        let mut readers = Vec::new();
        let child = match wiring {
            Wiring::Separate | Wiring::StdoutClosed => {
                cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
                let mut child = spawn_locked(cmd);
                let stdout = child.stdout.take().expect("stdout pipe");
                if wiring == Wiring::StdoutClosed {
                    drop(stdout);
                } else {
                    readers.push(spawn_reader(
                        Stream::Stdout,
                        stdout,
                        Arc::clone(&transcript),
                    ));
                }
                readers.push(spawn_reader(
                    Stream::Stderr,
                    child.stderr.take().expect("stderr pipe"),
                    Arc::clone(&transcript),
                ));
                child
            }
            Wiring::Merged => {
                // Pipe creation, spawn and the drop of the parent's write ends under the spawn
                // lock (see `SPAWN_LOCK`).
                let guard = spawn_lock();
                let (reader, writer) = std::io::pipe().expect("pipe");
                let writer_for_stderr = writer.try_clone().expect("clone pipe writer");
                cmd.stdout(writer).stderr(writer_for_stderr);
                let child = cmd.spawn().expect("spawn advance (merged streams)");
                drop(cmd);
                drop(guard);
                readers.push(spawn_reader(
                    Stream::Merged,
                    reader,
                    Arc::clone(&transcript),
                ));
                child
            }
        };
        LiveRun {
            child,
            reaped: false,
            transcript,
            readers,
            boot_slot,
        }
    }

    fn snapshot(&self) -> (bool, Option<Instant>, Streams) {
        let t = self.transcript.lock().unwrap_or_else(|e| e.into_inner());
        (
            boot_complete(&t),
            t.last_activity,
            Streams {
                stdout: t.text(Stream::Stdout),
                stderr: t.text(Stream::Stderr),
                merged: t.text(Stream::Merged),
            },
        )
    }

    /// Wait for the last boot line, then for the streams to stay quiet for [`QUIET_PERIOD`];
    /// releases the boot slot.
    fn wait_until_settled(&mut self) {
        let start = Instant::now();
        loop {
            let (complete, _, s) = self.snapshot();
            if complete {
                assert_boot_not_starved(&s);
                break;
            }
            if let Ok(Some(status)) = self.child.try_wait() {
                self.reaped = true;
                panic!(
                    "advance start exited before boot completed ({status:?})\nstdout:\n{}\nstderr:\n{}\nmerged:\n{}",
                    s.stdout, s.stderr, s.merged
                );
            }
            if start.elapsed() > BOOT_TIMEOUT {
                panic!(
                    "advance start did not complete boot within {BOOT_TIMEOUT:?}\nstdout:\n{}\nstderr:\n{}\nmerged:\n{}",
                    s.stdout, s.stderr, s.merged
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let settle_start = Instant::now();
        loop {
            let (_, last, s) = self.snapshot();
            if last.is_some_and(|l| l.elapsed() >= QUIET_PERIOD) {
                self.boot_slot = None;
                return;
            }
            if settle_start.elapsed() > SETTLE_TIMEOUT {
                panic!(
                    "advance start output did not settle within {SETTLE_TIMEOUT:?}\nstdout:\n{}\nstderr:\n{}\nmerged:\n{}",
                    s.stdout, s.stderr, s.merged
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// SIGTERM, wait up to `SIGTERM_EXIT_BUDGET_SECS`, SIGKILL if still running, then read the
    /// streams to EOF.
    fn sigterm_and_collect(mut self) -> (ExitOutcome, Streams) {
        let pid = i32::try_from(self.child.id()).expect("pid fits i32");
        // SAFETY: kill(2) with SIGTERM on the child we spawned and have not reaped yet.
        let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
        assert_eq!(rc, 0, "kill(SIGTERM): {}", std::io::Error::last_os_error());
        let deadline = Instant::now() + Duration::from_secs(SIGTERM_EXIT_BUDGET_SECS);
        let outcome = loop {
            match self.child.try_wait().expect("try_wait") {
                Some(status) => break exit_outcome(status),
                None if Instant::now() >= deadline => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break ExitOutcome::NoExitAfterSigterm;
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        };
        self.reaped = true;
        self.boot_slot = None;
        (outcome, self.collect())
    }

    /// Wait for a process that is expected to end on its own, then read the streams to EOF.
    fn wait_for_exit(mut self) -> (ExitOutcome, Streams) {
        let deadline = Instant::now() + FAILURE_EXIT_BUDGET;
        let status = loop {
            match self.child.try_wait().expect("try_wait") {
                Some(status) => break status,
                None if Instant::now() >= deadline => {
                    let (_, _, s) = self.snapshot();
                    panic!(
                        "advance did not exit within {FAILURE_EXIT_BUDGET:?}\nstdout:\n{}\nstderr:\n{}",
                        s.stdout, s.stderr
                    );
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        };
        self.reaped = true;
        self.boot_slot = None;
        (exit_outcome(status), self.collect())
    }

    fn collect(&mut self) -> Streams {
        assert!(
            join_bounded(&mut self.readers, READER_EOF_BUDGET),
            "a pipe reader did not reach EOF within {READER_EOF_BUDGET:?} after the process ended \
             (another process holds the pipe open)"
        );
        let (_, _, streams) = self.snapshot();
        streams
    }
}

impl Drop for LiveRun {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.reaped = true;
        }
        let _ = join_bounded(&mut self.readers, Duration::from_secs(5));
    }
}

fn exit_outcome(status: ExitStatus) -> ExitOutcome {
    match (status.code(), status.signal()) {
        (Some(code), _) => ExitOutcome::Code(code),
        (None, Some(signal)) => ExitOutcome::Signal(signal),
        (None, None) => panic!("exit status without code or signal: {status:?}"),
    }
}

fn presence(path: &Path) -> &'static str {
    if std::fs::symlink_metadata(path).is_ok() {
        "present"
    } else {
        "absent"
    }
}

fn runtime_files_presence(ws: &Path) -> String {
    let dir = ws.join(".runtime");
    format!(
        "runtime.lock={} client-api={} selected-provider={}",
        presence(&dir.join("runtime.lock")),
        presence(&dir.join("client-api")),
        presence(&dir.join("selected-provider"))
    )
}

/// A stream golden; `span` says which part of the run the stream covers.
fn stream_golden(title: &str, stream: &str, span: &str, masked: &str) -> String {
    format!(
        "# MODULE-001-T111 (1) `advance start` {stream} on {title} — normalised, {span}\n\
         # {CAPTURED_ON}\n{masked}"
    )
}

/// The span of a whole-stream golden.
const SPAN_TO_EOF: &str = "spawn to EOF after SIGTERM";

/// The stdout line `advance start` prints once it has handled SIGTERM, before it returns.
const SHUTTING_DOWN_LINE: &str = "advance: shutting down";

/// The start of stderr's Client API line, the only line `advance start` writes before its
/// readiness line (see `start.h1_fs_llm.merged.golden`).
const CLIENT_API_LINE_PREFIX: &str = "advance: Client API and Web Console listening at http://";

/// Split `text` after the first whole line (newline included) that starts at or after byte
/// `from` and satisfies `is_split_line`. Without such a line everything stays on the first side
/// (`(text, "")`), where the baseline comparison then fails.
fn split_after_line(text: &str, from: usize, is_split_line: impl Fn(&str) -> bool) -> (&str, &str) {
    let mut start = 0;
    for line in text.split_inclusive('\n') {
        let end = start + line.len();
        if start >= from && line.strip_suffix('\n').is_some_and(&is_split_line) {
            return text.split_at(end);
        }
        start = end;
    }
    (text, "")
}

// ── Runtime files ─────────────────────────────────────────────────────────────────────────

fn file_mode(path: &Path) -> String {
    let meta = std::fs::symlink_metadata(path)
        .unwrap_or_else(|e| panic!("{} missing while running: {e}", path.display()));
    assert!(
        meta.file_type().is_file(),
        "{} is a regular file",
        path.display()
    );
    format!("{:04o}", meta.permissions().mode() & 0o7777)
}

/// `ps -o lstart= -p <pid>` exactly as `runtime.lock`'s writer runs it (same environment shape).
fn ps_lstart(pid: u32) -> String {
    let mut cmd = Command::new("ps");
    cmd.args(["-o", "lstart=", "-p", &pid.to_string()])
        .env_clear()
        .stdin(Stdio::null());
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    let out = output_locked(cmd);
    assert!(out.status.success(), "ps -o lstart= failed: {out:?}");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn assert_rfc3339_utc(value: &str, what: &str) {
    let inner = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or_else(|| panic!("{what} is quoted: {value}"));
    let parsed = chrono::DateTime::parse_from_rfc3339(inner)
        .unwrap_or_else(|e| panic!("{what} is RFC 3339 ({inner}): {e}"));
    assert_eq!(
        parsed.offset().local_minus_utc(),
        0,
        "{what} is UTC: {inner}"
    );
    assert!(
        inner.ends_with("+00:00"),
        "{what} renders the +00:00 offset: {inner}"
    );
}

/// `advance start` refreshes `runtime.lock` every 30 s after acquiring it (`start.rs`:
/// `RuntimeLock::acquire(&workspace, Duration::from_secs(30))`). The refresh (`touch_heartbeat`,
/// `runtime_lock.rs`) truncates the file and writes it again, so a read can land in between and
/// see a partial file. (Making that rewrite atomic is a product follow-up, outside this lane.)
const LOCK_HEARTBEAT_PERIOD: Duration = Duration::from_secs(30);
/// The harness reads `runtime.lock` of a live run, and starts the lock-held second
/// `advance start`, only while the next refresh is at least this far away.
const HEARTBEAT_CLEARANCE: Duration = Duration::from_secs(10);

/// The keys of a complete `runtime.lock`.
const RUNTIME_LOCK_KEYS: [&str; 6] = [
    "pid",
    "platform_uid",
    "started_at",
    "heartbeat_at",
    "workspace_root",
    "version",
];

/// Whether `body` is a complete `runtime.lock`: every key on exactly one line, the pid in digits
/// and every other value a closed quoted string.
fn runtime_lock_complete(body: &str) -> bool {
    RUNTIME_LOCK_KEYS.iter().all(|key| {
        let prefix = format!("{key}: ");
        let values: Vec<&str> = body
            .split('\n')
            .filter_map(|l| l.strip_prefix(prefix.as_str()))
            .collect();
        match values.as_slice() {
            [pid] if *key == "pid" => !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()),
            [value] => value.len() >= 2 && value.starts_with('"') && value.ends_with('"'),
            _ => false,
        }
    })
}

/// `.runtime/runtime.lock` of a live run, read again (bounded) while a heartbeat refresh leaves
/// it partial.
fn read_runtime_lock(ws: &Path) -> String {
    let path = ws.join(".runtime/runtime.lock");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        if runtime_lock_complete(&body) {
            return body;
        }
        assert!(
            Instant::now() < deadline,
            "runtime.lock stayed incomplete for 2s: {body:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Wait until the next `runtime.lock` refresh of a live run is at least [`HEARTBEAT_CLEARANCE`]
/// away. The next refresh is due [`LOCK_HEARTBEAT_PERIOD`] after the last `heartbeat_at`; when it
/// is closer, or overdue, wait for it to pass and look again.
fn wait_clear_of_heartbeat(ws: &Path) {
    let period_ms = i64::try_from(LOCK_HEARTBEAT_PERIOD.as_millis()).expect("period fits i64");
    let clearance_ms = i64::try_from(HEARTBEAT_CLEARANCE.as_millis()).expect("clearance fits i64");
    let deadline = Instant::now() + 2 * LOCK_HEARTBEAT_PERIOD;
    loop {
        let body = read_runtime_lock(ws);
        let last = field(&body, "heartbeat_at");
        assert_rfc3339_utc(last, "heartbeat_at");
        let last_ms = chrono::DateTime::parse_from_rfc3339(last.trim_matches('"'))
            .expect("heartbeat_at is RFC 3339")
            .timestamp_millis();
        let now = i64::try_from(now_ms()).expect("now fits i64");
        let until_next_ms = last_ms + period_ms - now;
        if until_next_ms >= clearance_ms {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "runtime.lock's heartbeat_at did not advance within {:?}: {body:?}",
            2 * LOCK_HEARTBEAT_PERIOD
        );
        let wait_ms = u64::try_from(until_next_ms.max(0)).expect("non-negative") + 500;
        std::thread::sleep(Duration::from_millis(wait_ms));
    }
}

/// `.runtime/runtime.lock` while running: mask pid / platform_uid / timestamps after checking
/// them; the workspace path is masked by the path masks. Its `version` line is the literal
/// lock-format version `"0.1.0"` (`runtime_lock.rs`), not the package version, and is kept.
fn normalised_runtime_lock(body: &str, pid: u32, masks: &Masks) -> String {
    assert_eq!(field(body, "pid"), pid.to_string(), "runtime.lock pid");
    let uid = field(body, "platform_uid");
    let expected_uid = format!("\"{}:{}:{}\"", std::env::consts::OS, pid, ps_lstart(pid));
    assert_eq!(
        uid, expected_uid,
        "platform_uid = \"<os>:<pid>:<ps lstart>\""
    );
    let started = field(body, "started_at");
    let heartbeat = field(body, "heartbeat_at");
    assert_rfc3339_utc(started, "started_at");
    assert_rfc3339_utc(heartbeat, "heartbeat_at");
    let mut out = replace_field(body, "pid", "<PID>");
    out = replace_field(&out, "platform_uid", "\"<OS>:<PID>:<PS_LSTART>\"");
    out = replace_field(&out, "started_at", "\"<RFC3339_UTC>\"");
    out = replace_field(&out, "heartbeat_at", "\"<RFC3339_UTC>\"");
    // `replace_field` re-joins with '\n' exactly as split, so a (missing) trailing newline is
    // preserved byte for byte.
    masks.apply(&out)
}

fn normalised_pid_file(body: &str, pid: u32, masks: &Masks) -> String {
    assert_eq!(field(body, "pid"), pid.to_string(), "pid line");
    masks.apply(&replace_field(body, "pid", "<PID>"))
}

/// The bound Client API address from stderr's `advance: Client API and Web Console listening at
/// http://<addr>` line.
fn client_api_addr_from_stderr(stderr: &str) -> String {
    stderr
        .lines()
        .find_map(|l| l.strip_prefix(CLIENT_API_LINE_PREFIX))
        .unwrap_or_else(|| panic!("no Client API line on stderr:\n{stderr}"))
        .to_string()
}

/// The runtime-files golden of a live run; `scope` completes the header (what it covers).
fn render_runtime_files(
    title: &str,
    scope: &str,
    home: &TestHome,
    pid: u32,
    stderr_so_far: &str,
) -> String {
    let masks = home.masks();
    let dir = home.ws.join(".runtime");
    let lock = dir.join("runtime.lock");
    let discovery = dir.join("client-api");
    let selected = dir.join("selected-provider");
    let lock_body = read_runtime_lock(&home.ws);
    let discovery_body = std::fs::read_to_string(&discovery).expect("read client-api");
    let selected_body = std::fs::read_to_string(&selected).expect("read selected-provider");
    assert_eq!(
        field(&discovery_body, "client_api_base"),
        format!("\"http://{}\"", client_api_addr_from_stderr(stderr_so_far)),
        "the discovery file names the bound Client API"
    );
    format!(
        "# MODULE-001-T111 (1) runtime files of `advance start` on {title} {scope}\n\
         # {CAPTURED_ON}\n\
         # bytes = the exact file content as a Rust string literal (no trailing newline unless shown)\n\
         .runtime/runtime.lock mode={} bytes={:?}\n\
         .runtime/client-api mode={} bytes={:?}\n\
         .runtime/selected-provider mode={} bytes={:?}\n",
        file_mode(&lock),
        normalised_runtime_lock(&lock_body, pid, &masks),
        file_mode(&discovery),
        normalised_pid_file(&discovery_body, pid, &masks),
        file_mode(&selected),
        normalised_pid_file(&selected_body, pid, &masks),
    )
}

/// What a start run records besides its streams.
#[derive(Debug, Clone, Copy)]
struct StartPlan {
    /// The `.runtime` files while running (and after exit, unless that part is pending).
    record_files: bool,
    /// A second `advance start` on the workspace while this one runs (runtime lock held).
    probe_lock_held: bool,
    /// The SIGTERM outcome is a pending decision: this golden (owned by that constant) holds the
    /// outcome and everything from the decision point on, and the stream goldens stop there.
    after_shutdown_golden: Option<&'static str>,
}

/// H1 also records its runtime files and probes the held runtime lock; H2 records its runtime
/// files, and its SIGTERM outcome is pending (`H2_SIGTERM_AFTER_READINESS`).
fn start_plan(spec: &HomeSpec) -> StartPlan {
    StartPlan {
        record_files: spec.label == H1.label || spec.label == H2.label,
        probe_lock_held: spec.label == H1.label,
        after_shutdown_golden: (spec.label == H2.label).then_some(H2_AFTER_SHUTDOWN_GOLDEN),
    }
}

/// One `advance start` run to EOF after SIGTERM.
struct StartRun {
    outcome: ExitOutcome,
    /// The stdout / stderr goldens (up to the decision point when the outcome is pending).
    stdout: String,
    stderr: String,
    /// The runtime-files golden, when recorded.
    runtime_files: Option<String>,
    /// The second `advance start` on the same workspace while this one runs, when probed.
    lock_held: Option<(ExitOutcome, String)>,
    /// The pending after-shutdown golden (name, text), when the outcome is pending.
    after_shutdown: Option<(&'static str, String)>,
}

fn start_run(spec: &HomeSpec, plan: StartPlan) -> StartRun {
    let home = make_home(spec);
    let title = describe(spec);
    let pending = plan.after_shutdown_golden.map(|golden| {
        let (owner, _) = pending_owner(golden)
            .unwrap_or_else(|| panic!("{golden} belongs to no pending constant"));
        (golden, owner)
    });
    let mut run = LiveRun::start(home.start_command(), Wiring::Separate);
    run.wait_until_settled();
    let pid = run.pid();
    if plan.record_files || plan.probe_lock_held {
        wait_clear_of_heartbeat(&home.ws);
    }
    let runtime_files = plan.record_files.then(|| {
        let scope = match pending {
            Some((golden, owner)) => {
                format!("while running (after exit: pinned by {owner} in {golden})")
            }
            None => "while running, and after exit".to_string(),
        };
        let (_, _, s) = run.snapshot();
        render_runtime_files(&title, &scope, &home, pid, &s.stderr)
    });
    let lock_held = plan
        .probe_lock_held
        .then(|| lock_held_run(spec, &home, pid));
    let (_, _, before_sigterm) = run.snapshot();
    let (outcome, streams) = run.sigterm_and_collect();
    let masks = home.masks();
    let after_exit = runtime_files_presence(&home.ws);
    let Some((golden, owner)) = pending else {
        return StartRun {
            outcome,
            stdout: stream_golden(&title, "stdout", SPAN_TO_EOF, &masks.apply(&streams.stdout)),
            stderr: stream_golden(&title, "stderr", SPAN_TO_EOF, &masks.apply(&streams.stderr)),
            runtime_files: runtime_files.map(|files| format!("{files}after exit: {after_exit}\n")),
            lock_held,
            after_shutdown: None,
        };
    };
    // Pending outcome: stdout through `advance: shutting down` and stderr until SIGTERM are
    // baseline goldens; what follows, the outcome and the files after exit are the pending one.
    assert!(
        streams.stdout.starts_with(&before_sigterm.stdout)
            && streams.stderr.starts_with(&before_sigterm.stderr),
        "a transcript only grows"
    );
    let (stdout_base, stdout_tail) =
        split_after_line(&streams.stdout, before_sigterm.stdout.len(), |line| {
            line == SHUTTING_DOWN_LINE
        });
    let (stderr_base, stderr_tail) = streams.stderr.split_at(before_sigterm.stderr.len());
    let after_shutdown = format!(
        "# MODULE-001-T111 (1) `advance start` on {title} after SIGTERM: the outcome, what each stream writes after the decision point, and the .runtime files after exit (DECISION PENDING: {owner})\n\
         # {CAPTURED_ON}\n\
         {}\n--- stdout after the `{SHUTTING_DOWN_LINE}` line ---\n{}--- stderr after SIGTERM ---\n{}--- .runtime after exit ---\n{after_exit}\n",
        outcome.render(),
        masks.apply(stdout_tail),
        masks.apply(stderr_tail),
    );
    StartRun {
        outcome,
        stdout: stream_golden(
            &title,
            "stdout",
            &format!(
                "spawn through the `{SHUTTING_DOWN_LINE}` line after SIGTERM (what follows: {owner}, {golden})"
            ),
            &masks.apply(stdout_base),
        ),
        stderr: stream_golden(
            &title,
            "stderr",
            &format!("spawn until SIGTERM (what follows: {owner}, {golden})"),
            &masks.apply(stderr_base),
        ),
        runtime_files,
        lock_held,
        after_shutdown: Some((golden, after_shutdown)),
    }
}

/// A second `advance start` on the workspace of a live run (`holder_pid`): the runtime lock is
/// held. The holder pid it names is checked, then masked.
fn lock_held_run(spec: &HomeSpec, home: &TestHome, holder_pid: u32) -> (ExitOutcome, String) {
    let (outcome, streams) = LiveRun::start_early_failure(home.start_command()).wait_for_exit();
    let masks = home.masks();
    let holder = format!("pid={holder_pid}");
    assert!(
        streams.stderr.contains(&holder),
        "the lock-held failure names the holder pid {holder_pid}:\n{}",
        streams.stderr
    );
    let lock_body = read_runtime_lock(&home.ws);
    let lock_names_holder = field(&lock_body, "pid") == holder_pid.to_string();
    let golden = format!(
        "# MODULE-001-T111 (1) a second `advance start` on {}'s workspace while the first one runs (runtime lock held)\n\
         # {CAPTURED_ON}\n\
         # <HOLDER_PID> = the first run's pid (checked)\n\
         {}\n--- stdout ---\n{}--- stderr ---\n{}--- .runtime after the second run exits (the first still running) ---\n\
         {}\nruntime.lock still names the first run: {lock_names_holder}\n",
        describe(spec),
        outcome.render(),
        masks.apply(&streams.stdout.replace(&holder, "pid=<HOLDER_PID>")),
        masks.apply(&streams.stderr.replace(&holder, "pid=<HOLDER_PID>")),
        runtime_files_presence(&home.ws),
    );
    (outcome, golden)
}

/// An H1 run with stderr joined to stdout's pipe: the cross-stream order of its lines.
fn merged_run(spec: &HomeSpec) -> (ExitOutcome, String) {
    let home = make_home(spec);
    let mut run = LiveRun::start(home.start_command(), Wiring::Merged);
    run.wait_until_settled();
    let (outcome, streams) = run.sigterm_and_collect();
    let golden = format!(
        "# MODULE-001-T111 (1) `advance start` on {} with stderr joined to stdout's pipe (the order of the lines across both streams) — normalised, spawn to EOF after SIGTERM\n\
         # {CAPTURED_ON}\n{}",
        describe(spec),
        home.masks().apply(&streams.merged)
    );
    (outcome, golden)
}

fn failure_golden(title: &str, outcome: ExitOutcome, streams: &Streams, home: &TestHome) -> String {
    let masks = home.masks();
    format!(
        "# MODULE-001-T111 (1) `advance start` {title}\n# {CAPTURED_ON}\n\
         {}\n--- stdout ---\n{}--- stderr ---\n{}--- .runtime after exit ---\n{}\n",
        outcome.render(),
        masks.apply(&streams.stdout),
        masks.apply(&streams.stderr),
        runtime_files_presence(&home.ws)
    )
}

/// Startup failure: the workspace exists but has no `.advance/runtime-config.yaml`.
fn missing_runtime_config_run() -> (ExitOutcome, String) {
    let home = TestHome::new_root();
    std::fs::create_dir_all(home.ws.join(".advance")).expect("create .advance");
    let (outcome, streams) = LiveRun::start_early_failure(home.start_command()).wait_for_exit();
    let golden = failure_golden(
        "on a workspace without .advance/runtime-config.yaml",
        outcome,
        &streams,
        &home,
    );
    (outcome, golden)
}

/// The malformed runtime config of [`malformed_runtime_config_run`].
const MALFORMED_RUNTIME_CONFIG: &str = "wasm:\n  max_memory_pages: [1024\n";

/// Startup failure: an initialised H1 home whose runtime config is not valid YAML.
fn malformed_runtime_config_run() -> (ExitOutcome, String) {
    let home = make_home(&H1);
    std::fs::write(
        home.ws.join(".advance/runtime-config.yaml"),
        MALFORMED_RUNTIME_CONFIG,
    )
    .expect("write malformed runtime config");
    let (outcome, streams) = LiveRun::start_early_failure(home.start_command()).wait_for_exit();
    let golden = failure_golden(
        &format!(
            "on {} with .advance/runtime-config.yaml = {MALFORMED_RUNTIME_CONFIG:?} (malformed YAML)",
            describe(&H1)
        ),
        outcome,
        &streams,
        &home,
    );
    (outcome, golden)
}

/// Readiness write failure: stdout's read end is closed right after spawn, so the first stdout
/// write (the readiness line; nothing reaches stdout before it) fails with EPIPE. Returns the
/// outcome, the baseline golden (stderr through the Client API line, written before the
/// readiness line) and the pending golden (the outcome and everything after that line).
fn readiness_write_failure_run() -> (ExitOutcome, String, String) {
    let home = make_home(&H1);
    let (outcome, streams) =
        LiveRun::start(home.start_command(), Wiring::StdoutClosed).wait_for_exit();
    let masks = home.masks();
    let (before_write, after_write) = split_after_line(&streams.stderr, 0, |line| {
        line.starts_with(CLIENT_API_LINE_PREFIX)
    });
    let (owner, _) =
        pending_owner(READINESS_AFTER_WRITE_GOLDEN).expect("the after-write golden is pending");
    let baseline = format!(
        "# MODULE-001-T111 (1) `advance start` on {} with stdout's read end closed right after spawn (EPIPE on the readiness line): stderr up to the readiness write\n\
         # {CAPTURED_ON}\n\
         # the outcome and what follows the Client API line: {owner}, {READINESS_AFTER_WRITE_GOLDEN}\n\
         --- stderr through the Client API line ---\n{}",
        describe(&H1),
        masks.apply(before_write),
    );
    let pending = format!(
        "# MODULE-001-T111 (1) `advance start` on {} with stdout's read end closed right after spawn: the outcome of the failed readiness write (DECISION PENDING: {owner})\n\
         # {CAPTURED_ON}\n\
         {}\n--- stderr after the Client API line ---\n{}--- .runtime after exit ---\n{}\n",
        describe(&H1),
        outcome.render(),
        masks.apply(after_write),
        runtime_files_presence(&home.ws)
    );
    (outcome, baseline, pending)
}

/// Render an exit row; a row bound to a pending constant renders the constant's name when the
/// observed outcome equals it (so the decision lives in that constant only).
fn exit_row(observed: ExitOutcome, pending: Option<(&PendingExpectation, &str)>) -> String {
    match pending {
        Some((expected, name)) if observed == expected.outcome => format!("= {name}"),
        _ => observed.render(),
    }
}

/// A named worker thread of the start test (the name prefixes its panic message).
struct Worker<T> {
    what: String,
    handle: JoinHandle<T>,
}

impl<T: Send + 'static> Worker<T> {
    fn spawn(what: impl Into<String>, body: impl FnOnce() -> T + Send + 'static) -> Worker<T> {
        let what = what.into();
        let handle = std::thread::Builder::new()
            .name(what.clone())
            .spawn(body)
            .unwrap_or_else(|e| panic!("spawn worker {what}: {e}"));
        Worker { what, handle }
    }

    /// Wait for the worker. A panic is recorded in `failed`; its message was already printed,
    /// under the worker's thread name.
    fn join(self, failed: &mut Vec<String>) -> Option<T> {
        match self.handle.join() {
            Ok(value) => Some(value),
            Err(_) => {
                failed.push(self.what);
                None
            }
        }
    }
}

/// The start-run homes, in golden order (see [`start_plan`] for what each also records).
const START_HOMES: [&HomeSpec; 6] = [&H1, &H2, &H3, &H4, &H5, &H6];

#[test]
fn module_001_t111_ac30_start_stdout_stderr_files_and_exit_codes() {
    let runs: Vec<(&HomeSpec, Worker<StartRun>)> = START_HOMES
        .into_iter()
        .map(|spec: &'static HomeSpec| {
            let worker = Worker::spawn(format!("{} start run", spec.name), move || {
                start_run(spec, start_plan(spec))
            });
            (spec, worker)
        })
        .collect();
    let merged = Worker::spawn("H1 merged-stream run", || merged_run(&H1));
    let missing = Worker::spawn("missing-config run", missing_runtime_config_run);
    let malformed = Worker::spawn("malformed-config run", malformed_runtime_config_run);
    let readiness = Worker::spawn("readiness run", readiness_write_failure_run);

    // Join every worker before asserting anything. A worker left detached by an early panic here
    // would never run its `LiveRun::drop` if the binary then exits, and its `advance start`
    // would outlive the test.
    let mut failed = Vec::new();
    let runs: Vec<(&HomeSpec, Option<StartRun>)> = runs
        .into_iter()
        .map(|(spec, worker)| (spec, worker.join(&mut failed)))
        .collect();
    let merged = merged.join(&mut failed);
    let missing = missing.join(&mut failed);
    let malformed = malformed.join(&mut failed);
    let readiness = readiness.join(&mut failed);
    assert!(
        failed.is_empty(),
        "worker(s) panicked: {} (each panic message is printed above under the worker's name; \
         every worker was joined, so every `advance` process was reaped)",
        failed.join(", ")
    );
    let runs: Vec<(&HomeSpec, StartRun)> = runs
        .into_iter()
        .map(|(spec, run)| (spec, run.expect("joined without a panic")))
        .collect();
    let (merged_outcome, merged_golden) = merged.expect("joined without a panic");
    let (missing_outcome, missing_golden) = missing.expect("joined without a panic");
    let (malformed_outcome, malformed_golden) = malformed.expect("joined without a panic");
    let (readiness_outcome, readiness_before_write, readiness_after_write) =
        readiness.expect("joined without a panic");
    let h1 = &runs[0].1;
    let (lock_held_outcome, lock_held_golden) =
        h1.lock_held.as_ref().expect("H1 probes the held lock");

    // Exit codes first: a mismatch here explains a stream mismatch below.
    let mut exit_codes = format!(
        "# MODULE-001-T111 (1) exit status of `advance start` (`= NAME` rows are pinned by that constant)\n\
         # {CAPTURED_ON}\n\
         missing_runtime_config: {}\n\
         malformed_runtime_config: {}\n\
         runtime_lock_held: {}\n\
         readiness_write_failure: {}\n",
        exit_row(missing_outcome, None),
        exit_row(malformed_outcome, None),
        exit_row(*lock_held_outcome, None),
        exit_row(
            readiness_outcome,
            Some((&READINESS_WRITE_FAILURE, "READINESS_WRITE_FAILURE"))
        ),
    );
    for (spec, run) in &runs {
        let pending = (spec.label == H2.label)
            .then_some((&H2_SIGTERM_AFTER_READINESS, "H2_SIGTERM_AFTER_READINESS"));
        let _ = writeln!(
            exit_codes,
            "sigterm_after_readiness {}: {}",
            spec.label,
            exit_row(run.outcome, pending)
        );
    }
    let _ = writeln!(
        exit_codes,
        "sigterm_after_readiness {} (stderr joined to stdout's pipe): {}",
        H1.label,
        exit_row(merged_outcome, None)
    );

    let mut goldens = Goldens::new();
    goldens.check("exit_codes.golden", &exit_codes);
    goldens.check("exit.missing_runtime_config.golden", &missing_golden);
    goldens.check("exit.malformed_runtime_config.golden", &malformed_golden);
    goldens.check("exit.runtime_lock_held.golden", lock_held_golden);
    goldens.check(READINESS_BEFORE_WRITE_GOLDEN, &readiness_before_write);
    goldens.check(READINESS_AFTER_WRITE_GOLDEN, &readiness_after_write);
    for (spec, run) in &runs {
        goldens.check(&format!("start.{}.stdout.golden", spec.label), &run.stdout);
        goldens.check(&format!("start.{}.stderr.golden", spec.label), &run.stderr);
        if let Some(files) = &run.runtime_files {
            goldens.check(&format!("runtime_files.{}.golden", spec.label), files);
        }
        if let Some((name, after_shutdown)) = &run.after_shutdown {
            goldens.check(name, after_shutdown);
        }
    }
    goldens.check(&format!("start.{}.merged.golden", H1.label), &merged_golden);
    goldens.finish();
}

// ── Route probes over HTTP ────────────────────────────────────────────────────────────────

struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        header_value(&self.headers, name)
    }
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn decode_chunked(mut raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let line_end = raw
            .windows(2)
            .position(|w| w == b"\r\n")
            .expect("chunk size line");
        let size_text = std::str::from_utf8(&raw[..line_end]).expect("chunk size utf-8");
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .expect("chunk size hex");
        raw = &raw[line_end + 2..];
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&raw[..size]);
        raw = &raw[size + 2..];
    }
}

fn header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|w| w == b"\r\n\r\n")
}

/// The status and headers of a response head.
fn parse_head(what: &str, head: &[u8]) -> (u16, Vec<(String, String)>) {
    let head = String::from_utf8_lossy(head).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("{what}: bad status line in {head:?}"));
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    (status, headers)
}

fn connect(addr: &str) -> TcpStream {
    let stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(PROBE_IO_TIMEOUT))
        .expect("read timeout");
    stream
        .set_write_timeout(Some(PROBE_IO_TIMEOUT))
        .expect("write timeout");
    stream
}

fn http(
    addr: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> HttpResponse {
    let mut stream = connect(addr);
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (name, value) in headers {
        let _ = write!(req, "{name}: {value}\r\n");
    }
    match body {
        Some(body) => {
            let _ = write!(
                req,
                "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
        }
        None => req.push_str("\r\n"),
    }
    stream.write_all(req.as_bytes()).expect("write request");
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .unwrap_or_else(|e| panic!("{method} {path}: response read failed (probe hung?): {e}"));
    let split = header_end(&raw).unwrap_or_else(|| panic!("{method} {path}: no header/body split"));
    let (status, headers) = parse_head(&format!("{method} {path}"), &raw[..split]);
    let mut response = HttpResponse {
        status,
        headers,
        body: raw[split + 4..].to_vec(),
    };
    if response
        .header("transfer-encoding")
        .is_some_and(|v| v.eq_ignore_ascii_case("chunked"))
    {
        response.body = decode_chunked(&response.body);
    }
    response
}

// ── Canonical rendering and the probe value masks ─────────────────────────────────────────

/// Compact JSON with every object's keys sorted.
fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(&mut out, value);
    out
}

fn write_canonical(out: &mut String, value: &Value) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String((*key).clone()).to_string());
                out.push(':');
                write_canonical(out, &map[*key]);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(out, item);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// What a masked value must look like before it is masked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// 64 lowercase hex characters (a 256-bit session / CSRF token).
    Hex64,
    /// `sess_` + 32 lowercase hex characters.
    SessionId,
    /// Epoch milliseconds in the future; the placeholder keeps the TTL rounded to minutes.
    ExpiresAtMs,
    /// A JSON bool whose value depends on the OS (keychain support).
    OsBool,
    /// A lowercase hyphenated UUID (8-4-4-4-12 hex).
    Uuid,
    /// `run-` + a lowercase hyphenated UUID.
    RunId,
    /// A sealed token `<prefix>.<base64url body>`: the body is masked, the prefix (everything up
    /// to the last `.`, e.g. the codec version and key id) is kept in the placeholder.
    SealedToken,
    /// An RFC 3339 UTC timestamp at most an hour old; the placeholder keeps the offset spelling
    /// (`Z` or `+00:00`). The fraction digits are not kept: a formatter that trims trailing zeros
    /// would make them vary run to run.
    RecentRfc3339Utc,
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && parts
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(part, len)| is_lower_hex(part, len))
}

impl Shape {
    /// `Ok(suffix)` (appended to the placeholder) when `value` has this shape.
    fn check(self, value: &Value, now_ms: u64) -> Result<String, String> {
        match (self, value) {
            (Shape::Hex64, Value::String(s)) if is_lower_hex(s, 64) => Ok(String::new()),
            (Shape::SessionId, Value::String(s))
                if s.strip_prefix("sess_").is_some_and(|h| is_lower_hex(h, 32)) =>
            {
                Ok(String::new())
            }
            (Shape::ExpiresAtMs, Value::Number(n)) => {
                let at = n.as_u64().ok_or_else(|| format!("{n} is not a u64"))?;
                if at <= now_ms.saturating_sub(60_000) {
                    return Err(format!("{at} is not in the future of {now_ms}"));
                }
                let minutes = (at.saturating_sub(now_ms) + 30_000) / 60_000;
                Ok(format!(": now+{minutes}min"))
            }
            (Shape::OsBool, Value::Bool(_)) => Ok(String::new()),
            (Shape::Uuid, Value::String(s)) if is_uuid(s) => Ok(String::new()),
            (Shape::RunId, Value::String(s)) if s.strip_prefix("run-").is_some_and(is_uuid) => {
                Ok(String::new())
            }
            (Shape::SealedToken, Value::String(s)) => {
                let (prefix, body) = s
                    .rsplit_once('.')
                    .ok_or_else(|| format!("{s:?} has no `<prefix>.` part"))?;
                let base64url = |b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'_';
                if prefix.is_empty() || body.len() < 16 || !body.bytes().all(base64url) {
                    return Err(format!("{s:?} is not `<prefix>.<base64url body>`"));
                }
                Ok(format!(": {prefix}.…"))
            }
            (Shape::RecentRfc3339Utc, Value::String(s)) => {
                let parsed = chrono::DateTime::parse_from_rfc3339(s)
                    .map_err(|e| format!("{s:?} is not RFC 3339: {e}"))?;
                if parsed.offset().local_minus_utc() != 0 {
                    return Err(format!("{s:?} is not UTC"));
                }
                let at = parsed.timestamp_millis();
                let now = i64::try_from(now_ms).map_err(|e| e.to_string())?;
                if at > now + 60_000 || at < now - 3_600_000 {
                    return Err(format!("{s:?} is not within the last hour of {now_ms}"));
                }
                let offset = if s.ends_with('Z') {
                    "Z"
                } else if s.ends_with("+00:00") {
                    "+00:00"
                } else {
                    return Err(format!("{s:?} spells UTC neither `Z` nor `+00:00`"));
                };
                Ok(format!(" {offset}"))
            }
            _ => Err(format!("{value} is not {self:?}")),
        }
    }
}

/// One masked value of a probe answer.
struct ProbeMask {
    /// The placeholder: the value renders as the JSON string `"<NAME>"` (plus the shape's
    /// suffix).
    name: &'static str,
    shape: Shape,
    /// Every value masked under this name in one home's probe must be the same value (e.g. the
    /// root agent's id wherever it appears), so the golden still pins which fields agree.
    same_value: bool,
    /// Where it applies: (probe line key as in the golden, RFC 6901 pointer into `data`), on
    /// every home where that line answers `data`. A `*` segment matches every array element /
    /// object member (possibly none); a pointer without `*` must resolve.
    at: &'static [(&'static str, &'static str)],
}

const KEY_LOGIN: &str = "POST /client/session/login";
const KEY_LOGIN_CONSOLE_ORIGIN: &str =
    "POST /client/session/login (Origin: http://127.0.0.1:<PORT> = the bound console origin)";
const KEY_LOGIN_FOREIGN_ORIGIN: &str = "POST /client/session/login (Origin: http://evil.invalid)";
const KEY_CSRF: &str =
    "POST /client/agents (console Origin + its session + idempotency-key, no x-csrf-token)";
const KEY_REFRESH: &str = "POST /client/session/refresh";
const KEY_LOGOUT: &str = "POST /client/session/logout";
const KEY_WS_EVENTS_SEED: &str = "WS /client/events/stream seed";
const KEY_WS_DELTAS_SEED: &str = "WS /client/llm/deltas/stream seed";
const KEY_WS_DELTAS_SUBSCRIBE: &str = "WS /client/llm/deltas/stream subscribe";
const KEY_AGENTS: &str = "GET /client/agents";
const KEY_RUNS: &str = "GET /client/runs";
const KEY_RUNS_TREE: &str = "GET /client/runs/tree";
const KEY_EVENTS: &str = "GET /client/events";
const KEY_EVENTS_STREAM: &str = "GET /client/events/stream";
const KEY_SECRETS_MODE: &str = "GET /client/secrets/mode";

/// The subscribe frame sent on the delta WebSocket: a stream key plus a resume cursor that no
/// codec ever minted.
const DELTA_SUBSCRIBE_FRAME: &str =
    r#"{"stream_key":"golden-probe","from_cursor":"golden-probe-cursor"}"#;

/// The closed list of probe value masks. Nothing else in a probe answer is masked: every other
/// value (counts, statuses, names, the schema hash, the event stream id, …) is pinned as is.
const PROBE_MASKS: &[ProbeMask] = &[
    ProbeMask {
        name: "SESSION_TOKEN",
        shape: Shape::Hex64,
        same_value: false,
        at: &[
            (KEY_LOGIN, "/token"),
            (KEY_LOGIN_CONSOLE_ORIGIN, "/token"),
            (KEY_REFRESH, "/token"),
        ],
    },
    ProbeMask {
        name: "SESSION_ID",
        shape: Shape::SessionId,
        same_value: false,
        at: &[
            (KEY_LOGIN, "/session_id"),
            (KEY_LOGIN_CONSOLE_ORIGIN, "/session_id"),
            (KEY_REFRESH, "/session_id"),
        ],
    },
    ProbeMask {
        name: "SESSION_EXPIRES_AT",
        shape: Shape::ExpiresAtMs,
        same_value: false,
        at: &[
            (KEY_LOGIN, "/expires_at"),
            (KEY_LOGIN_CONSOLE_ORIGIN, "/expires_at"),
            (KEY_REFRESH, "/expires_at"),
        ],
    },
    ProbeMask {
        name: "CSRF_TOKEN",
        shape: Shape::Hex64,
        same_value: false,
        at: &[(KEY_LOGIN_CONSOLE_ORIGIN, "/csrf_token")],
    },
    ProbeMask {
        name: "OS_KEYCHAIN_SUPPORTED",
        shape: Shape::OsBool,
        same_value: false,
        at: &[(KEY_SECRETS_MODE, "/platform_supported")],
    },
    ProbeMask {
        name: "OS_KEYCHAIN_SYNCHRONIZABLE",
        shape: Shape::OsBool,
        same_value: false,
        at: &[(KEY_SECRETS_MODE, "/synchronizable")],
    },
    // The root agent's id, minted by `advance init`.
    ProbeMask {
        name: "ROOT_AGENT_ID",
        shape: Shape::Uuid,
        same_value: true,
        at: &[
            (KEY_AGENTS, "/agents/0/id"),
            (KEY_RUNS_TREE, "/nodes/*/id"),
            (KEY_RUNS, "/runs/*/controller_agent"),
            (KEY_RUNS, "/runs/*/task_id"),
            (KEY_EVENTS, "/events/*/agent_id"),
            (KEY_EVENTS_STREAM, "/events/*/agent_id"),
            (KEY_WS_EVENTS_SEED, "/events/*/agent_id"),
        ],
    },
    // The root run, created at boot when a driver component is deployed (H1..H4, with or without
    // `lifecycle`; absent on H5, which has no driver: `{"runs":[]}`).
    ProbeMask {
        name: "ROOT_RUN_ID",
        shape: Shape::RunId,
        same_value: true,
        at: &[
            (KEY_RUNS, "/runs/*/run_id"),
            (KEY_EVENTS, "/events/*/run_id"),
            (KEY_EVENTS_STREAM, "/events/*/run_id"),
            (KEY_WS_EVENTS_SEED, "/events/*/run_id"),
        ],
    },
    ProbeMask {
        name: "RUN_TIMESTAMP",
        shape: Shape::RecentRfc3339Utc,
        same_value: false,
        at: &[
            (KEY_RUNS, "/runs/*/created_at"),
            (KEY_RUNS, "/runs/*/updated_at"),
        ],
    },
    // Sealed event ids / resume cursors (fresh nonce per seal).
    ProbeMask {
        name: "EVENT_ID",
        shape: Shape::SealedToken,
        same_value: false,
        at: &[
            (KEY_EVENTS, "/events/*/event_id"),
            (KEY_EVENTS_STREAM, "/events/*/event_id"),
            (KEY_EVENTS_STREAM, "/cursor/last_event_id"),
            (KEY_WS_EVENTS_SEED, "/events/*/event_id"),
            (KEY_WS_EVENTS_SEED, "/cursor/last_event_id"),
        ],
    },
    ProbeMask {
        name: "EVENT_TIMESTAMP",
        shape: Shape::RecentRfc3339Utc,
        same_value: false,
        at: &[
            (KEY_EVENTS, "/events/*/timestamp"),
            (KEY_EVENTS_STREAM, "/events/*/timestamp"),
            (KEY_WS_EVENTS_SEED, "/events/*/timestamp"),
        ],
    },
    ProbeMask {
        name: "TRACE_ID",
        shape: Shape::Uuid,
        same_value: false,
        at: &[
            (KEY_EVENTS, "/events/*/trace_id"),
            (KEY_EVENTS_STREAM, "/events/*/trace_id"),
            (KEY_WS_EVENTS_SEED, "/events/*/trace_id"),
        ],
    },
];

fn pointer_segments(pointer: &str) -> Vec<String> {
    assert!(pointer.starts_with('/'), "JSON pointer {pointer:?}");
    pointer[1..]
        .split('/')
        .map(|s| s.replace("~1", "/").replace("~0", "~"))
        .collect()
}

/// Visit every value `segs` resolves to (`*` = every element / member); the number visited.
fn visit_pointer(value: &mut Value, segs: &[String], visit: &mut dyn FnMut(&mut Value)) -> usize {
    let Some((head, rest)) = segs.split_first() else {
        visit(value);
        return 1;
    };
    let mut hits = 0;
    match value {
        Value::Object(map) if head == "*" => {
            for v in map.values_mut() {
                hits += visit_pointer(v, rest, visit);
            }
        }
        Value::Object(map) => {
            if let Some(v) = map.get_mut(head) {
                hits += visit_pointer(v, rest, visit);
            }
        }
        Value::Array(items) if head == "*" => {
            for v in items.iter_mut() {
                hits += visit_pointer(v, rest, visit);
            }
        }
        Value::Array(items) => {
            if let Some(v) = head.parse::<usize>().ok().and_then(|i| items.get_mut(i)) {
                hits += visit_pointer(v, rest, visit);
            }
        }
        _ => {}
    }
    hits
}

/// Mask state of one home's probe: the value each `same_value` mask first masked, and the clock
/// (the wall clock at each answer; fixed in the harness self-checks).
struct MaskState {
    fixed_now_ms: Option<u64>,
    first_value: std::collections::BTreeMap<&'static str, Value>,
}

impl MaskState {
    fn new() -> MaskState {
        MaskState {
            fixed_now_ms: None,
            first_value: std::collections::BTreeMap::new(),
        }
    }

    fn now_ms(&self) -> u64 {
        self.fixed_now_ms.unwrap_or_else(now_ms)
    }
}

/// Apply the [`PROBE_MASKS`] of line `key` to `data`, checking each value's shape (and, for a
/// `same_value` mask, its equality with the first value masked under that name) first.
fn mask_data(key: &str, data: &mut Value, state: &mut MaskState) {
    for mask in PROBE_MASKS {
        for (_, pointer) in mask.at.iter().filter(|(line, _)| *line == key) {
            let mut failures = Vec::new();
            let now_ms = state.now_ms();
            let first_value = &mut state.first_value;
            let hits = visit_pointer(data, &pointer_segments(pointer), &mut |v| {
                if mask.same_value {
                    let first = first_value.entry(mask.name).or_insert_with(|| v.clone());
                    if first != v {
                        failures.push(format!(
                            "{v} differs from the first {} value {first}",
                            mask.name
                        ));
                        return;
                    }
                }
                match mask.shape.check(v, now_ms) {
                    Ok(suffix) => *v = Value::String(format!("<{}{suffix}>", mask.name)),
                    Err(why) => failures.push(why),
                }
            });
            assert!(
                failures.is_empty(),
                "probe mask {} at {pointer} on `{key}`: {failures:?}",
                mask.name
            );
            assert!(
                hits > 0 || pointer.contains('*'),
                "probe mask {} expects a value at {pointer} on `{key}`; data: {data}",
                mask.name
            );
        }
    }
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_millis(),
    )
    .expect("millis fit u64")
}

const ENVELOPE_KEYS: [&str; 5] = ["api_version", "request_id", "data", "error", "warnings"];

/// `data <canonical JSON>` or `error <code> "<message>"` (+ details), plus
/// `warnings=[<code> "<message>", …]` when there are any. The envelope's `api_version` must be
/// [`API_VERSION`]; its `request_id` is checked present and not rendered.
fn render_envelope_body(key: &str, body: &[u8], state: &mut MaskState) -> String {
    let envelope: Value = serde_json::from_slice(body).unwrap_or_else(|e| {
        panic!(
            "{key}: non-JSON body ({e}): {}",
            String::from_utf8_lossy(body)
        )
    });
    let object = envelope
        .as_object()
        .unwrap_or_else(|| panic!("{key}: envelope is not an object: {envelope}"));
    for name in object.keys() {
        assert!(
            ENVELOPE_KEYS.contains(&name.as_str()),
            "{key}: unknown envelope field {name:?} in {envelope}"
        );
    }
    assert_eq!(
        envelope.get("api_version").and_then(Value::as_str),
        Some(API_VERSION),
        "{key}: envelope api_version"
    );
    assert!(
        envelope
            .get("request_id")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.is_empty()),
        "{key}: envelope request_id"
    );
    let error = envelope.get("error").filter(|e| !e.is_null());
    let data = envelope.get("data").filter(|d| !d.is_null());
    let mut out = match (error, data) {
        (Some(error), None) => {
            let code = error["code"].as_str().expect("error code");
            let message = error["message"].as_str().expect("error message");
            let mut out = format!("error {code} {message:?}");
            if let Some(details) = error.get("details").filter(|d| !d.is_null()) {
                let _ = write!(out, " details={}", canonical_json(details));
            }
            out
        }
        (None, Some(data)) => {
            let mut data = data.clone();
            mask_data(key, &mut data, state);
            format!("data {}", canonical_json(&data))
        }
        (None, None) => "data null".to_string(),
        (Some(_), Some(_)) => panic!("{key}: envelope with both data and error: {envelope}"),
    };
    if let Some(warnings) = envelope.get("warnings").and_then(Value::as_array) {
        if !warnings.is_empty() {
            let rendered: Vec<String> = warnings
                .iter()
                .map(|w| {
                    format!(
                        "{} {:?}",
                        w["code"].as_str().expect("warning code"),
                        w["message"].as_str().expect("warning message")
                    )
                })
                .collect();
            let _ = write!(out, " warnings=[{}]", rendered.join(", "));
        }
    }
    out
}

fn render_envelope(key: &str, response: &HttpResponse, state: &mut MaskState) -> String {
    format!(
        "{} {}",
        response.status,
        render_envelope_body(key, &response.body, state)
    )
}

/// A response that is not a Client API envelope: status, content type and the body text.
fn render_raw(response: &HttpResponse) -> String {
    format!(
        "{} content-type={} body={:?}",
        response.status,
        response.header("content-type").unwrap_or("<none>"),
        String::from_utf8_lossy(&response.body)
    )
}

/// Every response header but `date`, in wire order.
fn render_headers(headers: &[(String, String)]) -> String {
    headers
        .iter()
        .filter(|(k, _)| !k.eq_ignore_ascii_case("date"))
        .map(|(k, v)| format!("{}: {v}", k.to_ascii_lowercase()))
        .collect::<Vec<_>>()
        .join(" | ")
}

/// The concrete request path of a route: every `{name}` parameter becomes [`PROBE_PARAM`].
fn concrete_path(template: &str) -> String {
    let mut out = String::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let close = open
            + rest[open..]
                .find('}')
                .unwrap_or_else(|| panic!("unclosed parameter in {template}"));
        out.push_str(PROBE_PARAM);
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    out
}

// ── WebSocket probes ──────────────────────────────────────────────────────────────────────

/// The RFC 6455 sample key and its accept value.
const WS_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const WS_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

enum WsOpen {
    Upgraded {
        headers: Vec<(String, String)>,
        socket: Box<WebSocket<TcpStream>>,
    },
    Refused(HttpResponse),
}

/// Open a Client API WebSocket the way the console does: the client protocol plus the bearer
/// token as a second, unselected `advance.bearer.<token>` protocol (and the API version header).
fn ws_open(addr: &str, path: &str, token: &str) -> WsOpen {
    let mut stream = connect(addr);
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {WS_KEY}\r\n\
         Sec-WebSocket-Protocol: {CLIENT_WS_PROTOCOL}, advance.bearer.{token}\r\n\
         x-advance-api-version: {API_VERSION}\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .expect("write WebSocket handshake");
    let mut buf = Vec::new();
    let split = loop {
        if let Some(at) = header_end(&buf) {
            break at;
        }
        let mut chunk = [0u8; 4096];
        let n = stream
            .read(&mut chunk)
            .unwrap_or_else(|e| panic!("WS {path}: handshake read failed (probe hung?): {e}"));
        assert!(n > 0, "WS {path}: connection closed during the handshake");
        buf.extend_from_slice(&chunk[..n]);
    };
    let (status, headers) = parse_head(&format!("WS {path}"), &buf[..split]);
    let mut rest = buf[split + 4..].to_vec();
    if status == 101 {
        assert_eq!(
            header_value(&headers, "sec-websocket-accept"),
            Some(WS_ACCEPT),
            "WS {path}: Sec-WebSocket-Accept"
        );
        let socket = WebSocket::from_partially_read(stream, rest, Role::Client, None);
        return WsOpen::Upgraded {
            headers,
            socket: Box::new(socket),
        };
    }
    let len: usize = header_value(&headers, "content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("WS {path}: refused without content-length: {headers:?}"));
    while rest.len() < len {
        let mut chunk = [0u8; 4096];
        let n = stream
            .read(&mut chunk)
            .unwrap_or_else(|e| panic!("WS {path}: refusal body read failed: {e}"));
        assert!(
            n > 0,
            "WS {path}: connection closed inside the refusal body"
        );
        rest.extend_from_slice(&chunk[..n]);
    }
    rest.truncate(len);
    WsOpen::Refused(HttpResponse {
        status,
        headers,
        body: rest,
    })
}

/// The next text frame (pings / pongs are skipped; tungstenite answers pings itself).
fn ws_next_text(socket: &mut WebSocket<TcpStream>, what: &str) -> String {
    loop {
        match socket.read() {
            Ok(Message::Text(text)) => return text.as_str().to_string(),
            Ok(Message::Ping(_) | Message::Pong(_)) => {}
            Ok(other) => panic!("{what}: unexpected frame {other:?}"),
            Err(e) => panic!("{what}: read failed (probe hung or socket closed?): {e}"),
        }
    }
}

fn ws_close(mut socket: Box<WebSocket<TcpStream>>) {
    let _ = socket.close(None);
    for _ in 0..64 {
        if socket.read().is_err() {
            break;
        }
    }
}

// ── The probe of one home ─────────────────────────────────────────────────────────────────

/// A native client (loopback, no browser `Origin`, the API version header, a bearer session)
/// that renders each probe as one golden line.
struct Prober {
    addr: String,
    token: Option<String>,
    next_key: u32,
    masks: Masks,
    mask_state: MaskState,
    /// Every line key written so far: a key names exactly one line of the golden (the D5
    /// overlay addresses lines by key).
    keys: BTreeSet<String>,
    out: String,
}

impl Prober {
    fn section(&mut self, title: &str) {
        let _ = writeln!(self.out, "== {title}");
    }

    fn line(&mut self, key: &str, outcome: &str) {
        assert!(
            self.keys.insert(key.to_string()),
            "probe line key {key:?} written twice"
        );
        let line = self.masks.apply(&format!("{key} -> {outcome}"));
        let _ = writeln!(self.out, "{line}");
    }

    /// One line rendering an HTTP envelope answer.
    fn envelope_line(&mut self, key: &str, response: &HttpResponse) {
        let outcome = render_envelope(key, response, &mut self.mask_state);
        self.line(key, &outcome);
    }

    /// An envelope carried by a WebSocket frame (no HTTP status).
    fn frame(&mut self, key: &str, body: &str) -> String {
        render_envelope_body(key, body.as_bytes(), &mut self.mask_state)
    }

    fn native_headers(&mut self, mutation: bool) -> Vec<(&'static str, String)> {
        let mut headers = vec![("x-advance-api-version", API_VERSION.to_string())];
        if let Some(token) = &self.token {
            headers.push(("authorization", format!("Bearer {token}")));
        }
        if mutation {
            self.next_key += 1;
            headers.push((
                "idempotency-key",
                format!("d5-golden-probe-{}", self.next_key),
            ));
        }
        headers
    }

    fn call(&mut self, method: &str, path: &str, mutation: bool) -> HttpResponse {
        let headers = self.native_headers(mutation);
        let borrowed: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let body = (method == "POST").then_some("{}");
        http(&self.addr, method, path, &borrowed, body)
    }

    /// `POST /client/session/login` with `{"platform":"mac"}`: credential-less on loopback.
    fn login(&self, origin: Option<&str>) -> HttpResponse {
        let mut headers = vec![("x-advance-api-version", API_VERSION)];
        if let Some(origin) = origin {
            headers.push(("origin", origin));
        }
        http(
            &self.addr,
            "POST",
            "/client/session/login",
            &headers,
            Some(r#"{"platform":"mac"}"#),
        )
    }
}

fn session_token(response: &HttpResponse) -> String {
    let envelope: Value = serde_json::from_slice(&response.body).expect("session envelope");
    envelope["data"]["token"]
        .as_str()
        .unwrap_or_else(|| panic!("session token in {envelope}"))
        .to_string()
}

/// The discovery file's `client_api_base` (`http://127.0.0.1:<port>`) → `127.0.0.1:<port>`.
fn discovered_client_api_addr(ws: &Path) -> String {
    let body = std::fs::read_to_string(ws.join(".runtime/client-api")).expect("read client-api");
    field(&body, "client_api_base")
        .trim_matches('"')
        .strip_prefix("http://")
        .expect("http base")
        .to_string()
}

fn probe_home(spec: &HomeSpec) -> String {
    let home = make_home(spec);
    let mut run = LiveRun::start(home.start_command(), Wiring::Separate);
    run.wait_until_settled();
    let addr = discovered_client_api_addr(&home.ws);
    let mut p = Prober {
        addr: addr.clone(),
        token: None,
        next_key: 0,
        masks: home.masks(),
        mask_state: MaskState::new(),
        keys: BTreeSet::new(),
        out: format!(
            "# MODULE-001-T111 (2) route probes through `advance start` on {}\n\
             # {CAPTURED_ON}\n\
             # native client: loopback, no Origin, x-advance-api-version: {API_VERSION}, bearer session;\n\
             # GET with no query; POST with body {{}} (+ idempotency-key for mutations); path params = {PROBE_PARAM:?}\n\
             # <KEY> -> <status> data <canonical JSON of data, keys sorted> [warnings=[<code> \"<message>\", …]] | <status> error <code> \"<message>\" [details=…]\n\
             # masked values render as \"<NAME>\" (PROBE_MASKS in the test); <ROOT> = the temp root; 127.0.0.1:<PORT> = a loopback port\n",
            describe(spec)
        ),
    };

    // Sessions: the native session first, then the browser paths.
    p.section("session");
    let login = p.login(None);
    p.envelope_line(KEY_LOGIN, &login);
    p.token = Some(session_token(&login));
    let console_origin = format!("http://{addr}");
    let console = p.login(Some(console_origin.as_str()));
    p.envelope_line(KEY_LOGIN_CONSOLE_ORIGIN, &console);
    let foreign = p.login(Some("http://evil.invalid"));
    p.envelope_line(KEY_LOGIN_FOREIGN_ORIGIN, &foreign);
    if console.status == 200 {
        let console_token = format!("Bearer {}", session_token(&console));
        let csrf = http(
            &addr,
            "POST",
            "/client/agents",
            &[
                ("x-advance-api-version", API_VERSION),
                ("origin", console_origin.as_str()),
                ("authorization", console_token.as_str()),
                ("idempotency-key", "d5-golden-probe-csrf"),
            ],
            Some("{}"),
        );
        p.envelope_line(KEY_CSRF, &csrf);
    } else {
        p.line(KEY_CSRF, "not sent: the console-Origin login was refused");
    }

    // Reads first, then POST reads, then mutations: nothing probed can change what a later probe
    // sees (every mutation carries an empty body and/or a dummy id and is refused).
    let table = probe_route_table();
    let phases: [(&str, fn(&RouteTableEntry) -> bool); 3] = [
        ("GET routes", |e| e.method == Method::Get),
        ("POST reads", |e| e.method == Method::Post && !e.is_mutation),
        ("POST mutations", |e| {
            e.method == Method::Post && e.is_mutation
        }),
    ];
    let mut probed = 0usize;
    for (title, in_phase) in &phases {
        p.section(title);
        for entry in table.iter().filter(|e| in_phase(e)) {
            let method = method_name(entry.method);
            let key = format!("{method} {}", entry.path);
            let response = p.call(method, &concrete_path(&entry.path), entry.is_mutation);
            p.envelope_line(&key, &response);
            probed += 1;
        }
    }
    assert_eq!(
        probed,
        table.len(),
        "every route of the route table is probed"
    );

    p.section("router (not in the route table)");
    for (method, path) in [
        ("GET", "/client/golden-probe-unknown"),
        ("POST", "/client/health"),
    ] {
        let key = format!("{method} {path}");
        let response = p.call(method, path, false);
        p.envelope_line(&key, &response);
    }
    for (method, path) in [("GET", "/golden-probe-unknown"), ("POST", "/msg")] {
        let response = http(&addr, method, path, &[], (method == "POST").then_some("{}"));
        p.line(
            &format!("{method} {path} (Client API address)"),
            &render_raw(&response),
        );
    }

    p.section("Web Console assets");
    for asset in ["/", "/index.html", "/app.js", "/styles.css"] {
        let response = http(&addr, "GET", asset, &[], None);
        p.line(
            &format!("GET {asset}"),
            &format!(
                "{} content-type={} len={} sha256={}",
                response.status,
                response.header("content-type").unwrap_or("<none>"),
                response.body.len(),
                sha256_hex(&response.body)
            ),
        );
    }

    p.section("response headers (all but date, in wire order)");
    let health = p.call("GET", "/client/health", false);
    p.line(
        "GET /client/health headers",
        &render_headers(&health.headers),
    );
    let unknown = p.call("GET", "/client/golden-probe-unknown", false);
    p.line(
        "GET /client/golden-probe-unknown headers",
        &render_headers(&unknown.headers),
    );
    let index = http(&addr, "GET", "/", &[], None);
    p.line("GET / headers", &render_headers(&index.headers));

    p.section(&format!(
        "WebSocket (protocols: {CLIENT_WS_PROTOCOL}, advance.bearer.<session token>; delta subscribe frame {DELTA_SUBSCRIBE_FRAME})"
    ));
    let token = p.token.clone().expect("native session token");
    match ws_open(&addr, "/client/events/stream", &token) {
        WsOpen::Upgraded {
            headers,
            mut socket,
        } => {
            let seed = ws_next_text(&mut socket, KEY_WS_EVENTS_SEED);
            let seed = p.frame(KEY_WS_EVENTS_SEED, &seed);
            p.line(
                KEY_WS_EVENTS_SEED,
                &format!(
                    "101 protocol={} {seed}",
                    header_value(&headers, "sec-websocket-protocol").unwrap_or("<none>"),
                ),
            );
            ws_close(socket);
        }
        WsOpen::Refused(response) => {
            let refusal = render_envelope(KEY_WS_EVENTS_SEED, &response, &mut p.mask_state);
            p.line(KEY_WS_EVENTS_SEED, &format!("{refusal} (no upgrade)"));
        }
    }
    match ws_open(&addr, "/client/llm/deltas/stream", &token) {
        WsOpen::Upgraded {
            headers,
            mut socket,
        } => {
            let seed = ws_next_text(&mut socket, KEY_WS_DELTAS_SEED);
            let seed = p.frame(KEY_WS_DELTAS_SEED, &seed);
            p.line(
                KEY_WS_DELTAS_SEED,
                &format!(
                    "101 protocol={} {seed}",
                    header_value(&headers, "sec-websocket-protocol").unwrap_or("<none>"),
                ),
            );
            p.line(
                &format!("{KEY_WS_DELTAS_SEED} handshake headers"),
                &render_headers(&headers),
            );
            socket
                .send(Message::text(DELTA_SUBSCRIBE_FRAME))
                .expect("send the delta subscribe frame");
            let reply = ws_next_text(&mut socket, KEY_WS_DELTAS_SUBSCRIBE);
            let reply = p.frame(KEY_WS_DELTAS_SUBSCRIBE, &reply);
            p.line(KEY_WS_DELTAS_SUBSCRIBE, &reply);
            ws_close(socket);
        }
        WsOpen::Refused(response) => {
            let refusal = render_envelope(KEY_WS_DELTAS_SEED, &response, &mut p.mask_state);
            p.line(KEY_WS_DELTAS_SEED, &format!("{refusal} (no upgrade)"));
            p.line(KEY_WS_DELTAS_SUBSCRIBE, "not sent: no upgrade");
        }
    }

    p.section("POST /msg listener (the address on stdout's `advance: msg listener on` line)");
    let (_, _, streams) = run.snapshot();
    let msg_addr = streams.stdout.lines().find_map(|l| {
        l.strip_prefix("advance: msg listener on http://")
            .and_then(|rest| rest.strip_suffix("/msg"))
            .map(str::to_string)
    });
    match msg_addr {
        None => p.line(
            "POST /msg",
            "no msg listener (no `advance: msg listener on` line)",
        ),
        Some(msg_addr) => {
            let missing_payload = http(&msg_addr, "POST", "/msg", &[], Some("{}"));
            p.line("POST /msg body {}", &render_raw(&missing_payload));
            let other_agent = r#"{"agent_id":"agent:golden-probe-other","payload":"golden"}"#;
            let response = http(&msg_addr, "POST", "/msg", &[], Some(other_agent));
            p.line(
                &format!("POST /msg body {other_agent}"),
                &render_raw(&response),
            );
            let response = http(&msg_addr, "GET", "/msg", &[], None);
            p.line("GET /msg", &render_raw(&response));
        }
    }

    // Session-changing operations last: refresh rotates the token, logout revokes the session.
    p.section("session (last)");
    let refresh = p.call("POST", "/client/session/refresh", false);
    p.envelope_line(KEY_REFRESH, &refresh);
    if refresh.status == 200 {
        p.token = Some(session_token(&refresh));
    }
    let logout = p.call("POST", "/client/session/logout", false);
    p.envelope_line(KEY_LOGOUT, &logout);
    drop(run);
    p.out
}

fn route_probe_golden(spec: &HomeSpec) {
    let actual = probe_home(spec);
    let name = format!("route_probe.{}.golden", spec.label);
    let changes = expand_matrix(D5_CHANGE_MATRIX);
    assert!(
        !update_mode() || changes.is_empty(),
        "route-probe goldens are captured once and never re-captured once the D5 overlay is in \
         use; change D5_CHANGE_MATRIX instead"
    );
    if !update_mode() {
        // The ADR rows are enforced on the path that applies the overlay, so a filtered run
        // (`cargo test … route_probe`) checks them too. (Skipped in update mode, where the
        // overlay is empty and the other homes' goldens are being rewritten.)
        check_overlay_against_adr(&changes);
    }
    let mut goldens = Goldens::new();
    goldens.check_with_overlay(&name, &actual, |golden| {
        apply_overlay(&changes, spec.label, golden)
    });
    goldens.finish();
}

#[test]
fn module_001_t111_ac30_route_probe_h1_fs_llm() {
    route_probe_golden(&H1);
}

#[test]
fn module_001_t111_ac30_route_probe_h2_all_capabilities() {
    route_probe_golden(&H2);
}

#[test]
fn module_001_t111_ac30_route_probe_h3_fs_llm_lifecycle() {
    route_probe_golden(&H3);
}

#[test]
fn module_001_t111_ac30_route_probe_h4_fs_llm_grant() {
    route_probe_golden(&H4);
}

#[test]
fn module_001_t111_ac30_route_probe_h5_fs_llm_tools_no_driver() {
    route_probe_golden(&H5);
}

// ── Self-checks of the harness ────────────────────────────────────────────────────────────

/// Every golden the two test binaries produce.
fn expected_golden_names() -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for spec in [&H1, &H2] {
        names.insert(format!("route_table.{}.golden", spec.label));
        names.insert(format!("runtime_files.{}.golden", spec.label));
    }
    for spec in PROBE_HOMES {
        names.insert(format!("route_probe.{}.golden", spec.label));
    }
    for spec in START_HOMES {
        names.insert(format!("start.{}.stdout.golden", spec.label));
        names.insert(format!("start.{}.stderr.golden", spec.label));
        if let Some(golden) = start_plan(spec).after_shutdown_golden {
            names.insert(golden.to_string());
        }
    }
    names.insert(format!("start.{}.merged.golden", H1.label));
    for name in [
        "exit_codes.golden",
        "exit.missing_runtime_config.golden",
        "exit.malformed_runtime_config.golden",
        "exit.runtime_lock_held.golden",
        READINESS_BEFORE_WRITE_GOLDEN,
        READINESS_AFTER_WRITE_GOLDEN,
    ] {
        names.insert(name.to_string());
    }
    names
}

#[test]
fn module_001_t111_ac30_golden_pins_cover_every_golden() {
    let on_disk: BTreeSet<String> = std::fs::read_dir(GOLDEN_DIR)
        .expect("read golden dir")
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .into_string()
                .expect("utf-8 name")
        })
        .collect();
    let expected = expected_golden_names();
    assert_eq!(
        on_disk, expected,
        "the golden directory holds exactly the goldens the tests produce"
    );
    let mut pinned = BTreeSet::new();
    for (name, _) in BASELINE_GOLDEN_SHA256 {
        assert!(pinned.insert(name.to_string()), "{name} is pinned twice");
    }
    for (owner, pending) in PENDING_EXPECTATIONS {
        // One entry per outcome, an entry for the decided outcome, and every entry pins the
        // same goldens (only the decision-dependent part of the scenario).
        let mut outcomes = Vec::new();
        for (outcome, _) in pending.pins_by_outcome {
            assert!(
                !outcomes.contains(outcome),
                "{owner}: outcome {outcome:?} has two pin entries (a pending golden gets a new \
                 entry only for a new outcome)"
            );
            outcomes.push(*outcome);
        }
        let active = pending.active_pins().unwrap_or_else(|| {
            panic!(
                "{owner}: no pin entry for its decided outcome {:?}",
                pending.outcome
            )
        });
        let active_names: BTreeSet<&str> = active.iter().map(|(name, _)| *name).collect();
        for (outcome, pins) in pending.pins_by_outcome {
            let names: BTreeSet<&str> = pins.iter().map(|(name, _)| *name).collect();
            assert_eq!(
                names, active_names,
                "{owner}: the {outcome:?} entry pins other goldens than the decided one"
            );
        }
        for name in active_names {
            assert!(
                pinned.insert(name.to_string()),
                "{name} is pinned twice (also by {owner})"
            );
        }
    }
    assert_eq!(pinned, expected, "every golden has exactly one sha256 pin");
    // The decision-independent part of each pending scenario is a baseline golden.
    for baseline in [
        READINESS_BEFORE_WRITE_GOLDEN,
        "start.h2_all_capabilities.stdout.golden",
        "start.h2_all_capabilities.stderr.golden",
        "runtime_files.h2_all_capabilities.golden",
    ] {
        assert!(
            BASELINE_GOLDEN_SHA256
                .iter()
                .any(|(name, _)| *name == baseline),
            "{baseline} is pinned in BASELINE_GOLDEN_SHA256"
        );
    }
    for name in &expected {
        read_pinned_golden(name);
        assert!(golden_path(name).is_file());
    }
}

#[test]
fn module_001_t111_ac30_detects_a_captured_on_only_change() {
    // Every golden header is `# {CAPTURED_ON}`; the header of an older base starts the same way.
    assert!(CAPTURED_ON.starts_with("captured on "));
    let header = format!("# {CAPTURED_ON}");
    let older = "# captured on an older base";
    let pinned = format!("# title\n{older}\nline 1\nline 2\n");
    // Only the header changed: the in-place re-pin of a whole-tree re-capture.
    assert!(only_captured_on_line_changed(
        pinned.as_bytes(),
        &format!("# title\n{header}\nline 1\nline 2\n")
    ));
    for recaptured in [
        // The header and a data line changed.
        format!("# title\n{header}\nline 1\nline X\n"),
        // The header changed and a line was added.
        format!("# title\n{header}\nline 1\nline 2\nline 3\n"),
        // The new header in place of a data line, the old header kept.
        format!("# title\n{older}\n{header}\nline 2\n"),
        // No current header.
        format!("# title\n{older}\nline 1\nline X\n"),
    ] {
        assert!(
            !only_captured_on_line_changed(pinned.as_bytes(), &recaptured),
            "not a header-only change: {recaptured:?}"
        );
    }
    // Pinned under the current header already: nothing, or a data line, changed.
    let current = format!("# title\n{header}\nline 1\n");
    assert!(!only_captured_on_line_changed(current.as_bytes(), &current));
    assert!(!only_captured_on_line_changed(
        current.as_bytes(),
        &format!("# title\n{header}\nline X\n")
    ));
    assert!(!only_captured_on_line_changed(&[0xff, 0xfe], &header));
}

#[test]
fn module_001_t111_ac30_masks_only_volatile_tokens() {
    let masks = Masks {
        paths: vec![
            ("/private/var/x/.tmpAB".to_string(), "<ROOT>".to_string()),
            ("/var/x/.tmpAB".to_string(), "<ROOT>".to_string()),
        ],
    };
    assert_eq!(
        masks.apply("ready (workspace=\"/private/var/x/.tmpAB/ws\") /var/x/.tmpAB/home\n"),
        "ready (workspace=\"<ROOT>/ws\") <ROOT>/home\n"
    );
    assert_eq!(
        masks.apply("http://127.0.0.1:60986/msg 127.0.0.1: 10.0.0.1:80\n"),
        "http://127.0.0.1:<PORT>/msg 127.0.0.1: 10.0.0.1:80\n"
    );
    assert_eq!(
        masks.apply(
            "\nthread 'main' (46930464) panicked at library/std/src/io/stdio.rs:1165:9:\nfailed printing to stdout: Broken pipe (os error 32)\n"
        ),
        "\nthread 'main' (<TID>) panicked at <PANIC_LOCATION>:\nfailed printing to stdout: Broken pipe (os error 32)\n"
    );
    assert_eq!(
        masks.apply("thread 'main' panicked at src/x.rs:1:2:\n"),
        "thread 'main' (<TID>) panicked at <PANIC_LOCATION>:\n"
    );
    // Not a panic header: kept byte for byte.
    assert_eq!(
        masks.apply("thread 'main' said hello\n"),
        "thread 'main' said hello\n"
    );
    assert_eq!(
        replace_field("pid: 1\nversion: \"0.1.0\"", "pid", "<PID>"),
        "pid: <PID>\nversion: \"0.1.0\""
    );
    // The package version is never written into a golden.
    let refused = std::panic::catch_unwind(|| {
        let mut goldens = Goldens::new();
        goldens.check("exit_codes.golden", &format!("version {PACKAGE_VERSION}\n"));
        goldens.finish();
    });
    assert!(refused.is_err(), "a golden with the package version fails");
}

#[test]
fn module_001_t111_ac30_harness_splits_lock_reads_and_overload() {
    // The split of a pending scenario: after the first matching whole line at or after `from`.
    let stdout = "advance: runtime ready\nadvance: shutting down\nadvance: later\n";
    let boot = "advance: runtime ready\n";
    assert_eq!(
        split_after_line(stdout, boot.len(), |l| l == SHUTTING_DOWN_LINE),
        (
            "advance: runtime ready\nadvance: shutting down\n",
            "advance: later\n"
        )
    );
    // Not after `from`, or not a whole line: no split, everything stays on the baseline side.
    assert_eq!(
        split_after_line(stdout, stdout.len(), |l| l == SHUTTING_DOWN_LINE),
        (stdout, "")
    );
    assert_eq!(
        split_after_line("advance: shutting down", 0, |l| l == SHUTTING_DOWN_LINE),
        ("advance: shutting down", "")
    );
    let stderr =
        "advance: Client API and Web Console listening at http://127.0.0.1:1\n\nthread 'main'\n";
    assert_eq!(
        split_after_line(stderr, 0, |l| l.starts_with(CLIENT_API_LINE_PREFIX)),
        (
            "advance: Client API and Web Console listening at http://127.0.0.1:1\n",
            "\nthread 'main'\n"
        )
    );
    // A `runtime.lock` read in the middle of a heartbeat rewrite is incomplete.
    let lock = "pid: 42\nplatform_uid: \"macos:42:x\"\nstarted_at: \"a\"\nheartbeat_at: \"b\"\nworkspace_root: \"/w\"\nversion: \"0.1.0\"";
    assert!(runtime_lock_complete(lock));
    assert!(!runtime_lock_complete(""));
    assert!(!runtime_lock_complete(&lock[..lock.len() - 3]));
    assert!(!runtime_lock_complete(
        &lock[..lock.find("version").unwrap()]
    ));
    assert!(!runtime_lock_complete(&lock.replace("pid: 42", "pid: ")));
    // A boot that hit the registry-open timeout is reported as an overloaded environment.
    let streams = |stderr: &str| Streams {
        stdout: String::new(),
        stderr: stderr.to_string(),
        merged: String::new(),
    };
    assert_boot_not_starved(&streams(
        "advance: Client API and Web Console listening at x\n",
    ));
    let starved = std::panic::catch_unwind(|| {
        assert_boot_not_starved(&streams(&format!("{REGISTRY_OPEN_TIMED_OUT} after 5s\n")))
    });
    let message = starved.expect_err("a starved boot fails");
    let message = message
        .downcast_ref::<String>()
        .expect("formatted panic message");
    assert!(message.starts_with("ENVIRONMENT OVERLOADED"), "{message}");
}

#[test]
fn module_001_t111_ac30_probe_masks_are_closed_and_checked() {
    // Names are unique; every line is a probe line key; pointers are JSON pointers; no (line,
    // pointer) is masked twice.
    let mut names = BTreeSet::new();
    let mut places = BTreeSet::new();
    let route_keys: BTreeSet<String> = probe_route_table()
        .iter()
        .map(|e| format!("{} {}", method_name(e.method), e.path))
        .collect();
    let special = [
        KEY_LOGIN,
        KEY_LOGIN_CONSOLE_ORIGIN,
        KEY_REFRESH,
        KEY_WS_EVENTS_SEED,
        KEY_WS_DELTAS_SEED,
    ];
    for mask in PROBE_MASKS {
        assert!(names.insert(mask.name), "mask {} twice", mask.name);
        assert!(
            mask.name
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b == b'_'),
            "mask name {}",
            mask.name
        );
        assert!(!mask.at.is_empty(), "mask {} applies nowhere", mask.name);
        for (line, pointer) in mask.at {
            assert!(pointer.starts_with('/'), "pointer {pointer}");
            assert!(
                route_keys.contains(*line) || special.contains(line),
                "mask {} names {line:?}, which is no probe line",
                mask.name
            );
            assert!(
                places.insert((*line, *pointer)),
                "{line} {pointer} is masked twice"
            );
        }
    }
    // Shapes are checked before masking.
    let now = now_ms();
    let token = "ab".repeat(32);
    assert!(Shape::Hex64
        .check(&Value::from(token.as_str()), now)
        .is_ok());
    assert!(Shape::Hex64
        .check(&Value::from("AB".repeat(32)), now)
        .is_err());
    assert!(Shape::Hex64.check(&Value::from("ab"), now).is_err());
    assert!(Shape::SessionId
        .check(&Value::from(format!("sess_{}", "0f".repeat(16))), now)
        .is_ok());
    assert!(Shape::SessionId.check(&Value::from("sess_x"), now).is_err());
    assert_eq!(
        Shape::ExpiresAtMs.check(&Value::from(now + 480 * 60_000 - 2_000), now),
        Ok(": now+480min".to_string())
    );
    assert!(Shape::ExpiresAtMs
        .check(&Value::from(now - 600_000), now)
        .is_err());
    assert!(Shape::OsBool.check(&Value::from(true), now).is_ok());
    assert!(Shape::OsBool.check(&Value::from("true"), now).is_err());
    let uuid = "7150a00c-f8dc-4fd4-a2ed-370f675ee57f";
    assert!(Shape::Uuid.check(&Value::from(uuid), now).is_ok());
    assert!(Shape::Uuid
        .check(&Value::from(uuid.to_uppercase()), now)
        .is_err());
    assert!(Shape::Uuid.check(&Value::from("root"), now).is_err());
    assert!(Shape::RunId
        .check(&Value::from(format!("run-{uuid}")), now)
        .is_ok());
    assert!(Shape::RunId.check(&Value::from(uuid), now).is_err());
    assert_eq!(
        Shape::SealedToken.check(
            &Value::from("c1.local-k1.AAABoQTniYJDNkXUhtNHGK9o-igSIv74zKt8AYyE"),
            now
        ),
        Ok(": c1.local-k1.…".to_string())
    );
    assert!(Shape::SealedToken
        .check(&Value::from("no-prefix-AAABoQTniYJDNkXUhtNHGK9o"), now)
        .is_err());
    assert!(Shape::SealedToken
        .check(&Value::from("c1.local-k1.short"), now)
        .is_err());
    let recent = chrono::DateTime::from_timestamp_millis(i64::try_from(now).unwrap() - 5_000)
        .expect("timestamp");
    assert_eq!(
        Shape::RecentRfc3339Utc.check(
            &Value::from(recent.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)),
            now
        ),
        Ok(" Z".to_string())
    );
    assert_eq!(
        Shape::RecentRfc3339Utc.check(&Value::from(recent.to_rfc3339()), now),
        Ok(" +00:00".to_string())
    );
    assert!(Shape::RecentRfc3339Utc
        .check(&Value::from("2020-01-01T00:00:00Z"), now)
        .is_err());
    assert!(Shape::RecentRfc3339Utc
        .check(
            &Value::from(recent.to_rfc3339().replace("+00:00", "+01:00")),
            now
        )
        .is_err());
    let fixed = || MaskState {
        fixed_now_ms: Some(now),
        first_value: std::collections::BTreeMap::new(),
    };
    // A pointer that does not resolve fails; a shape mismatch fails; masking keeps the rest.
    let mut data = serde_json::json!({"token": token, "session_id": "sess_x", "platform": "mac"});
    let mismatch = std::panic::catch_unwind(move || mask_data(KEY_LOGIN, &mut data, &mut fixed()));
    assert!(mismatch.is_err(), "a mis-shaped session id fails the mask");
    let mut data =
        serde_json::json!({"platform_supported": true, "synchronizable": false, "mode": "file"});
    mask_data(KEY_SECRETS_MODE, &mut data, &mut fixed());
    assert_eq!(
        canonical_json(&data),
        r#"{"mode":"file","platform_supported":"<OS_KEYCHAIN_SUPPORTED>","synchronizable":"<OS_KEYCHAIN_SYNCHRONIZABLE>"}"#
    );
    let mut missing = serde_json::json!({"mode": "file"});
    let absent =
        std::panic::catch_unwind(move || mask_data(KEY_SECRETS_MODE, &mut missing, &mut fixed()));
    assert!(
        absent.is_err(),
        "a mask whose pointer does not resolve fails"
    );
    // A `same_value` mask: the root agent id is the same value on every line of one home.
    let mut state = fixed();
    let mut agents = serde_json::json!({"agents": [{"id": uuid, "kind": "root"}]});
    mask_data(KEY_AGENTS, &mut agents, &mut state);
    assert_eq!(
        canonical_json(&agents),
        r#"{"agents":[{"id":"<ROOT_AGENT_ID>","kind":"root"}]}"#
    );
    let mut tree = serde_json::json!({"nodes": [{"id": uuid}]});
    mask_data(KEY_RUNS_TREE, &mut tree, &mut state);
    assert_eq!(
        canonical_json(&tree),
        r#"{"nodes":[{"id":"<ROOT_AGENT_ID>"}]}"#
    );
    let mut other = serde_json::json!({"nodes": [{"id": "095a3ec4-906d-47f1-8df2-367667ce2d04"}]});
    let differs =
        std::panic::catch_unwind(move || mask_data(KEY_RUNS_TREE, &mut other, &mut state));
    assert!(
        differs.is_err(),
        "a `same_value` mask refuses a second, different value"
    );
    // Canonical JSON sorts keys at every depth and keeps array order.
    assert_eq!(
        canonical_json(&serde_json::json!({"b": [{"z": 1, "a": null}], "a": "x"})),
        r#"{"a":"x","b":[{"a":null,"z":1}]}"#
    );
}

#[test]
fn module_001_t111_ac30_d5_overlay_changes_only_named_lines() {
    let golden = "# header\nGET /client/tools -> 503 error module_unavailable \"provider not wired\"\nGET /client/runs -> 200 data {\"runs\":[]}\n";
    assert_eq!(apply_overlay(&[], "h1_fs_llm", golden), golden);
    let change = HomeChange {
        home: "h1_fs_llm",
        method: "GET",
        path: "/client/tools",
        before: "503 error module_unavailable \"provider not wired\"",
        after: "200 data {\"mcp\":[],\"skills\":[],\"wasm\":[]}",
    };
    assert_eq!(
        apply_overlay(&[change], "h1_fs_llm", golden),
        "# header\nGET /client/tools -> 200 data {\"mcp\":[],\"skills\":[],\"wasm\":[]}\nGET /client/runs -> 200 data {\"runs\":[]}\n"
    );
    // Another home: untouched.
    assert_eq!(
        apply_overlay(&[change], "h2_all_capabilities", golden),
        golden
    );
    // A `before` that is not what the golden recorded refuses to apply.
    let stale = HomeChange {
        before: "503 error module_unavailable \"something else\"",
        ..change
    };
    let refused = std::panic::catch_unwind(|| apply_overlay(&[stale], "h1_fs_llm", golden));
    assert!(refused.is_err(), "a stale `before` must not apply");
}

fn owned_changes(rows: &[(String, String, String, String, String)]) -> Vec<HomeChange<'_>> {
    rows.iter()
        .map(|(home, method, path, before, after)| HomeChange {
            home,
            method,
            path,
            before,
            after,
        })
        .collect()
}

/// The shipped overlay obeys the ADR D5 rows (see [`check_overlay_against_adr`]), and the check
/// itself bites: an H4 grants/pending entry, a line outside the rows and an incomplete overlay
/// are refused, while a complete synthetic overlay passes.
#[test]
fn module_001_t111_ac30_d5_overlay_only_adr_rows() {
    check_overlay_against_adr(&expand_matrix(D5_CHANGE_MATRIX));

    // A complete synthetic overlay (every derived line, with row-shaped `after`s) passes.
    let mut full: Vec<(String, String, String, String, String)> = Vec::new();
    for spec in PROBE_HOMES {
        for (row, method, path) in d5_targets(spec) {
            let before = golden_outcome(spec.label, method, path);
            let after = match row {
                D5Row::GrantsPending => GRANTS_PENDING_EMPTY.to_string(),
                D5Row::DeltaCursor => golden_outcome(H3.label, method, path),
                D5Row::EventsAndHistory if method == "WS" => "101 synthetic".to_string(),
                D5Row::EventsAndHistory | D5Row::Tools => "200 data {}".to_string(),
            };
            full.push((
                spec.label.to_string(),
                method.to_string(),
                path.to_string(),
                before,
                after,
            ));
        }
    }
    check_overlay_against_adr(&owned_changes(&full));

    // Incomplete: refused.
    let partial = owned_changes(&full[..1]);
    assert!(
        std::panic::catch_unwind(|| check_overlay_against_adr(&partial)).is_err(),
        "a non-empty overlay that misses an ADR line is refused"
    );
    // Row 3: H4's grants/pending is refused, even with the captured `before`.
    let h4_before = golden_outcome(H4.label, "GET", "/client/grants/pending");
    let mut with_h4 = owned_changes(&full);
    with_h4.push(HomeChange {
        home: H4.label,
        method: "GET",
        path: "/client/grants/pending",
        before: &h4_before,
        after: GRANTS_PENDING_EMPTY,
    });
    assert!(
        std::panic::catch_unwind(|| check_overlay_against_adr(&with_h4)).is_err(),
        "row 3: grants/pending on H4 never changes"
    );
    // A line no row names (an OSS route that must answer as captured): refused.
    let health_before = golden_outcome(H1.label, "GET", "/client/health");
    let mut with_health = owned_changes(&full);
    with_health.push(HomeChange {
        home: H1.label,
        method: "GET",
        path: "/client/health",
        before: &health_before,
        after: "200 data {}",
    });
    assert!(
        std::panic::catch_unwind(|| check_overlay_against_adr(&with_health)).is_err(),
        "a line outside the ADR rows is refused"
    );
}

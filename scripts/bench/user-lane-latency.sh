#!/usr/bin/env bash
# OSS-7 user-lane latency witness (MODULE-003 §2.13). Recorded, not a CI gate.
# Run on the external APFS volume: ADVANCE_BENCH_DIR=/Volumes/Sandisk/... ./scripts/bench/user-lane-latency.sh
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-6}"
export ADVANCE_BENCH_DIR="${ADVANCE_BENCH_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/advance-bench.XXXXXX")}"
mkdir -p "$ADVANCE_BENCH_DIR"
# OperatorHarness uses tempfile::TempDir::new(), which honors TMPDIR.
export TMPDIR="$ADVANCE_BENCH_DIR"
echo "ADVANCE_BENCH_DIR=$ADVANCE_BENCH_DIR"
echo "TMPDIR=$TMPDIR"
echo "CARGO_TARGET_DIR=$CARGO_TARGET_DIR"
cargo test -p cap-fs --test operator_bench --locked -- --ignored --nocapture --test-threads=1

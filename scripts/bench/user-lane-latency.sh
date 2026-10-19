#!/usr/bin/env bash
# OSS-7 user-lane latency witness (MODULE-003 §2.13). Recorded, not a CI gate.
# Measures: 10 KiB commit_user; 50-commit backlog; save-version; 1k/10k loose-object
# corpus; 10 000-path restore_tree; 2 GiB untracked-folder delete.
# Run on the external APFS volume. If ADVANCE_BENCH_DIR is unset and
# /Volumes/Sandisk/Advance is writable, tempfile lands there.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-6}"
if [ -z "${ADVANCE_BENCH_DIR:-}" ]; then
  if [ -d /Volumes/Sandisk/Advance ] && [ -w /Volumes/Sandisk/Advance ]; then
    ADVANCE_BENCH_DIR="$(mktemp -d /Volumes/Sandisk/Advance/advance-bench.XXXXXX)"
  else
    ADVANCE_BENCH_DIR="$(mktemp -d "${TMPDIR:-/tmp}/advance-bench.XXXXXX")"
  fi
fi
export ADVANCE_BENCH_DIR
mkdir -p "$ADVANCE_BENCH_DIR"
# OperatorHarness uses tempfile::TempDir::new(), which honors TMPDIR.
export TMPDIR="$ADVANCE_BENCH_DIR"
echo "ADVANCE_BENCH_DIR=$ADVANCE_BENCH_DIR"
echo "TMPDIR=$TMPDIR"
echo "CARGO_TARGET_DIR=$CARGO_TARGET_DIR"
cargo test -p cap-fs --test operator_bench --locked -- --ignored --nocapture --test-threads=1

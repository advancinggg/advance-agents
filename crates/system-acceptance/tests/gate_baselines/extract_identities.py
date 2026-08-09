#!/usr/bin/env python3
"""Reduce `cargo clippy` / `cargo deny` output to a stable FINDING-IDENTITY set.

Why identities and not transcripts, and not counts (plan SD-16c):

* The raw `cargo deny` output for this workspace is ~750 KB of dependency tree.
  Committing that as a baseline would make every future diff unreadable and
  would churn on unrelated dependency-graph movement.
* A COUNT-based comparison is not a gate at all: it passes when a lane removes
  one baseline error and introduces a different one.  Comparison must therefore
  be a SET operation over identities, with counts reported as a secondary
  signal only.

Identity design — deliberately insensitive to line movement, because the lane
edits files that already carry baseline findings (`crates/shared-types/src/`),
so a `file:line:col` identity would manufacture phantom regressions on every
unrelated insertion above a pre-existing finding.

    clippy   lint | file (no line/col) | message
    deny     kind | subject | detail

Usage:
    extract_identities.py clippy <raw.txt>   > identities.txt
    extract_identities.py deny   <raw.txt>   > identities.txt
    extract_identities.py compare <baseline.txt> <current.txt>
"""

import re
import sys
from collections import Counter

# `error: msg`, `error[E0433]: msg`, `warning: msg`
_DIAG = re.compile(r"^(error|warning)(\[[^\]]+\])?: (.*)$")
# `  --> crates/foo/src/bar.rs:12:34`
_ARROW = re.compile(r"^\s*--> ([^:]+):\d+:\d+\s*$")
# `= help: for further information visit https://.../index.html#too_many_arguments`
_LINT = re.compile(r"index\.html#([A-Za-z0-9_]+)")
# `error: could not compile `advance-database` (lib) due to 10 previous errors`
_COMPILE_FAIL = re.compile(
    r"^error: could not compile `([^`]+)` \(([^)]+)\) due to (\d+) previous error"
)

# Cargo's own job-scheduler chatter, not a diagnostic.  It appears only when a
# parallel job aborts while siblings are still running, so whether it shows up
# depends on machine parallelism and timing.  Keeping it in the identity set
# would make the gate flaky in one direction (baseline captured single-threaded,
# gate run parallel => phantom NEW finding).
_NOISE = (
    "build failed, waiting for other jobs to finish...",
    "aborting due to previous error",
)

# Cargo's per-crate ROLLUP lines — `\`advance-device-mesh\` (lib) generated 26 warnings` —
# are summaries, not findings, and they embed a COUNT. So their identity changes whenever
# any unrelated count changes, producing a NEW/FIXED pair that is pure noise and trains a
# reviewer to skim. The findings they summarise are already captured individually.
_ROLLUP = re.compile(r"^`[^`]+` \([^)]+\) generated \d+ warnings?")


def clippy_identities(text):
    """Return (Counter of identities, list of (crate, target, count) rollups)."""
    ids = Counter()
    rollups = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]

        cf = _COMPILE_FAIL.match(line)
        if cf:
            rollups.append((cf.group(1), cf.group(2), int(cf.group(3))))
            i += 1
            continue

        m = _DIAG.match(line)
        if not m or line.startswith("error: could not compile"):
            i += 1
            continue

        severity, message = m.group(1), m.group(3).strip()
        if message in _NOISE or _ROLLUP.match(message):
            i += 1
            continue
        path, lint = "", ""
        # Scan the block until the next diagnostic header or a blank-line gap
        # followed by one.  Clippy blocks are contiguous, so stop at the next
        # `error:`/`warning:` at column 0.
        j = i + 1
        while j < len(lines):
            nxt = lines[j]
            if _DIAG.match(nxt) or nxt.startswith("error: could not compile"):
                break
            if not path:
                a = _ARROW.match(nxt)
                if a:
                    path = a.group(1)
            if not lint:
                l = _LINT.search(nxt)
                if l:
                    lint = l.group(1)
            j += 1

        ids[f"{severity}|{lint or '-'}|{path or '-'}|{message}"] += 1
        i = j
    return ids, rollups


# `error[wildcard]: found 8 wildcard dependencies for crate 'cap-lifecycle'. ...`
_WILDCARD = re.compile(
    r"^error\[wildcard\]: found (\d+) wildcard dependenc(?:y|ies) for crate '([^']+)'"
)
# `   ┌─ /…/registry/src/index.crates.io-…/notify-6.1.1/Cargo.toml:33:12`
_REG_PATH = re.compile(r"registry/src/[^/]+/([A-Za-z0-9_.+-]+)/Cargo\.toml")
# ` 33 │ license = "CC0-1.0"`
_LICENSE = re.compile(r'license\s*=\s*"([^"]+)"')


def deny_identities(text):
    ids = Counter()
    lines = text.splitlines()
    for i, line in enumerate(lines):
        w = _WILDCARD.match(line)
        if w:
            # The COUNT is deliberately excluded from the identity: adding a
            # path dependency to an already-flagged crate is not a new finding
            # class.  The count is reported separately by `compare`.
            ids[f"wildcard|{w.group(2)}|path-dependency-wildcards"] += 1
            continue
        if line.startswith("error[rejected]"):
            pkg, lic = "-", "-"
            for nxt in lines[i + 1 : i + 12]:
                if pkg == "-":
                    p = _REG_PATH.search(nxt)
                    if p:
                        pkg = p.group(1)
                if lic == "-":
                    l = _LICENSE.search(nxt)
                    if l:
                        lic = l.group(1)
                if pkg != "-" and lic != "-":
                    break
            ids[f"rejected|{pkg}|license {lic} not in deny.toml allow list"] += 1
            continue
        if line.startswith("error[") and not line.startswith(
            ("error[wildcard]", "error[rejected]")
        ):
            kind = line[6 : line.index("]")] if "]" in line else "unknown"
            ids[f"{kind}|-|{line.split(': ', 1)[-1].strip()}"] += 1
    return ids


def render(kind, ids, rollups=None, meta=None):
    out = []
    if meta:
        out.extend(meta)
    out.append(f"# tool: {kind}")
    out.append(f"# distinct identities: {len(ids)}")
    out.append(f"# total occurrences: {sum(ids.values())}")
    if rollups:
        out.append("#")
        out.append("# per-crate rollups reported by the tool (count is INFORMATIONAL")
        out.append("# only; the gate compares the identity set below):")
        for crate, target, n in sorted(rollups):
            out.append(f"#   {crate} ({target}): {n}")
    out.append("#")
    out.append("# One identity per line, sorted.  Trailing field is the occurrence")
    out.append("# count at baseline capture, and is NOT part of the identity.")
    out.append("")
    for ident in sorted(ids):
        out.append(f"{ident}\t[x{ids[ident]}]")
    return "\n".join(out) + "\n"


def parse_identity_file(path):
    ids = Counter()
    with open(path) as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            ident, _, count = line.partition("\t")
            n = 1
            if count.startswith("[x") and count.endswith("]"):
                n = int(count[2:-1])
            ids[ident] = n
    return ids


def compare(baseline_path, current_path):
    """Exit 0 iff the current identity SET is a subset of the baseline set."""
    base = parse_identity_file(baseline_path)
    cur = parse_identity_file(current_path)
    new = sorted(set(cur) - set(base))
    gone = sorted(set(base) - set(cur))
    grew = sorted(i for i in set(cur) & set(base) if cur[i] > base[i])

    for ident in new:
        print(f"NEW      {ident}  [x{cur[ident]}]")
    for ident in grew:
        print(f"GREW     {ident}  [{base[ident]} -> {cur[ident]}]")
    for ident in gone:
        print(f"FIXED    {ident}  [was x{base[ident]}]")
    print(
        f"\nnew={len(new)} grew={len(grew)} fixed={len(gone)} "
        f"baseline={len(base)} current={len(cur)}"
    )
    # A GREW is a regression too: more occurrences of a known-bad pattern is
    # new debt introduced by this lane, even though the class already existed.
    return 1 if (new or grew) else 0


def main(argv):
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    mode = argv[1]
    if mode == "compare":
        if len(argv) != 4:
            print(__doc__, file=sys.stderr)
            return 2
        return compare(argv[2], argv[3])
    with open(argv[2], errors="replace") as fh:
        text = fh.read()
    if mode == "clippy":
        ids, rollups = clippy_identities(text)
        sys.stdout.write(render("clippy", ids, rollups))
    elif mode == "deny":
        ids = deny_identities(text)
        sys.stdout.write(render("deny", ids))
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

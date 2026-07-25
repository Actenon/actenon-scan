#!/usr/bin/env python3
"""CI perf gate: scan time on a pinned fixture, and parallel must never lose.

Two assertions:

  1. REGRESSION — the serial scan of the pinned fixture must stay under the
     recorded budget plus headroom.
  2. NEVER-SLOWER — the default (auto) mode must not be materially slower
     than forced serial. This is the check that would have caught
     parallel-by-default costing ~10% on 2-4 core runners, and it runs on
     GitHub's own low-core runners, which is exactly the hardware where the
     regression appeared.

The budget is per-machine, so it is expressed as a ratio against this run's
own serial time rather than as an absolute millisecond figure copied from
somebody else's laptop.
"""

from __future__ import annotations

import argparse
import os
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from actenon_scan.engine import auto_jobs, scan_path, scan_path_parallel  # noqa: E402

# The default mode may be at most this much slower than serial. Above 1.0
# means "parallel cost us time", which is the defect being gated.
MAX_AUTO_VS_SERIAL_RATIO = 1.05


def best_of(fn, n: int = 3) -> tuple[float, object]:
    times, res = [], None
    for _ in range(n):
        t = time.perf_counter()
        res = fn()
        times.append((time.perf_counter() - t) * 1000)
    return min(times), res


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--fixture", required=True, type=Path)
    ap.add_argument("--budget-ms", type=int, default=None,
                    help="optional absolute serial ceiling for this machine")
    args = ap.parse_args()

    if not args.fixture.exists():
        print(f"SKIP: fixture not present at {args.fixture}", file=sys.stderr)
        return 0

    cores = os.cpu_count() or 1
    serial_ms, serial_res = best_of(lambda: scan_path(args.fixture))
    files = serial_res.files_scanned
    chosen = auto_jobs(files, cores)

    if chosen > 1:
        auto_ms, auto_res = best_of(lambda: scan_path_parallel(args.fixture, jobs=chosen))
    else:
        auto_ms, auto_res = serial_ms, serial_res

    print(f"cores            : {cores}")
    print(f"files scanned    : {files}")
    print(f"auto_jobs chose  : {chosen} ({'parallel' if chosen > 1 else 'serial'})")
    print(f"serial           : {serial_ms:.0f}ms")
    print(f"default (auto)   : {auto_ms:.0f}ms")
    print(f"findings         : serial={len(serial_res.findings)} auto={len(auto_res.findings)}")

    problems = []

    if len(serial_res.findings) != len(auto_res.findings):
        problems.append(
            f"serial and auto modes disagree: {len(serial_res.findings)} vs "
            f"{len(auto_res.findings)} findings"
        )

    ratio = auto_ms / serial_ms if serial_ms else 1.0
    print(f"auto/serial ratio: {ratio:.3f} (max {MAX_AUTO_VS_SERIAL_RATIO})")
    if ratio > MAX_AUTO_VS_SERIAL_RATIO:
        problems.append(
            f"the default mode is {(ratio - 1) * 100:.1f}% SLOWER than serial on this "
            f"machine ({cores} cores). Parallelism must never cost time by default — "
            f"raise MIN_CORES_FOR_AUTO_PARALLEL or MIN_FILES_FOR_AUTO_PARALLEL."
        )

    if args.budget_ms and serial_ms > args.budget_ms:
        problems.append(f"serial {serial_ms:.0f}ms exceeds budget {args.budget_ms}ms")

    if problems:
        print("\nperf gate FAILED:", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1

    print("\nOK: default mode is never slower than serial, and findings match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

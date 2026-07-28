#!/usr/bin/env python3
"""Verify corpus scan results against corpus-triage.json.

Work Order 1.9-Resume, Phase 0.3: hardened corpus comparison.

This script compares a set of scan-result JSON files (one per repo)
against the hand-triage in ``tests/benchmark/corpus-triage.json``. It is
the script that backs the ``scanner_version_measured_with`` claim, so it
is part of the release process.

Hardening rules (Work Order 1.9-Resume):

1. **Repo-name matching is explicit.** ``corpus-triage.json`` uses full
   repository names (``modelcontextprotocol/servers``); scan output uses
   safe directory names (``servers``). A name mismatch must NEVER be
   reportable as drift, and drift must NEVER be hidden by a name
   mismatch. The script builds a bidirectional mapping from
   ``pinned_repos.json`` and raises a hard error if any scanned repo
   cannot be mapped to a triage entry, or vice versa.

2. **Both directions fail loudly.** A repo present in triage but absent
   from scan output is a hard error (not a silent "disappeared"). A repo
   present in scan output but absent from triage is a hard error (not a
   silent "appeared"). Both name the unmatched entries.

Usage:
    python scripts/verify_corpus_scan.py --scan-dir /tmp/wo19-corpus
    python scripts/verify_corpus_scan.py --scan-dir /tmp/wo19-corpus --check

``--check`` mode exits non-zero on any mismatch (for CI). Without
``--check``, prints a report and exits 0 if no errors.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCH = REPO_ROOT / "tests" / "benchmark"


def load_pinned() -> list[dict]:
    """Load pinned_repos.json and return the repos list."""
    return json.loads((BENCH / "pinned_repos.json").read_text())["repos"]


def load_triage() -> dict:
    """Load corpus-triage.json."""
    return json.loads((BENCH / "corpus-triage.json").read_text())


def build_name_maps(pinned: list[dict]) -> tuple[dict[str, str], dict[str, str]]:
    """Build bidirectional maps between safe names and full names.

    Returns (safe_to_full, full_to_safe).
    A "safe name" is the directory name used in scan output. Different
    fetch scripts use different conventions:
      - last path segment: "servers" from "modelcontextprotocol/servers"
      - full name with / replaced by _: "modelcontextprotocol_servers"
      - org-repo style: "modelcontextprotocol-servers"
    This function maps all three conventions to the full name.
    """
    safe_to_full: dict[str, str] = {}
    full_to_safe: dict[str, str] = {}
    for r in pinned:
        full = r["repo"]
        # Convention 1: last path segment
        safe_last = full.split("/")[-1]
        safe_to_full[safe_last] = full
        # Convention 2: full name with / replaced by _
        safe_underscore = full.replace("/", "_")
        safe_to_full[safe_underscore] = full
        # Convention 3: full name with / replaced by -
        safe_dash = full.replace("/", "-")
        safe_to_full[safe_dash] = full
        full_to_safe[full] = safe_last  # canonical safe name is last segment
    return safe_to_full, full_to_safe


def load_scan_results(scan_dir: Path, safe_to_full: dict[str, str]) -> dict[str, list[dict]]:
    """Load scan results from JSON files in scan_dir.

    Returns a dict mapping full repo name -> list of finding dicts.
    """
    results: dict[str, list[dict]] = {}
    for jf in sorted(scan_dir.glob("*.json")):
        safe = jf.stem
        # Skip non-repo files (e.g., summary.json, result.json)
        if safe in ("summary", "result", "results"):
            continue
        full = safe_to_full.get(safe)
        if full is None:
            # Try matching by the safe name directly — it might be a
            # full name already or an unmapped repo
            full = safe
        data = json.loads(jf.read_text())
        findings = [f for f in data.get("findings", []) if not f.get("suppressed")]
        results[full] = findings
    return results


def verify(
    scan_dir: Path,
    *,
    check_mode: bool = False,
) -> int:
    """Verify scan results against triage. Returns 0 on success, 1 on failure."""
    pinned = load_pinned()
    triage = load_triage()
    safe_to_full, full_to_safe = build_name_maps(pinned)

    # The set of repos that SHOULD be scanned (from pinned_repos.json)
    expected_full_names = {r["repo"] for r in pinned}

    scan_results = load_scan_results(scan_dir, safe_to_full)
    scanned_full_names = set(scan_results.keys())

    # ── Check 1: every expected repo was scanned ──
    missing_scans = expected_full_names - scanned_full_names
    if missing_scans:
        print("FAIL: repos in pinned_repos.json but not scanned:", file=sys.stderr)
        for name in sorted(missing_scans):
            print(f"  {name} (safe name: {full_to_safe.get(name, '?')})", file=sys.stderr)
        return 1

    # ── Check 2: no unexpected repos in scan output ──
    extra_scans = scanned_full_names - expected_full_names
    if extra_scans:
        print("FAIL: repos in scan output but not in pinned_repos.json:", file=sys.stderr)
        for name in sorted(extra_scans):
            print(f"  {name}", file=sys.stderr)
        return 1

    # ── Check 3: findings match triage ──
    triage_entries = triage["entries"]
    triage_findings: dict[tuple, dict] = {}
    for e in triage_entries:
        key = (e["repo"], e["file"], e["line"], e["rule_id"])
        triage_findings[key] = e

    scan_findings: dict[tuple, dict] = {}
    for full_name, findings in scan_results.items():
        for f in findings:
            key = (full_name, f["file"], f["line"], f["rule_id"])
            scan_findings[key] = f

    triage_keys = set(triage_findings.keys())
    scan_keys = set(scan_findings.keys())

    in_both = triage_keys & scan_keys
    in_triage_only = triage_keys - scan_keys
    in_scan_only = scan_keys - triage_keys

    # ── Report ──
    tp = sum(1 for e in triage_entries if e["verdict"] == "TRUE_POSITIVE")
    fp = sum(1 for e in triage_entries if e["verdict"] == "FALSE_POSITIVE")
    total = tp + fp

    print(f"Repos scanned: {len(scanned_full_names)}")
    print(f"Triage entries: {len(triage_entries)} ({tp} TP + {fp} FP = {total} total)")
    print(f"Scan findings: {len(scan_keys)}")
    print(f"In both: {len(in_both)}")
    print(f"Disappeared (in triage, not in scan): {len(in_triage_only)}")
    print(f"Appeared (in scan, not in triage): {len(in_scan_only)}")

    if in_triage_only:
        print("\nDISAPPEARED findings (in triage but not in scan):", file=sys.stderr)
        for k in sorted(in_triage_only):
            print(f"  {k[0]} {k[1]}:{k[2]} {k[3]}", file=sys.stderr)

    if in_scan_only:
        print("\nAPPEARED findings (in scan but not in triage):", file=sys.stderr)
        for k in sorted(in_scan_only):
            print(f"  {k[0]} {k[1]}:{k[2]} {k[3]}", file=sys.stderr)

    if in_triage_only or in_scan_only:
        print("\nFAIL: scan results do not match triage.", file=sys.stderr)
        return 1

    # ── Check 4: precision figure matches ──
    recorded_tp = triage.get("totals", {}).get("true_positives", 0)
    recorded_fp = triage.get("totals", {}).get("false_positives", 0)
    if recorded_tp != tp or recorded_fp != fp:
        print(f"\nFAIL: totals mismatch. triage.json totals={recorded_tp} TP / {recorded_fp} FP, "
              f"but entries have {tp} TP / {fp} FP.", file=sys.stderr)
        return 1

    print(f"\nOK: all {len(scan_keys)} findings match triage. {tp} TP / {fp} FP = {round(tp/total*100, 1)}% precision.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scan-dir", required=True, type=Path,
                    help="Directory containing per-repo scan JSON files")
    ap.add_argument("--check", action="store_true",
                    help="Exit non-zero on any mismatch (for CI)")
    args = ap.parse_args()

    if not args.scan_dir.exists():
        print(f"FAIL: scan dir does not exist: {args.scan_dir}", file=sys.stderr)
        return 1

    return verify(args.scan_dir, check_mode=args.check)


if __name__ == "__main__":
    sys.exit(main())

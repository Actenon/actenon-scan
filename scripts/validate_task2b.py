#!/usr/bin/env python3
"""Task 2b: Validate same-class method resolution against the 22
AGENT_REACHABLE labelled cases.

Fetches each case's file from GitHub at the pinned SHA, writes it to
a temp directory, scans it, and reports caught / 22.

Reports per-case: repo, file, line, mechanism, enclosing_class,
caught_before (per-file reachability only), caught_after (with
same-class method resolution).
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import urllib.request
from pathlib import Path

# Add the repo root to sys.path so we can import actenon_scan
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from actenon_scan.engine import scan_path
from actenon_scan.detectors.reachability import (
    detect_reachability,
    detect_same_class_method_reachability,
)
import ast


PAT = os.environ.get("GITHUB_TOKEN", "")
LABELS_FILE = Path(__file__).resolve().parent.parent / "research" / "reachability-ground-truth" / "labels.json"


def fetch_file(repo: str, sha: str, file_path: str) -> str:
    """Fetch a file from GitHub at a specific SHA."""
    url = f"https://api.github.com/repos/{repo}/contents/{file_path}?ref={sha}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"token {PAT}",
        "Accept": "application/vnd.github+json",
    })
    import base64
    with urllib.request.urlopen(req, timeout=30) as resp:
        d = json.loads(resp.read())
        return base64.b64decode(d["content"]).decode("utf-8", "replace")


def check_case(case: dict) -> dict:
    """Check a single AGENT_REACHABLE case. Returns whether it was
    caught before (per-file only) and after (with same-class resolution)."""
    repo = case["repo"]  # e.g. "TransformerOptimus/SuperAGI"
    sha = case["sha"]
    file_path = case["file"]  # e.g. "superagi/agent/output_handler.py"
    line = case["line"]
    rule_id = case["rule_id"]

    try:
        source = fetch_file(repo, sha, file_path)
    except Exception as e:
        return {**case, "caught_before": None, "caught_after": None, "error": str(e)[:200]}

    # Parse the file
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {**case, "caught_before": None, "caught_after": None, "error": "SyntaxError"}

    # Load default rules for reachability config
    from actenon_scan.rules.loader import load_rules
    rules = load_rules(None)

    # Check before: per-file reachability only
    reach_before = detect_reachability(tree, line, rules.reachability)
    caught_before = reach_before.confidence != "none"

    # Check after: with same-class AND module-level resolution
    same_class = detect_same_class_method_reachability(tree, rules.reachability)
    from actenon_scan.detectors.reachability import detect_module_level_reachability
    module_level = detect_module_level_reachability(tree, rules.reachability)
    # Find the enclosing function's lineno
    from actenon_scan.detectors.reachability import _find_enclosing_function
    enclosing = _find_enclosing_function(tree, line)
    caught_after = caught_before
    if not caught_after and enclosing is not None:
        if enclosing.lineno in same_class:
            caught_after = True
        elif enclosing.lineno in module_level:
            caught_after = True

    return {
        "idx": case["idx"],
        "repo_name": case["repo_name"],
        "file": case["file"],
        "line": case["line"],
        "rule_id": case["rule_id"],
        "mechanism": case.get("mechanism"),
        "enclosing_class": case.get("enclosing_class"),
        "caught_before": caught_before,
        "caught_after": caught_after,
        "error": None,
    }


def main() -> None:
    with open(LABELS_FILE) as f:
        labels = json.load(f)

    reachable = [d for d in labels if isinstance(d, dict) and d.get("label") == "AGENT_REACHABLE"]
    print(f"Total AGENT_REACHABLE cases: {len(reachable)}")
    print()

    results = []
    for i, case in enumerate(reachable):
        print(f"[{i+1}/{len(reachable)}] {case['repo_name']} {case['file']}:{case['line']}...", end=" ", flush=True)
        result = check_case(case)
        results.append(result)
        if result.get("error"):
            print(f"ERROR: {result['error'][:80]}")
        else:
            before = "✓" if result["caught_before"] else "✗"
            after = "✓" if result["caught_after"] else "✗"
            print(f"before={before} after={after} mech={result['mechanism']}")

    print()
    caught_before = sum(1 for r in results if r["caught_before"])
    caught_after = sum(1 for r in results if r["caught_after"])
    errors = sum(1 for r in results if r.get("error"))
    print(f"=== SUMMARY ===")
    print(f"Caught BEFORE (per-file only): {caught_before}/{len(results)}")
    print(f"Caught AFTER  (with same-class): {caught_after}/{len(results)}")
    print(f"Errors: {errors}")
    print()

    # Per-mechanism breakdown
    print("=== PER MECHANISM ===")
    mechs = {}
    for r in results:
        m = r["mechanism"]
        if m not in mechs:
            mechs[m] = {"total": 0, "before": 0, "after": 0}
        mechs[m]["total"] += 1
        if r["caught_before"]:
            mechs[m]["before"] += 1
        if r["caught_after"]:
            mechs[m]["after"] += 1
    for m, counts in sorted(mechs.items(), key=lambda x: -x[1]["total"]):
        print(f"  {m:30s} total={counts['total']:2d} before={counts['before']:2d} after={counts['after']:2d}")

    # Write results to JSON
    out = Path(__file__).resolve().parent.parent / "research" / "reachability-ground-truth" / "task2b_validation.json"
    out.write_text(json.dumps(results, indent=2) + "\n")
    print(f"\nResults written to {out}")


if __name__ == "__main__":
    main()

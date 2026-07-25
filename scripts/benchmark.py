#!/usr/bin/env python3
"""Benchmark runner: measures recall, precision, and soundness.

Usage:
    python scripts/benchmark.py              # print scoreboard
    python scripts/benchmark.py --baseline   # write baseline file
    python scripts/benchmark.py --check      # exit 1 if any score decreased

The benchmark scans each file in tests/benchmark/{recall,precision,soundness}/
and checks the expected outcome:

  recall/     — must produce >=1 finding (one per agent architecture)
  precision/  — must produce 0 findings (guarded, unreachable, test files)
  soundness/  — must produce >=1 finding (defeated guards)

Recall is reported on TWO axes:
  - recall (synthetic): fixture passes, informational only
  - recall (corpus-demonstrated): ratchets in CI; a detector graduates
    from synthetic to corpus-demonstrated only when it produces a
    hand-triaged TRUE POSITIVE on a pinned commit of a real repository
    (recorded in tests/benchmark/corpus-evidence.json)

Precision MUST be 100% — a drop fails the build.
Corpus-demonstrated recall and soundness use a ratcheting baseline.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCHMARK_DIR = REPO_ROOT / "tests" / "benchmark"
BASELINE_FILE = REPO_ROOT / "tests" / "benchmark" / "baseline.json"
CORPUS_EVIDENCE_FILE = REPO_ROOT / "tests" / "benchmark" / "corpus-evidence.json"


def scan_file(filepath: Path) -> int:
    """Scan a single file and return the finding count."""
    from actenon_scan.engine import scan_path
    result = scan_path(str(filepath))
    return len([f for f in result.findings if not f.suppressed])


def load_corpus_evidence() -> dict:
    """Load corpus evidence file."""
    if CORPUS_EVIDENCE_FILE.exists():
        return json.loads(CORPUS_EVIDENCE_FILE.read_text())
    return {}


def get_corpus_demonstrated_recall(corpus_evidence: dict) -> int:
    """Count how many recall fixtures have corpus evidence."""
    count = 0
    for f in sorted((BENCHMARK_DIR / "recall").glob("*.py")):
        fixture_name = f.stem  # e.g., "r01_mcp_tool"
        if fixture_name in corpus_evidence:
            evidence = corpus_evidence[fixture_name]
            if evidence.get("triage") == "true_positive":
                count += 1
    return count


def run_benchmark() -> dict:
    """Run all benchmark cases and return scores."""
    recall_pass = 0
    recall_total = 0
    recall_details = []

    for f in sorted((BENCHMARK_DIR / "recall").glob("*.py")):
        recall_total += 1
        count = scan_file(f)
        passed = count >= 1
        if passed:
            recall_pass += 1
        recall_details.append({
            "file": f.name,
            "expected": ">=1 finding",
            "got": f"{count} findings",
            "pass": passed,
        })

    precision_pass = 0
    precision_total = 0
    precision_details = []

    for f in sorted((BENCHMARK_DIR / "precision").glob("*")):
        if f.name.startswith("."):
            continue
        precision_total += 1
        count = scan_file(f)
        passed = count == 0
        if passed:
            precision_pass += 1
        precision_details.append({
            "file": f.name,
            "expected": "0 findings",
            "got": f"{count} findings",
            "pass": passed,
        })

    soundness_pass = 0
    soundness_total = 0
    soundness_details = []

    for f in sorted((BENCHMARK_DIR / "soundness").glob("*.py")):
        soundness_total += 1
        count = scan_file(f)
        passed = count >= 1
        if passed:
            soundness_pass += 1
        soundness_details.append({
            "file": f.name,
            "expected": ">=1 finding",
            "got": f"{count} findings",
            "pass": passed,
        })

    # Corpus-demonstrated recall
    corpus_evidence = load_corpus_evidence()
    corpus_recall = get_corpus_demonstrated_recall(corpus_evidence)

    return {
        "recall": {
            "pass": recall_pass,
            "total": recall_total,
            "pct": round(recall_pass / recall_total * 100) if recall_total else 0,
            "details": recall_details,
        },
        "recall_corpus": {
            "pass": corpus_recall,
            "total": recall_total,
            "pct": round(corpus_recall / recall_total * 100) if recall_total else 0,
            "evidence": corpus_evidence,
        },
        "precision": {
            "pass": precision_pass,
            "total": precision_total,
            "pct": round(precision_pass / precision_total * 100) if precision_total else 0,
            "details": precision_details,
        },
        "soundness": {
            "pass": soundness_pass,
            "total": soundness_total,
            "pct": round(soundness_pass / soundness_total * 100) if soundness_total else 0,
            "details": soundness_details,
        },
    }


def print_scoreboard(scores: dict) -> None:
    """Print the benchmark scoreboard."""
    print("=" * 60)
    print("actenon-scan benchmark")
    print("=" * 60)
    print()

    r = scores["recall"]
    rc = scores["recall_corpus"]
    p = scores["precision"]
    s = scores["soundness"]

    print(f"  recall (synthetic)           {r['pass']}/{r['total']}   ({r['pct']}%)")
    print(f"  recall (corpus-demonstrated) {rc['pass']}/{r['total']}   ({rc['pct']}%)  ← gates CI")
    print(f"  precision                    {p['pass']}/{p['total']}  ({p['pct']}%)")
    print(f"  soundness                    {s['pass']}/{s['total']}   ({s['pct']}%)")
    print()

    for category_name, category in [("RECALL (synthetic)", r), ("PRECISION", p), ("SOUNDNESS", s)]:
        print(f"  {category_name}:")
        for d in category["details"]:
            status = "✓" if d["pass"] else "✗"
            print(f"    {status} {d['file']:40s} expected={d['expected']:15s} got={d['got']}")
        print()

    if rc["evidence"]:
        print("  CORPUS EVIDENCE:")
        for fixture, ev in sorted(rc["evidence"].items()):
            print(f"    {fixture:40s} {ev.get('repo', '?'):30s} {ev.get('triage', '?')}")
        print()

    print("=" * 60)
    if p["pct"] < 100:
        print("  FAIL: precision must be 100%")
    else:
        print("  precision: OK (100%)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", action="store_true", help="write baseline file")
    parser.add_argument("--check", action="store_true", help="fail if scores decreased from baseline")
    args = parser.parse_args()

    scores = run_benchmark()
    print_scoreboard(scores)

    if args.baseline:
        BASELINE_FILE.write_text(json.dumps({
            "recall_corpus": scores["recall_corpus"]["pass"],
            "precision": scores["precision"]["pass"],
            "soundness": scores["soundness"]["pass"],
            # synthetic recall is informational, not gated
            "recall_synthetic": scores["recall"]["pass"],
        }, indent=2) + "\n")
        print(f"\nBaseline written to {BASELINE_FILE}")

    if args.check:
        if not BASELINE_FILE.exists():
            print("\nNo baseline file — run with --baseline first")
            return 0

        baseline = json.loads(BASELINE_FILE.read_text())
        failed = False

        if scores["precision"]["pass"] < baseline.get("precision", 0):
            print(f"\n  FAIL: precision decreased from {baseline['precision']} to {scores['precision']['pass']}")
            failed = True
        if scores["recall_corpus"]["pass"] < baseline.get("recall_corpus", 0):
            print(f"\n  FAIL: corpus-demonstrated recall decreased from {baseline.get('recall_corpus', 0)} to {scores['recall_corpus']['pass']}")
            failed = True
        if scores["soundness"]["pass"] < baseline.get("soundness", 0):
            print(f"\n  FAIL: soundness decreased from {baseline['soundness']} to {scores['soundness']['pass']}")
            failed = True

        if not failed:
            print("\n  All scores at or above baseline.")

        # Precision must ALWAYS be 100%
        if scores["precision"]["pct"] < 100:
            return 1
        return 1 if failed else 0

    # Default: exit 1 if precision is not 100%
    return 0 if scores["precision"]["pct"] == 100 else 1


if __name__ == "__main__":
    sys.exit(main())

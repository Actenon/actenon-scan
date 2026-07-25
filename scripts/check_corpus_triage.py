#!/usr/bin/env python3
"""CI gate: the corpus must contain zero false positives, and zero untriaged findings.

Two failure modes, both build-breaking:

  1. Any FALSE_POSITIVE entry in corpus-triage.json. The fix is to tighten the
     RULE and add a regression fixture — never to edit the verdict. A rule that
     cannot be tightened without losing a true positive is downgraded below
     HIGH instead.
  2. Any finding in corpus-results.json with no matching triage entry. An
     untriaged count is the same defect as a benchmark score with no detector
     behind it.

Also enforces the definitional rule that a finding in a non-agent control
repository is a precision failure.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "tests" / "benchmark"


def main() -> int:
    triage_path = BENCH / "corpus-triage.json"
    results_path = BENCH / "corpus-results.json"
    pinned_path = BENCH / "pinned_repos.json"

    for p in (triage_path, results_path, pinned_path):
        if not p.exists():
            print(f"FAIL: missing {p.relative_to(ROOT)}", file=sys.stderr)
            return 1

    triage = json.loads(triage_path.read_text())
    results = json.loads(results_path.read_text())
    pinned = json.loads(pinned_path.read_text())

    problems: list[str] = []

    entries = triage.get("entries", [])
    false_positives = [e for e in entries if e.get("verdict") == "FALSE_POSITIVE"]
    for e in false_positives:
        problems.append(
            f"FALSE_POSITIVE still present: {e['repo']} {e['file']}:{e['line']} "
            f"({e['rule_id']}) — fix the rule and add a regression fixture"
        )

    # Every finding must be triaged.
    triaged = {(e["repo"], e["file"], e["line"], e["rule_id"]) for e in entries}
    for f in results.get("findings", []):
        key = (f["repo"], f["file"], f["line"], f["rule_id"])
        if key not in triaged:
            problems.append(
                f"UNTRIAGED finding: {f['repo']} {f['file']}:{f['line']} ({f['rule_id']})"
            )

    # A finding in a control repo is a precision failure by definition.
    controls = {r["name"] for r in pinned["repos"] if r["category"] == "control"}
    for name, data in results.get("repos", {}).items():
        if name in controls and data.get("findings", 0):
            problems.append(
                f"CONTROL REPO FINDING: {name} produced {data['findings']} finding(s). "
                f"Non-agent libraries must produce zero."
            )

    if problems:
        print(f"corpus triage gate FAILED ({len(problems)} problem(s)):", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1

    totals = triage.get("totals", {})
    print(
        f"OK: {totals.get('findings', len(entries))} corpus findings, "
        f"{totals.get('true_positives', 0)} true positives, "
        f"0 false positives, 0 untriaged, "
        f"0 findings across {len(controls)} control repos"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

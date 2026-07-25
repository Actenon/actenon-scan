#!/usr/bin/env python3
"""CI gate: docs/COVERAGE.md is a contract, not prose.

Every architecture row marked COVERED must be backed by a hand-triaged
TRUE POSITIVE on a pinned commit of a real repository, recorded in
corpus-evidence.json. A row may NOT claim COVERED on a synthetic fixture
alone — a fixture proves the detector fires on code we wrote, which is not
evidence that it fires on code anyone else wrote.

This is the structural version of the two-axis recall split, and it is what
stops a public capability claim drifting from behaviour.

Checks:
  1. Every COVERED row names a corpus-evidence key that exists.
  2. That evidence entry is triaged "true_positive".
  3. The number of COVERED rows equals baseline.json's recall_corpus, so the
     documented contract and the gating number cannot disagree.
  4. Every architecture with a recall fixture appears as a row (no silent
     omissions).
  5. Rows that are not COVERED must not cite corpus evidence.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COVERAGE = ROOT / "docs" / "COVERAGE.md"
BENCH = ROOT / "tests" / "benchmark"

VALID_STATUS = {"COVERED", "PARTIAL", "NOT COVERED"}
# | `r01` | name | COVERED | `key` |  (evidence cell is `-` when not covered)
ROW = re.compile(
    r"^\|\s*`(?P<id>r\d{2})`\s*\|(?P<name>[^|]*)\|\s*(?P<status>COVERED|PARTIAL|NOT COVERED)\s*\|(?P<evidence>[^|]*)\|"
)


def parse_rows(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        m = ROW.match(line.strip())
        if m:
            rows.append({
                "id": m.group("id"),
                "name": m.group("name").strip(),
                "status": m.group("status").strip(),
                "evidence": m.group("evidence").strip().strip("`").strip(),
            })
    return rows


def main() -> int:
    if not COVERAGE.exists():
        print(f"FAIL: {COVERAGE} missing", file=sys.stderr)
        return 1

    rows = parse_rows(COVERAGE.read_text())
    if not rows:
        print("FAIL: no architecture rows parsed from COVERAGE.md — the "
              "contract table is missing or its format changed", file=sys.stderr)
        return 1

    evidence = json.loads((BENCH / "corpus-evidence.json").read_text())
    baseline = json.loads((BENCH / "baseline.json").read_text())

    problems: list[str] = []
    covered = [r for r in rows if r["status"] == "COVERED"]

    for r in covered:
        key = r["evidence"]
        if not key or key == "-":
            problems.append(
                f"{r['id']} claims COVERED but cites no corpus evidence. A row "
                f"cannot be COVERED on a synthetic fixture alone."
            )
            continue
        entry = evidence.get(key)
        if entry is None:
            problems.append(
                f"{r['id']} claims COVERED citing '{key}', which is not in "
                f"corpus-evidence.json"
            )
            continue
        if entry.get("triage") != "true_positive":
            problems.append(
                f"{r['id']} claims COVERED citing '{key}', but that entry is "
                f"triaged '{entry.get('triage')}', not true_positive"
            )

    for r in rows:
        if r["status"] != "COVERED" and r["evidence"] not in ("", "-"):
            problems.append(
                f"{r['id']} is {r['status']} but cites corpus evidence "
                f"'{r['evidence']}' — either promote the row or drop the citation"
            )

    declared = baseline.get("recall_corpus")
    if declared != len(covered):
        problems.append(
            f"COVERAGE.md marks {len(covered)} architecture(s) COVERED but "
            f"baseline.recall_corpus={declared}. The documented contract and "
            f"the gating number must agree."
        )

    fixtures = sorted(p.stem.split("_")[0] for p in (BENCH / "recall").glob("r*.py"))
    documented = {r["id"] for r in rows}
    for fx in fixtures:
        if fx not in documented:
            problems.append(f"recall fixture {fx} has no row in COVERAGE.md")

    if problems:
        print(f"COVERAGE contract FAILED ({len(problems)} problem(s)):", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1

    print(
        f"OK: {len(rows)} architecture rows, {len(covered)} COVERED and each "
        f"backed by a hand-triaged corpus true positive, matching "
        f"baseline.recall_corpus={declared}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

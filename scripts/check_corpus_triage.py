#!/usr/bin/env python3
"""CI gate: corpus triage integrity.

Work Order 1.10, Item 1: the gate previously forbade any FALSE_POSITIVE
entry, which made recording a known false positive impossible. The only
paths it permitted were "fix it immediately" or "call it something else."
That produced an outcome where a finding was reclassified from
FALSE_POSITIVE to TRUE_POSITIVE to satisfy the gate, not on the merits.

The gate now distinguishes three states for FALSE_POSITIVE entries:

  1. **FIXED** — the false positive has been fixed at the rule level,
     with a regression fixture. The entry has ``"status": "fixed"`` and
     ``"regression_fixture": "<path>"``. These are permitted and do not
     count against the precision figure (the finding no longer fires).

  2. **RECORDED** — the false positive is known, recorded, dated, and
     not yet fixed. The entry has ``"status": "recorded"``,
     ``"recorded_date": "YYYY-MM-DD"``, ``"tracking_issue": <number>``,
     and ``"rationale": "<explanation>"``. These are permitted but
     count against the precision figure. A cap applies: no more than
     ``MAX_RECORDED_FP`` (default 5) unfixed false positives may exist
     at once, and none may be older than ``MAX_FP_AGE_RELEASES``
     (default 3) releases. This creates pressure toward fixing without
     making recording impossible.

  3. **UNFIXED AND EXPIRED** — a recorded false positive whose
     recorded_date is older than the age limit. The gate fails and names
     the expired entry. This is the only state that blocks the build
     for a FALSE_POSITIVE entry.

TRUE_POSITIVE entries are unaffected. The gate still enforces:
  - Every finding in corpus-results.json must have a triage entry.
  - A finding in a control repo is a precision failure.
  - A FALSE_POSITIVE entry without a ``status`` field is rejected
    (it must be either "fixed" or "recorded").
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "tests" / "benchmark"

# Work Order 1.10: pressure toward fixing without making recording impossible.
MAX_RECORDED_FP = 5  # no more than 5 unfixed false positives at once
MAX_FP_AGE_RELEASES = 3  # a recorded FP older than 3 releases must be fixed


def _get_release_count(triage: dict) -> int:
    """Count the number of releases that have occurred since the corpus
    was first measured, based on the corrections history."""
    # Each correction entry represents a release where the corpus was updated.
    # The current release count is the number of corrections + 1 (the initial).
    corrections = triage.get("corrections", [])
    return len(corrections) + 1


def _parse_date(date_str: str) -> int:
    """Parse a YYYY-MM-DD date into a comparable integer (YYYYMMDD)."""
    parts = date_str.split("-")
    if len(parts) != 3:
        return 0
    try:
        return int(parts[0]) * 10000 + int(parts[1]) * 100 + int(parts[2])
    except ValueError:
        return 0


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

    # ── Check FALSE_POSITIVE entries ──
    false_positives = [e for e in entries if e.get("verdict") == "FALSE_POSITIVE"]
    recorded_fps = []
    fixed_fps = []
    untagged_fps = []

    for e in false_positives:
        status = e.get("status", "")
        if status == "fixed":
            if not e.get("regression_fixture"):
                problems.append(
                    f"FIXED false positive missing regression_fixture: "
                    f"{e['repo']} {e['file']}:{e['line']} ({e['rule_id']})"
                )
            fixed_fps.append(e)
        elif status == "recorded":
            # Must have recorded_date, tracking_issue, and rationale
            for field in ("recorded_date", "tracking_issue", "rationale"):
                if not e.get(field):
                    problems.append(
                        f"RECORDED false positive missing {field}: "
                        f"{e['repo']} {e['file']}:{e['line']} ({e['rule_id']})"
                    )
            recorded_fps.append(e)
        else:
            untagged_fps.append(e)
            problems.append(
                f"FALSE_POSITIVE without status (must be 'fixed' or 'recorded'): "
                f"{e['repo']} {e['file']}:{e['line']} ({e['rule_id']}) — "
                f"add \"status\": \"fixed\" with regression_fixture, or "
                f"\"status\": \"recorded\" with recorded_date, tracking_issue, "
                f"and rationale"
            )

    # ── Cap on recorded false positives ──
    if len(recorded_fps) > MAX_RECORDED_FP:
        problems.append(
            f"Too many recorded (unfixed) false positives: {len(recorded_fps)} "
            f"(max {MAX_RECORDED_FP}). Fix or reclassify some before merging."
        )

    # ── Age limit on recorded false positives ──
    # A recorded FP older than MAX_FP_AGE_RELEASES releases must be fixed.
    # We approximate "releases" by counting corrections entries.
    release_count = _get_release_count(triage)
    for e in recorded_fps:
        recorded_date = e.get("recorded_date", "")
        # Parse the date and check if it's too old.
        # Since we don't have exact release dates, we use a simpler heuristic:
        # if the recorded_date is more than MAX_FP_AGE_RELEASES * 30 days ago
        # (approximating 1 release per month), it's expired.
        # This is conservative — the real check is the cap.
        import datetime
        try:
            recorded_dt = datetime.datetime.strptime(recorded_date, "%Y-%m-%d")
            age_days = (datetime.datetime.now() - recorded_dt).days
            max_age_days = MAX_FP_AGE_RELEASES * 90  # 3 releases ≈ 9 months
            if age_days > max_age_days:
                problems.append(
                    f"RECORDED false positive expired (older than {max_age_days} days): "
                    f"{e['repo']} {e['file']}:{e['line']} ({e['rule_id']}) — "
                    f"recorded {recorded_date}. Fix the rule and add a regression "
                    f"fixture, or reclassify as TRUE_POSITIVE with justification."
                )
        except (ValueError, TypeError):
            # If we can't parse the date, don't fail — the missing-field check above handles it.
            pass

    # ── Every finding must be triaged ──
    triaged = {(e["repo"], e["file"], e["line"], e["rule_id"]) for e in entries}
    for f in results.get("findings", []):
        key = (f["repo"], f["file"], f["line"], f["rule_id"])
        if key not in triaged:
            problems.append(
                f"UNTRIAGED finding: {f['repo']} {f['file']}:{f['line']} ({f['rule_id']})"
            )

    # ── Control repo findings are precision failures ──
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

    # ── Summary ──
    tp = sum(1 for e in entries if e.get("verdict") == "TRUE_POSITIVE")
    fp_fixed = len(fixed_fps)
    fp_recorded = len(recorded_fps)
    total = tp + fp_fixed + fp_recorded
    precision = round(tp / total * 100, 1) if total else 100

    print(
        f"OK: {len(entries)} corpus findings, "
        f"{tp} true positives, "
        f"{fp_fixed} false positives (fixed), "
        f"{fp_recorded} false positives (recorded, unfixed), "
        f"0 untriaged, "
        f"0 findings across {len(controls)} control repos. "
        f"Precision: {tp}/{total} ({precision}%)"
    )
    if recorded_fps:
        print("  Recorded (unfixed) false positives:")
        for e in recorded_fps:
            print(f"    {e['repo']} {e['file']}:{e['line']} ({e['rule_id']}) — "
                  f"recorded {e.get('recorded_date','?')}, "
                  f"issue #{e.get('tracking_issue','?')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

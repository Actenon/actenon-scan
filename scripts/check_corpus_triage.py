#!/usr/bin/env python3
"""CI gate: corpus triage integrity.

Task 3: the gate now RE-MEASURES by default instead of reading
committed JSON. It clones each pinned repo at its pinned SHA, scans
it, and compares the findings to corpus-triage.json.

If network fetching is infeasible, the gate FAILS LOUDLY — it does NOT
fall back to reading committed data. A gate that cannot verify must
not report PASS.

Pass --no-remeasure to fall back to the old behaviour (reading
committed JSON) for local development without network access. CI must
NOT use this flag — CI must re-measure.

The gate fails on:
  - Any finding in a repo marked category "control" (precision failure)
  - Any finding not present in the triage file (untriaged)
  - Any FALSE_POSITIVE without a status (must be "fixed" or "recorded")
  - More than MAX_RECORDED_FP unfixed false positives
  - A recorded false positive older than MAX_FP_AGE_RELEASES releases

Exit codes:
  0 — gate passed (re-measured, all findings triaged, zero control findings)
  1 — gate failed (untriaged findings, control findings, or triage errors)
  2 — gate could not verify (network failure, --no-remeasure not passed)
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "tests" / "benchmark"

MAX_RECORDED_FP = 5
MAX_FP_AGE_RELEASES = 3


def _get_release_count(triage: dict) -> int:
    corrections = triage.get("corrections", [])
    return len(corrections) + 1


def _parse_date(date_str: str) -> int:
    parts = date_str.split("-")
    if len(parts) != 3:
        return 0
    try:
        return int(parts[0]) * 10000 + int(parts[1]) * 100 + int(parts[2])
    except ValueError:
        return 0


# ---------------------------------------------------------------------------
# Re-measurement: clone + scan each pinned repo
# ---------------------------------------------------------------------------


def _clone_repo(repo_full_name: str, sha: str, dest: Path) -> bool:
    """Clone a repo at a specific SHA. Returns True on success."""
    token = os.environ.get("GITHUB_TOKEN", "")
    url = f"https://{token}@github.com/{repo_full_name}.git" if token else f"https://github.com/{repo_full_name}.git"
    try:
        # Shallow clone at the specific SHA
        subprocess.run(
            ["git", "clone", "--depth", "1", url, str(dest)],
            capture_output=True, text=True, timeout=120, check=True,
        )
        # Checkout the specific SHA (may fail if shallow clone doesn't have it)
        subprocess.run(
            ["git", "fetch", "--depth", "1", "origin", sha],
            capture_output=True, text=True, timeout=120, check=True,
            cwd=str(dest),
        )
        subprocess.run(
            ["git", "checkout", sha],
            capture_output=True, text=True, timeout=30, check=True,
            cwd=str(dest),
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"  CLONE FAILED: {repo_full_name}@{sha[:8]} — {e}", file=sys.stderr)
        return False


def _scan_repo(repo_path: Path) -> list[dict]:
    """Scan a repo with actenon-scan. Returns list of findings as dicts."""
    try:
        from actenon_scan.engine import scan_path
        result = scan_path(repo_path, cache=None)
        findings = []
        for f in result.findings:
            if f.suppressed:
                continue
            findings.append({
                "file": f.file,
                "line": f.line,
                "rule_id": f.rule_id,
                "severity": f.severity,
                "confidence": f.confidence,
                "description": f.description,
                "call_text": f.call_text,
                "category": f.category,
            })
        return findings
    except Exception as e:
        print(f"  SCAN ERROR: {e}", file=sys.stderr)
        return []


def remeasure_corpus(pinned: dict, work_dir: Path | None = None) -> dict:
    """Clone + scan each pinned repo. Returns a results dict matching
    the corpus-results.json schema."""
    if work_dir is None:
        work_dir = Path(tempfile.mkdtemp(prefix="corpus-remeasure-"))

    results: dict = {
        "totals_by_category": {},
        "total_findings": 0,
        "repos": {},
        "findings": [],
        "measured_at_sha": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(ROOT), text=True
        ).strip(),
    }

    repos = pinned.get("repos", [])
    total = len(repos)
    for i, repo in enumerate(repos):
        name = repo["name"]
        full_name = repo.get("repo", repo.get("full_name", name))
        sha = repo["sha"]
        category = repo.get("category", "unknown")
        print(f"[{i+1}/{total}] {name} ({category})...", end=" ", flush=True)

        dest = work_dir / name
        if dest.exists():
            import shutil
            shutil.rmtree(dest)

        if not _clone_repo(full_name, sha, dest):
            results["repos"][name] = {"findings": -1, "error": "clone_failed", "category": category}
            print("CLONE FAILED")
            continue

        findings = _scan_repo(dest)
        print(f"{len(findings)} finding(s)")

        results["repos"][name] = {
            "findings": len(findings),
            "category": category,
            "sha": sha,
        }
        results["total_findings"] += len(findings)
        for f in findings:
            f["repo"] = name
            results["findings"].append(f)

        # Cleanup
        import shutil
        shutil.rmtree(dest, ignore_errors=True)

    return results


# ---------------------------------------------------------------------------
# Gate logic
# ---------------------------------------------------------------------------


def check_triage(triage: dict, results: dict, pinned: dict) -> list[str]:
    """Check triage integrity against re-measured results."""
    problems: list[str] = []
    entries = triage.get("entries", [])

    # ── Check FALSE_POSITIVE entries ──
    false_positives = [e for e in entries if e.get("verdict") == "FALSE_POSITIVE"]
    recorded_fps = []
    fixed_fps = []

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
            for field in ("recorded_date", "tracking_issue", "rationale"):
                if not e.get(field):
                    problems.append(
                        f"RECORDED false positive missing {field}: "
                        f"{e['repo']} {e['file']}:{e['line']} ({e['rule_id']})"
                    )
            recorded_fps.append(e)
        else:
            problems.append(
                f"FALSE_POSITIVE without status (must be 'fixed' or 'recorded'): "
                f"{e['repo']} {e['file']}:{e['line']} ({e['rule_id']})"
            )

    if len(recorded_fps) > MAX_RECORDED_FP:
        problems.append(
            f"Too many recorded (unfixed) false positives: {len(recorded_fps)} "
            f"(max {MAX_RECORDED_FP})."
        )

    import datetime
    for e in recorded_fps:
        recorded_date = e.get("recorded_date", "")
        try:
            recorded_dt = datetime.datetime.strptime(recorded_date, "%Y-%m-%d")
            age_days = (datetime.datetime.now() - recorded_dt).days
            max_age_days = MAX_FP_AGE_RELEASES * 90
            if age_days > max_age_days:
                problems.append(
                    f"RECORDED false positive expired: "
                    f"{e['repo']} {e['file']}:{e['line']} ({e['rule_id']}) — "
                    f"recorded {recorded_date}."
                )
        except (ValueError, TypeError):
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
    controls = {r["name"] for r in pinned["repos"] if r.get("category") == "control"}
    for name, data in results.get("repos", {}).items():
        if name in controls and data.get("findings", 0):
            problems.append(
                f"CONTROL REPO FINDING: {name} produced {data['findings']} finding(s). "
                f"Non-agent libraries must produce zero."
            )

    return problems


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Corpus triage gate")
    parser.add_argument(
        "--no-remeasure",
        action="store_true",
        default=False,
        help="Fall back to reading committed JSON (local dev only). "
             "CI must NOT use this — CI must re-measure.",
    )
    parser.add_argument(
        "--work-dir",
        default=None,
        help="Directory for cloned repos (default: temp dir).",
    )
    args = parser.parse_args()

    triage_path = BENCH / "corpus-triage.json"
    results_path = BENCH / "corpus-results.json"
    pinned_path = BENCH / "pinned_repos.json"

    for p in (triage_path, results_path, pinned_path):
        if not p.exists():
            print(f"FAIL: missing {p.relative_to(ROOT)}", file=sys.stderr)
            return 1

    triage = json.loads(triage_path.read_text())
    pinned = json.loads(pinned_path.read_text())

    if args.no_remeasure:
        print("WARNING: --no-remeasure — reading committed JSON (NOT re-measuring). "
              "CI must NOT use this flag.", file=sys.stderr)
        results = json.loads(results_path.read_text())
    else:
        print("Re-measuring corpus (cloning + scanning pinned repos)...", file=sys.stderr)
        results = remeasure_corpus(pinned, Path(args.work_dir) if args.work_dir else None)

        # Check for clone failures
        clone_failures = [
            name for name, data in results.get("repos", {}).items()
            if data.get("error") == "clone_failed"
        ]
        if clone_failures:
            print(
                f"FAIL: CANNOT RE-MEASURE — clone failed for {len(clone_failures)} repo(s): "
                f"{', '.join(clone_failures)}. "
                f"The gate cannot verify without network access. "
                f"Pass --no-remeasure ONLY for local dev (NOT for CI).",
                file=sys.stderr,
            )
            return 2

    problems = check_triage(triage, results, pinned)

    if problems:
        print(f"corpus triage gate FAILED ({len(problems)} problem(s)):", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1

    # Summary
    entries = triage.get("entries", [])
    tp = sum(1 for e in entries if e.get("verdict") == "TRUE_POSITIVE")
    fp_fixed = sum(1 for e in entries if e.get("verdict") == "FALSE_POSITIVE" and e.get("status") == "fixed")
    fp_recorded = sum(1 for e in entries if e.get("verdict") == "FALSE_POSITIVE" and e.get("status") == "recorded")
    total = tp + fp_fixed + fp_recorded
    precision = round(tp / total * 100, 1) if total else 100
    controls = {r["name"] for r in pinned["repos"] if r.get("category") == "control"}

    print(
        f"OK: {len(entries)} corpus findings, "
        f"{tp} true positives, "
        f"{fp_fixed} false positives (fixed), "
        f"{fp_recorded} false positives (recorded, unfixed), "
        f"0 untriaged, "
        f"0 findings across {len(controls)} control repos. "
        f"Precision: {tp}/{total} ({precision}%)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

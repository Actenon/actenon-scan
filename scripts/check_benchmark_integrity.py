#!/usr/bin/env python3
"""Benchmark integrity check: prevents silent fixture rewrites and score inflation.

Fails if tests/benchmark/**/* is modified in the same PR as an increase in
any score in tests/benchmark/baseline.json, UNLESS the PR description contains
a section headed exactly:

    ## Fixture change justification
    Fixture changed: <path>
    Reason: <why>
    Score against OLD fixture: <n>/<m>
    Score against NEW fixture: <n>/<m>

Usage (in CI):
    python scripts/check_benchmark_integrity.py

Exits 0 if OK, 1 if the integrity check fails.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCHMARK_DIR = REPO_ROOT / "tests" / "benchmark"
FIXTURE_LOCK = BENCHMARK_DIR / "fixture-lock.json"
BASELINE_FILE = BENCHMARK_DIR / "baseline.json"

REQUIRED_SECTION_HEADER = "## Fixture change justification"
REQUIRED_FIELDS = [
    "Fixture changed:",
    "Reason:",
    "Score against OLD fixture:",
    "Score against NEW fixture:",
]


def get_changed_files() -> set[str]:
    """Get the set of files changed in this PR vs the base branch."""
    # In GitHub Actions, use GITHUB_BASE_REF or the event payload
    base_ref = os.environ.get("GITHUB_BASE_REF", "")
    if base_ref:
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", f"origin/{base_ref}...HEAD"],
                capture_output=True, text=True, check=True, cwd=REPO_ROOT,
            )
            return set(result.stdout.strip().split("\n")) if result.stdout.strip() else set()
        except subprocess.CalledProcessError:
            pass

    # Fallback: diff against HEAD~1
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD~1"],
            capture_output=True, text=True, check=True, cwd=REPO_ROOT,
        )
        return set(result.stdout.strip().split("\n")) if result.stdout.strip() else set()
    except subprocess.CalledProcessError:
        return set()


def get_pr_body() -> str:
    """Get the PR body from the GitHub API or environment."""
    # Direct PR body environment variable (most reliable in GitHub Actions)
    pr_body = os.environ.get("PR_BODY", "")
    if pr_body:
        return pr_body

    # Fallback: read from event payload file
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    if event_path and Path(event_path).exists():
        try:
            event = json.loads(Path(event_path).read_text())
            return event.get("pull_request", {}).get("body", "") or ""
        except (json.JSONDecodeError, KeyError):
            pass
    return ""


def benchmark_files_changed(changed: set[str]) -> bool:
    """Check if any benchmark fixture files were changed."""
    for f in changed:
        if f.startswith("tests/benchmark/"):
            return True
    return False


def baseline_increased(changed: set[str]) -> bool:
    """Check if baseline.json was changed and scores increased."""
    if "tests/benchmark/baseline.json" not in changed:
        return False

    try:
        result = subprocess.run(
            ["git", "diff", "HEAD~1", "--", "tests/benchmark/baseline.json"],
            capture_output=True, text=True, check=True, cwd=REPO_ROOT,
        )
        diff = result.stdout
        # Check for added lines with higher numbers
        for line in diff.split("\n"):
            if line.startswith("+") and not line.startswith("+++"):
                # Look for increased numbers
                if '"recall"' in line or '"precision"' in line or '"soundness"' in line:
                    return True
    except subprocess.CalledProcessError:
        pass
    return False


def has_justification(pr_body: str) -> bool:
    """Check if the PR body contains the required justification section."""
    if not pr_body:
        return False

    # Find the section
    idx = pr_body.find(REQUIRED_SECTION_HEADER)
    if idx == -1:
        return False

    # Extract the section (until the next ## heading or end)
    section_start = idx + len(REQUIRED_SECTION_HEADER)
    rest = pr_body[section_start:]
    next_heading = rest.find("\n## ")
    if next_heading != -1:
        section = rest[:next_heading]
    else:
        section = rest

    # Check all required fields are present
    for field in REQUIRED_FIELDS:
        if field not in section:
            return False

    return True


def compute_fixture_digest() -> dict[str, str]:
    """Compute SHA-256 digests for all benchmark fixtures."""
    digests = {}
    for path in sorted(BENCHMARK_DIR.rglob("*")):
        if path.is_file() and path.name != "fixture-lock.json" and path.name != "baseline.json":
            rel = str(path.relative_to(REPO_ROOT))
            digests[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digests


def update_fixture_lock() -> None:
    """Write the current fixture digests to fixture-lock.json."""
    digests = compute_fixture_digest()
    FIXTURE_LOCK.write_text(json.dumps(digests, indent=2, sort_keys=True) + "\n")


def check_fixture_lock() -> tuple[bool, list[str]]:
    """Check if any fixtures changed since the last lock update.

    Returns (in_sync, changed_files).
    """
    if not FIXTURE_LOCK.exists():
        return False, ["(no lock file)"]

    locked = json.loads(FIXTURE_LOCK.read_text())
    current = compute_fixture_digest()

    changed = []
    for path, digest in current.items():
        if path not in locked:
            changed.append(f"{path} (new)")
        elif locked[path] != digest:
            changed.append(path)

    for path in locked:
        if path not in current:
            changed.append(f"{path} (deleted)")

    return len(changed) == 0, changed


def main() -> int:
    parser_check = "--check" in sys.argv
    parser_update = "--update-lock" in sys.argv

    if parser_update:
        update_fixture_lock()
        print(f"Fixture lock updated: {FIXTURE_LOCK}")
        return 0

    # Check fixture lock
    in_sync, changed = check_fixture_lock()
    if not in_sync:
        print("WARNING: benchmark fixtures have changed since last lock update:")
        for f in changed:
            print(f"  {f}")
        print("Run: python scripts/check_benchmark_integrity.py --update-lock")
        print("Then commit fixture-lock.json alongside the fixture changes.")
    else:
        print("OK: fixture lock in sync")

    # Check for benchmark gaming
    changed_files = get_changed_files()

    if not benchmark_files_changed(changed_files) and not baseline_increased(changed_files):
        print("OK: no benchmark files changed")
        return 0

    # Benchmark files were changed — check for justification
    pr_body = get_pr_body()

    if has_justification(pr_body):
        print("OK: fixture change justification found in PR body")
        return 0

    print("FAIL: benchmark files were changed but the PR body does not contain")
    print("the required justification section. Add the following to your PR description:")
    print()
    print(REQUIRED_SECTION_HEADER)
    for field in REQUIRED_FIELDS:
        print(f"{field} <...>")
    print()
    print("This rule exists because a benchmark fixture was silently rewritten")
    print("to move a score without fixing the detector. See CONTRIBUTING.md.")
    return 1 if parser_check else 0


if __name__ == "__main__":
    sys.exit(main())

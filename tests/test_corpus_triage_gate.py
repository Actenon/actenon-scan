"""Work Order 1.10, Item 1 — Tests for the corpus triage gate's three FP states.

Tests that the gate:
  1. Permits a FIXED false positive (with regression fixture)
  2. Permits a RECORDED false positive (with tracking issue, under cap/age)
  3. Fails a RECORDED false positive that has expired (over age limit)
  4. Fails a FALSE_POSITIVE without a status field
  5. Fails when too many recorded FPs exist (over cap)
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check_corpus_triage.py"
BENCH = REPO_ROOT / "tests" / "benchmark"


def _run_gate(triage: dict, results: dict, pinned: dict, tmp_path: Path) -> tuple[int, str, str]:
    """Run the gate with the given triage/results/pinned data.

    Writes the data to temp files and runs the script.
    """
    bench = tmp_path / "benchmark"
    bench.mkdir()
    (bench / "corpus-triage.json").write_text(json.dumps(triage, indent=2))
    (bench / "corpus-results.json").write_text(json.dumps(results, indent=2))
    (bench / "pinned_repos.json").write_text(json.dumps(pinned, indent=2))

    # Run the gate script with the temp bench dir patched in
    result = subprocess.run(
        [sys.executable, "-c", f"""
import sys
from pathlib import Path
sys.path.insert(0, "{REPO_ROOT}")
import scripts.check_corpus_triage as gate
gate.BENCH = Path("{bench}")
sys.exit(gate.main())
"""],
        capture_output=True, text=True, timeout=30,
    )
    return result.returncode, result.stdout, result.stderr


def _make_base_triage() -> dict:
    """Minimal triage with one TRUE_POSITIVE entry."""
    return {
        "_comment": "test",
        "totals": {"findings": 1, "true_positives": 1, "false_positives": 0},
        "entries": [
            {
                "repo": "test/repo",
                "sha": "abc123",
                "file": "test.py",
                "line": 1,
                "rule_id": "TEST-RULE",
                "confidence": "high",
                "verdict": "TRUE_POSITIVE",
                "rationale": "test",
            }
        ],
        "corrections": [],
    }


def _make_base_results() -> dict:
    """Minimal results matching the triage."""
    return {
        "_comment": "test",
        "total_findings": 1,
        "findings": [
            {"repo": "test/repo", "file": "test.py", "line": 1, "rule_id": "TEST-RULE"}
        ],
        "repos": {},
    }


def _make_base_pinned() -> dict:
    """Minimal pinned repos with no controls."""
    return {"repos": [{"repo": "test/repo", "name": "repo", "category": "framework", "sha": "abc123"}]}


def _add_fp_entry(triage: dict, status: str, **kwargs) -> dict:
    """Add a FALSE_POSITIVE entry with the given status."""
    entry = {
        "repo": "test/repo",
        "sha": "abc123",
        "file": "fp.py",
        "line": 99,
        "rule_id": "FP-RULE",
        "confidence": "high",
        "verdict": "FALSE_POSITIVE",
        "rationale": "test false positive",
        "status": status,
    }
    entry.update(kwargs)
    triage["entries"].append(entry)
    return triage


def test_gate_passes_with_fixed_fp(tmp_path: Path):
    """A FIXED false positive with a regression fixture is permitted."""
    triage = _make_base_triage()
    _add_fp_entry(triage, "fixed", regression_fixture="tests/benchmark/precision/p99_fp.py")
    results = _make_base_results()
    pinned = _make_base_pinned()
    code, stdout, stderr = _run_gate(triage, results, pinned, tmp_path)
    assert code == 0, f"Expected exit 0, got {code}.\nstderr: {stderr}"
    assert "1 false positives (fixed)" in stdout


def test_gate_passes_with_recorded_fp(tmp_path: Path):
    """A RECORDED false positive with tracking issue, under cap/age, is permitted."""
    triage = _make_base_triage()
    _add_fp_entry(triage, "recorded",
                  recorded_date="2026-07-29",
                  tracking_issue=999,
                  rationale="Known FP: interprocedural limitation")
    results = _make_base_results()
    pinned = _make_base_pinned()
    code, stdout, stderr = _run_gate(triage, results, pinned, tmp_path)
    assert code == 0, f"Expected exit 0, got {code}.\nstderr: {stderr}"
    assert "1 false positives (recorded, unfixed)" in stdout


def test_gate_fails_with_expired_recorded_fp(tmp_path: Path):
    """A RECORDED false positive older than the age limit fails."""
    triage = _make_base_triage()
    # Set the date to 2 years ago — well over the 9-month age limit
    _add_fp_entry(triage, "recorded",
                  recorded_date="2024-01-01",
                  tracking_issue=999,
                  rationale="Old FP that should have been fixed")
    results = _make_base_results()
    pinned = _make_base_pinned()
    code, stdout, stderr = _run_gate(triage, results, pinned, tmp_path)
    assert code == 1, f"Expected exit 1, got {code}.\nstdout: {stdout}"
    assert "expired" in stderr.lower()


def test_gate_fails_with_untagged_fp(tmp_path: Path):
    """A FALSE_POSITIVE without a status field fails."""
    triage = _make_base_triage()
    _add_fp_entry(triage, "")  # empty status
    # Remove the status field entirely
    triage["entries"][-1].pop("status", None)
    results = _make_base_results()
    pinned = _make_base_pinned()
    code, stdout, stderr = _run_gate(triage, results, pinned, tmp_path)
    assert code == 1, f"Expected exit 1, got {code}.\nstdout: {stdout}"
    assert "without status" in stderr


def test_gate_fails_with_too_many_recorded_fps(tmp_path: Path):
    """More than MAX_RECORDED_FP (5) recorded false positives fails."""
    triage = _make_base_triage()
    for i in range(6):  # 6 is over the cap of 5
        _add_fp_entry(triage, "recorded",
                      recorded_date="2026-07-29",
                      tracking_issue=100 + i,
                      rationale=f"FP #{i}")
    results = _make_base_results()
    pinned = _make_base_pinned()
    code, stdout, stderr = _run_gate(triage, results, pinned, tmp_path)
    assert code == 1, f"Expected exit 1, got {code}.\nstdout: {stdout}"
    assert "Too many recorded" in stderr


def test_gate_fails_with_fixed_fp_missing_fixture(tmp_path: Path):
    """A FIXED false positive without a regression_fixture fails."""
    triage = _make_base_triage()
    _add_fp_entry(triage, "fixed")  # no regression_fixture
    results = _make_base_results()
    pinned = _make_base_pinned()
    code, stdout, stderr = _run_gate(triage, results, pinned, tmp_path)
    assert code == 1, f"Expected exit 1, got {code}.\nstdout: {stdout}"
    assert "missing regression_fixture" in stderr

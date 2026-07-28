"""Work Order 1.9-Resume, Phase 0.3 — Tests for the hardened corpus verification script.

Tests that the script:
  - Passes when scan results match triage
  - Fails loudly when a repo is in triage but absent from scan output
  - Fails loudly when a repo is in scan output but absent from triage
  - Fails loudly when a finding appears (in scan but not in triage)
  - Fails loudly when a finding disappears (in triage but not in scan)

A name mismatch must never be reportable as drift, and drift must never
be hidden by a name mismatch.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "verify_corpus_scan.py"
BENCH = REPO_ROOT / "tests" / "benchmark"


def _make_scan_dir(tmp_path: Path, findings_by_repo: dict[str, list[dict]]) -> Path:
    """Create a scan directory with one JSON file per repo.

    ``findings_by_repo`` maps safe repo names (last path segment) to
    lists of finding dicts. Each finding dict needs at least ``file``,
    ``line``, ``rule_id`` keys.
    """
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    for safe_name, findings in findings_by_repo.items():
        data = {"findings": findings, "version": "1.3.0"}
        (scan_dir / f"{safe_name}.json").write_text(json.dumps(data))
    return scan_dir


def _run_verify(scan_dir: Path) -> tuple[int, str, str]:
    """Run verify_corpus_scan.py and return (exit_code, stdout, stderr)."""
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--scan-dir", str(scan_dir)],
        capture_output=True, text=True, timeout=30,
    )
    return result.returncode, result.stdout, result.stderr


def _get_triage_repos() -> set[str]:
    """Get the set of safe repo names from corpus-triage.json."""
    triage = json.loads((BENCH / "corpus-triage.json").read_text())
    return {e["repo"].split("/")[-1] for e in triage["entries"]}


def _get_pinned_safe_names() -> set[str]:
    """Get the set of all 25 safe repo names from pinned_repos.json."""
    pinned = json.loads((BENCH / "pinned_repos.json").read_text())
    return {r["repo"].split("/")[-1] for r in pinned["repos"]}


def _get_triage_findings_as_scan_format() -> dict[str, list[dict]]:
    """Get triage findings in the format the scan script expects, keyed by safe name."""
    triage = json.loads((BENCH / "corpus-triage.json").read_text())
    by_repo: dict[str, list[dict]] = {}
    for e in triage["entries"]:
        safe = e["repo"].split("/")[-1]
        by_repo.setdefault(safe, []).append({
            "file": e["file"],
            "line": e["line"],
            "rule_id": e["rule_id"],
        })
    return by_repo


@pytest.fixture
def all_repos_with_findings():
    """Fixture: scan dir with all 25 repos, findings matching triage exactly.

    Repos with no triage entries get empty findings lists.
    """
    import tempfile
    triage_findings = _get_triage_findings_as_scan_format()
    all_safe = _get_pinned_safe_names()
    findings_by_repo = {}
    for safe in all_safe:
        findings_by_repo[safe] = triage_findings.get(safe, [])
    return findings_by_repo


def test_verify_passes_when_scan_matches_triage(tmp_path: Path, all_repos_with_findings):
    """The script passes (exit 0) when scan results match triage exactly."""
    scan_dir = _make_scan_dir(tmp_path, all_repos_with_findings)
    code, stdout, stderr = _run_verify(scan_dir)
    assert code == 0, f"Expected exit 0, got {code}.\nstdout: {stdout}\nstderr: {stderr}"
    # The exact count may change as triage is updated; check for the
    # "OK: all" prefix and "findings match triage" suffix rather than
    # hard-coding the count.
    assert "OK: all" in stdout and "findings match triage" in stdout
    # Check for TP and FP in the precision line (count may vary)
    assert "TP /" in stdout and "FP =" in stdout


def test_verify_fails_when_repo_in_triage_but_absent_from_scan(tmp_path: Path, all_repos_with_findings):
    """Fails loudly when a repo with triage entries is missing from scan output.

    This is the 'disappeared' direction: a repo that should have findings
    is not scanned at all. Must be a hard error, not a silent 'disappeared'.
    """
    # Remove a repo that has triage entries (servers has 1 finding)
    del all_repos_with_findings["servers"]
    scan_dir = _make_scan_dir(tmp_path, all_repos_with_findings)
    code, stdout, stderr = _run_verify(scan_dir)
    assert code == 1, f"Expected exit 1, got {code}.\nstdout: {stdout}\nstderr: {stderr}"
    assert "repos in pinned_repos.json but not scanned" in stderr
    assert "modelcontextprotocol/servers" in stderr


def test_verify_fails_when_repo_in_scan_but_absent_from_pinned(tmp_path: Path, all_repos_with_findings):
    """Fails loudly when scan output contains a repo not in pinned_repos.json.

    This is the 'appeared' direction: an unexpected repo in the scan output.
    Must be a hard error, not a silent 'appeared'.
    """
    all_repos_with_findings["nonexistent-repo"] = []
    scan_dir = _make_scan_dir(tmp_path, all_repos_with_findings)
    code, stdout, stderr = _run_verify(scan_dir)
    assert code == 1, f"Expected exit 1, got {code}.\nstdout: {stdout}\nstderr: {stderr}"
    assert "repos in scan output but not in pinned_repos.json" in stderr
    assert "nonexistent-repo" in stderr


def test_verify_fails_when_finding_appeared(tmp_path: Path, all_repos_with_findings):
    """Fails loudly when a finding appears in scan but not in triage."""
    # Add a spurious finding to servers (which has 1 triage finding)
    all_repos_with_findings["servers"].append({
        "file": "src/spurious.ts",
        "line": 999,
        "rule_id": "FAKE-RULE",
    })
    scan_dir = _make_scan_dir(tmp_path, all_repos_with_findings)
    code, stdout, stderr = _run_verify(scan_dir)
    assert code == 1, f"Expected exit 1, got {code}.\nstdout: {stdout}\nstderr: {stderr}"
    assert "APPEARED findings" in stderr
    assert "src/spurious.ts" in stderr
    assert "FAKE-RULE" in stderr


def test_verify_fails_when_finding_disappeared(tmp_path: Path, all_repos_with_findings):
    """Fails loudly when a finding in triage is absent from scan."""
    # Remove the finding from servers (which has 1 triage finding)
    all_repos_with_findings["servers"] = []
    scan_dir = _make_scan_dir(tmp_path, all_repos_with_findings)
    code, stdout, stderr = _run_verify(scan_dir)
    assert code == 1, f"Expected exit 1, got {code}.\nstdout: {stdout}\nstderr: {stderr}"
    assert "DISAPPEARED findings" in stderr
    assert "src/memory/index.ts" in stderr


def test_verify_handles_name_conventions(tmp_path: Path, all_repos_with_findings):
    """Handles different scan-output naming conventions (last segment, underscore, dash)."""
    # Rename one file to use the underscore convention
    # "servers" -> "modelcontextprotocol_servers"
    triage = json.loads((BENCH / "corpus-triage.json").read_text())
    # Get a repo that has findings
    test_repo = "servers"
    full_name = "modelcontextprotocol/servers"
    underscore_name = full_name.replace("/", "_")

    findings = all_repos_with_findings.pop(test_repo)
    all_repos_with_findings[underscore_name] = findings

    scan_dir = _make_scan_dir(tmp_path, all_repos_with_findings)
    code, stdout, stderr = _run_verify(scan_dir)
    assert code == 0, f"Expected exit 0 with underscore naming, got {code}.\nstderr: {stderr}"

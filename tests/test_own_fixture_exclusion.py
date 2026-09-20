"""actenon-scan's own vulnerable fixtures must not become a user's findings.

Scanning a workspace that contains a clone of this repo produced 77 findings
of which 74 were this project's deliberately-unguarded test fixtures, and the
"most exposed" line pointed at tests/benchmark/recall/r10_no_validation_guard.py.
The repo's `.actenon-scan.json` only applies when the scan target IS the repo
root, so it did nothing here.

The fixtures are recognised by path wherever they appear, and confirmed by
checking that the tree they sit in really is an actenon-scan checkout — a
user's own tests/benchmark/ directory is not excluded. Exclusion is announced
with a count and is reversible with --include-fixtures; nothing is dropped
silently.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from actenon_scan.engine import is_own_fixture_path, scan_path
from actenon_scan.report.json_out import format_json
from actenon_scan.report.pretty import format_list, format_pretty

VULNERABLE = '''from agents import tool
import subprocess


@tool
def run_it(cmd):
    subprocess.run(cmd, shell=True)
'''


def _make_checkout(root: Path) -> None:
    """A minimal tree that looks like an actenon-scan checkout."""
    (root / "actenon_scan").mkdir(parents=True)
    (root / "actenon_scan" / "__init__.py").write_text("")
    (root / "pyproject.toml").write_text('[project]\nname = "actenon-scan"\n')


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """A workspace holding a clone of this repo plus the user's own code."""
    clone = tmp_path / "actenon-scan"
    _make_checkout(clone)
    # NOTE: tests/fixtures/** is already dropped by a pre-existing default
    # exclude glob in _collect_files, before any finding exists, so a file
    # there cannot appear in the excluded COUNT. The four below are the ones
    # that are actually scanned and then held aside.
    for rel in (
        "tests/benchmark/recall/r01.py",
        "tests/benchmark/soundness/s01.py",
        "tests/corpus/EXEC-SHELL/vulnerable/v01.py",
        "tests/challenge/c01.py",
    ):
        target = clone / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(VULNERABLE)

    mine = tmp_path / "my-app"
    mine.mkdir()
    (mine / "app.py").write_text(VULNERABLE)
    return tmp_path


def test_a_workspace_scan_reports_the_users_code_not_ours(workspace):
    result = scan_path(workspace)
    reported = {f.file for f in result.findings if not f.suppressed}
    assert reported == {"my-app/app.py"}
    assert len(result.excluded_fixture_findings) == 4


def test_the_exclusion_is_stated_with_a_count(workspace):
    out = format_pretty(scan_path(workspace))
    assert "4 finding(s) in actenon-scan's own test fixtures were excluded" in out
    assert "--include-fixtures to show" in out


def test_include_fixtures_puts_them_back(workspace):
    result = scan_path(workspace, include_fixtures=True)
    reported = {f.file for f in result.findings if not f.suppressed}
    assert len(reported) == 5
    assert result.excluded_fixture_findings == []


def test_exclusion_is_announced_in_list_and_json(workspace):
    result = scan_path(workspace)
    assert "own test fixtures were excluded" in format_list(result)
    block = json.loads(format_json(result))["excluded_fixtures"]
    assert block["count"] == 4
    assert block["show_with"] == "--include-fixtures"


def test_a_users_own_tests_benchmark_directory_is_not_excluded(tmp_path: Path):
    """The path shape alone is not enough — the tree must be this project."""
    mine = tmp_path / "their-project"
    (mine / "tests" / "benchmark" / "recall").mkdir(parents=True)
    (mine / "tests" / "benchmark" / "recall" / "r01.py").write_text(VULNERABLE)
    result = scan_path(tmp_path)
    assert result.excluded_fixture_findings == []
    assert len([f for f in result.findings if not f.suppressed]) == 1


def test_production_code_in_a_checkout_is_never_excluded(tmp_path: Path):
    clone = tmp_path / "actenon-scan"
    _make_checkout(clone)
    assert not is_own_fixture_path("actenon-scan/actenon_scan/cli.py", tmp_path)
    assert not is_own_fixture_path("actenon-scan/scripts/benchmark.py", tmp_path)
    assert is_own_fixture_path("actenon-scan/tests/benchmark/recall/r.py", tmp_path)


def test_headline_still_agrees_after_exclusion(workspace):
    """Excluding fixtures must not reintroduce the A4 inconsistency."""
    result = scan_path(workspace)
    assert result.capability_summary.review_required == result.consequential_action_count


def test_fixture_patterns_match_the_repos_own_exclude_config():
    """One answer to 'is this our fixture?', not two that can drift apart."""
    from actenon_scan.engine import _FIXTURE_DIR_PATTERNS

    config = Path(__file__).resolve().parent.parent / ".actenon-scan.json"
    excluded = json.loads(config.read_text())["exclude"]
    from_config = {tuple(g.replace("/**", "").split("/")) for g in excluded}
    assert set(_FIXTURE_DIR_PATTERNS) == from_config

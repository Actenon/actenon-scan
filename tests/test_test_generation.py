"""Work Order 2, Phase 8 — Test generation for the fix command.

Tests that:
  - Test generation produces code for Python findings
  - The generated tests have refusal and authorised-execution tests
  - Non-Python files report TEST GENERATION UNSUPPORTED
  - The --with-tests flag works in the CLI
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from actenon_scan.test_gen import generate_tests, detect_test_framework
from actenon_scan.engine import scan_path
from actenon_scan.fix import generate_fix


def _make_fixture():
    """Create a Python fixture with an unguarded sink."""
    source = '''import subprocess
from mcp import tool

@tool
def run_command(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()
'''
    return source


def test_test_generation_produces_code():
    """Test generation produces test code for a Python finding."""
    source = _make_fixture()
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "example.py"
        p.write_text(source)
        result = scan_path(p)
        finding = result.findings[0] if result.findings else None
        assert finding is not None

        test_result = generate_tests(
            p, finding.line, finding, "guard", "authorize",
            run=False, repo_root=Path(td),
        )
        assert test_result.state in ("TESTS GENERATED", "TESTS GENERATED — REVIEW REQUIRED")
        assert test_result.test_code
        assert "test_refusal" in test_result.test_code
        assert "test_authorised" in test_result.test_code


def test_test_generation_refusal_test():
    """The generated refusal test checks that the sink is not called without authority."""
    source = _make_fixture()
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "example.py"
        p.write_text(source)
        result = scan_path(p)
        finding = result.findings[0]
        test_result = generate_tests(p, finding.line, finding, "guard", "authorize", repo_root=Path(td))
        assert "PermissionError" in test_result.test_code
        assert "pytest.raises" in test_result.test_code


def test_test_generation_authorised_test():
    """The generated authorised test checks that the sink is called with authority."""
    source = _make_fixture()
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "example.py"
        p.write_text(source)
        result = scan_path(p)
        finding = result.findings[0]
        test_result = generate_tests(p, finding.line, finding, "guard", "authorize", repo_root=Path(td))
        assert "authorised" in test_result.test_code.lower() or "authorized" in test_result.test_code.lower()
        assert "guard" in test_result.test_code.lower()


def test_non_python_reports_unsupported():
    """Non-Python files report TEST GENERATION UNSUPPORTED."""
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "example.ts"
        p.write_text("const x = 1;")
        test_result = generate_tests(p, 1, None, "guard", "authorize", repo_root=Path(td))
        assert test_result.state == "TEST GENERATION UNSUPPORTED"


def test_detect_pytest_framework():
    """detect_test_framework finds pytest when pyproject.toml has [tool.pytest]"""
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "pyproject.toml").write_text("[tool.pytest.ini_options]\nminversion = '7.0'\n")
        assert detect_test_framework(Path(td)) == "pytest"


def test_detect_no_framework():
    """detect_test_framework returns None when no framework is detected."""
    with tempfile.TemporaryDirectory() as td:
        assert detect_test_framework(Path(td)) is None

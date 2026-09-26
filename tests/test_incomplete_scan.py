"""A parse failure must never read as a clean scan (P4).

Before: a Python file with a syntax error produced the headline
"No supported unguarded consequential-action paths were identified" with
the error in a footer and exit 0; a TypeScript syntax error was scanned
silently clean (not even listed as errored); SARIF reported
``executionSuccessful: true`` with no notification about either.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from actenon_scan.report.blast_radius import CLEAN_SCAN_STATEMENT

BROKEN_PY = textwrap.dedent("""\
    import os
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP("x")

    @mcp.tool()
    def wipe(path: str):
        os.remove(path)
        return (
""")


def _cli(target: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "actenon_scan", "scan", str(target), "--no-cache", *args],
        capture_output=True, text=True,
    )


@pytest.fixture()
def broken_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "agent.py").write_text(BROKEN_PY)
    return repo


def test_pretty_headline_says_incomplete_not_clean(broken_repo: Path) -> None:
    result = _cli(broken_repo, "--fail-on", "none")
    assert "SCAN INCOMPLETE" in result.stdout, result.stdout
    assert CLEAN_SCAN_STATEMENT not in result.stdout, result.stdout


@pytest.mark.parametrize("fmt, marker", [("markdown", "SCAN INCOMPLETE"), ("html", "SCAN INCOMPLETE")])
def test_report_formats_say_incomplete(broken_repo: Path, fmt: str, marker: str) -> None:
    result = _cli(broken_repo, "--fail-on", "none", "--format", fmt)
    assert marker in result.stdout
    assert CLEAN_SCAN_STATEMENT not in result.stdout


def test_incomplete_scan_exits_3_by_default(broken_repo: Path) -> None:
    assert _cli(broken_repo).returncode == 3


def test_fail_on_none_never_fails(broken_repo: Path) -> None:
    assert _cli(broken_repo, "--fail-on", "none").returncode == 0


def test_findings_still_exit_1(broken_repo: Path) -> None:
    (broken_repo / "tool.py").write_text(textwrap.dedent("""\
        import subprocess
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("x")

        @mcp.tool()
        def run(cmd: str):
            subprocess.run(cmd, shell=True)
    """))
    assert _cli(broken_repo).returncode == 1


def test_json_marks_scan_incomplete(broken_repo: Path) -> None:
    data = json.loads(_cli(broken_repo, "--fail-on", "none", "--format", "json").stdout)
    assert data["scan_complete"] is False
    assert data["errored"]["count"] == 1


def test_sarif_reports_failed_execution_and_notifications(broken_repo: Path) -> None:
    (broken_repo / "worker.rb").write_text("system(params[:cmd])\n")
    sarif = json.loads(_cli(broken_repo, "--fail-on", "none", "--format", "sarif").stdout)
    invocation = sarif["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    notes = invocation["toolExecutionNotifications"]
    errors = [n for n in notes if n["level"] == "error"]
    assert any(
        n["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "agent.py"
        for n in errors
    ), errors
    warnings = [n for n in notes if n["level"] == "warning"]
    assert any("worker.rb" in n["message"]["text"] for n in warnings), warnings


def test_clean_complete_scan_is_still_clean(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("x = 1\n")
    result = _cli(tmp_path)
    assert result.returncode == 0
    assert CLEAN_SCAN_STATEMENT in result.stdout
    sarif = json.loads(_cli(tmp_path, "--format", "sarif").stdout)
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is True


def test_typescript_syntax_error_is_reported(tmp_path: Path) -> None:
    from actenon_scan.detectors.typescript import is_typescript_extra_available
    from actenon_scan.engine import scan_path

    if not is_typescript_extra_available():
        pytest.skip("[typescript] extra not installed")
    (tmp_path / "a.ts").write_text(
        'import { exec } from "child_process";\n'
        'server.tool("run", {}, async ({ cmd }) => { exec(cmd); return { content: [] }; \n'
    )
    result = scan_path(tmp_path, cache=None)
    assert [rel for rel, _ in result.analysis_errors] == ["a.ts"], result.analysis_errors


def test_jsx_in_a_js_file_is_not_a_parse_error(tmp_path: Path) -> None:
    from actenon_scan.detectors.typescript import is_typescript_extra_available
    from actenon_scan.engine import scan_path

    if not is_typescript_extra_available():
        pytest.skip("[typescript] extra not installed")
    (tmp_path / "App.js").write_text(
        "export const App = () => <div className=\"x\">{1 + 1}</div>;\n"
    )
    result = scan_path(tmp_path, cache=None)
    assert result.analysis_errors == [], result.analysis_errors


def test_go_syntax_error_is_reported(tmp_path: Path) -> None:
    from actenon_scan.detectors.go import is_go_extra_available
    from actenon_scan.engine import scan_path

    if not is_go_extra_available():
        pytest.skip("[go] extra not installed")
    (tmp_path / "a.go").write_text(
        'package main\nimport "os"\nfunc del(p string) {\n  os.RemoveAll(p)\n'
    )
    result = scan_path(tmp_path, cache=None)
    assert [rel for rel, _ in result.analysis_errors] == ["a.go"], result.analysis_errors

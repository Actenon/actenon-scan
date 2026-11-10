"""No output format may imply complete analysis when supported files were not analysed.

A supported file that fails to parse (a SyntaxError, code written for a newer or older Python
than the one Scan runs on, a decode error) is never analysed. Before this fix:
- the all-guarded summary printed only "N files scanned";
- the Markdown and HTML reports (Markdown is the PR-comment format) said "Supported source files
  were parsed and analysed" and, on a clean scan, dropped the unsupported-language notice;
- SARIF reported neither parse failures nor unsupported files.

These tests pin the disclosure in every format, and that findings and exit codes do not change.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from actenon_scan import cli
from actenon_scan.capability import Capability
from actenon_scan.engine import Finding, ScanResult
from actenon_scan.report import blast_radius as br
from actenon_scan.report.html_out import format_html
from actenon_scan.report.json_out import format_json
from actenon_scan.report.markdown_out import format_markdown
from actenon_scan.report.pretty import format_list, format_pretty
from actenon_scan.report.sarif import format_sarif

INCOMPLETE = "ANALYSIS INCOMPLETE"
UNQUALIFIED = "source files were parsed and analysed"
ERR = ("broken.py", "SyntaxError: Missing parentheses in call to 'print' (broken.py, line 5)")

TEXT_FORMATS = {
    "pretty": format_pretty,
    "list": format_list,
    "markdown": format_markdown,
    "html": format_html,
}


def _guarded() -> Capability:
    return Capability(
        file="tools.py", line=7, col=4, rule_id="DATA-DELETE-FILE", category="data_destruction",
        severity="high", call_text="os.remove(path)", state="GUARD_FOUND", guard_status="guarded",
    )


def _finding() -> Finding:
    return Finding(
        file="agent.py", line=9, col=4, rule_id="EXEC-SHELL", category="shell_execution",
        severity="high", confidence="high", description="Shell execution",
        call_text="subprocess.run(cmd, shell=True)", remediation="Guard it",
    )


def _result(*, caps=(), findings=(), errors=(), unsupported=()) -> ScanResult:
    return ScanResult(
        findings=list(findings), capabilities=list(caps), files_scanned=2,
        analysis_errors=list(errors), unsupported_files=list(unsupported),
    )


def _sarif_notes(result: ScanResult) -> list[dict]:
    run = json.loads(format_sarif(result))["runs"][0]
    return run["invocations"][0]["toolExecutionNotifications"]


SCENARIOS = {
    "all-guarded+parse-failure": {"caps": [_guarded()], "errors": [ERR]},
    "all-guarded+unsupported+parse-failure": {"caps": [_guarded()], "errors": [ERR], "unsupported": [("h.rs", "Rust")]},
    "clean-partial-scan": {"errors": [ERR]},
    "findings+parse-failure": {"caps": [_guarded()], "findings": [_finding()], "errors": [ERR]},
}


# -- shared statement ------------------------------------------------------------------------------


def test_statement_is_absent_for_a_complete_scan():
    result = _result(caps=[_guarded()])
    assert br.analysis_incomplete_statement(result) is None
    assert br.clean_scan_limitations(result) == br.CLEAN_SCAN_LIMITATIONS


def test_statement_counts_files_and_names_repository_analysis_failure():
    result = _result(errors=[ERR, ("b.py", "UnicodeDecodeError"), (br.REPOSITORY_ANALYSIS_ERROR, "boom")])
    statement = br.analysis_incomplete_statement(result)
    assert statement.startswith("ANALYSIS INCOMPLETE: 2 supported file(s) could not be parsed")
    assert "repository-level (cross-file) analysis failed" in statement
    assert br.parse_failures(result) == [ERR, ("b.py", "UnicodeDecodeError")]


def test_qualified_limitations_replace_the_unqualified_claim():
    limitations = br.clean_scan_limitations(_result(errors=[ERR]))
    assert UNQUALIFIED not in limitations
    assert "1 supported file(s) could not be parsed and were not analysed" in limitations


# -- every format, every scenario ------------------------------------------------------------------


@pytest.mark.parametrize("scenario", SCENARIOS)
@pytest.mark.parametrize("fmt", TEXT_FORMATS)
def test_text_formats_disclose_the_failed_file_and_never_claim_full_parsing(scenario, fmt):
    out = TEXT_FORMATS[fmt](_result(**SCENARIOS[scenario]))
    assert INCOMPLETE in out
    assert "broken.py" in out
    assert UNQUALIFIED not in out


@pytest.mark.parametrize("fmt", TEXT_FORMATS)
def test_text_formats_disclose_unsupported_files_on_an_all_guarded_scan(fmt):
    out = TEXT_FORMATS[fmt](_result(caps=[_guarded()], unsupported=[("h.rs", "Rust")]))
    assert "NOT scanned" in out and "Rust" in out
    assert INCOMPLETE not in out  # unsupported languages have their own notice


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_sarif_reports_each_failed_file_as_an_error_notification(scenario):
    result = _result(**SCENARIOS[scenario])
    notes = _sarif_notes(result)
    file_notes = [n for n in notes if n.get("descriptor", {}).get("id") == "file-not-analysed"]
    assert len(file_notes) == 1 and file_notes[0]["level"] == "error"
    assert file_notes[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "broken.py"
    assert any(n["level"] == "error" and INCOMPLETE in n["message"]["text"] for n in notes)
    driver = json.loads(format_sarif(result))["runs"][0]["tool"]["driver"]
    assert driver["properties"]["analysis_error_count"] == 1


def test_sarif_reports_unsupported_languages_and_repository_failure():
    result = _result(unsupported=[("a.rs", "Rust"), ("b.rs", "Rust")], errors=[(br.REPOSITORY_ANALYSIS_ERROR, "x")])
    notes = _sarif_notes(result)
    assert any(n["level"] == "warning" and "2 Rust file(s)" in n["message"]["text"] for n in notes)
    assert any(n.get("descriptor", {}).get("id") == "repository-analysis-failed" for n in notes)
    assert json.loads(format_sarif(result))["runs"][0]["tool"]["driver"]["properties"]["unsupported_file_count"] == 2


def test_complete_scan_has_no_incomplete_wording_or_error_notifications():
    result = _result(caps=[_guarded()])
    for fmt, render in TEXT_FORMATS.items():
        out = render(result)
        assert INCOMPLETE not in out and "Not analysed" not in out, fmt
    assert all(n["level"] == "note" for n in _sarif_notes(result))


def test_json_already_discloses_and_is_unchanged_in_shape():
    data = json.loads(format_json(_result(caps=[_guarded()], errors=[ERR], unsupported=[("h.rs", "Rust")])))
    assert data["errored"]["count"] == 1 and data["errored"]["files"][0]["file"] == "broken.py"
    assert data["unsupported"]["count"] == 1


# -- end to end: real files, real parser, the CLI ---------------------------------------------------

GUARDED_TOOL = '''import os
from mcp import tool


@tool
def guarded(path: str) -> None:
    authorize(path)
    os.remove(path)


def authorize(path: str) -> None:
    if not path.startswith("/tmp/"):
        raise PermissionError(path)
'''

PY2_FILE = 'from mcp import tool\n\n@tool\ndef publish(repo):\n    print "legacy"\n'
PEP758_FILE = 'def f():\n    try:\n        pass\n    except ValueError, TypeError:\n        pass\n'


def _project(tmp_path: Path, *, broken: str | None = PY2_FILE, rust: bool = False) -> Path:
    (tmp_path / "tools.py").write_text(GUARDED_TOOL)
    (tmp_path / ".actenon-scan.json").write_text('{"guard_patterns": ["authorize"]}')
    if broken is not None:
        (tmp_path / "broken.py").write_text(broken)
    if rust:
        (tmp_path / "helper.rs").write_text("fn main() {}\n")
    return tmp_path


def _cli(project: Path, capsys, monkeypatch, *args: str) -> tuple[int, str]:
    monkeypatch.chdir(project)
    code = cli.main(["scan", ".", "--config", ".actenon-scan.json", *args])
    return code, capsys.readouterr().out


@pytest.mark.parametrize("fmt", ["pretty", "list", "markdown", "html", "sarif", "json"])
def test_all_guarded_repository_with_a_parse_failure_end_to_end(tmp_path, capsys, monkeypatch, fmt):
    _, out = _cli(_project(tmp_path, rust=True), capsys, monkeypatch, "--format", fmt)
    assert "broken.py" in out
    assert UNQUALIFIED not in out
    if fmt != "json":
        assert INCOMPLETE in out
        assert "Rust" in out


def test_findings_and_exit_code_do_not_change_when_a_file_fails_to_parse(tmp_path, capsys, monkeypatch):
    complete = tmp_path / "complete"
    partial = tmp_path / "partial"
    complete.mkdir()
    partial.mkdir()
    code_a, out_a = _cli(_project(complete, broken=None), capsys, monkeypatch, "--format", "json")
    code_b, out_b = _cli(_project(partial), capsys, monkeypatch, "--format", "json")
    a, b = json.loads(out_a), json.loads(out_b)
    assert code_a == code_b
    assert a["findings"] == b["findings"] and a["capabilities"] == b["capabilities"]
    assert (a["errored"]["count"], b["errored"]["count"]) == (0, 1)


def test_partial_multi_file_scan_discloses_the_file_that_failed(tmp_path, capsys, monkeypatch):
    project = _project(tmp_path)
    monkeypatch.chdir(project)
    cli.main(["scan", "tools.py", "broken.py", "--config", ".actenon-scan.json"])
    out = capsys.readouterr().out
    assert INCOMPLETE in out and "broken.py" in out


@pytest.mark.skipif(sys.version_info >= (3, 14), reason="PEP 758 syntax parses on Python 3.14+")
def test_code_for_a_newer_python_is_disclosed_not_silently_skipped(tmp_path, capsys, monkeypatch):
    _, out = _cli(_project(tmp_path, broken=PEP758_FILE), capsys, monkeypatch, "--format", "markdown")
    assert INCOMPLETE in out
    assert "`broken.py`: SyntaxError" in out

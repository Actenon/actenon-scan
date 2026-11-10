"""The analysis-error disclosure explains a Python-version mismatch and how to rerun.

Scan parses Python with the running interpreter's ``ast``. A project that declares
``requires-python = ">=3.14"`` and uses 3.14 syntax (PEP 758 ``except A, B:``) is all SyntaxErrors
when Scan runs on 3.12 or on the 3.10 that a bare ``uvx actenon-scan`` can pick. The report must keep
listing every error and add one line saying why and how to rerun, and nothing else may change.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from actenon_scan import cache as cache_mod
from actenon_scan import cli
from actenon_scan.cache import FileCache, compute_cache_key
from actenon_scan.engine import Finding, ScanResult
from actenon_scan.report import python_version as pv
from actenon_scan.report.pretty import format_list, format_pretty

PEP758 = "SyntaxError: multiple exception types must be parenthesized (tools.py, line 10)"
RUNNING = (3, 12, 13)
NEXT_MINOR = f"{sys.version_info[0]}.{sys.version_info[1] + 1}"

# A SyntaxError on every Python version, so the end-to-end tests do not depend on the CI interpreter.
BROKEN = "def broken(:\n    pass\n"
SHELL_TOOL = '''import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("shell")


@mcp.tool()
def run(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
'''


def _pyproject(root: Path, requires: str | None) -> Path:
    body = '[project]\nname = "demo"\nversion = "0.1.0"\n'
    if requires is not None:
        body += f'requires-python = "{requires}"\n'
    (root / "pyproject.toml").write_text(body)
    return root


def _errors(n: int, err: str = PEP758) -> list[tuple[str, str]]:
    return [(f"agent/m{i}.py", err) for i in range(n)]


def _finding() -> Finding:
    return Finding(
        file="agent/ok.py", line=8, col=4, rule_id="DATA-DELETE-OS", category="data_deletion",
        severity="high", confidence="high", description="d", call_text="os.rmdir(path)", remediation="r",
    )


def _hint(tmp_path: Path, errors, requires: str | None = ">=3.14", **kw) -> str | None:
    _pyproject(tmp_path, requires)
    return pv.python_version_hint(errors, tmp_path, running=RUNNING, **kw)


# -- when the line appears ---------------------------------------------------------------------------


def test_mismatch_gives_the_rerun_line(tmp_path):
    hint = _hint(tmp_path, _errors(54))
    assert hint == (
        f"All 54 are SyntaxErrors under Python 3.12, and pyproject.toml requires Python >=3.14. "
        f"Rerun with actenon-scan installed on Python 3.14: actenon-scan scan {tmp_path}"
    )


def test_under_uvx_the_rerun_pins_the_interpreter(tmp_path):
    hint = _hint(tmp_path, _errors(54), command="uvx actenon-scan")
    assert hint.endswith(f"Rerun with: uvx --python 3.14 actenon-scan scan {tmp_path}")


def test_the_rerun_reuses_the_target_as_typed_and_quotes_it(tmp_path, monkeypatch):
    project = tmp_path / "my project"
    project.mkdir()
    _pyproject(project, ">=3.14")
    monkeypatch.chdir(project)
    assert pv.python_version_hint(_errors(1), ".", running=RUNNING, command="uvx actenon-scan").endswith(
        "uvx --python 3.14 actenon-scan scan ."
    )
    hint = pv.python_version_hint(_errors(1), str(project), running=RUNNING, command="uvx actenon-scan")
    assert hint.startswith("This is a SyntaxError under Python 3.12")
    assert hint.endswith(f"scan '{project}'")


def test_most_but_not_all_errors_says_how_many(tmp_path):
    errors = _errors(3) + [("agent/x.py", "RecursionError: maximum recursion depth exceeded")]
    assert _hint(tmp_path, errors).startswith("3 of 4 are SyntaxErrors under Python 3.12")


def test_pyproject_in_a_parent_directory_is_used(tmp_path):
    _pyproject(tmp_path, ">=3.14")
    sub = tmp_path / "src" / "agent"
    sub.mkdir(parents=True)
    assert pv.python_version_hint(_errors(2), sub, running=RUNNING) is not None


# -- when it does not --------------------------------------------------------------------------------


def test_no_requires_python_no_line(tmp_path):
    assert _hint(tmp_path, _errors(54), requires=None) is None


def test_no_pyproject_no_line(tmp_path):
    assert pv.python_version_hint(_errors(54), tmp_path, running=RUNNING) is None


def test_errors_that_are_not_syntax_errors_no_line(tmp_path):
    errors = _errors(5, "UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff")
    errors += [("<repository-analysis>", "RecursionError: maximum recursion depth exceeded")]
    assert _hint(tmp_path, errors) is None


def test_half_or_fewer_syntax_errors_no_line(tmp_path):
    errors = _errors(2) + _errors(2, "OSError: [Errno 13] Permission denied")
    assert _hint(tmp_path, errors) is None


def test_syntax_errors_outside_python_files_do_not_count(tmp_path):
    assert _hint(tmp_path, [("web/a.ts", "SyntaxError: Unexpected token")]) is None


def test_running_python_satisfies_requires_python_no_line(tmp_path):
    assert _hint(tmp_path, _errors(54), requires=">=3.10") is None
    assert _hint(tmp_path, _errors(54), requires=">=3.12,<3.15") is None


def test_unparsable_pyproject_no_line(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project\nrequires-python = '>=3.14'\n")
    assert pv.python_version_hint(_errors(54), tmp_path, running=RUNNING) is None


def test_no_scan_target_no_line():
    assert pv.python_version_hint(_errors(54), None, running=RUNNING) is None


def test_pyproject_beyond_the_repository_root_is_not_used(tmp_path):
    _pyproject(tmp_path, ">=3.14")
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    assert pv.python_version_hint(_errors(54), repo, running=RUNNING) is None


# -- requires-python parsing -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("spec", "needed"),
    [
        (">=3.14", "3.14"),
        (">= 3.13, <4", "3.13"),
        ("~=3.13", "3.13"),
        ("==3.14.*", "3.14"),
        ("==4.*", "4.0"),
        (">3.13", "3.14"),
        (">3.12.13", "3.12.14"),
        (">=3.12.20", "3.12.20"),
        ("==3.14.2", "3.14.2"),
        ("~=3.14.2", "3.14.2"),
        (">=3.11,>=3.14", "3.14"),
        (">=3.14,<3.15", "3.14"),
        (">=3.10", None),
        (">=3.12", None),
        # PEP 440: 3.12.13 > 3.12 (= 3.12.0), so the running Python already satisfies this.
        (">3.12", None),
        ("<3.14", None),
        ("!=3.12.*", None),
        ("==3.*", None),
        (">=3", None),
        ("", None),
        ("python3.14", None),
        (">=3.14; os_name == 'nt'", None),
        ("===3.14", None),
        (">=3.14,", None),
        (">=3.14.0.1", None),
        (">=3.14.*", None),
        ("~=3", None),
    ],
)
def test_python_needed(spec, needed):
    assert pv.python_needed(spec, RUNNING) == needed


@pytest.mark.parametrize(
    ("spec", "needed"),
    [
        # The owner's review repros: the lower bound's series is excluded, so nothing is suggested.
        (">=3.14,!=3.14.*", None),
        (">=3.13,!=3.13.*,!=3.14.*", None),
        # Control: the exclusion does not touch the suggestion.
        (">=3.14,!=3.15.*", "3.14"),
        (">=3.14,!=3.13.*", "3.14"),
    ],
)
def test_python_needed_never_suggests_an_excluded_version(spec, needed):
    assert pv.python_needed(spec, (3, 12)) == needed


@pytest.mark.parametrize(
    "spec",
    [
        # `uvx --python 3.14` may pick any 3.14.x, so a bound inside the series rules out "3.14".
        ">=3.14,<3.14.5",
        ">=3.14,<=3.14",
        ">=3.14,<3.14",
        ">=3.14,!=3.14.0",
        ">=3.14,!=3.14.1",
        ">=3.14,<3.13",
        ">=3.12.20,!=3.12.20",
        ">=3.12.20,!=3.12.*",
        "==3.14",
    ],
)
def test_python_needed_suggests_nothing_it_cannot_show_satisfies_every_clause(spec):
    assert pv.python_needed(spec, RUNNING) is None


def test_every_suggestion_satisfies_the_whole_spec():
    # Property check over a grid of specs: whatever is suggested must be admitted by every clause.
    bounds = ["3.13", "3.14", "3.14.2", "3.15"]
    extras = ["", ",!=3.14.*", ",!=3.13.*", ",<3.15", ",<3.14.5", ",<=3.14", ",!=3.14.2", ",!=3.15.*"]
    for op in (">=", ">", "~=", "=="):
        for bound in bounds:
            for extra in extras:
                spec = f"{op}{bound}{extra}"
                needed = pv.python_needed(spec, RUNNING)
                if needed is None:
                    continue
                parts = tuple(int(p) for p in needed.split("."))
                clauses = pv._parse_spec(spec)
                if len(parts) == 2:
                    assert all(pv._admits_series(parts, c) for c in clauses), spec
                    releases = [(*parts, z) for z in range(0, 40)]
                else:
                    releases = [parts]
                for release in releases:
                    assert all(pv._admits(release, c) for c in clauses), (spec, release)


def test_exclusive_bound_depends_on_the_running_patch_release():
    assert pv.python_needed(">3.12", (3, 11, 9)) == "3.13"
    assert pv.python_needed(">3.12", (3, 12, 0)) == "3.13"
    assert pv.python_needed(">3.12", (3, 12, 1)) is None


def test_excluded_suggestion_means_no_report_line(tmp_path):
    assert _hint(tmp_path, _errors(54), requires=">=3.14,!=3.14.*") is None
    assert _hint(tmp_path, _errors(54), requires=">=3.14,!=3.15.*") is not None


def test_fallback_reader_without_a_toml_parser():
    # Python 3.10 has no tomllib and Scan installs no tomli, which is exactly what a bare
    # `uvx actenon-scan` can give on a clean machine.
    read = pv._requires_python_fallback
    assert read(b'[project]\nname = "x"\nrequires-python = ">=3.14"  # PEP 758\n') == ">=3.14"
    assert read(b"[project]\nrequires-python='>=3.13'\n") == ">=3.13"
    assert read(b'[ project ]  # metadata\nrequires-python = ">=3.13"\n') == ">=3.13"
    assert read(b'[tool.other]\nrequires-python = ">=3.14"\n[project]\nname = "x"\n') is None
    assert read(b'[project]\nname = "x"\n[tool.x]\nrequires-python = ">=3.14"\n') is None
    assert read(b'[project]\nrequires-python = """\n>=3.14"""\n') is None
    assert read(b"\xff\xfe") is None


@pytest.mark.parametrize(
    "header",
    ["[[tool.plugins]]", "[[ tool.plugins ]]", '[tool."my.plugin"]', "[tool . x]", "[project.urls]", "[[project]]"],
)
def test_fallback_reader_leaves_project_at_any_table_header(header):
    # The owner's review repro: `[[tool.plugins]]` did not end `[project]`, so a later table's
    # value was read as the project's.
    text = f'[project]\nname = "x"\n\n{header}\nname = "p"\nrequires-python = ">=3.14"\n'
    assert pv._requires_python_fallback(text.encode()) is None


def test_fallback_reader_reads_projects_own_value_before_other_tables():
    text = (
        b'[project]\nname = "x"\nrequires-python = ">=3.14"\n\n'
        b'[[tool.plugins]]\nname = "p"\nrequires-python = ">=3.99"\n'
    )
    assert pv._requires_python_fallback(text) == ">=3.14"


def test_fallback_reader_treats_a_multiline_string_as_unknown():
    # A `requires-python = ...` line inside a multi-line string is string content, not a key.
    text = b'[project]\nname = "x"\ndescription = """\nrequires-python = ">=3.14"\n"""\n'
    assert pv._requires_python_fallback(text) is None
    # Control: the project's value comes before any multi-line string and is still read.
    text = b"[project]\nrequires-python = '>=3.14'\n\n[tool.black]\nextend-exclude = '''\n/build/\n'''\n"
    assert pv._requires_python_fallback(text) == ">=3.14"


@pytest.mark.parametrize(
    "text",
    [
        b'[project]\nname = "x"\n\n[[tool.plugins]]\nname = "p"\nrequires-python = ">=3.14"\n',
        b'[project]\nname = "x"\n\n[tool."my.plugin"]\nrequires-python = ">=3.14"\n',
        b'[project]\nname = "x"\nrequires-python = ">=3.14"\n\n[[tool.plugins]]\nrequires-python = ">=3.99"\n',
    ],
)
def test_fallback_reader_agrees_with_tomllib(text):
    tomllib = pytest.importorskip("tomllib")
    expected = tomllib.loads(text.decode()).get("project", {}).get("requires-python")
    assert pv._requires_python_fallback(text) == expected


def test_tomllib_unavailable_uses_the_fallback(tmp_path, monkeypatch):
    _pyproject(tmp_path, ">=3.14")
    import builtins

    real_import = builtins.__import__

    def no_toml(name, *args, **kwargs):
        if name in ("tomllib", "tomli"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_toml)
    assert pv.read_requires_python(tmp_path) == ">=3.14"


# -- the report ----------------------------------------------------------------------------------------


def _with_running(monkeypatch, version=RUNNING):
    real = pv.python_version_hint
    monkeypatch.setattr(
        "actenon_scan.report.pretty.python_version_hint",
        lambda errors, target, **kw: real(errors, target, running=version, **kw),
    )


def test_clean_report_keeps_every_error_and_adds_the_line(tmp_path, monkeypatch):
    _with_running(monkeypatch)
    _pyproject(tmp_path, ">=3.14")
    result = ScanResult(files_scanned=12, analysis_errors=_errors(12))
    out = format_pretty(result, scan_target=tmp_path, command="uvx actenon-scan")
    lines = out.splitlines()
    i = lines.index("  12 file(s) errored during analysis.")
    assert lines[i + 1 : i + 11] == [f"    agent/m{n}.py: {PEP758}" for n in range(10)]
    assert lines[i + 11] == "    ... and 2 more"
    assert lines[i + 12] == (
        "  All 12 are SyntaxErrors under Python 3.12, and pyproject.toml requires Python >=3.14. "
        f"Rerun with: uvx --python 3.14 actenon-scan scan {tmp_path}"
    )


def test_findings_report_keeps_every_error_and_adds_the_line(tmp_path, monkeypatch):
    _with_running(monkeypatch)
    _pyproject(tmp_path, ">=3.14")
    result = ScanResult(findings=[_finding()], files_scanned=4, analysis_errors=_errors(3))
    out = format_pretty(result, scan_target=tmp_path)
    lines = out.splitlines()
    i = lines.index("analysis errors: 3 file(s) skipped")
    assert lines[i + 1 : i + 4] == [f"  agent/m{n}.py: {PEP758}" for n in range(3)]
    assert lines[i + 4].startswith("  All 3 are SyntaxErrors under Python 3.12")


@pytest.mark.parametrize("requires", [None, ">=3.10"])
def test_report_without_a_mismatch_is_unchanged(tmp_path, monkeypatch, requires):
    _with_running(monkeypatch)
    _pyproject(tmp_path, requires)
    for result in (
        ScanResult(files_scanned=3, analysis_errors=_errors(3)),
        ScanResult(findings=[_finding()], files_scanned=4, analysis_errors=_errors(3)),
    ):
        assert format_pretty(result, scan_target=tmp_path) == format_pretty(result)


def test_list_format_is_unchanged(tmp_path, monkeypatch):
    _with_running(monkeypatch)
    _pyproject(tmp_path, ">=3.14")
    out = format_list(ScanResult(files_scanned=3, analysis_errors=_errors(3)))
    assert "SyntaxErrors under" not in out


# -- end to end through the CLI ------------------------------------------------------------------------


def _project(tmp_path: Path, requires: str | None, *, with_finding: bool) -> Path:
    (tmp_path / "agent").mkdir()
    for i in range(3):
        (tmp_path / "agent" / f"broken{i}.py").write_text(BROKEN)
    if with_finding:
        (tmp_path / "agent" / "shell.py").write_text(SHELL_TOOL)
    return _pyproject(tmp_path, requires)


def _scan(project: Path, capsys, monkeypatch, *extra: str) -> str:
    monkeypatch.chdir(project)
    cli.main(["scan", ".", "--no-cache", *extra])
    return capsys.readouterr().out


@pytest.mark.parametrize("with_finding", [False, True])
def test_cli_mismatch_prints_the_line(tmp_path, capsys, monkeypatch, with_finding):
    monkeypatch.delenv("UV", raising=False)
    out = _scan(_project(tmp_path, f">={NEXT_MINOR}", with_finding=with_finding), capsys, monkeypatch)
    here = f"{sys.version_info[0]}.{sys.version_info[1]}"
    for i in range(3):
        assert f"agent/broken{i}.py: SyntaxError: " in out
    assert (
        f"  All 3 are SyntaxErrors under Python {here}, and pyproject.toml requires Python >={NEXT_MINOR}. "
        f"Rerun with actenon-scan installed on Python {NEXT_MINOR}: actenon-scan scan .\n"
    ) in out
    assert ("Most exposed:" in out) is with_finding


@pytest.mark.parametrize("with_finding", [False, True])
def test_cli_without_requires_python_prints_no_line(tmp_path, capsys, monkeypatch, with_finding):
    out = _scan(_project(tmp_path, None, with_finding=with_finding), capsys, monkeypatch)
    assert "agent/broken0.py: SyntaxError: " in out
    assert "SyntaxErrors under" not in out and "Rerun" not in out


@pytest.mark.parametrize("fmt", ["json", "sarif"])
def test_json_and_sarif_are_unchanged(tmp_path, capsys, monkeypatch, fmt):
    project = _project(tmp_path, f">={NEXT_MINOR}", with_finding=True)
    mismatch = _scan(project, capsys, monkeypatch, "--format", fmt)
    _pyproject(project, ">=3.0")
    no_mismatch = _scan(project, capsys, monkeypatch, "--format", fmt)

    def stable(text: str):
        data = json.loads(text)
        data.pop("elapsed_seconds", None)
        return data

    assert stable(mismatch) == stable(no_mismatch)
    assert "Rerun" not in mismatch and "SyntaxErrors under" not in mismatch
    if fmt == "json":
        errors = json.loads(mismatch)["analysis_errors"]
        assert len(errors) == 3 and all("SyntaxError" in json.dumps(e) for e in errors)


# -- the all-guarded summary (every capability guarded, no findings) ---------------------------------

INCOMPLETE = "ANALYSIS INCOMPLETE: 1 supported file(s) could not be parsed and were NOT analysed"
UNQUALIFIED = "source files were parsed and analysed"


def _guarded_capability():
    from actenon_scan.capability import Capability

    return Capability(
        file="tools.py", line=7, col=4, rule_id="DATA-DELETE-FILE", category="data_destruction",
        severity="high", call_text="os.remove(path)", state="GUARD_FOUND", guard_status="guarded",
    )


def test_all_guarded_report_adds_the_line_under_the_failed_files(tmp_path, monkeypatch):
    _with_running(monkeypatch)
    _pyproject(tmp_path, ">=3.14")
    result = ScanResult(capabilities=[_guarded_capability()], files_scanned=2, analysis_errors=_errors(1))
    lines = format_pretty(result, scan_target=tmp_path, command="uvx actenon-scan").splitlines()
    i = lines.index(INCOMPLETE + "; anything in them is unknown.")
    assert lines[i + 1] == f"  agent/m0.py: {PEP758}"
    assert lines[i + 2] == (
        "  This is a SyntaxError under Python 3.12, and pyproject.toml requires Python >=3.14. "
        f"Rerun with: uvx --python 3.14 actenon-scan scan {tmp_path}"
    )


@pytest.mark.parametrize("requires", [None, ">=3.10", ">=3.14,!=3.14.*"])
def test_all_guarded_report_without_a_suggestion_is_unchanged(tmp_path, monkeypatch, requires):
    _with_running(monkeypatch)
    _pyproject(tmp_path, requires)
    result = ScanResult(capabilities=[_guarded_capability()], files_scanned=2, analysis_errors=_errors(1))
    assert format_pretty(result, scan_target=tmp_path) == format_pretty(result)


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

PEP758_FILE = "def f():\n    try:\n        pass\n    except ValueError, TypeError:\n        pass\n"


def _all_guarded_project(tmp_path: Path, requires: str | None) -> Path:
    (tmp_path / "tools.py").write_text(GUARDED_TOOL)
    (tmp_path / ".actenon-scan.json").write_text('{"guard_patterns": ["authorize"]}')
    (tmp_path / "broken.py").write_text(PEP758_FILE)
    return _pyproject(tmp_path, requires)


@pytest.mark.skipif(sys.version_info >= (3, 14), reason="PEP 758 `except A, B:` parses on Python 3.14+")
@pytest.mark.parametrize(
    ("command", "rerun"),
    [
        ("uvx actenon-scan", "Rerun with: uvx --python 3.14 actenon-scan scan ."),
        ("actenon-scan", "Rerun with actenon-scan installed on Python 3.14: actenon-scan scan ."),
    ],
)
def test_all_guarded_project_for_a_newer_python_end_to_end(tmp_path, capsys, monkeypatch, command, rerun):
    # The real parser, the real CLI and auto-discovered config. Every capability is guarded, so the
    # report takes the all-guarded summary; the one file it could not parse must still be reported
    # as not analysed, with why and how to rerun.
    monkeypatch.setattr(cli, "scan_command", lambda: command)
    out = _scan(_all_guarded_project(tmp_path, ">=3.14"), capsys, monkeypatch)
    lines = out.splitlines()
    here = f"{sys.version_info[0]}.{sys.version_info[1]}"

    assert "  Guard found on path:       1" in lines and "Review required" not in out  # all-guarded path
    incomplete = lines.index(INCOMPLETE + "; anything in them is unknown.")
    assert lines[incomplete + 1].startswith(
        "  broken.py: SyntaxError: multiple exception types must be parenthesized"
    )
    assert lines[incomplete + 2] == (
        f"  This is a SyntaxError under Python {here}, and pyproject.toml requires Python >=3.14. {rerun}"
    )
    assert UNQUALIFIED not in out
    assert "No supported unguarded consequential-action paths were identified." not in out


@pytest.mark.skipif(sys.version_info >= (3, 14), reason="PEP 758 `except A, B:` parses on Python 3.14+")
@pytest.mark.parametrize("requires", [None, ">=3.10", ">=3.14,!=3.14.*"])
def test_all_guarded_project_without_a_suggestion_still_discloses(tmp_path, capsys, monkeypatch, requires):
    out = _scan(_all_guarded_project(tmp_path, requires), capsys, monkeypatch)
    assert INCOMPLETE in out and "  broken.py: SyntaxError: " in out
    assert "Rerun" not in out and "SyntaxError under" not in out
    assert UNQUALIFIED not in out


# -- the cache must not replay an older interpreter's SyntaxError ----------------------------------------


def test_cache_key_includes_the_python_parser_version(monkeypatch):
    config = type("Config", (), {"sinks": [], "guard_patterns": [], "reachability": []})()
    monkeypatch.setattr(cache_mod, "_parser_version", lambda: "py3.12")
    k312 = compute_cache_key("except A, B:\n    pass\n", config)
    monkeypatch.setattr(cache_mod, "_parser_version", lambda: "py3.14")
    assert compute_cache_key("except A, B:\n    pass\n", config) != k312


def test_syntax_error_cached_on_one_python_is_a_miss_on_another(tmp_path, monkeypatch):
    from actenon_scan.rules.loader import load_default_rules

    rules = load_default_rules()
    cache = FileCache(tmp_path / "cache")
    source = "try:\n    pass\nexcept A, B:\n    pass\n"
    monkeypatch.setattr(cache_mod, "_parser_version", lambda: "py3.12")
    cache.store(source, "agent/tools.py", rules, [], f"SyntaxError: {PEP758}")
    assert cache.findings_for(source, "agent/tools.py", rules) is not None
    monkeypatch.setattr(cache_mod, "_parser_version", lambda: "py3.14")
    assert cache.findings_for(source, "agent/tools.py", rules) is None

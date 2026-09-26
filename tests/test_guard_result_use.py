"""P3 (clearly-wrong parts only).

1. ``subprocess.check_output`` / ``check_call`` matched the ``check_*``
   validation-guard name pattern, so running a command about a path
   "guarded" a later ``os.remove(path)`` (GUARD_FOUND).
2. Assigning a predicate guard's result counted as "result used" even
   when the variable was never read: ``allowed = check_permission(...)``
   followed by the sink was GUARD_FOUND.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from actenon_scan.engine import scan_path

HEADER = """\
import os, subprocess
from subprocess import check_call
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
"""


def _remove_findings(tmp_path: Path, body: str) -> list[str]:
    (tmp_path / "agent.py").write_text(HEADER + textwrap.dedent(body))
    result = scan_path(tmp_path, cache=None)
    return [f.rule_id for f in result.findings
            if not f.suppressed and "remove" in f.call_text]


def test_check_output_is_not_a_guard(tmp_path: Path) -> None:
    assert _remove_findings(tmp_path, """
        @mcp.tool()
        def delete(path: str) -> str:
            info = subprocess.check_output(["stat", path])
            os.remove(path)
            return info.decode()
    """) == ["DATA-DELETE-OS"]


def test_check_call_is_not_a_guard(tmp_path: Path) -> None:
    assert _remove_findings(tmp_path, """
        @mcp.tool()
        def delete(path: str) -> None:
            rc = check_call(["stat", path])
            if rc:
                return
            os.remove(path)
    """) == ["DATA-DELETE-OS"]


def test_assigned_but_never_read_result_is_not_used(tmp_path: Path) -> None:
    assert _remove_findings(tmp_path, """
        def check_permission(user, path):
            return user == "admin"

        @mcp.tool()
        def delete(path: str, user: str) -> None:
            allowed = check_permission(user, path)
            os.remove(path)
    """) == ["DATA-DELETE-OS-WEAK"]


def test_assigned_and_tested_result_still_guards(tmp_path: Path) -> None:
    assert _remove_findings(tmp_path, """
        def check_permission(user, path):
            return user == "admin"

        @mcp.tool()
        def delete(path: str, user: str) -> None:
            allowed = check_permission(user, path)
            if not allowed:
                raise PermissionError(path)
            os.remove(path)
    """) == []


def test_tuple_assigned_validation_result_still_guards(tmp_path: Path) -> None:
    assert _remove_findings(tmp_path, """
        def _validate_path(path):
            if path.startswith("/etc"):
                return False, "no"
            return True, "ok"

        @mcp.tool()
        def delete(path: str) -> str:
            valid, msg = _validate_path(path)
            if not valid:
                return msg
            os.remove(path)
            return "ok"
    """) == []

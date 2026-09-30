"""Sinks reached through import aliases must be found (P1).

Only the fully spelled-out form (``import os; os.system(cmd)``) was
matched. Inside an ``@mcp.tool`` every one of these reported
"No supported unguarded consequential-action paths":

    import subprocess as sp;         sp.run(cmd, shell=True)
    from subprocess import run;      run(cmd, shell=True)
    from subprocess import run as r; r(cmd, shell=True)
    from os import system;           system(cmd)

The same holds for TypeScript (``import { exec as run }``) and Go
(``osx "os"``).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from actenon_scan.engine import scan_path

PY_HEADER = """\
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
"""


def _py_rules(tmp_path: Path, imports: str, call: str) -> list[str]:
    src = imports + "\n" + PY_HEADER + textwrap.dedent(f"""
        @mcp.tool()
        def tool(cmd: str, path: str, url: str) -> None:
            {call}
    """)
    (tmp_path / "agent.py").write_text(src)
    result = scan_path(tmp_path, cache=None)
    return sorted(f.rule_id for f in result.findings if not f.suppressed)


@pytest.mark.parametrize(
    "imports, call, rule",
    [
        ("import subprocess as sp", "sp.run(cmd, shell=True)", "EXEC-SHELL"),
        ("import subprocess as sp", "sp.Popen(cmd, shell=True)", "EXEC-SHELL"),
        ("from subprocess import run", "run(cmd, shell=True)", "EXEC-SHELL"),
        ("from subprocess import run as r", "r(cmd, shell=True)", "EXEC-SHELL"),
        ("from subprocess import check_output", "check_output(cmd, shell=True)", "EXEC-SHELL"),
        ("from os import system", "system(cmd)", "EXEC-SHELL"),
        ("from os import system as sh", "sh(cmd)", "EXEC-SHELL"),
        ("import os as o", "o.system(cmd)", "EXEC-SHELL"),
        ("import os as o", "o.remove(path)", "DATA-DELETE-OS"),
        ("import shutil as sh", "sh.rmtree(path)", "FILE-WRITE"),
        ("from shutil import rmtree as nuke", "nuke(path)", "FILE-WRITE"),
        ("import requests as rq", "rq.post(url, data=cmd)", "NET-EGRESS"),
        ("from requests import post", "post(url, data=cmd)", "NET-EGRESS"),
    ],
)
def test_python_aliased_sink_is_found(tmp_path: Path, imports: str, call: str, rule: str) -> None:
    assert rule in _py_rules(tmp_path, imports, call)


def test_python_relative_import_of_a_local_run_is_not_a_shell_sink(tmp_path: Path) -> None:
    # A project's own `run` helper is not subprocess.run.
    assert _py_rules(tmp_path, "from .jobs import run", "run(cmd)") == []


def test_python_non_sink_import_alias_stays_clean(tmp_path: Path) -> None:
    assert _py_rules(tmp_path, "import json as j", "j.dumps(cmd)") == []


def test_typescript_aliased_named_import_is_found(tmp_path: Path) -> None:
    from actenon_scan.detectors.typescript import is_typescript_extra_available

    if not is_typescript_extra_available():
        pytest.skip("[typescript] extra not installed")
    (tmp_path / "index.ts").write_text(textwrap.dedent("""\
        import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
        import { z } from "zod";
        import { exec as run } from "child_process";
        import { rmSync as wipe } from "fs";

        const server = new McpServer({ name: "x", version: "1" });
        server.tool("run", { cmd: z.string(), p: z.string() }, async ({ cmd, p }) => {
          run(cmd);
          wipe(p);
          return { content: [] };
        });
    """))
    result = scan_path(tmp_path, cache=None)
    rules = sorted(f.rule_id for f in result.findings if not f.suppressed)
    assert rules == ["DATA-DELETE-FILE", "EXEC-SHELL"], rules


def test_go_aliased_import_is_found(tmp_path: Path) -> None:
    from actenon_scan.detectors.go import is_go_extra_available

    if not is_go_extra_available():
        pytest.skip("[go] extra not installed")
    (tmp_path / "main.go").write_text(textwrap.dedent("""\
        package main

        import (
        \t"context"
        \tosx "os"
        \tex "os/exec"

        \t"github.com/modelcontextprotocol/go-sdk/mcp"
        )

        type Args struct{ Path string; Cmd string }

        func del(ctx context.Context, req *mcp.CallToolRequest, a Args) (*mcp.CallToolResult, any, error) {
        \tosx.RemoveAll(a.Path)
        \tex.Command("sh", "-c", a.Cmd).Run()
        \treturn nil, nil, nil
        }

        func main() { s := mcp.NewServer(nil, nil); mcp.AddTool(s, &mcp.Tool{Name: "del"}, del) }
    """))
    result = scan_path(tmp_path, cache=None)
    rules = sorted(f.rule_id for f in result.findings if not f.suppressed)
    assert rules == ["DATA-DELETE-OS-GO", "EXEC-SHELL-GO"], rules

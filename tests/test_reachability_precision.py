"""Tests for reachability precision improvements.

Fixes the false positives found in the corpus validation:
  - __main__ block exclusion (5 FPs in openai-agents-python + autogen)
  - class-body lambda exclusion (2 FPs in autogen)
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from actenon_scan.engine import scan_path


def _scan_source(source: str) -> list:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(source)
        f.flush()
        result = scan_path(f.name)
    Path(f.name).unlink()
    return [f for f in result.findings if not f.suppressed]


class TestMainBlockExclusion:
    """Sinks inside `if __name__ == "__main__":` are NOT agent-reachable."""

    def test_subprocess_in_main_block_not_reported(self):
        """The 4 openai-agents-python FPs were subprocess.Popen in __main__."""
        source = '''import subprocess
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
if __name__ == "__main__":
    subprocess.Popen(["uv", "run", "server.py"])
'''
        findings = _scan_source(source)
        assert len(findings) == 0, f"__main__ block should not be reported: {findings}"

    def test_file_write_in_main_block_not_reported(self):
        """The autogen FP was open() in __main__."""
        source = '''import json
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
if __name__ == "__main__":
    with open("gallery.json", "w") as f:
        f.write(json.dumps({"data": "x"}))
'''
        findings = _scan_source(source)
        assert len(findings) == 0, f"__main__ block should not be reported: {findings}"

    def test_subprocess_in_tool_function_still_reported(self):
        """Sinks inside @mcp.tool functions are still caught."""
        source = '''import subprocess
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
@mcp.tool()
def run_cmd(cmd: str):
    subprocess.run(cmd)
'''
        findings = _scan_source(source)
        assert len(findings) >= 1, f"Tool function should be reported: {findings}"


class TestClassBodyExclusion:
    """Sinks in class-body assignments (not in methods) are NOT agent-reachable."""

    def test_pydantic_config_lambda_not_reported(self):
        """The autogen FPs were SecretStr.get_secret_value() in ConfigDict."""
        source = '''from pydantic import BaseModel, ConfigDict, SecretStr
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")
class MyModel(BaseModel):
    name: str
    model_config = ConfigDict(
        json_encoders={SecretStr: lambda v: v.get_secret_value()}
    )
'''
        findings = _scan_source(source)
        assert len(findings) == 0, f"Class-body lambda should not be reported: {findings}"

    def test_method_still_reported(self):
        """Sinks inside class methods are still caught (if the class is a tool base)."""
        source = '''from langchain_core.tools import BaseTool
class MyTool(BaseTool):
    def _run(self, cmd: str):
        import subprocess; subprocess.run(cmd)
'''
        findings = _scan_source(source)
        assert len(findings) >= 1, f"Tool method should be reported: {findings}"


class TestCorpusRegression:
    """Regression tests using the exact snippets from the corpus validation."""

    def test_openai_agents_subprocess_fp_eliminated(self):
        """Exact pattern from openai-agents-python examples."""
        source = '''import subprocess
import os
from agents import Agent, Runner

if __name__ == "__main__":
    env = os.environ.copy()
    process = subprocess.Popen(["uv", "run", "server.py"], env=env)
    time.sleep(3)
'''
        findings = _scan_source(source)
        assert len(findings) == 0

    def test_autogen_secret_read_fp_eliminated(self):
        """Exact pattern from autogen studio datamodel."""
        source = '''from pydantic import BaseModel, ConfigDict, SecretStr
from autogenstudio import Gallery
class MyModel(BaseModel):
    model_config = ConfigDict(
        json_encoders={SecretStr: lambda v: v.get_secret_value()}
    )
'''
        findings = _scan_source(source)
        assert len(findings) == 0

    def test_crewai_sql_tp_still_caught(self):
        """The crewAI SingleStore TP must still be caught."""
        source = '''from crewai.tools import tool
@tool("SingleStore Search")
def search(search_query: str) -> str:
    conn = get_connection()
    with conn.cursor() as cursor:
        cursor.execute(search_query)
        return str(cursor.fetchall())
'''
        findings = _scan_source(source)
        sql_findings = [f for f in findings if f.rule_id == "DATA-DELETE-SQL"]
        assert len(sql_findings) >= 1

    def test_mcp_memory_server_tp_still_caught(self):
        """The MCP memory server writeFile TP must still be caught (TypeScript)."""
        # This is tested via the TypeScript test suite; here we just verify
        # the Python equivalent pattern.
        source = '''from mcp.server.fastmcp import FastMCP
mcp = FastMCP("memory")
@mcp.tool()
def write_memory(content: str):
    with open("memory.json", "w") as f:
        f.write(content)
'''
        findings = _scan_source(source)
        assert len(findings) >= 1

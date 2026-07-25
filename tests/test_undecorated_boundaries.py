"""Agent boundaries that announce themselves without a decorator.

Two reachability signals, benchmark recall cases r06 and r07:

  action_dispatch      — sink executes a payload carried by an action object
  tool_schema_dispatch — sink sits in a branch selected by a schema-declared
                         tool name

Both were measured in detection-only mode across 7,354 files of the ten-repo
corpus before being wired in: zero candidates, therefore zero false positives
and zero real detections on that corpus. The negative cases below are what
keeps the first half of that true — each one is a near-miss that must NOT
promote a sink to reachable.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from actenon_scan.engine import scan_path


def _scan(source: str) -> list:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(source)
        f.flush()
        result = scan_path(f.name)
    Path(f.name).unlink()
    return [f for f in result.findings if not f.suppressed]


# ---------------------------------------------------------------------------
# r06 — action / observation dispatch
# ---------------------------------------------------------------------------

ACTION_MODULE = '''import subprocess
from dataclasses import dataclass

@dataclass
class CmdRunAction:
    command: str

class Runtime:
    def _run_cmd(self, action: CmdRunAction) -> str:
        result = subprocess.run(action.command, shell=True, capture_output=True)
        return result.stdout
'''


class TestActionDispatch:
    def test_action_payload_reaches_sink(self):
        findings = _scan(ACTION_MODULE)
        assert len(findings) == 1, f"expected the action sink to be found: {findings}"
        assert findings[0].confidence == "high"

    def test_imported_action_type_works(self):
        """The action class lives in another module — annotation name is enough."""
        source = '''import subprocess
from myframework.events import CmdRunAction

class Runtime:
    def _run_cmd(self, action: CmdRunAction) -> str:
        return subprocess.run(action.command, shell=True).stdout
'''
        assert len(_scan(source)) == 1

    def test_string_annotation_works(self):
        source = '''import subprocess

class Runtime:
    def _run_cmd(self, action: "CmdRunAction") -> str:
        return subprocess.run(action.command, shell=True).stdout
'''
        assert len(_scan(source)) == 1

    def test_unannotated_parameter_is_not_a_boundary(self):
        """Naming a parameter `action` is not evidence of an agent boundary."""
        source = '''import subprocess

class Runner:
    def _run_cmd(self, action) -> str:
        return subprocess.run(action.command, shell=True).stdout
'''
        assert _scan(source) == []

    def test_sink_must_consume_the_action_payload(self):
        """A method that takes an action but runs something else is not a boundary."""
        source = '''import subprocess
from dataclasses import dataclass

@dataclass
class CmdRunAction:
    command: str

class Runtime:
    def _cleanup(self, action: CmdRunAction) -> str:
        return subprocess.run("git status", shell=True).stdout
'''
        assert _scan(source) == []

    def test_non_payload_attribute_does_not_qualify(self):
        """action.thought is not an executable payload."""
        source = '''import subprocess
from dataclasses import dataclass

@dataclass
class CmdRunAction:
    command: str
    thought: str = ""

class Runtime:
    def _log(self, action: CmdRunAction) -> str:
        return subprocess.run(action.thought, shell=True).stdout
'''
        assert _scan(source) == []

    def test_ordinary_class_name_does_not_qualify(self):
        """A type not named like an action carries no boundary signal."""
        source = '''import subprocess
from dataclasses import dataclass

@dataclass
class BuildConfig:
    command: str

def build(cfg: BuildConfig) -> str:
    return subprocess.run(cfg.command, shell=True).stdout
'''
        assert _scan(source) == []


# ---------------------------------------------------------------------------
# r07 — raw tool-schema dispatch
# ---------------------------------------------------------------------------

SCHEMA_MODULE = '''import subprocess

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "run_command",
            "description": "Run a shell command",
            "parameters": {"type": "object", "properties": {}},
        },
    }
]

def dispatch_tool(name: str, args: dict) -> str:
    if name == "run_command":
        return subprocess.run(args.get("command", ""), shell=True).stdout
    return "unknown tool"
'''


class TestToolSchemaDispatch:
    def test_schema_declared_name_selects_the_sink(self):
        findings = _scan(SCHEMA_MODULE)
        assert len(findings) == 1, f"expected the dispatch sink to be found: {findings}"
        assert findings[0].confidence == "high"

    def test_flat_anthropic_schema_form(self):
        source = '''import subprocess

TOOLS = [{"name": "run_command", "description": "run", "input_schema": {"type": "object"}}]

def dispatch(name: str, args: dict) -> str:
    if name == "run_command":
        return subprocess.run(args["command"], shell=True).stdout
    return ""
'''
        assert len(_scan(source)) == 1

    def test_match_statement_dispatch(self):
        source = '''import subprocess

TOOLS = [{"name": "run_command", "description": "run", "input_schema": {}}]

def dispatch(name: str, args: dict) -> str:
    match name:
        case "run_command":
            return subprocess.run(args["command"], shell=True).stdout
        case _:
            return ""
'''
        assert len(_scan(source)) == 1

    def test_dispatch_without_a_schema_is_not_a_boundary(self):
        """Branching on a string is not an agent boundary on its own.

        This is the shape of every command-line dispatcher ever written.
        """
        source = '''import subprocess

def dispatch(name: str, args: dict) -> str:
    if name == "run_command":
        return subprocess.run(args["command"], shell=True).stdout
    return ""
'''
        assert _scan(source) == []

    def test_schema_present_but_sink_outside_the_branch(self):
        """A sink elsewhere in the dispatcher is not selected by the tool name."""
        source = '''import subprocess

TOOLS = [{"name": "read_file", "description": "read", "input_schema": {}}]

def dispatch(name: str, args: dict) -> str:
    subprocess.run("git status", shell=True)
    if name == "read_file":
        return open(args["path"]).read()
    return ""
'''
        assert _scan(source) == []

    def test_branch_name_not_declared_in_schema(self):
        """Only names the schema actually declares count."""
        source = '''import subprocess

TOOLS = [{"name": "read_file", "description": "read", "input_schema": {}}]

def dispatch(name: str, args: dict) -> str:
    if name == "run_command":
        return subprocess.run(args["command"], shell=True).stdout
    return ""
'''
        assert _scan(source) == []

    def test_plain_dict_is_not_a_tool_schema(self):
        """A dict with a "name" key is not a schema without a parameter block."""
        source = '''import subprocess

CONFIG = {"name": "run_command", "enabled": True}

def dispatch(name: str, args: dict) -> str:
    if name == "run_command":
        return subprocess.run(args["command"], shell=True).stdout
    return ""
'''
        assert _scan(source) == []

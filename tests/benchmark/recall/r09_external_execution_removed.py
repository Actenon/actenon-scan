"""Recall fixture: same tool WITHOUT external_execution=True must fire.

Paired with p14_external_execution_guard.py. When the
external_execution=True flag is removed, the tool is auto-executed by
the agent and the subprocess call is an unguarded consequential action.

Expected findings: >= 1
"""

import subprocess

from agno.tools import tool


@tool()
def execute_shell_command(command: str) -> str:
    """Execute a shell command."""
    if command.startswith("ls"):
        return subprocess.check_output(command, shell=True).decode("utf-8")
    else:
        raise Exception(f"Unsupported command: {command}")

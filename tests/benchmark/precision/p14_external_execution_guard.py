"""Regression fixture: agno @tool(external_execution=True) must NOT fire.

external_execution=True is agno's human-in-the-loop primitive. The agent
does NOT auto-execute this tool — the call is handed back for a human to
run. This is the same class of guard as ctx.elicit and LangChain's
HumanApprovalCallbackHandler.

Verified against real source in:
  agno/cookbook/02_agents/10_human_in_the_loop/external_tool_execution.py

Expected findings: 0
"""

import subprocess

from agno.tools import tool


@tool(external_execution=True)
def execute_shell_command(command: str) -> str:
    """Execute a shell command."""
    if command.startswith("ls"):
        return subprocess.check_output(command, shell=True).decode("utf-8")
    else:
        raise Exception(f"Unsupported command: {command}")

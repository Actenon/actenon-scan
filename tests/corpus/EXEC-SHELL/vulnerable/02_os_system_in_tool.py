import os
from langchain.tools import tool

@tool
def execute_shell(cmd: str) -> str:
    """Execute a shell command."""
    os.system(cmd)
    return "done"

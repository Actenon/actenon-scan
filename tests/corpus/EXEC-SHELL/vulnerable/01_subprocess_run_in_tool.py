import subprocess
from langchain.tools import tool

@tool
def run_command(cmd: str) -> str:
    """Run a shell command."""
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout.decode()

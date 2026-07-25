# r02: LangChain @tool — PASSES today
# Expected: >=1 finding (subprocess.run inside @tool)
from langchain_core.tools import tool

@tool("run_command")
def run_command(cmd: str):
    """Run a shell command."""
    import subprocess
    subprocess.run(cmd, shell=True)

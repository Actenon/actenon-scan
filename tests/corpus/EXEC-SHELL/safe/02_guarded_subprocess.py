import subprocess
from langchain.tools import tool

@tool
def deploy(cmd: str) -> str:
    """Deploy with authorization."""
    authorize(action="deploy")
    subprocess.run(cmd, shell=True)
    return "done"

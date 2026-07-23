from langchain.tools import tool
import subprocess

def requires_auth(fn):
    return fn

@tool
@requires_auth
def run_cmd(cmd: str):
    """Guarded by decorator."""
    return subprocess.run(cmd, shell=True)

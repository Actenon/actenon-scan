import os
from langchain.tools import tool

@tool
def make_executable(path: str) -> str:
    """Make a file executable."""
    os.chmod(path, 0o755)
    return "done"

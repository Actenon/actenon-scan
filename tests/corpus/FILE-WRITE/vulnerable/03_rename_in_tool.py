from pathlib import Path
from langchain.tools import tool

@tool
def move_file(src: str, dst: str) -> str:
    """Move a file."""
    p = Path(src)
    p.rename(dst)
    return "moved"

from pathlib import Path
from langchain.tools import tool

@tool
def write_config(path: str, content: str) -> str:
    """Write a config file."""
    p = Path(path)
    p.write_text(content)
    return "written"

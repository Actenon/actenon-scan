from pathlib import Path
from langchain.tools import tool

@tool
def write_config(path: str, content: str) -> str:
    """Write with authorization."""
    authorize(action="file_write")
    Path(path).write_text(content)
    return "written"

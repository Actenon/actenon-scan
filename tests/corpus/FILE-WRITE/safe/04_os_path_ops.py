import os
from langchain.tools import tool

@tool
def check_file(path: str) -> dict:
    """os.path.exists/join/getsize are read-only path operations, NOT file writes."""
    return {
        "exists": os.path.exists(path),
        "size": os.path.getsize(path) if os.path.exists(path) else 0,
        "dir": os.path.dirname(path),
        "name": os.path.basename(path),
    }

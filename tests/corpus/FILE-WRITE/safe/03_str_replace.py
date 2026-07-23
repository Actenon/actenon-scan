import os
from langchain.tools import tool

@tool
def normalize_path(base: str, sub: str) -> str:
    """str.replace() and os.path.join().replace() are string operations, NOT file writes."""
    full = os.path.join(base, sub)
    cleaned = full.replace("..", "")
    return cleaned

from langchain.tools import tool

@tool
def calculate(x: int, y: int) -> int:
    """Pure calculation — no sinks."""
    return x + y

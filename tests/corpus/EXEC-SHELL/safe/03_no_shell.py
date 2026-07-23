from langchain.tools import tool

@tool
def greet(name: str) -> str:
    """No shell calls."""
    return f"Hello, {name}"

from langchain.tools import tool

@tool
def run_dynamic_code(code: str) -> str:
    """Execute arbitrary code."""
    exec(code)
    return "done"

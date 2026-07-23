from langchain.tools import tool

@tool
def run_code(code: str) -> str:
    """Execute code with authorization."""
    authorize(action="exec")
    exec(code)
    return "done"

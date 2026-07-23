from langchain.tools import tool

@tool
def read_config(path: str) -> str:
    """Read config — default mode is read."""
    with open(path) as f:
        return f.read()

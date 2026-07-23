from langchain.tools import tool

@tool
def read_file(path: str) -> str:
    """Read a file — open in read mode, not a sink."""
    with open(path, "r") as f:
        return f.read()

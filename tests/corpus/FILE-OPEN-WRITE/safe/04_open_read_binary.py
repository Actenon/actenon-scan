from langchain.tools import tool

@tool
def read_binary_file(path: str) -> bytes:
    """open(path, 'rb') is read-only, NOT a file write."""
    with open(path, "rb") as f:
        return f.read()

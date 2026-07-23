from langchain.tools import tool

@tool
def write_binary(path: str, data: bytes) -> str:
    """Write binary data."""
    with open(path, "wb") as f:
        f.write(data)
    return "written"

from langchain.tools import tool

@tool
def append_file(path: str, content: str) -> str:
    """Append to a file using open(mode=...)."""
    with open(path, mode="a") as f:
        f.write(content)
    return "appended"

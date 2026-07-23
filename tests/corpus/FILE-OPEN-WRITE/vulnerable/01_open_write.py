from langchain.tools import tool

@tool
def write_file(path: str, content: str) -> str:
    """Write a file using open()."""
    with open(path, "w") as f:
        f.write(content)
    return "written"

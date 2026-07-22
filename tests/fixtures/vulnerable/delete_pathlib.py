"""Vulnerable fixture: a LangChain @tool that calls pathlib.Path.unlink."""

from pathlib import Path

from langchain.tools import tool


@tool
def delete_config(config_path: str) -> str:
    """Delete a config file."""
    p = Path(config_path)
    p.unlink()
    return "deleted"

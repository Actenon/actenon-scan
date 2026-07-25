"""GitHub REST contents PUT in an MCP tool — must fire GITHUB-REST-MUTATION.

Covers: requests.put("https://api.github.com/repos/{repo}/contents/{path}", ...)
"""

import requests

from mcp import tool


@tool()
def commit_via_rest(repo: str, path: str, content: str) -> None:
    """Agent-controlled GitHub REST mutation."""
    requests.put(
        f"https://api.github.com/repos/{repo}/contents/{path}",
        json={"content": content},
    )

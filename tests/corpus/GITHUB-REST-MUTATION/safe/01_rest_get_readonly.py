"""Safe: GET to api.github.com — must NOT fire (read-only method).

A GET request to the GitHub API is read-only. The GITHUB-REST-MUTATION
matcher only accepts POST/PUT/PATCH/DELETE.
"""

import requests

from mcp import tool


@tool()
def get_repo_info(repo: str) -> dict:
    """Agent-controlled GitHub REST read — not a mutation."""
    response = requests.get(f"https://api.github.com/repos/{repo}")
    return response.json()

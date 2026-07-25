"""GitHub REST pulls DELETE and merges POST — must fire GITHUB-REST-MUTATION.

Covers:
  httpx.delete(f"https://api.github.com/repos/{repo}/pulls/{n}")
  requests.post(f"https://api.github.com/repos/{repo}/merges", ...)
"""

import httpx
import requests

from mcp import tool


@tool()
def delete_pull(repo: str, n: int) -> None:
    """Agent-controlled GitHub PR deletion via REST."""
    httpx.delete(f"https://api.github.com/repos/{repo}/pulls/{n}")


@tool()
def merge_branch(repo: str, base: str, head: str) -> None:
    """Agent-controlled GitHub merge via REST."""
    requests.post(
        f"https://api.github.com/repos/{repo}/merges",
        json={"base": base, "head": head},
    )

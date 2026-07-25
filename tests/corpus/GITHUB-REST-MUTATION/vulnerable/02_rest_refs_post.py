"""GitHub REST refs POST and releases POST — must fire GITHUB-REST-MUTATION.

Covers:
  requests.post("https://api.github.com/repos/{repo}/git/refs", ...)
  requests.post("https://api.github.com/repos/{repo}/releases", ...)
"""

import requests

from mcp import tool


@tool()
def create_ref(repo: str, ref: str, sha: str) -> None:
    """Agent-controlled GitHub ref creation via REST."""
    requests.post(
        f"https://api.github.com/repos/{repo}/git/refs",
        json={"ref": ref, "sha": sha},
    )


@tool()
def create_release(repo: str, tag: str, name: str) -> None:
    """Agent-controlled GitHub release creation via REST."""
    requests.post(
        f"https://api.github.com/repos/{repo}/releases",
        json={"tag_name": tag, "name": name},
    )

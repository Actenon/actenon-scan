"""Safe: POST to api.github.com but not a mutation path — must NOT fire.

A POST to a GitHub API path that is not a repository mutation surface
(e.g., /user/starred) is not a REPOSITORY mutation. The matcher
requires one of the mutation path suffixes (/contents, /git/refs,
/releases, /pulls, /merges, /branches, /git/commits, /git/trees,
/git/blobs).
"""

import requests

from mcp import tool


@tool()
def star_repo(repo: str) -> None:
    """Agent-controlled GitHub star — not a repository mutation."""
    requests.put(f"https://api.github.com/user/starred/{repo}")

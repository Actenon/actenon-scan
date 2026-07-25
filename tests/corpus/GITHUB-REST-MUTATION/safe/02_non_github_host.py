"""Safe: POST to a non-GitHub host — must NOT fire (wrong host).

A POST to an arbitrary API is not a GitHub mutation. The matcher
requires "api.github.com" in the URL.
"""

import requests

from mcp import tool


@tool()
def post_webhook(url: str, payload: dict) -> None:
    """Agent-controlled POST to an arbitrary URL — not a GitHub mutation."""
    requests.post(url, json=payload)

"""PyGithub create_file in an MCP tool — must fire REPOSITORY-MUTATION.

Covers: github.get_repo(repo).create_file(path, message, content, branch=branch)
"""

from github import Github

from mcp import tool


@tool()
def commit_file(repo: str, path: str, content: str, branch: str) -> None:
    """Agent-controlled GitHub file creation."""
    g = Github("token")
    g.get_repo(repo).create_file(path, "m", content, branch=branch)

"""PyGithub delete_file and update_file in an MCP tool — must fire.

Covers:
  github.get_repo(repo).update_file(path, message, content, sha=sha)
  github.get_repo(repo).delete_file(path, message, sha=sha)
"""

from github import Github

from mcp import tool


@tool()
def update_file(repo: str, path: str, content: str, sha: str) -> None:
    """Agent-controlled GitHub file update."""
    g = Github("token")
    g.get_repo(repo).update_file(path, "m", content, sha=sha)


@tool()
def delete_file(repo: str, path: str, sha: str) -> None:
    """Agent-controlled GitHub file deletion."""
    g = Github("token")
    g.get_repo(repo).delete_file(path, "m", sha=sha)

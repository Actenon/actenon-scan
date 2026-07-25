"""PyGithub release, tag, ref, pull mutations in an MCP tool — must fire.

Covers:
  github.get_repo(repo).create_git_release(tag, name, message)
  github.get_repo(repo).create_git_tag(tag, message, object, type)
  github.get_repo(repo).create_git_ref(ref, sha)
  github.get_repo(repo).get_git_ref(ref).delete()
"""

from github import Github

from mcp import tool


@tool()
def create_release(repo: str, tag: str, name: str, message: str) -> None:
    """Agent-controlled GitHub release creation."""
    g = Github("token")
    g.get_repo(repo).create_git_release(tag, name, message)


@tool()
def delete_ref(repo: str, ref: str) -> None:
    """Agent-controlled GitHub ref deletion."""
    g = Github("token")
    g.get_repo(repo).get_git_ref(ref).delete()

"""Safe: PyGithub call in a NON-agent context — must NOT fire (reachability).

A GitHub library helper that wraps PyGithub but is not exposed as an
agent tool. The reachability filter suppresses this finding because
no agent entry point reaches the sink.
"""

from github import Github


def commit_file(repo: str, path: str, content: str, branch: str) -> None:
    """Internal helper, not agent-reachable."""
    g = Github("token")
    g.get_repo(repo).create_file(path, "m", content, branch=branch)

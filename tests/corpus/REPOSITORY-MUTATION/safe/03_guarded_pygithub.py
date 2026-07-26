"""Safe: guarded PyGithub call — must NOT fire (guard dominance).

A GitHub tool that checks an Actenon proof before mutating. The guard
dominates the sink, so the finding is suppressed.
"""

from github import Github

from actenon_kernel import verify_pccb

from mcp import tool


@tool()
def commit_file(repo: str, path: str, content: str, branch: str, proof: str) -> None:
    """Agent-controlled GitHub file creation — guarded by Actenon proof."""
    verify_pccb(proof, action="repository.create_file", target=repo)
    g = Github("token")
    g.get_repo(repo).create_file(path, "m", content, branch=branch)

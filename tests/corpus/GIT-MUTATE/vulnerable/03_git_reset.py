from langchain.tools import tool

@tool
def reset_repo(repo_path: str) -> str:
    """Reset a git repo."""
    from git import Repo
    repo = Repo(repo_path)
    repo.reset("--hard")
    return "reset"

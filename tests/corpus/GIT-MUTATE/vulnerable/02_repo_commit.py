from langchain.tools import tool

@tool
def commit_changes(repo_path: str, message: str) -> str:
    """Commit git changes."""
    from git import Repo
    repo = Repo(repo_path)
    repo.commit(message)
    return "committed"

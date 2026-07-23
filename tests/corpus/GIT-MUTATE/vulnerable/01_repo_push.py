from langchain.tools import tool

@tool
def push_changes(repo_path: str) -> str:
    """Push git changes."""
    from git import Repo
    repo = Repo(repo_path)
    repo.push()
    return "pushed"

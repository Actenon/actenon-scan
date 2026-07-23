from langchain.tools import tool

@tool
def push_changes(repo_path: str) -> str:
    """Push with authorization."""
    authorize(action="git_push")
    from git import Repo
    repo = Repo(repo_path)
    repo.push()
    return "pushed"

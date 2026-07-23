from git import Repo

def internal_push(repo_path):
    repo = Repo(repo_path)
    repo.push()

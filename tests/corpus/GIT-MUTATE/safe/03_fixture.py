from langchain.tools import tool

@tool
def safe_2():
    """Safe fixture for GIT-MUTATE — no sink calls."""
    return 'safe'

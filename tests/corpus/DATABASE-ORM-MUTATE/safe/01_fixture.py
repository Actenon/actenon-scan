from langchain.tools import tool

@tool
def safe_0():
    """Safe fixture for DATABASE-ORM-MUTATE — no sink calls."""
    return 'safe'

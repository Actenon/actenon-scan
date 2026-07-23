from langchain.tools import tool

@tool
def safe_1():
    """Safe fixture for DATABASE-MUTATE — no sink calls."""
    return 'safe'

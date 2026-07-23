from langchain.tools import tool

@tool
def safe_2():
    """Safe fixture for DATABASE-MUTATE — no sink calls."""
    return 'safe'

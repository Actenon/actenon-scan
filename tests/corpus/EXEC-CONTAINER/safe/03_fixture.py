from langchain.tools import tool

@tool
def safe_2():
    """Safe fixture for EXEC-CONTAINER — no sink calls."""
    return 'safe'

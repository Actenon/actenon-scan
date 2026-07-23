from langchain.tools import tool

@tool
def safe_0():
    """Safe fixture for DATA-DELETE-SQL — no sink calls."""
    return 'safe'

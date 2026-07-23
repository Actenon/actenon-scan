from langchain.tools import tool

@tool
def safe_0():
    """Safe fixture for DATA-DELETE-SQL-RAW — no sink calls."""
    return 'safe'

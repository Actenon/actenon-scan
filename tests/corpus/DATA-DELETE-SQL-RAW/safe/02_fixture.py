from langchain.tools import tool

@tool
def safe_1():
    """Safe fixture for DATA-DELETE-SQL-RAW — no sink calls."""
    return 'safe'

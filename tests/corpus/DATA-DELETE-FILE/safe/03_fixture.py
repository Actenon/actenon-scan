from langchain.tools import tool

@tool
def safe_2():
    """Safe fixture for DATA-DELETE-FILE — no sink calls."""
    return 'safe'

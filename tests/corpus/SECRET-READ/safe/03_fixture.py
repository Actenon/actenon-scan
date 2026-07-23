from langchain.tools import tool

@tool
def safe_2():
    """Safe fixture for SECRET-READ — no sink calls."""
    return 'safe'

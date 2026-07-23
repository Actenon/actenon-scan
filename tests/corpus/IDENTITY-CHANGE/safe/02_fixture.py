from langchain.tools import tool

@tool
def safe_1():
    """Safe fixture for IDENTITY-CHANGE — no sink calls."""
    return 'safe'

from langchain.tools import tool

@tool
def safe_2():
    """Safe fixture for IDENTITY-CHANGE — no sink calls."""
    return 'safe'

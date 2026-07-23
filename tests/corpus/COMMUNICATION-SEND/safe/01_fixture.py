from langchain.tools import tool

@tool
def safe_0():
    """Safe fixture for COMMUNICATION-SEND — no sink calls."""
    return 'safe'

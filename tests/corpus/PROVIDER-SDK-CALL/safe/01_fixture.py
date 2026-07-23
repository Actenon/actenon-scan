from langchain.tools import tool

@tool
def safe_0():
    """Safe fixture for PROVIDER-SDK-CALL — no sink calls."""
    return 'safe'

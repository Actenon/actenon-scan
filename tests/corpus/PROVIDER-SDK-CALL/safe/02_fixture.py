from langchain.tools import tool

@tool
def safe_1():
    """Safe fixture for PROVIDER-SDK-CALL — no sink calls."""
    return 'safe'

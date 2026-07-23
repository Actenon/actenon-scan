from langchain.tools import tool

@tool
def safe_2():
    """Safe fixture for PROVIDER-SDK-CALL — no sink calls."""
    return 'safe'

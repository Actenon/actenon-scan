from langchain.tools import tool

@tool
def safe_2():
    """Safe fixture for COMMUNICATION-SEND — no sink calls."""
    return 'safe'

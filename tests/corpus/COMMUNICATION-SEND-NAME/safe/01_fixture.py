from langchain.tools import tool

@tool
def safe_0():
    """Safe fixture for COMMUNICATION-SEND-NAME — no sink calls."""
    return 'safe'

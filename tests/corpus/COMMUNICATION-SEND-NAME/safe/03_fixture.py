from langchain.tools import tool

@tool
def safe_2():
    """Safe fixture for COMMUNICATION-SEND-NAME — no sink calls."""
    return 'safe'

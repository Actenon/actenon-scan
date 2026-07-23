from langchain.tools import tool

@tool
def safe_0():
    """Safe fixture for PAY-GENERIC-REFUND — no sink calls."""
    return 'safe'

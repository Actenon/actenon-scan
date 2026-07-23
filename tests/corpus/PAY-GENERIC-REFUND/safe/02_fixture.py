from langchain.tools import tool

@tool
def safe_1():
    """Safe fixture for PAY-GENERIC-REFUND — no sink calls."""
    return 'safe'

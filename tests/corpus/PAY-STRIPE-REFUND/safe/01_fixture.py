from langchain.tools import tool

@tool
def safe_0():
    """Safe fixture for PAY-STRIPE-REFUND — no sink calls."""
    return 'safe'

from langchain.tools import tool

@tool
def safe_0():
    """Safe fixture for ACCESS-CONTROL-MUTATE — no sink calls."""
    return 'safe'

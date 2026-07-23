from langchain.tools import tool

@tool
def safe_1():
    """Safe fixture for ACCESS-CONTROL-MUTATE — no sink calls."""
    return 'safe'

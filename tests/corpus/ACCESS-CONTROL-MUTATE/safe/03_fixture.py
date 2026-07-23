from langchain.tools import tool

@tool
def safe_2():
    """Safe fixture for ACCESS-CONTROL-MUTATE — no sink calls."""
    return 'safe'

from langchain.tools import tool

@tool
def safe_2():
    """Safe fixture for BROWSER-ACTION — no sink calls."""
    return 'safe'

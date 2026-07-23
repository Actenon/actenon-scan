from langchain.tools import tool

@tool
def safe_1():
    """Safe fixture for DATA-DELETE-OBJ — no sink calls."""
    return 'safe'

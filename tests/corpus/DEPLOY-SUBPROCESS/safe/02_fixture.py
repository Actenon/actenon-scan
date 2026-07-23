from langchain.tools import tool

@tool
def safe_1():
    """Safe fixture for DEPLOY-SUBPROCESS — no sink calls."""
    return 'safe'

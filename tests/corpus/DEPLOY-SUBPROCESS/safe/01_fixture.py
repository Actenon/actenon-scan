from langchain.tools import tool

@tool
def safe_0():
    """Safe fixture for DEPLOY-SUBPROCESS — no sink calls."""
    return 'safe'

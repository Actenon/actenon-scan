from langchain.tools import tool

@tool
def safe_2():
    """Safe fixture for DEPLOY-SUBPROCESS — no sink calls."""
    return 'safe'

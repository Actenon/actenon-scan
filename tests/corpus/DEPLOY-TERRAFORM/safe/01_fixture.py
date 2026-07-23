from langchain.tools import tool

@tool
def safe_0():
    """Safe fixture for DEPLOY-TERRAFORM — no sink calls."""
    return 'safe'

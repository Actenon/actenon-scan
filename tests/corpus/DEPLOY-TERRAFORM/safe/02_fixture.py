from langchain.tools import tool

@tool
def safe_1():
    """Safe fixture for DEPLOY-TERRAFORM — no sink calls."""
    return 'safe'

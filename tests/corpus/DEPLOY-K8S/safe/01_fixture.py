from langchain.tools import tool

@tool
def safe_0():
    """Safe fixture for DEPLOY-K8S — no sink calls."""
    return 'safe'

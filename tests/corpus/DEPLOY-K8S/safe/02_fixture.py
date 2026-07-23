from langchain.tools import tool

@tool
def safe_1():
    """Safe fixture for DEPLOY-K8S — no sink calls."""
    return 'safe'

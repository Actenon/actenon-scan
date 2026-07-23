from langchain.tools import tool

@tool
def safe_0():
    """Safe fixture for IDENTITY-IAM-MUTATE — no sink calls."""
    return 'safe'

from langchain.tools import tool

@tool
def safe_2():
    """Safe fixture for IDENTITY-IAM-MUTATE — no sink calls."""
    return 'safe'

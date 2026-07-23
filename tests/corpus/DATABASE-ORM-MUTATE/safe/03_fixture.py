from langchain.tools import tool

@tool
def safe_2():
    """Safe fixture for DATABASE-ORM-MUTATE — no sink calls."""
    return 'safe'

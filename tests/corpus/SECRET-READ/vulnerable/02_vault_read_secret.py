from langchain.tools import tool

@tool
def get_api_key(path: str) -> str:
    """Read a secret from Vault."""
    import hvac
    client = hvac.Client()
    result = client.read_secret(path)
    return result["data"]["data"]["key"]

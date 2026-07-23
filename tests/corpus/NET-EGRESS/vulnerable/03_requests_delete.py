import requests
from langchain.tools import tool

@tool
def delete_resource(url: str) -> str:
    """DELETE a resource."""
    resp = requests.delete(url)
    return str(resp.status_code)

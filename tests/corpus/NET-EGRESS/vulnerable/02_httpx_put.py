import httpx
from langchain.tools import tool

@tool
def update_resource(url: str, data: dict) -> str:
    """PUT to a resource."""
    resp = httpx.put(url, json=data)
    return str(resp.status_code)

import requests
from langchain.tools import tool

@tool
def fetch_data(url: str) -> str:
    """GET request — read-only, not a sink."""
    resp = requests.get(url)
    return resp.text

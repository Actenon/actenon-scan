from langchain.tools import tool
import requests

@tool
def fetch(url: str, body: dict):
    """Agent supplies the URL."""
    return requests.post(url, json=body)

@tool
def fetch_fstring(host: str):
    """Agent supplies part of the URL."""
    return requests.post(f"https://{host}/api", json={})

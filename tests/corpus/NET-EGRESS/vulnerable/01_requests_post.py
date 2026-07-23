import requests
from langchain.tools import tool

@tool
def send_webhook(url: str, payload: dict) -> str:
    """Send a POST request."""
    resp = requests.post(url, json=payload)
    return str(resp.status_code)

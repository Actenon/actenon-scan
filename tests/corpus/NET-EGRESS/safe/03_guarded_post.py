import requests
from langchain.tools import tool

@tool
def send_webhook(url: str, payload: dict) -> str:
    """POST with authorization."""
    authorize(action="webhook_send")
    resp = requests.post(url, json=payload)
    return str(resp.status_code)

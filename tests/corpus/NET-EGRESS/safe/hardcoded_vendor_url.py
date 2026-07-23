from langchain.tools import tool
import requests

API = "https://api.vendor.com/v1/evaluate"

@tool
def evaluate(payload: dict):
    """Fixed vendor endpoint."""
    return requests.post(API, json=payload)

@tool
def evaluate_literal(payload: dict):
    """Literal endpoint."""
    return requests.post("https://api.vendor.com/v1/rerank", json=payload)

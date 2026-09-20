"""NET-EGRESS at depth 0: the sink is in the tool body."""

import requests
from agents import tool


@tool
def publish(data):
    requests.post("https://example.com/upload", json=data)

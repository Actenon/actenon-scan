"""NET-EGRESS at depth 1: one same-module hop."""

import requests
from agents import tool


@tool
def publish(data):
    send_to_external_service(data)


def send_to_external_service(data):
    requests.post("https://example.com/upload", json=data)

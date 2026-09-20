"""The sink, one module away from the entry point."""

import requests


def send_to_external_service(data):
    requests.post("https://example.com/upload", json=data)

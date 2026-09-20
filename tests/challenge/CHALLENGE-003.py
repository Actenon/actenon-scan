"""CHALLENGE-003 fixture: a sink one hop from the entry point.

The consequential action is a plain network egress. It is invisible to the
scanner only because it sits in a helper the tool calls rather than in the
tool body. See CHALLENGE-003.control.py for the same sink written inline,
which IS reported — the control proves the sink itself is detectable and
that the hop is the whole difference.
"""

import requests
from agents import tool


@tool
def publish(data):
    send_to_external_service(data)


def send_to_external_service(data):
    requests.post("https://example.com/upload", json=data)

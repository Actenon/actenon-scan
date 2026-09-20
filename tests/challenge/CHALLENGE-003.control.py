"""CHALLENGE-003 control: the same sink, inline in the tool body.

Reported as MEDIUM NET-EGRESS. This file exists so the challenge cannot be
dismissed as "that sink is not in the ruleset": the only difference between
this file and CHALLENGE-003.py is one function call.
"""

import requests
from agents import tool


@tool
def publish(data):
    requests.post("https://example.com/upload", json=data)

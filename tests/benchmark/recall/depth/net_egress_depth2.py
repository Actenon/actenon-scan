"""NET-EGRESS at depth 2: two same-module hops. EXPECTED MISS.

Following is depth-1 and non-transitive, so `relay` is analysed but its own
outgoing call is not walked. The scan reports no finding here and discloses
the unfollowed call from relay() onward.
"""

import requests
from agents import tool


@tool
def publish(data):
    relay(data)


def relay(data):
    send_to_external_service(data)


def send_to_external_service(data):
    requests.post("https://example.com/upload", json=data)

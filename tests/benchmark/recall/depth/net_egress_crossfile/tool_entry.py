"""NET-EGRESS across files: the helper lives in another module. EXPECTED MISS.

There is no cross-file analysis. The call is disclosed as unfollowed with
reason `cross_file`.
"""

from agents import tool

from .egress_helper import send_to_external_service


@tool
def publish(data):
    send_to_external_service(data)

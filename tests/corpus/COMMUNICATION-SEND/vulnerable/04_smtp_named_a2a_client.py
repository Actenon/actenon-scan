"""Audit fixture (Work Order 1, Part 1.3): SMTP client with misleading name.

A genuine smtplib.SMTP client assigned to a variable named `a2a_client`
must STILL fire COMMUNICATION-SEND. The A2A exclusion is now bound to
receiver origin (constructor or assignment traced to a recognised A2A
client), not to the variable name. A bare name match is no longer
sufficient to suppress a finding (RULE 7).

This fixture pairs with the A2A precision fixture
(tests/benchmark/precision/p13_a2a_send_message.py) to prove the
narrowing is SAFE: A2A case stays clean, SMTP case still fires.
"""

import smtplib

from mcp import tool


@tool()
def send_email(message: str) -> None:
    """Agent-controlled email send — variable name is misleading on purpose."""
    # The variable is named a2a_client to test that the exclusion no longer
    # matches by bare name. This is an smtplib.SMTP instance, so the finding
    # MUST fire.
    a2a_client = smtplib.SMTP("host")
    a2a_client.send_message(message)

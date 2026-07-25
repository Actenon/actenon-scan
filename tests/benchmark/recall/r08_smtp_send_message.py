"""Recall fixture: smtplib.SMTP.send_message must fire.

Paired with p13_a2a_send_message.py (the precision fixture). The A2A
exclusion is narrowed to require receiver-origin evidence (a constructor
or assignment traced to a recognised A2A / agent-transport client), so a
genuine SMTP send_message — whether inline or assigned — is NOT
suppressed.

Covers both forms required by Work Order 1, Part 1.2:

    smtplib.SMTP("host").send_message(message)   # inline constructor
    smtp = smtplib.SMTP("host")                   # assigned receiver
    smtp.send_message(message)

Expected findings: >= 1
"""

import smtplib

from mcp import tool


@tool()
def send_email_inline(host: str, message: str) -> None:
    """Agent-controlled email send — inline constructor form."""
    smtplib.SMTP(host).send_message(message)


@tool()
def send_email_assigned(host: str, message: str) -> None:
    """Agent-controlled email send — assigned receiver form."""
    smtp = smtplib.SMTP(host)
    smtp.send_message(message)

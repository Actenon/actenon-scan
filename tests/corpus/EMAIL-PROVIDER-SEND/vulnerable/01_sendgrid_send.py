"""SendGrid send in an MCP tool — must fire EMAIL-PROVIDER-SEND.

Covers: sg = sendgrid.SendGridAPIClient(api_key); sg.send(mail)
"""

import sendgrid

from mcp import tool


@tool()
def send_email(api_key: str, mail) -> None:
    """Agent-controlled SendGrid email send."""
    sg = sendgrid.SendGridAPIClient(api_key)
    sg.send(mail)

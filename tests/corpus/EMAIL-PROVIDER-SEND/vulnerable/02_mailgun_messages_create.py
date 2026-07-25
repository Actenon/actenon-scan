"""Mailgun messages.create in an MCP tool — must fire EMAIL-PROVIDER-SEND.

Covers: client = mailgun.Client(api_key); client.messages.create(domain, data)
"""

import mailgun

from mcp import tool


@tool()
def send_email(api_key: str, domain: str, to: str, subject: str, body: str) -> None:
    """Agent-controlled Mailgun email send."""
    client = mailgun.Client(api_key)
    client.messages.create(
        domain,
        {"from": f"agent@{domain}", "to": to, "subject": subject, "text": body},
    )

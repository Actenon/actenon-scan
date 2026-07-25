"""SendGrid send via inline constructor — must fire EMAIL-PROVIDER-SEND.

Covers: sendgrid.SendGridAPIClient(api_key).send(mail)
"""

import sendgrid

from mcp import tool


@tool()
def send_email(api_key: str, mail) -> None:
    """Agent-controlled SendGrid email send — inline constructor form."""
    sendgrid.SendGridAPIClient(api_key).send(mail)

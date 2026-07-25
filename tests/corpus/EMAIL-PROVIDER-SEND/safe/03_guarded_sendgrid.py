"""Safe: guarded SendGrid call — must NOT fire (guard dominance).

A SendGrid tool that checks an Actenon proof before sending. The guard
dominates the sink, so the finding is suppressed.
"""

import sendgrid

from actenon import verify_proof

from mcp import tool


@tool()
def send_email(api_key: str, mail, proof: str) -> None:
    """Agent-controlled SendGrid email send — guarded by Actenon proof."""
    verify_proof(proof, action="email.send", target="external")
    sg = sendgrid.SendGridAPIClient(api_key)
    sg.send(mail)

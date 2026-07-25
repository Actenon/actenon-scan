"""Safe: SendGrid call in a NON-agent context — must NOT fire (reachability).

A SendGrid library helper that wraps the SDK but is not exposed as an
agent tool. The reachability filter suppresses this finding.
"""

import sendgrid


def send_email(api_key: str, mail) -> None:
    """Internal helper, not agent-reachable."""
    sg = sendgrid.SendGridAPIClient(api_key)
    sg.send(mail)

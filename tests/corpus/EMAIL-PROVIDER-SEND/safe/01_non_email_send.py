"""Safe: non-email object with send method — must NOT fire.

A non-email domain object that happens to have a .send() method. The
origin gate requires the receiver to trace to SendGridAPIClient or
MailgunClient, so a generic Sender.send() does not fire.
"""


class Sender:
    """A non-email domain object with a .send() method."""

    def send(self, message: str) -> None:
        pass


def send_internal(message: str) -> None:
    """Not an agent tool, not an email send — must not fire."""
    sender = Sender()
    sender.send(message)

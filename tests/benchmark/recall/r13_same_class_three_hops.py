# r13: same-class multi-hop resolution — BaseTool._execute calls self.send() calls self._send() which has a sink.
# Real source: TransformerOptimus/SuperAGI @ c3c1982e7bd6a11cfed53c5a193ea502f924b1b6
#               superagi/tools/email/send_email_attachment.py:141
# Pattern: SendEmailAttachmentTool(BaseTool)._execute -> self.send_email_with_attachment() -> smtp.send_message :141
# Expected: >=1 finding (same_class_method signal, MEDIUM confidence, 2 hops)

from crewai_tools.tools.base_tool import BaseTool
import smtplib
from email.mime.text import MIMEText


class SendEmailAttachmentTool(BaseTool):
    def _execute(self, to: str, subject: str, body: str) -> str:
        """Agent-reachable entrypoint — _execute is a tool_base_class_method."""
        return self.send_email_with_attachment(to, subject, body)

    def send_email_with_attachment(self, to: str, subject: str, body: str) -> str:
        """Same-class method called from _execute. Sends an email
        to an agent-chosen recipient."""
        msg = MIMEText(body)
        msg["To"] = to
        msg["Subject"] = subject
        # The sink — agent-controlled recipient
        with smtplib.SMTP("smtp.gmail.com") as smtp:
            smtp.send_message(msg)
        return "sent"

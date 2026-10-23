import email
import imaplib
import os
import smtplib
from email.message import EmailMessage

from anthropic import Anthropic

client = Anthropic()
USER, PASSWORD = os.environ["MAIL_USER"], os.environ["MAIL_PASS"]
FIELDS = {"to": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"}}
TOOLS = [{
    "name": "send_email",
    "description": "Send an email from the user's mailbox.",
    "input_schema": {"type": "object", "properties": FIELDS, "required": list(FIELDS)},
}]


def send_email(to: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = USER, to, subject
    msg.set_content(body)
    with smtplib.SMTP_SSL("smtp.example.com") as smtp:
        smtp.login(USER, PASSWORD)
        smtp.send_message(msg)


def process_inbox() -> None:
    imap = imaplib.IMAP4_SSL("imap.example.com")
    imap.login(USER, PASSWORD)
    imap.select("INBOX")
    _, ids = imap.search(None, "UNSEEN")
    for num in ids[0].split():
        _, data = imap.fetch(num, "(RFC822)")
        mail = email.message_from_bytes(data[0][1])
        body = (mail.get_payload(decode=True) or b"").decode(errors="replace")
        reply = client.messages.create(
            model="claude-sonnet-4-5", max_tokens=1024, tools=TOOLS,
            system="You are an email assistant. Reply to messages that need a response.",
            messages=[{"role": "user", "content": f"From: {mail['From']}\n\n{body}"}],
        )
        for block in reply.content:
            if block.type == "tool_use" and block.name == "send_email":
                send_email(**block.input)

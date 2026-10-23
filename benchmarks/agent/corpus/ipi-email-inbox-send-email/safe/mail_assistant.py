import email
import imaplib
import os
from email.message import EmailMessage

from anthropic import Anthropic

client = Anthropic()
USER, PASSWORD = os.environ["MAIL_USER"], os.environ["MAIL_PASS"]


def draft_replies() -> None:
    imap = imaplib.IMAP4_SSL("imap.example.com")
    imap.login(USER, PASSWORD)
    imap.select("INBOX")
    _, ids = imap.search(None, "UNSEEN")
    for num in ids[0].split():
        _, data = imap.fetch(num, "(RFC822)")
        mail = email.message_from_bytes(data[0][1])
        body = (mail.get_payload(decode=True) or b"").decode(errors="replace")
        reply = client.messages.create(
            model="claude-sonnet-4-5", max_tokens=1024,
            system="You are an email assistant. Write a short draft reply to the email in <email> tags.",
            messages=[{"role": "user", "content": f"<email>\nFrom: {mail['From']}\n\n{body}\n</email>"}],
        )
        # drafts stay in the Drafts folder until the user reviews and sends them
        draft = EmailMessage()
        draft["From"], draft["To"] = USER, mail["From"]
        draft["Subject"] = "Re: " + (mail["Subject"] or "")
        draft.set_content(reply.content[0].text)
        imap.append("Drafts", "\\Draft", None, draft.as_bytes())

from typing import Literal

from googleapiclient.discovery import build
from openai import OpenAI
from pydantic import BaseModel

client = OpenAI()


class Decision(BaseModel):
    event_id: str
    status: Literal["accepted", "declined", "tentative"]


class Triage(BaseModel):
    decisions: list[Decision]


def triage_invites(creds) -> None:
    cal = build("calendar", "v3", credentials=creds)
    events = cal.events().list(calendarId="primary", singleEvents=True, maxResults=20).execute()["items"]
    listing = "\n\n".join(
        f"[{e['id']}] {e.get('summary')} from {e['organizer'].get('email')}\n{e.get('description', '')}" for e in events
    )
    resp = client.responses.parse(
        model="gpt-4.1", instructions="Triage my meeting invites.", input=listing, text_format=Triage
    )
    known = {e["id"]: e for e in events}
    for d in resp.output_parsed.decisions:
        event = known.get(d.event_id)
        if event is None:
            continue
        attendees = event.get("attendees", [])
        for a in attendees:
            if a.get("self"):
                a["responseStatus"] = d.status
        cal.events().patch(calendarId="primary", eventId=d.event_id, body={"attendees": attendees}, sendUpdates="all").execute()

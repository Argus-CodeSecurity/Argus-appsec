import json

from googleapiclient.discovery import build
from openai import OpenAI

client = OpenAI()


def _fn(name: str, description: str, props: dict) -> dict:
    schema = {"type": "object", "properties": props, "required": list(props)}
    return {"type": "function", "name": name, "description": description, "parameters": schema}


TOOLS = [
    _fn("respond", "Accept or decline an invite.", {"event_id": {"type": "string"}, "status": {"type": "string"}}),
    _fn("add_attendee", "Add someone to an event.", {"event_id": {"type": "string"}, "email": {"type": "string"}}),
]


def triage_invites(creds) -> None:
    cal = build("calendar", "v3", credentials=creds)
    events = cal.events().list(calendarId="primary", singleEvents=True, maxResults=20).execute()["items"]
    listing = "\n\n".join(
        f"[{e['id']}] {e.get('summary')} from {e['organizer'].get('email')}\n{e.get('description', '')}" for e in events
    )
    resp = client.responses.create(model="gpt-4.1", instructions="Triage my meeting invites.", input=listing, tools=TOOLS)
    for item in resp.output:
        if item.type != "function_call":
            continue
        args = json.loads(item.arguments)
        event = cal.events().get(calendarId="primary", eventId=args["event_id"]).execute()
        attendees = event.get("attendees", [])
        if item.name == "add_attendee":
            attendees.append({"email": args["email"]})
        else:
            for a in attendees:
                if a.get("self"):
                    a["responseStatus"] = args["status"]
        cal.events().patch(calendarId="primary", eventId=args["event_id"], body={"attendees": attendees}, sendUpdates="all").execute()

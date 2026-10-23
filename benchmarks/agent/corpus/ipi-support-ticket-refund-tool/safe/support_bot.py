import json

import requests
from openai import OpenAI

client = OpenAI()
HELPDESK = "https://helpdesk.example.com/api/v2"

TOOLS = [{
    "type": "function",
    "function": {
        "name": "issue_refund",
        "description": "Propose a refund for an order. A support lead reviews it before money moves.",
        "parameters": {
            "type": "object",
            "properties": {"order_id": {"type": "string"}, "amount": {"type": "number"}},
            "required": ["order_id", "amount"],
        },
    },
}]


def propose_refund(ticket_id: int, order_id: str, amount: float) -> dict:
    # lands in the refund review queue; nothing is paid until a lead approves it there
    payload = {"order_id": order_id, "amount": amount, "status": "pending_review"}
    r = requests.post(f"{HELPDESK}/tickets/{ticket_id}/refund-proposals", json=payload, timeout=10)
    return r.json()


def handle_ticket(ticket_id: int) -> str:
    ticket = requests.get(f"{HELPDESK}/tickets/{ticket_id}", timeout=10).json()
    messages = [
        {"role": "system", "content": "You are a support agent. Resolve the ticket and propose a refund when the customer is owed money."},
        {"role": "user", "content": f"Subject: {ticket['subject']}\n\n{ticket['description']}"},
    ]
    resp = client.chat.completions.create(model="gpt-4o", messages=messages, tools=TOOLS)
    msg = resp.choices[0].message
    for tc in msg.tool_calls or []:
        args = json.loads(tc.function.arguments)
        propose_refund(ticket_id, args["order_id"], args["amount"])
    return msg.content or ""

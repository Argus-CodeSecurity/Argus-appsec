import json

import requests
from openai import OpenAI

client = OpenAI()
HELPDESK = "https://helpdesk.example.com/api/v2"

TOOLS = [{
    "type": "function",
    "function": {
        "name": "issue_refund",
        "description": "Refund an order to the original payment method.",
        "parameters": {
            "type": "object",
            "properties": {"order_id": {"type": "string"}, "amount": {"type": "number"}},
            "required": ["order_id", "amount"],
        },
    },
}]


def issue_refund(order_id: str, amount: float) -> dict:
    r = requests.post(f"{HELPDESK}/refunds", json={"order_id": order_id, "amount": amount}, timeout=10)
    return r.json()


def handle_ticket(ticket_id: int) -> str:
    ticket = requests.get(f"{HELPDESK}/tickets/{ticket_id}", timeout=10).json()
    messages = [
        {"role": "system", "content": "You are a support agent. Resolve the ticket and refund when the customer is owed money."},
        {"role": "user", "content": f"Subject: {ticket['subject']}\n\n{ticket['description']}"},
    ]
    resp = client.chat.completions.create(model="gpt-4o", messages=messages, tools=TOOLS)
    msg = resp.choices[0].message
    for tc in msg.tool_calls or []:
        args = json.loads(tc.function.arguments)
        issue_refund(args["order_id"], args["amount"])
    return msg.content or ""

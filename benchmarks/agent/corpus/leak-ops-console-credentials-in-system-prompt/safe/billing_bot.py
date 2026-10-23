import json
import os

import requests
from openai import OpenAI

client = OpenAI()

SYSTEM_PROMPT = """You are the Acme billing assistant for customers.
If a customer reports a double charge, call the escalate tool with a short summary
and tell them it will be reviewed."""

TOOLS = [{
    "type": "function",
    "function": {
        "name": "escalate",
        "description": "File a double-charge case for the billing ops team.",
        "parameters": {"type": "object", "properties": {"summary": {"type": "string"}}, "required": ["summary"]},
    },
}]


def escalate(customer_id: str, summary: str) -> None:
    requests.post(
        os.environ["OPS_ESCALATION_URL"],
        json={"customer_id": customer_id, "summary": summary[:1000]},
        headers={"Authorization": f"Bearer {os.environ['OPS_API_TOKEN']}"},
        timeout=10,
    )


def reply(customer_id: str, history: list[dict], user_message: str) -> str:
    messages = [{"role": "system", "content": SYSTEM_PROMPT}, *history, {"role": "user", "content": user_message}]
    msg = client.chat.completions.create(model="gpt-4o-mini", messages=messages, tools=TOOLS).choices[0].message
    for tc in msg.tool_calls or []:
        escalate(customer_id, json.loads(tc.function.arguments)["summary"])
    return msg.content or "Thanks, I have passed this to our billing team for review."

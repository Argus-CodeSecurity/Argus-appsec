import json

import requests
from flask import Flask, jsonify, request
from flask_login import current_user, login_required
from openai import OpenAI

app = Flask(__name__)
client = OpenAI()
BILLING = "https://billing.internal.example.com/v1"


def _spec(name: str, description: str, props: dict) -> dict:
    return {"type": "function", "function": {"name": name, "description": description,
            "parameters": {"type": "object", "properties": props, "required": list(props)}}}


TOOL_SPECS = {
    "list_invoices": _spec("list_invoices", "List the customer's invoices.", {}),
    "issue_credit": _spec("issue_credit", "Credit an amount to an account.", {"account_id": {"type": "string"}, "amount": {"type": "number"}}),
}
TOOL_IMPLS = {
    "list_invoices": lambda user, a: requests.get(f"{BILLING}/accounts/{user.account_id}/invoices", timeout=10).json(),
    "issue_credit": lambda user, a: requests.post(f"{BILLING}/accounts/{a['account_id']}/credits", json={"amount": a["amount"]}, timeout=10).json(),
}
TOOLS_BY_ROLE = {"customer": ["list_invoices"], "billing_staff": ["list_invoices", "issue_credit"]}


@app.post("/assistant")
@login_required
def assistant():
    body = request.get_json()
    enabled = TOOLS_BY_ROLE.get(current_user.role, [])
    messages = [
        {"role": "system", "content": "You help customers with billing questions."},
        {"role": "user", "content": body["message"]},
    ]
    msg = client.chat.completions.create(model="gpt-4o", messages=messages, tools=[TOOL_SPECS[n] for n in enabled]).choices[0].message
    results = [
        TOOL_IMPLS[tc.function.name](current_user, json.loads(tc.function.arguments))
        for tc in msg.tool_calls or [] if tc.function.name in enabled
    ]
    return jsonify(reply=msg.content, results=results)
